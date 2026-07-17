/**
 * Unit tests for the `@shrug/freeipa/group` model.
 *
 * Two layers:
 *  - The pure value-shaping helpers (IPA array unwrapping + member merging), the
 *    `radius-vlan-<id>` name builder, the DuplicateEntry idempotency predicate,
 *    and the JSON-RPC body builder.
 *  - The method execute paths (groupFind/ensureVlanGroup/groupAdd|RemoveMember)
 *    driven through a mocked transport. The model's one network seam is
 *    `ipaLogin()` over the global `fetch`; {@link installFetch} stubs `fetch` to
 *    return IPA JSON-RPC envelopes so the methods run hermetically. The
 *    interesting branches are ensureVlanGroup's happy path, its DuplicateEntry
 *    swallow (re-run idempotency), and its partial-failure path — group_add
 *    lands but hostgroup_add fails non-duplicate, which must persist
 *    `complete:false` state and rethrow.
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  attrEquals,
  buildRpcBody,
  isDuplicateEntry,
  isNotFound,
  model,
  one,
  parseGroupRow,
  parseGroupRows,
  toInt,
  toStrArray,
  vlanGroupCn,
} from "./group.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["radius-vlan-10"]), "radius-vlan-10");
  assertEquals(one("scalar"), "scalar");
  assertEquals(one([]), undefined);
  assertEquals(one(undefined), undefined);
});

Deno.test("toInt() coerces array-wrapped numeric strings", () => {
  assertEquals(toInt(["10001"]), 10001);
  assertEquals(toInt("0"), 0);
  assertEquals(toInt(undefined), null);
  assertEquals(toInt(["not-a-number"]), null);
});

Deno.test("toStrArray() normalizes scalars, arrays, and absence", () => {
  assertEquals(toStrArray(["alice", "bob"]), ["alice", "bob"]);
  assertEquals(toStrArray("alice"), ["alice"]);
  assertEquals(toStrArray(undefined), []);
});

Deno.test("buildRpcBody() shapes the IPA JSON-RPC envelope", () => {
  assertEquals(buildRpcBody("group_find", [""], { all: true }, "2.254"), {
    method: "group_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("vlanGroupCn() builds the radius-vlan-<id> convention name", () => {
  assertEquals(vlanGroupCn(10), "radius-vlan-10");
  assertEquals(vlanGroupCn(99), "radius-vlan-99");
});

Deno.test("parseGroupRow() flattens a user group with gid + members", () => {
  const raw = {
    cn: ["radius-vlan-10"],
    description: ["FreeRADIUS VLAN 10 steering"],
    gidnumber: ["10001"],
    member_user: ["alice", "bob"],
    member_group: ["nested-grp"],
  };
  assertEquals(parseGroupRow(raw), {
    cn: "radius-vlan-10",
    description: "FreeRADIUS VLAN 10 steering",
    gidNumber: 10001,
    members: ["alice", "bob", "nested-grp"],
    raw,
  });
});

Deno.test("parseGroupRow() handles a host group with no gid/description", () => {
  const raw = {
    cn: ["radius-vlan-10"],
    member_host: ["host1.example.com"],
  };
  assertEquals(parseGroupRow(raw), {
    cn: "radius-vlan-10",
    description: undefined,
    gidNumber: undefined,
    members: ["host1.example.com"],
    raw,
  });
});

Deno.test("parseGroupRows() maps a find result array", () => {
  const rows = parseGroupRows([
    { cn: ["admins"], member_user: ["admin"] },
    { cn: ["editors"] },
  ]);
  assertEquals(rows.length, 2);
  assertEquals(rows[0].cn, "admins");
  assertEquals(rows[0].members, ["admin"]);
  assertEquals(rows[1].members, []);
});

Deno.test("isDuplicateEntry() detects DuplicateEntry / code 4002", () => {
  // Raw IPA error object shape.
  assertEquals(isDuplicateEntry({ name: "DuplicateEntry", code: 4002 }), true);
  assertEquals(isDuplicateEntry({ code: 4002 }), true);
  // The Error message shape formatted by ipaLogin.
  assertEquals(
    isDuplicateEntry(
      new Error(
        'IPA group_add failed: DuplicateEntry: group with name "radius-vlan-10" already exists (code 4002)',
      ),
    ),
    true,
  );
  // Bare string.
  assertEquals(isDuplicateEntry("code 4002"), true);
  // Non-duplicate errors.
  assertEquals(
    isDuplicateEntry(new Error("IPA group_add failed: NotFound: (code 4001)")),
    false,
  );
  assertEquals(isDuplicateEntry({ name: "SomethingElse", code: 4001 }), false);
  assertEquals(isDuplicateEntry(undefined), false);
});

// ---------------------------------------------------------------------------
// Mocked-transport harness — drives the method execute paths without a network.
// ---------------------------------------------------------------------------

/** An IPA JSON-RPC response envelope, success or failure. */
type Envelope = {
  error: { name?: string; message?: string; code?: number } | null;
  result: Record<string, unknown> | null;
};

/** Build a success envelope wrapping the given `result` payload. */
function ok(result: Record<string, unknown>): Envelope {
  return { error: null, result };
}

/** Build a failure envelope carrying an IPA-style error. */
function err(name: string, message: string, code = 4001): Envelope {
  return { error: { name, message, code }, result: null };
}

/** A recorded `writeResource` call. */
interface WriteCall {
  spec: string;
  name: string;
  data: Record<string, unknown>;
}

/** Installed `fetch` mock: dispatches by IPA command, records JSON calls. */
interface FetchMock {
  restore: () => void;
  /** Each `/session/json` request, in order, by IPA command (no `/1`). */
  jsonCalls: Array<{ command: string; params: unknown }>;
}

/**
 * Replace the global `fetch` with an in-memory IPA server.
 *
 * The `login_password` step returns a Set-Cookie `ipa_session`; each
 * `/session/json` request is dispatched to `handlers` keyed by IPA command
 * (e.g. `group_add`). A handler value is an {@link Envelope} (or a thunk
 * returning one); an unmapped command is a test bug and throws.
 */
function installFetch(
  handlers: Record<string, Envelope | (() => Envelope)>,
): FetchMock {
  const original = globalThis.fetch;
  const jsonCalls: FetchMock["jsonCalls"] = [];

  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/session/login_password")) {
      const headers = new Headers();
      headers.append("set-cookie", "ipa_session=SESSION; Path=/ipa; HttpOnly");
      return Promise.resolve(new Response("", { status: 200, headers }));
    }
    if (url.endsWith("/session/json")) {
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        method: string;
        params: unknown;
      };
      const command = body.method.replace(/\/1$/, "");
      jsonCalls.push({ command, params: body.params });
      const handler = handlers[command];
      if (handler === undefined) {
        throw new Error(`unexpected IPA command in test: ${command}`);
      }
      const env = typeof handler === "function" ? handler() : handler;
      return Promise.resolve(
        new Response(JSON.stringify(env), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    }
    throw new Error(`unexpected fetch URL in test: ${url}`);
  }) as typeof fetch;

  return {
    restore: () => {
      globalThis.fetch = original;
    },
    jsonCalls,
  };
}

/** Stub ExecuteContext: no-op logger, recording writeResource, test globals. */
function stubContext() {
  const writes: WriteCall[] = [];
  const noop = (_m: string, _p?: Record<string, unknown>) => {};
  const context = {
    globalArgs: {
      server: "ipa1.example.com",
      user: "admin",
      password: "secret",
      apiVersion: "2.254",
    },
    logger: { debug: noop, info: noop, warning: noop, error: noop },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
    // deno-lint-ignore no-explicit-any
  } as any;
  return { context, writes };
}

Deno.test("groupFind: snapshots user + host groups into `groups`", async () => {
  const mock = installFetch({
    group_find: ok({ result: [{ cn: ["admins"] }], count: 1 }),
    hostgroup_find: ok({ result: [{ cn: ["webservers"] }], count: 1 }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupFind.execute({}, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "group_find",
      "hostgroup_find",
    ]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "groups");
    assertEquals((writes[0].data.userGroups as unknown[]).length, 1);
    assertEquals((writes[0].data.hostGroups as unknown[]).length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("ensureVlanGroup: both adds succeed -> attempt + complete state", async () => {
  const mock = installFetch({
    group_add: ok({ result: { cn: ["radius-vlan-20"] } }),
    hostgroup_add: ok({ result: { cn: ["radius-vlan-20"] } }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureVlanGroup.execute({ vlanId: 20 }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "group_add",
      "hostgroup_add",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "vlanGroup"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(writes[1].data.complete, true);
    assertEquals(writes[1].data.userGroupPresent, true);
    assertEquals(writes[1].data.hostGroupPresent, true);
  } finally {
    mock.restore();
  }
});

Deno.test("ensureVlanGroup: DuplicateEntry is swallowed -> idempotent success", async () => {
  // A re-run: the user group already exists (group_add -> DuplicateEntry), the
  // host group is created fresh. The whole ensure still succeeds and completes.
  const mock = installFetch({
    group_add: err(
      "DuplicateEntry",
      'group with name "radius-vlan-20" already exists',
      4002,
    ),
    hostgroup_add: ok({ result: { cn: ["radius-vlan-20"] } }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureVlanGroup.execute({ vlanId: 20 }, context);
    assertEquals(writes.map((w) => w.spec), ["attempt", "vlanGroup"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(writes[1].data.complete, true);
    assertEquals(writes[1].data.userGroupPresent, true);
    assertEquals(writes[1].data.hostGroupPresent, true);
  } finally {
    mock.restore();
  }
});

Deno.test("ensureVlanGroup: partial failure persists complete:false then rethrows", async () => {
  // group_add lands, but hostgroup_add fails with a non-duplicate error. The
  // real partial state must be persisted (complete:false, only the user half
  // present) and the step must fail.
  const mock = installFetch({
    group_add: ok({ result: { cn: ["radius-vlan-20"] } }),
    hostgroup_add: err("DatabaseError", "constraint violation", 4203),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () => model.methods.ensureVlanGroup.execute({ vlanId: 20 }, context),
      Error,
      "hostgroup_add failed",
    );
    // Failure audit first, then the partial state.
    assertEquals(writes.map((w) => w.spec), ["attempt", "vlanGroup"]);
    assertEquals(writes[0].data.success, false);
    assertEquals(writes[0].data.response, null);
    assertEquals(writes[1].data.complete, false);
    assertEquals(writes[1].data.userGroupPresent, true);
    assertEquals(writes[1].data.hostGroupPresent, false);
  } finally {
    mock.restore();
  }
});

Deno.test("groupAddMember: audits the add and surfaces IPA's failed structure", async () => {
  const mock = installFetch({
    group_add_member: ok({
      completed: 1,
      failed: { member: { user: [], group: [] } },
      result: { cn: ["radius-vlan-20"], member_user: ["alice"] },
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupAddMember.execute(
      { cn: "radius-vlan-20", kind: "user", users: ["alice"] },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["group_add_member"]);
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
    const response = writes[0].data.response as { completed: unknown };
    assertEquals(response.completed, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("groupRemoveMember: host kind maps to hostgroup_remove_member", async () => {
  const mock = installFetch({
    hostgroup_remove_member: ok({
      completed: 1,
      failed: { member: { host: [] } },
      result: { cn: ["radius-vlan-20"] },
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupRemoveMember.execute(
      { cn: "radius-vlan-20", kind: "host", hosts: ["host1.example.com"] },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "hostgroup_remove_member",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

// ---------------------------------------------------------------------------
// Generic user-group CRUD + sync (groupShow/groupAdd/groupMod/groupDel/groupSync)
// ---------------------------------------------------------------------------

Deno.test("isNotFound() detects NotFound / code 4001", () => {
  assertEquals(isNotFound({ name: "NotFound" }), true);
  assertEquals(isNotFound({ code: 4001 }), true);
  assertEquals(
    isNotFound(new Error("IPA group_show failed: NotFound: x (code 4001)")),
    true,
  );
  assertEquals(isNotFound({ name: "DuplicateEntry", code: 4002 }), false);
  assertEquals(isNotFound("nope"), false);
});

Deno.test("attrEquals() compares set-wise, scalar == single-array", () => {
  assertEquals(attrEquals(["swamp runtime"], "swamp runtime"), true);
  assertEquals(attrEquals(["12000"], 12000), true);
  assertEquals(attrEquals(undefined, "x"), false);
  assertEquals(attrEquals(["a", "b"], ["b", "a"]), true);
});

Deno.test("groupShow: snapshots a single user group into `group`", async () => {
  const mock = installFetch({
    group_show: ok({
      result: { cn: ["swamp"], gidnumber: ["12000"], member_user: ["swamp"] },
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupShow.execute({ cn: "swamp" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["group_show"]);
    assertEquals(writes.map((w) => w.spec), ["group"]);
    const group = writes[0].data.group as { cn: string; gidNumber: number };
    assertEquals(group.cn, "swamp");
    assertEquals(group.gidNumber, 12000);
  } finally {
    mock.restore();
  }
});

Deno.test("groupAdd: creates a group and records attempt + group state", async () => {
  const mock = installFetch({
    group_add: ok({
      result: { cn: ["swamp"], description: ["swamp runtime"] },
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupAdd.execute(
      { cn: "swamp", description: "swamp runtime" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["group_add"]);
    // The description option is passed through to group_add.
    const params = mock.jsonCalls[0].params as [
      unknown[],
      Record<string, unknown>,
    ];
    assertEquals(params[1].description, "swamp runtime");
    assertEquals(writes.map((w) => w.spec), ["attempt", "group"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("groupAdd: idempotent swallows DuplicateEntry and re-reads via group_show", async () => {
  const mock = installFetch({
    group_add: err("DuplicateEntry", "group swamp already exists", 4002),
    group_show: ok({ result: { cn: ["swamp"], gidnumber: ["12000"] } }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupAdd.execute(
      { cn: "swamp", idempotent: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "group_add",
      "group_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "group"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("groupAdd: non-idempotent DuplicateEntry rejects and audits failure", async () => {
  const mock = installFetch({
    group_add: err("DuplicateEntry", "group swamp already exists", 4002),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(() =>
      model.methods.groupAdd.execute({ cn: "swamp" }, context)
    );
    // Only the failure attempt is persisted (no group state on failure).
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
  } finally {
    mock.restore();
  }
});

Deno.test("groupDel: confirm:false refuses without any network call", async () => {
  const mock = installFetch({});
  try {
    const { context } = stubContext();
    await assertRejects(
      () =>
        model.methods.groupDel.execute(
          { cn: "swamp", confirm: false },
          context,
        ),
      Error,
      "confirm:true",
    );
    assertEquals(mock.jsonCalls.length, 0);
  } finally {
    mock.restore();
  }
});

Deno.test("groupDel: idempotent swallows NotFound as a no-op success", async () => {
  const mock = installFetch({
    group_del: err("NotFound", "swamp: group not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupDel.execute(
      { cn: "swamp", confirm: true, idempotent: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["group_del"]);
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("groupSync: absent group is created (group_show 404 -> group_add)", async () => {
  const calls: string[] = [];
  const mock = installFetch({
    group_show: () =>
      calls.push("show") === 1
        ? err("NotFound", "swamp: group not found", 4001)
        : ok({ result: { cn: ["swamp"], description: ["swamp runtime"] } }),
    group_add: ok({ result: { cn: ["swamp"] } }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupSync.execute(
      { cn: "swamp", description: "swamp runtime" },
      context,
    );
    // show (404) -> add -> show (final re-read).
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "group_show",
      "group_add",
      "group_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "group"]);
    const resp = writes[0].data.response as {
      created: boolean;
      changes: string[];
    };
    assertEquals(resp.created, true);
    assertEquals(resp.changes, ["created"]);
  } finally {
    mock.restore();
  }
});

Deno.test("groupSync: converged group issues no writes (mod skipped)", async () => {
  const mock = installFetch({
    group_show: ok({
      result: { cn: ["swamp"], description: ["swamp runtime"] },
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupSync.execute(
      { cn: "swamp", description: "swamp runtime" },
      context,
    );
    // No group_add and no group_mod — only the initial + final group_show.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "group_show",
      "group_show",
    ]);
    const resp = writes[0].data.response as {
      converged: boolean;
      changes: string[];
    };
    assertEquals(resp.converged, true);
    assertEquals(resp.changes, []);
  } finally {
    mock.restore();
  }
});

Deno.test("groupSync: drifted description triggers group_mod of only that key", async () => {
  const mock = installFetch({
    group_show: ok({
      result: { cn: ["swamp"], description: ["old desc"] },
    }),
    group_mod: ok({ result: { cn: ["swamp"], description: ["new desc"] } }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupSync.execute(
      { cn: "swamp", description: "new desc" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "group_show",
      "group_mod",
      "group_show",
    ]);
    const modParams = mock.jsonCalls[1].params as [
      unknown[],
      Record<string, unknown>,
    ];
    assertEquals(modParams[1].description, "new desc");
    const resp = writes[0].data.response as { changes: string[] };
    assertEquals(resp.changes, ["mod:description"]);
  } finally {
    mock.restore();
  }
});

Deno.test("groupMod: modifies a group and records attempt + group state", async () => {
  const mock = installFetch({
    group_mod: ok({
      result: { cn: ["swamp"], description: ["swamp runtime service group"] },
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupMod.execute(
      { cn: "swamp", set: { description: "swamp runtime service group" } },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["group_mod"]);
    // The `set` object is passed straight through as the IPA options map.
    const params = mock.jsonCalls[0].params as [
      unknown[],
      Record<string, unknown>,
    ];
    assertEquals(params[0], ["swamp"]);
    assertEquals(params[1].description, "swamp runtime service group");
    assertEquals(writes.map((w) => w.spec), ["attempt", "group"]);
    assertEquals(writes[0].data.success, true);
    assertEquals((writes[1].data.group as { cn: string }).cn, "swamp");
  } finally {
    mock.restore();
  }
});

Deno.test("groupDel: confirm:true deletes an existing group and audits success", async () => {
  const mock = installFetch({
    group_del: ok({ result: true, value: "swamp", summary: null }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.groupDel.execute(
      { cn: "swamp", confirm: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["group_del"]);
    // Delete records only the audit — no `group` state is written on removal.
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(
      (writes[0].data.request as { idempotent: boolean }).idempotent,
      false,
    );
  } finally {
    mock.restore();
  }
});

Deno.test("groupDel: default (non-idempotent) NotFound rejects and audits failure", async () => {
  // The documented default (idempotent:false) must preserve fail-on-missing:
  // an absent group is a real error, not a silent no-op.
  const mock = installFetch({
    group_del: err("NotFound", "swamp: group not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.groupDel.execute({ cn: "swamp", confirm: true }, context),
      Error,
      "group_del failed",
    );
    // Only the failure audit is persisted, then the error rethrows.
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
    assertEquals(writes[0].data.response, null);
  } finally {
    mock.restore();
  }
});

Deno.test("groupSync: a failed group_mod records the failure audit and rethrows", async () => {
  // Present group with drift, but group_mod fails: the three-way persistence
  // rule means the failure audit is written (success:false) and the error
  // propagates — no converged `group` state is persisted on failure.
  const mock = installFetch({
    group_show: ok({ result: { cn: ["swamp"], description: ["old desc"] } }),
    group_mod: err("DatabaseError", "constraint violation", 4203),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.groupSync.execute(
          { cn: "swamp", description: "new desc" },
          context,
        ),
      Error,
      "group_mod failed",
    );
    // Initial show succeeded, mod failed -> no trailing re-read/state write.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "group_show",
      "group_mod",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
    assertEquals(writes[0].data.response, null);
  } finally {
    mock.restore();
  }
});
