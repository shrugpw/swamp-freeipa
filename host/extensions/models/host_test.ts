/**
 * Unit tests for the `@shrug/freeipa/host` model.
 *
 * Two layers:
 *  - The pure value-shaping helpers (IPA's single-element array unwrapping,
 *    boolean coercion, host-row parsing) and the JSON-RPC body builder.
 *  - The method execute paths (find/show/add/mod/del/disable/sync) driven
 *    through a mocked transport. The model's one network seam is `ipaLogin()`
 *    over the global `fetch`; {@link installFetch} stubs `fetch` to return IPA
 *    JSON-RPC envelopes (including the `login_password` Set-Cookie step) so the
 *    methods run hermetically — no network — and we can assert the write-kernel
 *    contract: an `attempt` audit resource on BOTH success and failure (with a
 *    rethrow on failure), STATE resources on success only, and that a random
 *    enrollment password lands on the host STATE resource but NEVER in the audit.
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
  parseHost,
  toBool,
  toInt,
  toStrArray,
} from "./host.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["host1.example.com"]), "host1.example.com");
  assertEquals(one("scalar"), "scalar");
  assertEquals(one([]), undefined);
  assertEquals(one(undefined), undefined);
});

Deno.test("toInt() coerces array-wrapped numeric strings", () => {
  assertEquals(toInt(["1"]), 1);
  assertEquals(toInt("0"), 0);
  assertEquals(toInt(undefined), null);
  assertEquals(toInt(["not-a-number"]), null);
});

Deno.test("toStrArray() normalizes scalars, arrays, and absence", () => {
  assertEquals(toStrArray(["webservers", "dbservers"]), [
    "webservers",
    "dbservers",
  ]);
  assertEquals(toStrArray("webservers"), ["webservers"]);
  assertEquals(toStrArray(undefined), []);
});

Deno.test("toBool() reads IPA boolean-ish values", () => {
  assertEquals(toBool([true]), true);
  assertEquals(toBool("TRUE"), true);
  assertEquals(toBool(["false"]), false);
  assertEquals(toBool(false), false);
  assertEquals(toBool(undefined), false);
});

Deno.test("buildRpcBody() shapes the IPA JSON-RPC envelope", () => {
  assertEquals(buildRpcBody("host_find", [""], { all: true }, "2.254"), {
    method: "host_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("parseHost() flattens a host entry and keeps raw", () => {
  const entry = {
    fqdn: ["host1.example.com"],
    description: ["web node"],
    nsosversion: ["Fedora 40"],
    nshardwareplatform: ["x86_64"],
    managedby_host: ["host1.example.com"],
    memberof_hostgroup: ["webservers", "ipaservers"],
    has_keytab: [true],
    has_password: [false],
    dn: "fqdn=host1.example.com,cn=computers,cn=accounts,dc=example,dc=com",
  };
  assertEquals(parseHost(entry), {
    fqdn: "host1.example.com",
    description: "web node",
    os: "Fedora 40",
    platform: "x86_64",
    managedByHosts: ["host1.example.com"],
    memberOfHostGroups: ["webservers", "ipaservers"],
    hasKeytab: true,
    hasPassword: false,
    raw: entry,
  });
});

Deno.test("parseHost() defaults absent optionals sensibly", () => {
  const entry = { fqdn: ["host2.example.com"] };
  assertEquals(parseHost(entry), {
    fqdn: "host2.example.com",
    description: undefined,
    os: undefined,
    platform: undefined,
    managedByHosts: [],
    memberOfHostGroups: [],
    hasKeytab: false,
    hasPassword: false,
    raw: entry,
  });
});

Deno.test("isDuplicateEntry() matches by name, code, or message", () => {
  assertEquals(isDuplicateEntry({ name: "DuplicateEntry", code: 4002 }), true);
  assertEquals(isDuplicateEntry({ code: 4002 }), true);
  assertEquals(
    isDuplicateEntry(new Error("IPA host_add failed: DuplicateEntry: x")),
    true,
  );
  assertEquals(isDuplicateEntry("… (code 4002)"), true);
  assertEquals(isDuplicateEntry({ name: "NotFound", code: 4001 }), false);
  assertEquals(isDuplicateEntry(new Error("boom")), false);
});

Deno.test("isNotFound() matches by name, code, or message", () => {
  assertEquals(isNotFound({ name: "NotFound", code: 4001 }), true);
  assertEquals(isNotFound({ code: 4001 }), true);
  assertEquals(
    isNotFound(new Error("IPA host_del failed: NotFound: x (code 4001)")),
    true,
  );
  assertEquals(isNotFound("… (code 4001)"), true);
  assertEquals(isNotFound({ name: "DuplicateEntry", code: 4002 }), false);
  assertEquals(isNotFound(new Error("boom")), false);
});

Deno.test("attrEquals() compares desired vs raw IPA values set-wise", () => {
  // Scalar desired vs single-element IPA array.
  assertEquals(attrEquals(["Fedora 40"], "Fedora 40"), true);
  // Order-insensitive multi-value.
  assertEquals(attrEquals(["a", "b"], ["b", "a"]), true);
  // Absent actual vs a desired value differs.
  assertEquals(attrEquals(undefined, ["web node"]), false);
  // Absent both sides converge.
  assertEquals(attrEquals(undefined, []), true);
  // Genuine drift.
  assertEquals(attrEquals(["web node"], "edge node"), false);
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
 * The `login_password` step returns a Set-Cookie `ipa_session` (unless
 * `loginOk:false`); each `/session/json` request is dispatched to `handlers`
 * keyed by IPA command (e.g. `host_add`). A handler value is an {@link Envelope}
 * (or a thunk returning one); an unmapped command is a test bug and throws.
 */
function installFetch(
  handlers: Record<string, Envelope | (() => Envelope)>,
  opts: { loginOk?: boolean; cookie?: string | null } = {},
): FetchMock {
  const original = globalThis.fetch;
  const jsonCalls: FetchMock["jsonCalls"] = [];
  const loginOk = opts.loginOk ?? true;
  const cookie = opts.cookie === undefined
    ? "ipa_session=SESSION"
    : opts.cookie;

  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/session/login_password")) {
      const headers = new Headers();
      if (loginOk && cookie) {
        headers.append("set-cookie", `${cookie}; Path=/ipa; HttpOnly`);
      }
      if (!loginOk) headers.set("x-ipa-rejection-reason", "invalid-password");
      return Promise.resolve(
        new Response(loginOk ? "" : "login failed", {
          status: loginOk ? 200 : 401,
          headers,
        }),
      );
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
function stubContext(globalOverrides: Record<string, unknown> = {}) {
  const writes: WriteCall[] = [];
  const noop = (_m: string, _p?: Record<string, unknown>) => {};
  const context = {
    globalArgs: {
      server: "ipa1.example.com",
      user: "admin",
      password: "secret",
      apiVersion: "2.254",
      ...globalOverrides,
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

/** A minimal parsed IPA host entry for result payloads. */
const host1Entry = {
  fqdn: ["host1.example.com"],
  description: ["web node"],
  has_keytab: [false],
};

Deno.test("find: snapshots matched hosts into a `hosts` resource", async () => {
  const mock = installFetch({
    host_find: ok({
      result: [host1Entry],
      count: 1,
      summary: "1 host matched",
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.find.execute({ criteria: "host1" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_find"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "hosts");
    assertEquals((writes[0].data.hosts as unknown[]).length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("show: snapshots a single host into a `host` resource", async () => {
  const mock = installFetch({ host_show: ok({ result: host1Entry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.show.execute({ fqdn: "host1.example.com" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_show"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "host");
    assertEquals(
      (writes[0].data.host as { fqdn: string }).fqdn,
      "host1.example.com",
    );
  } finally {
    mock.restore();
  }
});

Deno.test("add: writes attempt(success) then the host state, in order", async () => {
  const mock = installFetch({ host_add: ok({ result: host1Entry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.add.execute(
      { fqdn: "host1.example.com", description: "web node" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_add"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "host"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(writes[0].data.error, null);
    assertEquals(
      (writes[0].data.response as { result: unknown }).result != null,
      true,
    );
    // No random password requested -> the state carries none.
    assertEquals(writes[1].data.randomPassword, undefined);
  } finally {
    mock.restore();
  }
});

Deno.test("add: records attempt(failure) and rethrows; no state resource", async () => {
  const mock = installFetch({
    host_add: err(
      "DuplicateEntry",
      "host with name host1.example.com already exists",
      4002,
    ),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.add.execute(
          { fqdn: "host1.example.com" },
          context,
        ),
      Error,
      "host_add failed",
    );
    // The audit resource is the ONLY write: state is success-only.
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
    assertEquals(writes[0].data.response, null);
    assertEquals(typeof writes[0].data.error, "string");
  } finally {
    mock.restore();
  }
});

Deno.test("add random:true vaults the OTP on host state and keeps it out of the audit", async () => {
  const OTP = "S3cretOneTimePW";
  const mock = installFetch({
    host_add: ok({
      result: { ...host1Entry, randompassword: [OTP] },
      summary: "Added host host1.example.com",
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.add.execute(
      { fqdn: "host1.example.com", random: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_add"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "host"]);

    // The one-time password is persisted onto the host STATE resource...
    assertEquals(writes[1].data.randomPassword, OTP);

    // ...and appears NOWHERE in the attempt audit (request or response), nor in
    // the host row's `raw` passthrough — it was stripped before parsing.
    const auditJson = JSON.stringify(writes[0].data);
    assertEquals(auditJson.includes(OTP), false);
    const hostRow = writes[1].data.host as { raw: Record<string, unknown> };
    assertEquals("randompassword" in hostRow.raw, false);
  } finally {
    mock.restore();
  }
});

Deno.test("add idempotent: DuplicateEntry re-reads and records success", async () => {
  // host_add reports the entry exists; the idempotent path re-reads via
  // host_show and records the attempt as a success no-op.
  const mock = installFetch({
    host_add: err(
      "DuplicateEntry",
      "host host1.example.com already exists",
      4002,
    ),
    host_show: ok({ result: host1Entry }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.add.execute(
      { fqdn: "host1.example.com", idempotent: true },
      context,
    );
    // The duplicate is caught inside the attempt, so host_show follows host_add.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "host_add",
      "host_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "host"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(
      (writes[0].data.request as { idempotent: boolean }).idempotent,
      true,
    );
    assertEquals(
      (writes[1].data.host as { fqdn: string }).fqdn,
      "host1.example.com",
    );
    // A re-read never carries a random password.
    assertEquals(writes[1].data.randomPassword, undefined);
  } finally {
    mock.restore();
  }
});

Deno.test("add non-idempotent: DuplicateEntry still fails (default preserved)", async () => {
  const mock = installFetch({
    host_add: err(
      "DuplicateEntry",
      "host host1.example.com already exists",
      4002,
    ),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.add.execute(
          { fqdn: "host1.example.com" },
          context,
        ),
      Error,
      "host_add failed",
    );
    // No idempotent re-read; audit-only, failure.
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_add"]);
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
  } finally {
    mock.restore();
  }
});

Deno.test("mod: writes attempt(success) then the updated host state", async () => {
  const mock = installFetch({ host_mod: ok({ result: host1Entry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.mod.execute(
      { fqdn: "host1.example.com", set: { nsosversion: "Fedora 40" } },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_mod"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "host"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("disable: audits the revoke then re-reads host state", async () => {
  const mock = installFetch({
    host_disable: ok({ result: true, value: "host1.example.com", summary: "" }),
    host_show: ok({ result: { ...host1Entry, has_keytab: [false] } }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.disable.execute(
      { fqdn: "host1.example.com" },
      context,
    );
    // Disable command, then a fresh host_show to reflect the revoked keytab.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "host_disable",
      "host_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "host"]);
    assertEquals(writes[0].data.method, "host_disable");
    assertEquals(
      (writes[1].data.host as { hasKeytab: boolean }).hasKeytab,
      false,
    );
  } finally {
    mock.restore();
  }
});

Deno.test("del: confirm:false throws before any transport or write", async () => {
  const mock = installFetch({});
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.del.execute(
          { fqdn: "host1.example.com", confirm: false },
          context,
        ),
      Error,
      "confirm:true",
    );
    assertEquals(mock.jsonCalls.length, 0);
    assertEquals(writes.length, 0);
  } finally {
    mock.restore();
  }
});

Deno.test("del: confirm:true audits the delete, writes no state", async () => {
  const mock = installFetch({
    host_del: ok({
      result: true,
      value: ["host1.example.com"],
      summary: "Deleted host host1.example.com",
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.del.execute(
      { fqdn: "host1.example.com", confirm: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_del"]);
    // Delete produces only the audit record — there is no live host to snapshot.
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("del idempotent: NotFound records success, no state", async () => {
  const mock = installFetch({
    host_del: err("NotFound", "host gone.example.com not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.del.execute(
      { fqdn: "gone.example.com", confirm: true, idempotent: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["host_del"]);
    // No live host to snapshot: audit-only, but a success no-op.
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(
      (writes[0].data.response as { alreadyAbsent?: boolean }).alreadyAbsent,
      true,
    );
  } finally {
    mock.restore();
  }
});

Deno.test("del non-idempotent: NotFound still fails (default preserved)", async () => {
  const mock = installFetch({
    host_del: err("NotFound", "host gone.example.com not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.del.execute(
          { fqdn: "gone.example.com", confirm: true },
          context,
        ),
      Error,
      "host_del failed",
    );
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
  } finally {
    mock.restore();
  }
});

Deno.test("del idempotent still honors the confirm guard", async () => {
  const mock = installFetch({});
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.del.execute(
          { fqdn: "host1.example.com", confirm: false, idempotent: true },
          context,
        ),
      Error,
      "confirm:true",
    );
    assertEquals(mock.jsonCalls.length, 0);
    assertEquals(writes.length, 0);
  } finally {
    mock.restore();
  }
});

Deno.test("sync: absent host is created, then snapshotted", async () => {
  let shows = 0;
  const mock = installFetch({
    // First host_show (the reconcile read) 404s -> create; the final
    // snapshot host_show succeeds.
    host_show: () =>
      shows++ === 0
        ? err("NotFound", "host host1.example.com not found", 4001)
        : ok({ result: host1Entry }),
    host_add: ok({ result: host1Entry }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sync.execute(
      { fqdn: "host1.example.com", description: "web node" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "host_show",
      "host_add",
      "host_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "host"]);
    assertEquals(writes[0].data.success, true);
    const resp = writes[0].data.response as {
      created: boolean;
      changes: string[];
      converged: boolean;
    };
    assertEquals(resp.created, true);
    assertEquals(resp.changes, ["created"]);
  } finally {
    mock.restore();
  }
});

Deno.test("sync: a converged host issues no IPA writes", async () => {
  // Actual matches desired exactly (description "web node") so the diff is empty
  // and no host_add/host_mod is issued.
  const mock = installFetch({ host_show: ok({ result: host1Entry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.sync.execute(
      { fqdn: "host1.example.com", description: "web node" },
      context,
    );
    // Only the initial reconcile read and the final snapshot read — no writes.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "host_show",
      "host_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "host"]);
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

Deno.test("sync: drift is reconciled with host_mod", async () => {
  let shows = 0;
  const edited = { ...host1Entry, description: ["edge node"] };
  const mock = installFetch({
    // Initial read: description "web node" (drifted from desired "edge node");
    // final read shows the reconciled entry.
    host_show: () =>
      shows++ === 0 ? ok({ result: host1Entry }) : ok({ result: edited }),
    host_mod: ok({ result: edited }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sync.execute(
      { fqdn: "host1.example.com", description: "edge node" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "host_show",
      "host_mod",
      "host_show",
    ]);
    // host_mod set only the drifted `description` attribute.
    const modCall = mock.jsonCalls.find((c) => c.command === "host_mod");
    assertEquals(
      (modCall!.params as [string[], Record<string, unknown>])[1].description,
      "edge node",
    );
    const resp = writes[0].data.response as { changes: string[] };
    assertEquals(resp.changes, ["mod:description"]);
  } finally {
    mock.restore();
  }
});
