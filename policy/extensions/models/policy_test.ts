/**
 * Unit tests for the `@shrug/freeipa/policy` model (Wave 1: sudo surface).
 *
 * Two layers:
 *  - The pure value-shaping helpers (IPA's single-element array unwrapping,
 *    boolean coercion, sudo-rule parsing) and the JSON-RPC body builder.
 *  - The method execute paths (sudoRuleFind/Show, ensureSudoRule,
 *    sudoRuleAddOption/AddUser/AddHost/AddCommand, sudoRuleSetEnabled,
 *    sudoRuleDel) driven through a mocked transport. The model's one network
 *    seam is `ipaLogin()` over the global `fetch`; {@link installFetch} stubs
 *    `fetch` to return IPA JSON-RPC envelopes (including the `login_password`
 *    Set-Cookie step) so the methods run hermetically — no network — and we can
 *    assert the write-kernel contract: an `attempt` audit resource on BOTH
 *    success and failure (with a rethrow on failure), and STATE resources on
 *    success only.
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  buildRpcBody,
  isDuplicateEntry,
  isNotFound,
  model,
  one,
  parseSudoRule,
  toBool,
  toInt,
  toStrArray,
} from "./policy.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["allow-web"]), "allow-web");
  assertEquals(one("scalar"), "scalar");
  assertEquals(one([]), undefined);
  assertEquals(one(undefined), undefined);
});

Deno.test("toInt() coerces array-wrapped numeric strings", () => {
  assertEquals(toInt(["10"]), 10);
  assertEquals(toInt("0"), 0);
  assertEquals(toInt(undefined), null);
  assertEquals(toInt(["not-a-number"]), null);
});

Deno.test("toStrArray() normalizes scalars, arrays, and absence", () => {
  assertEquals(toStrArray(["alice", "jdoe"]), ["alice", "jdoe"]);
  assertEquals(toStrArray("alice"), ["alice"]);
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
  assertEquals(buildRpcBody("sudorule_find", [""], { all: true }, "2.254"), {
    method: "sudorule_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("parseSudoRule() flattens a rule entry and keeps raw", () => {
  const entry = {
    cn: ["allow-web-admins"],
    description: ["Web admins passwordless sudo"],
    ipaenabledflag: ["TRUE"],
    sudoorder: ["50"],
    cmdcategory: ["all"],
    memberuser_user: ["alice", "jdoe"],
    memberuser_group: ["web-admins"],
    memberhost_host: ["host1.example.com"],
    memberhost_hostgroup: ["webservers"],
    memberallowcmd_sudocmd: ["/usr/bin/systemctl"],
    memberallowcmd_sudocmdgroup: ["net-tools"],
    ipasudoopt: ["!authenticate"],
    dn: "ipaUniqueID=abc,cn=sudorules,cn=sudo,dc=example,dc=com",
  };
  assertEquals(parseSudoRule(entry), {
    cn: "allow-web-admins",
    description: "Web admins passwordless sudo",
    enabled: true,
    sudoOrder: 50,
    cmdCategory: "all",
    userCategory: undefined,
    hostCategory: undefined,
    memberUsers: ["alice", "jdoe"],
    memberGroups: ["web-admins"],
    memberHosts: ["host1.example.com"],
    memberHostGroups: ["webservers"],
    allowCommands: ["/usr/bin/systemctl"],
    allowCommandGroups: ["net-tools"],
    sudoOptions: ["!authenticate"],
    raw: entry,
  });
});

Deno.test("parseSudoRule() defaults absent optionals sensibly", () => {
  const entry = { cn: ["bare-rule"] };
  assertEquals(parseSudoRule(entry), {
    cn: "bare-rule",
    description: undefined,
    enabled: false,
    sudoOrder: null,
    cmdCategory: undefined,
    userCategory: undefined,
    hostCategory: undefined,
    memberUsers: [],
    memberGroups: [],
    memberHosts: [],
    memberHostGroups: [],
    allowCommands: [],
    allowCommandGroups: [],
    sudoOptions: [],
    raw: entry,
  });
});

Deno.test("isDuplicateEntry() matches by name, code, or message", () => {
  assertEquals(isDuplicateEntry({ name: "DuplicateEntry", code: 4002 }), true);
  assertEquals(isDuplicateEntry({ code: 4002 }), true);
  assertEquals(
    isDuplicateEntry(new Error("IPA sudorule_add failed: DuplicateEntry: x")),
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
    isNotFound(new Error("IPA sudorule_del failed: NotFound: x (code 4001)")),
    true,
  );
  assertEquals(isNotFound("… (code 4001)"), true);
  assertEquals(isNotFound({ name: "DuplicateEntry", code: 4002 }), false);
  assertEquals(isNotFound(new Error("boom")), false);
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
 * keyed by IPA command (e.g. `sudorule_add`). A handler value is an
 * {@link Envelope} (or a thunk returning one); an unmapped command is a test
 * bug and throws.
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

/** A minimal parsed IPA sudo rule entry for result payloads. */
const webRuleEntry = {
  cn: ["allow-web"],
  ipaenabledflag: ["TRUE"],
  sudoorder: ["10"],
  cmdcategory: ["all"],
};

Deno.test("sudoRuleFind: snapshots matched rules into a `sudoRules` resource", async () => {
  const mock = installFetch({
    sudorule_find: ok({
      result: [webRuleEntry],
      count: 1,
      summary: "1 sudo rule matched",
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleFind.execute({ criteria: "web" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_find"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "sudoRules");
    assertEquals((writes[0].data.sudoRules as unknown[]).length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleShow: snapshots a single rule into a `sudoRule` resource", async () => {
  const mock = installFetch({ sudorule_show: ok({ result: webRuleEntry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleShow.execute({ cn: "allow-web" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_show"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "sudoRule");
    assertEquals(
      (writes[0].data.sudoRule as { cn: string }).cn,
      "allow-web",
    );
  } finally {
    mock.restore();
  }
});

Deno.test("ensureSudoRule: writes attempt(success) then rule state, in order", async () => {
  const mock = installFetch({ sudorule_add: ok({ result: webRuleEntry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureSudoRule.execute(
      { cn: "allow-web", sudoOrder: 10, cmdCategory: "all" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_add"]);
    // sudoorder is a first-class arg — assert it reaches the IPA options.
    const addCall = mock.jsonCalls.find((c) => c.command === "sudorule_add");
    assertEquals(
      (addCall!.params as [string[], Record<string, unknown>])[1].sudoorder,
      10,
    );
    assertEquals(writes.map((w) => w.spec), ["attempt", "sudoRule"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(writes[0].data.error, null);
    assertEquals(
      (writes[0].data.response as { result: unknown }).result != null,
      true,
    );
  } finally {
    mock.restore();
  }
});

Deno.test("ensureSudoRule idempotent: DuplicateEntry re-reads and records success", async () => {
  // sudorule_add reports the rule exists; the idempotent path re-reads via
  // sudorule_show and records the attempt as a success no-op.
  const mock = installFetch({
    sudorule_add: err("DuplicateEntry", "sudo rule allow-web exists", 4002),
    sudorule_show: ok({ result: webRuleEntry }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureSudoRule.execute({ cn: "allow-web" }, context);
    // The duplicate is caught inside the attempt, so show follows add.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "sudorule_add",
      "sudorule_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "sudoRule"]);
    assertEquals(writes[0].data.success, true);
    assertEquals((writes[1].data.sudoRule as { cn: string }).cn, "allow-web");
  } finally {
    mock.restore();
  }
});

Deno.test("ensureSudoRule: records attempt(failure) and rethrows; no state", async () => {
  const mock = installFetch({
    sudorule_add: err("ExecutionError", "backend unavailable", 4203),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () => model.methods.ensureSudoRule.execute({ cn: "allow-web" }, context),
      Error,
      "sudorule_add failed",
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

Deno.test("sudoRuleAddOption: audits and re-writes rule state", async () => {
  const optioned = { ...webRuleEntry, ipasudoopt: ["!authenticate"] };
  const mock = installFetch({
    sudorule_add_option: ok({ result: optioned }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleAddOption.execute(
      { cn: "allow-web", option: "!authenticate" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_add_option"]);
    const call = mock.jsonCalls[0];
    assertEquals(
      (call.params as [string[], Record<string, unknown>])[1].ipasudoopt,
      "!authenticate",
    );
    assertEquals(writes.map((w) => w.spec), ["attempt", "sudoRule"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(
      (writes[1].data.sudoRule as { sudoOptions: string[] }).sudoOptions,
      ["!authenticate"],
    );
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleAddUser: fan-out multi-element lists reach IPA params", async () => {
  const withUsers = {
    ...webRuleEntry,
    memberuser_user: ["alice", "jdoe"],
    memberuser_group: ["web-admins"],
  };
  const mock = installFetch({
    sudorule_add_user: ok({
      completed: 3,
      failed: {},
      result: withUsers,
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleAddUser.execute(
      {
        cn: "allow-web",
        users: ["alice", "jdoe"],
        groups: ["web-admins"],
      },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_add_user"]);
    const call = mock.jsonCalls[0];
    const opts = (call.params as [string[], Record<string, unknown>])[1];
    assertEquals(opts.user, ["alice", "jdoe"]);
    assertEquals(opts.group, ["web-admins"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "sudoRule"]);
    assertEquals(writes[0].data.success, true);
    // The `completed`/`failed` structure is surfaced in the audit response.
    assertEquals(
      (writes[0].data.response as { completed: unknown }).completed,
      3,
    );
    assertEquals(
      (writes[1].data.sudoRule as { memberUsers: string[] }).memberUsers,
      ["alice", "jdoe"],
    );
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleAddHost: fan-out hosts + hostgroups reach IPA params", async () => {
  const withHosts = {
    ...webRuleEntry,
    memberhost_host: ["host1.example.com", "host2.example.com"],
    memberhost_hostgroup: ["webservers"],
  };
  const mock = installFetch({
    sudorule_add_host: ok({ completed: 3, failed: {}, result: withHosts }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleAddHost.execute(
      {
        cn: "allow-web",
        hosts: ["host1.example.com", "host2.example.com"],
        hostgroups: ["webservers"],
      },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_add_host"]);
    const opts =
      (mock.jsonCalls[0].params as [string[], Record<string, unknown>])[1];
    assertEquals(opts.host, ["host1.example.com", "host2.example.com"]);
    assertEquals(opts.hostgroup, ["webservers"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "sudoRule"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleAddCommand: fan-out commands reach the allow_command call", async () => {
  const withCmds = {
    ...webRuleEntry,
    memberallowcmd_sudocmd: ["/usr/bin/systemctl", "/usr/bin/journalctl"],
  };
  const mock = installFetch({
    sudorule_add_allow_command: ok({
      completed: 2,
      failed: {},
      result: withCmds,
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleAddCommand.execute(
      {
        cn: "allow-web",
        commands: ["/usr/bin/systemctl", "/usr/bin/journalctl"],
        commandGroups: ["net-tools"],
      },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "sudorule_add_allow_command",
    ]);
    const opts =
      (mock.jsonCalls[0].params as [string[], Record<string, unknown>])[1];
    assertEquals(opts.sudocmd, ["/usr/bin/systemctl", "/usr/bin/journalctl"]);
    assertEquals(opts.sudocmdgroup, ["net-tools"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "sudoRule"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleSetEnabled: audits the toggle then re-reads rule state", async () => {
  const mock = installFetch({
    sudorule_disable: ok({ result: true, value: "allow-web", summary: "Off" }),
    sudorule_show: ok({
      result: { ...webRuleEntry, ipaenabledflag: ["FALSE"] },
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleSetEnabled.execute(
      { cn: "allow-web", enabled: false },
      context,
    );
    // Toggle command, then a fresh sudorule_show to reflect the new state.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "sudorule_disable",
      "sudorule_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "sudoRule"]);
    assertEquals(writes[0].data.method, "sudorule_disable");
    assertEquals(
      (writes[1].data.sudoRule as { enabled: boolean }).enabled,
      false,
    );
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleDel: confirm:false throws before any transport or write", async () => {
  const mock = installFetch({});
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.sudoRuleDel.execute(
          { cn: "allow-web", confirm: false },
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

Deno.test("sudoRuleDel: confirm:true audits the delete, writes no state", async () => {
  const mock = installFetch({
    sudorule_del: ok({
      result: true,
      value: ["allow-web"],
      summary: "Deleted sudo rule allow-web",
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleDel.execute(
      { cn: "allow-web", confirm: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_del"]);
    // Delete produces only the audit record — there is no live rule to snapshot.
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleDel idempotent: NotFound records success, no state", async () => {
  const mock = installFetch({
    sudorule_del: err("NotFound", "sudo rule gone not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.sudoRuleDel.execute(
      { cn: "gone", confirm: true, idempotent: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["sudorule_del"]);
    // No live rule to snapshot: audit-only, but a success no-op.
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

Deno.test("sudoRuleDel non-idempotent: NotFound still fails (default preserved)", async () => {
  const mock = installFetch({
    sudorule_del: err("NotFound", "sudo rule gone not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.sudoRuleDel.execute(
          { cn: "gone", confirm: true },
          context,
        ),
      Error,
      "sudorule_del failed",
    );
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
  } finally {
    mock.restore();
  }
});

Deno.test("sudoRuleDel idempotent still honors the confirm guard", async () => {
  const mock = installFetch({});
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.sudoRuleDel.execute(
          { cn: "allow-web", confirm: false, idempotent: true },
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
