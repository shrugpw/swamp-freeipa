/**
 * Unit tests for the `@shrug/freeipa/user` model.
 *
 * Two layers:
 *  - The pure value-shaping helpers (IPA's single-element array unwrapping,
 *    boolean coercion, user-row parsing) and the JSON-RPC body builder.
 *  - The method execute paths (find/show/add/mod/del/setEnabled) driven through
 *    a mocked transport. The model's one network seam is `ipaLogin()` over the
 *    global `fetch`; {@link installFetch} stubs `fetch` to return IPA JSON-RPC
 *    envelopes (including the `login_password` Set-Cookie step) so the methods
 *    run hermetically — no network — and we can assert the write-kernel
 *    contract: an `attempt` audit resource on BOTH success and failure (with a
 *    rethrow on failure), and STATE resources on success only.
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  buildRpcBody,
  model,
  one,
  parseUser,
  toBool,
  toInt,
  toStrArray,
} from "./user.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["jdoe"]), "jdoe");
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
  assertEquals(toStrArray(["admins", "ipausers"]), ["admins", "ipausers"]);
  assertEquals(toStrArray("ipausers"), ["ipausers"]);
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
  assertEquals(buildRpcBody("user_find", [""], { all: true }, "2.254"), {
    method: "user_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("parseUser() flattens a user entry and keeps raw", () => {
  const entry = {
    uid: ["jdoe"],
    givenname: ["John"],
    sn: ["Doe"],
    cn: ["John Doe"],
    mail: ["jdoe@example.com", "j.doe@example.com"],
    nsaccountlock: [true],
    memberof_group: ["admins", "ipausers"],
    dn: "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
  };
  assertEquals(parseUser(entry), {
    uid: "jdoe",
    givenName: "John",
    sn: "Doe",
    cn: "John Doe",
    mail: ["jdoe@example.com", "j.doe@example.com"],
    disabled: true,
    memberOfGroups: ["admins", "ipausers"],
    raw: entry,
  });
});

Deno.test("parseUser() defaults absent optionals sensibly", () => {
  const entry = { uid: ["svc"] };
  assertEquals(parseUser(entry), {
    uid: "svc",
    givenName: undefined,
    sn: undefined,
    cn: undefined,
    mail: [],
    disabled: false,
    memberOfGroups: [],
    raw: entry,
  });
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
 * keyed by IPA command (e.g. `user_add`). A handler value is an {@link Envelope}
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

/** A minimal parsed IPA user entry for result payloads. */
const jdoeEntry = {
  uid: ["jdoe"],
  givenname: ["John"],
  sn: ["Doe"],
  nsaccountlock: [false],
};

Deno.test("find: snapshots matched users into a `users` resource", async () => {
  const mock = installFetch({
    user_find: ok({ result: [jdoeEntry], count: 1, summary: "1 user matched" }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.find.execute({ criteria: "jd" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["user_find"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "users");
    assertEquals((writes[0].data.users as unknown[]).length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("show: snapshots a single user into a `user` resource", async () => {
  const mock = installFetch({ user_show: ok({ result: jdoeEntry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.show.execute({ uid: "jdoe" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["user_show"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "user");
    assertEquals(
      (writes[0].data.user as { uid: string }).uid,
      "jdoe",
    );
  } finally {
    mock.restore();
  }
});

Deno.test("add: writes attempt(success) then the user state, in order", async () => {
  const mock = installFetch({ user_add: ok({ result: jdoeEntry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.add.execute(
      { uid: "jdoe", givenName: "John", sn: "Doe" },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["user_add"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "user"]);
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

Deno.test("add: records attempt(failure) and rethrows; no state resource", async () => {
  const mock = installFetch({
    user_add: err("DuplicateEntry", "user with name jdoe already exists"),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.add.execute(
          { uid: "jdoe", givenName: "John", sn: "Doe" },
          context,
        ),
      Error,
      "user_add failed",
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

Deno.test("mod: writes attempt(success) then the updated user state", async () => {
  const mock = installFetch({ user_mod: ok({ result: jdoeEntry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.mod.execute(
      { uid: "jdoe", set: { mail: ["j@example.com"] } },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["user_mod"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "user"]);
    assertEquals(writes[0].data.success, true);
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
          { uid: "jdoe", confirm: false },
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
    user_del: ok({
      result: true,
      value: ["jdoe"],
      summary: "Deleted user jdoe",
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.del.execute(
      { uid: "jdoe", confirm: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["user_del"]);
    // Delete produces only the audit record — there is no live user to snapshot.
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("setEnabled: audits the toggle then re-reads user state", async () => {
  const mock = installFetch({
    user_disable: ok({ result: true, value: "jdoe", summary: "Disabled" }),
    user_show: ok({ result: { ...jdoeEntry, nsaccountlock: [true] } }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.setEnabled.execute(
      { uid: "jdoe", enabled: false },
      context,
    );
    // Toggle command, then a fresh user_show to reflect the new lock state.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "user_disable",
      "user_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "user"]);
    assertEquals(writes[0].data.method, "user_disable");
    assertEquals((writes[1].data.user as { disabled: boolean }).disabled, true);
  } finally {
    mock.restore();
  }
});
