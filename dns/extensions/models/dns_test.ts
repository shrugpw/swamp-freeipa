/**
 * Unit tests for the `@shrug/freeipa/dns` model.
 *
 * Two layers:
 *  - The pure value-shaping helpers (IPA's single-element array unwrapping,
 *    boolean coercion, zone/record parsing, the record-type attribute map) and
 *    the JSON-RPC body builder.
 *  - The method execute paths (zoneFind/zoneShow/ensureZone/zoneDel/recordFind/
 *    ensureRecords/recordDel/ensureForwardZone) driven through a mocked
 *    transport. The model's one network seam is `ipaLogin()` over the global
 *    `fetch`; {@link installFetch} stubs `fetch` to return IPA JSON-RPC
 *    envelopes (including the `login_password` Set-Cookie step) so the methods
 *    run hermetically — no network — and we can assert the write-kernel
 *    contract: an `attempt` audit resource on BOTH success and failure (with a
 *    rethrow on failure), STATE resources on success only, and — for the
 *    `ensureRecords` fan-out — an honest partial-apply snapshot.
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  buildRpcBody,
  dnsNameStr,
  isDuplicateEntry,
  isNotFound,
  model,
  one,
  parseRecord,
  parseZone,
  recordAttr,
  toBool,
  toDnsName,
  toDnsNameArray,
  toInt,
  toStrArray,
} from "./dns.ts";

// FreeIPA returns dnszone/dnsrecord names (and name-valued rdata like CNAME
// targets) in a `{ "__dns_name__": "fqdn." }` wire form, NOT as plain strings.
// Fixtures below use that real shape so the parsers are proven against it.
const dn = (s: string) => ({ "__dns_name__": s });

Deno.test("dnsNameStr/toDnsName/toDnsNameArray unwrap IPA __dns_name__ objects", () => {
  assertEquals(dnsNameStr({ "__dns_name__": "example.com." }), "example.com.");
  assertEquals(dnsNameStr("plain.example.com."), "plain.example.com.");
  assertEquals(dnsNameStr(undefined), "");
  assertEquals(
    toDnsName([{ "__dns_name__": "www.example.com." }]),
    "www.example.com.",
  );
  assertEquals(toDnsName(["already-a-string"]), "already-a-string");
  assertEquals(
    toDnsNameArray([{ "__dns_name__": "a.example.com." }, {
      "__dns_name__": "b.example.com.",
    }]),
    ["a.example.com.", "b.example.com."],
  );
  assertEquals(toDnsNameArray(undefined), []);
});

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["example.com."]), "example.com.");
  assertEquals(one("scalar"), "scalar");
  assertEquals(one([]), undefined);
  assertEquals(one(undefined), undefined);
});

Deno.test("toInt() coerces array-wrapped numeric strings", () => {
  assertEquals(toInt(["3600"]), 3600);
  assertEquals(toInt("0"), 0);
  assertEquals(toInt(undefined), null);
  assertEquals(toInt(["not-a-number"]), null);
});

Deno.test("toStrArray() normalizes scalars, arrays, and absence", () => {
  assertEquals(toStrArray(["192.0.2.10", "192.0.2.11"]), [
    "192.0.2.10",
    "192.0.2.11",
  ]);
  assertEquals(toStrArray("192.0.2.10"), ["192.0.2.10"]);
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
  assertEquals(buildRpcBody("dnszone_find", [""], { all: true }, "2.254"), {
    method: "dnszone_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("recordAttr() maps record types to IPA option keys", () => {
  assertEquals(recordAttr("A"), "arecord");
  assertEquals(recordAttr("aaaa"), "aaaarecord");
  assertEquals(recordAttr("CNAME"), "cnamerecord");
  assertEquals(recordAttr("MX"), "mxrecord");
  // Unknown types fall back to the <type>record convention.
  assertEquals(recordAttr("CAA"), "caarecord");
});

Deno.test("parseZone() flattens a zone entry and keeps raw", () => {
  const entry = {
    idnsname: [dn("example.com.")],
    idnszoneactive: ["TRUE"],
    idnsforwarders: ["192.0.2.53"],
    idnsforwardpolicy: ["only"],
    dn: "idnsname=example.com.,cn=dns,dc=example,dc=com",
  };
  assertEquals(parseZone(entry), {
    idnsname: "example.com.",
    active: true,
    forwarders: ["192.0.2.53"],
    forwardPolicy: "only",
    raw: entry,
  });
});

Deno.test("parseZone() defaults absent optionals sensibly", () => {
  const entry = { idnsname: [dn("example.com.")] };
  assertEquals(parseZone(entry), {
    idnsname: "example.com.",
    active: false,
    forwarders: [],
    forwardPolicy: undefined,
    raw: entry,
  });
});

Deno.test("parseRecord() flattens a record entry and keeps raw", () => {
  const entry = {
    idnsname: [dn("www")],
    arecord: ["192.0.2.10"],
    aaaarecord: ["3fff::10"],
    dnsttl: ["3600"],
    dn: "idnsname=www,idnsname=example.com.,cn=dns,dc=example,dc=com",
  };
  assertEquals(parseRecord(entry), {
    idnsname: "www",
    ttl: 3600,
    aRecords: ["192.0.2.10"],
    aaaaRecords: ["3fff::10"],
    cnameRecords: [],
    raw: entry,
  });
});

Deno.test("parseRecord() unwraps a CNAME target from IPA's __dns_name__ form", () => {
  const entry = {
    idnsname: [dn("alias")],
    cnamerecord: [dn("target.example.com.")],
  };
  const parsed = parseRecord(entry);
  assertEquals(parsed.idnsname, "alias");
  assertEquals(parsed.cnameRecords, ["target.example.com."]);
  assertEquals(parsed.aRecords, []);
});

Deno.test("isDuplicateEntry() matches by name, code, or message", () => {
  assertEquals(isDuplicateEntry({ name: "DuplicateEntry", code: 4002 }), true);
  assertEquals(isDuplicateEntry({ code: 4002 }), true);
  assertEquals(
    isDuplicateEntry(new Error("IPA dnszone_add failed: DuplicateEntry: x")),
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
    isNotFound(new Error("IPA dnszone_del failed: NotFound: x (code 4001)")),
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
 * keyed by IPA command (e.g. `dnszone_add`). A handler value is an
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

/** A minimal parsed IPA zone entry for result payloads (real __dns_name__ form). */
const zoneEntry = {
  idnsname: [dn("example.com.")],
  idnszoneactive: ["TRUE"],
};

/** A minimal parsed IPA forward-zone entry for result payloads. */
const forwardZoneEntry = {
  idnsname: [dn("example.com.")],
  idnsforwarders: ["192.0.2.53"],
  idnsforwardpolicy: ["only"],
};

/** Minimal parsed IPA record entries for result payloads. */
const wwwRecord = { idnsname: [dn("www")], arecord: ["192.0.2.10"] };
const apiRecord = { idnsname: [dn("api")], arecord: ["192.0.2.20"] };

Deno.test("zoneFind: snapshots matched zones into a `zones` resource", async () => {
  const mock = installFetch({
    dnszone_find: ok({ result: [zoneEntry], count: 1, summary: "1 zone" }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.zoneFind.execute({ criteria: "example" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnszone_find"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "zones");
    assertEquals((writes[0].data.zones as unknown[]).length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("zoneShow: snapshots a single zone into a `zone` resource", async () => {
  const mock = installFetch({ dnszone_show: ok({ result: zoneEntry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.zoneShow.execute({ idnsname: "example.com." }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnszone_show"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "zone");
    assertEquals(
      (writes[0].data.zone as { idnsname: string }).idnsname,
      "example.com.",
    );
  } finally {
    mock.restore();
  }
});

Deno.test("ensureZone: writes attempt(success) then the zone state, in order", async () => {
  const mock = installFetch({ dnszone_add: ok({ result: zoneEntry }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureZone.execute(
      { idnsname: "example.com." },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnszone_add"]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "zone"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(writes[0].data.error, null);
    assertEquals(
      (writes[1].data.zone as { idnsname: string }).idnsname,
      "example.com.",
    );
  } finally {
    mock.restore();
  }
});

Deno.test("ensureZone idempotent: DuplicateEntry re-reads and records success", async () => {
  const mock = installFetch({
    dnszone_add: err("DuplicateEntry", "zone already exists", 4002),
    dnszone_show: ok({ result: zoneEntry }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureZone.execute(
      { idnsname: "example.com." },
      context,
    );
    // The duplicate is caught inside the attempt, so dnszone_show follows add.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "dnszone_add",
      "dnszone_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "zone"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("ensureZone: hard error records attempt(failure) and rethrows; no state", async () => {
  const mock = installFetch({
    dnszone_add: err("ExecutionError", "backend down", 4203),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.ensureZone.execute({ idnsname: "example.com." }, context),
      Error,
      "dnszone_add failed",
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

Deno.test("zoneDel: confirm:false throws before any transport or write", async () => {
  const mock = installFetch({});
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.zoneDel.execute(
          { idnsname: "example.com.", confirm: false },
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

Deno.test("zoneDel: confirm:true audits the delete, writes no state", async () => {
  const mock = installFetch({
    dnszone_del: ok({
      result: true,
      value: ["example.com."],
      summary: "Deleted",
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.zoneDel.execute(
      { idnsname: "example.com.", confirm: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnszone_del"]);
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("zoneDel idempotent: NotFound records success, no state", async () => {
  const mock = installFetch({
    dnszone_del: err("NotFound", "zone gone not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.zoneDel.execute(
      { idnsname: "gone.example.com.", confirm: true, idempotent: true },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnszone_del"]);
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

Deno.test("recordFind: snapshots a zone's records into a `records` resource", async () => {
  const mock = installFetch({
    dnsrecord_find: ok({ result: [wwwRecord], count: 1 }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.recordFind.execute({ zone: "example.com." }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnsrecord_find"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "records");
    assertEquals(writes[0].data.complete, true);
    assertEquals(writes[0].data.zone, "example.com.");
    assertEquals((writes[0].data.records as unknown[]).length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("ensureRecords fan-out: adds a LIST in one call, snapshots records + record", async () => {
  const mock = installFetch({
    dnsrecord_add: ok({ result: {} }),
    dnsrecord_find: ok({ result: [wwwRecord, apiRecord] }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureRecords.execute(
      {
        zone: "example.com.",
        records: [
          { name: "www", type: "A", data: "192.0.2.10" },
          { name: "api", type: "A", data: "192.0.2.20" },
        ],
      },
      context,
    );
    // Two dnsrecord_add calls (one per record — the fan-out), then a find.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "dnsrecord_add",
      "dnsrecord_add",
      "dnsrecord_find",
    ]);
    const addCalls = mock.jsonCalls.filter((c) =>
      c.command === "dnsrecord_add"
    );
    assertEquals(addCalls.length >= 2, true);
    // The first add carried the A rdata in the IPA `arecord` option.
    assertEquals(
      (addCalls[0].params as [string[], Record<string, unknown>])[1].arecord,
      "192.0.2.10",
    );
    assertEquals(
      (addCalls[1].params as [string[], Record<string, unknown>])[1].arecord,
      "192.0.2.20",
    );
    assertEquals(writes.map((w) => w.spec), ["attempt", "records", "record"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(writes[1].data.complete, true);
    assertEquals((writes[1].data.records as unknown[]).length, 2);
    assertEquals(
      (writes[0].data.request as { count: number }).count,
      2,
    );
  } finally {
    mock.restore();
  }
});

Deno.test("ensureRecords partial failure: dup swallowed, hard fail persists successes then rethrows", async () => {
  let addN = 0;
  const mock = installFetch({
    // First record (www) already exists -> swallowed as a success no-op;
    // second record (api) fails hard -> the batch is a partial apply.
    dnsrecord_add: () =>
      addN++ === 0
        ? err("DuplicateEntry", "www already exists", 4002)
        : err("ExecutionError", "backend rejected api", 4203),
    dnsrecord_find: ok({ result: [wwwRecord] }),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.ensureRecords.execute(
          {
            zone: "example.com.",
            records: [
              { name: "www", type: "A", data: "192.0.2.10" },
              { name: "api", type: "A", data: "192.0.2.20" },
            ],
          },
          context,
        ),
      Error,
      "ensureRecords",
    );
    // Both adds attempted, then a find to capture what actually landed.
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "dnsrecord_add",
      "dnsrecord_add",
      "dnsrecord_find",
    ]);
    // Audit(failure) first, then the PARTIAL records snapshot + the last
    // ensured record — the successes are honestly persisted before the throw.
    assertEquals(writes.map((w) => w.spec), ["attempt", "records", "record"]);
    assertEquals(writes[0].data.success, false);
    assertEquals(writes[1].data.complete, false);
    assertEquals((writes[1].data.records as unknown[]).length, 1);
    assertEquals(
      (writes[2].data.record as { idnsname: string }).idnsname,
      "www",
    );
  } finally {
    mock.restore();
  }
});

Deno.test("recordDel: confirm:false throws before any transport or write", async () => {
  const mock = installFetch({});
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.recordDel.execute(
          {
            zone: "example.com.",
            name: "www",
            type: "A",
            data: "192.0.2.10",
            confirm: false,
          },
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

Deno.test("recordDel: confirm:true audits the delete with the typed rdata option", async () => {
  const mock = installFetch({
    dnsrecord_del: ok({ result: true, value: ["www"], summary: "Deleted" }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.recordDel.execute(
      {
        zone: "example.com.",
        name: "www",
        type: "A",
        data: "192.0.2.10",
        confirm: true,
      },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnsrecord_del"]);
    // The rdata was passed under the IPA `arecord` option.
    assertEquals(
      (mock.jsonCalls[0].params as [string[], Record<string, unknown>])[1]
        .arecord,
      "192.0.2.10",
    );
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});

Deno.test("recordDel idempotent: NotFound records success, no state", async () => {
  const mock = installFetch({
    dnsrecord_del: err("NotFound", "record gone not found", 4001),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.recordDel.execute(
      {
        zone: "example.com.",
        name: "gone",
        type: "A",
        data: "192.0.2.99",
        confirm: true,
        idempotent: true,
      },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnsrecord_del"]);
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

Deno.test("ensureForwardZone: writes attempt(success) then the zone state", async () => {
  const mock = installFetch({
    dnsforwardzone_add: ok({ result: forwardZoneEntry }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureForwardZone.execute(
      {
        idnsname: "example.com.",
        forwarders: ["192.0.2.53"],
        forwardPolicy: "only",
      },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["dnsforwardzone_add"]);
    // The forwarders were passed under the IPA `idnsforwarders` option.
    assertEquals(
      (mock.jsonCalls[0].params as [string[], Record<string, unknown>])[1]
        .idnsforwarders,
      ["192.0.2.53"],
    );
    assertEquals(writes.map((w) => w.spec), ["attempt", "zone"]);
    assertEquals(writes[0].data.success, true);
    assertEquals(
      (writes[1].data.zone as { forwarders: string[] }).forwarders,
      ["192.0.2.53"],
    );
  } finally {
    mock.restore();
  }
});

Deno.test("ensureForwardZone idempotent: DuplicateEntry re-reads and records success", async () => {
  const mock = installFetch({
    dnsforwardzone_add: err("DuplicateEntry", "forward zone exists", 4002),
    dnsforwardzone_show: ok({ result: forwardZoneEntry }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.ensureForwardZone.execute(
      { idnsname: "example.com.", forwarders: ["192.0.2.53"] },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "dnsforwardzone_add",
      "dnsforwardzone_show",
    ]);
    assertEquals(writes.map((w) => w.spec), ["attempt", "zone"]);
    assertEquals(writes[0].data.success, true);
  } finally {
    mock.restore();
  }
});
