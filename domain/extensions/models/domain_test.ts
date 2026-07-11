/**
 * Unit tests for the `@shrug/freeipa/domain` model.
 *
 * Two layers:
 *  - The pure value-shaping/rendering logic (IPA array unwrapping, server/segment
 *    parsing, the Mermaid + markdown renderers) and the JSON-RPC body builder.
 *  - The read-only method execute paths (env/servers/topology) driven through a
 *    mocked transport. The model's one network seam is `ipaLogin()` over the
 *    global `fetch`; {@link installFetch} stubs `fetch` to return IPA JSON-RPC
 *    envelopes so the methods run hermetically — asserting each snapshots its
 *    state resource and issues the expected IPA commands (including topology's
 *    per-suffix segment fan-out).
 *
 * @module
 */
import { assertEquals } from "jsr:@std/assert@1";
import {
  buildRpcBody,
  mermaidNodeId,
  model,
  one,
  parseSegments,
  parseServers,
  renderMarkdown,
  renderTopologyMermaid,
  segmentArrow,
  toInt,
  toStrArray,
} from "./domain.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["ipa2.example.com"]), "ipa2.example.com");
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
  assertEquals(toStrArray(["CA server", "DNS server"]), [
    "CA server",
    "DNS server",
  ]);
  assertEquals(toStrArray("DNS server"), ["DNS server"]);
  assertEquals(toStrArray(undefined), []);
});

Deno.test("buildRpcBody() shapes the IPA JSON-RPC envelope", () => {
  assertEquals(buildRpcBody("server_find", [""], { all: true }, "2.254"), {
    method: "server_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("parseServers() flattens server_find rows", () => {
  const raw = [
    {
      cn: ["ipa1.example.com"],
      ipamindomainlevel: ["0"],
      ipamaxdomainlevel: ["1"],
      enabled_role_servrole: ["CA server", "DNS server"],
      iparepltopomanagedsuffix_topologysuffix: ["domain", "ca"],
    },
    {
      cn: ["ipa2.example.com"],
      ipamindomainlevel: ["0"],
      ipamaxdomainlevel: ["1"],
      // no roles, fallback suffix attribute name
      iparepltopomanagedsuffix: ["domain"],
    },
  ];
  assertEquals(parseServers(raw), [
    {
      fqdn: "ipa1.example.com",
      minDomainLevel: 0,
      maxDomainLevel: 1,
      roles: ["CA server", "DNS server"],
      managedSuffixes: ["domain", "ca"],
    },
    {
      fqdn: "ipa2.example.com",
      minDomainLevel: 0,
      maxDomainLevel: 1,
      roles: [],
      managedSuffixes: ["domain"],
    },
  ]);
});

Deno.test("parseSegments() flattens topologysegment_find edges", () => {
  const raw = [
    {
      cn: ["ipa1-to-ipa2"],
      iparepltoposegmentleftnode: ["ipa1.example.com"],
      iparepltoposegmentrightnode: ["ipa2.example.com"],
      iparepltoposegmentdirection: ["both"],
    },
  ];
  assertEquals(parseSegments("domain", raw), [
    {
      suffix: "domain",
      name: "ipa1-to-ipa2",
      left: "ipa1.example.com",
      right: "ipa2.example.com",
      direction: "both",
    },
  ]);
});

Deno.test("mermaidNodeId() and segmentArrow() sanitize/route", () => {
  assertEquals(
    mermaidNodeId("domain", "ipa1.example.com"),
    "domain_ipa1_example_com",
  );
  assertEquals(segmentArrow("both"), "<-->");
  assertEquals(segmentArrow("left-right"), "-->");
});

Deno.test("renderTopologyMermaid() groups segments into per-suffix subgraphs", () => {
  const mmd = renderTopologyMermaid({
    server: "ipa1.example.com",
    suffixes: [{ name: "domain", managedRoot: null }],
    segments: [
      {
        suffix: "domain",
        name: "f1-to-f2",
        left: "ipa1.example.com",
        right: "ipa2.example.com",
        direction: "both",
      },
    ],
    retrievedAt: "2026-07-10T00:00:00.000Z",
  });
  assertEquals(mmd.startsWith("graph LR"), true);
  assertEquals(mmd.includes("subgraph domain"), true);
  assertEquals(
    mmd.includes("domain_ipa1_example_com <--> domain_ipa2_example_com"),
    true,
  );
});

Deno.test("renderMarkdown() hints when snapshots are missing", () => {
  const md = renderMarkdown(null, null, null);
  assertEquals(md.includes("run the `env` method"), true);
  assertEquals(md.includes("run the `servers` method"), true);
  assertEquals(md.includes("run the `topology` method"), true);
});

// ---------------------------------------------------------------------------
// Mocked-transport harness — drives the read-only method paths without a network.
// ---------------------------------------------------------------------------

/** An IPA JSON-RPC response envelope. */
type Envelope = {
  error: { name?: string; message?: string; code?: number } | null;
  result: Record<string, unknown> | null;
};

/** Build a success envelope wrapping the given `result` payload. */
function ok(result: Record<string, unknown>): Envelope {
  return { error: null, result };
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
  jsonCalls: Array<{ command: string; params: unknown }>;
}

/**
 * Replace the global `fetch` with an in-memory IPA server. The `login_password`
 * step returns a Set-Cookie `ipa_session`; each `/session/json` request is
 * dispatched to `handlers` keyed by IPA command. An unmapped command throws.
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

Deno.test("env: snapshots realm/domain/level into the `config` resource", async () => {
  const mock = installFetch({
    env: ok({
      result: {
        realm: "EXAMPLE.COM",
        domain: "ipa.example.com",
        basedn: "dc=example,dc=com",
        version: "4.12.0",
      },
    }),
    config_show: ok({ result: { ipamaxusernamelength: ["32"] } }),
    domainlevel_get: ok({ result: 1 }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.env.execute({}, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "env",
      "config_show",
      "domainlevel_get",
    ]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "config");
    assertEquals(writes[0].data.realm, "EXAMPLE.COM");
    assertEquals(writes[0].data.domainLevel, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("servers: snapshots the replica inventory into `servers`", async () => {
  const mock = installFetch({
    server_find: ok({
      result: [
        {
          cn: ["ipa1.example.com"],
          enabled_role_servrole: ["CA server", "DNS server"],
        },
        { cn: ["ipa2.example.com"], enabled_role_servrole: ["CA server"] },
      ],
      count: 2,
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.servers.execute({}, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["server_find"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "servers");
    assertEquals((writes[0].data.servers as unknown[]).length, 2);
  } finally {
    mock.restore();
  }
});

Deno.test("topology: fans out topologysegment_find per suffix", async () => {
  const mock = installFetch({
    topologysuffix_find: ok({
      result: [
        { cn: ["domain"], iparepltopoconfroot: ["dc=example,dc=com"] },
        { cn: ["ca"], iparepltopoconfroot: ["o=ipaca"] },
      ],
      count: 2,
    }),
    topologysegment_find: ok({
      result: [
        {
          cn: ["ipa1-to-ipa2"],
          iparepltoposegmentleftnode: ["ipa1.example.com"],
          iparepltoposegmentrightnode: ["ipa2.example.com"],
          iparepltoposegmentdirection: ["both"],
        },
      ],
      count: 1,
    }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.topology.execute({}, context);
    // One suffix find, then one segment find per suffix (2).
    assertEquals(mock.jsonCalls.map((c) => c.command), [
      "topologysuffix_find",
      "topologysegment_find",
      "topologysegment_find",
    ]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "topology");
    assertEquals((writes[0].data.suffixes as unknown[]).length, 2);
    // One segment parsed from each of the two suffixes.
    assertEquals((writes[0].data.segments as unknown[]).length, 2);
  } finally {
    mock.restore();
  }
});
