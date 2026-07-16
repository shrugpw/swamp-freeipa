/**
 * Unit tests for the `@shrug/freeipa/cert` model.
 *
 * Two layers:
 *  - The pure value-shaping/parse logic, the PEM-vs-path discriminator, the
 *    JSON-RPC body builder, and deterministic in-process CSR generation via
 *    WebCrypto + `@peculiar/x509` (no network).
 *  - The method execute paths (find/show/certRequest/revoke) driven through a
 *    mocked transport. The model's one network seam is `ipaLogin()` over the
 *    global `fetch`; {@link installFetch} stubs `fetch` to return IPA JSON-RPC
 *    envelopes so the methods run hermetically. The cert-specific invariant
 *    under test is that certRequest persists the IRREPLACEABLE private key into
 *    the `cert` state resource on success (and never into the audit trail), and
 *    that a failed issuance persists only the failure audit — a key with no
 *    signed cert is worthless, so it is deliberately not saved as state.
 *
 * @module
 */
import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import * as x509 from "npm:@peculiar/x509@1.12.3";
import {
  buildRpcBody,
  generateCsr,
  looksLikePem,
  model,
  one,
  parseCertRow,
  toCertPem,
} from "./cert.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["12345"]), "12345");
  assertEquals(one("scalar"), "scalar");
  assertEquals(one([]), undefined);
  assertEquals(one(undefined), undefined);
});

Deno.test("buildRpcBody() shapes the IPA JSON-RPC envelope", () => {
  assertEquals(buildRpcBody("cert_show", [7], { all: true }, "2.254"), {
    method: "cert_show/1",
    params: [[7], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("parseCertRow() flattens a cert result row", () => {
  const raw = {
    serial_number: ["268369921"],
    subject: ["CN=alice,O=EXAMPLE.COM"],
    issuer: ["CN=Certificate Authority,O=EXAMPLE.COM"],
    status: ["VALID"],
    revoked: [false],
    valid_not_before: ["Thu Jul 10 00:00:00 2026 UTC"],
    valid_not_after: ["Fri Jul 10 00:00:00 2028 UTC"],
  };
  assertEquals(parseCertRow(raw), {
    serialNumber: "268369921",
    subject: "CN=alice,O=EXAMPLE.COM",
    issuer: "CN=Certificate Authority,O=EXAMPLE.COM",
    status: "VALID",
    revoked: false,
    notBefore: "Thu Jul 10 00:00:00 2026 UTC",
    notAfter: "Fri Jul 10 00:00:00 2028 UTC",
    raw,
  });
});

Deno.test("parseCertRow() maps missing revoked to null and a revoked cert to true", () => {
  assertEquals(parseCertRow({ serial_number: ["1"] }).revoked, null);
  assertEquals(
    parseCertRow({ serial_number: ["2"], revoked: [true] }).revoked,
    true,
  );
});

Deno.test("looksLikePem() discriminates inline PEM from a filesystem path", () => {
  assertEquals(
    looksLikePem(
      "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
    ),
    true,
  );
  assertEquals(
    looksLikePem("-----BEGIN NEW CERTIFICATE REQUEST-----\nx"),
    true,
  );
  assertEquals(looksLikePem("/etc/ipa/requests/alice.csr"), false);
  assertEquals(looksLikePem("./alice.csr"), false);
  assertEquals(looksLikePem("alice.csr"), false);
});

Deno.test("toCertPem() wraps bare base64 DER and passes PEM through", () => {
  const bare = "MIIByjCCATOgAwIBAgIEEAABAAABBBBB"; // not real, just base64-ish
  const pem = toCertPem(bare);
  assertStringIncludes(pem, "-----BEGIN CERTIFICATE-----");
  assertStringIncludes(pem, "-----END CERTIFICATE-----");
  assertStringIncludes(pem, bare);

  const already =
    "-----BEGIN CERTIFICATE-----\nMIIByjCC\n-----END CERTIFICATE-----";
  assertEquals(toCertPem(already), already + "\n");
});

Deno.test("generateCsr() defaults to an RSA 2048 CSR with the expected CN", async () => {
  // RSA is the default for stock-IPA compatibility (Dogtag rejects EC by
  // default); the EC path is exercised in the next test.
  const gen = await generateCsr({ subjectCn: "host/laptop.ipa.example.com" });

  assertEquals(gen.algorithm, "rsa");
  assertStringIncludes(gen.csrPem, "-----BEGIN CERTIFICATE REQUEST-----");
  // Exported as PKCS#8, never the legacy "RSA PRIVATE KEY" form.
  assertStringIncludes(gen.privateKeyPem, "-----BEGIN PRIVATE KEY-----");

  // Re-parse with @peculiar/x509; the subject CN must survive the round-trip and
  // the request must self-verify against its own public key.
  const csr = new x509.Pkcs10CertificateRequest(gen.csrPem);
  assertStringIncludes(csr.subject, "host/laptop.ipa.example.com");
  assertStringIncludes(csr.signatureAlgorithm.name, "RSA");
  assertEquals(await csr.verify(), true);
});

Deno.test("generateCsr() honors algorithm=ec (ECDSA P-256)", async () => {
  const gen = await generateCsr({ subjectCn: "alice", algorithm: "ec" });

  assertEquals(gen.algorithm, "ec");
  assertStringIncludes(gen.privateKeyPem, "-----BEGIN PRIVATE KEY-----");
  const csr = new x509.Pkcs10CertificateRequest(gen.csrPem);
  assertStringIncludes(csr.subject, "alice");
  assertEquals(csr.signatureAlgorithm.name, "ECDSA");
  assertEquals(await csr.verify(), true);
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
 * (e.g. `cert_request`). A handler value is an {@link Envelope} (or a thunk
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
      ecProfileId: "ecUserCert",
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

/** A representative issued-cert result row (serial + base64 DER cert). */
const issuedRow = {
  serial_number: ["0x1A"],
  subject: ["CN=alice"],
  issuer: ["CN=Certificate Authority,O=EXAMPLE.COM"],
  status: ["VALID"],
  certificate: "QUJDREVG", // opaque base64; toCertPem only wraps, never parses
  valid_not_before: ["20260101000000Z"],
  valid_not_after: ["20280101000000Z"],
};

Deno.test("find: snapshots matching certs into the `certs` resource", async () => {
  const mock = installFetch({
    cert_find: ok({ result: [issuedRow], count: 1 }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.find.execute({ subject: "CN=alice" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["cert_find"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "certs");
    assertEquals((writes[0].data.certs as unknown[]).length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("show: snapshots a single cert into cert-<serial>", async () => {
  const mock = installFetch({ cert_show: ok({ result: issuedRow }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.show.execute({ serial: "0x1A" }, context);
    assertEquals(mock.jsonCalls.map((c) => c.command), ["cert_show"]);
    assertEquals(writes.length, 1);
    assertEquals(writes[0].spec, "cert");
    assertEquals(writes[0].name, "cert-0x1A");
    // Reading an existing cert never yields a private key.
    assertEquals(writes[0].data.privateKey, undefined);
  } finally {
    mock.restore();
  }
});

Deno.test("certRequest: generated key is persisted in cert state, never in the audit", async () => {
  const mock = installFetch({ cert_request: ok({ result: issuedRow }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.certRequest.execute(
      {
        principal: "alice",
        algorithm: "rsa",
        keySize: 2048,
        addPrincipal: false,
      },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["cert_request"]);
    // recordAttempt writes the audit first; the irreplaceable cert+key second.
    assertEquals(writes.map((w) => w.spec), ["attempt", "cert"]);

    const attempt = writes[0];
    const cert = writes[1];
    assertEquals(attempt.data.success, true);
    // The generated private key lands ONLY in the cert state resource.
    assertStringIncludes(
      cert.data.privateKey as string,
      "-----BEGIN PRIVATE KEY-----",
    );
    assertEquals(cert.name, "cert-0x1A");
    // The audit records that a key was generated, but never the key material.
    assertEquals(
      (attempt.data.request as { keyGenerated: boolean }).keyGenerated,
      true,
    );
    assertEquals(JSON.stringify(attempt.data).includes("PRIVATE KEY"), false);
  } finally {
    mock.restore();
  }
});

Deno.test("certRequest: algorithm=ec auto-selects ecProfileId when no explicit profileId", async () => {
  const mock = installFetch({ cert_request: ok({ result: issuedRow }) });
  try {
    const { context } = stubContext();
    await model.methods.certRequest.execute(
      { principal: "alice", algorithm: "ec", keySize: 256, addPrincipal: false },
      context,
    );
    const opts = (mock.jsonCalls[0].params as [
      unknown[],
      Record<string, unknown>,
    ])[1];
    assertEquals(opts.profile_id, "ecUserCert");
  } finally {
    mock.restore();
  }
});

Deno.test("certRequest: explicit profileId wins over the ec auto-select", async () => {
  const mock = installFetch({ cert_request: ok({ result: issuedRow }) });
  try {
    const { context } = stubContext();
    await model.methods.certRequest.execute(
      {
        principal: "alice",
        algorithm: "ec",
        keySize: 256,
        profileId: "customEC",
        addPrincipal: false,
      },
      context,
    );
    const opts = (mock.jsonCalls[0].params as [
      unknown[],
      Record<string, unknown>,
    ])[1];
    assertEquals(opts.profile_id, "customEC");
  } finally {
    mock.restore();
  }
});

Deno.test("certRequest: algorithm=rsa sets no profile_id (stock default)", async () => {
  const mock = installFetch({ cert_request: ok({ result: issuedRow }) });
  try {
    const { context } = stubContext();
    await model.methods.certRequest.execute(
      {
        principal: "alice",
        algorithm: "rsa",
        keySize: 2048,
        addPrincipal: false,
      },
      context,
    );
    const opts = (mock.jsonCalls[0].params as [
      unknown[],
      Record<string, unknown>,
    ])[1];
    assertEquals(opts.profile_id, undefined);
  } finally {
    mock.restore();
  }
});

Deno.test("certRequest: BYO CSR path issues without generating a key", async () => {
  const byoCsr =
    "-----BEGIN CERTIFICATE REQUEST-----\nMIIBogIBADAT\n-----END CERTIFICATE REQUEST-----\n";
  const mock = installFetch({ cert_request: ok({ result: issuedRow }) });
  try {
    const { context, writes } = stubContext();
    await model.methods.certRequest.execute(
      {
        principal: "alice",
        csr: byoCsr,
        algorithm: "rsa",
        keySize: 2048,
        addPrincipal: false,
      },
      context,
    );
    assertEquals(writes.map((w) => w.spec), ["attempt", "cert"]);
    const cert = writes[1];
    // No keypair was generated, so no private key is stored; the submitted CSR
    // is preserved for provenance.
    assertEquals(cert.data.privateKey, undefined);
    assertEquals(cert.data.csr, byoCsr);
    assertEquals(
      (writes[0].data.request as { keyGenerated: boolean }).keyGenerated,
      false,
    );
  } finally {
    mock.restore();
  }
});

Deno.test("certRequest: a failed issuance records only the failure audit", async () => {
  // The keypair is generated before the call, but if cert_request fails there is
  // no signed cert — a bare key is worthless, so no `cert` state is persisted;
  // only the honest failure audit, then a rethrow.
  const mock = installFetch({
    cert_request: err("CertificateOperationError", "CA is unreachable", 4301),
  });
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.certRequest.execute(
          {
            principal: "alice",
            algorithm: "rsa",
            keySize: 2048,
            addPrincipal: false,
          },
          context,
        ),
      Error,
      "cert_request failed",
    );
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, false);
    assertEquals(writes[0].data.response, null);
    assertEquals(JSON.stringify(writes[0].data).includes("PRIVATE KEY"), false);
  } finally {
    mock.restore();
  }
});

Deno.test("revoke: confirm:false throws before any transport or write", async () => {
  const mock = installFetch({});
  try {
    const { context, writes } = stubContext();
    await assertRejects(
      () =>
        model.methods.revoke.execute(
          { serial: "0x1A", confirm: false, reason: 0 },
          context,
        ),
      Error,
      "confirm=true",
    );
    assertEquals(mock.jsonCalls.length, 0);
    assertEquals(writes.length, 0);
  } finally {
    mock.restore();
  }
});

Deno.test("revoke: confirm:true audits the revocation", async () => {
  const mock = installFetch({
    cert_revoke: ok({ result: {}, value: "0x1A", summary: null }),
  });
  try {
    const { context, writes } = stubContext();
    await model.methods.revoke.execute(
      { serial: "0x1A", confirm: true, reason: 1 },
      context,
    );
    assertEquals(mock.jsonCalls.map((c) => c.command), ["cert_revoke"]);
    assertEquals(writes.map((w) => w.spec), ["attempt"]);
    assertEquals(writes[0].data.success, true);
    assertEquals((writes[0].data.request as { reason: number }).reason, 1);
  } finally {
    mock.restore();
  }
});
