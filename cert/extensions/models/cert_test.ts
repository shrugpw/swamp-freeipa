/**
 * Unit tests for the pure helpers of the `@shrug/freeipa/cert` model.
 *
 * These cover the value-shaping/parse logic, the PEM-vs-path discriminator, the
 * JSON-RPC body builder, and deterministic in-process CSR generation via
 * WebCrypto + `@peculiar/x509` (no network). The transport seam (`ipaLogin`) and
 * any live cert issue/revoke are intentionally NOT exercised here — this suite
 * never touches IPA or the network.
 *
 * @module
 */
import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import * as x509 from "npm:@peculiar/x509@1.12.3";
import {
  buildRpcBody,
  generateCsr,
  looksLikePem,
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
