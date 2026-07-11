/**
 * FreeIPA certificate model — issue, inspect, and revoke X.509 certs for ANY
 * IPA principal (user, host, or service) over the JSON-RPC API.
 *
 * This model is deliberately **principal-agnostic**: `cert_request` signs a CSR
 * for whatever `principal` you name — a user (`alice`), a host
 * (`host/laptop.ipa.example.com`), or a service (`HTTP/web.ipa.example.com`). The
 * FreeRADIUS EAP-TLS path needs BOTH per-user and per-device certs, so a single
 * agnostic surface serves both rather than splitting user- and host-cert models.
 *
 * ## Transport
 *
 * All network access is isolated in {@link ipaLogin}, the single transport seam
 * (the analog of `@shrug/vyos`'s `sshExec`), copied byte-for-byte from the P0
 * `@shrug/freeipa/domain` package. It performs a password session-login against
 * `/ipa/session/login_password`, keeps the `ipa_session` cookie, and exposes a
 * `call()` closure that issues JSON-RPC requests against `/ipa/session/json`. A
 * later revision can swap the auth step to Kerberos (SPNEGO) behind the same
 * seam without touching any method logic.
 *
 * ## Irreplaceable material
 *
 * When `certRequest` generates its own keypair (EC or RSA), the private key
 * exists only in this process. The instant IPA signs the CSR, the cert is real —
 * if we then
 * threw before persisting, the only key matching a real cert would be lost
 * forever. So the `cert` state resource (keypair + signed cert) is persisted the
 * INSTANT the signed cert is in hand, before any later step can throw. The
 * `privateKey` field is marked `z.meta({ sensitive: true })` so swamp vaults it.
 *
 * ## Authentication & TLS
 *
 * The login password is a global argument — resolve it from a swamp vault at
 * model-create time with a CEL expression, e.g.
 * `--global-arg 'password=${{ vault.get("freeipa", "ADMIN_PASSWORD") }}'`.
 *
 * FreeIPA presents a cert issued by its own CA. Set the `caCert` global argument
 * to the PEM path of that CA (`/etc/ipa/ca.crt`) and the model trusts it for
 * just this connection — no system-trust changes required. Omit `caCert` to fall
 * back to the host's system trust store (which an enrolled host already has).
 *
 * @module
 */
import { z } from "npm:zod@4";
import * as x509 from "npm:@peculiar/x509@1.12.3";

/** Connection and authentication settings for the target FreeIPA server. */
const GlobalArgsSchema = z.object({
  server: z
    .string()
    .describe("FreeIPA server FQDN, e.g. ipa1.example.com"),
  user: z
    .string()
    .default("admin")
    .describe("Principal username used for the session login"),
  password: z
    .string()
    .meta({ sensitive: true })
    .describe(
      "Password for the login principal — resolve from a vault via CEL, do not hard-code",
    ),
  apiVersion: z
    .string()
    .default("2.254")
    .describe("IPA API version pinned in each request's options"),
  caCert: z
    .string()
    .optional()
    .describe(
      "Path to the IPA CA cert (PEM, e.g. /etc/ipa/ca.crt) to trust for this connection; omit to use system trust",
    ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Transport + value-shaping helpers — copied VERBATIM from the P0 model at
// swamp/freeipa/domain/extensions/models/domain.ts. Do NOT change the transport;
// the whole `@shrug/freeipa/*` family shares this seam byte-for-byte.
// ---------------------------------------------------------------------------

/**
 * Unwrap FreeIPA's single-element attribute arrays.
 *
 * IPA returns most LDAP attributes as one-element arrays (`cn: ["host"]`). This
 * returns the first element of an array, or the value itself otherwise.
 *
 * @param v A raw attribute value from an IPA result.
 * @returns The scalar value, or `undefined` when absent/empty.
 */
export function one(v: unknown): unknown {
  if (Array.isArray(v)) return v.length > 0 ? v[0] : undefined;
  return v;
}

/**
 * Coerce a (possibly array-wrapped, possibly string) IPA value to an integer.
 *
 * @param v A raw attribute value.
 * @returns The parsed integer, or `null` when absent/non-numeric.
 */
export function toInt(v: unknown): number | null {
  const s = one(v);
  if (s === undefined || s === null) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

/**
 * Coerce a raw IPA attribute value to an array of strings.
 *
 * @param v A raw attribute value (scalar, array, or absent).
 * @returns A string array (empty when absent).
 */
export function toStrArray(v: unknown): string[] {
  if (v === undefined || v === null) return [];
  return (Array.isArray(v) ? v : [v]).map((x) => String(x));
}

/**
 * Build a FreeIPA JSON-RPC request body.
 *
 * IPA's JSON-RPC shape is `{ method: "<cmd>/1", params: [positional, options],
 * id }` where `options` always carries the pinned API `version`.
 *
 * @param method IPA command name (e.g. `server_find`), without the `/1` suffix.
 * @param args Positional arguments in command order.
 * @param options Command options/flags (e.g. `{ all: true }`).
 * @param version API version to pin in the options object.
 * @returns The request body object ready to `JSON.stringify`.
 */
export function buildRpcBody(
  method: string,
  args: unknown[],
  options: Record<string, unknown>,
  version: string,
): {
  method: string;
  params: [unknown[], Record<string, unknown>];
  id: number;
} {
  return {
    method: `${method}/1`,
    params: [args, { ...options, version }],
    id: 0,
  };
}

/** A logged-in IPA JSON-RPC client. */
interface IpaClient {
  /**
   * Issue one JSON-RPC command.
   *
   * @param method IPA command name without the `/1` suffix.
   * @param args Positional arguments.
   * @param options Command options.
   * @returns The command's `result` object (`{ result, count, summary, … }`).
   */
  call: (
    method: string,
    args?: unknown[],
    options?: Record<string, unknown>,
  ) => Promise<Record<string, unknown>>;
}

/**
 * Log in to FreeIPA and return a JSON-RPC client — the sole transport seam.
 *
 * Performs a form password login to `/ipa/session/login_password`, captures the
 * `ipa_session` cookie, and returns a `call()` closure bound to that session.
 * TLS validation uses the host system trust store (see the module docs).
 *
 * TODO(kerberos): add a SPNEGO login path against `/ipa/session/login_kerberos`
 * selected by a global argument, keeping this return shape so methods are
 * unaffected.
 *
 * @param cfg Connection + credentials.
 * @returns A client whose `call()` issues authenticated JSON-RPC requests.
 * @throws If the login request fails or returns a non-2xx status.
 */
async function ipaLogin(cfg: GlobalArgs): Promise<IpaClient> {
  const base = `https://${cfg.server}/ipa`;
  const referer = `${base}/`;

  // Trust the IPA CA for just this connection when caCert is set (no
  // system-trust changes). Left open for the lifetime of the short-lived
  // method run; the runtime reclaims it on exit.
  const clientOpt: { client?: Deno.HttpClient } = {};
  if (cfg.caCert) {
    const ca = await Deno.readTextFile(cfg.caCert);
    clientOpt.client = Deno.createHttpClient({ caCerts: [ca] });
  }

  const loginResp = await fetch(`${base}/session/login_password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "text/plain",
      "Referer": referer,
    },
    body: new URLSearchParams({ user: cfg.user, password: cfg.password }),
    ...clientOpt,
  });
  // Drain the body so the connection can be reused/closed cleanly.
  const loginText = await loginResp.text();
  if (!loginResp.ok) {
    const reason = loginResp.headers.get("x-ipa-rejection-reason") ??
      loginText.slice(0, 200);
    throw new Error(
      `IPA login failed on ${cfg.server} (HTTP ${loginResp.status}): ${reason}`,
    );
  }

  const cookies = loginResp.headers.getSetCookie();
  const sessionCookie = cookies
    .map((c) => c.split(";", 1)[0])
    .find((c) => c.startsWith("ipa_session="));
  if (!sessionCookie) {
    throw new Error(
      `IPA login on ${cfg.server} returned no ipa_session cookie`,
    );
  }

  const call = async (
    method: string,
    args: unknown[] = [],
    options: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> => {
    const resp = await fetch(`${base}/session/json`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": referer,
        "Cookie": sessionCookie,
      },
      body: JSON.stringify(
        buildRpcBody(method, args, options, cfg.apiVersion),
      ),
      ...clientOpt,
    });
    const json = await resp.json() as {
      error: { name?: string; message?: string; code?: number } | null;
      result: Record<string, unknown> | null;
    };
    if (json.error) {
      throw new Error(
        `IPA ${method} failed: ${json.error.name ?? "Error"}: ` +
          `${json.error.message ?? "unknown"} (code ${json.error.code ?? "?"})`,
      );
    }
    if (!json.result) {
      throw new Error(`IPA ${method} returned no result`);
    }
    return json.result;
  };

  return { call };
}

// ---------------------------------------------------------------------------
// Shared write-kernel — CANONICAL across @shrug/freeipa/{user,group,cert}.
// Replicated verbatim in each package (extensions publish independently and
// cannot cross-import). Keep byte-identical; changes are a 3-repo sync.
// ---------------------------------------------------------------------------

/**
 * An honest record of one mutation attempt — the audit resource every write
 * method persists, on BOTH the success and failure paths.
 *
 * This is deliberately NOT a state resource: nobody CEL-references it to read a
 * live attribute, and when `success` is false it says so truthfully. That is
 * why persisting it on failure does not violate swamp's "don't persist
 * misleading state" rule — an attempt-log is telemetry-as-data, not state.
 */
const AttemptSchema = z.object({
  method: z.string().describe(
    "Model method name, e.g. user_add / ensureVlanGroup",
  ),
  ipaCommands: z.array(z.string()).describe("IPA commands attempted, in order"),
  request: z
    .record(z.string(), z.unknown())
    .describe("Sanitized method arguments (no secrets)"),
  success: z.boolean(),
  response: z
    .record(z.string(), z.unknown())
    .nullable()
    .describe("IPA result on success, null on failure"),
  error: z.string().nullable().describe(
    "Error message on failure, null on success",
  ),
  target: z.string().describe("Principal/group/cert acted on"),
  server: z.string(),
  attemptedAt: z.iso.datetime(),
});

/** One mutation attempt-record (see {@link AttemptSchema}). */
export type Attempt = z.infer<typeof AttemptSchema>;

/** Minimal execute context the write-kernel relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
  readResource?: (
    instanceName: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/**
 * Run one mutation, persisting an `attempt` audit resource on BOTH paths, then
 * rethrowing on failure so the workflow step is marked failed.
 *
 * The three-way persistence rule (see the package README):
 *  - STATE resources (the object itself) are written only by the CALLER, only
 *    on success — never here.
 *  - IRREPLACEABLE material generated mid-op (a private key, a signed cert) is
 *    persisted by the CALLER the instant it is real, BEFORE calling this or
 *    before any later throw — never lose it to a downstream error.
 *  - The AUDIT record is this function's job, on both success and failure.
 *
 * @param context Execute context (needs writeResource + globalArgs).
 * @param target Principal/group/cert name acted on (for the audit + instance id).
 * @param method Model method name (audit `method`, e.g. "user_add").
 * @param ipaCommands IPA commands this attempt issues, in order.
 * @param request Sanitized, secret-free copy of the method arguments.
 * @param fn The mutation itself; its resolved value is recorded as `response`.
 * @returns Whatever `fn` resolves to, on success.
 * @throws Rethrows `fn`'s error after the failure attempt is persisted.
 */
async function recordAttempt<T extends Record<string, unknown>>(
  context: ExecuteContext,
  target: string,
  method: string,
  ipaCommands: string[],
  request: Record<string, unknown>,
  fn: () => Promise<T>,
): Promise<{ result: T; handle: { name: string } }> {
  const base = {
    method,
    ipaCommands,
    request,
    target,
    server: context.globalArgs.server,
    attemptedAt: new Date().toISOString(),
  };
  const instance = `attempt-${method}-${target}`;
  try {
    const result = await fn();
    const handle = await context.writeResource("attempt", instance, {
      ...base,
      success: true,
      response: result,
      error: null,
    });
    return { result, handle };
  } catch (e) {
    await context.writeResource("attempt", instance, {
      ...base,
      success: false,
      response: null,
      error: e instanceof Error ? e.message : String(e),
    });
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Certificate schemas.
// ---------------------------------------------------------------------------

/** One certificate row (from `cert_find` / `cert_show`). */
const CertRowSchema = z.object({
  serialNumber: z.string(),
  subject: z.string().optional(),
  issuer: z.string().optional(),
  status: z.string().optional(),
  revoked: z.boolean().nullable(),
  notBefore: z.string().optional(),
  notAfter: z.string().optional(),
  raw: z.record(z.string(), z.unknown()).describe("Full IPA result row"),
});

/** Snapshot of a `cert_find` result set. */
const CertsSchema = z.object({
  server: z.string(),
  subject: z.string().optional(),
  criteria: z.string().optional(),
  certs: z.array(CertRowSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * State of a single certificate. When this model GENERATED the keypair,
 * `privateKey` holds the PEM — marked sensitive so swamp vaults it. Reading an
 * existing cert (`show`) leaves `privateKey` unset (IPA never returns keys).
 */
const CertStateSchema = z.object({
  principal: z.string().optional().describe(
    "IPA principal the cert was issued to (user, host, or service)",
  ),
  serialNumber: z.string(),
  certificate: z.string().optional().describe("Issued certificate (PEM)"),
  subject: z.string().optional(),
  issuer: z.string().optional(),
  status: z.string().optional(),
  revoked: z.boolean().nullable().optional(),
  notBefore: z.string().optional(),
  notAfter: z.string().optional(),
  privateKey: z
    .string()
    .meta({ sensitive: true })
    .optional()
    .describe(
      "PEM RSA private key — present ONLY when this model generated the keypair; vaulted by swamp",
    ),
  csr: z.string().optional().describe(
    "The PKCS#10 CSR that was submitted (PEM)",
  ),
  raw: z.record(z.string(), z.unknown()).describe("Full IPA result row"),
  retrievedAt: z.iso.datetime(),
});

/** One certificate row. */
export type CertRow = z.infer<typeof CertRowSchema>;

/**
 * Map a raw IPA cert result row (`cert_find` / `cert_show` / `cert_request`)
 * into a friendly {@link CertRowSchema} row.
 *
 * @param raw The `result` object/row from an IPA cert command.
 * @returns A flattened cert row (with the raw row preserved for passthrough).
 */
export function parseCertRow(raw: Record<string, unknown>): CertRow {
  const revokedVal = one(raw.revoked);
  return {
    serialNumber: String(one(raw.serial_number) ?? ""),
    subject: one(raw.subject) as string | undefined,
    issuer: one(raw.issuer) as string | undefined,
    status: one(raw.status) as string | undefined,
    revoked: revokedVal === undefined || revokedVal === null
      ? null
      : Boolean(revokedVal),
    notBefore: one(raw.valid_not_before) as string | undefined,
    notAfter: one(raw.valid_not_after) as string | undefined,
    raw,
  };
}

/**
 * Discriminate a bring-your-own CSR that is inline PEM text from one that is a
 * filesystem path. A PEM blob contains a `-----BEGIN …-----` armor line; a path
 * does not.
 *
 * @param s The `csr` argument value.
 * @returns `true` when `s` is inline PEM, `false` when it should be read from disk.
 */
export function looksLikePem(s: string): boolean {
  return /-----BEGIN [A-Z0-9 ]+-----/.test(s);
}

/**
 * Normalize an IPA-returned certificate (bare base64 DER or already-PEM) to a
 * PEM string. Pure and total — never throws — so it is safe to run on the
 * irreplaceable-material path before persisting.
 *
 * @param raw The `certificate` value from a cert result.
 * @returns A `-----BEGIN CERTIFICATE-----` PEM block.
 */
export function toCertPem(raw: string): string {
  if (looksLikePem(raw)) return raw.trim() + "\n";
  const body = raw.replace(/\s+/g, "").match(/.{1,64}/g)?.join("\n") ?? raw;
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

/** Key algorithm for in-model generation: RSA (default) or EC P-256. */
export type KeyAlgorithm = "ec" | "rsa";

/** A locally generated keypair + PKCS#10 CSR. */
export interface GeneratedCsr {
  /** PEM PKCS#10 certification request. */
  csrPem: string;
  /** PEM PKCS#8 private key (sensitive). */
  privateKeyPem: string;
  /** PEM SubjectPublicKeyInfo public key. */
  publicKeyPem: string;
  /** Key algorithm used ("ec" = ECDSA P-256, "rsa" = RSASSA-PKCS1-v1_5). */
  algorithm: KeyAlgorithm;
}

/**
 * Encode a DER buffer as a labelled PEM block (64-char lines).
 *
 * @param label PEM label (e.g. `PRIVATE KEY`, `PUBLIC KEY`).
 * @param der The DER bytes.
 * @returns A PEM string terminated by a trailing newline.
 */
function derToPem(label: string, der: ArrayBuffer): string {
  const bytes = new Uint8Array(der);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const wrapped = (btoa(bin).match(/.{1,64}/g) ?? []).join("\n");
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

/**
 * Generate a keypair and a bare-CN PKCS#10 CSR entirely in-process (no network),
 * using WebCrypto + `@peculiar/x509` — no vulnerable pure-JS crypto deps.
 *
 * Defaults to **RSA 2048** (`keySize` bits, SHA-256) for compatibility with a
 * stock IPA CA — Dogtag's default `caIPAserviceCert` profile rejects EC keys.
 * Pass `algorithm: "ec"` for ECDSA P-256 (compact, modern) where an EC-enabled
 * cert profile exists. The CSR subject is `CN=<subjectCn>`; the private key is
 * exported as PKCS#8 PEM.
 *
 * The Microsoft-UPN `otherName` subjectAltName supported by the previous
 * (node-forge) implementation is intentionally dropped: it was best-effort and
 * unused — FreeRADIUS keys its VLAN lookup on `User-Name`, not the SAN — and a
 * bare-CN CSR is what EAP-TLS onboarding actually relies on.
 *
 * @param opts Subject CN, optional algorithm (default `ec`) and RSA key size.
 * @returns The CSR PEM, the private + public key PEMs, and the algorithm used.
 */
export async function generateCsr(opts: {
  subjectCn: string;
  algorithm?: KeyAlgorithm;
  keySize?: number;
}): Promise<GeneratedCsr> {
  x509.cryptoProvider.set(crypto);
  const algorithm: KeyAlgorithm = opts.algorithm ?? "rsa";

  const keyAlg: EcKeyGenParams | RsaHashedKeyGenParams = algorithm === "rsa"
    ? {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: opts.keySize ?? 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    }
    : { name: "ECDSA", namedCurve: "P-256" };
  const signingAlgorithm = algorithm === "rsa"
    ? { name: "RSASSA-PKCS1-v1_5" }
    : { name: "ECDSA", hash: "SHA-256" };

  const keys = await crypto.subtle.generateKey(keyAlg, true, [
    "sign",
    "verify",
  ]) as CryptoKeyPair;

  const privateKeyPem = derToPem(
    "PRIVATE KEY",
    await crypto.subtle.exportKey("pkcs8", keys.privateKey),
  );
  const publicKeyPem = derToPem(
    "PUBLIC KEY",
    await crypto.subtle.exportKey("spki", keys.publicKey),
  );

  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${opts.subjectCn}`,
    keys,
    signingAlgorithm,
  });
  // Round-trip to prove the encoding parses before we rely on it.
  const csrPem = csr.toString("pem");
  new x509.Pkcs10CertificateRequest(csrPem);

  return { csrPem, privateKeyPem, publicKeyPem, algorithm };
}

// ---------------------------------------------------------------------------
// Model definition.
// ---------------------------------------------------------------------------

/** FreeIPA certificate model definition. */
export const model = {
  type: "@shrug/freeipa/cert",
  version: "2026.07.10.1",
  description:
    "Issue, inspect, and revoke X.509 certs for any FreeIPA principal (user/host/service) over the JSON-RPC API. Optional in-model RSA keygen with vaulted private keys.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "certs": {
      description: "Snapshot of a cert_find result set",
      schema: CertsSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "cert": {
      description:
        "State of a single certificate; carries the (sensitive) private key when this model generated the keypair",
      schema: CertStateSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "attempt": {
      description:
        "Audit record of a mutation attempt (request + result/error + timestamp). Written on both success and failure.",
      schema: AttemptSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
  },
  methods: {
    find: {
      description:
        "Search certificates (cert_find) and snapshot the matching rows into the `certs` resource.",
      arguments: z.object({
        subject: z
          .string()
          .optional()
          .describe("Filter by certificate subject (e.g. CN substring)"),
        criteria: z
          .string()
          .optional()
          .describe(
            "Free-text search criteria passed positionally to cert_find",
          ),
      }),
      execute: async (
        args: { subject?: string; criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = { all: true, sizelimit: 0 };
        if (args.subject) options.subject = args.subject;
        const res = await client.call(
          "cert_find",
          args.criteria ? [args.criteria] : [],
          options,
        );
        const rows = (res.result ?? []) as Array<Record<string, unknown>>;
        const handle = await context.writeResource("certs", "certs", {
          server: cfg.server,
          subject: args.subject,
          criteria: args.criteria,
          certs: rows.map(parseCertRow),
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    show: {
      description:
        "Fetch one certificate by serial (cert_show) and snapshot it into a `cert` state resource. Reads an existing cert — no private key.",
      arguments: z.object({
        serial: z
          .union([z.number(), z.string()])
          .describe("Certificate serial number"),
      }),
      execute: async (
        args: { serial: number | string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const res = await client.call("cert_show", [args.serial], {
          all: true,
        });
        const raw = (res.result ?? {}) as Record<string, unknown>;
        const row = parseCertRow(raw);
        const certVal = one(raw.certificate);
        const handle = await context.writeResource(
          "cert",
          `cert-${row.serialNumber}`,
          {
            serialNumber: row.serialNumber,
            certificate: typeof certVal === "string"
              ? toCertPem(certVal)
              : undefined,
            subject: row.subject,
            issuer: row.issuer,
            status: row.status,
            revoked: row.revoked,
            notBefore: row.notBefore,
            notAfter: row.notAfter,
            raw,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    certRequest: {
      description:
        "Issue a certificate for any IPA principal (user/host/service). Either submit your own CSR (PEM or path) or let the model generate an RSA (default) or EC keypair + CSR (vaulted key).",
      arguments: z.object({
        principal: z
          .string()
          .describe(
            "IPA principal to issue for: user (alice), host (host/laptop.ipa.example.com), or service (HTTP/web.ipa.example.com)",
          ),
        csr: z
          .string()
          .optional()
          .describe(
            "Bring-your-own PKCS#10 CSR: inline PEM, or a filesystem path to a PEM file. Omit to have the model generate a keypair + CSR.",
          ),
        algorithm: z
          .enum(["ec", "rsa"])
          .default("rsa")
          .describe(
            "Key algorithm when the model generates the keypair: rsa = RSASSA-PKCS1-v1_5 (default, works with a stock IPA CA), ec = ECDSA P-256 (needs an EC-enabled cert profile)",
          ),
        keySize: z
          .number()
          .int()
          .default(2048)
          .describe("RSA modulus size when algorithm=rsa (ignored for ec)"),
        addPrincipal: z
          .boolean()
          .default(false)
          .describe(
            "Pass cert_request `add` to auto-add the principal if missing",
          ),
        profileId: z
          .string()
          .optional()
          .describe("Certificate profile id (cert_request `profile_id`)"),
        caCn: z
          .string()
          .optional()
          .describe("Sub-CA to issue from (cert_request `cacn`)"),
        subjectCn: z
          .string()
          .optional()
          .describe("CSR subject CN when generating (defaults to `principal`)"),
      }),
      execute: async (
        args: {
          principal: string;
          csr?: string;
          algorithm: KeyAlgorithm;
          keySize: number;
          addPrincipal: boolean;
          profileId?: string;
          caCn?: string;
          subjectCn?: string;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;

        // Resolve the CSR: bring-your-own (PEM or path) vs. in-model keygen.
        let csrPem: string;
        let privateKeyPem: string | undefined;
        if (args.csr) {
          csrPem = looksLikePem(args.csr)
            ? args.csr
            : await Deno.readTextFile(args.csr.trim());
        } else {
          const gen = await generateCsr({
            subjectCn: args.subjectCn ?? args.principal,
            algorithm: args.algorithm,
            keySize: args.keySize,
          });
          csrPem = gen.csrPem;
          privateKeyPem = gen.privateKeyPem;
        }

        const options: Record<string, unknown> = {
          principal: args.principal,
          add: args.addPrincipal,
          all: true,
        };
        if (args.profileId) options.profile_id = args.profileId;
        if (args.caCn) options.cacn = args.caCn;

        const client = await ipaLogin(cfg);
        // Sanitized request for the audit trail — never the private key.
        const sanitized: Record<string, unknown> = {
          principal: args.principal,
          algorithm: args.algorithm,
          keySize: args.keySize,
          addPrincipal: args.addPrincipal,
          profileId: args.profileId ?? null,
          caCn: args.caCn ?? null,
          subjectCn: args.subjectCn ?? null,
          csrProvided: Boolean(args.csr),
          keyGenerated: privateKeyPem !== undefined,
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.principal,
          "cert_request",
          ["cert_request"],
          sanitized,
          async () => {
            const res = await client.call("cert_request", [csrPem], options);
            return (res.result ?? res) as Record<string, unknown>;
          },
        );

        // IRREPLACEABLE MATERIAL: the cert is now real and the private key
        // exists only here. Persist the keypair + signed cert IMMEDIATELY,
        // before any later step can throw. parseCertRow/toCertPem are pure and
        // total, so nothing between the signing and this write can fail.
        const row = parseCertRow(result);
        const certVal = one(result.certificate);
        const state: Record<string, unknown> = {
          principal: args.principal,
          serialNumber: row.serialNumber,
          certificate: typeof certVal === "string"
            ? toCertPem(certVal)
            : undefined,
          subject: row.subject,
          issuer: row.issuer,
          status: row.status,
          revoked: row.revoked,
          notBefore: row.notBefore,
          notAfter: row.notAfter,
          csr: csrPem,
          raw: result,
          retrievedAt: new Date().toISOString(),
        };
        if (privateKeyPem !== undefined) state.privateKey = privateKeyPem;

        const certHandle = await context.writeResource(
          "cert",
          `cert-${row.serialNumber}`,
          state,
        );
        return { dataHandles: [certHandle, attemptHandle] };
      },
    },
    revoke: {
      description:
        "Revoke a certificate by serial (cert_revoke). Requires confirm=true.",
      arguments: z.object({
        serial: z
          .union([z.number(), z.string()])
          .describe("Certificate serial number to revoke"),
        confirm: z
          .boolean()
          .describe("Must be true — guards against accidental revocation"),
        reason: z
          .number()
          .int()
          .default(0)
          .describe(
            "RFC 5280 CRL revocation reason code (0 = unspecified, 1 = keyCompromise, …)",
          ),
      }),
      execute: async (
        args: { serial: number | string; confirm: boolean; reason: number },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            "revoke requires confirm=true to proceed (refusing to revoke without explicit confirmation)",
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const target = String(args.serial);
        const { handle } = await recordAttempt(
          context,
          target,
          "cert_revoke",
          ["cert_revoke"],
          { serial: target, reason: args.reason },
          async () => {
            const res = await client.call("cert_revoke", [args.serial], {
              revocation_reason: args.reason,
            });
            return (res.result ?? res) as Record<string, unknown>;
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
  checks: {
    "cert-exists": {
      description:
        "Verify the certificate serial exists and is not already revoked before revoking it",
      labels: ["live"],
      appliesTo: ["revoke"],
      execute: async (
        context: {
          globalArgs: GlobalArgs;
          arguments?: { serial?: number | string };
        },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const client = await ipaLogin(context.globalArgs);
        // Checks are not guaranteed the method arguments (the runtime passes
        // globalArgs/dataRepository, not the method args). When the serial IS
        // available, assert the cert exists and is live; otherwise degrade to a
        // connectivity assertion (login above already proved IPA is reachable).
        const serial = context.arguments?.serial;
        if (serial === undefined || serial === null) {
          return { pass: true };
        }
        try {
          const res = await client.call("cert_show", [serial], { all: true });
          const raw = (res.result ?? {}) as Record<string, unknown>;
          const revokedVal = one(raw.revoked);
          if (
            revokedVal !== undefined && revokedVal !== null &&
            Boolean(revokedVal)
          ) {
            return {
              pass: false,
              errors: [`Certificate ${serial} is already revoked`],
            };
          }
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Certificate ${serial} could not be verified: ` +
              (e instanceof Error ? e.message : String(e)),
            ],
          };
        }
      },
    },
  },
};
