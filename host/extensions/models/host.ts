/**
 * FreeIPA host management model.
 *
 * Connects to an existing FreeIPA server's JSON-RPC API to inspect and manage
 * host (machine) entries. `find`/`show` snapshot hosts read-only; `add`/`mod`/
 * `del`, `sync`, and `disable` mutate them. Every mutation records an honest
 * `attempt` audit resource on BOTH the success and failure paths (see
 * {@link recordAttempt}), the state resources (`host`/`hosts`) are written only
 * on success, and the destructive `del` is gated behind an explicit `confirm`
 * flag plus a `live` pre-flight existence check. This is the host surface of the
 * `@shrug/freeipa/*` family.
 *
 * ## Enrollment OTP (irreplaceable material)
 *
 * `add` with `random:true` asks IPA to generate a one-time enrollment password
 * (`randompassword`). It is returned exactly once and can never be re-read, so
 * it is treated like a signed cert's private key: captured out of the IPA
 * response, persisted onto the `host` STATE resource in a `randomPassword` field
 * marked `z.meta({ sensitive: true })` (so swamp vaults it) the instant it is
 * real — before any later throw — and deliberately kept OUT of the `attempt`
 * audit's request and response.
 *
 * ## Transport
 *
 * All network access is isolated in {@link ipaLogin}, the single transport seam
 * (the analog of `@shrug/vyos`'s `sshExec`). It performs a password
 * session-login against `/ipa/session/login_password`, keeps the `ipa_session`
 * cookie, and exposes a `call()` closure that issues JSON-RPC requests against
 * `/ipa/session/json`. A later revision can swap the auth step to Kerberos
 * (SPNEGO) behind the same seam without touching any method logic.
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

/**
 * The structural slice of swamp's LogTape logger the write-kernel and methods
 * use. Declared locally (not imported) so the kernel stays self-contained and
 * byte-identical across the family. Messages use `{name}` placeholders filled
 * from the properties object — never string interpolation, and never secrets.
 */
interface MethodLogger {
  debug(message: string, properties?: Record<string, unknown>): void;
  info(message: string, properties?: Record<string, unknown>): void;
  warning(message: string, properties?: Record<string, unknown>): void;
  error(message: string, properties?: Record<string, unknown>): void;
}

/** Minimal execute context the write-kernel relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: MethodLogger;
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
  context.logger.info(
    "{method}: applying to {target} on {server}",
    { method, target, server: base.server, ipaCommands },
  );
  try {
    const result = await fn();
    const handle = await context.writeResource("attempt", instance, {
      ...base,
      success: true,
      response: result,
      error: null,
    });
    context.logger.info("{method}: succeeded on {target}", { method, target });
    return { result, handle };
  } catch (e) {
    await context.writeResource("attempt", instance, {
      ...base,
      success: false,
      response: null,
      error: e instanceof Error ? e.message : String(e),
    });
    context.logger.error(
      "{method}: failed on {target}: {error}",
      { method, target, error: e instanceof Error ? e.message : String(e) },
    );
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Host value-shaping — parse IPA host entries into friendly rows.
// ---------------------------------------------------------------------------

/**
 * Coerce a raw IPA boolean-ish value to a boolean.
 *
 * IPA renders booleans as a native `true`/`false` or as the strings
 * `"TRUE"`/`"FALSE"`, sometimes wrapped in a single-element array. Absence
 * means false — an unset `nsaccountlock`, for example, is an enabled account.
 *
 * @param v A raw attribute value.
 * @returns The boolean value; false when absent.
 */
export function toBool(v: unknown): boolean {
  const s = one(v);
  if (s === undefined || s === null) return false;
  if (typeof s === "boolean") return s;
  return String(s).toLowerCase() === "true";
}

/** A parsed FreeIPA host row (single-element IPA arrays unwrapped). */
const HostRowSchema = z.object({
  fqdn: z.string(),
  description: z.string().optional(),
  os: z.string().optional().describe(
    "Operating system string (IPA `nsosversion`)",
  ),
  platform: z.string().optional().describe(
    "Hardware platform (IPA `nshardwareplatform`)",
  ),
  managedByHosts: z.array(z.string()).describe(
    "Hosts that manage this host (IPA `managedby_host`)",
  ),
  memberOfHostGroups: z.array(z.string()).describe(
    "Host groups this host is a direct member of (IPA `memberof_hostgroup`)",
  ),
  hasKeytab: z.boolean().describe(
    "Whether the host has a Kerberos keytab (IPA `has_keytab`)",
  ),
  hasPassword: z.boolean().describe(
    "Whether the host has an enrollment password set (IPA `has_password`)",
  ),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA host entry, unmodified — nothing is lost",
  ),
});

/** A single parsed host + provenance — the `host` state resource. */
const HostSchema = z.object({
  server: z.string(),
  host: HostRowSchema,
  randomPassword: z
    .string()
    .meta({ sensitive: true })
    .optional()
    .describe(
      "One-time enrollment password (IPA `randompassword`), present only when `add` was run with random:true. Irreplaceable — IPA returns it exactly once — so it is vaulted here; it never appears in the audit trail.",
    ),
  retrievedAt: z.iso.datetime(),
});

/** A snapshot of many hosts — the `hosts` state resource. */
const HostsSchema = z.object({
  server: z.string(),
  hosts: z.array(HostRowSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * Map a raw IPA host entry (a `host_find`/`host_show`/`host_add` result row)
 * into a friendly {@link HostRowSchema} row, keeping the untouched entry under
 * `raw` so no attribute is ever lost.
 *
 * @param entry A single host entry from an IPA result.
 * @returns The flattened host row.
 */
export function parseHost(
  entry: Record<string, unknown>,
): z.infer<typeof HostRowSchema> {
  return {
    fqdn: String(one(entry.fqdn) ?? ""),
    description: one(entry.description) as string | undefined,
    os: one(entry.nsosversion) as string | undefined,
    platform: one(entry.nshardwareplatform) as string | undefined,
    managedByHosts: toStrArray(entry.managedby_host),
    memberOfHostGroups: toStrArray(entry.memberof_hostgroup),
    hasKeytab: toBool(entry.has_keytab),
    hasPassword: toBool(entry.has_password),
    raw: entry,
  };
}

/** A parsed host row produced by {@link parseHost}. */
export type HostRow = z.infer<typeof HostRowSchema>;
/** A single-host snapshot resource. */
export type Host = z.infer<typeof HostSchema>;
/** A multi-host snapshot resource. */
export type Hosts = z.infer<typeof HostsSchema>;

/**
 * Predicate: is this error IPA's "entry already exists" (`DuplicateEntry`,
 * code 4002)? Used to make `add` idempotent — a duplicate means the user is
 * already present, which is success for an idempotent create.
 *
 * Accepts the raw IPA error object, an `Error` whose message was formatted by
 * {@link ipaLogin} (`... DuplicateEntry: ... (code 4002)`), or a bare string.
 * Copied verbatim from the family's `group` package (extensions publish
 * independently and cannot cross-import); keep the two in sync.
 *
 * @param e The caught error (any shape).
 * @returns `true` when it represents a duplicate-entry condition.
 */
export function isDuplicateEntry(e: unknown): boolean {
  const matches = (s: string) =>
    /DuplicateEntry/i.test(s) || /\bcode 4002\b/.test(s);
  if (e && typeof e === "object") {
    const obj = e as { name?: unknown; code?: unknown; message?: unknown };
    if (obj.name === "DuplicateEntry") return true;
    if (obj.code === 4002) return true;
    if (typeof obj.message === "string" && matches(obj.message)) return true;
    return false;
  }
  if (typeof e === "string") return matches(e);
  return false;
}

/**
 * Predicate: is this error IPA's "no such entry" (`NotFound`, code 4001)? The
 * mirror of {@link isDuplicateEntry} — used to make `del` idempotent, where a
 * missing target means it is already gone, which is success for an idempotent
 * delete.
 *
 * Accepts the raw IPA error object, an `Error` whose message was formatted by
 * {@link ipaLogin} (`... NotFound: ... (code 4001)`), or a bare string.
 *
 * @param e The caught error (any shape).
 * @returns `true` when it represents a not-found condition.
 */
export function isNotFound(e: unknown): boolean {
  const matches = (s: string) => /NotFound/i.test(s) || /\bcode 4001\b/.test(s);
  if (e && typeof e === "object") {
    const obj = e as { name?: unknown; code?: unknown; message?: unknown };
    if (obj.name === "NotFound") return true;
    if (obj.code === 4001) return true;
    if (typeof obj.message === "string" && matches(obj.message)) return true;
    return false;
  }
  if (typeof e === "string") return matches(e);
  return false;
}

/**
 * Compare a desired attribute value against a raw IPA attribute value for the
 * `sync` reconcile diff. IPA stores attributes as (often single-element)
 * arrays; a desired value may be a scalar or an array. Both sides are
 * normalized to sorted string arrays and compared set-wise, so multi-valued
 * attributes (e.g. `mail`) are order-insensitive and `"John"` equals
 * `["John"]`.
 *
 * @param actualRaw The raw IPA value (from a parsed user's `raw` entry).
 * @param desired The desired value (scalar or array).
 * @returns `true` when the two represent the same attribute set.
 */
export function attrEquals(actualRaw: unknown, desired: unknown): boolean {
  const a = toStrArray(actualRaw).slice().sort();
  const d = toStrArray(desired).slice().sort();
  return a.length === d.length && a.every((x, i) => x === d[i]);
}

/** Minimal check context this model's pre-flight checks rely on. */
interface CheckContext {
  globalArgs: GlobalArgs;
  modelType: string;
  modelId: string;
  dataRepository: {
    getContent: (
      type: string,
      modelId: string,
      dataName: string,
      version?: number,
    ) => Promise<Uint8Array | null>;
  };
}

/** FreeIPA host management model definition. */
export const model = {
  type: "@shrug/freeipa/host",
  version: "2026.07.11.1",
  description:
    "Manage FreeIPA hosts over the JSON-RPC API: find/show read-only snapshots plus add/mod/del/disable writes and a desired-state sync reconcile, each with an audit trail and a confirm-guarded delete. add random:true vaults the one-time enrollment password; add/del take an optional idempotent flag.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "hosts": {
      description: "Snapshot of hosts matching a find (array of parsed rows)",
      schema: HostsSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "host": {
      description:
        "Snapshot of a single host (parsed row + raw entry); carries the sensitive one-time enrollment password when add generated one",
      schema: HostSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "attempt": {
      description:
        "Audit record of a mutation attempt (request + result/error + timestamp). Written on both success and failure.",
      schema: AttemptSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
  },
  checks: {
    "host-exists": {
      description:
        "Verify the most recently snapshotted host still exists before a destructive delete.",
      labels: ["live"],
      appliesTo: ["del"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `host` snapshot this model recorded. The method's own
        // confirm:true guard and IPA's NotFound error remain the per-fqdn
        // safeguards; this catches a stale-target delete against a live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "host",
        );
        if (!bytes) return { pass: true };
        let fqdn = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            host?: { fqdn?: string };
          };
          fqdn = snap.host?.fqdn ?? "";
        } catch {
          return { pass: true };
        }
        if (!fqdn) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("host_show", [fqdn], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `host "${fqdn}" not found on ${context.globalArgs.server}: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
  },
  methods: {
    find: {
      description:
        "Snapshot hosts matching an optional search criteria (read-only).",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all hosts"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding hosts matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call("host_find", [args.criteria ?? ""], {
          all: true,
        });
        const hosts = ((res.result ?? []) as Array<Record<string, unknown>>)
          .map(parseHost);
        context.logger.info("Found {count} hosts", { count: hosts.length });

        const handle = await context.writeResource("hosts", "hosts", {
          server: cfg.server,
          hosts,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    show: {
      description: "Snapshot a single host by fqdn (read-only).",
      arguments: z.object({
        fqdn: z.string().describe("Host fully-qualified domain name to fetch"),
      }),
      execute: async (
        args: { fqdn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing host {fqdn}", { fqdn: args.fqdn });
        const client = await ipaLogin(cfg);
        const res = await client.call("host_show", [args.fqdn], { all: true });
        const host = parseHost((res.result ?? {}) as Record<string, unknown>);
        context.logger.info("Retrieved host {fqdn}", { fqdn: args.fqdn });

        const handle = await context.writeResource("host", "host", {
          server: cfg.server,
          host,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    add: {
      description:
        "Create a host (host_add). With random:true IPA returns a one-time enrollment password, vaulted onto the host state and kept out of the audit. Writes the created host state on success; audits both paths.",
      arguments: z.object({
        fqdn: z.string().describe("Host fully-qualified domain name"),
        description: z
          .string()
          .optional()
          .describe("Free-text description (IPA `description`)"),
        os: z
          .string()
          .optional()
          .describe("Operating system string (IPA `nsosversion`)"),
        ipAddress: z
          .string()
          .optional()
          .describe(
            "IP address to add/reverse in DNS at create time (IPA `ip_address`)",
          ),
        force: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "Force host add even when the DNS A/AAAA record is missing (IPA `force`)",
          ),
        random: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "Generate a one-time random enrollment password (IPA `random`). The returned password is irreplaceable and sensitive: it is vaulted on the host state and never audited.",
          ),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-existing host (IPA DuplicateEntry) is treated as success: the live entry is re-read and recorded as a no-op instead of failing. Default false preserves fail-on-duplicate. Note: an idempotent re-read never yields a fresh random password.",
          ),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA host_add options (lowercase IPA option names), merged last",
          ),
      }),
      execute: async (
        args: {
          fqdn: string;
          description?: string;
          os?: string;
          ipAddress?: string;
          force?: boolean;
          random?: boolean;
          idempotent?: boolean;
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;
        const options: Record<string, unknown> = {
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.os !== undefined ? { nsosversion: args.os } : {}),
          ...(args.ipAddress !== undefined
            ? { ip_address: args.ipAddress }
            : {}),
          ...(args.force ? { force: true } : {}),
          ...(args.random ? { random: true } : {}),
          ...(args.options ?? {}),
        };

        // Captured out of the IPA response inside the attempt fn; persisted onto
        // the host STATE resource below, and deliberately never handed to
        // recordAttempt (so the one-time password can never land in the audit).
        let randomPassword: string | undefined;

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.fqdn,
          "host_add",
          idempotent ? ["host_add", "host_show"] : ["host_add"],
          {
            fqdn: args.fqdn,
            description: args.description ?? null,
            os: args.os ?? null,
            ipAddress: args.ipAddress ?? null,
            force: args.force ?? false,
            random: args.random ?? false,
            idempotent,
          },
          async () => {
            try {
              const res = await client.call("host_add", [args.fqdn], options);
              const entry = (res.result ?? {}) as Record<string, unknown>;
              // IRREPLACEABLE + SENSITIVE: lift the one-time enrollment password
              // out of the entry the instant it is real, then strip it so the
              // recorded audit `response` never contains it.
              const rp = one(entry.randompassword);
              if (typeof rp === "string") randomPassword = rp;
              const { randompassword: _omit, ...safeEntry } = entry;
              return { ...res, result: safeEntry };
            } catch (e) {
              // Idempotent create: an existing host is a no-op success. Re-read
              // the live entry so the recorded response and the `host` state
              // reflect reality. A re-read never carries a random password.
              // Non-duplicate errors and the default (idempotent:false) path
              // still propagate.
              if (idempotent && isDuplicateEntry(e)) {
                context.logger.info(
                  "host_add: {fqdn} already exists, treating as no-op (idempotent)",
                  { fqdn: args.fqdn },
                );
                return await client.call("host_show", [args.fqdn], {
                  all: true,
                });
              }
              throw e;
            }
          },
        );

        // State resource, success-only. Persist the (possibly sensitive)
        // enrollment password NOW — parseHost is pure and total, so nothing
        // between capturing the password and this write can throw and lose it.
        const host = parseHost(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const state: Record<string, unknown> = {
          server: cfg.server,
          host,
          retrievedAt: new Date().toISOString(),
        };
        if (randomPassword !== undefined) state.randomPassword = randomPassword;
        const hostHandle = await context.writeResource("host", "host", state);
        return { dataHandles: [attemptHandle, hostHandle] };
      },
    },
    mod: {
      description:
        "Modify a host (host_mod). Writes the updated host state on success; audits both paths.",
      arguments: z.object({
        fqdn: z.string().describe("Host fully-qualified domain name to modify"),
        set: z
          .record(z.string(), z.unknown())
          .describe(
            'Fields to change as IPA options (lowercase IPA option names, e.g. { nsosversion: "Fedora 40", ip_address: "203.0.113.10" })',
          ),
      }),
      execute: async (
        args: { fqdn: string; set: Record<string, unknown> },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.fqdn,
          "host_mod",
          ["host_mod"],
          { fqdn: args.fqdn, set: args.set },
          () => client.call("host_mod", [args.fqdn], args.set),
        );

        const host = parseHost(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const hostHandle = await context.writeResource("host", "host", {
          server: cfg.server,
          host,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, hostHandle] };
      },
    },
    del: {
      description:
        "Delete a host (host_del). Requires confirm:true; audits both paths.",
      arguments: z.object({
        fqdn: z.string().describe("Host fully-qualified domain name to delete"),
        confirm: z
          .boolean()
          .describe("Must be true; a guard against accidental deletion"),
        updatedns: z
          .boolean()
          .optional()
          .describe(
            "Also remove the host's DNS entries when deleting (IPA `updatedns`)",
          ),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-absent host (IPA NotFound) is treated as success instead of failing. Default false preserves fail-on-missing. The confirm guard always applies.",
          ),
      }),
      execute: async (
        args: {
          fqdn: string;
          confirm: boolean;
          updatedns?: boolean;
          idempotent?: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            `Refusing to delete host "${args.fqdn}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;
        const options: Record<string, unknown> = args.updatedns !== undefined
          ? { updatedns: args.updatedns }
          : {};

        const { handle } = await recordAttempt(
          context,
          args.fqdn,
          "host_del",
          ["host_del"],
          { fqdn: args.fqdn, updatedns: args.updatedns ?? false, idempotent },
          async () => {
            try {
              return await client.call("host_del", [args.fqdn], options);
            } catch (e) {
              // Idempotent delete: an already-gone host is a no-op success.
              // Non-NotFound errors and the default (idempotent:false) path
              // still propagate so a real failure is never masked.
              if (idempotent && isNotFound(e)) {
                context.logger.info(
                  "host_del: {fqdn} already absent, treating as no-op (idempotent)",
                  { fqdn: args.fqdn },
                );
                return { result: true, alreadyAbsent: true };
              }
              throw e;
            }
          },
        );
        return { dataHandles: [handle] };
      },
    },
    disable: {
      description:
        "Disable a host (host_disable): revoke its keytab and held certificates. This is NOT a deletion — the host entry remains. Writes the updated host state on success; audits both paths.",
      arguments: z.object({
        fqdn: z.string().describe("Host fully-qualified domain name"),
      }),
      execute: async (
        args: { fqdn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { handle: attemptHandle } = await recordAttempt(
          context,
          args.fqdn,
          "host_disable",
          ["host_disable"],
          { fqdn: args.fqdn },
          () => client.call("host_disable", [args.fqdn], {}),
        );

        // State resource, success-only: re-read the host so the snapshot
        // reflects the revoked keytab/certs (host_disable returns a boolean, not
        // the entry itself).
        const showRes = await client.call("host_show", [args.fqdn], {
          all: true,
        });
        const host = parseHost(
          (showRes.result ?? {}) as Record<string, unknown>,
        );
        const hostHandle = await context.writeResource("host", "host", {
          server: cfg.server,
          host,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, hostHandle] };
      },
    },
    sync: {
      description:
        "Reconcile a host to a desired spec: create it if absent (host_add), otherwise host_mod only the drifted attributes (description/os + extra options). Idempotent — a converged host issues no IPA writes. Writes the converged host state on success; audits both paths, and the audit response lists the `changes` made.",
      arguments: z.object({
        fqdn: z.string().describe("Host fully-qualified domain name"),
        description: z
          .string()
          .optional()
          .describe(
            "Desired description (IPA `description`); omit to leave it unmanaged",
          ),
        os: z
          .string()
          .optional()
          .describe(
            "Desired operating system string (IPA `nsosversion`); omit to leave it unmanaged",
          ),
        force: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "On create only: force host add without a DNS record (IPA `force`)",
          ),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra desired IPA attributes to reconcile (lowercase IPA option names), diffed and host_mod'd like the built-in fields",
          ),
      }),
      execute: async (
        args: {
          fqdn: string;
          description?: string;
          os?: string;
          force?: boolean;
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        context.logger.info("Reconciling host {fqdn}", { fqdn: args.fqdn });

        // 1. Read actual state (the host may not exist yet).
        let actual: HostRow | null = null;
        try {
          const showRes = await client.call("host_show", [args.fqdn], {
            all: true,
          });
          actual = parseHost(
            (showRes.result ?? {}) as Record<string, unknown>,
          );
        } catch (e) {
          if (!isNotFound(e)) throw e;
          context.logger.info("host {fqdn} absent — will create", {
            fqdn: args.fqdn,
          });
        }

        // The desired managed attribute set, in IPA option form.
        const desiredAttrs: Record<string, unknown> = {
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.os !== undefined ? { nsosversion: args.os } : {}),
          ...(args.options ?? {}),
        };

        const changes: string[] = [];
        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.fqdn,
          "sync",
          ["host_show", "host_add", "host_mod"],
          {
            fqdn: args.fqdn,
            desired: desiredAttrs,
            force: args.force ?? false,
          },
          async () => {
            if (actual === null) {
              // 2a. Absent -> create with the full desired spec.
              const createOpts: Record<string, unknown> = {
                ...desiredAttrs,
                ...(args.force ? { force: true } : {}),
              };
              await client.call("host_add", [args.fqdn], createOpts);
              changes.push("created");
            } else {
              // 2b. Present -> host_mod only the attributes that drifted.
              const set: Record<string, unknown> = {};
              for (const [k, v] of Object.entries(desiredAttrs)) {
                if (!attrEquals(actual.raw[k], v)) set[k] = v;
              }
              if (Object.keys(set).length > 0) {
                await client.call("host_mod", [args.fqdn], set);
                changes.push(...Object.keys(set).map((k) => `mod:${k}`));
              }
            }

            return {
              fqdn: args.fqdn,
              created: actual === null,
              changes,
              converged: changes.length === 0,
            };
          },
        );

        // State resource, success-only: re-read so the snapshot is the
        // converged host regardless of which branch ran.
        context.logger.info("host {fqdn} reconciled: {changes}", {
          fqdn: args.fqdn,
          changes: (result as { changes: string[] }).changes,
        });
        const finalRes = await client.call("host_show", [args.fqdn], {
          all: true,
        });
        const host = parseHost(
          (finalRes.result ?? {}) as Record<string, unknown>,
        );
        const hostHandle = await context.writeResource("host", "host", {
          server: cfg.server,
          host,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, hostHandle] };
      },
    },
  },
};
