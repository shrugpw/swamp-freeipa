/**
 * FreeIPA policy management model (Wave 1: sudo surface).
 *
 * Connects to an existing FreeIPA server's JSON-RPC API to inspect and manage
 * sudo rules. `sudoRuleFind`/`sudoRuleShow` snapshot rules read-only;
 * `ensureSudoRule` creates them idempotently; `sudoRuleAddOption`/
 * `sudoRuleAddUser`/`sudoRuleAddHost`/`sudoRuleAddCommand` populate them (the
 * member methods fan out over lists in one call); `sudoRuleSetEnabled` toggles
 * them; and the destructive `sudoRuleDel` removes them. Every mutation records
 * an honest `attempt` audit resource on BOTH the success and failure paths (see
 * {@link recordAttempt}), the state resources (`sudoRule`/`sudoRules`) are
 * written only on success, and `sudoRuleDel` is gated behind an explicit
 * `confirm` flag plus a `live` pre-flight existence check. This is the policy
 * surface of the `@shrug/freeipa/*` family (HBAC and RBAC arrive in Wave 2).
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
// Sudo-rule value-shaping — parse IPA sudo rule entries into friendly rows.
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

/** A parsed FreeIPA sudo rule row (single-element IPA arrays unwrapped). */
const SudoRuleRowSchema = z.object({
  cn: z.string().describe("Sudo rule name (IPA `cn`)"),
  description: z.string().optional().describe("Free-text description"),
  enabled: z.boolean().describe(
    "Rule enabled state (IPA `ipaenabledflag`); true == enabled",
  ),
  sudoOrder: z.number().int().nullable().describe(
    "Evaluation order (IPA `sudoorder`); sudo is last-match-wins so a higher order wins",
  ),
  cmdCategory: z.string().optional().describe(
    "Command category (IPA `cmdcategory`, e.g. `all`) when set instead of explicit commands",
  ),
  userCategory: z.string().optional().describe(
    "User category (IPA `usercategory`, e.g. `all`) when set instead of explicit users",
  ),
  hostCategory: z.string().optional().describe(
    "Host category (IPA `hostcategory`, e.g. `all`) when set instead of explicit hosts",
  ),
  memberUsers: z.array(z.string()).describe(
    "Users this rule applies to (IPA `memberuser_user`)",
  ),
  memberGroups: z.array(z.string()).describe(
    "User groups this rule applies to (IPA `memberuser_group`)",
  ),
  memberHosts: z.array(z.string()).describe(
    "Hosts this rule applies to (IPA `memberhost_host`)",
  ),
  memberHostGroups: z.array(z.string()).describe(
    "Host groups this rule applies to (IPA `memberhost_hostgroup`)",
  ),
  allowCommands: z.array(z.string()).describe(
    "Allowed commands (IPA `memberallowcmd_sudocmd`)",
  ),
  allowCommandGroups: z.array(z.string()).describe(
    "Allowed command groups (IPA `memberallowcmd_sudocmdgroup`)",
  ),
  sudoOptions: z.array(z.string()).describe(
    "Sudo options (IPA `ipasudoopt`, e.g. `!authenticate` for passwordless)",
  ),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA sudo rule entry, unmodified — nothing is lost",
  ),
});

/** A single parsed sudo rule + provenance — the `sudoRule` state resource. */
const SudoRuleSchema = z.object({
  server: z.string(),
  sudoRule: SudoRuleRowSchema,
  retrievedAt: z.iso.datetime(),
});

/** A snapshot of many sudo rules — the `sudoRules` state resource. */
const SudoRulesSchema = z.object({
  server: z.string(),
  sudoRules: z.array(SudoRuleRowSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * Map a raw IPA sudo rule entry (a `sudorule_find`/`sudorule_show`/
 * `sudorule_add` result row) into a friendly {@link SudoRuleRowSchema} row,
 * keeping the untouched entry under `raw` so no attribute is ever lost.
 *
 * @param entry A single sudo rule entry from an IPA result.
 * @returns The flattened sudo rule row.
 */
export function parseSudoRule(
  entry: Record<string, unknown>,
): z.infer<typeof SudoRuleRowSchema> {
  return {
    cn: String(one(entry.cn) ?? ""),
    description: one(entry.description) as string | undefined,
    enabled: toBool(entry.ipaenabledflag),
    sudoOrder: toInt(entry.sudoorder),
    cmdCategory: one(entry.cmdcategory) as string | undefined,
    userCategory: one(entry.usercategory) as string | undefined,
    hostCategory: one(entry.hostcategory) as string | undefined,
    memberUsers: toStrArray(entry.memberuser_user),
    memberGroups: toStrArray(entry.memberuser_group),
    memberHosts: toStrArray(entry.memberhost_host),
    memberHostGroups: toStrArray(entry.memberhost_hostgroup),
    allowCommands: toStrArray(entry.memberallowcmd_sudocmd),
    allowCommandGroups: toStrArray(entry.memberallowcmd_sudocmdgroup),
    sudoOptions: toStrArray(entry.ipasudoopt),
    raw: entry,
  };
}

/** A parsed sudo rule row produced by {@link parseSudoRule}. */
export type SudoRuleRow = z.infer<typeof SudoRuleRowSchema>;
/** A single sudo-rule snapshot resource. */
export type SudoRule = z.infer<typeof SudoRuleSchema>;
/** A multi sudo-rule snapshot resource. */
export type SudoRules = z.infer<typeof SudoRulesSchema>;

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

/** FreeIPA policy management model definition (Wave 1: sudo). */
export const model = {
  type: "@shrug/freeipa/policy",
  version: "2026.07.11.1",
  description:
    "Manage FreeIPA sudo rules over the JSON-RPC API: sudoRuleFind/sudoRuleShow read-only snapshots plus idempotent ensureSudoRule, fan-out sudoRuleAddOption/AddUser/AddHost/AddCommand, sudoRuleSetEnabled, and a confirm-guarded sudoRuleDel, each with an audit trail. (Wave 2 adds HBAC and RBAC.)",
  globalArguments: GlobalArgsSchema,
  resources: {
    "sudoRules": {
      description:
        "Snapshot of sudo rules matching a find (array of parsed rows)",
      schema: SudoRulesSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "sudoRule": {
      description: "Snapshot of a single sudo rule (parsed row + raw entry)",
      schema: SudoRuleSchema,
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
    "sudorule-exists": {
      description:
        "Verify the most recently snapshotted sudo rule still exists before a destructive delete.",
      labels: ["live"],
      appliesTo: ["sudoRuleDel"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `sudoRule` snapshot this model recorded. The method's
        // own confirm:true guard and IPA's NotFound error remain the per-name
        // safeguards; this catches a stale-target delete against a live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "sudoRule",
        );
        if (!bytes) return { pass: true };
        let cn = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            sudoRule?: { cn?: string };
          };
          cn = snap.sudoRule?.cn ?? "";
        } catch {
          return { pass: true };
        }
        if (!cn) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("sudorule_show", [cn], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `sudo rule "${cn}" not found on ${context.globalArgs.server}: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
  },
  methods: {
    sudoRuleFind: {
      description:
        "Snapshot sudo rules matching an optional search criteria (read-only).",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all sudo rules"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding sudo rules matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call("sudorule_find", [args.criteria ?? ""], {
          all: true,
        });
        const sudoRules = ((res.result ?? []) as Array<Record<string, unknown>>)
          .map(parseSudoRule);
        context.logger.info("Found {count} sudo rules", {
          count: sudoRules.length,
        });

        const handle = await context.writeResource("sudoRules", "sudoRules", {
          server: cfg.server,
          sudoRules,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    sudoRuleShow: {
      description: "Snapshot a single sudo rule by name (read-only).",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn) to fetch"),
      }),
      execute: async (
        args: { cn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing sudo rule {cn}", { cn: args.cn });
        const client = await ipaLogin(cfg);
        const res = await client.call("sudorule_show", [args.cn], {
          all: true,
        });
        const sudoRule = parseSudoRule(
          (res.result ?? {}) as Record<string, unknown>,
        );
        context.logger.info("Retrieved sudo rule {cn}", { cn: args.cn });

        const handle = await context.writeResource("sudoRule", "sudoRule", {
          server: cfg.server,
          sudoRule,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    ensureSudoRule: {
      description:
        "Idempotently ensure a sudo rule exists (sudorule_add). Swallows DuplicateEntry and re-reads via sudorule_show, so re-runs are safe. sudoorder is a first-class arg because sudo evaluation is last-match-wins — order matters. Writes the sudo rule state on success; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn)"),
        sudoOrder: z
          .number()
          .int()
          .optional()
          .describe(
            "Evaluation order (IPA `sudoorder`); higher wins under last-match-wins",
          ),
        cmdCategory: z
          .string()
          .optional()
          .describe(
            "Command category (IPA `cmdcategory`, e.g. `all`) to allow all commands",
          ),
        description: z
          .string()
          .optional()
          .describe("Free-text description (IPA `description`)"),
        userCategory: z
          .string()
          .optional()
          .describe("User category (IPA `usercategory`, e.g. `all`)"),
        hostCategory: z
          .string()
          .optional()
          .describe("Host category (IPA `hostcategory`, e.g. `all`)"),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA sudorule_add options (lowercase IPA option names), merged last",
          ),
      }),
      execute: async (
        args: {
          cn: string;
          sudoOrder?: number;
          cmdCategory?: string;
          description?: string;
          userCategory?: string;
          hostCategory?: string;
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = {
          ...(args.sudoOrder !== undefined
            ? { sudoorder: args.sudoOrder }
            : {}),
          ...(args.cmdCategory !== undefined
            ? { cmdcategory: args.cmdCategory }
            : {}),
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.userCategory !== undefined
            ? { usercategory: args.userCategory }
            : {}),
          ...(args.hostCategory !== undefined
            ? { hostcategory: args.hostCategory }
            : {}),
          ...(args.options ?? {}),
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "sudorule_add",
          ["sudorule_add", "sudorule_show"],
          {
            cn: args.cn,
            sudoOrder: args.sudoOrder ?? null,
            cmdCategory: args.cmdCategory ?? null,
            description: args.description ?? null,
            userCategory: args.userCategory ?? null,
            hostCategory: args.hostCategory ?? null,
          },
          async () => {
            try {
              return await client.call("sudorule_add", [args.cn], options);
            } catch (e) {
              // Idempotent create: an existing rule is a no-op success. Re-read
              // the live entry so the recorded response and the `sudoRule` state
              // reflect reality. Non-duplicate errors still propagate.
              if (isDuplicateEntry(e)) {
                context.logger.info(
                  "sudorule_add: {cn} already exists, treating as no-op (idempotent)",
                  { cn: args.cn },
                );
                return await client.call("sudorule_show", [args.cn], {
                  all: true,
                });
              }
              throw e;
            }
          },
        );

        const sudoRule = parseSudoRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "sudoRule",
          "sudoRule",
          {
            server: cfg.server,
            sudoRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    sudoRuleAddOption: {
      description:
        "Add a sudo option to a rule (sudorule_add_option), e.g. `!authenticate` for passwordless sudo. Writes the updated sudo rule state on success; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn)"),
        option: z
          .string()
          .describe(
            "Sudo option (IPA `ipasudoopt`), e.g. `!authenticate` or `!requiretty`",
          ),
      }),
      execute: async (
        args: { cn: string; option: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "sudorule_add_option",
          ["sudorule_add_option"],
          { cn: args.cn, option: args.option },
          () =>
            client.call("sudorule_add_option", [args.cn], {
              ipasudoopt: args.option,
            }),
        );

        const sudoRule = parseSudoRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "sudoRule",
          "sudoRule",
          {
            server: cfg.server,
            sudoRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    sudoRuleAddUser: {
      description:
        "Add users and/or user groups to a sudo rule in one call (sudorule_add_user). Fan-out: pass lists of users and groups. Surfaces IPA's `failed` structure in the audit response; writes the updated sudo rule state on success.",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn)"),
        users: z
          .array(z.string())
          .optional()
          .describe("User logins to add (IPA `user`)"),
        groups: z
          .array(z.string())
          .optional()
          .describe("User groups to add (IPA `group`)"),
      }),
      execute: async (
        args: { cn: string; users?: string[]; groups?: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "sudorule_add_user",
          ["sudorule_add_user"],
          { cn: args.cn, users: args.users ?? [], groups: args.groups ?? [] },
          async () => {
            const res = await client.call("sudorule_add_user", [args.cn], {
              user: args.users ?? [],
              group: args.groups ?? [],
            });
            // `completed` count and `failed` structure are surfaced so a
            // silent half-fail is visible in the attempt audit.
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const sudoRule = parseSudoRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "sudoRule",
          "sudoRule",
          {
            server: cfg.server,
            sudoRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    sudoRuleAddHost: {
      description:
        "Add hosts and/or host groups to a sudo rule in one call (sudorule_add_host). Fan-out: pass lists of hosts and hostgroups. Surfaces IPA's `failed` structure in the audit response; writes the updated sudo rule state on success.",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn)"),
        hosts: z
          .array(z.string())
          .optional()
          .describe("Host FQDNs to add (IPA `host`)"),
        hostgroups: z
          .array(z.string())
          .optional()
          .describe("Host groups to add (IPA `hostgroup`)"),
      }),
      execute: async (
        args: { cn: string; hosts?: string[]; hostgroups?: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "sudorule_add_host",
          ["sudorule_add_host"],
          {
            cn: args.cn,
            hosts: args.hosts ?? [],
            hostgroups: args.hostgroups ?? [],
          },
          async () => {
            const res = await client.call("sudorule_add_host", [args.cn], {
              host: args.hosts ?? [],
              hostgroup: args.hostgroups ?? [],
            });
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const sudoRule = parseSudoRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "sudoRule",
          "sudoRule",
          {
            server: cfg.server,
            sudoRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    sudoRuleAddCommand: {
      description:
        "Add allowed commands and/or command groups to a sudo rule in one call (sudorule_add_allow_command). Fan-out: pass lists of sudocmds and sudocmdgroups. Surfaces IPA's `failed` structure in the audit response; writes the updated sudo rule state on success.",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn)"),
        commands: z
          .array(z.string())
          .optional()
          .describe("Allowed commands to add (IPA `sudocmd`)"),
        commandGroups: z
          .array(z.string())
          .optional()
          .describe("Allowed command groups to add (IPA `sudocmdgroup`)"),
      }),
      execute: async (
        args: { cn: string; commands?: string[]; commandGroups?: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "sudorule_add_allow_command",
          ["sudorule_add_allow_command"],
          {
            cn: args.cn,
            commands: args.commands ?? [],
            commandGroups: args.commandGroups ?? [],
          },
          async () => {
            const res = await client.call(
              "sudorule_add_allow_command",
              [args.cn],
              {
                sudocmd: args.commands ?? [],
                sudocmdgroup: args.commandGroups ?? [],
              },
            );
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const sudoRule = parseSudoRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "sudoRule",
          "sudoRule",
          {
            server: cfg.server,
            sudoRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    sudoRuleSetEnabled: {
      description:
        "Enable or disable a sudo rule (sudorule_enable / sudorule_disable). Writes the updated sudo rule state on success; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn)"),
        enabled: z
          .boolean()
          .describe("true -> sudorule_enable, false -> sudorule_disable"),
      }),
      execute: async (
        args: { cn: string; enabled: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const command = args.enabled ? "sudorule_enable" : "sudorule_disable";

        const { handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          command,
          [command],
          { cn: args.cn, enabled: args.enabled },
          () => client.call(command, [args.cn], {}),
        );

        // State resource, success-only: re-read the rule so the snapshot
        // reflects the new enabled state (enable/disable return a boolean, not
        // the entry itself).
        const showRes = await client.call("sudorule_show", [args.cn], {
          all: true,
        });
        const sudoRule = parseSudoRule(
          (showRes.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "sudoRule",
          "sudoRule",
          {
            server: cfg.server,
            sudoRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    sudoRuleDel: {
      description:
        "Delete a sudo rule (sudorule_del). Requires confirm:true; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("Sudo rule name (cn) to delete"),
        confirm: z
          .boolean()
          .describe("Must be true; a guard against accidental deletion"),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-absent rule (IPA NotFound) is treated as success instead of failing. Default false preserves fail-on-missing. The confirm guard always applies.",
          ),
      }),
      execute: async (
        args: { cn: string; confirm: boolean; idempotent?: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            `Refusing to delete sudo rule "${args.cn}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "sudorule_del",
          ["sudorule_del"],
          { cn: args.cn, idempotent },
          async () => {
            try {
              return await client.call("sudorule_del", [args.cn], {});
            } catch (e) {
              // Idempotent delete: an already-gone rule is a no-op success.
              // Non-NotFound errors and the default (idempotent:false) path
              // still propagate so a real failure is never masked.
              if (idempotent && isNotFound(e)) {
                context.logger.info(
                  "sudorule_del: {cn} already absent, treating as no-op (idempotent)",
                  { cn: args.cn },
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
  },
};
