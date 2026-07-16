/**
 * FreeIPA policy management model (sudo + HBAC + RBAC + privilege + CA ACL).
 *
 * Connects to an existing FreeIPA server's JSON-RPC API to inspect and manage
 * five policy surfaces, each following the same shape:
 *
 *  - **sudo:** `sudoRuleFind`/`sudoRuleShow` snapshot rules read-only;
 *    `ensureSudoRule` creates them idempotently; `sudoRuleAddOption`/
 *    `sudoRuleAddUser`/`sudoRuleAddHost`/`sudoRuleAddCommand` populate them;
 *    `sudoRuleSetEnabled` toggles them; `sudoRuleDel` removes them.
 *  - **HBAC:** `hbacRuleFind`/`hbacRuleShow`, idempotent `ensureHbacRule`,
 *    fan-out `hbacRuleAddUser`/`hbacRuleAddHost`/`hbacRuleAddService`,
 *    `hbacRuleSetEnabled`, and `hbacRuleDel`.
 *  - **RBAC:** `roleFind`/`roleShow`, idempotent `ensureRole`, fan-out
 *    `roleAddPrivilege`/`roleAddMember`, read-only `privilegeFind`/
 *    `permissionFind`, and `roleDel`.
 *  - **privilege:** `privilegeShow`, idempotent `ensurePrivilege`, fan-out
 *    `privilegeAddPermission`, and `privilegeDel`.
 *  - **CA ACL:** `caAclFind`/`caAclShow`, idempotent `ensureCaAcl`, fan-out
 *    `caAclAddCertprofile`/`caAclAddUser`, `caAclSetEnabled`, and `caAclDel`.
 *
 * The privilege and CA-ACL surfaces are privilege-escalation sensitive and
 * admin/break-glass scoped: the scoped service account
 * is deliberately NOT granted `Delegation Administrator`, so those mutations run
 * only within rights the operator already holds. (The code is auth-agnostic;
 * this is an operational note.)
 *
 * The member/privilege methods fan out over lists in one call. Every mutation
 * records an honest `attempt` audit resource on BOTH the success and failure
 * paths (see {@link recordAttempt}), the state resources are written only on
 * success, and each destructive `*Del` is gated behind an explicit `confirm`
 * flag plus a `live` pre-flight existence check. This is the policy surface of
 * the `@shrug/freeipa/*` family.
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

// ---------------------------------------------------------------------------
// HBAC-rule value-shaping — parse IPA HBAC rule entries into friendly rows.
// ---------------------------------------------------------------------------

/** A parsed FreeIPA HBAC rule row (single-element IPA arrays unwrapped). */
const HbacRuleRowSchema = z.object({
  cn: z.string().describe("HBAC rule name (IPA `cn`)"),
  description: z.string().optional().describe("Free-text description"),
  enabled: z.boolean().describe(
    "Rule enabled state (IPA `ipaenabledflag`); true == enabled",
  ),
  accessRuleType: z.string().optional().describe(
    "Access rule type (IPA `accessruletype`); normally `allow`",
  ),
  userCategory: z.string().optional().describe(
    "User category (IPA `usercategory`, e.g. `all`) when set instead of explicit users",
  ),
  hostCategory: z.string().optional().describe(
    "Host category (IPA `hostcategory`, e.g. `all`) when set instead of explicit hosts",
  ),
  serviceCategory: z.string().optional().describe(
    "Service category (IPA `servicecategory`, e.g. `all`) when set instead of explicit services",
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
  memberServices: z.array(z.string()).describe(
    "HBAC services this rule applies to (IPA `memberservice_hbacsvc`)",
  ),
  memberServiceGroups: z.array(z.string()).describe(
    "HBAC service groups this rule applies to (IPA `memberservice_hbacsvcgroup`)",
  ),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA HBAC rule entry, unmodified — nothing is lost",
  ),
});

/** A single parsed HBAC rule + provenance — the `hbacRule` state resource. */
const HbacRuleSchema = z.object({
  server: z.string(),
  hbacRule: HbacRuleRowSchema,
  retrievedAt: z.iso.datetime(),
});

/** A snapshot of many HBAC rules — the `hbacRules` state resource. */
const HbacRulesSchema = z.object({
  server: z.string(),
  hbacRules: z.array(HbacRuleRowSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * Map a raw IPA HBAC rule entry (a `hbacrule_find`/`hbacrule_show`/
 * `hbacrule_add` result row) into a friendly {@link HbacRuleRowSchema} row,
 * keeping the untouched entry under `raw` so no attribute is ever lost.
 *
 * Mirrors {@link parseSudoRule}: single-element IPA arrays are unwrapped and the
 * full entry is preserved verbatim under `raw`.
 *
 * @param entry A single HBAC rule entry from an IPA result.
 * @returns The flattened HBAC rule row.
 */
export function parseHbacRule(
  entry: Record<string, unknown>,
): z.infer<typeof HbacRuleRowSchema> {
  return {
    cn: String(one(entry.cn) ?? ""),
    description: one(entry.description) as string | undefined,
    enabled: toBool(entry.ipaenabledflag),
    accessRuleType: one(entry.accessruletype) as string | undefined,
    userCategory: one(entry.usercategory) as string | undefined,
    hostCategory: one(entry.hostcategory) as string | undefined,
    serviceCategory: one(entry.servicecategory) as string | undefined,
    memberUsers: toStrArray(entry.memberuser_user),
    memberGroups: toStrArray(entry.memberuser_group),
    memberHosts: toStrArray(entry.memberhost_host),
    memberHostGroups: toStrArray(entry.memberhost_hostgroup),
    memberServices: toStrArray(entry.memberservice_hbacsvc),
    memberServiceGroups: toStrArray(entry.memberservice_hbacsvcgroup),
    raw: entry,
  };
}

/** A parsed HBAC rule row produced by {@link parseHbacRule}. */
export type HbacRuleRow = z.infer<typeof HbacRuleRowSchema>;
/** A single HBAC-rule snapshot resource. */
export type HbacRule = z.infer<typeof HbacRuleSchema>;
/** A multi HBAC-rule snapshot resource. */
export type HbacRules = z.infer<typeof HbacRulesSchema>;

// ---------------------------------------------------------------------------
// RBAC value-shaping — parse IPA role/privilege/permission entries into rows.
// ---------------------------------------------------------------------------

/** A parsed FreeIPA role row (single-element IPA arrays unwrapped). */
const RoleRowSchema = z.object({
  cn: z.string().describe("Role name (IPA `cn`)"),
  description: z.string().optional().describe("Free-text description"),
  memberUsers: z.array(z.string()).describe(
    "Users granted this role (IPA `member_user`)",
  ),
  memberGroups: z.array(z.string()).describe(
    "User groups granted this role (IPA `member_group`)",
  ),
  memberHosts: z.array(z.string()).describe(
    "Hosts granted this role (IPA `member_host`)",
  ),
  memberHostGroups: z.array(z.string()).describe(
    "Host groups granted this role (IPA `member_hostgroup`)",
  ),
  memberServices: z.array(z.string()).describe(
    "Services granted this role (IPA `member_service`)",
  ),
  privileges: z.array(z.string()).describe(
    "Privileges bundled into this role (IPA `memberof_privilege`)",
  ),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA role entry, unmodified — nothing is lost",
  ),
});

/** A single parsed role + provenance — the `role` state resource. */
const RoleSchema = z.object({
  server: z.string(),
  role: RoleRowSchema,
  retrievedAt: z.iso.datetime(),
});

/** A snapshot of many roles — the `roles` state resource. */
const RolesSchema = z.object({
  server: z.string(),
  roles: z.array(RoleRowSchema),
  retrievedAt: z.iso.datetime(),
});

/** A parsed FreeIPA privilege/permission row (read-only inspection). */
const RbacEntryRowSchema = z.object({
  cn: z.string().describe("Entry name (IPA `cn`)"),
  description: z.string().optional().describe("Free-text description"),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA entry, unmodified — nothing is lost",
  ),
});

/** A read-only snapshot of privileges — the `privileges` state resource. */
const PrivilegesSchema = z.object({
  server: z.string(),
  privileges: z.array(RbacEntryRowSchema),
  retrievedAt: z.iso.datetime(),
});

/** A read-only snapshot of permissions — the `permissions` state resource. */
const PermissionsSchema = z.object({
  server: z.string(),
  permissions: z.array(RbacEntryRowSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * Map a raw IPA role entry (a `role_find`/`role_show`/`role_add` result row)
 * into a friendly {@link RoleRowSchema} row, keeping the untouched entry under
 * `raw` so no attribute is ever lost. Mirrors {@link parseSudoRule}.
 *
 * @param entry A single role entry from an IPA result.
 * @returns The flattened role row.
 */
export function parseRole(
  entry: Record<string, unknown>,
): z.infer<typeof RoleRowSchema> {
  return {
    cn: String(one(entry.cn) ?? ""),
    description: one(entry.description) as string | undefined,
    memberUsers: toStrArray(entry.member_user),
    memberGroups: toStrArray(entry.member_group),
    memberHosts: toStrArray(entry.member_host),
    memberHostGroups: toStrArray(entry.member_hostgroup),
    memberServices: toStrArray(entry.member_service),
    privileges: toStrArray(entry.memberof_privilege),
    raw: entry,
  };
}

/**
 * Map a raw IPA privilege or permission entry into a minimal
 * {@link RbacEntryRowSchema} row for the read-only `privilegeFind`/
 * `permissionFind` snapshots, keeping the untouched entry under `raw`.
 *
 * @param entry A single privilege/permission entry from an IPA result.
 * @returns The flattened `{cn, description?, raw}` row.
 */
export function parseRbacEntry(
  entry: Record<string, unknown>,
): z.infer<typeof RbacEntryRowSchema> {
  return {
    cn: String(one(entry.cn) ?? ""),
    description: one(entry.description) as string | undefined,
    raw: entry,
  };
}

/** A parsed role row produced by {@link parseRole}. */
export type RoleRow = z.infer<typeof RoleRowSchema>;
/** A single role snapshot resource. */
export type Role = z.infer<typeof RoleSchema>;
/** A multi role snapshot resource. */
export type Roles = z.infer<typeof RolesSchema>;
/** A parsed privilege/permission row produced by {@link parseRbacEntry}. */
export type RbacEntryRow = z.infer<typeof RbacEntryRowSchema>;
/** A read-only privileges snapshot resource. */
export type Privileges = z.infer<typeof PrivilegesSchema>;
/** A read-only permissions snapshot resource. */
export type Permissions = z.infer<typeof PermissionsSchema>;

// ---------------------------------------------------------------------------
// Privilege + CA-ACL value-shaping — parse IPA privilege/caacl entries.
//
// Two defensive coercions shared by both parsers below. Beyond the usual
// single-element-array unwrapping ({@link one}/{@link toStrArray}), IPA
// occasionally renders name-valued attributes as `{ "__dns_name__": "fqdn." }`
// objects rather than plain strings (a real bug that bit the `dns` package's
// parsers — see the family memory). These coercions reduce such an object to
// its string so a stray wrapped value never becomes `"[object Object]"`.
// ---------------------------------------------------------------------------

/**
 * Coerce a single IPA attribute value to a string, unwrapping both a
 * single-element array and the `{ "__dns_name__": … }` object wire form.
 *
 * @param v A raw attribute value.
 * @returns The string value; empty string when absent.
 */
export function caaclStr(v: unknown): string {
  const s = one(v);
  if (s && typeof s === "object" && "__dns_name__" in s) {
    return String((s as { __dns_name__: unknown }).__dns_name__ ?? "");
  }
  return s === undefined || s === null ? "" : String(s);
}

/**
 * Coerce a raw IPA attribute value to an array of strings, unwrapping each
 * `{ "__dns_name__": … }` object and dropping empties. Mirrors
 * {@link toStrArray} but defends against the object wire form.
 *
 * @param v A raw attribute value (scalar, array, or absent).
 * @returns A string array (empty when absent).
 */
export function caaclStrArray(v: unknown): string[] {
  if (v === undefined || v === null) return [];
  return (Array.isArray(v) ? v : [v])
    .map((x) =>
      x && typeof x === "object" && "__dns_name__" in x
        ? String((x as { __dns_name__: unknown }).__dns_name__ ?? "")
        : String(x)
    )
    .filter((s) => s.length > 0);
}

/** Merge two string arrays, de-duplicating while preserving first-seen order. */
function mergeDedup(a: string[], b: string[]): string[] {
  return [...new Set([...a, ...b])];
}

/** A parsed FreeIPA privilege row (single-element IPA arrays unwrapped). */
const PrivilegeRowSchema = z.object({
  cn: z.string().describe("Privilege name (IPA `cn`)"),
  description: z.string().optional().describe("Free-text description"),
  permissions: z.array(z.string()).describe(
    "Permissions bundled into this privilege (IPA `member_permission` / `memberof_permission`)",
  ),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA privilege entry, unmodified — nothing is lost",
  ),
});

/** A single parsed privilege + provenance — the `privilege` state resource. */
const PrivilegeSchema = z.object({
  server: z.string(),
  privilege: PrivilegeRowSchema,
  retrievedAt: z.iso.datetime(),
});

/**
 * Map a raw IPA privilege entry (a `privilege_show`/`privilege_add`/
 * `privilege_add_permission` result row) into a friendly
 * {@link PrivilegeRowSchema} row, keeping the untouched entry under `raw`.
 * Mirrors {@link parseRole}; the richer read (with permissions) that
 * `privilegeShow` uses, versus the minimal {@link parseRbacEntry} that the
 * read-only `privilegeFind` snapshot keeps.
 *
 * @param entry A single privilege entry from an IPA result.
 * @returns The flattened privilege row.
 */
export function parsePrivilege(
  entry: Record<string, unknown>,
): z.infer<typeof PrivilegeRowSchema> {
  return {
    cn: caaclStr(entry.cn),
    description: one(entry.description) as string | undefined,
    permissions: mergeDedup(
      caaclStrArray(entry.member_permission),
      caaclStrArray(entry.memberof_permission),
    ),
    raw: entry,
  };
}

/** A parsed privilege row produced by {@link parsePrivilege}. */
export type PrivilegeRow = z.infer<typeof PrivilegeRowSchema>;
/** A single privilege snapshot resource. */
export type Privilege = z.infer<typeof PrivilegeSchema>;

/** A parsed FreeIPA CA ACL row (single-element IPA arrays unwrapped). */
const CaAclRowSchema = z.object({
  cn: z.string().describe("CA ACL name (IPA `cn`)"),
  description: z.string().optional().describe("Free-text description"),
  enabled: z.boolean().describe(
    "ACL enabled state (IPA `ipaenabledflag`); true == enabled",
  ),
  userCategory: z.string().optional().describe(
    "User category (IPA `usercategory`, e.g. `all`) when set instead of explicit users",
  ),
  certprofiles: z.array(z.string()).describe(
    "Certificate profiles this ACL permits (IPA `ipamembercertprofile_certprofile` / `member_certprofile`)",
  ),
  users: z.array(z.string()).describe(
    "Users this ACL applies to (IPA `memberuser_user`)",
  ),
  groups: z.array(z.string()).describe(
    "User groups this ACL applies to (IPA `memberuser_group`)",
  ),
  hosts: z.array(z.string()).describe(
    "Hosts this ACL applies to (IPA `memberhost_host`)",
  ),
  services: z.array(z.string()).describe(
    "Services this ACL applies to (IPA `memberservice_service`)",
  ),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA CA ACL entry, unmodified — nothing is lost",
  ),
});

/** A single parsed CA ACL + provenance — the `caAcl` state resource. */
const CaAclSchema = z.object({
  server: z.string(),
  caAcl: CaAclRowSchema,
  retrievedAt: z.iso.datetime(),
});

/** A snapshot of many CA ACLs — the `caAcls` state resource. */
const CaAclsSchema = z.object({
  server: z.string(),
  caAcls: z.array(CaAclRowSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * Map a raw IPA CA ACL entry (a `caacl_find`/`caacl_show`/`caacl_add` or
 * `caacl_add_profile`/`caacl_add_user` result row) into a friendly
 * {@link CaAclRowSchema} row, keeping the untouched entry under `raw`.
 * Mirrors {@link parseSudoRule}; certprofile members and the cn are read via
 * the {@link caaclStr}/{@link caaclStrArray} object-wire-form-safe coercions.
 *
 * @param entry A single CA ACL entry from an IPA result.
 * @returns The flattened CA ACL row.
 */
export function parseCaAcl(
  entry: Record<string, unknown>,
): z.infer<typeof CaAclRowSchema> {
  return {
    cn: caaclStr(entry.cn),
    description: one(entry.description) as string | undefined,
    enabled: toBool(entry.ipaenabledflag),
    userCategory: one(entry.usercategory) as string | undefined,
    certprofiles: mergeDedup(
      caaclStrArray(entry.ipamembercertprofile_certprofile),
      caaclStrArray(entry.member_certprofile),
    ),
    users: toStrArray(entry.memberuser_user),
    groups: toStrArray(entry.memberuser_group),
    hosts: toStrArray(entry.memberhost_host),
    services: toStrArray(entry.memberservice_service),
    raw: entry,
  };
}

/** A parsed CA ACL row produced by {@link parseCaAcl}. */
export type CaAclRow = z.infer<typeof CaAclRowSchema>;
/** A single CA ACL snapshot resource. */
export type CaAcl = z.infer<typeof CaAclSchema>;
/** A multi CA ACL snapshot resource. */
export type CaAcls = z.infer<typeof CaAclsSchema>;

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

/** FreeIPA policy management model definition (sudo + HBAC + RBAC + privilege + CA ACL). */
export const model = {
  type: "@shrug/freeipa/policy",
  version: "2026.07.16.1",
  description:
    "Manage FreeIPA sudo, HBAC, RBAC, privilege, and CA-ACL policy over the JSON-RPC API: find/show read-only snapshots plus idempotent ensureSudoRule/ensureHbacRule/ensureRole/ensurePrivilege/ensureCaAcl, fan-out member/option/privilege/permission/certprofile methods, enable/disable toggles, read-only privilegeFind/permissionFind/privilegeShow/caAclFind, and confirm-guarded deletes — each mutation with an audit trail.",
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
    "hbacRules": {
      description:
        "Snapshot of HBAC rules matching a find (array of parsed rows)",
      schema: HbacRulesSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "hbacRule": {
      description: "Snapshot of a single HBAC rule (parsed row + raw entry)",
      schema: HbacRuleSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "roles": {
      description: "Snapshot of roles matching a find (array of parsed rows)",
      schema: RolesSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "role": {
      description: "Snapshot of a single role (parsed row + raw entry)",
      schema: RoleSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "privileges": {
      description:
        "Read-only snapshot of privileges matching a find (name + description + raw)",
      schema: PrivilegesSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "permissions": {
      description:
        "Read-only snapshot of permissions matching a find (name + description + raw)",
      schema: PermissionsSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "privilege": {
      description:
        "Snapshot of a single privilege (parsed row incl. bundled permissions + raw entry)",
      schema: PrivilegeSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "caAcls": {
      description: "Snapshot of CA ACLs matching a find (array of parsed rows)",
      schema: CaAclsSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "caAcl": {
      description: "Snapshot of a single CA ACL (parsed row + raw entry)",
      schema: CaAclSchema,
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
    "hbacrule-exists": {
      description:
        "Verify the most recently snapshotted HBAC rule still exists before a destructive delete.",
      labels: ["live"],
      appliesTo: ["hbacRuleDel"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `hbacRule` snapshot this model recorded. The method's
        // own confirm:true guard and IPA's NotFound error remain the per-name
        // safeguards; this catches a stale-target delete against a live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "hbacRule",
        );
        if (!bytes) return { pass: true };
        let cn = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            hbacRule?: { cn?: string };
          };
          cn = snap.hbacRule?.cn ?? "";
        } catch {
          return { pass: true };
        }
        if (!cn) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("hbacrule_show", [cn], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `HBAC rule "${cn}" not found on ${context.globalArgs.server}: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
    "role-exists": {
      description:
        "Verify the most recently snapshotted role still exists before a destructive delete.",
      labels: ["live"],
      appliesTo: ["roleDel"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `role` snapshot this model recorded. The method's own
        // confirm:true guard and IPA's NotFound error remain the per-name
        // safeguards; this catches a stale-target delete against a live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "role",
        );
        if (!bytes) return { pass: true };
        let cn = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            role?: { cn?: string };
          };
          cn = snap.role?.cn ?? "";
        } catch {
          return { pass: true };
        }
        if (!cn) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("role_show", [cn], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `role "${cn}" not found on ${context.globalArgs.server}: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
    "privilege-exists": {
      description:
        "Verify the most recently snapshotted privilege still exists before a destructive delete.",
      labels: ["live"],
      appliesTo: ["privilegeDel"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `privilege` snapshot this model recorded. The
        // method's own confirm:true guard and IPA's NotFound error remain the
        // per-name safeguards; this catches a stale-target delete against a
        // live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "privilege",
        );
        if (!bytes) return { pass: true };
        let cn = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            privilege?: { cn?: string };
          };
          cn = snap.privilege?.cn ?? "";
        } catch {
          return { pass: true };
        }
        if (!cn) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("privilege_show", [cn], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `privilege "${cn}" not found on ${context.globalArgs.server}: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
    "caacl-exists": {
      description:
        "Verify the most recently snapshotted CA ACL still exists before a destructive delete.",
      labels: ["live"],
      appliesTo: ["caAclDel"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `caAcl` snapshot this model recorded. The method's
        // own confirm:true guard and IPA's NotFound error remain the per-name
        // safeguards; this catches a stale-target delete against a live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "caAcl",
        );
        if (!bytes) return { pass: true };
        let cn = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            caAcl?: { cn?: string };
          };
          cn = snap.caAcl?.cn ?? "";
        } catch {
          return { pass: true };
        }
        if (!cn) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("caacl_show", [cn], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `CA ACL "${cn}" not found on ${context.globalArgs.server}: ${
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
    hbacRuleFind: {
      description:
        "Snapshot HBAC rules matching an optional search criteria (read-only).",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all HBAC rules"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding HBAC rules matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call("hbacrule_find", [args.criteria ?? ""], {
          all: true,
        });
        const hbacRules = ((res.result ?? []) as Array<Record<string, unknown>>)
          .map(parseHbacRule);
        context.logger.info("Found {count} HBAC rules", {
          count: hbacRules.length,
        });

        const handle = await context.writeResource("hbacRules", "hbacRules", {
          server: cfg.server,
          hbacRules,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    hbacRuleShow: {
      description: "Snapshot a single HBAC rule by name (read-only).",
      arguments: z.object({
        cn: z.string().describe("HBAC rule name (cn) to fetch"),
      }),
      execute: async (
        args: { cn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing HBAC rule {cn}", { cn: args.cn });
        const client = await ipaLogin(cfg);
        const res = await client.call("hbacrule_show", [args.cn], {
          all: true,
        });
        const hbacRule = parseHbacRule(
          (res.result ?? {}) as Record<string, unknown>,
        );
        context.logger.info("Retrieved HBAC rule {cn}", { cn: args.cn });

        const handle = await context.writeResource("hbacRule", "hbacRule", {
          server: cfg.server,
          hbacRule,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    ensureHbacRule: {
      description:
        "Idempotently ensure an HBAC rule exists (hbacrule_add). Swallows DuplicateEntry and re-reads via hbacrule_show, so re-runs are safe. Writes the HBAC rule state on success; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("HBAC rule name (cn)"),
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
        serviceCategory: z
          .string()
          .optional()
          .describe("Service category (IPA `servicecategory`, e.g. `all`)"),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA hbacrule_add options (lowercase IPA option names), merged last",
          ),
      }),
      execute: async (
        args: {
          cn: string;
          description?: string;
          userCategory?: string;
          hostCategory?: string;
          serviceCategory?: string;
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = {
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.userCategory !== undefined
            ? { usercategory: args.userCategory }
            : {}),
          ...(args.hostCategory !== undefined
            ? { hostcategory: args.hostCategory }
            : {}),
          ...(args.serviceCategory !== undefined
            ? { servicecategory: args.serviceCategory }
            : {}),
          ...(args.options ?? {}),
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "hbacrule_add",
          ["hbacrule_add", "hbacrule_show"],
          {
            cn: args.cn,
            description: args.description ?? null,
            userCategory: args.userCategory ?? null,
            hostCategory: args.hostCategory ?? null,
            serviceCategory: args.serviceCategory ?? null,
          },
          async () => {
            try {
              return await client.call("hbacrule_add", [args.cn], options);
            } catch (e) {
              // Idempotent create: an existing rule is a no-op success. Re-read
              // the live entry so the recorded response and the `hbacRule` state
              // reflect reality. Non-duplicate errors still propagate.
              if (isDuplicateEntry(e)) {
                context.logger.info(
                  "hbacrule_add: {cn} already exists, treating as no-op (idempotent)",
                  { cn: args.cn },
                );
                return await client.call("hbacrule_show", [args.cn], {
                  all: true,
                });
              }
              throw e;
            }
          },
        );

        const hbacRule = parseHbacRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "hbacRule",
          "hbacRule",
          {
            server: cfg.server,
            hbacRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    hbacRuleAddUser: {
      description:
        "Add users and/or user groups to an HBAC rule in one call (hbacrule_add_user). Fan-out: pass lists of users and groups. Surfaces IPA's `failed` structure in the audit response; writes the updated HBAC rule state on success.",
      arguments: z.object({
        cn: z.string().describe("HBAC rule name (cn)"),
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
          "hbacrule_add_user",
          ["hbacrule_add_user"],
          { cn: args.cn, users: args.users ?? [], groups: args.groups ?? [] },
          async () => {
            const res = await client.call("hbacrule_add_user", [args.cn], {
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

        const hbacRule = parseHbacRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "hbacRule",
          "hbacRule",
          {
            server: cfg.server,
            hbacRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    hbacRuleAddHost: {
      description:
        "Add hosts and/or host groups to an HBAC rule in one call (hbacrule_add_host). Fan-out: pass lists of hosts and hostgroups. Surfaces IPA's `failed` structure in the audit response; writes the updated HBAC rule state on success.",
      arguments: z.object({
        cn: z.string().describe("HBAC rule name (cn)"),
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
          "hbacrule_add_host",
          ["hbacrule_add_host"],
          {
            cn: args.cn,
            hosts: args.hosts ?? [],
            hostgroups: args.hostgroups ?? [],
          },
          async () => {
            const res = await client.call("hbacrule_add_host", [args.cn], {
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

        const hbacRule = parseHbacRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "hbacRule",
          "hbacRule",
          {
            server: cfg.server,
            hbacRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    hbacRuleAddService: {
      description:
        "Add HBAC services and/or service groups to an HBAC rule in one call (hbacrule_add_service). Fan-out: pass lists of hbacsvcs and hbacsvcgroups. Surfaces IPA's `failed` structure in the audit response; writes the updated HBAC rule state on success.",
      arguments: z.object({
        cn: z.string().describe("HBAC rule name (cn)"),
        services: z
          .array(z.string())
          .optional()
          .describe("HBAC services to add (IPA `hbacsvc`)"),
        serviceGroups: z
          .array(z.string())
          .optional()
          .describe("HBAC service groups to add (IPA `hbacsvcgroup`)"),
      }),
      execute: async (
        args: { cn: string; services?: string[]; serviceGroups?: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "hbacrule_add_service",
          ["hbacrule_add_service"],
          {
            cn: args.cn,
            services: args.services ?? [],
            serviceGroups: args.serviceGroups ?? [],
          },
          async () => {
            const res = await client.call("hbacrule_add_service", [args.cn], {
              hbacsvc: args.services ?? [],
              hbacsvcgroup: args.serviceGroups ?? [],
            });
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const hbacRule = parseHbacRule(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "hbacRule",
          "hbacRule",
          {
            server: cfg.server,
            hbacRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    hbacRuleSetEnabled: {
      description:
        "Enable or disable an HBAC rule (hbacrule_enable / hbacrule_disable). Writes the updated HBAC rule state on success; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("HBAC rule name (cn)"),
        enabled: z
          .boolean()
          .describe("true -> hbacrule_enable, false -> hbacrule_disable"),
      }),
      execute: async (
        args: { cn: string; enabled: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const command = args.enabled ? "hbacrule_enable" : "hbacrule_disable";

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
        const showRes = await client.call("hbacrule_show", [args.cn], {
          all: true,
        });
        const hbacRule = parseHbacRule(
          (showRes.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "hbacRule",
          "hbacRule",
          {
            server: cfg.server,
            hbacRule,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    hbacRuleDel: {
      description:
        "Delete an HBAC rule (hbacrule_del). Requires confirm:true; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("HBAC rule name (cn) to delete"),
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
            `Refusing to delete HBAC rule "${args.cn}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "hbacrule_del",
          ["hbacrule_del"],
          { cn: args.cn, idempotent },
          async () => {
            try {
              return await client.call("hbacrule_del", [args.cn], {});
            } catch (e) {
              // Idempotent delete: an already-gone rule is a no-op success.
              // Non-NotFound errors and the default (idempotent:false) path
              // still propagate so a real failure is never masked.
              if (idempotent && isNotFound(e)) {
                context.logger.info(
                  "hbacrule_del: {cn} already absent, treating as no-op (idempotent)",
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
    roleFind: {
      description:
        "Snapshot roles matching an optional search criteria (read-only).",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all roles"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding roles matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call("role_find", [args.criteria ?? ""], {
          all: true,
        });
        const roles = ((res.result ?? []) as Array<Record<string, unknown>>)
          .map(parseRole);
        context.logger.info("Found {count} roles", { count: roles.length });

        const handle = await context.writeResource("roles", "roles", {
          server: cfg.server,
          roles,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    roleShow: {
      description: "Snapshot a single role by name (read-only).",
      arguments: z.object({
        cn: z.string().describe("Role name (cn) to fetch"),
      }),
      execute: async (
        args: { cn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing role {cn}", { cn: args.cn });
        const client = await ipaLogin(cfg);
        const res = await client.call("role_show", [args.cn], {
          all: true,
        });
        const role = parseRole(
          (res.result ?? {}) as Record<string, unknown>,
        );
        context.logger.info("Retrieved role {cn}", { cn: args.cn });

        const handle = await context.writeResource("role", "role", {
          server: cfg.server,
          role,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    ensureRole: {
      description:
        "Idempotently ensure a role exists (role_add). Swallows DuplicateEntry and re-reads via role_show, so re-runs are safe. Writes the role state on success; audits both paths. NOTE: role/privilege mutation is privilege-escalation sensitive — the scoped service account is deliberately NOT granted Delegation Administrator, so this operates only within the rights the operator already holds.",
      arguments: z.object({
        cn: z.string().describe("Role name (cn)"),
        description: z
          .string()
          .optional()
          .describe("Free-text description (IPA `description`)"),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA role_add options (lowercase IPA option names), merged last",
          ),
      }),
      execute: async (
        args: {
          cn: string;
          description?: string;
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = {
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.options ?? {}),
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "role_add",
          ["role_add", "role_show"],
          { cn: args.cn, description: args.description ?? null },
          async () => {
            try {
              return await client.call("role_add", [args.cn], options);
            } catch (e) {
              // Idempotent create: an existing role is a no-op success. Re-read
              // the live entry so the recorded response and the `role` state
              // reflect reality. Non-duplicate errors still propagate.
              if (isDuplicateEntry(e)) {
                context.logger.info(
                  "role_add: {cn} already exists, treating as no-op (idempotent)",
                  { cn: args.cn },
                );
                return await client.call("role_show", [args.cn], {
                  all: true,
                });
              }
              throw e;
            }
          },
        );

        const role = parseRole(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource("role", "role", {
          server: cfg.server,
          role,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    roleAddPrivilege: {
      description:
        "Add privileges to a role in one call (role_add_privilege). Fan-out: pass a list of privileges. Surfaces IPA's `failed` structure in the audit response; writes the updated role state on success. NOTE: privilege-escalation sensitive — bounded by the operator's own rights (no Delegation Administrator on the scoped account).",
      arguments: z.object({
        cn: z.string().describe("Role name (cn)"),
        privileges: z
          .array(z.string())
          .describe("Privileges to add to the role (IPA `privilege`)"),
      }),
      execute: async (
        args: { cn: string; privileges: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "role_add_privilege",
          ["role_add_privilege"],
          { cn: args.cn, privileges: args.privileges },
          async () => {
            const res = await client.call("role_add_privilege", [args.cn], {
              privilege: args.privileges,
            });
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const role = parseRole(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource("role", "role", {
          server: cfg.server,
          role,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    roleAddMember: {
      description:
        "Add users and/or user groups to a role in one call (role_add_member). Fan-out: pass lists of users and groups. Surfaces IPA's `failed` structure in the audit response; writes the updated role state on success.",
      arguments: z.object({
        cn: z.string().describe("Role name (cn)"),
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
          "role_add_member",
          ["role_add_member"],
          { cn: args.cn, users: args.users ?? [], groups: args.groups ?? [] },
          async () => {
            const res = await client.call("role_add_member", [args.cn], {
              user: args.users ?? [],
              group: args.groups ?? [],
            });
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const role = parseRole(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource("role", "role", {
          server: cfg.server,
          role,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    privilegeFind: {
      description:
        "Snapshot privileges matching an optional search criteria (read-only). Useful for discovering the privilege names to feed roleAddPrivilege.",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all privileges"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding privileges matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call("privilege_find", [args.criteria ?? ""], {
          all: true,
        });
        const privileges =
          ((res.result ?? []) as Array<Record<string, unknown>>)
            .map(parseRbacEntry);
        context.logger.info("Found {count} privileges", {
          count: privileges.length,
        });

        const handle = await context.writeResource("privileges", "privileges", {
          server: cfg.server,
          privileges,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    permissionFind: {
      description:
        "Snapshot permissions matching an optional search criteria (read-only). Useful for discovering the permission names bundled into privileges.",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all permissions"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding permissions matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call(
          "permission_find",
          [args.criteria ?? ""],
          { all: true },
        );
        const permissions =
          ((res.result ?? []) as Array<Record<string, unknown>>)
            .map(parseRbacEntry);
        context.logger.info("Found {count} permissions", {
          count: permissions.length,
        });

        const handle = await context.writeResource(
          "permissions",
          "permissions",
          {
            server: cfg.server,
            permissions,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    roleDel: {
      description:
        "Delete a role (role_del). Requires confirm:true; audits both paths. NOTE: role deletion is privilege-escalation sensitive and admin-scoped by design.",
      arguments: z.object({
        cn: z.string().describe("Role name (cn) to delete"),
        confirm: z
          .boolean()
          .describe("Must be true; a guard against accidental deletion"),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-absent role (IPA NotFound) is treated as success instead of failing. Default false preserves fail-on-missing. The confirm guard always applies.",
          ),
      }),
      execute: async (
        args: { cn: string; confirm: boolean; idempotent?: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            `Refusing to delete role "${args.cn}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "role_del",
          ["role_del"],
          { cn: args.cn, idempotent },
          async () => {
            try {
              return await client.call("role_del", [args.cn], {});
            } catch (e) {
              // Idempotent delete: an already-gone role is a no-op success.
              // Non-NotFound errors and the default (idempotent:false) path
              // still propagate so a real failure is never masked.
              if (idempotent && isNotFound(e)) {
                context.logger.info(
                  "role_del: {cn} already absent, treating as no-op (idempotent)",
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
    privilegeShow: {
      description:
        "Snapshot a single privilege by name, including its bundled permissions (read-only).",
      arguments: z.object({
        cn: z.string().describe("Privilege name (cn) to fetch"),
      }),
      execute: async (
        args: { cn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing privilege {cn}", { cn: args.cn });
        const client = await ipaLogin(cfg);
        const res = await client.call("privilege_show", [args.cn], {
          all: true,
        });
        const privilege = parsePrivilege(
          (res.result ?? {}) as Record<string, unknown>,
        );
        context.logger.info("Retrieved privilege {cn}", { cn: args.cn });

        const handle = await context.writeResource("privilege", "privilege", {
          server: cfg.server,
          privilege,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    ensurePrivilege: {
      description:
        "Idempotently ensure a privilege exists (privilege_add). Swallows DuplicateEntry and re-reads via privilege_show, so re-runs are safe. Writes the privilege state on success; audits both paths. NOTE: privilege mutation is privilege-escalation sensitive and admin/break-glass scoped — the scoped service account is deliberately NOT granted Delegation Administrator, so this operates only within the rights the operator already holds.",
      arguments: z.object({
        cn: z.string().describe("Privilege name (cn)"),
        description: z
          .string()
          .optional()
          .describe("Free-text description (IPA `description`)"),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA privilege_add options (lowercase IPA option names), merged last",
          ),
      }),
      execute: async (
        args: {
          cn: string;
          description?: string;
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = {
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.options ?? {}),
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "privilege_add",
          ["privilege_add", "privilege_show"],
          { cn: args.cn, description: args.description ?? null },
          async () => {
            try {
              return await client.call("privilege_add", [args.cn], options);
            } catch (e) {
              // Idempotent create: an existing privilege is a no-op success.
              // Re-read the live entry so the recorded response and the
              // `privilege` state reflect reality. Non-duplicate errors still
              // propagate.
              if (isDuplicateEntry(e)) {
                context.logger.info(
                  "privilege_add: {cn} already exists, treating as no-op (idempotent)",
                  { cn: args.cn },
                );
                return await client.call("privilege_show", [args.cn], {
                  all: true,
                });
              }
              throw e;
            }
          },
        );

        const privilege = parsePrivilege(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "privilege",
          "privilege",
          {
            server: cfg.server,
            privilege,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    privilegeAddPermission: {
      description:
        "Add permissions to a privilege in one call (privilege_add_permission). Fan-out: pass a list of permissions. Surfaces IPA's `completed`/`failed`/`result` structure in the audit response; writes the updated privilege state on success. NOTE: privilege mutation is privilege-escalation sensitive and admin/break-glass scoped — bounded by the operator's own rights (no Delegation Administrator on the scoped service account).",
      arguments: z.object({
        cn: z.string().describe("Privilege name (cn)"),
        permissions: z
          .array(z.string())
          .describe("Permissions to add to the privilege (IPA `permission`)"),
      }),
      execute: async (
        args: { cn: string; permissions: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "privilege_add_permission",
          ["privilege_add_permission"],
          { cn: args.cn, permissions: args.permissions },
          async () => {
            const res = await client.call(
              "privilege_add_permission",
              [args.cn],
              { permission: args.permissions },
            );
            // `completed` count and `failed` structure are surfaced so a
            // silent half-fail (e.g. already-member) is visible in the audit.
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const privilege = parsePrivilege(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource(
          "privilege",
          "privilege",
          {
            server: cfg.server,
            privilege,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    privilegeDel: {
      description:
        "Delete a privilege (privilege_del). Requires confirm:true; audits both paths. NOTE: privilege deletion is privilege-escalation sensitive and admin/break-glass scoped by design (the scoped service account is deliberately NOT granted Delegation Administrator).",
      arguments: z.object({
        cn: z.string().describe("Privilege name (cn) to delete"),
        confirm: z
          .boolean()
          .describe("Must be true; a guard against accidental deletion"),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-absent privilege (IPA NotFound) is treated as success instead of failing. Default false preserves fail-on-missing. The confirm guard always applies.",
          ),
      }),
      execute: async (
        args: { cn: string; confirm: boolean; idempotent?: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            `Refusing to delete privilege "${args.cn}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "privilege_del",
          ["privilege_del"],
          { cn: args.cn, idempotent },
          async () => {
            try {
              return await client.call("privilege_del", [args.cn], {});
            } catch (e) {
              // Idempotent delete: an already-gone privilege is a no-op
              // success. Non-NotFound errors and the default (idempotent:false)
              // path still propagate so a real failure is never masked.
              if (idempotent && isNotFound(e)) {
                context.logger.info(
                  "privilege_del: {cn} already absent, treating as no-op (idempotent)",
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
    caAclFind: {
      description:
        "Snapshot CA ACLs matching an optional search criteria (read-only).",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all CA ACLs"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding CA ACLs matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call("caacl_find", [args.criteria ?? ""], {
          all: true,
        });
        const caAcls = ((res.result ?? []) as Array<Record<string, unknown>>)
          .map(parseCaAcl);
        context.logger.info("Found {count} CA ACLs", { count: caAcls.length });

        const handle = await context.writeResource("caAcls", "caAcls", {
          server: cfg.server,
          caAcls,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    caAclShow: {
      description: "Snapshot a single CA ACL by name (read-only).",
      arguments: z.object({
        cn: z.string().describe("CA ACL name (cn) to fetch"),
      }),
      execute: async (
        args: { cn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing CA ACL {cn}", { cn: args.cn });
        const client = await ipaLogin(cfg);
        const res = await client.call("caacl_show", [args.cn], {
          all: true,
        });
        const caAcl = parseCaAcl(
          (res.result ?? {}) as Record<string, unknown>,
        );
        context.logger.info("Retrieved CA ACL {cn}", { cn: args.cn });

        const handle = await context.writeResource("caAcl", "caAcl", {
          server: cfg.server,
          caAcl,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    ensureCaAcl: {
      description:
        "Idempotently ensure a CA ACL exists (caacl_add). Swallows DuplicateEntry and re-reads via caacl_show, so re-runs are safe. Writes the CA ACL state on success; audits both paths. `userCategory:'all'` and the other attrs are applied on CREATE only — like ensureRole/ensureSudoRule, a pre-existing divergent ACL is re-read but NOT reconciled on the duplicate path. NOTE: CA-ACL mutation is privilege-escalation sensitive and admin/break-glass scoped — a CA ACL governs who may obtain certificates; the scoped service account is deliberately NOT granted Delegation Administrator.",
      arguments: z.object({
        cn: z.string().describe("CA ACL name (cn)"),
        description: z
          .string()
          .optional()
          .describe("Free-text description (IPA `description`)"),
        userCategory: z
          .enum(["all"])
          .optional()
          .describe(
            "User category (IPA `usercategory`); `all` == the ACL applies to all users. Set this when the ACL is user-category-wide; otherwise attach explicit users via caAclAddUser. Applied on create only.",
          ),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA caacl_add options (lowercase IPA option names) — an escape hatch, merged last so it takes precedence on conflict",
          ),
      }),
      execute: async (
        args: {
          cn: string;
          description?: string;
          userCategory?: "all";
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = {
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.userCategory ? { usercategory: args.userCategory } : {}),
          ...(args.options ?? {}),
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "caacl_add",
          ["caacl_add", "caacl_show"],
          { cn: args.cn, description: args.description ?? null },
          async () => {
            try {
              return await client.call("caacl_add", [args.cn], options);
            } catch (e) {
              // Idempotent create: an existing ACL is a no-op success. Re-read
              // the live entry so the recorded response and the `caAcl` state
              // reflect reality. Non-duplicate errors still propagate.
              if (isDuplicateEntry(e)) {
                context.logger.info(
                  "caacl_add: {cn} already exists, treating as no-op (idempotent)",
                  { cn: args.cn },
                );
                return await client.call("caacl_show", [args.cn], {
                  all: true,
                });
              }
              throw e;
            }
          },
        );

        const caAcl = parseCaAcl(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource("caAcl", "caAcl", {
          server: cfg.server,
          caAcl,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    caAclAddCertprofile: {
      description:
        "Add certificate profiles to a CA ACL in one call (caacl_add_profile; the IPA CLI is `caacl-add-profile --certprofiles=`). Fan-out: pass a list of certprofiles (IPA option `certprofile`). Surfaces IPA's `completed`/`failed`/`result` structure in the audit response; writes the updated CA ACL state on success. NOTE: CA-ACL mutation is privilege-escalation sensitive and admin/break-glass scoped (no Delegation Administrator on the scoped service account).",
      arguments: z.object({
        cn: z.string().describe("CA ACL name (cn)"),
        certprofiles: z
          .array(z.string())
          .describe(
            "Certificate profiles to add (IPA `certprofile`), e.g. caIPAserviceCert",
          ),
      }),
      execute: async (
        args: { cn: string; certprofiles: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "caacl_add_profile",
          ["caacl_add_profile"],
          { cn: args.cn, certprofiles: args.certprofiles },
          async () => {
            const res = await client.call(
              "caacl_add_profile",
              [args.cn],
              { certprofile: args.certprofiles },
            );
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const caAcl = parseCaAcl(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource("caAcl", "caAcl", {
          server: cfg.server,
          caAcl,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    caAclAddUser: {
      description:
        "Add users and/or user groups to a CA ACL in one call (caacl_add_user). Fan-out: pass lists of users and groups (IPA options `user`/`group`). Surfaces IPA's `completed`/`failed`/`result` structure in the audit response; writes the updated CA ACL state on success. NOTE: CA-ACL mutation is privilege-escalation sensitive and admin/break-glass scoped (no Delegation Administrator on the scoped service account).",
      arguments: z.object({
        cn: z.string().describe("CA ACL name (cn)"),
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
          "caacl_add_user",
          ["caacl_add_user"],
          { cn: args.cn, users: args.users ?? [], groups: args.groups ?? [] },
          async () => {
            const res = await client.call("caacl_add_user", [args.cn], {
              user: args.users ?? [],
              group: args.groups ?? [],
            });
            return {
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );

        const caAcl = parseCaAcl(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource("caAcl", "caAcl", {
          server: cfg.server,
          caAcl,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    caAclSetEnabled: {
      description:
        "Enable or disable a CA ACL (caacl_enable / caacl_disable). Writes the updated CA ACL state on success; audits both paths. NOTE: CA-ACL mutation is privilege-escalation sensitive and admin/break-glass scoped (no Delegation Administrator on the scoped service account).",
      arguments: z.object({
        cn: z.string().describe("CA ACL name (cn)"),
        enabled: z
          .boolean()
          .describe("true -> caacl_enable, false -> caacl_disable"),
      }),
      execute: async (
        args: { cn: string; enabled: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const command = args.enabled ? "caacl_enable" : "caacl_disable";

        const { handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          command,
          [command],
          { cn: args.cn, enabled: args.enabled },
          () => client.call(command, [args.cn], {}),
        );

        // State resource, success-only: re-read the ACL so the snapshot
        // reflects the new enabled state (enable/disable return a boolean, not
        // the entry itself).
        const showRes = await client.call("caacl_show", [args.cn], {
          all: true,
        });
        const caAcl = parseCaAcl(
          (showRes.result ?? {}) as Record<string, unknown>,
        );
        const stateHandle = await context.writeResource("caAcl", "caAcl", {
          server: cfg.server,
          caAcl,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, stateHandle] };
      },
    },
    caAclDel: {
      description:
        "Delete a CA ACL (caacl_del). Requires confirm:true; audits both paths. NOTE: CA-ACL deletion is privilege-escalation sensitive and admin/break-glass scoped by design (the scoped service account is deliberately NOT granted Delegation Administrator).",
      arguments: z.object({
        cn: z.string().describe("CA ACL name (cn) to delete"),
        confirm: z
          .boolean()
          .describe("Must be true; a guard against accidental deletion"),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-absent CA ACL (IPA NotFound) is treated as success instead of failing. Default false preserves fail-on-missing. The confirm guard always applies.",
          ),
      }),
      execute: async (
        args: { cn: string; confirm: boolean; idempotent?: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            `Refusing to delete CA ACL "${args.cn}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "caacl_del",
          ["caacl_del"],
          { cn: args.cn, idempotent },
          async () => {
            try {
              return await client.call("caacl_del", [args.cn], {});
            } catch (e) {
              // Idempotent delete: an already-gone ACL is a no-op success.
              // Non-NotFound errors and the default (idempotent:false) path
              // still propagate so a real failure is never masked.
              if (idempotent && isNotFound(e)) {
                context.logger.info(
                  "caacl_del: {cn} already absent, treating as no-op (idempotent)",
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
