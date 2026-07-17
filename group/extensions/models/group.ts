/**
 * FreeIPA group management model (read + write).
 *
 * Connects to an existing FreeIPA server's JSON-RPC API and manages IPA groups —
 * both user groups (`ipausergroup`) and host groups (`ipahostgroup`). It snapshots
 * the group inventory and performs idempotent, auditable mutations: creating the
 * `radius-vlan-<id>` groups that steer FreeRADIUS EAP-TLS sessions onto a VLAN,
 * and adding/removing members. This is the group-management surface of the
 * `@shrug/freeipa/*` family.
 *
 * ## Headline feature — `ensureVlanGroup` (FreeRADIUS VLAN steering)
 *
 * The FreeRADIUS EAP-TLS → VLAN convention requires a group named
 * `radius-vlan-<id>` to exist as BOTH an `ipausergroup` (so a user certificate
 * steers) AND an `ipahostgroup` (so a host certificate steers). post-auth maps
 * membership → `Tunnel-Private-Group-Id`. {@link vlanGroupCn} computes the name
 * and the `ensureVlanGroup` method creates both halves idempotently, swallowing
 * IPA's `DuplicateEntry` so re-runs are safe.
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
 * ## Write-safety model
 *
 * Mutations run through the shared {@link recordAttempt} write-kernel, which
 * persists an `attempt` audit resource on BOTH the success and failure paths so
 * a partial failure (user group created, host group failed) is never silent.
 * The `vlanGroup` state resource is written on success (`complete: true`); on a
 * partial failure the caller still persists which half landed (`complete:
 * false`) before rethrowing — the same persist-real-state-before-throw rule the
 * cert model uses for issued keys. See the package README for the three-way
 * persistence rule.
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
 * One IPA group (user group or host group), flattened from a `*_find` row.
 * IPA returns attributes as single-element arrays; these are unwrapped.
 */
const GroupRowSchema = z.object({
  cn: z.string().describe("Group common name"),
  description: z.string().optional().describe("Group description, if set"),
  gidNumber: z
    .number()
    .int()
    .optional()
    .describe("POSIX GID (user groups only)"),
  members: z
    .array(z.string())
    .describe("Direct members (users, hosts, and nested groups)"),
  raw: z
    .record(z.string(), z.unknown())
    .describe("Full raw IPA result row (passthrough)"),
});

/** Snapshot of the user-group + host-group inventory. */
const GroupsSchema = z.object({
  server: z.string(),
  userGroups: z.array(GroupRowSchema).describe("ipausergroup entries"),
  hostGroups: z.array(GroupRowSchema).describe("ipahostgroup entries"),
  retrievedAt: z.iso.datetime(),
});

/**
 * Snapshot of a single user group (parsed row + raw entry) — the `group` state
 * resource written by the generic `groupShow`/`groupAdd`/`groupMod`/`groupSync`
 * methods. The mirror of the user model's `user` resource.
 */
const GroupSchema = z.object({
  server: z.string(),
  group: GroupRowSchema,
  retrievedAt: z.iso.datetime(),
});

/**
 * State of a `radius-vlan-<id>` group pair after {@link vlanGroupCn} ensure.
 *
 * Written on success (`complete: true`) and also on a partial failure
 * (`complete: false`) — when one half landed but the other errored, the real
 * state is recorded before the step fails so it is never silent. Consumers must
 * check `complete` before treating the pair as whole.
 */
const VlanGroupSchema = z.object({
  vlanId: z.number().int().describe("Steered VLAN id"),
  cn: z.string().describe("Group name: radius-vlan-<id>"),
  userGroupPresent: z.boolean().describe("ipausergroup exists after ensure"),
  hostGroupPresent: z.boolean().describe("ipahostgroup exists after ensure"),
  complete: z
    .boolean()
    .describe("Both halves present; false = partial (re-run to reconcile)"),
  retrievedAt: z.iso.datetime(),
});

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
// Group-specific pure helpers (unit-tested; no network).
// ---------------------------------------------------------------------------

/** A single flattened group row. */
export type GroupRow = z.infer<typeof GroupRowSchema>;

/**
 * The FreeRADIUS VLAN-steering group name convention: `radius-vlan-<id>`.
 *
 * The same name must exist as both an `ipausergroup` and an `ipahostgroup`
 * (see {@link model}'s `ensureVlanGroup`).
 *
 * @param vlanId The VLAN id to steer onto.
 * @returns The canonical group common name.
 */
export function vlanGroupCn(vlanId: number): string {
  return `radius-vlan-${vlanId}`;
}

/**
 * Flatten one raw `group_find`/`hostgroup_find` result row into a
 * {@link GroupRow}. IPA single-element arrays are unwrapped; direct members
 * (users, hosts, nested groups) are merged into one `members` array.
 *
 * @param raw A raw IPA result row.
 * @returns The flattened group row.
 */
export function parseGroupRow(raw: Record<string, unknown>): GroupRow {
  const gid = toInt(raw.gidnumber);
  const members = [
    ...toStrArray(raw.member_user),
    ...toStrArray(raw.member_host),
    ...toStrArray(raw.member_group),
  ];
  return {
    cn: String(one(raw.cn) ?? ""),
    description: (one(raw.description) as string | undefined) ?? undefined,
    gidNumber: gid === null ? undefined : gid,
    members,
    raw,
  };
}

/**
 * Map a raw `group_find`/`hostgroup_find` result array into {@link GroupRow}s.
 *
 * @param result The `result` array from a find response.
 * @returns Flattened group rows.
 */
export function parseGroupRows(
  result: Array<Record<string, unknown>>,
): GroupRow[] {
  return result.map(parseGroupRow);
}

/**
 * Predicate: is this error IPA's "entry already exists" (`DuplicateEntry`,
 * code 4002)? Used to make group creation idempotent — a duplicate means the
 * group is already present, which is success for an ensure operation.
 *
 * Accepts the raw IPA error object, an `Error` whose message was formatted by
 * {@link ipaLogin} (`... DuplicateEntry: ... (code 4002)`), or a bare string.
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
 * mirror of {@link isDuplicateEntry} — used to make `groupDel` idempotent (a
 * missing target is already gone, which is success for an idempotent delete)
 * and to let `groupSync` detect an absent group and create it.
 *
 * Accepts the raw IPA error object, an `Error` whose message was formatted by
 * {@link ipaLogin} (`... NotFound: ... (code 4001)`), or a bare string. Copied
 * verbatim from the family's `user` package (extensions publish independently
 * and cannot cross-import); keep the two in sync.
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
 * `groupSync` reconcile diff. IPA stores attributes as (often single-element)
 * arrays; a desired value may be a scalar or an array. Both sides are
 * normalized to sorted string arrays and compared set-wise, so multi-valued
 * attributes are order-insensitive and `"x"` equals `["x"]`. Copied verbatim
 * from the family's `user` package; keep the two in sync.
 *
 * @param actualRaw The raw IPA value (from a parsed group's `raw` entry).
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

/** FreeIPA group management model definition. */
export const model = {
  type: "@shrug/freeipa/group",
  version: "2026.07.17.1",
  description:
    "Manage FreeIPA user & host groups over the JSON-RPC API: snapshot the inventory, generic user-group CRUD (groupShow/groupAdd/groupMod/groupDel) plus a desired-state groupSync reconcile, ensure the FreeRADIUS radius-vlan-<id> group pair, and add/remove members — idempotent and auditable, with a confirm-guarded delete.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "groups": {
      description: "User-group + host-group inventory snapshot",
      schema: GroupsSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "group": {
      description: "Snapshot of a single user group (parsed row + raw entry)",
      schema: GroupSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "vlanGroup": {
      description:
        "State of a radius-vlan-<id> group pair (user + host) after ensure",
      schema: VlanGroupSchema,
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
  checks: {
    "group-exists": {
      description:
        "Best-effort pre-flight: swamp checks cannot see the method args, so this re-checks the LAST group this model snapshotted (not necessarily the groupDel target) still exists on the server, catching a stale-target delete against a live server. The confirm:true guard and IPA's own NotFound error remain the per-cn safeguards.",
      labels: ["live"],
      appliesTo: ["groupDel"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `group` snapshot this model recorded. The method's
        // own confirm:true guard and IPA's NotFound error remain the per-cn
        // safeguards; this catches a stale-target delete against a live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "group",
        );
        if (!bytes) return { pass: true };
        let cn = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            group?: { cn?: string };
          };
          cn = snap.group?.cn ?? "";
        } catch {
          return { pass: true };
        }
        if (!cn) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("group_show", [cn], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `group "${cn}" not found on ${context.globalArgs.server}: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
  },
  methods: {
    groupFind: {
      description:
        "Snapshot user groups (group_find) and host groups (hostgroup_find), including membership.",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Optional free-text search criteria; omit to list all"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding groups matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const crit = args.criteria ?? "";
        const userRes = await client.call("group_find", [crit], { all: true });
        const hostRes = await client.call("hostgroup_find", [crit], {
          all: true,
        });
        const userGroups = parseGroupRows(
          (userRes.result ?? []) as Array<Record<string, unknown>>,
        );
        const hostGroups = parseGroupRows(
          (hostRes.result ?? []) as Array<Record<string, unknown>>,
        );
        context.logger.info(
          "Found {userCount} user groups and {hostCount} host groups",
          { userCount: userGroups.length, hostCount: hostGroups.length },
        );

        const handle = await context.writeResource("groups", "groups", {
          server: cfg.server,
          userGroups,
          hostGroups,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    groupShow: {
      description:
        "Snapshot a single user group by cn (group_show, read-only).",
      arguments: z.object({
        cn: z.string().describe("User-group common name to fetch"),
      }),
      execute: async (
        args: { cn: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing group {cn}", { cn: args.cn });
        const client = await ipaLogin(cfg);
        const res = await client.call("group_show", [args.cn], { all: true });
        const group = parseGroupRow(
          (res.result ?? {}) as Record<string, unknown>,
        );
        const handle = await context.writeResource("group", "group", {
          server: cfg.server,
          group,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    groupAdd: {
      description:
        "Create a user group (group_add). Writes the created group state on success; audits both paths. Optional idempotent flag treats an existing group as a no-op.",
      arguments: z.object({
        cn: z.string().describe("User-group common name"),
        description: z
          .string()
          .optional()
          .describe("Group description (IPA `description`)"),
        gid: z
          .number()
          .int()
          .optional()
          .describe(
            "Explicit POSIX GID (IPA `gidnumber`); omit to let IPA auto-assign",
          ),
        nonposix: z
          .boolean()
          .optional()
          .describe(
            "Create a non-POSIX group (IPA `nonposix`); omit for a normal POSIX group",
          ),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-existing group (IPA DuplicateEntry) is treated as success: the live entry is re-read and recorded as a no-op instead of failing. Default false preserves fail-on-duplicate.",
          ),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA group_add options (lowercase IPA option names), merged last",
          ),
      }),
      execute: async (
        args: {
          cn: string;
          description?: string;
          gid?: number;
          nonposix?: boolean;
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
          ...(args.gid !== undefined ? { gidnumber: args.gid } : {}),
          ...(args.nonposix !== undefined ? { nonposix: args.nonposix } : {}),
          ...(args.options ?? {}),
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "group_add",
          idempotent ? ["group_add", "group_show"] : ["group_add"],
          {
            cn: args.cn,
            description: args.description ?? null,
            gid: args.gid ?? null,
            nonposix: args.nonposix ?? null,
            idempotent,
          },
          async () => {
            try {
              return await client.call("group_add", [args.cn], options);
            } catch (e) {
              // Idempotent create: an existing group is a no-op success. Re-read
              // the live entry so the recorded response and the `group` state
              // reflect reality. Non-duplicate errors and the default
              // (idempotent:false) path still propagate.
              if (idempotent && isDuplicateEntry(e)) {
                context.logger.info(
                  "group_add: {cn} already exists, treating as no-op (idempotent)",
                  { cn: args.cn },
                );
                return await client.call("group_show", [args.cn], {
                  all: true,
                });
              }
              throw e;
            }
          },
        );

        const group = parseGroupRow(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const groupHandle = await context.writeResource("group", "group", {
          server: cfg.server,
          group,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, groupHandle] };
      },
    },
    groupMod: {
      description:
        "Modify a user group (group_mod). Writes the updated group state on success; audits both paths.",
      arguments: z.object({
        cn: z.string().describe("User-group common name to modify"),
        set: z
          .record(z.string(), z.unknown())
          .describe(
            'Fields to change as IPA options (lowercase IPA option names, e.g. { description: "swamp runtime service group", gidnumber: 12000 })',
          ),
      }),
      execute: async (
        args: { cn: string; set: Record<string, unknown> },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "group_mod",
          ["group_mod"],
          { cn: args.cn, set: args.set },
          () => client.call("group_mod", [args.cn], args.set),
        );

        const group = parseGroupRow(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const groupHandle = await context.writeResource("group", "group", {
          server: cfg.server,
          group,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, groupHandle] };
      },
    },
    groupDel: {
      description:
        "Delete a user group (group_del). Requires confirm:true; audits both paths. Optional idempotent flag treats an already-absent group as success.",
      arguments: z.object({
        cn: z.string().describe("User-group common name to delete"),
        confirm: z
          .boolean()
          .describe("Must be true; a guard against accidental deletion"),
        idempotent: z
          .boolean()
          .optional()
          .default(false)
          .describe(
            "When true, an already-absent group (IPA NotFound) is treated as success instead of failing. Default false preserves fail-on-missing. The confirm guard always applies.",
          ),
      }),
      execute: async (
        args: { cn: string; confirm: boolean; idempotent?: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            `Refusing to delete group "${args.cn}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const idempotent = args.idempotent ?? false;

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "group_del",
          ["group_del"],
          { cn: args.cn, idempotent },
          async () => {
            try {
              return await client.call("group_del", [args.cn], {});
            } catch (e) {
              // Idempotent delete: an already-gone group is a no-op success.
              // Non-NotFound errors and the default (idempotent:false) path
              // still propagate so a real failure is never masked.
              if (idempotent && isNotFound(e)) {
                context.logger.info(
                  "group_del: {cn} already absent, treating as no-op (idempotent)",
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
    groupSync: {
      description:
        "Reconcile a user group to a desired spec: create it if absent (group_add), otherwise group_mod only the drifted attributes (description/gid + extra options). Idempotent — a converged group issues no IPA writes. Membership is out of scope (see groupAddMember/groupRemoveMember). Writes the converged group state on success; audits both paths, and the audit response lists the `changes` made.",
      arguments: z.object({
        cn: z.string().describe("User-group common name to reconcile"),
        description: z
          .string()
          .optional()
          .describe(
            "Desired description (IPA `description`); omit to leave it unmanaged",
          ),
        gid: z
          .number()
          .int()
          .optional()
          .describe(
            "Desired POSIX GID (IPA `gidnumber`); omit to leave it unmanaged (IPA auto-assigns on create)",
          ),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra desired IPA attributes to reconcile (lowercase IPA option names), diffed and group_mod'd like the built-in fields",
          ),
      }),
      execute: async (
        args: {
          cn: string;
          description?: string;
          gid?: number;
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        context.logger.info("Reconciling group {cn}", { cn: args.cn });

        // 1. Read actual state (the group may not exist yet).
        let actual: GroupRow | null = null;
        try {
          const showRes = await client.call("group_show", [args.cn], {
            all: true,
          });
          actual = parseGroupRow(
            (showRes.result ?? {}) as Record<string, unknown>,
          );
        } catch (e) {
          if (!isNotFound(e)) throw e;
          context.logger.info("group {cn} absent — will create", {
            cn: args.cn,
          });
        }

        // The desired managed attribute set, in IPA option form.
        const desiredAttrs: Record<string, unknown> = {
          ...(args.description !== undefined
            ? { description: args.description }
            : {}),
          ...(args.gid !== undefined ? { gidnumber: args.gid } : {}),
          ...(args.options ?? {}),
        };

        const changes: string[] = [];
        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.cn,
          "groupSync",
          ["group_show", "group_add", "group_mod"],
          { cn: args.cn, desired: desiredAttrs },
          async () => {
            if (actual === null) {
              // 2a. Absent -> create with the full desired spec.
              await client.call("group_add", [args.cn], desiredAttrs);
              changes.push("created");
            } else {
              // 2b. Present -> group_mod only the attributes that drifted.
              const set: Record<string, unknown> = {};
              for (const [k, v] of Object.entries(desiredAttrs)) {
                if (!attrEquals(actual.raw[k], v)) set[k] = v;
              }
              if (Object.keys(set).length > 0) {
                await client.call("group_mod", [args.cn], set);
                changes.push(...Object.keys(set).map((k) => `mod:${k}`));
              }
            }
            return {
              cn: args.cn,
              created: actual === null,
              changes,
              converged: changes.length === 0,
            };
          },
        );

        // State resource, success-only: re-read so the snapshot is the
        // converged group regardless of which branch ran.
        context.logger.info("group {cn} reconciled: {changes}", {
          cn: args.cn,
          changes: (result as { changes: string[] }).changes,
        });
        const finalRes = await client.call("group_show", [args.cn], {
          all: true,
        });
        const group = parseGroupRow(
          (finalRes.result ?? {}) as Record<string, unknown>,
        );
        const groupHandle = await context.writeResource("group", "group", {
          server: cfg.server,
          group,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, groupHandle] };
      },
    },
    ensureVlanGroup: {
      description:
        "Idempotently ensure the FreeRADIUS radius-vlan-<id> group exists as BOTH an ipausergroup (group_add) and an ipahostgroup (hostgroup_add). Swallows DuplicateEntry so re-runs are safe.",
      arguments: z.object({
        vlanId: z.number().int().describe("VLAN id to steer onto"),
        description: z
          .string()
          .optional()
          .describe("Description applied to both created groups"),
      }),
      execute: async (
        args: { vlanId: number; description?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const cn = vlanGroupCn(args.vlanId);
        const options: Record<string, unknown> = args.description
          ? { description: args.description }
          : {};

        // Track which half landed in the outer scope so that if the second
        // half (hostgroup_add) fails hard, we can still persist the real
        // partial state before failing the step — a re-run is idempotent and
        // `complete: false` marks the pair as not-yet-whole.
        let userGroupPresent = false;
        let hostGroupPresent = false;
        const persistState = (complete: boolean) =>
          context.writeResource("vlanGroup", cn, {
            vlanId: args.vlanId,
            cn,
            userGroupPresent,
            hostGroupPresent,
            complete,
            retrievedAt: new Date().toISOString(),
          });

        try {
          const { handle } = await recordAttempt(
            context,
            cn,
            "ensureVlanGroup",
            ["group_add", "hostgroup_add"],
            {
              vlanId: args.vlanId,
              cn,
              description: args.description ?? null,
            },
            async () => {
              const client = await ipaLogin(cfg);

              try {
                await client.call("group_add", [cn], options);
                userGroupPresent = true;
              } catch (e) {
                if (isDuplicateEntry(e)) userGroupPresent = true;
                else throw e;
              }

              try {
                await client.call("hostgroup_add", [cn], options);
                hostGroupPresent = true;
              } catch (e) {
                if (isDuplicateEntry(e)) hostGroupPresent = true;
                else throw e;
              }

              return { userGroupPresent, hostGroupPresent };
            },
          );

          const stateHandle = await persistState(true);
          return { dataHandles: [handle, stateHandle] };
        } catch (e) {
          // Partial failure: one half may have landed. Persist that real state
          // (complete: false) before rethrowing so it is auditable and a
          // re-run can reconcile it. recordAttempt has already written the
          // failure audit with the underlying error.
          await persistState(false);
          throw e;
        }
      },
    },
    groupAddMember: {
      description:
        "Add members to a group in one call. kind=user -> group_add_member (user:[...]); kind=host -> hostgroup_add_member (host:[...]). Surfaces IPA's `failed` structure in the audit response.",
      arguments: z.object({
        cn: z.string().describe("Target group common name"),
        kind: z
          .enum(["user", "host"])
          .describe("user -> ipausergroup, host -> ipahostgroup"),
        users: z
          .array(z.string())
          .optional()
          .describe("User logins to add (kind=user)"),
        hosts: z
          .array(z.string())
          .optional()
          .describe("Host FQDNs to add (kind=host)"),
      }),
      execute: async (
        args: {
          cn: string;
          kind: "user" | "host";
          users?: string[];
          hosts?: string[];
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ipaCmd = args.kind === "user"
          ? "group_add_member"
          : "hostgroup_add_member";
        const options: Record<string, unknown> = args.kind === "user"
          ? { user: args.users ?? [] }
          : { host: args.hosts ?? [] };

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "groupAddMember",
          [ipaCmd],
          {
            cn: args.cn,
            kind: args.kind,
            users: args.users ?? [],
            hosts: args.hosts ?? [],
          },
          async () => {
            const client = await ipaLogin(cfg);
            const res = await client.call(ipaCmd, [args.cn], options);
            // `completed` count and `failed` structure are surfaced so a
            // silent half-fail is visible in the attempt audit.
            return {
              cn: args.cn,
              kind: args.kind,
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );
        return { dataHandles: [handle] };
      },
    },
    groupRemoveMember: {
      description:
        "Remove members from a group in one call. kind=user -> group_remove_member (user:[...]); kind=host -> hostgroup_remove_member (host:[...]). Surfaces IPA's `failed` structure in the audit response.",
      arguments: z.object({
        cn: z.string().describe("Target group common name"),
        kind: z
          .enum(["user", "host"])
          .describe("user -> ipausergroup, host -> ipahostgroup"),
        users: z
          .array(z.string())
          .optional()
          .describe("User logins to remove (kind=user)"),
        hosts: z
          .array(z.string())
          .optional()
          .describe("Host FQDNs to remove (kind=host)"),
      }),
      execute: async (
        args: {
          cn: string;
          kind: "user" | "host";
          users?: string[];
          hosts?: string[];
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ipaCmd = args.kind === "user"
          ? "group_remove_member"
          : "hostgroup_remove_member";
        const options: Record<string, unknown> = args.kind === "user"
          ? { user: args.users ?? [] }
          : { host: args.hosts ?? [] };

        const { handle } = await recordAttempt(
          context,
          args.cn,
          "groupRemoveMember",
          [ipaCmd],
          {
            cn: args.cn,
            kind: args.kind,
            users: args.users ?? [],
            hosts: args.hosts ?? [],
          },
          async () => {
            const client = await ipaLogin(cfg);
            const res = await client.call(ipaCmd, [args.cn], options);
            return {
              cn: args.cn,
              kind: args.kind,
              completed: res.completed ?? null,
              failed: res.failed ?? null,
              result: res.result ?? null,
            };
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
