/**
 * FreeIPA user management model.
 *
 * Connects to an existing FreeIPA server's JSON-RPC API to inspect and manage
 * user accounts. `find`/`show` snapshot users read-only; `add`/`mod`/`del` and
 * `setEnabled` mutate them. Every mutation records an honest `attempt` audit
 * resource on BOTH the success and failure paths (see {@link recordAttempt}),
 * the state resources (`user`/`users`) are written only on success, and the
 * destructive `del` is gated behind an explicit `confirm` flag plus a `live`
 * pre-flight existence check. This is the user surface of the
 * `@shrug/freeipa/*` family.
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
// User value-shaping — parse IPA user entries into friendly rows.
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

/** A parsed FreeIPA user row (single-element IPA arrays unwrapped). */
const UserRowSchema = z.object({
  uid: z.string(),
  givenName: z.string().optional(),
  sn: z.string().optional(),
  cn: z.string().optional(),
  mail: z.array(z.string()).describe(
    "Email addresses (IPA `mail`, may be multi-valued)",
  ),
  disabled: z.boolean().describe(
    "Account lock state (IPA `nsaccountlock`); true == disabled",
  ),
  memberOfGroups: z.array(z.string()).describe(
    "Groups this user is a direct member of (IPA `memberof_group`)",
  ),
  raw: z.record(z.string(), z.unknown()).describe(
    "Full IPA user entry, unmodified — nothing is lost",
  ),
});

/** A single parsed user + provenance — the `user` state resource. */
const UserSchema = z.object({
  server: z.string(),
  user: UserRowSchema,
  retrievedAt: z.iso.datetime(),
});

/** A snapshot of many users — the `users` state resource. */
const UsersSchema = z.object({
  server: z.string(),
  users: z.array(UserRowSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * Map a raw IPA user entry (a `user_find`/`user_show`/`user_add` result row)
 * into a friendly {@link UserRowSchema} row, keeping the untouched entry under
 * `raw` so no attribute is ever lost.
 *
 * @param entry A single user entry from an IPA result.
 * @returns The flattened user row.
 */
export function parseUser(
  entry: Record<string, unknown>,
): z.infer<typeof UserRowSchema> {
  return {
    uid: String(one(entry.uid) ?? ""),
    givenName: one(entry.givenname) as string | undefined,
    sn: one(entry.sn) as string | undefined,
    cn: one(entry.cn) as string | undefined,
    mail: toStrArray(entry.mail),
    disabled: toBool(entry.nsaccountlock),
    memberOfGroups: toStrArray(entry.memberof_group),
    raw: entry,
  };
}

/** A parsed user row produced by {@link parseUser}. */
export type UserRow = z.infer<typeof UserRowSchema>;
/** A single-user snapshot resource. */
export type User = z.infer<typeof UserSchema>;
/** A multi-user snapshot resource. */
export type Users = z.infer<typeof UsersSchema>;

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

/** FreeIPA user management model definition. */
export const model = {
  type: "@shrug/freeipa/user",
  version: "2026.07.11.1",
  description:
    "Manage FreeIPA users over the JSON-RPC API: find/show read-only snapshots plus add/mod/del/setEnabled writes, each with an audit trail and a confirm-guarded delete.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "users": {
      description: "Snapshot of users matching a find (array of parsed rows)",
      schema: UsersSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "user": {
      description: "Snapshot of a single user (parsed row + raw entry)",
      schema: UserSchema,
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
    "user-exists": {
      description:
        "Verify the most recently snapshotted user still exists before a destructive delete.",
      labels: ["live"],
      appliesTo: ["del"],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        // Pre-flight checks cannot see the method's arguments, so this verifies
        // against the last `user` snapshot this model recorded. The method's own
        // confirm:true guard and IPA's NotFound error remain the per-uid
        // safeguards; this catches a stale-target delete against a live server.
        const bytes = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "user",
        );
        if (!bytes) return { pass: true };
        let uid = "";
        try {
          const snap = JSON.parse(new TextDecoder().decode(bytes)) as {
            user?: { uid?: string };
          };
          uid = snap.user?.uid ?? "";
        } catch {
          return { pass: true };
        }
        if (!uid) return { pass: true };
        const client = await ipaLogin(context.globalArgs);
        try {
          await client.call("user_show", [uid], {});
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `user "${uid}" not found on ${context.globalArgs.server}: ${
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
        "Snapshot users matching an optional search criteria (read-only).",
      arguments: z.object({
        criteria: z
          .string()
          .optional()
          .describe("Free-text search; omit to list all users"),
      }),
      execute: async (
        args: { criteria?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Finding users matching {criteria}", {
          criteria: args.criteria ?? "(all)",
        });
        const client = await ipaLogin(cfg);
        const res = await client.call("user_find", [args.criteria ?? ""], {
          all: true,
        });
        const users = ((res.result ?? []) as Array<Record<string, unknown>>)
          .map(parseUser);
        context.logger.info("Found {count} users", { count: users.length });

        const handle = await context.writeResource("users", "users", {
          server: cfg.server,
          users,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    show: {
      description: "Snapshot a single user by uid (read-only).",
      arguments: z.object({
        uid: z.string().describe("User login (uid) to fetch"),
      }),
      execute: async (
        args: { uid: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Showing user {uid}", { uid: args.uid });
        const client = await ipaLogin(cfg);
        const res = await client.call("user_show", [args.uid], { all: true });
        const user = parseUser((res.result ?? {}) as Record<string, unknown>);
        context.logger.info("Retrieved user {uid}", { uid: args.uid });

        const handle = await context.writeResource("user", "user", {
          server: cfg.server,
          user,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    add: {
      description:
        "Create a user (user_add). Writes the created user state on success; audits both paths.",
      arguments: z.object({
        uid: z.string().describe("User login (uid)"),
        givenName: z.string().describe("First name (IPA `givenname`)"),
        sn: z.string().describe("Surname (IPA `sn`)"),
        cn: z
          .string()
          .optional()
          .describe(
            "Full name (IPA `cn`); IPA derives it from givenName+sn when omitted",
          ),
        mail: z
          .array(z.string())
          .optional()
          .describe("Email address(es) (IPA `mail`)"),
        options: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Extra raw IPA user_add options (lowercase IPA option names), merged last",
          ),
      }),
      execute: async (
        args: {
          uid: string;
          givenName: string;
          sn: string;
          cn?: string;
          mail?: string[];
          options?: Record<string, unknown>;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = {
          givenname: args.givenName,
          sn: args.sn,
          ...(args.cn !== undefined ? { cn: args.cn } : {}),
          ...(args.mail !== undefined ? { mail: args.mail } : {}),
          ...(args.options ?? {}),
        };

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.uid,
          "user_add",
          ["user_add"],
          {
            uid: args.uid,
            givenName: args.givenName,
            sn: args.sn,
            cn: args.cn ?? null,
            mail: args.mail ?? null,
          },
          () => client.call("user_add", [args.uid], options),
        );

        const user = parseUser(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const userHandle = await context.writeResource("user", "user", {
          server: cfg.server,
          user,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, userHandle] };
      },
    },
    mod: {
      description:
        "Modify a user (user_mod). Writes the updated user state on success; audits both paths.",
      arguments: z.object({
        uid: z.string().describe("User login (uid) to modify"),
        set: z
          .record(z.string(), z.unknown())
          .describe(
            'Fields to change as IPA options (lowercase IPA option names, e.g. { mail: ["a@b"], givenname: "Jane" })',
          ),
      }),
      execute: async (
        args: { uid: string; set: Record<string, unknown> },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);

        const { result, handle: attemptHandle } = await recordAttempt(
          context,
          args.uid,
          "user_mod",
          ["user_mod"],
          { uid: args.uid, set: args.set },
          () => client.call("user_mod", [args.uid], args.set),
        );

        const user = parseUser(
          (result.result ?? {}) as Record<string, unknown>,
        );
        const userHandle = await context.writeResource("user", "user", {
          server: cfg.server,
          user,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, userHandle] };
      },
    },
    del: {
      description:
        "Delete or preserve a user (user_del). Requires confirm:true; audits both paths.",
      arguments: z.object({
        uid: z.string().describe("User login (uid) to delete"),
        confirm: z
          .boolean()
          .describe("Must be true; a guard against accidental deletion"),
        preserve: z
          .boolean()
          .optional()
          .describe(
            "Preserve the entry (soft-delete) instead of removing it (IPA `preserve`)",
          ),
      }),
      execute: async (
        args: { uid: string; confirm: boolean; preserve?: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.confirm !== true) {
          throw new Error(
            `Refusing to delete user "${args.uid}": pass confirm:true to proceed`,
          );
        }
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const options: Record<string, unknown> = args.preserve !== undefined
          ? { preserve: args.preserve }
          : {};

        const { handle } = await recordAttempt(
          context,
          args.uid,
          "user_del",
          ["user_del"],
          { uid: args.uid, preserve: args.preserve ?? false },
          () => client.call("user_del", [args.uid], options),
        );
        return { dataHandles: [handle] };
      },
    },
    setEnabled: {
      description:
        "Enable or disable a user (user_enable / user_disable). Writes the updated user state on success; audits both paths.",
      arguments: z.object({
        uid: z.string().describe("User login (uid)"),
        enabled: z
          .boolean()
          .describe("true -> user_enable, false -> user_disable"),
      }),
      execute: async (
        args: { uid: string; enabled: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const client = await ipaLogin(cfg);
        const command = args.enabled ? "user_enable" : "user_disable";

        const { handle: attemptHandle } = await recordAttempt(
          context,
          args.uid,
          command,
          [command],
          { uid: args.uid, enabled: args.enabled },
          () => client.call(command, [args.uid], {}),
        );

        // State resource, success-only: re-read the user so the snapshot
        // reflects the new lock state (enable/disable return a boolean, not the
        // entry itself).
        const showRes = await client.call("user_show", [args.uid], {
          all: true,
        });
        const user = parseUser(
          (showRes.result ?? {}) as Record<string, unknown>,
        );
        const userHandle = await context.writeResource("user", "user", {
          server: cfg.server,
          user,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, userHandle] };
      },
    },
  },
};
