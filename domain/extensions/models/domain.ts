/**
 * FreeIPA domain inspection model (read-only).
 *
 * Connects to an existing FreeIPA server's JSON-RPC API and snapshots
 * domain-wide facts: environment/config (realm, base DN, domain level), the
 * server + replica inventory with enabled roles, and the replication topology
 * (suffixes and segments). It performs **no** mutations — this is the "understand
 * the domain under management" surface of the `@shrug/freeipa/*` family.
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

/** Snapshot of domain environment + configuration. */
const ConfigSchema = z.object({
  server: z.string(),
  realm: z.string().optional(),
  domain: z.string().optional(),
  basedn: z.string().optional(),
  ipaVersion: z.string().optional(),
  domainLevel: z.number().int().nullable(),
  env: z.record(z.string(), z.unknown()).describe("Full `env` command result"),
  config: z
    .record(z.string(), z.unknown())
    .describe("Full `config_show` command result"),
  retrievedAt: z.iso.datetime(),
});

/** One server/replica with its enabled roles. */
const ServerEntrySchema = z.object({
  fqdn: z.string(),
  minDomainLevel: z.number().int().nullable(),
  maxDomainLevel: z.number().int().nullable(),
  roles: z.array(z.string()).describe(
    "Enabled roles (CA server, DNS server …)",
  ),
  managedSuffixes: z.array(z.string()),
});

/** Snapshot of the server/replica inventory. */
const ServersSchema = z.object({
  server: z.string(),
  servers: z.array(ServerEntrySchema),
  retrievedAt: z.iso.datetime(),
});

/** One replication segment (edge in the topology graph). */
const SegmentSchema = z.object({
  suffix: z.string(),
  name: z.string(),
  left: z.string(),
  right: z.string(),
  direction: z.string(),
});

/** Snapshot of the replication topology (suffixes + segments). */
const TopologySchema = z.object({
  server: z.string(),
  suffixes: z.array(
    z.object({ name: z.string(), managedRoot: z.string().nullable() }),
  ),
  segments: z.array(SegmentSchema),
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

/**
 * Map a raw `server_find` result into friendly {@link ServerEntrySchema} rows.
 *
 * @param result The `result` array from a `server_find` response.
 * @returns Flattened server entries.
 */
export function parseServers(
  result: Array<Record<string, unknown>>,
): z.infer<typeof ServerEntrySchema>[] {
  return result.map((s) => ({
    fqdn: String(one(s.cn) ?? ""),
    minDomainLevel: toInt(s.ipamindomainlevel),
    maxDomainLevel: toInt(s.ipamaxdomainlevel),
    roles: toStrArray(s.enabled_role_servrole),
    managedSuffixes: toStrArray(
      s.iparepltopomanagedsuffix_topologysuffix ??
        s.iparepltopomanagedsuffix,
    ),
  }));
}

/**
 * Map a raw `topologysegment_find` result into {@link SegmentSchema} edges.
 *
 * @param suffix The topology suffix these segments belong to.
 * @param result The `result` array from a `topologysegment_find` response.
 * @returns Flattened replication segments.
 */
export function parseSegments(
  suffix: string,
  result: Array<Record<string, unknown>>,
): z.infer<typeof SegmentSchema>[] {
  return result.map((seg) => ({
    suffix,
    name: String(one(seg.cn) ?? ""),
    left: String(one(seg.iparepltoposegmentleftnode) ?? ""),
    right: String(one(seg.iparepltoposegmentrightnode) ?? ""),
    direction: String(one(seg.iparepltoposegmentdirection) ?? ""),
  }));
}

// ---------------------------------------------------------------------------
// Report: render the latest config/servers/topology snapshots as markdown with
// a Mermaid graph of the replication topology.
// ---------------------------------------------------------------------------

/** Realm/configuration snapshot produced by the `env` method. */
export type Config = z.infer<typeof ConfigSchema>;
/** Replica-server inventory snapshot produced by the `servers` method. */
export type Servers = z.infer<typeof ServersSchema>;
/** Replication-topology snapshot produced by the `topology` method. */
export type Topology = z.infer<typeof TopologySchema>;
type Segment = z.infer<typeof SegmentSchema>;

/**
 * Sanitize an FQDN into a Mermaid-safe node id, namespaced by suffix so the
 * same host appears as a distinct node in each suffix subgraph.
 *
 * @param suffix Topology suffix (e.g. `domain`).
 * @param fqdn Server FQDN.
 * @returns An identifier containing only `[A-Za-z0-9_]`.
 */
export function mermaidNodeId(suffix: string, fqdn: string): string {
  return `${suffix}_${fqdn}`.replace(/[^a-zA-Z0-9_]/g, "_");
}

/**
 * Mermaid arrow for a replication segment direction.
 *
 * @param direction IPA segment direction (`both`, `left-right`, `right-left`).
 * @returns `<-->` for bidirectional, `-->` for one-way.
 */
export function segmentArrow(direction: string): string {
  return direction === "both" ? "<-->" : "-->";
}

/**
 * Render the replication topology as a Mermaid `graph LR`, one subgraph per
 * suffix. Right-to-left segments are drawn with endpoints swapped so the arrow
 * points the correct way.
 *
 * @param topology The topology snapshot.
 * @returns Mermaid source (without the surrounding code fence).
 */
export function renderTopologyMermaid(topology: Topology): string {
  const bySuffix = new Map<string, Segment[]>();
  for (const seg of topology.segments) {
    const list = bySuffix.get(seg.suffix) ?? [];
    list.push(seg);
    bySuffix.set(seg.suffix, list);
  }

  const lines = ["graph LR"];
  for (const [suffix, segs] of bySuffix) {
    lines.push(`  subgraph ${suffix}`);
    const nodes = new Set<string>();
    for (const seg of segs) {
      nodes.add(seg.left);
      nodes.add(seg.right);
    }
    for (const fqdn of nodes) {
      lines.push(`    ${mermaidNodeId(suffix, fqdn)}["${fqdn}"]`);
    }
    for (const seg of segs) {
      const [a, b] = seg.direction === "right-left"
        ? [seg.right, seg.left]
        : [seg.left, seg.right];
      lines.push(
        `    ${mermaidNodeId(suffix, a)} ${segmentArrow(seg.direction)} ` +
          `${mermaidNodeId(suffix, b)}`,
      );
    }
    lines.push("  end");
  }
  return lines.join("\n");
}

/**
 * Render a full markdown domain summary from the three latest snapshots. Any
 * snapshot may be `null` (its method has not been run yet) — the corresponding
 * section renders a hint instead of failing.
 *
 * @param config Latest `config` snapshot, or null.
 * @param servers Latest `servers` snapshot, or null.
 * @param topology Latest `topology` snapshot, or null.
 * @returns Markdown document.
 */
export function renderMarkdown(
  config: Config | null,
  servers: Servers | null,
  topology: Topology | null,
): string {
  const lines: string[] = [];
  lines.push(`# FreeIPA domain — ${config?.realm ?? "(realm unknown)"}`, "");

  if (config) {
    lines.push(
      `- **Domain:** ${config.domain ?? "?"}`,
      `- **Base DN:** ${config.basedn ?? "?"}`,
      `- **IPA version:** ${config.ipaVersion ?? "?"}`,
      `- **Domain level:** ${config.domainLevel ?? "?"}`,
      `- **Queried via:** ${config.server}`,
      `- **Snapshot:** ${config.retrievedAt}`,
      "",
    );
  } else {
    lines.push("_No `config` snapshot yet — run the `env` method._", "");
  }

  lines.push(`## Servers${servers ? ` (${servers.servers.length})` : ""}`, "");
  if (servers && servers.servers.length > 0) {
    lines.push(
      "| FQDN | Roles | Domain level | Managed suffixes |",
      "| --- | --- | --- | --- |",
    );
    for (const s of servers.servers) {
      const lvl = s.minDomainLevel === s.maxDomainLevel
        ? `${s.minDomainLevel}`
        : `${s.minDomainLevel}–${s.maxDomainLevel}`;
      lines.push(
        `| ${s.fqdn} | ${s.roles.join(", ")} | ${lvl} | ` +
          `${s.managedSuffixes.join(", ")} |`,
      );
    }
    lines.push("");
  } else {
    lines.push("_No `servers` snapshot yet — run the `servers` method._", "");
  }

  lines.push("## Replication topology", "");
  if (topology && topology.segments.length > 0) {
    lines.push("```mermaid", renderTopologyMermaid(topology), "```", "");
    lines.push(
      "| Suffix | Left | Direction | Right |",
      "| --- | --- | --- | --- |",
    );
    for (const seg of topology.segments) {
      lines.push(
        `| ${seg.suffix} | ${seg.left} | ${seg.direction} | ${seg.right} |`,
      );
    }
    lines.push("");
  } else if (topology) {
    lines.push("_No replication segments (single-server domain?)._", "");
  } else {
    lines.push("_No `topology` snapshot yet — run the `topology` method._", "");
  }

  return lines.join("\n");
}

/** Minimal shape of the report context this model's report relies on. */
export interface ReportContext {
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

/**
 * Read the latest bytes of a named resource and JSON-parse them, or return null
 * when the resource has not been produced yet.
 *
 * @param ctx Report context providing the data repository.
 * @param dataName Resource instance name (`config`, `servers`, `topology`).
 * @returns The parsed resource object, or null when absent.
 */
export async function readLatest<T>(
  ctx: ReportContext,
  dataName: string,
): Promise<T | null> {
  const bytes = await ctx.dataRepository.getContent(
    ctx.modelType,
    ctx.modelId,
    dataName,
  );
  if (!bytes) return null;
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

/**
 * The structural slice of swamp's LogTape logger the methods use. Declared
 * locally (not imported) so the model stays self-contained. Messages use
 * `{name}` placeholders filled from the properties object — never string
 * interpolation, and never secrets.
 */
interface MethodLogger {
  debug(message: string, properties?: Record<string, unknown>): void;
  info(message: string, properties?: Record<string, unknown>): void;
  warning(message: string, properties?: Record<string, unknown>): void;
  error(message: string, properties?: Record<string, unknown>): void;
}

/** Minimal shape of the execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: MethodLogger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** FreeIPA domain inspection model definition. */
export const model = {
  type: "@shrug/freeipa/domain",
  version: "2026.07.11.1",
  description:
    "Read-only FreeIPA domain inspection over the JSON-RPC API: env/config, server & role inventory, replication topology.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "config": {
      description: "Domain environment + configuration snapshot",
      schema: ConfigSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "servers": {
      description: "Server/replica inventory with enabled roles",
      schema: ServersSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "topology": {
      description: "Replication topology (suffixes + segments)",
      schema: TopologySchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  methods: {
    env: {
      description:
        "Snapshot domain environment + configuration (realm, base DN, domain level).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Snapshotting domain env/config from {server}", {
          server: cfg.server,
        });
        const client = await ipaLogin(cfg);
        const envRes = await client.call("env", [], {});
        const configRes = await client.call("config_show", [], { all: true });
        const levelRes = await client.call("domainlevel_get", [], {});

        const env = (envRes.result ?? {}) as Record<string, unknown>;
        const config = (configRes.result ?? {}) as Record<string, unknown>;
        context.logger.info("Captured domain config (realm={realm})", {
          realm: String(one(env.realm) ?? "unknown"),
        });

        const handle = await context.writeResource("config", "config", {
          server: cfg.server,
          realm: one(env.realm) as string | undefined,
          domain: one(env.domain) as string | undefined,
          basedn: one(env.basedn) as string | undefined,
          ipaVersion: one(env.version) as string | undefined,
          domainLevel: toInt(levelRes.result),
          env,
          config,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    servers: {
      description:
        "Snapshot the server/replica inventory and each server's enabled roles.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info("Snapshotting server inventory from {server}", {
          server: cfg.server,
        });
        const client = await ipaLogin(cfg);
        const serverRes = await client.call("server_find", [""], { all: true });
        const servers = parseServers(
          (serverRes.result ?? []) as Array<Record<string, unknown>>,
        );
        context.logger.info("Captured {count} servers", {
          count: servers.length,
        });

        const handle = await context.writeResource("servers", "servers", {
          server: cfg.server,
          servers,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    topology: {
      description:
        "Snapshot the replication topology: every suffix and its segments.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        context.logger.info(
          "Snapshotting replication topology from {server}",
          { server: cfg.server },
        );
        const client = await ipaLogin(cfg);
        const suffixRes = await client.call("topologysuffix_find", [""], {
          all: true,
        });
        const suffixRows = (suffixRes.result ?? []) as Array<
          Record<string, unknown>
        >;

        const suffixes = suffixRows.map((s) => ({
          name: String(one(s.cn) ?? ""),
          managedRoot: (one(s.iparepltopoconfroot) as string | undefined) ??
            null,
        }));

        const segments: z.infer<typeof SegmentSchema>[] = [];
        for (const suffix of suffixes) {
          const segRes = await client.call(
            "topologysegment_find",
            [suffix.name],
            { all: true },
          );
          segments.push(
            ...parseSegments(
              suffix.name,
              (segRes.result ?? []) as Array<Record<string, unknown>>,
            ),
          );
        }

        context.logger.info(
          "Captured {suffixCount} suffixes and {segmentCount} segments",
          { suffixCount: suffixes.length, segmentCount: segments.length },
        );

        const handle = await context.writeResource("topology", "topology", {
          server: cfg.server,
          suffixes,
          segments,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
  },
  reports: ["@shrug/freeipa/domain-summary"],
};
