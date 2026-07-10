/**
 * Model-scope report for `@shrug/freeipa/domain`.
 *
 * Reads the latest `config`, `servers`, and `topology` resource snapshots that
 * the model's `env`/`servers`/`topology` methods persist, and renders them as a
 * human-readable markdown briefing with an embedded Mermaid replication-topology
 * graph. The rendering logic lives in the model module so the report and the
 * model share one source of truth for shaping and layout.
 *
 * @module
 */
import {
  type Config,
  readLatest,
  renderMarkdown,
  type ReportContext,
  type Servers,
  type Topology,
} from "../models/domain.ts";

export const report = {
  name: "@shrug/freeipa/domain-summary",
  description:
    "Render the latest domain config, server inventory, and replication topology as markdown with a Mermaid topology graph.",
  scope: "model" as const,
  labels: ["freeipa", "inventory", "topology"],
  execute: async (
    context: ReportContext,
  ): Promise<{ markdown: string; json: Record<string, unknown> }> => {
    const config = await readLatest<Config>(context, "config");
    const servers = await readLatest<Servers>(context, "servers");
    const topology = await readLatest<Topology>(context, "topology");

    const markdown = renderMarkdown(config, servers, topology);
    const json: Record<string, unknown> = {
      realm: config?.realm ?? null,
      domain: config?.domain ?? null,
      basedn: config?.basedn ?? null,
      ipaVersion: config?.ipaVersion ?? null,
      domainLevel: config?.domainLevel ?? null,
      servers: servers?.servers ?? [],
      suffixes: topology?.suffixes ?? [],
      segments: topology?.segments ?? [],
      generatedAt: new Date().toISOString(),
    };
    return { markdown, json };
  },
};
