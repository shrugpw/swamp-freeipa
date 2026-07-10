/**
 * Unit tests for the `@shrug/freeipa/domain-summary` report's `execute`.
 *
 * These exercise the report end-to-end with a stub `dataRepository`: the happy
 * path where all three snapshots are present, and the empty path where none
 * have been produced yet. The markdown-shaping internals are covered separately
 * in the model's `domain_test.ts`; here we pin the report's own wiring (reading
 * the right resources and assembling the `json` sidecar).
 *
 * @module
 */
import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { report } from "./freeipa_domain_summary.ts";
import type { ReportContext } from "../models/domain.ts";

/** Build a stub ReportContext whose data repository serves the given resources. */
function contextWith(
  resources: Record<string, unknown>,
): ReportContext {
  return {
    modelType: "@shrug/freeipa/domain",
    modelId: "test-ipa",
    dataRepository: {
      // deno-lint-ignore require-await
      getContent: async (_type, _modelId, dataName) => {
        if (!(dataName in resources)) return null;
        return new TextEncoder().encode(JSON.stringify(resources[dataName]));
      },
    },
  };
}

Deno.test("report renders all three snapshots into markdown + json", async () => {
  const ctx = contextWith({
    config: {
      server: "ipa1.example.com",
      realm: "EXAMPLE.COM",
      domain: "ipa.example.com",
      basedn: "dc=example,dc=com",
      ipaVersion: "4.13.1",
      domainLevel: 1,
      env: {},
      config: {},
      retrievedAt: "2026-07-10T00:00:00.000Z",
    },
    servers: {
      server: "ipa1.example.com",
      servers: [
        {
          fqdn: "ipa1.example.com",
          minDomainLevel: 1,
          maxDomainLevel: 1,
          roles: ["CA server"],
          managedSuffixes: ["domain", "ca"],
        },
      ],
      retrievedAt: "2026-07-10T00:00:00.000Z",
    },
    topology: {
      server: "ipa1.example.com",
      suffixes: [{ name: "domain", managedRoot: null }],
      segments: [
        {
          suffix: "domain",
          name: "ipa1-to-ipa2",
          left: "ipa1.example.com",
          right: "ipa2.example.com",
          direction: "both",
        },
      ],
      retrievedAt: "2026-07-10T00:00:00.000Z",
    },
  });

  const out = await report.execute(ctx);

  assertStringIncludes(out.markdown, "# FreeIPA domain — EXAMPLE.COM");
  assertStringIncludes(out.markdown, "ipa1.example.com");
  assertStringIncludes(out.markdown, "```mermaid");
  assertEquals(out.json.realm, "EXAMPLE.COM");
  assertEquals(out.json.domainLevel, 1);
  assertEquals((out.json.servers as unknown[]).length, 1);
  assertEquals((out.json.segments as unknown[]).length, 1);
});

Deno.test("report degrades gracefully when no snapshots exist", async () => {
  const out = await report.execute(contextWith({}));

  assertStringIncludes(out.markdown, "run the `env` method");
  assertStringIncludes(out.markdown, "run the `servers` method");
  assertStringIncludes(out.markdown, "run the `topology` method");
  assertEquals(out.json.realm, null);
  assertEquals(out.json.servers, []);
  assertEquals(out.json.segments, []);
});
