/**
 * Unit tests for the pure helpers of the `@shrug/freeipa/domain` model.
 *
 * These cover the value-shaping logic (IPA's single-element array unwrapping)
 * and the JSON-RPC body builder — the parts with branching worth pinning. The
 * network seam (`ipaLogin`) is intentionally not exercised here; it is covered
 * by the live smoke test.
 *
 * @module
 */
import { assertEquals } from "jsr:@std/assert@1";
import {
  buildRpcBody,
  mermaidNodeId,
  one,
  parseSegments,
  parseServers,
  renderMarkdown,
  renderTopologyMermaid,
  segmentArrow,
  toInt,
  toStrArray,
} from "./domain.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["freeipa2.ipa.shrug.pw"]), "freeipa2.ipa.shrug.pw");
  assertEquals(one("scalar"), "scalar");
  assertEquals(one([]), undefined);
  assertEquals(one(undefined), undefined);
});

Deno.test("toInt() coerces array-wrapped numeric strings", () => {
  assertEquals(toInt(["1"]), 1);
  assertEquals(toInt("0"), 0);
  assertEquals(toInt(undefined), null);
  assertEquals(toInt(["not-a-number"]), null);
});

Deno.test("toStrArray() normalizes scalars, arrays, and absence", () => {
  assertEquals(toStrArray(["CA server", "DNS server"]), [
    "CA server",
    "DNS server",
  ]);
  assertEquals(toStrArray("DNS server"), ["DNS server"]);
  assertEquals(toStrArray(undefined), []);
});

Deno.test("buildRpcBody() shapes the IPA JSON-RPC envelope", () => {
  assertEquals(buildRpcBody("server_find", [""], { all: true }, "2.254"), {
    method: "server_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("parseServers() flattens server_find rows", () => {
  const raw = [
    {
      cn: ["freeipa1.ipa.shrug.pw"],
      ipamindomainlevel: ["0"],
      ipamaxdomainlevel: ["1"],
      enabled_role_servrole: ["CA server", "DNS server"],
      iparepltopomanagedsuffix_topologysuffix: ["domain", "ca"],
    },
    {
      cn: ["freeipa2.ipa.shrug.pw"],
      ipamindomainlevel: ["0"],
      ipamaxdomainlevel: ["1"],
      // no roles, fallback suffix attribute name
      iparepltopomanagedsuffix: ["domain"],
    },
  ];
  assertEquals(parseServers(raw), [
    {
      fqdn: "freeipa1.ipa.shrug.pw",
      minDomainLevel: 0,
      maxDomainLevel: 1,
      roles: ["CA server", "DNS server"],
      managedSuffixes: ["domain", "ca"],
    },
    {
      fqdn: "freeipa2.ipa.shrug.pw",
      minDomainLevel: 0,
      maxDomainLevel: 1,
      roles: [],
      managedSuffixes: ["domain"],
    },
  ]);
});

Deno.test("parseSegments() flattens topologysegment_find edges", () => {
  const raw = [
    {
      cn: ["freeipa1-to-freeipa2"],
      iparepltoposegmentleftnode: ["freeipa1.ipa.shrug.pw"],
      iparepltoposegmentrightnode: ["freeipa2.ipa.shrug.pw"],
      iparepltoposegmentdirection: ["both"],
    },
  ];
  assertEquals(parseSegments("domain", raw), [
    {
      suffix: "domain",
      name: "freeipa1-to-freeipa2",
      left: "freeipa1.ipa.shrug.pw",
      right: "freeipa2.ipa.shrug.pw",
      direction: "both",
    },
  ]);
});

Deno.test("mermaidNodeId() and segmentArrow() sanitize/route", () => {
  assertEquals(
    mermaidNodeId("domain", "freeipa1.ipa.shrug.pw"),
    "domain_freeipa1_ipa_shrug_pw",
  );
  assertEquals(segmentArrow("both"), "<-->");
  assertEquals(segmentArrow("left-right"), "-->");
});

Deno.test("renderTopologyMermaid() groups segments into per-suffix subgraphs", () => {
  const mmd = renderTopologyMermaid({
    server: "freeipa1.ipa.shrug.pw",
    suffixes: [{ name: "domain", managedRoot: null }],
    segments: [
      {
        suffix: "domain",
        name: "f1-to-f2",
        left: "freeipa1.ipa.shrug.pw",
        right: "freeipa2.ipa.shrug.pw",
        direction: "both",
      },
    ],
    retrievedAt: "2026-07-10T00:00:00.000Z",
  });
  assertEquals(mmd.startsWith("graph LR"), true);
  assertEquals(mmd.includes("subgraph domain"), true);
  assertEquals(
    mmd.includes("domain_freeipa1_ipa_shrug_pw <--> domain_freeipa2_ipa_shrug_pw"),
    true,
  );
});

Deno.test("renderMarkdown() hints when snapshots are missing", () => {
  const md = renderMarkdown(null, null, null);
  assertEquals(md.includes("run the `env` method"), true);
  assertEquals(md.includes("run the `servers` method"), true);
  assertEquals(md.includes("run the `topology` method"), true);
});
