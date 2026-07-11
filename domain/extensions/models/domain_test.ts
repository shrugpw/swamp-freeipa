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
  assertEquals(one(["ipa2.example.com"]), "ipa2.example.com");
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
      cn: ["ipa1.example.com"],
      ipamindomainlevel: ["0"],
      ipamaxdomainlevel: ["1"],
      enabled_role_servrole: ["CA server", "DNS server"],
      iparepltopomanagedsuffix_topologysuffix: ["domain", "ca"],
    },
    {
      cn: ["ipa2.example.com"],
      ipamindomainlevel: ["0"],
      ipamaxdomainlevel: ["1"],
      // no roles, fallback suffix attribute name
      iparepltopomanagedsuffix: ["domain"],
    },
  ];
  assertEquals(parseServers(raw), [
    {
      fqdn: "ipa1.example.com",
      minDomainLevel: 0,
      maxDomainLevel: 1,
      roles: ["CA server", "DNS server"],
      managedSuffixes: ["domain", "ca"],
    },
    {
      fqdn: "ipa2.example.com",
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
      cn: ["ipa1-to-ipa2"],
      iparepltoposegmentleftnode: ["ipa1.example.com"],
      iparepltoposegmentrightnode: ["ipa2.example.com"],
      iparepltoposegmentdirection: ["both"],
    },
  ];
  assertEquals(parseSegments("domain", raw), [
    {
      suffix: "domain",
      name: "ipa1-to-ipa2",
      left: "ipa1.example.com",
      right: "ipa2.example.com",
      direction: "both",
    },
  ]);
});

Deno.test("mermaidNodeId() and segmentArrow() sanitize/route", () => {
  assertEquals(
    mermaidNodeId("domain", "ipa1.example.com"),
    "domain_ipa1_example_com",
  );
  assertEquals(segmentArrow("both"), "<-->");
  assertEquals(segmentArrow("left-right"), "-->");
});

Deno.test("renderTopologyMermaid() groups segments into per-suffix subgraphs", () => {
  const mmd = renderTopologyMermaid({
    server: "ipa1.example.com",
    suffixes: [{ name: "domain", managedRoot: null }],
    segments: [
      {
        suffix: "domain",
        name: "f1-to-f2",
        left: "ipa1.example.com",
        right: "ipa2.example.com",
        direction: "both",
      },
    ],
    retrievedAt: "2026-07-10T00:00:00.000Z",
  });
  assertEquals(mmd.startsWith("graph LR"), true);
  assertEquals(mmd.includes("subgraph domain"), true);
  assertEquals(
    mmd.includes("domain_ipa1_example_com <--> domain_ipa2_example_com"),
    true,
  );
});

Deno.test("renderMarkdown() hints when snapshots are missing", () => {
  const md = renderMarkdown(null, null, null);
  assertEquals(md.includes("run the `env` method"), true);
  assertEquals(md.includes("run the `servers` method"), true);
  assertEquals(md.includes("run the `topology` method"), true);
});
