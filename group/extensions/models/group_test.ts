/**
 * Unit tests for the pure helpers of the `@shrug/freeipa/group` model.
 *
 * These cover the value-shaping logic (IPA's single-element array unwrapping and
 * member merging), the `radius-vlan-<id>` name builder, the DuplicateEntry
 * predicate that makes group creation idempotent, and the JSON-RPC body builder.
 * The network seam (`ipaLogin`) is intentionally not exercised here; it is
 * covered by the live smoke test.
 *
 * @module
 */
import { assertEquals } from "jsr:@std/assert@1";
import {
  buildRpcBody,
  isDuplicateEntry,
  one,
  parseGroupRow,
  parseGroupRows,
  toInt,
  toStrArray,
  vlanGroupCn,
} from "./group.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["radius-vlan-10"]), "radius-vlan-10");
  assertEquals(one("scalar"), "scalar");
  assertEquals(one([]), undefined);
  assertEquals(one(undefined), undefined);
});

Deno.test("toInt() coerces array-wrapped numeric strings", () => {
  assertEquals(toInt(["10001"]), 10001);
  assertEquals(toInt("0"), 0);
  assertEquals(toInt(undefined), null);
  assertEquals(toInt(["not-a-number"]), null);
});

Deno.test("toStrArray() normalizes scalars, arrays, and absence", () => {
  assertEquals(toStrArray(["alice", "bob"]), ["alice", "bob"]);
  assertEquals(toStrArray("alice"), ["alice"]);
  assertEquals(toStrArray(undefined), []);
});

Deno.test("buildRpcBody() shapes the IPA JSON-RPC envelope", () => {
  assertEquals(buildRpcBody("group_find", [""], { all: true }, "2.254"), {
    method: "group_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("vlanGroupCn() builds the radius-vlan-<id> convention name", () => {
  assertEquals(vlanGroupCn(10), "radius-vlan-10");
  assertEquals(vlanGroupCn(99), "radius-vlan-99");
});

Deno.test("parseGroupRow() flattens a user group with gid + members", () => {
  const raw = {
    cn: ["radius-vlan-10"],
    description: ["FreeRADIUS VLAN 10 steering"],
    gidnumber: ["10001"],
    member_user: ["alice", "bob"],
    member_group: ["nested-grp"],
  };
  assertEquals(parseGroupRow(raw), {
    cn: "radius-vlan-10",
    description: "FreeRADIUS VLAN 10 steering",
    gidNumber: 10001,
    members: ["alice", "bob", "nested-grp"],
    raw,
  });
});

Deno.test("parseGroupRow() handles a host group with no gid/description", () => {
  const raw = {
    cn: ["radius-vlan-10"],
    member_host: ["host1.example.com"],
  };
  assertEquals(parseGroupRow(raw), {
    cn: "radius-vlan-10",
    description: undefined,
    gidNumber: undefined,
    members: ["host1.example.com"],
    raw,
  });
});

Deno.test("parseGroupRows() maps a find result array", () => {
  const rows = parseGroupRows([
    { cn: ["admins"], member_user: ["admin"] },
    { cn: ["editors"] },
  ]);
  assertEquals(rows.length, 2);
  assertEquals(rows[0].cn, "admins");
  assertEquals(rows[0].members, ["admin"]);
  assertEquals(rows[1].members, []);
});

Deno.test("isDuplicateEntry() detects DuplicateEntry / code 4002", () => {
  // Raw IPA error object shape.
  assertEquals(isDuplicateEntry({ name: "DuplicateEntry", code: 4002 }), true);
  assertEquals(isDuplicateEntry({ code: 4002 }), true);
  // The Error message shape formatted by ipaLogin.
  assertEquals(
    isDuplicateEntry(
      new Error(
        'IPA group_add failed: DuplicateEntry: group with name "radius-vlan-10" already exists (code 4002)',
      ),
    ),
    true,
  );
  // Bare string.
  assertEquals(isDuplicateEntry("code 4002"), true);
  // Non-duplicate errors.
  assertEquals(
    isDuplicateEntry(new Error("IPA group_add failed: NotFound: (code 4001)")),
    false,
  );
  assertEquals(isDuplicateEntry({ name: "SomethingElse", code: 4001 }), false);
  assertEquals(isDuplicateEntry(undefined), false);
});
