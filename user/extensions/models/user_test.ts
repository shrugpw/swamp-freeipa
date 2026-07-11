/**
 * Unit tests for the pure helpers of the `@shrug/freeipa/user` model.
 *
 * These cover the value-shaping logic (IPA's single-element array unwrapping,
 * boolean coercion, user-row parsing) and the JSON-RPC body builder — the parts
 * with branching worth pinning. The network seam (`ipaLogin`) is intentionally
 * not exercised here; it is covered by the live smoke test.
 *
 * @module
 */
import { assertEquals } from "jsr:@std/assert@1";
import {
  buildRpcBody,
  one,
  parseUser,
  toBool,
  toInt,
  toStrArray,
} from "./user.ts";

Deno.test("one() unwraps single-element arrays", () => {
  assertEquals(one(["jdoe"]), "jdoe");
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
  assertEquals(toStrArray(["admins", "ipausers"]), ["admins", "ipausers"]);
  assertEquals(toStrArray("ipausers"), ["ipausers"]);
  assertEquals(toStrArray(undefined), []);
});

Deno.test("toBool() reads IPA boolean-ish values", () => {
  assertEquals(toBool([true]), true);
  assertEquals(toBool("TRUE"), true);
  assertEquals(toBool(["false"]), false);
  assertEquals(toBool(false), false);
  assertEquals(toBool(undefined), false);
});

Deno.test("buildRpcBody() shapes the IPA JSON-RPC envelope", () => {
  assertEquals(buildRpcBody("user_find", [""], { all: true }, "2.254"), {
    method: "user_find/1",
    params: [[""], { all: true, version: "2.254" }],
    id: 0,
  });
});

Deno.test("parseUser() flattens a user entry and keeps raw", () => {
  const entry = {
    uid: ["jdoe"],
    givenname: ["John"],
    sn: ["Doe"],
    cn: ["John Doe"],
    mail: ["jdoe@example.com", "j.doe@example.com"],
    nsaccountlock: [true],
    memberof_group: ["admins", "ipausers"],
    dn: "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
  };
  assertEquals(parseUser(entry), {
    uid: "jdoe",
    givenName: "John",
    sn: "Doe",
    cn: "John Doe",
    mail: ["jdoe@example.com", "j.doe@example.com"],
    disabled: true,
    memberOfGroups: ["admins", "ipausers"],
    raw: entry,
  });
});

Deno.test("parseUser() defaults absent optionals sensibly", () => {
  const entry = { uid: ["svc"] };
  assertEquals(parseUser(entry), {
    uid: "svc",
    givenName: undefined,
    sn: undefined,
    cn: undefined,
    mail: [],
    disabled: false,
    memberOfGroups: [],
    raw: entry,
  });
});
