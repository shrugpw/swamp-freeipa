# @shrug/freeipa/policy

A swamp model for **managing [FreeIPA](https://www.freeipa.org/) policy** over
its JSON-RPC API. It covers five policy surfaces — **sudo**, **HBAC**, **RBAC**
(roles/privileges/permissions), **privilege**, and **CA ACL** — each following
the same shape: log in with a session password, snapshot rules as versioned
resources, create them idempotently, populate them with fan-out member methods
(a single call per list), toggle them, and delete them behind an explicit
confirmation — recording an honest audit trail for every write.

- **sudo:** `sudoRuleFind`/`sudoRuleShow`, `ensureSudoRule`,
  `sudoRuleAddOption`/`sudoRuleAddUser`/`sudoRuleAddHost`/`sudoRuleAddCommand`,
  `sudoRuleSetEnabled`, `sudoRuleDel`.
- **HBAC:** `hbacRuleFind`/`hbacRuleShow`, `ensureHbacRule`,
  `hbacRuleAddUser`/`hbacRuleAddHost`/`hbacRuleAddService`,
  `hbacRuleSetEnabled`, `hbacRuleDel`.
- **RBAC:** `roleFind`/`roleShow`, `ensureRole`,
  `roleAddPrivilege`/`roleAddMember`, read-only `privilegeFind`/`permissionFind`,
  `roleDel`.
- **privilege:** `privilegeShow`, `ensurePrivilege`, fan-out
  `privilegeAddPermission`, `privilegeDel`.
- **CA ACL:** `caAclFind`/`caAclShow`, `ensureCaAcl`, fan-out
  `caAclAddCertprofile`/`caAclAddUser`, `caAclSetEnabled`, `caAclDel`.

> **Privilege escalation note.** The privilege and CA-ACL surfaces are
> escalation-sensitive and admin/break-glass scoped: the scoped service account
> is deliberately **not** granted
> `Delegation Administrator`, so those mutations run only within rights the
> operator already holds. A CA ACL governs who may obtain certificates; a
> privilege bundles permissions into roles. The code is auth-agnostic — this is
> an operational note.

It is the policy surface of the `@shrug/freeipa/*` family; the read-only
domain-inspection surface lives in `@shrug/freeipa/domain`, and identity objects
live in `@shrug/freeipa/user`, `@shrug/freeipa/group`, and `@shrug/freeipa/host`.

## Installation

```sh
swamp extension pull @shrug/freeipa/policy
```

## Authentication

The model authenticates via IPA's form login (`/ipa/session/login_password`)
and reuses the returned `ipa_session` cookie for JSON-RPC calls. The login
password is supplied through a swamp vault reference on the instance — it is
never stored in the model or its data. A [`pass`](https://www.passwordstore.org/)
-backed vault (`@webframp/pass`) is the recommended source. Prefer a
scoped-write service account (`Sudo Administrator` privilege) over `admin`.

If your IPA CA is not in the system trust store, point `caCert` at the PEM
(`/etc/ipa/ca.crt`) and the model trusts it per-connection.

## Usage

```sh
# Create an instance (server is required; user defaults to "admin")
swamp model create @shrug/freeipa/policy my-ipa-sudo \
  --global-arg server=ipa1.example.com \
  --global-arg 'password=${{ vault.pass.read("example.com/freeipa/svc-rw") }}' \
  --global-arg caCert=/etc/ipa/ca.crt

# Read-only: snapshot sudo rules (optionally filtered) -> "sudoRules" resource
swamp model method run my-ipa-sudo sudoRuleFind --input criteria=web

# Read-only: snapshot one rule -> "sudoRule" resource
swamp model method run my-ipa-sudo sudoRuleShow --input cn=allow-web

# Ensure a rule exists (idempotent) -> "sudoRule" (state) + "attempt" (audit).
# sudoOrder is first-class: sudo is last-match-wins, so order decides precedence.
swamp model method run my-ipa-sudo ensureSudoRule \
  --input cn=allow-web --input sudoOrder=10 --input cmdCategory=all

# Make it passwordless -> updated "sudoRule" + "attempt"
swamp model method run my-ipa-sudo sudoRuleAddOption \
  --input cn=allow-web --input 'option=!authenticate'

# Fan-out: add several users and groups in one call
swamp model method run my-ipa-sudo sudoRuleAddUser \
  --input cn=allow-web --input 'users=["alice","jdoe"]' --input 'groups=["web-admins"]'

# Fan-out: add hosts and host groups in one call
swamp model method run my-ipa-sudo sudoRuleAddHost \
  --input cn=allow-web --input 'hosts=["host1.example.com"]' --input 'hostgroups=["webservers"]'

# Fan-out: add allowed commands and command groups in one call
swamp model method run my-ipa-sudo sudoRuleAddCommand \
  --input cn=allow-web --input 'commands=["/usr/bin/systemctl"]' --input 'commandGroups=["net-tools"]'

# Enable / disable a rule -> updated "sudoRule" + "attempt"
swamp model method run my-ipa-sudo sudoRuleSetEnabled --input cn=allow-web --input enabled=false

# Delete a rule (confirm:true REQUIRED) -> "attempt"
swamp model method run my-ipa-sudo sudoRuleDel --input cn=allow-web --input confirm=true

# Delete idempotently: an already-absent rule is a no-op success
swamp model method run my-ipa-sudo sudoRuleDel --input cn=allow-web --input confirm=true --input idempotent=true
```

### HBAC

```sh
# Snapshot HBAC rules (optionally filtered) / one rule
swamp model method run my-ipa-sudo hbacRuleFind --input criteria=ssh
swamp model method run my-ipa-sudo hbacRuleShow --input cn=allow-ssh

# Ensure a rule exists (idempotent) -> "hbacRule" (state) + "attempt" (audit)
swamp model method run my-ipa-sudo ensureHbacRule --input cn=allow-ssh

# Fan-out: add users/groups, hosts/hostgroups, and services in one call each
swamp model method run my-ipa-sudo hbacRuleAddUser \
  --input cn=allow-ssh --input 'users=["alice","jdoe"]' --input 'groups=["web-admins"]'
swamp model method run my-ipa-sudo hbacRuleAddHost \
  --input cn=allow-ssh --input 'hosts=["host1.example.com"]' --input 'hostgroups=["webservers"]'
swamp model method run my-ipa-sudo hbacRuleAddService \
  --input cn=allow-ssh --input 'services=["sshd"]'

# Enable / disable, then delete (confirm:true REQUIRED)
swamp model method run my-ipa-sudo hbacRuleSetEnabled --input cn=allow-ssh --input enabled=false
swamp model method run my-ipa-sudo hbacRuleDel --input cn=allow-ssh --input confirm=true
```

### RBAC

```sh
# Read-only discovery: find privilege / permission names
swamp model method run my-ipa-sudo privilegeFind --input criteria=admin
swamp model method run my-ipa-sudo permissionFind --input criteria=user

# Snapshot roles / one role
swamp model method run my-ipa-sudo roleFind --input criteria=help
swamp model method run my-ipa-sudo roleShow --input cn=helpdesk

# Ensure a role exists (idempotent), then attach privileges and members (fan-out)
swamp model method run my-ipa-sudo ensureRole --input cn=helpdesk --input 'description=Helpdesk operators'
swamp model method run my-ipa-sudo roleAddPrivilege \
  --input cn=helpdesk --input 'privileges=["User Administrators","Group Administrators"]'
swamp model method run my-ipa-sudo roleAddMember \
  --input cn=helpdesk --input 'users=["alice"]' --input 'groups=["support"]'

# Delete a role (confirm:true REQUIRED)
swamp model method run my-ipa-sudo roleDel --input cn=helpdesk --input confirm=true
```

## Methods

| Method               | IPA command(s)                           | Reads/Writes | State resource            | Audit |
| -------------------- | ---------------------------------------- | ------------ | ------------------------- | ----- |
| `sudoRuleFind`       | `sudorule_find [criteria\|""]`           | read         | `sudoRules`               | —     |
| `sudoRuleShow`       | `sudorule_show [cn]`                      | read         | `sudoRule`                | —     |
| `ensureSudoRule`     | `sudorule_add [cn]` (+ `sudorule_show`)  | write        | `sudoRule` (on success)   | ✓     |
| `sudoRuleAddOption`  | `sudorule_add_option [cn]`               | write        | `sudoRule` (on success)   | ✓     |
| `sudoRuleAddUser`    | `sudorule_add_user [cn]`                 | write        | `sudoRule` (on success)   | ✓     |
| `sudoRuleAddHost`    | `sudorule_add_host [cn]`                 | write        | `sudoRule` (on success)   | ✓     |
| `sudoRuleAddCommand` | `sudorule_add_allow_command [cn]`        | write        | `sudoRule` (on success)   | ✓     |
| `sudoRuleSetEnabled` | `sudorule_enable`/`sudorule_disable`     | write        | `sudoRule` (on success)   | ✓     |
| `sudoRuleDel`        | `sudorule_del [cn]`                       | write        | — (nothing to store)      | ✓     |

Parsed sudo rule rows expose `cn`, `description`, `enabled` (from
`ipaenabledflag`), `sudoOrder`, `cmdCategory`/`userCategory`/`hostCategory`,
`memberUsers[]`, `memberGroups[]`, `memberHosts[]`, `memberHostGroups[]`,
`allowCommands[]`, `allowCommandGroups[]`, and `sudoOptions[]`, plus a `raw`
passthrough of the complete IPA entry so nothing is lost.

### HBAC methods

Host-Based Access Control rules gate which users may reach which services on
which hosts. The surface mirrors sudo one-for-one.

| Method               | IPA command(s)                            | Reads/Writes | State resource            | Audit |
| -------------------- | ----------------------------------------- | ------------ | ------------------------- | ----- |
| `hbacRuleFind`       | `hbacrule_find [criteria\|""]`            | read         | `hbacRules`               | —     |
| `hbacRuleShow`       | `hbacrule_show [cn]`                       | read         | `hbacRule`                | —     |
| `ensureHbacRule`     | `hbacrule_add [cn]` (+ `hbacrule_show`)    | write        | `hbacRule` (on success)   | ✓     |
| `hbacRuleAddUser`    | `hbacrule_add_user [cn]`                   | write        | `hbacRule` (on success)   | ✓     |
| `hbacRuleAddHost`    | `hbacrule_add_host [cn]`                   | write        | `hbacRule` (on success)   | ✓     |
| `hbacRuleAddService` | `hbacrule_add_service [cn]`                | write        | `hbacRule` (on success)   | ✓     |
| `hbacRuleSetEnabled` | `hbacrule_enable`/`hbacrule_disable`       | write        | `hbacRule` (on success)   | ✓     |
| `hbacRuleDel`        | `hbacrule_del [cn]`                        | write        | — (nothing to store)      | ✓     |

Parsed HBAC rule rows expose `cn`, `description`, `enabled`, `accessRuleType`,
`userCategory`/`hostCategory`/`serviceCategory`, `memberUsers[]`,
`memberGroups[]`, `memberHosts[]`, `memberHostGroups[]`, `memberServices[]`,
`memberServiceGroups[]`, plus a `raw` passthrough. `ensureHbacRule` is idempotent
(swallows `DuplicateEntry` and re-reads via `hbacrule_show`); the member methods
are fan-out (lists in one call); `hbacRuleDel` requires `confirm:true` and is
backed by the `hbacrule-exists` live pre-flight check.

### RBAC methods

Role-Based Access Control bundles privileges (which bundle permissions) and
grants them to users/groups via roles.

| Method            | IPA command(s)              | Reads/Writes | State resource          | Audit |
| ----------------- | --------------------------- | ------------ | ----------------------- | ----- |
| `roleFind`        | `role_find [criteria\|""]`  | read         | `roles`                 | —     |
| `roleShow`        | `role_show [cn]`            | read         | `role`                  | —     |
| `ensureRole`      | `role_add [cn]` (+ `role_show`) | write    | `role` (on success)     | ✓     |
| `roleAddPrivilege`| `role_add_privilege [cn]`   | write        | `role` (on success)     | ✓     |
| `roleAddMember`   | `role_add_member [cn]`      | write        | `role` (on success)     | ✓     |
| `privilegeFind`   | `privilege_find [criteria\|""]` | read     | `privileges`            | —     |
| `permissionFind`  | `permission_find [criteria\|""]` | read    | `permissions`           | —     |
| `roleDel`         | `role_del [cn]`             | write        | — (nothing to store)    | ✓     |

Parsed role rows expose `cn`, `description`, `memberUsers[]`, `memberGroups[]`,
`memberHosts[]`, `memberHostGroups[]`, `memberServices[]`, `privileges[]`, plus a
`raw` passthrough. `privilegeFind`/`permissionFind` are read-only discovery
snapshots — use them to find the privilege names to feed `roleAddPrivilege`.
`ensureRole` is idempotent; `roleAddPrivilege`/`roleAddMember` are fan-out;
`roleDel` requires `confirm:true` and is backed by the `role-exists` live
pre-flight check.

> **RBAC is privilege-escalation sensitive.** Creating a role and attaching
> privileges to it grants rights, so a scoped write service account is
> deliberately **not** granted the "Delegation Administrator" privilege.
> `ensureRole`/`roleAddPrivilege` therefore operate only **within the rights the
> operator already holds** — they cannot mint rights the caller does not have.
> Keep role/privilege mutation to a principal you have explicitly authorized for
> RBAC administration; the read-only `privilegeFind`/`permissionFind` are safe to
> run under any authenticated principal.

### Privilege methods

A privilege bundles permissions; roles then bundle privileges. These methods
build and inspect a privilege (e.g. the custom `cert-issuers` privilege).

| Method                   | IPA command(s)                            | Reads/Writes | State resource            | Audit |
| ------------------------ | ----------------------------------------- | ------------ | ------------------------- | ----- |
| `privilegeShow`          | `privilege_show [cn]`                      | read         | `privilege`               | —     |
| `ensurePrivilege`        | `privilege_add [cn]` (+ `privilege_show`)  | write        | `privilege` (on success)  | ✓     |
| `privilegeAddPermission` | `privilege_add_permission [cn]`            | write        | `privilege` (on success)  | ✓     |
| `privilegeDel`           | `privilege_del [cn]`                       | write        | — (nothing to store)      | ✓     |

Parsed privilege rows expose `cn`, `description`, `permissions[]` (merged from
IPA's `member_permission`/`memberof_permission`), plus a `raw` passthrough.
`ensurePrivilege` is idempotent (swallows `DuplicateEntry`, re-reads via
`privilege_show`); `privilegeAddPermission` is **fan-out** over a list of
permissions and surfaces IPA's `completed`/`failed`/`result` structure in the
audit (an already-member re-add returns `completed:0` + a `failed` payload and
does **not** throw); `privilegeDel` requires `confirm:true` and is backed by the
`privilege-exists` live pre-flight check.

### CA ACL methods

A CA ACL (`caacl`) defines which principals may obtain which certificate profiles
from the CA — e.g. the `user-cert-acl` ACL that lets user certs be issued
within policy instead of via an ignore-ACL bypass. Note IPA's CLI flags are
plural (`--certprofiles`/`--users`/`--groups`) but the JSON-RPC option names are
singular (`certprofile`/`user`/`group`).

| Method                | IPA command(s)                        | Reads/Writes | State resource        | Audit |
| --------------------- | ------------------------------------- | ------------ | --------------------- | ----- |
| `caAclFind`           | `caacl_find [criteria\|""]`           | read         | `caAcls`              | —     |
| `caAclShow`           | `caacl_show [cn]`                     | read         | `caAcl`               | —     |
| `ensureCaAcl`         | `caacl_add [cn]` (+ `caacl_show`)     | write        | `caAcl` (on success)  | ✓     |
| `caAclAddCertprofile` | `caacl_add_profile [cn]`              | write        | `caAcl` (on success)  | ✓     |
| `caAclAddUser`        | `caacl_add_user [cn]`                 | write        | `caAcl` (on success)  | ✓     |
| `caAclSetEnabled`     | `caacl_enable`/`caacl_disable [cn]`   | write        | `caAcl` (on success)  | ✓     |
| `caAclDel`            | `caacl_del [cn]`                      | write        | — (nothing to store)  | ✓     |

Parsed CA ACL rows expose `cn`, `description`, `enabled`, `userCategory`,
`certprofiles[]`, `users[]`, `groups[]`, `hosts[]`, `services[]`, plus a `raw`
passthrough. `ensureCaAcl` takes an optional raw `options` map (e.g.
`{ usercategory: "all" }`) and is idempotent; `caAclAddCertprofile`/`caAclAddUser`
are **fan-out**; `caAclSetEnabled` toggles enable/disable and re-reads the ACL
for state; `caAclDel` requires `confirm:true` and is backed by the `caacl-exists`
live pre-flight check.

> **Both surfaces are privilege-escalation sensitive** in the same way RBAC is: a
> privilege grants rights once bundled into a role, and a CA ACL controls
> certificate issuance. Keep their mutation to an explicitly authorized principal
> — the scoped write account is deliberately **not** granted "Delegation
> Administrator". The read-only `privilegeShow`/`caAclFind`/`caAclShow` are safe
> under any authenticated principal.

### Idempotency & reconcile

`ensureSudoRule` is idempotent by construction: an already-existing rule (IPA
`DuplicateEntry`) is treated as a no-op success — the live entry is re-read via
`sudorule_show` and recorded as the `sudoRule` state — so re-runs converge
safely. `sudoRuleDel` takes an optional `idempotent: boolean` (default `false`);
when true, an already-absent rule (IPA `NotFound`) is a success no-op. The
default preserves fail-on-missing, and `del`'s `confirm` guard always applies
regardless.

The member methods (`sudoRuleAddUser`/`AddHost`/`AddCommand`) are **fan-out**:
each accepts lists and performs one IPA call for all targets, and surfaces IPA's
`completed` count and `failed` structure in the `attempt` audit so a silent
half-fail is visible.

## Sudo gotchas (read before relying on a rule)

- **Sudo is last-match-wins**, and nsswitch typically has `sudoers: files sss`,
  which puts IPA (`sss`) rules **last**. A local `/etc/sudoers` `NOPASSWD` line
  can therefore be **shadowed** by an IPA sudo rule that does not carry
  `!authenticate` — the IPA rule matches last and wins, re-imposing a password
  prompt. If a user is covered by **multiple** IPA sudo rules, the one with the
  **highest `sudoorder`** is the effective match, so that rule must carry
  `!authenticate` for passwordless sudo to actually take effect. This is why
  `ensureSudoRule` treats `sudoOrder` as a first-class argument and
  `sudoRuleAddOption` exists.
- **The SSSD sudo cache is stale after a change.** Adding or editing an IPA sudo
  rule does not take effect on a host until SSSD refreshes its cache
  (`sssctl cache-expire -E`, or restart `sssd`). That refresh is **host-side and
  out of this package's API scope** — this model manages the rule on the IPA
  server; it does not, and cannot, expire a remote host's cache. Trigger the
  refresh yourself (or wait for the cache TTL) when testing a rule change.

## Write-safety model

Every mutation follows the **three-way persistence rule** shared across the
`@shrug/freeipa/*` write family:

- **State** (the `sudoRule`/`sudoRules`, `hbacRule`/`hbacRules`, `role`/`roles`,
  `privilege`, `caAcl`/`caAcls`, and read-only `privileges`/`permissions`
  snapshots) is written **only on success**. A failed write never leaves a
  misleading "live" snapshot behind.
- **Irreplaceable material** generated mid-operation (a private key, a signed
  cert) is persisted by the method the instant it is real, before any later
  throw — the policy model generates none, but the contract is shared with
  `cert` and `host`.
- **Audit** (`attempt`) is written on **both** the success and failure paths.
  The `attempt` resource records the method, the IPA commands issued, the
  sanitized request, and the result-or-error with a timestamp. It is telemetry,
  not state — persisting a `success:false` attempt is honest, not misleading.

### Confirm guard + pre-flight check

Each destructive delete — `sudoRuleDel`, `hbacRuleDel`, `roleDel`,
`privilegeDel`, and `caAclDel` — takes a required `confirm: boolean` and throws
immediately unless it is exactly `true`. A matching `live`-labeled pre-flight
check (`sudorule-exists`, `hbacrule-exists`, `role-exists`, `privilege-exists`,
`caacl-exists`, each scoped to its delete method) additionally logs in and
`*_show`-asserts the last-snapshotted object still exists on the server, failing
the run when it is absent. (Pre-flight checks cannot see a method's arguments, so
each check verifies against the most recent snapshot of its object; the `confirm`
guard and IPA's own NotFound error are the per-name safeguards.) Skip them with
`--skip-check-label live` in offline runs. Each delete also accepts an optional
`idempotent: boolean` (default `false`) that treats an already-absent target
(IPA `NotFound`) as a success no-op; the `confirm` guard always applies.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
