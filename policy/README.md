# @shrug/freeipa/policy

A swamp model for **managing [FreeIPA](https://www.freeipa.org/) policy** over
its JSON-RPC API. Wave 1 covers the **sudo** surface: it logs in with a session
password, snapshots sudo rules (`sudoRuleFind`/`sudoRuleShow`) as versioned
resources, creates them idempotently (`ensureSudoRule`), populates them
(`sudoRuleAddOption`/`sudoRuleAddUser`/`sudoRuleAddHost`/`sudoRuleAddCommand` —
the member methods fan out over lists in one call), toggles them
(`sudoRuleSetEnabled`), and deletes them (`sudoRuleDel`) — recording an honest
audit trail for every write and guarding the destructive delete behind an
explicit confirmation.

It is the policy surface of the `@shrug/freeipa/*` family; the read-only
domain-inspection surface lives in `@shrug/freeipa/domain`, and identity objects
live in `@shrug/freeipa/user`, `@shrug/freeipa/group`, and `@shrug/freeipa/host`.
HBAC and RBAC (role/privilege/permission) methods arrive in a Wave 2 version bump
of this same package.

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

- **State** (`sudoRule`/`sudoRules`) is written **only on success**. A failed
  write never leaves a misleading "live" snapshot behind.
- **Irreplaceable material** generated mid-operation (a private key, a signed
  cert) is persisted by the method the instant it is real, before any later
  throw — the policy model generates none, but the contract is shared with
  `cert` and `host`.
- **Audit** (`attempt`) is written on **both** the success and failure paths.
  The `attempt` resource records the method, the IPA commands issued, the
  sanitized request, and the result-or-error with a timestamp. It is telemetry,
  not state — persisting a `success:false` attempt is honest, not misleading.

### Confirm guard + pre-flight check

`sudoRuleDel` takes a required `confirm: boolean` and throws immediately unless
it is exactly `true`. A `live`-labeled pre-flight check (`sudorule-exists`,
scoped to `sudoRuleDel`) additionally logs in and `sudorule_show`-asserts the
last-snapshotted rule still exists on the server, failing the run when it is
absent. (Pre-flight checks cannot see a method's arguments, so the check
verifies against the most recent `sudoRule` snapshot; the `confirm` guard and
IPA's own NotFound error are the per-name safeguards.) Skip it with
`--skip-check-label live` in offline runs.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
