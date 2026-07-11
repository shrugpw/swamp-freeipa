# @shrug/freeipa/group

A swamp model for **managing [FreeIPA](https://www.freeipa.org/) groups** — both
user groups (`ipausergroup`) and host groups (`ipahostgroup`) — over the IPA
JSON-RPC API. It snapshots the group inventory and performs idempotent,
auditable mutations, snapshotting each as a versioned resource.

Its headline feature is **`ensureVlanGroup`**: the FreeRADIUS EAP-TLS → VLAN
steering automation.

## The FreeRADIUS `radius-vlan-<id>` payoff

The FreeRADIUS EAP-TLS → VLAN convention requires a group named
`radius-vlan-<id>` to exist as **both**:

- an `ipausergroup` — so a client **user** certificate steers, and
- an `ipahostgroup` — so a client **host** certificate steers.

FreeRADIUS's post-auth maps membership of that group → the
`Tunnel-Private-Group-Id` reply attribute, placing the supplicant on VLAN
`<id>`. `ensureVlanGroup` creates **both** halves in a single method call, and is
**idempotent**: IPA's `DuplicateEntry` (code 4002) is swallowed and treated as
"already present", so re-running against an already-provisioned VLAN is safe and
a no-op.

```sh
# Ensure the VLAN-10 steering group pair exists (creates both, or no-ops)
swamp model method run my-ipa-groups ensureVlanGroup \
  --arg vlanId=10 \
  --arg description="FreeRADIUS VLAN 10 steering"
```

This writes a `vlanGroup` state resource
(`{ vlanId, cn, userGroupPresent, hostGroupPresent, complete, retrievedAt }`).
`complete` is `true` when both halves are present; on a partial failure (one
half created, the other errored) the resource is still written with
`complete: false` before the step fails, so which half landed is never lost — a
re-run is idempotent and reconciles it. Consumers should check `complete` before
treating the pair as whole.

## Installation

```sh
swamp extension pull @shrug/freeipa/group
```

## Authentication

The model authenticates via IPA's form login (`/ipa/session/login_password`)
and reuses the returned `ipa_session` cookie for JSON-RPC calls. The admin
password is supplied through a swamp vault reference on the instance — it is
never stored in the model or its data. A [`pass`](https://www.passwordstore.org/)
-backed vault (`@webframp/pass`) is the recommended source.

If your IPA CA is not in the system trust store, point `caCert` at the PEM
(`/etc/ipa/ca.crt`) and the model trusts it per-connection.

## Usage

```sh
# Create an instance (server is required; user defaults to "admin")
swamp model create @shrug/freeipa/group my-ipa-groups \
  --global server=ipa1.example.com \
  --global 'password=${{ vault.pass.read("example.com/freeipa/admin") }}' \
  --global caCert=/etc/ipa/ca.crt

# Snapshot the user + host group inventory -> "groups" resource
swamp model method run my-ipa-groups groupFind

# Ensure a FreeRADIUS VLAN-steering group pair -> "vlanGroup" + "attempt"
swamp model method run my-ipa-groups ensureVlanGroup --arg vlanId=10

# Add members (fan-out: all members in one call)
swamp model method run my-ipa-groups groupAddMember \
  --arg cn=radius-vlan-10 --arg kind=user --arg 'users=["alice","bob"]'

swamp model method run my-ipa-groups groupAddMember \
  --arg cn=radius-vlan-10 --arg kind=host --arg 'hosts=["host1.example.com"]'

# Remove members (mirror of add)
swamp model method run my-ipa-groups groupRemoveMember \
  --arg cn=radius-vlan-10 --arg kind=user --arg 'users=["bob"]'
```

## Methods

| Method              | Kind   | IPA commands                                     | Resource(s)          |
| ------------------- | ------ | ------------------------------------------------ | -------------------- |
| `groupFind`         | read   | `group_find`, `hostgroup_find`                   | `groups`             |
| `ensureVlanGroup`   | write  | `group_add`, `hostgroup_add`                     | `vlanGroup`, `attempt` |
| `groupAddMember`    | write  | `group_add_member` / `hostgroup_add_member`      | `attempt`            |
| `groupRemoveMember` | write  | `group_remove_member` / `hostgroup_remove_member`| `attempt`            |

Read methods persist a versioned JSON snapshot. Write methods run through the
shared write-kernel (below).

## Write-safety model

Every write method obeys the `@shrug/freeipa/*` shared write-kernel.

### Three-way persistence rule

1. **STATE resources** (`vlanGroup` — the object itself) are written by the
   **caller** on the **success** path (`complete: true`). A failed mutation
   never persists *misleading* state — but a *real* partial state is not
   misleading: on a partial failure the caller persists which half actually
   landed (`complete: false`) before rethrowing (see item 2 — the same
   persist-real-state-before-throw rule).
2. **IRREPLACEABLE material** generated mid-operation (a private key, a signed
   cert — not applicable to this package) would be persisted by the caller the
   instant it is real, before any later throw.
3. The **AUDIT record** (`attempt` resource) is the write-kernel's job, written
   on **both** success and failure. It is telemetry-as-data — when `success` is
   `false` it says so truthfully — so persisting it on failure does not violate
   swamp's "don't persist misleading state" rule.

### Idempotency

`ensureVlanGroup` swallows IPA's `DuplicateEntry` (error name `DuplicateEntry`,
code 4002) for each of `group_add` and `hostgroup_add`, treating a duplicate as
"already present". Re-runs against an already-provisioned VLAN are safe no-ops.

### Partial-failure audit

`ensureVlanGroup` fans out to two independent creates (`group_add` **and**
`hostgroup_add`). If the first succeeds and the second fails with a real
(non-duplicate) error, two things are persisted before the method fails loudly:
the `attempt` audit resource captures the failure (including which command was
attempted), **and** the `vlanGroup` state resource is written with the real
partial state (`userGroupPresent: true, hostGroupPresent: false,
complete: false`). Nothing is lost — an idempotent re-run reconciles the pair.

Member add/remove surface IPA's `completed` count and `failed` structure in the
`attempt` response, so a member operation that silently half-fails is visible.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
