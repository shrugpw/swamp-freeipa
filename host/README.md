# @shrug/freeipa/host

A swamp model for **managing [FreeIPA](https://www.freeipa.org/) host (machine)
entries** over its JSON-RPC API. It logs in with a session password, snapshots
hosts (`find`/`show`) as versioned resources, mutates them (`add`/`mod`/`del`/
`disable`), and reconciles them to a desired spec (`sync`) — recording an honest
audit trail for every write and guarding the destructive delete behind an
explicit confirmation.

It is the host surface of the `@shrug/freeipa/*` family; the identity surface
lives in `@shrug/freeipa/user` and the read-only domain-inspection surface in
`@shrug/freeipa/domain`.

## Installation

```sh
swamp extension pull @shrug/freeipa/host
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
swamp model create @shrug/freeipa/host my-ipa-hosts \
  --global server=ipa1.example.com \
  --global 'password=${{ vault.pass.read("example.com/freeipa/admin") }}' \
  --global caCert=/etc/ipa/ca.crt

# Read-only: snapshot hosts (optionally filtered) -> "hosts" resource
swamp model method run my-ipa-hosts find --input criteria=host1

# Read-only: snapshot one host -> "host" resource
swamp model method run my-ipa-hosts show --input fqdn=host1.example.com

# Create a host -> "host" (state) + "attempt" (audit)
swamp model method run my-ipa-hosts add \
  --input fqdn=host1.example.com --input description="web node"

# Create with a one-time enrollment password (vaulted onto the host state)
swamp model method run my-ipa-hosts add \
  --input fqdn=host1.example.com --input random=true --input force=true

# Create idempotently: an existing host is a no-op success, not a failure
swamp model method run my-ipa-hosts add \
  --input fqdn=host1.example.com --input idempotent=true

# Modify a host -> updated "host" + "attempt"
swamp model method run my-ipa-hosts mod \
  --input fqdn=host1.example.com --input 'set={"nsosversion":"Fedora 40"}'

# Reconcile a host to a desired spec (create-or-update; converged == no writes)
swamp model method run my-ipa-hosts sync \
  --input fqdn=host1.example.com --input description="web node" \
  --input os="Fedora 40"

# Disable a host: revoke its keytab + certs (NOT a deletion) -> "host" + "attempt"
swamp model method run my-ipa-hosts disable --input fqdn=host1.example.com

# Delete a host (confirm:true REQUIRED) -> "attempt"
swamp model method run my-ipa-hosts del --input fqdn=host1.example.com --input confirm=true

# Delete idempotently, and also clean up DNS
swamp model method run my-ipa-hosts del \
  --input fqdn=host1.example.com --input confirm=true \
  --input updatedns=true --input idempotent=true
```

## Methods

| Method    | IPA command(s)                       | Reads/Writes | State resource       | Audit |
| --------- | ------------------------------------ | ------------ | -------------------- | ----- |
| `find`    | `host_find [criteria\|""]`           | read         | `hosts`              | —     |
| `show`    | `host_show [fqdn]`                   | read         | `host`               | —     |
| `add`     | `host_add [fqdn]`                    | write        | `host` (on success)  | ✓     |
| `mod`     | `host_mod [fqdn]`                    | write        | `host` (on success)  | ✓     |
| `disable` | `host_disable [fqdn]`                | write        | `host` (on success)  | ✓     |
| `del`     | `host_del [fqdn]`                    | write        | — (nothing to store) | ✓     |
| `sync`    | `host_show` + `host_add`/`host_mod`  | write        | `host` (converged)   | ✓     |

Parsed host rows expose `fqdn`, `description`, `os` (from `nsosversion`),
`platform` (from `nshardwareplatform`), `managedByHosts[]`,
`memberOfHostGroups[]`, `hasKeytab`, and `hasPassword`, plus a `raw` passthrough
of the complete IPA entry so nothing is lost.

### Enrollment OTP (`add random:true`)

`add` with `random:true` asks IPA to generate a one-time enrollment password
(`randompassword`) used to `ipa-client-install` the host. IPA returns it exactly
once and it can never be re-read, so it is treated like a signed cert's private
key: it is persisted onto the `host` state resource in a `randomPassword` field
marked sensitive (so swamp vaults it) the instant it is real, and it is
deliberately kept **out** of the `attempt` audit's request and response. An
idempotent re-read of an already-existing host never yields a fresh password.

### Idempotency & reconcile

`add` and `del` take an optional `idempotent: boolean` (default `false`). When
true, `add` treats an existing host (IPA `DuplicateEntry`) as a no-op success —
re-reading the live entry — and `del` treats an already-absent host (IPA
`NotFound`) as success. The default preserves fail-on-conflict; `del`'s `confirm`
guard always applies regardless.

`sync` reconciles a host to a desired spec: it creates the host when absent,
otherwise `host_mod`s **only** the attributes that have drifted (`description`,
`os`, and any extra `options`). It is idempotent — a fully-converged host issues
no IPA writes, and the `attempt` audit records the exact `changes` made.

## Write-safety model

Every mutation follows the **three-way persistence rule** shared across the
`@shrug/freeipa/*` write family:

- **State** (`host`/`hosts`) is written **only on success**. A failed write
  never leaves a misleading "live" snapshot behind.
- **Irreplaceable material** generated mid-operation (here, the one-time
  enrollment password from `add random:true`) is persisted by the method the
  instant it is real, before any later throw — and never enters the audit trail.
- **Audit** (`attempt`) is written on **both** the success and failure paths.
  The `attempt` resource records the method, the IPA commands issued, the
  sanitized request, and the result-or-error with a timestamp. It is telemetry,
  not state — persisting a `success:false` attempt is honest, not misleading.

### Confirm guard + pre-flight check

`del` takes a required `confirm: boolean` and throws immediately unless it is
exactly `true`. A `live`-labeled pre-flight check (`host-exists`, scoped to
`del`) additionally logs in and `host_show`-asserts the last-snapshotted host
still exists on the server, failing the run when it is absent. (Pre-flight
checks cannot see a method's arguments, so the check verifies against the most
recent `host` snapshot; the `confirm` guard and IPA's own NotFound error are the
per-fqdn safeguards.) Skip it with `--skip-check-label live` in offline runs.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
