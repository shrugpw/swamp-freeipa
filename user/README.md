# @shrug/freeipa/user

A swamp model for **managing [FreeIPA](https://www.freeipa.org/) user accounts**
over its JSON-RPC API. It logs in with a session password, snapshots users
(`find`/`show`) as versioned resources, and mutates them (`add`/`mod`/`del`/
`setEnabled`) — recording an honest audit trail for every write and guarding the
destructive delete behind an explicit confirmation.

It is the user surface of the `@shrug/freeipa/*` family; the read-only
domain-inspection surface lives in `@shrug/freeipa/domain`.

## Installation

```sh
swamp extension pull @shrug/freeipa/user
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
swamp model create @shrug/freeipa/user my-ipa-users \
  --global server=ipa1.example.com \
  --global 'password=${{ vault.pass.read("example.com/freeipa/admin") }}' \
  --global caCert=/etc/ipa/ca.crt

# Read-only: snapshot users (optionally filtered) -> "users" resource
swamp model method run my-ipa-users find --arg criteria=doe

# Read-only: snapshot one user -> "user" resource
swamp model method run my-ipa-users show --arg uid=jdoe

# Create a user -> "user" (state) + "attempt" (audit)
swamp model method run my-ipa-users add \
  --arg uid=jdoe --arg givenName=John --arg sn=Doe --arg 'mail=["jdoe@example.com"]'

# Modify a user -> updated "user" + "attempt"
swamp model method run my-ipa-users mod --arg uid=jdoe --arg 'set={"title":"Staff"}'

# Enable / disable a user -> updated "user" + "attempt"
swamp model method run my-ipa-users setEnabled --arg uid=jdoe --arg enabled=false

# Delete a user (confirm:true REQUIRED) -> "attempt"
swamp model method run my-ipa-users del --arg uid=jdoe --arg confirm=true
```

## Methods

| Method       | IPA command(s)                | Reads/Writes | State resource       | Audit |
| ------------ | ----------------------------- | ------------ | -------------------- | ----- |
| `find`       | `user_find [criteria\|""]`    | read         | `users`              | —     |
| `show`       | `user_show [uid]`             | read         | `user`               | —     |
| `add`        | `user_add [uid]`              | write        | `user` (on success)  | ✓     |
| `mod`        | `user_mod [uid]`              | write        | `user` (on success)  | ✓     |
| `del`        | `user_del [uid]`              | write        | — (nothing to store) | ✓     |
| `setEnabled` | `user_enable`/`user_disable`  | write        | `user` (on success)  | ✓     |

Parsed user rows expose `uid`, `givenName`, `sn`, `cn`, `mail[]`, `disabled`
(from `nsaccountlock`), and `memberOfGroups[]`, plus a `raw` passthrough of the
complete IPA entry so nothing is lost.

## Write-safety model

Every mutation follows the **three-way persistence rule** shared across the
`@shrug/freeipa/*` write family:

- **State** (`user`/`users`) is written **only on success**. A failed write
  never leaves a misleading "live" snapshot behind.
- **Irreplaceable material** generated mid-operation (a private key, a signed
  cert) is persisted by the method the instant it is real, before any later
  throw — the user model has none, but the contract is shared with `cert`.
- **Audit** (`attempt`) is written on **both** the success and failure paths.
  The `attempt` resource records the method, the IPA commands issued, the
  sanitized request, and the result-or-error with a timestamp. It is telemetry,
  not state — persisting a `success:false` attempt is honest, not misleading.

### Confirm guard + pre-flight check

`del` takes a required `confirm: boolean` and throws immediately unless it is
exactly `true`. A `live`-labeled pre-flight check (`user-exists`, scoped to
`del`) additionally logs in and `user_show`-asserts the last-snapshotted user
still exists on the server, failing the run when it is absent. (Pre-flight
checks cannot see a method's arguments, so the check verifies against the most
recent `user` snapshot; the `confirm` guard and IPA's own NotFound error are the
per-uid safeguards.) Skip it with `--skip-check-label live` in offline runs.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
