# @shrug/freeipa/dns

A swamp model for **managing [FreeIPA](https://www.freeipa.org/) DNS zones and
records** over its JSON-RPC API. It logs in with a session password, snapshots
zones and records (`zoneFind`/`zoneShow`/`recordFind`) as versioned resources,
creates them idempotently (`ensureZone`/`ensureRecords`/`ensureForwardZone`),
and removes them (`zoneDel`/`recordDel`) — recording an honest audit trail for
every write and guarding the destructive deletes behind an explicit
confirmation.

It is the DNS surface of the `@shrug/freeipa/*` family; the read-only
domain-inspection surface lives in `@shrug/freeipa/domain`.

## Installation

```sh
swamp extension pull @shrug/freeipa/dns
```

## Authentication

The model authenticates via IPA's form login (`/ipa/session/login_password`)
and reuses the returned `ipa_session` cookie for JSON-RPC calls. The login
password is supplied through a swamp vault reference on the instance — it is
never stored in the model or its data. A [`pass`](https://www.passwordstore.org/)
-backed vault (`@webframp/pass`) is the recommended source.

If your IPA CA is not in the system trust store, point `caCert` at the PEM
(`/etc/ipa/ca.crt`) and the model trusts it per-connection.

## Usage

```sh
# Create an instance (server is required; user defaults to "admin")
swamp model create @shrug/freeipa/dns my-ipa-dns \
  --global-arg server=ipa1.example.com \
  --global-arg 'password=${{ vault.pass.read("example.com/freeipa/admin") }}' \
  --global-arg caCert=/etc/ipa/ca.crt

# Read-only: snapshot zones (optionally filtered) -> "zones" resource
swamp model method run my-ipa-dns zoneFind --input criteria=example

# Read-only: snapshot one zone -> "zone" resource
swamp model method run my-ipa-dns zoneShow --input idnsname=example.com.

# Ensure a zone (idempotent) -> "zone" (state) + "attempt" (audit)
swamp model method run my-ipa-dns ensureZone --input idnsname=example.com.

# Read-only: snapshot a zone's records -> "records" resource
swamp model method run my-ipa-dns recordFind --input zone=example.com.

# Ensure a LIST of records in ONE call (fan-out) -> "records" + "record" + "attempt"
swamp model method run my-ipa-dns ensureRecords \
  --input zone=example.com. \
  --input 'records=[{"name":"www","type":"A","data":"192.0.2.10"},{"name":"api","type":"AAAA","data":"3fff::20"}]'

# Ensure a forward zone (idempotent) -> "zone" + "attempt"
swamp model method run my-ipa-dns ensureForwardZone \
  --input idnsname=example.com. \
  --input 'forwarders=["192.0.2.53"]' --input forwardPolicy=only

# Delete a record's rdata (confirm:true REQUIRED) -> "attempt"
swamp model method run my-ipa-dns recordDel \
  --input zone=example.com. --input name=www --input type=A \
  --input data=192.0.2.10 --input confirm=true

# Delete a zone (confirm:true REQUIRED) -> "attempt"
swamp model method run my-ipa-dns zoneDel --input idnsname=example.com. --input confirm=true

# Delete idempotently: an already-absent target is a no-op success
swamp model method run my-ipa-dns zoneDel \
  --input idnsname=example.com. --input confirm=true --input idempotent=true
```

## Methods

| Method              | IPA command(s)                                  | Reads/Writes | State resource         | Audit |
| ------------------- | ----------------------------------------------- | ------------ | ---------------------- | ----- |
| `zoneFind`          | `dnszone_find [criteria\|""]`                   | read         | `zones`                | —     |
| `zoneShow`          | `dnszone_show [idnsname]`                        | read         | `zone`                 | —     |
| `ensureZone`        | `dnszone_add [idnsname]` (+`dnszone_show`)       | write        | `zone` (on success)    | ✓     |
| `zoneDel`           | `dnszone_del [idnsname]`                         | write        | — (nothing to store)   | ✓     |
| `recordFind`        | `dnsrecord_find [zone]`                          | read         | `records`              | —     |
| `ensureRecords`     | `dnsrecord_add [zone] [name]` × N + `dnsrecord_find` | write   | `records` + `record`   | ✓     |
| `recordDel`         | `dnsrecord_del [zone] [name]`                    | write        | — (nothing to store)   | ✓     |
| `ensureForwardZone` | `dnsforwardzone_add [idnsname]` (+`dnsforwardzone_show`) | write | `zone` (on success)  | ✓     |

Parsed zone rows expose `idnsname`, `active` (from `idnszoneactive`),
`forwarders[]` (from `idnsforwarders`), and `forwardPolicy`; parsed record rows
expose `idnsname`, `ttl`, `aRecords[]`, `aaaaRecords[]`, and `cnameRecords[]`.
Both keep a `raw` passthrough of the complete IPA entry — every rdata type is
preserved there — so nothing is lost.

### `ensureRecords` is fan-out

Per [repo rule 6](../CLAUDE.md), `ensureRecords` takes a **list** of records
(`[{ name, type, data, ttl? }]`) and adds them all in **one** method run —
prefer it over looping N separate method calls, which contend on the per-model
lock. Each record is added idempotently (an existing record — IPA
`DuplicateEntry` — is a no-op success). After the batch it re-reads the zone
with `dnsrecord_find` and snapshots the resulting `records`, plus the most
recently ensured `record` (the pre-flight target for `recordDel`). The record
type is mapped to its IPA option (`A`→`arecord`, `AAAA`→`aaaarecord`,
`CNAME`→`cnamerecord`, …, with a `<type>record` fallback for uncommon types).

### Idempotency & reconcile

`ensureZone`, `ensureRecords`, and `ensureForwardZone` are **idempotent
creates**: a target that already exists (IPA `DuplicateEntry`) is treated as a
no-op success, and the live entry is re-read so the state snapshot reflects
reality. Re-running an ensure against a converged server is safe.

`zoneDel` and `recordDel` take an optional `idempotent: boolean` (default
`false`). When true, an already-absent target (IPA `NotFound`) is treated as
success instead of failing. The default preserves fail-on-missing; the `confirm`
guard always applies regardless.

## Write-safety model

Every mutation follows the **three-way persistence rule** shared across the
`@shrug/freeipa/*` write family:

- **State** (`zone`/`zones`/`record`/`records`) is written **only on success**.
  A failed write never leaves a misleading "live" snapshot behind. The one
  nuance is `ensureRecords`' honest partial apply: when part of a batch lands
  and a later record fails hard, the records that **did** land are persisted
  with `complete: false` before the step is failed — a truthful record of what
  is really on the server, and a base for an idempotent re-run.
- **Irreplaceable material** generated mid-operation (a private key, a signed
  cert) is persisted by the method the instant it is real, before any later
  throw — the DNS model generates none, but the contract is shared with `cert`.
- **Audit** (`attempt`) is written on **both** the success and failure paths.
  The `attempt` resource records the method, the IPA commands issued, the
  sanitized request, and the result-or-error with a timestamp. It is telemetry,
  not state — persisting a `success:false` attempt is honest, not misleading.

### Confirm guard + pre-flight check

`zoneDel` and `recordDel` take a required `confirm: boolean` and throw
immediately — before any transport or write — unless it is exactly `true`.
`live`-labeled pre-flight checks (`zone-exists` scoped to `zoneDel`,
`record-exists` scoped to `recordDel`) additionally log in and `_show`-assert
the last-snapshotted zone/record still exists on the server, failing the run
when it is absent. (Pre-flight checks cannot see a method's arguments, so they
verify against the most recent `zone`/`record` snapshot; the `confirm` guard and
IPA's own `NotFound` error are the per-target safeguards.) Skip them with
`--skip-check-label live` in offline runs.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
