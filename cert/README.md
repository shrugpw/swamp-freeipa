# @shrug/freeipa/cert

A swamp model for **issuing, inspecting, and revoking X.509 certificates** on a
[FreeIPA](https://www.freeipa.org/) domain over its JSON-RPC API.

It is deliberately **principal-agnostic**: `certRequest` signs a CSR for any IPA
principal — a **user** (`alice`), a **host** (`host/laptop.ipa.example.com`), or a
**service** (`HTTP/web.ipa.example.com`). The FreeRADIUS EAP-TLS path needs BOTH
per-user and per-device certs, so a single surface serves both rather than
splitting user- and host-cert models.

## Installation

```sh
swamp extension pull @shrug/freeipa/cert
```

## Authentication

The model authenticates via IPA's form login (`/ipa/session/login_password`)
and reuses the returned `ipa_session` cookie for JSON-RPC calls — the same
transport seam as `@shrug/freeipa/domain`. The admin password is supplied
through a swamp vault reference on the instance; it is never stored in the model
or its data.

If your IPA CA is not in the system trust store, point `caCert` at the PEM
(`/etc/ipa/ca.crt`) and the model trusts it per-connection.

## Usage

```sh
# Create an instance (server is required; user defaults to "admin")
swamp model create @shrug/freeipa/cert my-ipa-certs \
  --global server=ipa1.example.com \
  --global 'password=${{ vault.get("freeipa", "ADMIN_PASSWORD") }}' \
  --global caCert=/etc/ipa/ca.crt

# Issue a cert, letting the model generate the keypair (key is vaulted)
swamp model method run my-ipa-certs certRequest \
  --arg principal='host/laptop.ipa.example.com'

# Issue from a CSR you already have (inline PEM or a path)
swamp model method run my-ipa-certs certRequest \
  --arg principal='alice' --arg csr=/etc/ipa/requests/alice.csr

# Look up an existing cert by serial
swamp model method run my-ipa-certs show --arg serial=268369921

# Search certs
swamp model method run my-ipa-certs find --arg subject='CN=alice'

# Revoke (guarded — confirm is required)
swamp model method run my-ipa-certs revoke \
  --arg serial=268369921 --arg confirm=true --arg reason=1
```

## Methods

| Method        | IPA command(s)  | Writes                          |
| ------------- | --------------- | ------------------------------- |
| `find`        | `cert_find`     | `certs` (result-set snapshot)   |
| `show`        | `cert_show`     | `cert` (state, no private key)  |
| `certRequest` | `cert_request`  | `cert` (state) + `attempt`      |
| `revoke`      | `cert_revoke`   | `attempt`                       |

### `certRequest` — two modes

`certRequest` issues a certificate for `principal` in one of two ways:

1. **Bring-your-own CSR.** Pass `csr` as either an inline PKCS#10 PEM string or
   a filesystem path to a PEM file (the model detects which by looking for the
   `-----BEGIN …-----` armor and reads the file when it is a path). The CSR is
   submitted as-is; **no private key is generated or stored** — you keep it.

2. **In-model keygen.** Omit `csr` and the model generates a keypair and a
   bare-CN PKCS#10 CSR in-process using WebCrypto +
   [`@peculiar/x509`](https://www.npmjs.com/package/@peculiar/x509) (no network,
   bundles cleanly under Deno). `algorithm` selects the key type:
   - `rsa` (**default**) — RSASSA-PKCS1-v1_5, `keySize` bits (default 2048).
     Works with a stock IPA CA; Dogtag's default `caIPAserviceCert` profile
     **rejects EC keys**.
   - `ec` — ECDSA P-256 (compact, modern). Use only where the CA has an
     EC-enabled cert profile, or `cert_request` fails with a `Key Type` error.

   The CSR subject is `CN=${subjectCn ?? principal}`. FreeRADIUS keys its VLAN
   lookup on `User-Name`, so a bare CN is all EAP-TLS onboarding needs.

Either way the model then calls `cert_request` with `{ principal, profile_id?,
cacn?, add }` and persists the outcome.

## Sensitive keys & vaulting

When the model generates the keypair, the resulting `cert` state resource
carries the PKCS#8 private key in its `privateKey` field, which is marked
`z.meta({ sensitive: true })`. Swamp **vaults** that field — it is encrypted at
rest and redacted from normal output. Reading an existing cert with `show`
leaves `privateKey` unset (IPA never returns private keys).

## Irreplaceable-material persistence guarantee

A generated private key exists only inside the running method. The **instant**
IPA signs the CSR, the certificate is real — and if the method then threw before
persisting, the only key matching a real, live certificate would be lost
forever. So `certRequest` persists the `cert` state resource (keypair + signed
cert) the moment the signed cert is in hand, **before any later step can throw**.
The transforms between signing and that write (`parseCertRow`, `toCertPem`) are
pure and total, so nothing can fail in between.

This is the "irreplaceable material" leg of the shared `@shrug/freeipa/*`
three-way persistence rule:

- **State** resources are written by the method, only on success.
- **Irreplaceable material** (a private key, a signed cert) is persisted the
  instant it is real, before any downstream error can discard it.
- **Audit** records (`attempt`) are written on both success and failure by the
  shared `recordAttempt` wrapper — telemetry, not state.

## Revoke guard

`revoke` is destructive, so it takes a required `confirm: boolean` and **throws
immediately unless `confirm === true`**. A `live`-labeled pre-flight check
(`cert-exists`, scoped to `revoke`) logs in and, when the serial is available,
asserts via `cert_show` that the certificate exists and is not already revoked
before the revocation runs. Skip live checks in offline environments with
`--skip-check-label live`.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
