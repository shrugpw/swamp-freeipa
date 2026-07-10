# @shrug/freeipa/domain

A swamp model for **read-only inspection of a [FreeIPA](https://www.freeipa.org/)
domain** over its JSON-RPC API. It logs in with a session password, reads the
realm/configuration, enumerates the replica servers and their roles, and maps
the replication topology — snapshotting each as a versioned resource so you can
diff a domain over time or feed the data into reports and workflows.

It never mutates the domain.

## Installation

```sh
swamp extension pull @shrug/freeipa/domain
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
swamp model create @shrug/freeipa/domain my-ipa \
  --global server=ipa1.example.com \
  --global 'password=${{ vault.pass.read("example.com/freeipa/admin") }}' \
  --global caCert=/etc/ipa/ca.crt

# Realm / config summary  -> "config" resource
swamp model method run my-ipa env

# Replica inventory + roles -> "servers" resource
swamp model method run my-ipa servers

# Replication topology (suffixes + segments) -> "topology" resource
swamp model method run my-ipa topology
```

## Methods

| Method     | Reads (IPA commands)                                            | Resource   |
| ---------- | -------------------------------------------------------------- | ---------- |
| `env`      | `env`, `config_show`, `domainlevel_get`                        | `config`   |
| `servers`  | `server_find`                                                  | `servers`  |
| `topology` | `topologysuffix_find`, `topologysegment_find`                 | `topology` |

Each method persists a single versioned JSON resource snapshot; nothing on the
domain is changed.

## Report

`@shrug/freeipa/domain-summary` (model scope) renders the latest `config`,
`servers`, and `topology` snapshots as a markdown briefing with an embedded
Mermaid replication-topology graph:

```sh
swamp report get "@shrug/freeipa/domain-summary" --model my-ipa --markdown
```

## License

MIT — see [LICENSE.txt](LICENSE.txt).
