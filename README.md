# swamp-freeipa

[swamp](https://github.com/swamp-club/swamp) model extensions for managing and
inspecting [FreeIPA](https://www.freeipa.org/) domains — the `@shrug/freeipa/*`
family. Each package is an independently published, self-contained extension in
its own subdirectory.

## Packages

| Package                 | Directory           | Status    | Summary                                                                          |
| ----------------------- | ------------------- | --------- | -------------------------------------------------------------------------------- |
| `@shrug/freeipa/domain` | [`domain/`](domain) | Published | Read-only domain inspection: realm/config, server inventory, replication topology. |
| `@shrug/freeipa/user`   | [`user/`](user)     | Published | User lifecycle: find/show + add/mod/del/setEnabled, each audited, confirm-guarded delete. |
| `@shrug/freeipa/group`  | [`group/`](group)   | Published | Groups + membership; `ensureVlanGroup` creates a `radius-vlan-<id>` pair as both an ipausergroup and ipahostgroup. |
| `@shrug/freeipa/cert`   | [`cert/`](cert)     | Published | Issue / inspect / revoke X.509 certs for any principal (user/host/service); optional in-model RSA/EC keygen with vaulted private keys. |

The `user`, `group`, and `cert` packages share a small write-kernel (an `attempt`
audit resource written on both success and failure, plus a three-way persistence
rule covering state, irreplaceable material, and audit records).

Further planes (hosts, policy/HBAC/sudo, DNS, replication-topology management,
and SSH-based install/lifecycle) are planned as sibling packages.

## Installation

```sh
swamp extension pull @shrug/freeipa/domain
swamp extension pull @shrug/freeipa/user
swamp extension pull @shrug/freeipa/group
swamp extension pull @shrug/freeipa/cert
```

See each package's README for usage.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
