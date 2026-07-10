# swamp-freeipa

[swamp](https://github.com/swamp-club/swamp) model extensions for managing and
inspecting [FreeIPA](https://www.freeipa.org/) domains — the `@shrug/freeipa/*`
family. Each package is an independently published, self-contained extension in
its own subdirectory.

## Packages

| Package                   | Directory          | Status    | Summary                                                                 |
| ------------------------- | ------------------ | --------- | ----------------------------------------------------------------------- |
| `@shrug/freeipa/domain`   | [`domain/`](domain) | Published | Read-only domain inspection: realm/config, server inventory, topology.  |

Additional planes (identity/users, hosts, replication topology management,
install) are planned as sibling packages.

## Installation

```sh
swamp extension pull @shrug/freeipa/domain
```

See each package's README for usage.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
