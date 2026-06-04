# Contributing

Agent Pantry handles authenticated browser sessions and secrets, so changes need
to preserve a small, auditable security boundary.

## Local checks

Run these before opening a pull request:

```sh
go test ./...
go vet ./...
make gosec
make vuln
```

For changes to parsers, framing, filesystem writes, or browser cookie decoding,
also run the relevant fuzz target:

```sh
make fuzz PKG=./internal/transport FUZZ=FuzzOpen
```

## Development notes

- Do not log cookie values, token values, pre-shared keys, or secret file
  contents.
- Keep synced domains and secret names opt-in.
- Write secret-bearing files mode `0600` and containing directories mode `0700`.
- Reject symlink targets and path traversal for sink-side secret writes.
- Prefer small, focused changes with tests at the package boundary they affect.

## Security reports

Please do not open public issues for vulnerabilities. Use the repository's
GitHub security advisory flow as described in `SECURITY.md`.
