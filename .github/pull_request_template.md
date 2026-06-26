## Summary

- 

## Checks

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `make gosec`
- [ ] `make vuln`
- [ ] No PII, secrets, real private IPs, or machine-specific paths in the diff (content-guard clean)

## Security notes

Note any changes to synced secret material, cookie handling, filesystem writes,
network exposure, or release artifacts.
