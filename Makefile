.PHONY: build test vet windows vuln gosec fuzz package clean-dist install

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell if git rev-parse --git-dir >/dev/null 2>&1; then c=$$(git rev-parse --short HEAD); if git diff --quiet && git diff --cached --quiet; then echo $$c; else echo $$c-dirty; fi; else echo unknown; fi)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
PREFIX ?= $(HOME)/.local

build:
	go build -ldflags "$(LDFLAGS)" ./...

# Install the version-stamped binary to $(PREFIX)/bin (default ~/.local/bin).
# scripts/cut-release.sh runs this after tagging so the live binary matches the
# release; the embedded version comes from `git describe`, so run from a clean
# checkout of the tagged commit.
install:
	install -d "$(PREFIX)/bin"
	go build -trimpath -ldflags "$(LDFLAGS)" -o "$(PREFIX)/bin/agentpantry" ./cmd/agentpantry
	@echo "installed $(PREFIX)/bin/agentpantry ($(VERSION))"
test:
	go test ./...
vet:
	go vet ./...
windows:
	GOOS=windows go build -ldflags "$(LDFLAGS)" ./...
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.27.1 ./...
# Fuzz one package/target, e.g. make fuzz PKG=./internal/transport FUZZ=FuzzOpen
PKG ?= ./internal/transport
FUZZ ?= FuzzOpen
fuzz:
	go test $(PKG) -run '^$$' -fuzz $(FUZZ) -fuzztime 20s
clean-dist:
	rm -rf dist
package: clean-dist test vet gosec vuln
	mkdir -p dist/tmp
	for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		pkg="agentpantry_$(VERSION)_$${os}_$${arch}"; \
		out="dist/tmp/$$pkg"; \
		mkdir -p "$$out"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out/agentpantry$$ext" ./cmd/agentpantry; \
		cp README.md CHANGELOG.md LICENSE "$$out/"; \
		chmod 755 "$$out" "$$out/agentpantry$$ext"; \
		chmod 644 "$$out/README.md" "$$out/CHANGELOG.md" "$$out/LICENSE"; \
		tar -C dist/tmp -czf "dist/$$pkg.tar.gz" "$$pkg"; \
	done
	cd dist && sha256sum *.tar.gz > checksums.txt
	chmod 644 dist/*.tar.gz dist/checksums.txt
	rm -rf dist/tmp
