# The version reported by `litemd -version`. Defaults to the constant in
# cmd/litemd/main.go; override for a one-off build with:
#   make build VERSION=0.2.0-rc1
VERSION ?=

# Extra link flags; the version is only stamped when explicitly requested.
LDFLAGS := $(if $(VERSION),-X main.version=$(VERSION),)

.PHONY: build test test-race cover clean run install fmt vet lint snapshot release

build:
	go build $(if $(LDFLAGS),-ldflags "$(LDFLAGS)",) -o litemd ./cmd/litemd

# Cross-compile every release target into dist/ without publishing. The plain
# executables land in dist/litemd_<os>_<arch>_<variant>/litemd.
snapshot:
	goreleaser release --snapshot --clean

# Publish a release. Requires a git tag (the tag is the version) and a
# GITHUB_TOKEN in the environment.
release:
	goreleaser release

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

cover:
	go test -cover ./...

fmt:
	gofmt -l .

vet:
	go vet ./...

clean:
	rm -f litemd
	rm -rf dist

run: build
	./litemd

install:
	go install ./cmd/litemd

lint: fmt vet
	golangci-lint run
