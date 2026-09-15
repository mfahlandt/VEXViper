GO ?= go
BIN := bin/vexviper
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test test-race test-integration lint fmt vet clean e2e e2e-ci

all: build

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/vexviper

test:
	$(GO) test ./... -count=1

test-race:
	$(GO) test ./... -count=1 -race

# Requires a running BOMHort with AUTH_ENABLED=true; see hack/e2e-bomhort.sh
test-integration:
	$(GO) test ./test/integration/ -count=1 -tags=integration -v

fmt:
	@test -z "$$(gofmt -l cmd internal test | tee /dev/stderr)" || (echo "gofmt: files need formatting" && exit 1)

vet:
	$(GO) vet ./...

lint: fmt vet
	$(GO) vet -tags=integration ./test/...

e2e:
	./hack/e2e-bomhort.sh

# Same as CI (.github/workflows/e2e.yml): build BOMHort from $(BOMHORT_SRC), do not touch examples/.
e2e-ci:
	BOMHORT_BUILD=1 BOMHORT_IMAGE_PREFIX=vexviper-e2e/ BOMHORT_IMAGE_TAG=ci E2E_UPDATE_EXAMPLE=0 ./hack/e2e-bomhort.sh

clean:
	rm -rf bin dist .vexviper-cache
