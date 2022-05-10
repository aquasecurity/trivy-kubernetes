# Set the default goal
.DEFAULT_GOAL := test
# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on

SOURCES := $(shell find . -name '*.go')

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

.PHONY: test
## Runs both unit and integration tests
test: unit-tests 

.PHONY: unit-tests
## Runs unit tests with code coverage enabled
unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.46.0

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run --timeout 5m

