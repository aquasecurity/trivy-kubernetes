# Set the default goal
.DEFAULT_GOAL := test
# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on

SOURCES := $(shell find . -name '*.go')

.PHONY: test
## Runs both unit and integration tests
test: unit-tests 

.PHONY: unit-tests
## Runs unit tests with code coverage enabled
unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...
