# Set the default goal
.DEFAULT_GOAL := test

# for outdated (deprecated) K8s APIs
OUTDATED_API_DATA_URL=https://raw.githubusercontent.com/aquasecurity/trivy-db-data/refs/heads/main/k8s/api/k8s-outdated-api.json
GO_OUTPUT=pkg/trivyk8s/deprecatedapi.go

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
	go test -v -short -race -timeout 300s -coverprofile=coverage.txt ./...

.PHONY: e2e-tests
## Runs e2e tests
integrations-tests: $(SOURCES)
	go test -v -race -timeout 30s -coverprofile=coverage.txt ./tests/integrations

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.46.0

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run --timeout 5m

.PHONY: update-outdated-api-data
update-outdated-api-data:
	@echo "Updating outdated API data..."
	@mkdir -p tmp-json-api
	@curl -sSL $(OUTDATED_API_DATA_URL) -o tmp-json-api/outdated-api.json
	@echo "Outdated API data updated successfully."
	@echo "package trivyk8s" > $(GO_OUTPUT)
	@echo "" >> $(GO_OUTPUT)
	@echo "var deprecatedAPIs = map[string][]string{" >> $(GO_OUTPUT)
	@jq -r 'to_entries[] | \
		"\"\(.key)\": {" + \
		( .value | keys_unsorted | map("\"\(.)\"") | join(", ") ) + \
		"},"' tmp-json-api/outdated-api.json | \
	sed 's/^/    /' >> $(GO_OUTPUT)
	@echo "}" >> $(GO_OUTPUT)
	@rm -r tmp-json-api
