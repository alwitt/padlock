all: build

.PHONY: lint
lint: .prepare ## Lint the files
	@go mod tidy -compat=1.17
	@golint ./...
	@golangci-lint run ./...

.PHONY: fix
fix: .prepare ## Lint and fix vialoations
	@go mod tidy
	@golangci-lint run --fix ./...

.PHONY: test
test: .prepare ## Run unittests
	@go test --count 1 -timeout 30s -short ./...

.PHONY: build
build: lint ## Build the application

.prepare: ## Prepare the project for local development
	@pip3 install --user pre-commit
	@pre-commit install
	@pre-commit install-hooks
	@GO111MODULE=on go install github.com/go-critic/go-critic/cmd/gocritic@v0.5.4
	@touch .prepare

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
