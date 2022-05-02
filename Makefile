all: build

.PHONY: lint
lint: .prepare ## Lint the files
	@go mod tidy
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
	@go build -o padlock .

.PHONY: openapi
openapi: .prepare ## Generate the OpenAPI spec
	@swag init
	@rm docs/docs.go

.PHONY: compose
compose: ## Prepare the development docker stack
	@docker-compose -f docker/docker-compose.yaml up -d

.PHONY: clean
clean: ## Clean up development environment
	@docker-compose -f docker/docker-compose.yaml down

.prepare: ## Prepare the project for local development
	@pip3 install --user pre-commit
	@pre-commit install
	@pre-commit install-hooks
	@GO111MODULE=on go install github.com/go-critic/go-critic/cmd/gocritic@v0.5.4
	@GO111MODULE=on go get -v -u github.com/swaggo/swag/cmd/swag
	@touch .prepare

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
