all: build

.PHONY: lint
lint: .prepare ## Lint the files
	@go mod tidy
	@revive -config revive.toml ./...
	@golangci-lint run ./...

.PHONY: fix
fix: .prepare ## Lint and fix vialoations
	@go mod tidy
	@go fmt ./...
	@golangci-lint run --fix ./...

.PHONY: test
test: .prepare ## Run unittests
	@go test --count 1 -timeout 30s -short ./...

.PHONY: one-test
one-test: .prepare ## Run one unittest
	@go test --count 1 -v -timeout 30s -run ^$(FILTER) github.com/alwitt/padlock/...

.PHONY: build
build: lint ## Build the application
	@go build -o padlock .

.PHONY: openapi
openapi: .prepare ## Generate the OpenAPI spec
	@swag init -g main.go --parseDependency
	@rm docs/docs.go

.PHONY: up
up: ## Prepare the development docker stack
	@docker compose -f docker/docker-compose.yaml up -d

.PHONY: down
down: ## Remove the development docker stack
	@docker compose -f docker/docker-compose.yaml down

.prepare: ## Prepare the project for local development
	@pre-commit install
	@pre-commit install-hooks
	@GO111MODULE=on go get -v -u github.com/swaggo/swag/cmd/swag
	@touch .prepare

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
