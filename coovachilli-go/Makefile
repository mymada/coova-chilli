# CoovaChilli-Go Makefile
# Facilite le build, les tests, et l'exécution

.PHONY: help build test test-unit test-integration test-race clean docker-build docker-test install run dev lint coverage

# Variables
GO := go
GOFLAGS := -v
BINARY := coovachilli
MAIN_PATH := ./cmd/coovachilli
PKG_PATH := ./pkg/...
COVERAGE_FILE := coverage.out
INTEGRATION_DIR := test/integration

# Colors for output
COLOR_RESET := \033[0m
COLOR_BOLD := \033[1m
COLOR_GREEN := \033[32m
COLOR_YELLOW := \033[33m
COLOR_BLUE := \033[34m

# Help target
help: ## Show this help message
	@echo "$(COLOR_BOLD)CoovaChilli-Go - Available Commands$(COLOR_RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-20s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""

# Build targets
build: ## Build the CoovaChilli binary
	@echo "$(COLOR_BLUE)Building CoovaChilli-Go...$(COLOR_RESET)"
	CGO_ENABLED=1 $(GO) build $(GOFLAGS) -o $(BINARY) $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✓ Build complete: $(BINARY)$(COLOR_RESET)"

build-static: ## Build static binary (for containers)
	@echo "$(COLOR_BLUE)Building static binary...$(COLOR_RESET)"
	CGO_ENABLED=1 $(GO) build $(GOFLAGS) -ldflags="-s -w" -o $(BINARY) $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✓ Static build complete$(COLOR_RESET)"

install: ## Install the binary to $GOPATH/bin
	@echo "$(COLOR_BLUE)Installing CoovaChilli-Go...$(COLOR_RESET)"
	CGO_ENABLED=1 $(GO) install $(GOFLAGS) $(MAIN_PATH)
	@echo "$(COLOR_GREEN)✓ Installed to $(GOPATH)/bin/$(BINARY)$(COLOR_RESET)"

# Test targets
test: test-unit ## Run all tests (unit only)

test-unit: ## Run unit tests
	@echo "$(COLOR_BLUE)Running unit tests...$(COLOR_RESET)"
	$(GO) test $(GOFLAGS) $(PKG_PATH)
	@echo "$(COLOR_GREEN)✓ Unit tests passed$(COLOR_RESET)"

test-race: ## Run tests with race detector
	@echo "$(COLOR_BLUE)Running tests with race detector...$(COLOR_RESET)"
	$(GO) test -race $(GOFLAGS) $(PKG_PATH)
	@echo "$(COLOR_GREEN)✓ Race tests passed$(COLOR_RESET)"

test-integration: ## Run integration tests locally (all)
	@echo "$(COLOR_BLUE)Running integration tests...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && ./run_tests_local.sh all
	@echo "$(COLOR_GREEN)✓ Integration tests complete$(COLOR_RESET)"

test-integration-ipv4: ## Run IPv4 integration tests only
	@echo "$(COLOR_BLUE)Running IPv4 integration tests...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && ./run_tests_local.sh ipv4
	@echo "$(COLOR_GREEN)✓ IPv4 tests complete$(COLOR_RESET)"

test-integration-ipv6: ## Run IPv6 integration tests only
	@echo "$(COLOR_BLUE)Running IPv6 integration tests...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && ./run_tests_local.sh ipv6
	@echo "$(COLOR_GREEN)✓ IPv6 tests complete$(COLOR_RESET)"

test-integration-iptables: ## Run iptables integration tests only
	@echo "$(COLOR_BLUE)Running iptables integration tests...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && ./run_tests_local.sh iptables
	@echo "$(COLOR_GREEN)✓ iptables tests complete$(COLOR_RESET)"

test-integration-ufw: ## Run ufw integration tests only
	@echo "$(COLOR_BLUE)Running ufw integration tests...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && ./run_tests_local.sh ufw
	@echo "$(COLOR_GREEN)✓ ufw tests complete$(COLOR_RESET)"

test-all: test-unit test-race test-integration ## Run all tests (unit + race + integration)
	@echo "$(COLOR_GREEN)✓ All tests passed!$(COLOR_RESET)"

# Coverage targets
coverage: ## Generate test coverage report
	@echo "$(COLOR_BLUE)Generating coverage report...$(COLOR_RESET)"
	$(GO) test -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(PKG_PATH)
	@echo "$(COLOR_GREEN)✓ Coverage report generated: $(COVERAGE_FILE)$(COLOR_RESET)"

coverage-html: coverage ## Generate and open HTML coverage report
	@echo "$(COLOR_BLUE)Generating HTML coverage report...$(COLOR_RESET)"
	$(GO) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "$(COLOR_GREEN)✓ HTML report generated: coverage.html$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Opening in browser...$(COLOR_RESET)"
	@which xdg-open > /dev/null && xdg-open coverage.html || open coverage.html

# Benchmark targets
bench: ## Run benchmarks
	@echo "$(COLOR_BLUE)Running benchmarks...$(COLOR_RESET)"
	$(GO) test -bench=. -benchmem $(PKG_PATH)

bench-session: ## Run session management benchmarks only
	@echo "$(COLOR_BLUE)Running session benchmarks...$(COLOR_RESET)"
	$(GO) test -bench=. -benchmem ./pkg/core -run=^$

# Docker targets
docker-build: ## Build Docker images for integration tests
	@echo "$(COLOR_BLUE)Building Docker images...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && docker compose -f docker-compose.e2e.yml build
	@echo "$(COLOR_GREEN)✓ Docker images built$(COLOR_RESET)"

docker-test: docker-build ## Run integration tests in Docker
	@echo "$(COLOR_BLUE)Running integration tests in Docker...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && ./run_tests_local.sh all
	@echo "$(COLOR_GREEN)✓ Docker tests complete$(COLOR_RESET)"

docker-clean: ## Clean Docker containers and volumes
	@echo "$(COLOR_BLUE)Cleaning Docker resources...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && docker compose -f docker-compose.e2e.yml down -v
	@echo "$(COLOR_GREEN)✓ Docker cleanup complete$(COLOR_RESET)"

# Development targets
dev: build ## Build and run CoovaChilli in development mode
	@echo "$(COLOR_BLUE)Starting CoovaChilli-Go in development mode...$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Note: Requires sudo for TUN interface and firewall$(COLOR_RESET)"
	sudo ./$(BINARY)

run: build ## Build and run CoovaChilli (alias for dev)
	@make dev

# Code quality targets
lint: ## Run linters (requires golangci-lint)
	@echo "$(COLOR_BLUE)Running linters...$(COLOR_RESET)"
	@which golangci-lint > /dev/null || (echo "$(COLOR_YELLOW)golangci-lint not found. Install: https://golangci-lint.run/usage/install/$(COLOR_RESET)" && exit 1)
	golangci-lint run $(PKG_PATH)
	@echo "$(COLOR_GREEN)✓ Linting complete$(COLOR_RESET)"

fmt: ## Format code with gofmt
	@echo "$(COLOR_BLUE)Formatting code...$(COLOR_RESET)"
	$(GO) fmt $(PKG_PATH)
	@echo "$(COLOR_GREEN)✓ Code formatted$(COLOR_RESET)"

vet: ## Run go vet
	@echo "$(COLOR_BLUE)Running go vet...$(COLOR_RESET)"
	$(GO) vet $(PKG_PATH)
	@echo "$(COLOR_GREEN)✓ Vet complete$(COLOR_RESET)"

# Dependency targets
deps: ## Download dependencies
	@echo "$(COLOR_BLUE)Downloading dependencies...$(COLOR_RESET)"
	$(GO) mod download
	@echo "$(COLOR_GREEN)✓ Dependencies downloaded$(COLOR_RESET)"

deps-update: ## Update dependencies
	@echo "$(COLOR_BLUE)Updating dependencies...$(COLOR_RESET)"
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "$(COLOR_GREEN)✓ Dependencies updated$(COLOR_RESET)"

deps-verify: ## Verify dependencies
	@echo "$(COLOR_BLUE)Verifying dependencies...$(COLOR_RESET)"
	$(GO) mod verify
	@echo "$(COLOR_GREEN)✓ Dependencies verified$(COLOR_RESET)"

# Clean targets
clean: ## Remove build artifacts
	@echo "$(COLOR_BLUE)Cleaning build artifacts...$(COLOR_RESET)"
	rm -f $(BINARY)
	rm -f $(COVERAGE_FILE) coverage.html
	rm -rf $(INTEGRATION_DIR)/results/*
	@echo "$(COLOR_GREEN)✓ Cleanup complete$(COLOR_RESET)"

clean-all: clean docker-clean ## Remove all build artifacts and Docker resources
	@echo "$(COLOR_GREEN)✓ Full cleanup complete$(COLOR_RESET)"

# CI/CD targets (used by GitHub Actions)
ci-test: ## Run CI tests (unit + race + coverage)
	@echo "$(COLOR_BLUE)Running CI test suite...$(COLOR_RESET)"
	$(GO) test -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(PKG_PATH)
	@echo "$(COLOR_GREEN)✓ CI tests complete$(COLOR_RESET)"

ci-integration: docker-build ## Run CI integration tests
	@echo "$(COLOR_BLUE)Running CI integration tests...$(COLOR_RESET)"
	cd $(INTEGRATION_DIR) && ./run_tests_local.sh all yes
	@echo "$(COLOR_GREEN)✓ CI integration tests complete$(COLOR_RESET)"

# Documentation targets
docs: ## Generate documentation
	@echo "$(COLOR_BLUE)Generating documentation...$(COLOR_RESET)"
	@which godoc > /dev/null || (echo "$(COLOR_YELLOW)godoc not found. Install: go install golang.org/x/tools/cmd/godoc@latest$(COLOR_RESET)" && exit 1)
	@echo "$(COLOR_GREEN)✓ Starting godoc server at http://localhost:6060$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Visit http://localhost:6060/pkg/coovachilli-go/$(COLOR_RESET)"
	godoc -http=:6060

# Default target
.DEFAULT_GOAL := help
