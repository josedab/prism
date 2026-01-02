.PHONY: all build release test check fmt clippy clean docker docs bench install help

# Variables
CARGO := cargo
DOCKER := docker
VERSION := $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DOCKER_IMAGE := prism
DOCKER_TAG := $(VERSION)

# Default target
all: check test build

# Build targets
build:
	@echo "Building prism..."
	$(CARGO) build

release:
	@echo "Building release binary..."
	$(CARGO) build --release

build-all-features:
	@echo "Building with all features..."
	$(CARGO) build --all-features

# Testing
test:
	@echo "Running tests..."
	$(CARGO) test

test-all:
	@echo "Running all tests with all features..."
	$(CARGO) test --all-features

test-coverage:
	@echo "Generating test coverage..."
	$(CARGO) llvm-cov --all-features --html
	@echo "Coverage report: target/llvm-cov/html/index.html"

# Code quality
check:
	@echo "Checking code..."
	$(CARGO) check --all-features

fmt:
	@echo "Formatting code..."
	$(CARGO) fmt --all

fmt-check:
	@echo "Checking code formatting..."
	$(CARGO) fmt --all -- --check

clippy:
	@echo "Running clippy..."
	$(CARGO) clippy --all-targets --all-features -- -D warnings

lint: fmt-check clippy

# Benchmarks
bench:
	@echo "Running benchmarks..."
	$(CARGO) bench

bench-save:
	@echo "Running benchmarks and saving baseline..."
	$(CARGO) bench -- --save-baseline main

bench-compare:
	@echo "Comparing benchmarks against baseline..."
	$(CARGO) bench -- --baseline main

# Documentation
docs:
	@echo "Building documentation..."
	$(CARGO) doc --all-features --no-deps --open

docs-build:
	$(CARGO) doc --all-features --no-deps

# Docker
docker-build:
	@echo "Building Docker image..."
	$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):latest .

docker-build-dev:
	@echo "Building Docker image for development..."
	$(DOCKER) build --target builder -t $(DOCKER_IMAGE):dev .

docker-run:
	@echo "Running Docker container..."
	$(DOCKER) run --rm -p 8080:8080 -p 9090:9090 $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-push:
	@echo "Pushing Docker image..."
	$(DOCKER) push $(DOCKER_IMAGE):$(DOCKER_TAG)
	$(DOCKER) push $(DOCKER_IMAGE):latest

# Development
dev:
	@echo "Starting development server with hot reload..."
	$(CARGO) watch -x 'run -- --config examples/basic.yaml'

dev-compose:
	@echo "Starting development environment..."
	docker-compose up -d

dev-compose-down:
	docker-compose down

dev-compose-logs:
	docker-compose logs -f prism

# Installation
install:
	@echo "Installing prism..."
	$(CARGO) install --path .

install-dev-deps:
	@echo "Installing development dependencies..."
	$(CARGO) install cargo-watch cargo-llvm-cov cargo-audit cargo-outdated

# Security
audit:
	@echo "Running security audit..."
	$(CARGO) audit

outdated:
	@echo "Checking for outdated dependencies..."
	$(CARGO) outdated

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean

clean-all: clean
	rm -rf target/
	docker-compose down -v 2>/dev/null || true

# Release preparation
prepare-release: fmt clippy test-all
	@echo "Release preparation complete!"

# Generate example config
gen-config:
	@echo "Generating example configuration..."
	$(CARGO) run -- --generate-config > prism.yaml.example

# Validate config
validate-config:
	@echo "Validating configuration..."
	$(CARGO) run -- --config $(CONFIG) --validate

# Profile
profile:
	@echo "Building with profiling enabled..."
	RUSTFLAGS="-C target-cpu=native" $(CARGO) build --release

flamegraph:
	@echo "Generating flamegraph..."
	$(CARGO) flamegraph --bin prism -- --config examples/basic.yaml

# Print version info
version:
	@echo "Prism version: $(VERSION)"
	@echo "Git SHA: $(GIT_SHA)"

# Help
help:
	@echo "Prism - High-Performance Reverse Proxy"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build Targets:"
	@echo "  build              Build debug binary"
	@echo "  release            Build release binary"
	@echo "  build-all-features Build with all features enabled"
	@echo ""
	@echo "Testing:"
	@echo "  test               Run tests"
	@echo "  test-all           Run all tests with all features"
	@echo "  test-coverage      Generate test coverage report"
	@echo "  bench              Run benchmarks"
	@echo ""
	@echo "Code Quality:"
	@echo "  check              Check code compiles"
	@echo "  fmt                Format code"
	@echo "  clippy             Run clippy linter"
	@echo "  lint               Run all linters"
	@echo "  audit              Security audit dependencies"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build       Build Docker image"
	@echo "  docker-run         Run Docker container"
	@echo "  docker-push        Push Docker image"
	@echo ""
	@echo "Development:"
	@echo "  dev                Start dev server with hot reload"
	@echo "  dev-compose        Start docker-compose environment"
	@echo "  docs               Build and open documentation"
	@echo "  install            Install prism binary"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean              Clean build artifacts"
	@echo "  clean-all          Clean everything including docker"
