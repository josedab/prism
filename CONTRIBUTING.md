# Contributing to Prism

Thank you for your interest in contributing to Prism! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Rust**: 1.75.0 or later (check with `rustc --version`)
- **Cargo**: Latest stable
- **Docker** (optional): For integration testing
- **Make**: For development commands

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/prism.git
cd prism

# Install development tools
make setup

# Build the project
make build

# Run tests
make test

# Run lints
make lint
```

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/prism.git
cd prism
git remote add upstream https://github.com/your-org/prism.git
```

### 2. Install Development Dependencies

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install additional components
rustup component add rustfmt clippy

# Install development tools
cargo install cargo-watch cargo-audit cargo-deny cargo-outdated cargo-llvm-cov

# Optional: Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### 3. Verify Setup

```bash
# Run the full test suite
make test-all

# Run clippy
make clippy

# Check formatting
make fmt-check
```

### 4. IDE Setup

**VS Code** (recommended):
```bash
# Install rust-analyzer extension
code --install-extension rust-lang.rust-analyzer
```

Recommended settings (`.vscode/settings.json`):
```json
{
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.cargo.features": "all",
  "editor.formatOnSave": true
}
```

**IntelliJ IDEA / CLion**:
- Install the Rust plugin
- Enable "Run rustfmt on save"

## Making Changes

### 1. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create a feature branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### Branch Naming Conventions

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `perf/` - Performance improvements
- `test/` - Test additions or changes
- `chore/` - Build process or auxiliary tool changes

### 2. Make Your Changes

- Write clean, readable code
- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run unit tests
cargo test

# Run all tests including integration
make test-all

# Run with specific feature flags
cargo test --features "http3,opentelemetry"

# Run benchmarks (for performance changes)
cargo bench
```

### 4. Commit Your Changes

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: <type>(<scope>): <description>

# Examples:
git commit -m "feat(router): add regex path matching"
git commit -m "fix(upstream): resolve connection pool leak"
git commit -m "docs(readme): update configuration examples"
git commit -m "perf(middleware): optimize header parsing"
git commit -m "test(e2e): add WebSocket upgrade tests"
```

**Commit Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `test`: Adding missing tests
- `chore`: Changes to build process or auxiliary tools
- `ci`: CI/CD changes

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Pull Request Process

### PR Checklist

Before submitting your PR, ensure:

- [ ] Code compiles without errors (`cargo build`)
- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] Clippy passes with no warnings (`cargo clippy -- -D warnings`)
- [ ] Documentation is updated if needed
- [ ] CHANGELOG.md is updated for user-facing changes
- [ ] Commit messages follow conventional commits

### PR Review Process

1. **Automated Checks**: CI will run tests, linting, and security checks
2. **Code Review**: A maintainer will review your code
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, a maintainer will merge your PR

### PR Title Format

Follow conventional commits for PR titles:
```
feat(router): add support for regex path patterns
fix(upstream): resolve connection leak on timeout
docs: update configuration reference
```

## Coding Standards

### Rust Style Guide

We follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):

```rust
// Use descriptive names
fn calculate_request_timeout(config: &TimeoutConfig) -> Duration { ... }

// Prefer impl Trait for return types when appropriate
fn create_middleware() -> impl Middleware { ... }

// Use Result for fallible operations
fn parse_config(path: &Path) -> Result<Config, ConfigError> { ... }

// Document public APIs
/// Creates a new router with the given configuration.
///
/// # Arguments
/// * `config` - The router configuration
///
/// # Examples
/// ```
/// let router = Router::new(config);
/// ```
pub fn new(config: RouterConfig) -> Self { ... }
```

### Error Handling

```rust
// Use thiserror for error definitions
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("upstream connection failed: {0}")]
    UpstreamConnection(String),

    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
}

// Propagate errors with ?
fn process_request(&self, req: Request) -> Result<Response, ProxyError> {
    let upstream = self.select_upstream()?;
    let response = upstream.forward(req)?;
    Ok(response)
}
```

### Safety Guidelines

- **No `unwrap()` in production code** - Use `expect()` with a clear message or handle the error
- **No `unsafe` without justification** - Document why unsafe is necessary
- **Bounds checking** - Always validate indices and sizes
- **Input validation** - Validate all external input

### Performance Considerations

- Avoid allocations in hot paths
- Use `Bytes` for zero-copy operations
- Prefer iterators over collecting into vectors
- Profile before optimizing

## Testing Guidelines

### Test Organization

```rust
// Unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specific_behavior() {
        // Arrange
        let input = create_test_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected);
    }
}
```

### Integration Tests

Place integration tests in `tests/`:

```rust
// tests/integration_test.rs
use prism::*;

#[tokio::test]
async fn test_full_proxy_flow() {
    // Test complete request-response cycle
}
```

### Test Naming

- Use descriptive names: `test_router_matches_exact_path`
- Prefix with `test_`
- Include the behavior being tested

### Property-Based Tests

For complex logic, use proptest:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_roundtrip(input: String) {
        let encoded = encode(&input);
        let decoded = decode(&encoded)?;
        prop_assert_eq!(input, decoded);
    }
}
```

## Documentation

### Code Documentation

- Document all public APIs
- Include examples in doc comments
- Use `# Safety` sections for unsafe code
- Use `# Panics` sections when functions can panic

### README and Docs

- Update README.md for user-facing changes
- Update docs/ for architectural changes
- Keep examples/ up to date

### Changelog

Update `CHANGELOG.md` for:
- New features
- Breaking changes
- Bug fixes
- Performance improvements

Format:
```markdown
## [Unreleased]

### Added
- New feature description (#123)

### Changed
- Changed behavior description (#124)

### Fixed
- Bug fix description (#125)
```

## Release Process

Releases are managed by maintainers. The process:

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create a git tag: `git tag v1.2.3`
4. Push tag: `git push origin v1.2.3`
5. CI will automatically build and publish releases

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/your-org/prism/discussions)
- **Bugs**: Open an [Issue](https://github.com/your-org/prism/issues)
- **Security**: See [SECURITY.md](.github/SECURITY.md)

## Recognition

Contributors are recognized in:
- Release notes
- Contributors list
- Annual contributor highlights

Thank you for contributing to Prism!
