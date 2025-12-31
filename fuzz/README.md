# Fuzzing Prism

This directory contains fuzz targets for security testing Prism.

## Prerequisites

```bash
# Install cargo-fuzz (requires nightly Rust)
cargo install cargo-fuzz

# Switch to nightly
rustup default nightly
```

## Running Fuzz Targets

```bash
# List available targets
cargo fuzz list

# Run a specific target
cargo fuzz run fuzz_config_parser

# Run with timeout and iterations
cargo fuzz run fuzz_config_parser -- -max_total_time=300 -max_len=4096

# Run all targets
for target in $(cargo fuzz list); do
    cargo fuzz run "$target" -- -max_total_time=60
done
```

## Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_config_parser` | YAML/TOML configuration parsing |
| `fuzz_path_matcher` | URL path matching and routing |
| `fuzz_header_parser` | HTTP header parsing |
| `fuzz_url_parser` | URL and URI parsing |

## Corpus Management

```bash
# Minimize corpus
cargo fuzz cmin fuzz_config_parser

# Show coverage
cargo fuzz coverage fuzz_config_parser
```

## CI Integration

The fuzzing targets are run in CI with limited time. For thorough fuzzing,
run locally with longer durations:

```bash
# 1 hour fuzzing session
cargo fuzz run fuzz_config_parser -- -max_total_time=3600
```

## Reporting Issues

If you find a crash:

1. Check if it's a duplicate in `fuzz/artifacts/`
2. Minimize the test case: `cargo fuzz tmin fuzz_target crash_file`
3. Report via security policy (see SECURITY.md)
