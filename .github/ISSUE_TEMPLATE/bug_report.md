---
name: Bug Report
about: Report a bug to help us improve Prism
title: '[BUG] '
labels: bug, triage
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Environment

- **Prism Version**: (e.g., 1.0.0)
- **OS**: (e.g., Ubuntu 22.04, macOS 14.0)
- **Rust Version**: (output of `rustc --version`)
- **Installation Method**: (cargo, docker, binary)

## Configuration

<details>
<summary>prism.yaml (sanitized)</summary>

```yaml
# Paste your configuration here (remove sensitive data)
```

</details>

## Steps to Reproduce

1. Start Prism with the above configuration
2. Send a request: `curl http://localhost:8080/...`
3. Observe the error

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened.

## Logs

<details>
<summary>Prism logs</summary>

```
# Paste relevant logs here
# Run with RUST_LOG=debug for more detail
```

</details>

## Additional Context

- [ ] I have searched existing issues for duplicates
- [ ] I can reproduce this issue consistently
- [ ] This worked in a previous version (specify: ___)

## Possible Solution

If you have ideas on how to fix this, please share.
