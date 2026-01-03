# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to: security@example.com
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: Next release

### Disclosure Policy

- We follow coordinated disclosure
- We will credit reporters (unless they prefer anonymity)
- We aim to fix issues before public disclosure

## Security Best Practices

When deploying Prism, follow these security guidelines:

### Configuration

```yaml
# Always use TLS in production
listeners:
  - address: "0.0.0.0:443"
    protocol: https
    tls:
      cert_file: /etc/prism/certs/server.crt
      key_file: /etc/prism/certs/server.key
      min_version: "1.2"
      cipher_suites:
        - TLS_AES_256_GCM_SHA384
        - TLS_CHACHA20_POLY1305_SHA256
```

### Network Security

- Run behind a firewall
- Use network policies in Kubernetes
- Limit admin API access to internal networks

### Container Security

- Use the official image or build from source
- Run as non-root user (already configured in Dockerfile)
- Use read-only root filesystem
- Drop all capabilities

### Authentication

- Enable authentication for admin API
- Use strong JWT secrets
- Rotate API keys regularly
- Implement rate limiting

## Security Features

Prism includes several security features:

- **Memory Safety**: Written in Rust, eliminating buffer overflows
- **TLS Termination**: Native TLS with rustls (memory-safe)
- **Rate Limiting**: Protect against DDoS
- **Circuit Breaker**: Prevent cascade failures
- **JWT/API Key Auth**: Secure API access
- **mTLS**: Mutual TLS for service mesh
- **CORS**: Cross-Origin Resource Sharing control

## Audit Log

Security-relevant events are logged:

- Authentication failures
- Rate limit rejections
- Configuration changes
- TLS handshake failures

Enable detailed logging:

```yaml
observability:
  logging:
    level: info
    format: json
    include_request_headers: false  # Don't log sensitive headers
```

## Known Security Considerations

1. **Admin API**: Should not be exposed to the internet
2. **Hot Reload**: Config changes are logged but not authenticated
3. **Metrics Endpoint**: May expose sensitive statistics
4. **Error Messages**: Configured to not leak internal details

## Dependencies

We regularly audit dependencies using:

```bash
cargo audit
```

Dependencies are updated in minor versions for security patches.
