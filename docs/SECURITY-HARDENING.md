# Security Hardening Guide

This guide covers security best practices for deploying Prism in production environments.

## Table of Contents

1. [TLS Configuration](#tls-configuration)
2. [Authentication](#authentication)
3. [Rate Limiting](#rate-limiting)
4. [Network Security](#network-security)
5. [Container Security](#container-security)
6. [Logging & Auditing](#logging--auditing)
7. [Secrets Management](#secrets-management)

## TLS Configuration

### Minimum TLS Version

Always use TLS 1.2 or higher:

```yaml
listeners:
  - address: "0.0.0.0:443"
    protocol: https
    tls:
      min_version: "1.2"  # Or "1.3" for maximum security
```

### Strong Cipher Suites

Use only strong cipher suites:

```yaml
tls:
  cipher_suites:
    # TLS 1.3 (preferred)
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
    - TLS_AES_128_GCM_SHA256
    # TLS 1.2 fallback
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

### Certificate Management

```yaml
tls:
  cert_file: /etc/prism/certs/server.crt
  key_file: /etc/prism/certs/server.key
  # Auto-reload on certificate change
  watch_certs: true
```

### Mutual TLS (mTLS)

For service-to-service authentication:

```yaml
tls:
  client_auth: required
  client_ca_file: /etc/prism/certs/ca.crt
```

## Authentication

### JWT Validation

```yaml
middlewares:
  - type: auth
    jwt:
      issuer: "https://auth.example.com"
      audience: "api.example.com"
      jwks_url: "https://auth.example.com/.well-known/jwks.json"
      # Cache JWKS for performance
      jwks_cache_duration: 1h
```

### API Key Authentication

```yaml
middlewares:
  - type: auth
    api_key:
      header: "X-API-Key"
      keys:
        - name: "service-a"
          key_hash: "sha256:..."  # Never store plain text keys
          rate_limit: 1000  # Per-key rate limiting
```

### Rate Limiting by Identity

```yaml
middlewares:
  - type: rate_limit
    key: "${jwt.sub}"  # Rate limit per user
    requests: 100
    window: 1m
```

## Rate Limiting

### Basic Rate Limiting

```yaml
middlewares:
  - type: rate_limit
    requests: 1000
    window: 1m
    key: "${remote_addr}"
```

### Distributed Rate Limiting

For multi-instance deployments:

```yaml
middlewares:
  - type: rate_limit
    distributed:
      redis_url: "redis://localhost:6379"
      key_prefix: "prism:ratelimit:"
    requests: 10000
    window: 1m
```

### Burst Protection

```yaml
middlewares:
  - type: rate_limit
    algorithm: token_bucket
    requests: 100
    window: 1s
    burst: 50  # Allow bursts up to 50 requests
```

## Network Security

### Kubernetes Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: prism-network-policy
spec:
  podSelector:
    matchLabels:
      app: prism
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              role: backend
      ports:
        - protocol: TCP
          port: 80
```

### IP Allowlisting

```yaml
middlewares:
  - type: ip_filter
    allow:
      - 10.0.0.0/8
      - 192.168.0.0/16
    deny:
      - 0.0.0.0/0
```

### Admin API Protection

```yaml
admin:
  enabled: true
  address: "127.0.0.1:9090"  # Only localhost
  auth:
    type: basic
    users:
      - username: admin
        password_hash: "bcrypt:..."
```

## Container Security

### Dockerfile Best Practices

```dockerfile
# Multi-stage build for minimal image
FROM rust:1.75-alpine AS builder
# ... build steps ...

FROM alpine:3.19
# Non-root user
RUN addgroup -g 1000 prism && adduser -u 1000 -G prism -D prism
USER prism

# Read-only root filesystem
# Set in docker run: --read-only

# Drop all capabilities
# Set in docker run: --cap-drop=ALL
```

### Kubernetes Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

## Logging & Auditing

### Security Event Logging

```yaml
observability:
  logging:
    level: info
    format: json
    security_events: true  # Log auth failures, rate limits
```

### Audit Trail

```yaml
observability:
  logging:
    access_log:
      enabled: true
      format: json
      fields:
        - timestamp
        - remote_addr
        - method
        - path
        - status
        - duration
        - user_id  # From JWT
```

### Sensitive Data Filtering

```yaml
observability:
  logging:
    redact_headers:
      - Authorization
      - Cookie
      - X-API-Key
    redact_query_params:
      - token
      - api_key
```

## Secrets Management

### Environment Variables

```yaml
# prism.yaml
tls:
  key_file: "${TLS_KEY_PATH}"

upstreams:
  backend:
    auth:
      token: "${env:BACKEND_TOKEN}"
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: prism-secrets
type: Opaque
stringData:
  jwt-secret: "your-secret-here"
---
# In deployment
env:
  - name: JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: prism-secrets
        key: jwt-secret
```

### HashiCorp Vault Integration

```yaml
secrets:
  provider: vault
  vault:
    address: "https://vault.example.com"
    auth_method: kubernetes
    role: prism
    secret_path: "secret/data/prism"
```

## Security Checklist

Before going to production:

- [ ] TLS 1.2+ with strong ciphers
- [ ] Authentication enabled on all sensitive routes
- [ ] Rate limiting configured
- [ ] Admin API not exposed externally
- [ ] Running as non-root user
- [ ] Read-only root filesystem
- [ ] Network policies in place
- [ ] Security logging enabled
- [ ] Secrets properly managed
- [ ] Regular dependency audits scheduled
- [ ] Incident response plan documented
