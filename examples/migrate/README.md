# Configuration Migration Examples

This directory contains example configurations for migrating from other proxies to Prism.

## Supported Source Proxies

- **Nginx** - nginx.conf files
- **Envoy** - bootstrap.yaml / config.yaml files
- **Traefik** - traefik.yml / traefik.toml files
- **HAProxy** - haproxy.cfg files

## Usage

### CLI Migration

```bash
# Migrate from Nginx
prism migrate --from nginx --input /etc/nginx/nginx.conf --output prism.yaml

# Migrate from Envoy
prism migrate --from envoy --input /etc/envoy/envoy.yaml --output prism.yaml

# Migrate from Traefik
prism migrate --from traefik --input /etc/traefik/traefik.yml --output prism.yaml

# Migrate from HAProxy
prism migrate --from haproxy --input /etc/haproxy/haproxy.cfg --output prism.yaml

# With validation (dry-run)
prism migrate --from nginx --input nginx.conf --output prism.yaml --validate

# Generate migration report
prism migrate --from nginx --input nginx.conf --output prism.yaml --report report.txt
```

### Programmatic Migration

```rust
use prism::migrate::{migrate, SourceProxy, format_report};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = migrate(SourceProxy::Nginx, Path::new("nginx.conf"))?;

    // Print migration report
    println!("{}", format_report(&result));

    // Access the generated config
    let config = result.config;

    // Check for warnings
    for warning in &result.warnings {
        eprintln!("Warning: {}", warning.message);
        if let Some(suggestion) = &warning.suggestion {
            eprintln!("  Suggestion: {}", suggestion);
        }
    }

    // Save the config
    let yaml = serde_yaml::to_string(&config)?;
    std::fs::write("prism.yaml", yaml)?;

    Ok(())
}
```

## Example Files

### sample-nginx.conf

A sample Nginx configuration demonstrating common patterns.

### sample-envoy.yaml

A sample Envoy bootstrap configuration.

### sample-traefik.yml

A sample Traefik configuration.

### sample-haproxy.cfg

A sample HAProxy configuration.

## Migration Notes

### Nginx Migration

Supported directives:
- `server` blocks → Prism listeners
- `upstream` blocks → Prism upstreams
- `location` blocks → Prism routes
- `listen` → Listener address and TLS config
- `server_name` → Route host matching
- `proxy_pass` → Route upstream
- `proxy_set_header` → Route request headers
- `ssl_certificate` / `ssl_certificate_key` → TLS config
- Load balancing: round-robin, least_conn, ip_hash

Partial support:
- `rewrite` → Logged as warning, manual conversion needed
- `map` → Logged as warning
- `if` → Logged as warning

Not supported:
- Lua scripts
- Perl modules
- Internal redirects

### Envoy Migration

Supported:
- Static listeners → Prism listeners
- Static clusters → Prism upstreams
- HTTP connection manager routes → Prism routes
- Load balancing policies
- Health checks
- Circuit breakers (as warnings)

Not supported:
- xDS (dynamic configuration)
- Filters (Lua, Wasm, etc.)
- Access logging configuration

### Traefik Migration

Supported:
- Entry points → Prism listeners
- Services (load balancer) → Prism upstreams
- Routers → Prism routes
- Middleware notes (logged as warnings)

Not supported:
- Docker provider
- Kubernetes provider
- Consul provider
- Let's Encrypt (ACME)

### HAProxy Migration

Supported:
- Frontend → Prism listeners + routes
- Backend → Prism upstreams
- Listen → Combined listener + upstream + route
- ACL-based routing
- Server options (weight, backup, check)
- Load balancing algorithms

Not supported:
- Stick tables
- TCP content inspection
- Lua scripts
