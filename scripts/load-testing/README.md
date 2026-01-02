# Load Testing Scripts

This directory contains load testing configurations for various tools.

## Quick Start

```bash
# Start Prism
cargo run --release -- --config examples/basic.yaml

# In another terminal, run load tests
```

## Tools

### k6 (Recommended)

Modern load testing tool with JavaScript scripting.

```bash
# Install
brew install k6  # macOS
# or: https://k6.io/docs/getting-started/installation/

# Basic test
k6 run scripts/load-testing/k6-basic.js

# With custom URL
PRISM_URL=http://localhost:8080 k6 run scripts/load-testing/k6-basic.js

# Quick smoke test
k6 run --vus 10 --duration 30s scripts/load-testing/k6-basic.js
```

### wrk

High-performance HTTP benchmarking tool.

```bash
# Install
brew install wrk  # macOS
apt install wrk   # Ubuntu

# Basic test (4 threads, 100 connections, 30 seconds)
wrk -t4 -c100 -d30s http://localhost:8080/

# With Lua script
wrk -t4 -c100 -d30s -s scripts/load-testing/wrk-basic.lua http://localhost:8080
```

### Vegeta

HTTP load testing tool and library.

```bash
# Install
go install github.com/tsenart/vegeta@latest

# Run script
./scripts/load-testing/vegeta-attack.sh

# Or manually
echo "GET http://localhost:8080/" | vegeta attack -rate=100 -duration=30s | vegeta report
```

### hey

Simple HTTP load generator.

```bash
# Install
go install github.com/rakyll/hey@latest

# Basic test (1000 requests, 50 concurrent)
hey -n 1000 -c 50 http://localhost:8080/

# Sustained load (30 seconds, 100 concurrent)
hey -z 30s -c 100 http://localhost:8080/
```

## Test Scenarios

### Smoke Test
Verify the system works under minimal load.

```bash
k6 run --vus 1 --duration 10s scripts/load-testing/k6-basic.js
```

### Load Test
Assess performance under expected load.

```bash
k6 run scripts/load-testing/k6-basic.js
# Uses the built-in load scenario (ramps to 50 VUs)
```

### Stress Test
Find the breaking point.

```bash
k6 run --env SCENARIO=stress scripts/load-testing/k6-basic.js
# Ramps up to 300 VUs
```

### Soak Test
Check for memory leaks and degradation over time.

```bash
k6 run --vus 50 --duration 1h scripts/load-testing/k6-basic.js
```

### Spike Test
Test sudden traffic spikes.

```bash
k6 run --stage 10s:10,10s:500,30s:500,10s:10 scripts/load-testing/k6-basic.js
```

## Performance Targets

| Metric | Target | Description |
|--------|--------|-------------|
| P50 latency | < 10ms | Median response time |
| P95 latency | < 50ms | 95th percentile |
| P99 latency | < 100ms | 99th percentile |
| Error rate | < 0.1% | Failed requests |
| Throughput | > 10k req/s | Requests per second |

## Monitoring During Tests

```bash
# Watch Prism metrics
watch -n1 'curl -s http://localhost:9091/metrics | grep prism_'

# Monitor system resources
htop

# Check file descriptors
watch -n1 'ls /proc/$(pgrep prism)/fd | wc -l'
```

## Results Analysis

Results are saved to `./load-test-results/`:

- `report.txt` - Human-readable summary
- `report.json` - Machine-readable data
- `histogram.txt` - Latency distribution
- `plot.html` - Visual graph (if gnuplot available)

## CI Integration

```yaml
# .github/workflows/load-test.yml
- name: Run load tests
  run: |
    k6 run --out json=results.json scripts/load-testing/k6-basic.js
    # Fail if thresholds not met (built into k6)
```
