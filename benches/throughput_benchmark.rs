//! Throughput benchmarks comparing Prism components
//!
//! These benchmarks measure the performance of critical path components.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http::{Method, Request, Uri};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// Router Benchmarks
// ============================================================================

fn bench_router_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_matching");
    group.throughput(Throughput::Elements(1));

    // Setup router with various route counts
    for route_count in [10, 50, 100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("routes", route_count),
            route_count,
            |b, &count| {
                // Create mock routes
                let routes: Vec<String> = (0..count)
                    .map(|i| format!("/api/v1/resource{}", i))
                    .collect();

                b.iter(|| {
                    // Simulate route matching
                    let path = "/api/v1/resource50";
                    let _matched = routes.iter().find(|r| path.starts_with(r.as_str()));
                    black_box(path)
                });
            },
        );
    }

    group.finish();
}

fn bench_path_prefix_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_prefix_matching");

    let prefixes = vec![
        "/api/",
        "/api/v1/",
        "/api/v1/users/",
        "/api/v1/users/123/",
        "/api/v1/users/123/posts/",
    ];

    for prefix in prefixes {
        group.bench_with_input(
            BenchmarkId::new("prefix_depth", prefix.matches('/').count()),
            prefix,
            |b, prefix| {
                let path = "/api/v1/users/123/posts/456";
                b.iter(|| black_box(path.starts_with(prefix)));
            },
        );
    }

    group.finish();
}

fn bench_regex_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex_matching");

    let patterns = vec![
        (r"^/api/.*$", "simple"),
        (r"^/api/v\d+/.*$", "with_digits"),
        (r"^/api/v\d+/users/[0-9a-f-]+$", "uuid_like"),
    ];

    for (pattern, name) in patterns {
        let regex = regex::Regex::new(pattern).unwrap();
        group.bench_with_input(BenchmarkId::new("pattern", name), &regex, |b, regex| {
            let path = "/api/v1/users/550e8400-e29b-41d4-a716-446655440000";
            b.iter(|| black_box(regex.is_match(path)));
        });
    }

    group.finish();
}

// ============================================================================
// Load Balancer Benchmarks
// ============================================================================

fn bench_round_robin(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer_round_robin");
    group.throughput(Throughput::Elements(1));

    for server_count in [2, 5, 10, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("servers", server_count),
            server_count,
            |b, &count| {
                let counter = AtomicU64::new(0);
                let servers: Vec<String> = (0..count).map(|i| format!("server{}", i)).collect();

                b.iter(|| {
                    let idx = counter.fetch_add(1, Ordering::Relaxed) as usize % servers.len();
                    black_box(&servers[idx])
                });
            },
        );
    }

    group.finish();
}

fn bench_weighted_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer_weighted");

    let server_count = 10;
    let servers: Vec<(String, u32)> = (0..server_count)
        .map(|i| (format!("server{}", i), (i + 1) as u32))
        .collect();

    let total_weight: u32 = servers.iter().map(|(_, w)| w).sum();

    group.bench_function("weighted_select", |b| {
        let mut rng_state: u64 = 12345;
        b.iter(|| {
            // Simple LCG for reproducible randomness
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let r = (rng_state >> 33) as u32 % total_weight;

            let mut cumulative = 0u32;
            for (server, weight) in &servers {
                cumulative += weight;
                if r < cumulative {
                    return black_box(server);
                }
            }
            black_box(&servers[0].0)
        });
    });

    group.finish();
}

fn bench_consistent_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer_consistent_hash");

    use std::collections::BTreeMap;
    use std::hash::{Hash, Hasher};

    fn hash_key(key: &str) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    // Create a ring with virtual nodes
    let mut ring: BTreeMap<u64, String> = BTreeMap::new();
    let virtual_nodes = 150;
    let server_count = 10;

    for i in 0..server_count {
        for v in 0..virtual_nodes {
            let key = format!("server{}:{}", i, v);
            ring.insert(hash_key(&key), format!("server{}", i));
        }
    }

    group.bench_function("hash_lookup", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let key = format!("client:{}", counter);
            let hash = hash_key(&key);

            // Find the first server with hash >= our hash
            let server = ring
                .range(hash..)
                .next()
                .or_else(|| ring.iter().next())
                .map(|(_, s)| s);

            black_box(server)
        });
    });

    group.finish();
}

// ============================================================================
// Header Processing Benchmarks
// ============================================================================

fn bench_header_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_parsing");

    let headers_str = "Host: example.com\r\n\
                       User-Agent: Mozilla/5.0\r\n\
                       Accept: text/html,application/xhtml+xml\r\n\
                       Accept-Language: en-US,en;q=0.9\r\n\
                       Accept-Encoding: gzip, deflate, br\r\n\
                       Connection: keep-alive\r\n\
                       Cookie: session=abc123; preferences=dark\r\n\
                       X-Request-ID: 550e8400-e29b-41d4-a716-446655440000\r\n";

    group.throughput(Throughput::Bytes(headers_str.len() as u64));

    group.bench_function("parse_headers", |b| {
        b.iter(|| {
            let headers: HashMap<&str, &str> = headers_str
                .lines()
                .filter_map(|line| {
                    let mut parts = line.splitn(2, ": ");
                    Some((parts.next()?, parts.next()?.trim_end()))
                })
                .collect();
            black_box(headers)
        });
    });

    group.finish();
}

fn bench_header_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_lookup");

    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("host".to_string(), "example.com".to_string());
    headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
    headers.insert("accept".to_string(), "text/html".to_string());
    headers.insert(
        "x-request-id".to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
    );
    headers.insert("authorization".to_string(), "Bearer token123".to_string());

    group.bench_function("hashmap_get", |b| {
        b.iter(|| black_box(headers.get("x-request-id")));
    });

    group.bench_function("hashmap_get_missing", |b| {
        b.iter(|| black_box(headers.get("x-nonexistent")));
    });

    group.finish();
}

// ============================================================================
// Body Processing Benchmarks
// ============================================================================

fn bench_body_buffering(c: &mut Criterion) {
    let mut group = c.benchmark_group("body_buffering");

    for size in [1024, 10240, 102400, 1048576].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("size", size), &data, |b, data| {
            b.iter(|| {
                let bytes = Bytes::copy_from_slice(data);
                black_box(bytes)
            });
        });
    }

    group.finish();
}

fn bench_body_zero_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("body_zero_copy");

    for size in [1024, 10240, 102400, 1048576].iter() {
        let data: Bytes = Bytes::from(vec![0u8; *size]);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("size", size), &data, |b, data| {
            b.iter(|| {
                // Clone is cheap for Bytes (reference counted)
                let cloned = data.clone();
                black_box(cloned)
            });
        });
    }

    group.finish();
}

// ============================================================================
// Connection Pool Benchmarks
// ============================================================================

fn bench_connection_pool_operations(c: &mut Criterion) {
    use dashmap::DashMap;

    let mut group = c.benchmark_group("connection_pool");

    let pool: Arc<DashMap<String, Vec<u64>>> = Arc::new(DashMap::new());

    // Pre-populate pool
    for i in 0..100 {
        pool.insert(format!("server{}", i), vec![1, 2, 3, 4, 5]);
    }

    group.bench_function("get_connection", |b| {
        let pool = pool.clone();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let key = format!("server{}", counter % 100);
            let conn = pool.get(&key).and_then(|v| v.first().copied());
            black_box(conn)
        });
    });

    group.bench_function("return_connection", |b| {
        let pool = pool.clone();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let key = format!("server{}", counter % 100);
            if let Some(mut entry) = pool.get_mut(&key) {
                entry.push(counter);
                if entry.len() > 10 {
                    entry.pop();
                }
            }
            black_box(())
        });
    });

    group.finish();
}

// ============================================================================
// Metrics Benchmarks
// ============================================================================

fn bench_metrics_recording(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics");

    let counter = AtomicU64::new(0);
    let histogram: Arc<parking_lot::RwLock<Vec<Duration>>> =
        Arc::new(parking_lot::RwLock::new(Vec::with_capacity(10000)));

    group.bench_function("counter_increment", |b| {
        b.iter(|| {
            counter.fetch_add(1, Ordering::Relaxed);
            black_box(())
        });
    });

    group.bench_function("histogram_observe", |b| {
        let histogram = histogram.clone();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let duration = Duration::from_nanos(counter % 1000000);
            let mut guard = histogram.write();
            if guard.len() < 10000 {
                guard.push(duration);
            }
            black_box(())
        });
    });

    group.finish();
}

// ============================================================================
// Rate Limiter Benchmarks
// ============================================================================

fn bench_rate_limiter(c: &mut Criterion) {
    use dashmap::DashMap;
    use std::time::Instant;

    let mut group = c.benchmark_group("rate_limiter");

    struct TokenBucket {
        tokens: AtomicU64,
        last_refill: parking_lot::RwLock<Instant>,
        rate: u64,
        capacity: u64,
    }

    impl TokenBucket {
        fn new(rate: u64, capacity: u64) -> Self {
            Self {
                tokens: AtomicU64::new(capacity),
                last_refill: parking_lot::RwLock::new(Instant::now()),
                rate,
                capacity,
            }
        }

        fn try_acquire(&self) -> bool {
            let current = self.tokens.load(Ordering::Relaxed);
            if current > 0 {
                self.tokens.fetch_sub(1, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }

    let buckets: DashMap<String, Arc<TokenBucket>> = DashMap::new();
    for i in 0..1000 {
        buckets.insert(format!("client{}", i), Arc::new(TokenBucket::new(100, 100)));
    }

    group.bench_function("check_rate_limit", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let key = format!("client{}", counter % 1000);
            let allowed = buckets
                .get(&key)
                .map(|bucket| bucket.try_acquire())
                .unwrap_or(false);
            black_box(allowed)
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets =
        bench_router_matching,
        bench_path_prefix_matching,
        bench_regex_matching,
        bench_round_robin,
        bench_weighted_selection,
        bench_consistent_hash,
        bench_header_parsing,
        bench_header_lookup,
        bench_body_buffering,
        bench_body_zero_copy,
        bench_connection_pool_operations,
        bench_metrics_recording,
        bench_rate_limiter
);

criterion_main!(benches);
