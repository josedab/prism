//! Benchmarks for the routing system

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http::Request;
use prism::config::{MatchConfig, RouteConfig};
use prism::router::Router;
use std::collections::HashMap;

fn create_routes(count: usize) -> Vec<RouteConfig> {
    (0..count)
        .map(|i| RouteConfig {
            match_config: MatchConfig {
                host: Some(format!("api{}.example.com", i)),
                path_prefix: Some(format!("/service{}", i)),
                path: None,
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some(format!("backend{}", i)),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: i as i32,
        })
        .collect()
}

fn create_request(host: &str, path: &str) -> Request<()> {
    Request::builder()
        .uri(path)
        .header("Host", host)
        .body(())
        .unwrap()
}

fn bench_router_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_creation");

    for count in [10, 50, 100, 500].iter() {
        let routes = create_routes(*count);

        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::new("routes", count), count, |b, _| {
            b.iter(|| Router::new(black_box(&routes)).unwrap())
        });
    }

    group.finish();
}

fn bench_route_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_matching");

    // Create router with varying route counts
    for count in [10, 50, 100, 500].iter() {
        let routes = create_routes(*count);
        let router = Router::new(&routes).unwrap();

        group.throughput(Throughput::Elements(1));

        // Benchmark matching first route
        let first_request = create_request("api0.example.com", "/service0/test");
        group.bench_with_input(BenchmarkId::new("match_first", count), count, |b, _| {
            b.iter(|| router.resolve(black_box(&first_request)))
        });

        // Benchmark matching middle route
        let mid = count / 2;
        let mid_request = create_request(
            &format!("api{}.example.com", mid),
            &format!("/service{}/test", mid),
        );
        group.bench_with_input(BenchmarkId::new("match_middle", count), count, |b, _| {
            b.iter(|| router.resolve(black_box(&mid_request)))
        });

        // Benchmark matching last route
        let last = count - 1;
        let last_request = create_request(
            &format!("api{}.example.com", last),
            &format!("/service{}/test", last),
        );
        group.bench_with_input(BenchmarkId::new("match_last", count), count, |b, _| {
            b.iter(|| router.resolve(black_box(&last_request)))
        });

        // Benchmark no match
        let no_match_request = create_request("unknown.example.com", "/unknown/path");
        group.bench_with_input(BenchmarkId::new("no_match", count), count, |b, _| {
            b.iter(|| router.resolve(black_box(&no_match_request)))
        });
    }

    group.finish();
}

fn bench_path_prefix_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_prefix_matching");

    // Create routes with different path depths
    let routes: Vec<RouteConfig> = vec![
        RouteConfig {
            match_config: MatchConfig {
                host: None,
                path_prefix: Some("/api".to_string()),
                path: None,
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("backend1".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 0,
        },
        RouteConfig {
            match_config: MatchConfig {
                host: None,
                path_prefix: Some("/api/v1".to_string()),
                path: None,
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("backend2".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 1,
        },
        RouteConfig {
            match_config: MatchConfig {
                host: None,
                path_prefix: Some("/api/v1/users".to_string()),
                path: None,
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("backend3".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 2,
        },
    ];

    let router = Router::new(&routes).unwrap();

    group.throughput(Throughput::Elements(1));

    // Short path
    let short_request = create_request("example.com", "/api/test");
    group.bench_function("short_path", |b| {
        b.iter(|| router.resolve(black_box(&short_request)))
    });

    // Medium path
    let medium_request = create_request("example.com", "/api/v1/resources");
    group.bench_function("medium_path", |b| {
        b.iter(|| router.resolve(black_box(&medium_request)))
    });

    // Long path
    let long_request = create_request("example.com", "/api/v1/users/123/profile");
    group.bench_function("long_path", |b| {
        b.iter(|| router.resolve(black_box(&long_request)))
    });

    group.finish();
}

fn bench_regex_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex_matching");

    let routes: Vec<RouteConfig> = vec![RouteConfig {
        match_config: MatchConfig {
            host: None,
            path_prefix: None,
            path: None,
            path_regex: Some(r"^/users/\d+/posts/\d+$".to_string()),
            headers: HashMap::new(),
            methods: vec![],
        },
        upstream: Some("backend".to_string()),
        handler: None,
        middlewares: vec![],
        rewrite: None,
        priority: 0,
    }];

    let router = Router::new(&routes).unwrap();

    group.throughput(Throughput::Elements(1));

    // Matching regex
    let match_request = create_request("example.com", "/users/123/posts/456");
    group.bench_function("regex_match", |b| {
        b.iter(|| router.resolve(black_box(&match_request)))
    });

    // Non-matching regex
    let no_match_request = create_request("example.com", "/users/abc/posts/def");
    group.bench_function("regex_no_match", |b| {
        b.iter(|| router.resolve(black_box(&no_match_request)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_router_creation,
    bench_route_matching,
    bench_path_prefix_matching,
    bench_regex_matching
);
criterion_main!(benches);
