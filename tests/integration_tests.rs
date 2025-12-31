//! Integration tests for Prism reverse proxy

use prism::config::{
    Config, GlobalConfig, ListenerConfig, MatchConfig, ObservabilityConfig, PoolConfig, Protocol,
    RouteConfig, ServerConfig, UpstreamConfig,
};
use prism::router::Router;
use prism::upstream::UpstreamManager;
use std::collections::HashMap;
use std::time::Duration;

/// Create a minimal test configuration
fn create_test_config() -> Config {
    Config {
        listeners: vec![ListenerConfig {
            address: "127.0.0.1:0".to_string(),
            protocol: Protocol::Http,
            max_connections: 1000,
            tls: None,
        }],
        upstreams: {
            let mut map = HashMap::new();
            map.insert(
                "test_backend".to_string(),
                UpstreamConfig {
                    servers: vec![ServerConfig {
                        address: "127.0.0.1:8080".to_string(),
                        weight: 1,
                        enabled: true,
                    }],
                    load_balancing: prism::config::LoadBalancingAlgorithm::RoundRobin,
                    health_check: None,
                    pool: PoolConfig::default(),
                    connect_timeout: Duration::from_secs(5),
                    request_timeout: Duration::from_secs(30),
                    circuit_breaker: None,
                    retry: None,
                },
            );
            map
        },
        routes: vec![RouteConfig {
            match_config: MatchConfig {
                host: None,
                path: None,
                path_prefix: Some("/api".to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("test_backend".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 0,
        }],
        observability: ObservabilityConfig::default(),
        admin: None,
        global: GlobalConfig::default(),
        // Next-gen features (all optional)
        spiffe: None,
        io_uring: None,
        xds: None,
        kubernetes: None,
        edge: None,
        plugins: None,
        http3: None,
        anomaly_detection: None,
        ebpf: None,
        graphql: None,
    }
}

#[test]
fn test_config_creation() {
    let config = create_test_config();
    assert_eq!(config.listeners.len(), 1);
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);
}

#[test]
fn test_router_initialization() {
    let config = create_test_config();
    let router = Router::new(&config.routes).expect("Router should be created");
    assert_eq!(router.len(), 1);
}

#[test]
fn test_upstream_manager_initialization() {
    let config = create_test_config();
    let manager =
        UpstreamManager::from_config(&config.upstreams).expect("UpstreamManager should be created");

    let upstream = manager.get("test_backend");
    assert!(upstream.is_some(), "Should find test_backend upstream");
}

#[test]
fn test_router_path_matching() {
    let config = create_test_config();
    let router = Router::new(&config.routes).expect("Router should be created");

    // Create a test request
    let request = http::Request::builder().uri("/api/users").body(()).unwrap();

    let resolved = router.resolve(&request);
    assert!(resolved.is_some(), "Should match /api prefix");
    assert_eq!(resolved.unwrap().upstream, Some("test_backend".to_string()));
}

#[test]
fn test_router_no_match() {
    let config = create_test_config();
    let router = Router::new(&config.routes).expect("Router should be created");

    let request = http::Request::builder()
        .uri("/other/path")
        .body(())
        .unwrap();

    let resolved = router.resolve(&request);
    assert!(resolved.is_none(), "Should not match /other/path");
}

#[test]
fn test_load_balancer_round_robin() {
    let config = create_test_config();
    let manager = UpstreamManager::from_config(&config.upstreams).unwrap();

    let upstream = manager.get("test_backend").unwrap();

    // Select servers multiple times - should cycle
    let server1 = upstream.select_server();
    assert!(server1.is_some());

    let server2 = upstream.select_server();
    assert!(server2.is_some());
}

#[test]
fn test_multiple_routes_priority() {
    let routes = vec![
        RouteConfig {
            match_config: MatchConfig {
                host: None,
                path: None,
                path_prefix: Some("/".to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("default".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 100, // Lower priority
        },
        RouteConfig {
            match_config: MatchConfig {
                host: None,
                path: None,
                path_prefix: Some("/api".to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("api_backend".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 0, // Higher priority
        },
    ];

    let router = Router::new(&routes).expect("Router should be created");

    let request = http::Request::builder().uri("/api/users").body(()).unwrap();

    let resolved = router.resolve(&request);
    assert!(resolved.is_some());
    assert_eq!(
        resolved.unwrap().upstream,
        Some("api_backend".to_string()),
        "Should match more specific route"
    );
}

#[test]
fn test_host_based_routing() {
    let routes = vec![
        RouteConfig {
            match_config: MatchConfig {
                host: Some("api.example.com".to_string()),
                path: None,
                path_prefix: Some("/".to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("api_backend".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 0,
        },
        RouteConfig {
            match_config: MatchConfig {
                host: Some("web.example.com".to_string()),
                path: None,
                path_prefix: Some("/".to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("web_backend".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 0,
        },
    ];

    let router = Router::new(&routes).expect("Router should be created");

    // Test api.example.com
    let api_request = http::Request::builder()
        .uri("/users")
        .header("host", "api.example.com")
        .body(())
        .unwrap();

    let resolved = router.resolve(&api_request);
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().upstream, Some("api_backend".to_string()));

    // Test web.example.com
    let web_request = http::Request::builder()
        .uri("/home")
        .header("host", "web.example.com")
        .body(())
        .unwrap();

    let resolved = router.resolve(&web_request);
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().upstream, Some("web_backend".to_string()));
}

#[test]
fn test_method_based_routing() {
    let routes = vec![RouteConfig {
        match_config: MatchConfig {
            host: None,
            path: None,
            path_prefix: Some("/api".to_string()),
            path_regex: None,
            headers: HashMap::new(),
            methods: vec!["GET".to_string(), "POST".to_string()],
        },
        upstream: Some("api_backend".to_string()),
        handler: None,
        middlewares: vec![],
        rewrite: None,
        priority: 0,
    }];

    let router = Router::new(&routes).expect("Router should be created");

    // GET should match
    let get_request = http::Request::builder()
        .method("GET")
        .uri("/api/users")
        .body(())
        .unwrap();
    assert!(router.resolve(&get_request).is_some());

    // POST should match
    let post_request = http::Request::builder()
        .method("POST")
        .uri("/api/users")
        .body(())
        .unwrap();
    assert!(router.resolve(&post_request).is_some());

    // DELETE should not match
    let delete_request = http::Request::builder()
        .method("DELETE")
        .uri("/api/users")
        .body(())
        .unwrap();
    assert!(router.resolve(&delete_request).is_none());
}

#[tokio::test]
async fn test_upstream_server_selection() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "multi_server".to_string(),
        UpstreamConfig {
            servers: vec![
                ServerConfig {
                    address: "127.0.0.1:8001".to_string(),
                    weight: 1,
                    enabled: true,
                },
                ServerConfig {
                    address: "127.0.0.1:8002".to_string(),
                    weight: 1,
                    enabled: true,
                },
                ServerConfig {
                    address: "127.0.0.1:8003".to_string(),
                    weight: 1,
                    enabled: true,
                },
            ],
            load_balancing: prism::config::LoadBalancingAlgorithm::RoundRobin,
            health_check: None,
            pool: PoolConfig::default(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            circuit_breaker: None,
            retry: None,
        },
    );

    let manager = UpstreamManager::from_config(&upstreams).unwrap();
    let upstream = manager.get("multi_server").unwrap();

    // Track which servers are selected
    let mut selections = std::collections::HashSet::new();
    for _ in 0..10 {
        if let Some(server) = upstream.select_server() {
            selections.insert(server.server.address.to_string());
        }
    }

    // With round robin, we should eventually select all servers
    assert!(
        selections.len() >= 2,
        "Should select multiple different servers"
    );
}

#[test]
fn test_config_validation() {
    // Test that config with valid structure passes validation
    let config = create_test_config();
    let result = prism::config::validate_config(&config);
    assert!(result.is_ok(), "Valid config should pass validation");
}

#[test]
fn test_regex_path_matching() {
    let routes = vec![RouteConfig {
        match_config: MatchConfig {
            host: None,
            path: None,
            path_prefix: None,
            path_regex: Some(r"/users/\d+".to_string()),
            headers: HashMap::new(),
            methods: vec![],
        },
        upstream: Some("user_backend".to_string()),
        handler: None,
        middlewares: vec![],
        rewrite: None,
        priority: 0,
    }];

    let router = Router::new(&routes).expect("Router should be created");

    // Should match /users/123
    let request = http::Request::builder().uri("/users/123").body(()).unwrap();
    assert!(
        router.resolve(&request).is_some(),
        "Should match /users/123"
    );

    // Should not match /users/abc
    let request = http::Request::builder().uri("/users/abc").body(()).unwrap();
    assert!(
        router.resolve(&request).is_none(),
        "Should not match /users/abc"
    );
}

#[test]
fn test_exact_path_matching() {
    let routes = vec![RouteConfig {
        match_config: MatchConfig {
            host: None,
            path: Some("/health".to_string()),
            path_prefix: None,
            path_regex: None,
            headers: HashMap::new(),
            methods: vec![],
        },
        upstream: Some("health_backend".to_string()),
        handler: None,
        middlewares: vec![],
        rewrite: None,
        priority: 0,
    }];

    let router = Router::new(&routes).expect("Router should be created");

    // Should match exactly /health
    let request = http::Request::builder().uri("/health").body(()).unwrap();
    assert!(router.resolve(&request).is_some(), "Should match /health");

    // Should not match /health/check
    let request = http::Request::builder()
        .uri("/health/check")
        .body(())
        .unwrap();
    assert!(
        router.resolve(&request).is_none(),
        "Should not match /health/check"
    );
}
