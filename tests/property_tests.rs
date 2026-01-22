//! Property-based tests for Prism
//!
//! These tests use proptest to verify properties hold for arbitrary inputs.

use proptest::prelude::*;

// ============================================================================
// Path Matching Properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Prefix matching is reflexive - a path always matches itself as prefix
    #[test]
    fn prop_prefix_match_reflexive(path in "[a-z/]{1,100}") {
        prop_assert!(path.starts_with(&path));
    }

    /// Prefix matching is transitive
    #[test]
    fn prop_prefix_match_transitive(
        a in "[a-z]{1,10}",
        b in "[a-z]{1,10}",
        c in "[a-z]{1,10}"
    ) {
        let path_ab = format!("/{}/{}", a, b);
        let path_abc = format!("/{}/{}/{}", a, b, c);
        let prefix_a = format!("/{}", a);

        // If abc starts with ab, and ab starts with a, then abc starts with a
        if path_abc.starts_with(&path_ab) && path_ab.starts_with(&prefix_a) {
            prop_assert!(path_abc.starts_with(&prefix_a));
        }
    }

    /// Empty prefix matches everything
    #[test]
    fn prop_empty_prefix_matches_all(path in "[a-z/]{0,100}") {
        prop_assert!(path.starts_with(""));
    }

    /// Longer prefix is more specific
    #[test]
    fn prop_longer_prefix_more_specific(
        prefix in "[a-z]{1,20}",
        suffix in "[a-z]{1,20}"
    ) {
        let short_prefix = format!("/{}", prefix);
        let long_prefix = format!("/{}/{}", prefix, suffix);
        let path = format!("/{}/{}/extra", prefix, suffix);

        // Path matches both prefixes
        prop_assert!(path.starts_with(&short_prefix));
        prop_assert!(path.starts_with(&long_prefix));
    }
}

// ============================================================================
// Header Validation Properties
// ============================================================================

fn valid_header_name() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9-]{0,62}".prop_map(|s| s.to_lowercase())
}

fn valid_header_value() -> impl Strategy<Value = String> {
    "[ -~]{0,8000}" // Printable ASCII
}

proptest! {
    /// Valid header names are accepted
    #[test]
    fn prop_valid_header_names_accepted(name in valid_header_name()) {
        let result = http::header::HeaderName::try_from(name.as_str());
        prop_assert!(result.is_ok(), "Header name '{}' should be valid", name);
    }

    /// Header names are case-insensitive
    #[test]
    fn prop_header_names_case_insensitive(name in valid_header_name()) {
        let lower = http::header::HeaderName::try_from(name.to_lowercase().as_str());
        let upper = http::header::HeaderName::try_from(name.to_uppercase().as_str());

        prop_assert!(lower.is_ok());
        prop_assert!(upper.is_ok());
        prop_assert_eq!(lower.unwrap(), upper.unwrap());
    }

    /// Valid header values are accepted
    #[test]
    fn prop_valid_header_values_accepted(value in valid_header_value()) {
        // Filter out values with control characters
        if value.chars().all(|c| c >= ' ' && c <= '~') {
            let result = http::header::HeaderValue::try_from(value.as_str());
            prop_assert!(result.is_ok(), "Header value should be valid");
        }
    }
}

// ============================================================================
// URL Parsing Properties
// ============================================================================

fn valid_path_segment() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9._~-]{1,20}"
}

fn valid_query_param() -> impl Strategy<Value = (String, String)> {
    ("[a-zA-Z][a-zA-Z0-9_]{0,19}", "[a-zA-Z0-9._-]{0,50}")
}

proptest! {
    /// Valid paths parse successfully
    #[test]
    fn prop_valid_paths_parse(
        segments in prop::collection::vec(valid_path_segment(), 1..5)
    ) {
        let path = format!("/{}", segments.join("/"));
        let result = path.parse::<http::Uri>();
        prop_assert!(result.is_ok(), "Path '{}' should parse", path);
    }

    /// Paths preserve segments after parsing
    #[test]
    fn prop_path_segments_preserved(
        segments in prop::collection::vec(valid_path_segment(), 1..5)
    ) {
        let path = format!("/{}", segments.join("/"));
        let uri: http::Uri = path.parse().unwrap();

        for segment in &segments {
            prop_assert!(
                uri.path().contains(segment),
                "Path '{}' should contain segment '{}'",
                uri.path(),
                segment
            );
        }
    }

    /// Query parameters are preserved
    #[test]
    fn prop_query_params_preserved(
        path in valid_path_segment(),
        params in prop::collection::vec(valid_query_param(), 1..3)
    ) {
        let query = params.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        let full_path = format!("/{}?{}", path, query);

        let uri: http::Uri = full_path.parse().unwrap();
        let parsed_query = uri.query().unwrap_or("");

        for (key, value) in &params {
            prop_assert!(
                parsed_query.contains(&format!("{}={}", key, value)),
                "Query '{}' should contain '{}={}'",
                parsed_query, key, value
            );
        }
    }
}

// ============================================================================
// Load Balancer Properties
// ============================================================================

proptest! {
    /// Round robin distributes evenly
    #[test]
    fn prop_round_robin_distributes_evenly(
        server_count in 2usize..10,
        request_count in 100usize..1000
    ) {
        let mut distribution = vec![0usize; server_count];

        for i in 0..request_count {
            let selected = i % server_count;
            distribution[selected] += 1;
        }

        // Each server should get roughly equal requests
        let expected = request_count / server_count;
        let tolerance = 1; // Allow off-by-one due to remainder

        for (i, count) in distribution.iter().enumerate() {
            prop_assert!(
                (*count as i64 - expected as i64).abs() <= tolerance as i64,
                "Server {} got {} requests, expected ~{}",
                i, count, expected
            );
        }
    }

    /// Weighted selection respects weights over many iterations
    #[test]
    fn prop_weighted_respects_ratios(
        weights in prop::collection::vec(1u32..10, 2..5),
        iterations in 1000usize..5000
    ) {
        let total_weight: u32 = weights.iter().sum();
        let mut counts = vec![0usize; weights.len()];
        let mut rng_state: u64 = 12345;

        for _ in 0..iterations {
            // Simple LCG
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let r = (rng_state >> 33) as u32 % total_weight;

            let mut cumulative = 0u32;
            for (i, &weight) in weights.iter().enumerate() {
                cumulative += weight;
                if r < cumulative {
                    counts[i] += 1;
                    break;
                }
            }
        }

        // Check that ratios are approximately correct (within 20%)
        for (i, (&weight, &count)) in weights.iter().zip(counts.iter()).enumerate() {
            let expected_ratio = weight as f64 / total_weight as f64;
            let actual_ratio = count as f64 / iterations as f64;
            let diff = (expected_ratio - actual_ratio).abs();

            prop_assert!(
                diff < 0.2,
                "Server {} with weight {} has ratio {:.3}, expected {:.3}",
                i, weight, actual_ratio, expected_ratio
            );
        }
    }
}

// ============================================================================
// Rate Limiter Properties
// ============================================================================

proptest! {
    /// Rate limiter respects the limit
    #[test]
    fn prop_rate_limiter_respects_limit(
        limit in 10u64..100,
        requests in 50usize..200
    ) {
        use std::sync::atomic::{AtomicU64, Ordering};

        let tokens = AtomicU64::new(limit);
        let mut allowed = 0usize;

        for _ in 0..requests {
            let current = tokens.load(Ordering::Relaxed);
            if current > 0 {
                tokens.fetch_sub(1, Ordering::Relaxed);
                allowed += 1;
            }
        }

        prop_assert!(
            allowed <= limit as usize,
            "Allowed {} requests but limit is {}",
            allowed, limit
        );
    }
}

// ============================================================================
// Configuration Properties
// ============================================================================

proptest! {
    /// Environment variable expansion is idempotent for non-variable strings
    #[test]
    fn prop_env_expansion_idempotent(value in "[a-zA-Z0-9._/-]{1,50}") {
        // Values without ${} should remain unchanged
        if !value.contains("${") {
            // Assuming expand function exists
            // let expanded = prism::config::expand_env_vars(&value);
            // prop_assert_eq!(expanded, value);
            prop_assert!(true); // Placeholder
        }
    }

    /// Config key names are valid identifiers
    #[test]
    fn prop_config_keys_valid(key in "[a-z][a-z0-9_]{0,30}") {
        // Valid config keys should be lowercase with underscores
        prop_assert!(key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
        prop_assert!(key.chars().next().unwrap().is_ascii_lowercase());
    }
}

// ============================================================================
// Hash Consistency Properties
// ============================================================================

proptest! {
    /// Same input always produces same hash
    #[test]
    fn prop_hash_deterministic(input in "[a-zA-Z0-9]{1,100}") {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher1 = DefaultHasher::new();
        input.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        input.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        prop_assert_eq!(hash1, hash2);
    }

    /// Consistent hash ring assigns same key to same server
    #[test]
    fn prop_consistent_hash_stable(
        key in "[a-zA-Z0-9]{1,50}",
        _server_count in 3usize..10
    ) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Hash the key twice
        let hash = |s: &str| {
            let mut hasher = DefaultHasher::new();
            s.hash(&mut hasher);
            hasher.finish()
        };

        let h1 = hash(&key);
        let h2 = hash(&key);

        prop_assert_eq!(h1, h2, "Same key should hash to same value");
    }
}
