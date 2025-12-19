//! Matchers for host and path matching

use crate::error::Result;
use regex::Regex;
use std::collections::HashMap;

/// Host matcher that supports exact match and wildcards
#[derive(Debug, Clone)]
pub enum HostMatcher {
    /// Exact host match
    Exact(String),
    /// Wildcard match (e.g., *.example.com)
    Wildcard { suffix: String },
    /// Match any host
    Any,
}

impl HostMatcher {
    /// Create a new host matcher from a pattern
    pub fn new(pattern: &str) -> Result<Self> {
        let pattern = pattern.to_lowercase();

        if pattern == "*" {
            return Ok(HostMatcher::Any);
        }

        if pattern.starts_with("*.") {
            let suffix = pattern[1..].to_string();
            return Ok(HostMatcher::Wildcard { suffix });
        }

        Ok(HostMatcher::Exact(pattern))
    }

    /// Check if a host matches this pattern
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_lowercase();

        match self {
            HostMatcher::Exact(pattern) => host == *pattern,
            HostMatcher::Wildcard { suffix } => host.ends_with(suffix) || host == suffix[1..],
            HostMatcher::Any => true,
        }
    }

    /// Check if this matcher allows missing host
    pub fn allows_missing(&self) -> bool {
        matches!(self, HostMatcher::Any)
    }
}

/// Path matcher that supports exact, prefix, and regex matching
#[derive(Debug, Clone)]
pub enum PathMatcher {
    /// Match any path
    Any,
    /// Exact path match
    Exact(String),
    /// Prefix path match
    Prefix(String),
    /// Regex path match with capture groups
    Regex(PathRegex),
    /// Combined matchers (all must match)
    Combined(Vec<PathMatcher>),
}

/// Compiled regex path matcher
#[derive(Debug, Clone)]
pub struct PathRegex {
    regex: Regex,
    capture_names: Vec<String>,
}

impl PathMatcher {
    /// Create a new path matcher
    pub fn new(exact: Option<&str>, prefix: Option<&str>, regex: Option<&str>) -> Result<Self> {
        let mut matchers = Vec::new();

        if let Some(exact) = exact {
            matchers.push(PathMatcher::Exact(exact.to_string()));
        }

        if let Some(prefix) = prefix {
            matchers.push(PathMatcher::Prefix(prefix.to_string()));
        }

        if let Some(regex) = regex {
            let compiled = Regex::new(regex)?;
            let capture_names: Vec<String> = compiled
                .capture_names()
                .flatten()
                .map(|s| s.to_string())
                .collect();

            matchers.push(PathMatcher::Regex(PathRegex {
                regex: compiled,
                capture_names,
            }));
        }

        match matchers.len() {
            0 => Ok(PathMatcher::Any),
            1 => Ok(matchers.remove(0)),
            _ => Ok(PathMatcher::Combined(matchers)),
        }
    }

    /// Match a path and return captured parameters
    pub fn matches(&self, path: &str) -> Option<HashMap<String, String>> {
        match self {
            PathMatcher::Any => Some(HashMap::new()),

            PathMatcher::Exact(pattern) => {
                if path == pattern {
                    Some(HashMap::new())
                } else {
                    None
                }
            }

            PathMatcher::Prefix(prefix) => {
                if path.starts_with(prefix) {
                    Some(HashMap::new())
                } else {
                    None
                }
            }

            PathMatcher::Regex(path_regex) => {
                if let Some(captures) = path_regex.regex.captures(path) {
                    let mut params = HashMap::new();
                    for name in &path_regex.capture_names {
                        if let Some(m) = captures.name(name) {
                            params.insert(name.clone(), m.as_str().to_string());
                        }
                    }
                    Some(params)
                } else {
                    None
                }
            }

            PathMatcher::Combined(matchers) => {
                let mut all_params = HashMap::new();
                for matcher in matchers {
                    match matcher.matches(path) {
                        Some(params) => all_params.extend(params),
                        None => return None,
                    }
                }
                Some(all_params)
            }
        }
    }
}

/// Header matcher
#[derive(Debug, Clone)]
pub struct HeaderMatcher {
    /// Required headers with exact values
    exact: HashMap<String, String>,
    /// Headers that must exist (value doesn't matter)
    exists: Vec<String>,
    /// Regex patterns for header values
    patterns: HashMap<String, Regex>,
}

impl HeaderMatcher {
    /// Create a new header matcher
    pub fn new(requirements: &HashMap<String, String>) -> Result<Self> {
        let mut exact = HashMap::new();
        let mut exists = Vec::new();
        let mut patterns = HashMap::new();

        for (name, value) in requirements {
            let name_lower = name.to_lowercase();

            if value == "*" {
                exists.push(name_lower);
            } else if let Some(regex_pattern) = value.strip_prefix("~") {
                let pattern = Regex::new(regex_pattern)?;
                patterns.insert(name_lower, pattern);
            } else {
                exact.insert(name_lower, value.clone());
            }
        }

        Ok(Self {
            exact,
            exists,
            patterns,
        })
    }

    /// Check if headers match
    pub fn matches(&self, headers: &http::HeaderMap) -> bool {
        // Check exact matches
        for (name, expected) in &self.exact {
            match headers.get(name) {
                Some(value) => {
                    if value.to_str().ok() != Some(expected.as_str()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check existence
        for name in &self.exists {
            if !headers.contains_key(name) {
                return false;
            }
        }

        // Check patterns
        for (name, pattern) in &self.patterns {
            match headers.get(name) {
                Some(value) => {
                    if let Ok(value_str) = value.to_str() {
                        if !pattern.is_match(value_str) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod host_matcher_tests {
        use super::*;

        #[test]
        fn test_exact_match() {
            let matcher = HostMatcher::new("example.com").unwrap();
            assert!(matcher.matches("example.com"));
            assert!(matcher.matches("EXAMPLE.COM"));
            assert!(!matcher.matches("other.com"));
            assert!(!matcher.matches("sub.example.com"));
        }

        #[test]
        fn test_wildcard_match() {
            let matcher = HostMatcher::new("*.example.com").unwrap();
            assert!(matcher.matches("sub.example.com"));
            assert!(matcher.matches("api.example.com"));
            assert!(matcher.matches("example.com"));
            assert!(!matcher.matches("other.com"));
        }

        #[test]
        fn test_any_match() {
            let matcher = HostMatcher::new("*").unwrap();
            assert!(matcher.matches("anything.com"));
            assert!(matcher.matches("example.com"));
        }
    }

    mod path_matcher_tests {
        use super::*;

        #[test]
        fn test_exact_match() {
            let matcher = PathMatcher::new(Some("/api/users"), None, None).unwrap();
            assert!(matcher.matches("/api/users").is_some());
            assert!(matcher.matches("/api/users/").is_none());
            assert!(matcher.matches("/api").is_none());
        }

        #[test]
        fn test_prefix_match() {
            let matcher = PathMatcher::new(None, Some("/api"), None).unwrap();
            assert!(matcher.matches("/api").is_some());
            assert!(matcher.matches("/api/users").is_some());
            assert!(matcher.matches("/other").is_none());
        }

        #[test]
        fn test_regex_match() {
            let matcher = PathMatcher::new(None, None, Some(r"/api/users/(?P<id>\d+)")).unwrap();

            let result = matcher.matches("/api/users/123");
            assert!(result.is_some());
            let params = result.unwrap();
            assert_eq!(params.get("id"), Some(&"123".to_string()));

            assert!(matcher.matches("/api/users/abc").is_none());
        }

        #[test]
        fn test_any_match() {
            let matcher = PathMatcher::new(None, None, None).unwrap();
            assert!(matcher.matches("/anything").is_some());
            assert!(matcher.matches("/").is_some());
        }
    }
}
