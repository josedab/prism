//! API Versioning Module
//!
//! Provides flexible API versioning strategies:
//! - URL path versioning (/v1/, /v2/)
//! - Header-based versioning (Accept-Version, X-API-Version)
//! - Query parameter versioning (?version=1)
//! - Content negotiation (Accept: application/vnd.api.v1+json)
//! - Version deprecation and sunset headers

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Version extraction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VersioningStrategy {
    /// Extract from URL path (e.g., /v1/users)
    UrlPath,
    /// Extract from header (e.g., Accept-Version: 1)
    Header,
    /// Extract from query parameter (e.g., ?version=1)
    QueryParam,
    /// Extract from Accept header media type
    MediaType,
    /// Custom extraction
    Custom,
}

/// API version configuration
#[derive(Debug, Clone)]
pub struct VersioningConfig {
    /// Enabled versioning strategies (in priority order)
    pub strategies: Vec<VersioningStrategy>,
    /// Header name for header-based versioning
    pub header_name: String,
    /// Query parameter name
    pub query_param: String,
    /// URL path prefix pattern (regex)
    pub path_pattern: String,
    /// Media type vendor prefix (e.g., "vnd.api")
    pub media_type_vendor: String,
    /// Default version when not specified
    pub default_version: ApiVersion,
    /// Enable strict version matching
    pub strict_matching: bool,
    /// Add deprecation headers
    pub add_deprecation_headers: bool,
}

impl Default for VersioningConfig {
    fn default() -> Self {
        Self {
            strategies: vec![
                VersioningStrategy::UrlPath,
                VersioningStrategy::Header,
                VersioningStrategy::QueryParam,
            ],
            header_name: "X-API-Version".to_string(),
            query_param: "version".to_string(),
            path_pattern: r"^/v(\d+)".to_string(),
            media_type_vendor: "vnd.api".to_string(),
            default_version: ApiVersion::new(1, 0, 0),
            strict_matching: false,
            add_deprecation_headers: true,
        }
    }
}

/// API version representation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ApiVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn major_only(major: u32) -> Self {
        Self::new(major, 0, 0)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('v');
        let parts: Vec<&str> = s.split('.').collect();

        let major = parts.first()?.parse().ok()?;
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        Some(Self::new(major, minor, patch))
    }

    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    pub fn to_string_full(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    pub fn to_string_short(&self) -> String {
        format!("v{}", self.major)
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for ApiVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApiVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.major.cmp(&other.major) {
            std::cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
                std::cmp::Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

/// Version status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionStatus {
    /// Version is current and recommended
    Current,
    /// Version is supported but not recommended
    Supported,
    /// Version is deprecated
    Deprecated,
    /// Version is sunset (no longer available)
    Sunset,
    /// Version is in beta
    Beta,
    /// Version is in preview
    Preview,
}

/// Version definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDefinition {
    pub version: ApiVersion,
    pub status: VersionStatus,
    pub release_date: Option<DateTime<Utc>>,
    pub deprecation_date: Option<DateTime<Utc>>,
    pub sunset_date: Option<DateTime<Utc>>,
    pub documentation_url: Option<String>,
    pub migration_guide_url: Option<String>,
    /// Backend to route to
    pub backend: String,
    /// Path transformation (e.g., strip version prefix)
    pub path_transform: Option<PathTransform>,
}

/// Path transformation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTransform {
    /// Strip version prefix from path
    pub strip_prefix: bool,
    /// Replace pattern
    pub replace_from: Option<String>,
    pub replace_to: Option<String>,
    /// Add prefix
    pub add_prefix: Option<String>,
}

/// Version resolution result
#[derive(Debug, Clone)]
pub struct VersionResolution {
    pub version: ApiVersion,
    pub definition: VersionDefinition,
    pub source: VersioningStrategy,
    pub original_path: String,
    pub transformed_path: String,
}

/// Deprecation warning headers
#[derive(Debug, Clone)]
pub struct DeprecationHeaders {
    pub deprecation: Option<String>,
    pub sunset: Option<String>,
    pub link: Option<String>,
    pub warning: Option<String>,
}

/// Version statistics
#[derive(Debug, Default)]
pub struct VersionStats {
    pub requests_by_version: DashMap<ApiVersion, AtomicU64>,
    pub requests_by_strategy: DashMap<VersioningStrategy, AtomicU64>,
    pub deprecated_requests: AtomicU64,
    pub default_version_requests: AtomicU64,
    pub invalid_version_requests: AtomicU64,
}

/// API versioning manager
pub struct ApiVersionManager {
    config: VersioningConfig,
    versions: DashMap<ApiVersion, VersionDefinition>,
    current_version: RwLock<Option<ApiVersion>>,
    path_regex: regex::Regex,
    stats: VersionStats,
}

impl ApiVersionManager {
    pub fn new(config: VersioningConfig) -> Self {
        let path_regex = regex::Regex::new(&config.path_pattern)
            .unwrap_or_else(|_| regex::Regex::new(r"^/v(\d+)").unwrap());

        Self {
            config,
            versions: DashMap::new(),
            current_version: RwLock::new(None),
            path_regex,
            stats: VersionStats::default(),
        }
    }

    /// Register a version
    pub fn register_version(&self, definition: VersionDefinition) {
        let version = definition.version.clone();

        // Update current version if this is marked as Current
        if definition.status == VersionStatus::Current {
            *self.current_version.write() = Some(version.clone());
        }

        self.versions.insert(version, definition);
    }

    /// Get current version
    pub fn current_version(&self) -> Option<ApiVersion> {
        self.current_version.read().clone()
    }

    /// List all versions
    pub fn list_versions(&self) -> Vec<VersionDefinition> {
        self.versions.iter().map(|e| e.value().clone()).collect()
    }

    /// Resolve version from request
    pub fn resolve(
        &self,
        path: &str,
        headers: &HashMap<String, String>,
        query_params: &HashMap<String, String>,
    ) -> Result<VersionResolution, VersionError> {
        let mut version: Option<(ApiVersion, VersioningStrategy)> = None;

        // Try each strategy in order
        for strategy in &self.config.strategies {
            if let Some(v) = self.extract_version(*strategy, path, headers, query_params) {
                version = Some((v, *strategy));
                break;
            }
        }

        // Use default if not found
        let (version, strategy) = version.unwrap_or_else(|| {
            self.stats
                .default_version_requests
                .fetch_add(1, Ordering::Relaxed);
            (
                self.config.default_version.clone(),
                VersioningStrategy::Custom,
            )
        });

        // Look up version definition
        let (resolved_version, definition) = self
            .versions
            .get(&version)
            .map(|e| (version.clone(), e.clone()))
            .or_else(|| {
                // Try to find compatible version
                if !self.config.strict_matching {
                    self.find_compatible_version(&version)
                        .map(|def| (def.version.clone(), def))
                } else {
                    None
                }
            })
            .ok_or(VersionError::UnsupportedVersion(version.clone()))?;

        // Check if version is sunset
        if definition.status == VersionStatus::Sunset {
            return Err(VersionError::VersionSunset(resolved_version));
        }

        // Track deprecated usage
        if definition.status == VersionStatus::Deprecated {
            self.stats
                .deprecated_requests
                .fetch_add(1, Ordering::Relaxed);
        }

        // Update stats
        self.stats
            .requests_by_version
            .entry(resolved_version.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        self.stats
            .requests_by_strategy
            .entry(strategy)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // Transform path if needed
        let transformed_path = self.transform_path(path, &definition);

        Ok(VersionResolution {
            version: resolved_version,
            definition,
            source: strategy,
            original_path: path.to_string(),
            transformed_path,
        })
    }

    fn extract_version(
        &self,
        strategy: VersioningStrategy,
        path: &str,
        headers: &HashMap<String, String>,
        query_params: &HashMap<String, String>,
    ) -> Option<ApiVersion> {
        match strategy {
            VersioningStrategy::UrlPath => self
                .path_regex
                .captures(path)
                .and_then(|cap| cap.get(1).and_then(|m| ApiVersion::parse(m.as_str()))),
            VersioningStrategy::Header => headers
                .get(&self.config.header_name.to_lowercase())
                .or_else(|| headers.get(&self.config.header_name))
                .and_then(|v| ApiVersion::parse(v)),
            VersioningStrategy::QueryParam => query_params
                .get(&self.config.query_param)
                .and_then(|v| ApiVersion::parse(v)),
            VersioningStrategy::MediaType => headers
                .get("accept")
                .and_then(|accept| self.parse_media_type_version(accept)),
            VersioningStrategy::Custom => None,
        }
    }

    fn parse_media_type_version(&self, accept: &str) -> Option<ApiVersion> {
        // Parse: application/vnd.api.v1+json
        let vendor = &self.config.media_type_vendor;
        let pattern = format!(r"{}\.(v\d+(?:\.\d+(?:\.\d+)?)?)", regex::escape(vendor));

        if let Ok(re) = regex::Regex::new(&pattern) {
            if let Some(cap) = re.captures(accept) {
                return cap.get(1).and_then(|m| ApiVersion::parse(m.as_str()));
            }
        }

        None
    }

    fn find_compatible_version(&self, version: &ApiVersion) -> Option<VersionDefinition> {
        // Find the highest minor/patch version for the same major
        self.versions
            .iter()
            .filter(|e| e.key().major == version.major)
            .max_by_key(|e| e.key().clone())
            .map(|e| e.value().clone())
    }

    fn transform_path(&self, path: &str, definition: &VersionDefinition) -> String {
        let mut result = path.to_string();

        if let Some(ref transform) = definition.path_transform {
            // Strip version prefix
            if transform.strip_prefix {
                if let Some(cap) = self.path_regex.find(path) {
                    result = result[cap.end()..].to_string();
                    if result.is_empty() {
                        result = "/".to_string();
                    }
                }
            }

            // Apply replacement
            if let (Some(from), Some(to)) = (&transform.replace_from, &transform.replace_to) {
                if let Ok(re) = regex::Regex::new(from) {
                    result = re.replace_all(&result, to.as_str()).to_string();
                }
            }

            // Add prefix
            if let Some(prefix) = &transform.add_prefix {
                result = format!("{}{}", prefix, result);
            }
        }

        result
    }

    /// Generate deprecation headers
    pub fn deprecation_headers(&self, definition: &VersionDefinition) -> DeprecationHeaders {
        if !self.config.add_deprecation_headers {
            return DeprecationHeaders {
                deprecation: None,
                sunset: None,
                link: None,
                warning: None,
            };
        }

        let deprecation = definition
            .deprecation_date
            .map(|d| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string());

        let sunset = definition
            .sunset_date
            .map(|d| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string());

        let link = definition
            .migration_guide_url
            .as_ref()
            .map(|url| format!("<{}>; rel=\"successor-version\"", url));

        let warning = if definition.status == VersionStatus::Deprecated {
            Some(format!(
                "299 - \"API version {} is deprecated\"",
                definition.version
            ))
        } else {
            None
        };

        DeprecationHeaders {
            deprecation,
            sunset,
            link,
            warning,
        }
    }

    /// Get version statistics
    pub fn stats(&self) -> &VersionStats {
        &self.stats
    }

    /// Get requests count per version
    pub fn requests_by_version(&self) -> Vec<(ApiVersion, u64)> {
        self.stats
            .requests_by_version
            .iter()
            .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
            .collect()
    }
}

/// Version error
#[derive(Debug)]
pub enum VersionError {
    UnsupportedVersion(ApiVersion),
    VersionSunset(ApiVersion),
    InvalidVersionFormat(String),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "Unsupported API version: {}", v),
            Self::VersionSunset(v) => write!(f, "API version {} has been sunset", v),
            Self::InvalidVersionFormat(s) => write!(f, "Invalid version format: {}", s),
        }
    }
}

impl std::error::Error for VersionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_manager() -> ApiVersionManager {
        let manager = ApiVersionManager::new(VersioningConfig::default());

        manager.register_version(VersionDefinition {
            version: ApiVersion::new(1, 0, 0),
            status: VersionStatus::Deprecated,
            release_date: None,
            deprecation_date: Some(Utc::now()),
            sunset_date: None,
            documentation_url: None,
            migration_guide_url: Some("https://docs.example.com/migrate".to_string()),
            backend: "http://api-v1:8080".to_string(),
            path_transform: Some(PathTransform {
                strip_prefix: true,
                replace_from: None,
                replace_to: None,
                add_prefix: None,
            }),
        });

        manager.register_version(VersionDefinition {
            version: ApiVersion::new(2, 0, 0),
            status: VersionStatus::Current,
            release_date: Some(Utc::now()),
            deprecation_date: None,
            sunset_date: None,
            documentation_url: Some("https://docs.example.com/v2".to_string()),
            migration_guide_url: None,
            backend: "http://api-v2:8080".to_string(),
            path_transform: Some(PathTransform {
                strip_prefix: true,
                replace_from: None,
                replace_to: None,
                add_prefix: None,
            }),
        });

        manager
    }

    #[test]
    fn test_version_parsing() {
        assert_eq!(ApiVersion::parse("1"), Some(ApiVersion::new(1, 0, 0)));
        assert_eq!(ApiVersion::parse("v1"), Some(ApiVersion::new(1, 0, 0)));
        assert_eq!(ApiVersion::parse("1.2"), Some(ApiVersion::new(1, 2, 0)));
        assert_eq!(ApiVersion::parse("1.2.3"), Some(ApiVersion::new(1, 2, 3)));
        assert_eq!(ApiVersion::parse("v2.0.1"), Some(ApiVersion::new(2, 0, 1)));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = ApiVersion::new(1, 0, 0);
        let v2 = ApiVersion::new(2, 0, 0);
        let v1_1 = ApiVersion::new(1, 1, 0);

        assert!(v1 < v2);
        assert!(v1 < v1_1);
        assert!(v1_1 < v2);
    }

    #[test]
    fn test_resolve_from_path() {
        let manager = create_manager();

        let result = manager
            .resolve("/v2/users", &HashMap::new(), &HashMap::new())
            .unwrap();

        assert_eq!(result.version, ApiVersion::new(2, 0, 0));
        assert_eq!(result.source, VersioningStrategy::UrlPath);
        assert_eq!(result.transformed_path, "/users");
    }

    #[test]
    fn test_resolve_from_header() {
        let manager = create_manager();

        let mut headers = HashMap::new();
        headers.insert("x-api-version".to_string(), "1".to_string());

        let result = manager
            .resolve("/users", &headers, &HashMap::new())
            .unwrap();

        assert_eq!(result.version, ApiVersion::new(1, 0, 0));
        assert_eq!(result.source, VersioningStrategy::Header);
    }

    #[test]
    fn test_resolve_from_query() {
        let manager = create_manager();

        let mut query = HashMap::new();
        query.insert("version".to_string(), "2".to_string());

        let result = manager.resolve("/users", &HashMap::new(), &query).unwrap();

        assert_eq!(result.version, ApiVersion::new(2, 0, 0));
        assert_eq!(result.source, VersioningStrategy::QueryParam);
    }

    #[test]
    fn test_default_version() {
        let manager = create_manager();

        // No version specified
        let result = manager
            .resolve("/users", &HashMap::new(), &HashMap::new())
            .unwrap();

        assert_eq!(result.version, ApiVersion::new(1, 0, 0)); // Default
    }

    #[test]
    fn test_deprecation_headers() {
        let manager = create_manager();

        let result = manager
            .resolve("/v1/users", &HashMap::new(), &HashMap::new())
            .unwrap();

        let headers = manager.deprecation_headers(&result.definition);
        assert!(headers.deprecation.is_some());
        assert!(headers.warning.is_some());
        assert!(headers.link.is_some());
    }

    #[test]
    fn test_sunset_version() {
        let manager = ApiVersionManager::new(VersioningConfig::default());

        manager.register_version(VersionDefinition {
            version: ApiVersion::new(1, 0, 0),
            status: VersionStatus::Sunset,
            release_date: None,
            deprecation_date: None,
            sunset_date: None,
            documentation_url: None,
            migration_guide_url: None,
            backend: "http://api-v1:8080".to_string(),
            path_transform: None,
        });

        let result = manager.resolve("/v1/users", &HashMap::new(), &HashMap::new());
        assert!(matches!(result, Err(VersionError::VersionSunset(_))));
    }

    #[test]
    fn test_media_type_versioning() {
        let _manager = create_manager();

        let mut headers = HashMap::new();
        headers.insert(
            "accept".to_string(),
            "application/vnd.api.v2+json".to_string(),
        );

        // Enable media type strategy
        let config = VersioningConfig {
            strategies: vec![VersioningStrategy::MediaType],
            ..Default::default()
        };
        let manager = ApiVersionManager::new(config);
        manager.register_version(VersionDefinition {
            version: ApiVersion::new(2, 0, 0),
            status: VersionStatus::Current,
            release_date: None,
            deprecation_date: None,
            sunset_date: None,
            documentation_url: None,
            migration_guide_url: None,
            backend: "http://api-v2:8080".to_string(),
            path_transform: None,
        });

        let result = manager
            .resolve("/users", &headers, &HashMap::new())
            .unwrap();

        assert_eq!(result.version, ApiVersion::new(2, 0, 0));
    }

    #[test]
    fn test_compatible_version_matching() {
        let manager = ApiVersionManager::new(VersioningConfig {
            strict_matching: false,
            ..Default::default()
        });

        manager.register_version(VersionDefinition {
            version: ApiVersion::new(1, 2, 0),
            status: VersionStatus::Current,
            release_date: None,
            deprecation_date: None,
            sunset_date: None,
            documentation_url: None,
            migration_guide_url: None,
            backend: "http://api:8080".to_string(),
            path_transform: None,
        });

        // Request v1.0.0, should match v1.2.0
        let result = manager
            .resolve("/v1/users", &HashMap::new(), &HashMap::new())
            .unwrap();

        assert_eq!(result.version, ApiVersion::new(1, 2, 0));
    }

    #[test]
    fn test_stats_tracking() {
        let manager = create_manager();

        manager
            .resolve("/v1/users", &HashMap::new(), &HashMap::new())
            .unwrap();
        manager
            .resolve("/v2/users", &HashMap::new(), &HashMap::new())
            .unwrap();
        manager
            .resolve("/v2/posts", &HashMap::new(), &HashMap::new())
            .unwrap();

        let by_version = manager.requests_by_version();
        let v1_count = by_version
            .iter()
            .find(|(v, _)| v.major == 1)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let v2_count = by_version
            .iter()
            .find(|(v, _)| v.major == 2)
            .map(|(_, c)| *c)
            .unwrap_or(0);

        assert_eq!(v1_count, 1);
        assert_eq!(v2_count, 2);
    }
}
