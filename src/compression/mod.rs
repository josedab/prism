//! Adaptive Compression Module
//!
//! Provides intelligent compression that adapts based on:
//! - Content type and size
//! - Client capabilities (Accept-Encoding)
//! - Network conditions
//! - CPU load
//! - Historical compression ratios

use bytes::Bytes;
use dashmap::DashMap;
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use parking_lot::RwLock;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// Gzip compression
    Gzip,
    /// Deflate compression
    Deflate,
    /// Brotli compression (best ratio for text)
    Brotli,
    /// Zstd compression (best speed/ratio balance)
    Zstd,
}

impl CompressionAlgorithm {
    pub fn content_encoding(&self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Gzip => Some("gzip"),
            Self::Deflate => Some("deflate"),
            Self::Brotli => Some("br"),
            Self::Zstd => Some("zstd"),
        }
    }

    pub fn from_accept_encoding(header: &str) -> Vec<(Self, f32)> {
        let mut algorithms = Vec::new();

        for part in header.split(',') {
            let part = part.trim();
            let (encoding, quality) = if let Some(pos) = part.find(";q=") {
                let q: f32 = part[pos + 3..].parse().unwrap_or(1.0);
                (&part[..pos], q)
            } else {
                (part, 1.0)
            };

            let algo = match encoding.trim() {
                "br" => Self::Brotli,
                "gzip" => Self::Gzip,
                "deflate" => Self::Deflate,
                "zstd" => Self::Zstd,
                "*" => Self::Gzip, // Default for wildcard
                _ => continue,
            };

            algorithms.push((algo, quality));
        }

        // Sort by quality descending
        algorithms.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        algorithms
    }
}

/// Compression level based on conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression
    None,
    /// Fast compression (level 1-3)
    Fast,
    /// Balanced compression (level 4-6)
    Balanced,
    /// Best compression (level 7-9)
    Best,
}

impl CompressionLevel {
    pub fn to_level(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Fast => 1,
            Self::Balanced => 6,
            Self::Best => 9,
        }
    }
}

/// Configuration for adaptive compression
#[derive(Debug, Clone)]
pub struct AdaptiveCompressionConfig {
    /// Enable adaptive compression
    pub enabled: bool,
    /// Minimum size to compress (bytes)
    pub min_size: usize,
    /// Maximum size to compress (bytes)
    pub max_size: usize,
    /// Content types to compress
    pub compressible_types: Vec<String>,
    /// CPU threshold for reducing compression level
    pub cpu_threshold_reduce: f64,
    /// CPU threshold for disabling compression
    pub cpu_threshold_disable: f64,
    /// Minimum compression ratio to continue
    pub min_ratio: f64,
    /// Enable learning from compression results
    pub learning_enabled: bool,
    /// Preferred algorithm order
    pub preferred_algorithms: Vec<CompressionAlgorithm>,
}

impl Default for AdaptiveCompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_size: 860, // Below this, compression overhead not worth it
            max_size: 100 * 1024 * 1024, // 100MB
            compressible_types: vec![
                "text/".to_string(),
                "application/json".to_string(),
                "application/javascript".to_string(),
                "application/xml".to_string(),
                "application/xhtml+xml".to_string(),
                "image/svg+xml".to_string(),
            ],
            cpu_threshold_reduce: 70.0,
            cpu_threshold_disable: 90.0,
            min_ratio: 0.9, // Don't compress if result is > 90% of original
            learning_enabled: true,
            preferred_algorithms: vec![
                CompressionAlgorithm::Zstd,
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Deflate,
            ],
        }
    }
}

/// Statistics for a content type
#[derive(Debug, Default)]
struct ContentTypeStats {
    samples: AtomicU64,
    total_original: AtomicU64,
    total_compressed: AtomicU64,
    compression_time_ns: AtomicU64,
}

impl ContentTypeStats {
    fn average_ratio(&self) -> f64 {
        let original = self.total_original.load(Ordering::Relaxed);
        let compressed = self.total_compressed.load(Ordering::Relaxed);
        if original == 0 {
            1.0
        } else {
            compressed as f64 / original as f64
        }
    }

    fn average_speed_mbps(&self) -> f64 {
        let original = self.total_original.load(Ordering::Relaxed);
        let time_ns = self.compression_time_ns.load(Ordering::Relaxed);
        if time_ns == 0 {
            0.0
        } else {
            let time_sec = time_ns as f64 / 1_000_000_000.0;
            (original as f64 / 1_000_000.0) / time_sec
        }
    }
}

/// Compression decision result
#[derive(Debug)]
pub struct CompressionDecision {
    /// Algorithm to use
    pub algorithm: CompressionAlgorithm,
    /// Compression level
    pub level: CompressionLevel,
    /// Reason for decision
    pub reason: String,
}

/// Compression result
#[derive(Debug)]
pub struct CompressionResult {
    /// Compressed data
    pub data: Bytes,
    /// Algorithm used
    pub algorithm: CompressionAlgorithm,
    /// Original size
    pub original_size: usize,
    /// Compressed size
    pub compressed_size: usize,
    /// Compression duration
    pub duration: Duration,
}

impl CompressionResult {
    pub fn ratio(&self) -> f64 {
        if self.original_size == 0 {
            1.0
        } else {
            self.compressed_size as f64 / self.original_size as f64
        }
    }

    pub fn savings_percent(&self) -> f64 {
        (1.0 - self.ratio()) * 100.0
    }
}

/// System conditions for adaptive decisions
#[derive(Debug, Clone, Default)]
pub struct SystemConditions {
    /// Current CPU usage percentage
    pub cpu_usage: f64,
    /// Current memory usage percentage
    pub memory_usage: f64,
    /// Network congestion indicator (0-1)
    pub network_congestion: f64,
    /// Pending requests count
    pub pending_requests: u64,
}

/// Adaptive compression engine
pub struct AdaptiveCompressor {
    config: AdaptiveCompressionConfig,
    content_type_stats: DashMap<String, Arc<ContentTypeStats>>,
    algorithm_stats: DashMap<CompressionAlgorithm, Arc<ContentTypeStats>>,
    conditions: RwLock<SystemConditions>,
    stats: CompressionStats,
}

/// Global compression statistics
#[derive(Debug, Default)]
pub struct CompressionStats {
    pub total_requests: AtomicU64,
    pub compressed_requests: AtomicU64,
    pub skipped_too_small: AtomicU64,
    pub skipped_not_compressible: AtomicU64,
    pub skipped_cpu_high: AtomicU64,
    pub skipped_poor_ratio: AtomicU64,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
    pub total_time_ns: AtomicU64,
}

impl CompressionStats {
    pub fn overall_ratio(&self) -> f64 {
        let bytes_in = self.total_bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.total_bytes_out.load(Ordering::Relaxed);
        if bytes_in == 0 {
            1.0
        } else {
            bytes_out as f64 / bytes_in as f64
        }
    }

    pub fn compression_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let compressed = self.compressed_requests.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            compressed as f64 / total as f64 * 100.0
        }
    }
}

impl AdaptiveCompressor {
    pub fn new(config: AdaptiveCompressionConfig) -> Self {
        Self {
            config,
            content_type_stats: DashMap::new(),
            algorithm_stats: DashMap::new(),
            conditions: RwLock::new(SystemConditions::default()),
            stats: CompressionStats::default(),
        }
    }

    /// Update system conditions
    pub fn update_conditions(&self, conditions: SystemConditions) {
        *self.conditions.write() = conditions;
    }

    /// Check if content type is compressible
    pub fn is_compressible(&self, content_type: &str) -> bool {
        self.config
            .compressible_types
            .iter()
            .any(|ct| content_type.starts_with(ct.as_str()))
    }

    /// Make compression decision
    pub fn decide(
        &self,
        content_type: &str,
        content_length: usize,
        accept_encoding: Option<&str>,
    ) -> CompressionDecision {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check if compression is enabled
        if !self.config.enabled {
            return CompressionDecision {
                algorithm: CompressionAlgorithm::None,
                level: CompressionLevel::None,
                reason: "Compression disabled".to_string(),
            };
        }

        // Check size constraints
        if content_length < self.config.min_size {
            self.stats.skipped_too_small.fetch_add(1, Ordering::Relaxed);
            return CompressionDecision {
                algorithm: CompressionAlgorithm::None,
                level: CompressionLevel::None,
                reason: format!(
                    "Content too small ({} < {})",
                    content_length, self.config.min_size
                ),
            };
        }

        if content_length > self.config.max_size {
            return CompressionDecision {
                algorithm: CompressionAlgorithm::None,
                level: CompressionLevel::None,
                reason: format!(
                    "Content too large ({} > {})",
                    content_length, self.config.max_size
                ),
            };
        }

        // Check content type
        if !self.is_compressible(content_type) {
            self.stats
                .skipped_not_compressible
                .fetch_add(1, Ordering::Relaxed);
            return CompressionDecision {
                algorithm: CompressionAlgorithm::None,
                level: CompressionLevel::None,
                reason: format!("Content type not compressible: {}", content_type),
            };
        }

        // Check CPU conditions
        let conditions = self.conditions.read().clone();
        if conditions.cpu_usage > self.config.cpu_threshold_disable {
            self.stats.skipped_cpu_high.fetch_add(1, Ordering::Relaxed);
            return CompressionDecision {
                algorithm: CompressionAlgorithm::None,
                level: CompressionLevel::None,
                reason: format!("CPU too high: {:.1}%", conditions.cpu_usage),
            };
        }

        // Select compression level based on CPU
        let level = if conditions.cpu_usage > self.config.cpu_threshold_reduce {
            CompressionLevel::Fast
        } else if content_length > 1024 * 1024 {
            // Large files: use fast compression
            CompressionLevel::Fast
        } else if content_length < 10 * 1024 {
            // Small files: best compression is fast anyway
            CompressionLevel::Best
        } else {
            CompressionLevel::Balanced
        };

        // Select algorithm based on Accept-Encoding and preferences
        let algorithm = self.select_algorithm(accept_encoding);

        // Check historical ratio for this content type
        if self.config.learning_enabled {
            if let Some(stats) = self.content_type_stats.get(content_type) {
                let avg_ratio = stats.average_ratio();
                if avg_ratio > self.config.min_ratio && stats.samples.load(Ordering::Relaxed) > 10 {
                    self.stats
                        .skipped_poor_ratio
                        .fetch_add(1, Ordering::Relaxed);
                    return CompressionDecision {
                        algorithm: CompressionAlgorithm::None,
                        level: CompressionLevel::None,
                        reason: format!("Historical ratio too poor: {:.1}%", avg_ratio * 100.0),
                    };
                }
            }
        }

        CompressionDecision {
            algorithm,
            level,
            reason: format!("Selected {:?} at {:?} level", algorithm, level),
        }
    }

    /// Select best algorithm based on client support
    fn select_algorithm(&self, accept_encoding: Option<&str>) -> CompressionAlgorithm {
        let client_prefs = accept_encoding
            .map(CompressionAlgorithm::from_accept_encoding)
            .unwrap_or_default();

        if client_prefs.is_empty() {
            return CompressionAlgorithm::None;
        }

        // Find best match between our preferences and client support
        for preferred in &self.config.preferred_algorithms {
            if client_prefs
                .iter()
                .any(|(algo, q)| algo == preferred && *q > 0.0)
            {
                return *preferred;
            }
        }

        // Fall back to client's top preference
        client_prefs
            .first()
            .map(|(algo, _)| *algo)
            .unwrap_or(CompressionAlgorithm::None)
    }

    /// Compress data with the given decision
    pub fn compress(&self, data: &[u8], decision: &CompressionDecision) -> CompressionResult {
        let start = Instant::now();
        let original_size = data.len();

        let compressed = match decision.algorithm {
            CompressionAlgorithm::None => {
                return CompressionResult {
                    data: Bytes::copy_from_slice(data),
                    algorithm: CompressionAlgorithm::None,
                    original_size,
                    compressed_size: original_size,
                    duration: Duration::ZERO,
                };
            }
            CompressionAlgorithm::Gzip => self.compress_gzip(data, decision.level),
            CompressionAlgorithm::Deflate => self.compress_deflate(data, decision.level),
            CompressionAlgorithm::Brotli => self.compress_brotli(data, decision.level),
            CompressionAlgorithm::Zstd => self.compress_zstd(data, decision.level),
        };

        let duration = start.elapsed();
        let compressed_size = compressed.len();

        // Update stats
        self.stats
            .compressed_requests
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_bytes_in
            .fetch_add(original_size as u64, Ordering::Relaxed);
        self.stats
            .total_bytes_out
            .fetch_add(compressed_size as u64, Ordering::Relaxed);
        self.stats
            .total_time_ns
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);

        CompressionResult {
            data: compressed,
            algorithm: decision.algorithm,
            original_size,
            compressed_size,
            duration,
        }
    }

    /// Record compression result for learning
    pub fn record_result(&self, content_type: &str, result: &CompressionResult) {
        if !self.config.learning_enabled {
            return;
        }

        // Update content type stats
        let stats = self
            .content_type_stats
            .entry(content_type.to_string())
            .or_insert_with(|| Arc::new(ContentTypeStats::default()));

        stats.samples.fetch_add(1, Ordering::Relaxed);
        stats
            .total_original
            .fetch_add(result.original_size as u64, Ordering::Relaxed);
        stats
            .total_compressed
            .fetch_add(result.compressed_size as u64, Ordering::Relaxed);
        stats
            .compression_time_ns
            .fetch_add(result.duration.as_nanos() as u64, Ordering::Relaxed);

        // Update algorithm stats
        let algo_stats = self
            .algorithm_stats
            .entry(result.algorithm)
            .or_insert_with(|| Arc::new(ContentTypeStats::default()));

        algo_stats.samples.fetch_add(1, Ordering::Relaxed);
        algo_stats
            .total_original
            .fetch_add(result.original_size as u64, Ordering::Relaxed);
        algo_stats
            .total_compressed
            .fetch_add(result.compressed_size as u64, Ordering::Relaxed);
        algo_stats
            .compression_time_ns
            .fetch_add(result.duration.as_nanos() as u64, Ordering::Relaxed);
    }

    fn compress_gzip(&self, data: &[u8], level: CompressionLevel) -> Bytes {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level.to_level()));
        encoder.write_all(data).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    fn compress_deflate(&self, data: &[u8], level: CompressionLevel) -> Bytes {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level.to_level()));
        encoder.write_all(data).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    fn compress_brotli(&self, data: &[u8], level: CompressionLevel) -> Bytes {
        let quality = match level {
            CompressionLevel::None => 0,
            CompressionLevel::Fast => 1,
            CompressionLevel::Balanced => 6,
            CompressionLevel::Best => 11,
        };

        let mut output = Vec::new();
        let params = brotli::enc::BrotliEncoderParams {
            quality,
            ..Default::default()
        };

        brotli::BrotliCompress(&mut std::io::Cursor::new(data), &mut output, &params).unwrap();
        Bytes::from(output)
    }

    fn compress_zstd(&self, data: &[u8], level: CompressionLevel) -> Bytes {
        let zstd_level = match level {
            CompressionLevel::None => 0,
            CompressionLevel::Fast => 1,
            CompressionLevel::Balanced => 3,
            CompressionLevel::Best => 19,
        };

        Bytes::from(zstd::encode_all(std::io::Cursor::new(data), zstd_level).unwrap())
    }

    /// Get compression statistics
    pub fn stats(&self) -> &CompressionStats {
        &self.stats
    }

    /// Get content type statistics
    pub fn content_type_report(&self) -> Vec<(String, f64, f64)> {
        self.content_type_stats
            .iter()
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry.value().average_ratio(),
                    entry.value().average_speed_mbps(),
                )
            })
            .collect()
    }
}

/// Decompression utilities
pub struct Decompressor;

impl Decompressor {
    pub fn decompress(data: &[u8], encoding: &str) -> std::io::Result<Bytes> {
        match encoding {
            "gzip" => Self::decompress_gzip(data),
            "deflate" => Self::decompress_deflate(data),
            "br" => Self::decompress_brotli(data),
            "zstd" => Self::decompress_zstd(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unknown encoding: {}", encoding),
            )),
        }
    }

    fn decompress_gzip(data: &[u8]) -> std::io::Result<Bytes> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(Bytes::from(output))
    }

    fn decompress_deflate(data: &[u8]) -> std::io::Result<Bytes> {
        use flate2::read::DeflateDecoder;
        use std::io::Read;

        let mut decoder = DeflateDecoder::new(data);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(Bytes::from(output))
    }

    fn decompress_brotli(data: &[u8]) -> std::io::Result<Bytes> {
        let mut output = Vec::new();
        brotli::BrotliDecompress(&mut std::io::Cursor::new(data), &mut output)?;
        Ok(Bytes::from(output))
    }

    fn decompress_zstd(data: &[u8]) -> std::io::Result<Bytes> {
        Ok(Bytes::from(zstd::decode_all(std::io::Cursor::new(data))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_accept_encoding() {
        let algos = CompressionAlgorithm::from_accept_encoding("gzip, deflate, br;q=1.0");
        assert_eq!(algos.len(), 3);
        assert!(algos
            .iter()
            .any(|(a, _)| *a == CompressionAlgorithm::Brotli));
    }

    #[test]
    fn test_compression_decision_too_small() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        let decision = compressor.decide("text/html", 100, Some("gzip"));
        assert_eq!(decision.algorithm, CompressionAlgorithm::None);
        assert!(decision.reason.contains("too small"));
    }

    #[test]
    fn test_compression_decision_not_compressible() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        let decision = compressor.decide("image/png", 10000, Some("gzip"));
        assert_eq!(decision.algorithm, CompressionAlgorithm::None);
        assert!(decision.reason.contains("not compressible"));
    }

    #[test]
    fn test_compression_decision_success() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        let decision = compressor.decide("text/html", 10000, Some("gzip, br"));
        assert_ne!(decision.algorithm, CompressionAlgorithm::None);
    }

    #[test]
    fn test_gzip_compression() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        let data = "Hello, World! ".repeat(100);
        let decision = CompressionDecision {
            algorithm: CompressionAlgorithm::Gzip,
            level: CompressionLevel::Balanced,
            reason: "test".to_string(),
        };

        let result = compressor.compress(data.as_bytes(), &decision);
        assert!(result.compressed_size < result.original_size);
        assert!(result.ratio() < 0.5);
    }

    #[test]
    fn test_brotli_compression() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        let data = "Hello, World! ".repeat(100);
        let decision = CompressionDecision {
            algorithm: CompressionAlgorithm::Brotli,
            level: CompressionLevel::Balanced,
            reason: "test".to_string(),
        };

        let result = compressor.compress(data.as_bytes(), &decision);
        assert!(result.compressed_size < result.original_size);
    }

    #[test]
    fn test_zstd_compression() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        let data = "Hello, World! ".repeat(100);
        let decision = CompressionDecision {
            algorithm: CompressionAlgorithm::Zstd,
            level: CompressionLevel::Balanced,
            reason: "test".to_string(),
        };

        let result = compressor.compress(data.as_bytes(), &decision);
        assert!(result.compressed_size < result.original_size);
    }

    #[test]
    fn test_decompression_roundtrip() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        let original = "Hello, World! ".repeat(100);

        for algo in &[
            CompressionAlgorithm::Gzip,
            CompressionAlgorithm::Deflate,
            CompressionAlgorithm::Brotli,
            CompressionAlgorithm::Zstd,
        ] {
            let decision = CompressionDecision {
                algorithm: *algo,
                level: CompressionLevel::Balanced,
                reason: "test".to_string(),
            };

            let compressed = compressor.compress(original.as_bytes(), &decision);
            let decompressed =
                Decompressor::decompress(&compressed.data, algo.content_encoding().unwrap())
                    .unwrap();

            assert_eq!(decompressed.as_ref(), original.as_bytes());
        }
    }

    #[test]
    fn test_cpu_threshold() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());
        compressor.update_conditions(SystemConditions {
            cpu_usage: 95.0,
            ..Default::default()
        });

        let decision = compressor.decide("text/html", 10000, Some("gzip"));
        assert_eq!(decision.algorithm, CompressionAlgorithm::None);
        assert!(decision.reason.contains("CPU"));
    }

    #[test]
    fn test_learning() {
        let compressor = AdaptiveCompressor::new(AdaptiveCompressionConfig::default());

        // Record some results
        for _ in 0..20 {
            let result = CompressionResult {
                data: Bytes::from(vec![0u8; 950]),
                algorithm: CompressionAlgorithm::Gzip,
                original_size: 1000,
                compressed_size: 950, // Poor ratio
                duration: Duration::from_micros(100),
            };
            compressor.record_result("application/x-poor", &result);
        }

        // Check that the content type report shows the poor ratio
        let report = compressor.content_type_report();
        let poor_entry = report.iter().find(|(ct, _, _)| ct == "application/x-poor");
        assert!(poor_entry.is_some());
        assert!(poor_entry.unwrap().1 > 0.9);
    }
}
