//! Benchmarks for proxy components

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use prism::config::CompressionConfig;
use prism::middleware::CompressionMiddleware;

fn create_test_data(size: usize) -> Vec<u8> {
    // Create compressible data (repeated patterns compress well)
    let pattern = b"The quick brown fox jumps over the lazy dog. ";
    pattern.iter().cycle().take(size).cloned().collect()
}

fn bench_gzip_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("gzip_compression");

    let config = CompressionConfig {
        gzip: true,
        brotli: false,
        min_size: 0,
    };
    let middleware = CompressionMiddleware::new(&config);

    for size in [1024, 10240, 102400, 1048576].iter() {
        let data = create_test_data(*size);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("size", size), &data, |b, data| {
            b.iter(|| middleware.compress_gzip_public(black_box(data)))
        });
    }

    group.finish();
}

fn bench_brotli_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("brotli_compression");

    let config = CompressionConfig {
        gzip: false,
        brotli: true,
        min_size: 0,
    };
    let middleware = CompressionMiddleware::new(&config);

    for size in [1024, 10240, 102400].iter() {
        let data = create_test_data(*size);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("size", size), &data, |b, data| {
            b.iter(|| middleware.compress_brotli_public(black_box(data)))
        });
    }

    group.finish();
}

fn bench_compression_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_comparison");

    let gzip_config = CompressionConfig {
        gzip: true,
        brotli: false,
        min_size: 0,
    };
    let brotli_config = CompressionConfig {
        gzip: false,
        brotli: true,
        min_size: 0,
    };

    let gzip_middleware = CompressionMiddleware::new(&gzip_config);
    let brotli_middleware = CompressionMiddleware::new(&brotli_config);

    let size = 10240;
    let data = create_test_data(size);

    group.throughput(Throughput::Bytes(size as u64));

    group.bench_function("gzip", |b| {
        b.iter(|| gzip_middleware.compress_gzip_public(black_box(&data)))
    });

    group.bench_function("brotli", |b| {
        b.iter(|| brotli_middleware.compress_brotli_public(black_box(&data)))
    });

    group.finish();
}

fn bench_encoding_negotiation(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoding_negotiation");

    let config = CompressionConfig {
        gzip: true,
        brotli: true,
        min_size: 0,
    };
    let middleware = CompressionMiddleware::new(&config);

    group.throughput(Throughput::Elements(1));

    group.bench_function("simple", |b| {
        b.iter(|| middleware.negotiate_encoding_public(black_box(Some("gzip"))))
    });

    group.bench_function("with_quality", |b| {
        b.iter(|| middleware.negotiate_encoding_public(black_box(Some("br;q=1.0, gzip;q=0.8"))))
    });

    group.bench_function("complex", |b| {
        b.iter(|| {
            middleware.negotiate_encoding_public(black_box(Some(
                "br;q=1.0, gzip;q=0.8, deflate;q=0.5, *;q=0.1",
            )))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_gzip_compression,
    bench_brotli_compression,
    bench_compression_comparison,
    bench_encoding_negotiation
);
criterion_main!(benches);
