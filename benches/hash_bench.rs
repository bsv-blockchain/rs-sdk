use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

use bsv::primitives::hash::{ripemd160, sha256, sha256_hmac, sha512, sha512_hmac};

fn hash_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash");
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));

    // Three input sizes matching TS hash-bench.js
    let small: Vec<u8> = (0..32u32).map(|i| (i & 0xff) as u8).collect();
    let medium: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
    let large: Vec<u8> = (0..1_048_576u32).map(|i| (i & 0xff) as u8).collect();
    let hmac_key: Vec<u8> = (0..32u32).map(|i| (i & 0xff) as u8).collect();

    // Correctness: verify SHA-256 output length is 32 bytes
    let result = sha256(&small);
    assert_eq!(result.len(), 32, "SHA-256 output must be 32 bytes");

    // SHA-256
    group.throughput(Throughput::Bytes(32));
    group.bench_function("sha256_32B", |bencher| {
        bencher.iter(|| criterion::black_box(sha256(&small)));
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("sha256_1KB", |bencher| {
        bencher.iter(|| criterion::black_box(sha256(&medium)));
    });

    group.throughput(Throughput::Bytes(1_048_576));
    group.bench_function("sha256_1MB", |bencher| {
        bencher.iter(|| criterion::black_box(sha256(&large)));
    });

    // SHA-512
    group.throughput(Throughput::Bytes(32));
    group.bench_function("sha512_32B", |bencher| {
        bencher.iter(|| criterion::black_box(sha512(&small)));
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("sha512_1KB", |bencher| {
        bencher.iter(|| criterion::black_box(sha512(&medium)));
    });

    group.throughput(Throughput::Bytes(1_048_576));
    group.bench_function("sha512_1MB", |bencher| {
        bencher.iter(|| criterion::black_box(sha512(&large)));
    });

    // RIPEMD-160
    group.throughput(Throughput::Bytes(32));
    group.bench_function("ripemd160_32B", |bencher| {
        bencher.iter(|| criterion::black_box(ripemd160(&small)));
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("ripemd160_1KB", |bencher| {
        bencher.iter(|| criterion::black_box(ripemd160(&medium)));
    });

    group.throughput(Throughput::Bytes(1_048_576));
    group.bench_function("ripemd160_1MB", |bencher| {
        bencher.iter(|| criterion::black_box(ripemd160(&large)));
    });

    // HMAC-SHA256 1KB
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("hmac_sha256_1KB", |bencher| {
        bencher.iter(|| criterion::black_box(sha256_hmac(&hmac_key, &medium)));
    });

    // HMAC-SHA512 1KB
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("hmac_sha512_1KB", |bencher| {
        bencher.iter(|| criterion::black_box(sha512_hmac(&hmac_key, &medium)));
    });

    group.finish();
}

criterion_group!(benches, hash_benchmarks);
criterion_main!(benches);
