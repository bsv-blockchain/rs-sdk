use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

use bsv::primitives::symmetric_key::SymmetricKey;

fn symmetric_key_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric_key");
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));

    let key = SymmetricKey::from_random();

    // Three sizes matching TS symmetric-key-bench.js
    let small: Vec<u8> = (0..100u32).map(|i| (i & 0xff) as u8).collect();
    let medium: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
    let large: Vec<u8> = (0..(2 * 1024 * 1024u32))
        .map(|i| (i & 0xff) as u8)
        .collect();

    // Pre-encrypt for decrypt benchmarks
    let enc_small = key.encrypt(&small).expect("encrypt small");
    let enc_medium = key.encrypt(&medium).expect("encrypt medium");
    let enc_large = key.encrypt(&large).expect("encrypt large");

    // Correctness: round-trip
    let dec = key.decrypt(&enc_small).expect("decrypt must succeed");
    assert_eq!(dec, small, "round-trip must match");

    // Single-message benchmarks with throughput
    group.throughput(Throughput::Bytes(100));
    group.bench_function("encrypt_small_100B", |bencher| {
        bencher.iter(|| {
            criterion::black_box(key.encrypt(&small).unwrap());
        });
    });
    group.bench_function("decrypt_small_100B", |bencher| {
        bencher.iter(|| {
            criterion::black_box(key.decrypt(&enc_small).unwrap());
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("encrypt_medium_1KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(key.encrypt(&medium).unwrap());
        });
    });
    group.bench_function("decrypt_medium_1KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(key.decrypt(&enc_medium).unwrap());
        });
    });

    group.throughput(Throughput::Bytes(2 * 1024 * 1024));
    group.bench_function("encrypt_large_2MB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(key.encrypt(&large).unwrap());
        });
    });
    group.bench_function("decrypt_large_2MB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(key.decrypt(&enc_large).unwrap());
        });
    });

    // Batch benchmarks matching TS (50 small, 200 medium)
    let small_msgs: Vec<Vec<u8>> = (0..50)
        .map(|j| (0..100u32).map(|i| ((i + j * 100) & 0xff) as u8).collect())
        .collect();
    let medium_msgs: Vec<Vec<u8>> = (0..200)
        .map(|j| {
            (0..1024u32)
                .map(|i| ((i + j * 1024) & 0xff) as u8)
                .collect()
        })
        .collect();
    let enc_small_batch: Vec<Vec<u8>> =
        small_msgs.iter().map(|m| key.encrypt(m).unwrap()).collect();
    let enc_medium_batch: Vec<Vec<u8>> = medium_msgs
        .iter()
        .map(|m| key.encrypt(m).unwrap())
        .collect();

    group.throughput(Throughput::Bytes(50 * 100));
    group.bench_function("encrypt_50_small", |bencher| {
        bencher.iter(|| {
            for m in &small_msgs {
                criterion::black_box(key.encrypt(m).unwrap());
            }
        });
    });
    group.bench_function("decrypt_50_small", |bencher| {
        bencher.iter(|| {
            for m in &enc_small_batch {
                criterion::black_box(key.decrypt(m).unwrap());
            }
        });
    });

    group.throughput(Throughput::Bytes(200 * 1024));
    group.bench_function("encrypt_200_medium", |bencher| {
        bencher.iter(|| {
            for m in &medium_msgs {
                criterion::black_box(key.encrypt(m).unwrap());
            }
        });
    });
    group.bench_function("decrypt_200_medium", |bencher| {
        bencher.iter(|| {
            for m in &enc_medium_batch {
                criterion::black_box(key.decrypt(m).unwrap());
            }
        });
    });

    group.finish();
}

criterion_group!(benches, symmetric_key_benchmarks);
criterion_main!(benches);
