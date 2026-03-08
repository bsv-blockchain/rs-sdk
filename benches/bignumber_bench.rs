use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bsv::primitives::big_number::BigNumber;

fn bignumber_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("bignumber");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));

    // Mirror TS bignumber-bench.js: digits=20000
    let large_hex: String = "f".repeat(20000);
    let a = BigNumber::from_hex(&large_hex).expect("valid hex");
    let b = BigNumber::from_hex(&large_hex).expect("valid hex");

    // Correctness assertion: mul and add produce non-zero results
    let mul_result = a.mul(&b);
    assert!(!mul_result.is_zero(), "mul result must be non-zero");
    let add_result = a.add(&b);
    assert!(!add_result.is_zero(), "add result must be non-zero");

    // Bench "mul_large_numbers": 5 iterations per sample (matching TS mulIterations=5)
    group.bench_function("mul_large_numbers", |bencher| {
        bencher.iter(|| {
            for _ in 0..5 {
                criterion::black_box(a.mul(&b));
            }
        });
    });

    // Bench "add_large_numbers": 1000 iterations per sample (matching TS addIterations=1000)
    group.bench_function("add_large_numbers", |bencher| {
        bencher.iter(|| {
            for _ in 0..1000 {
                criterion::black_box(a.add(&b));
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bignumber_benchmarks);
criterion_main!(benches);
