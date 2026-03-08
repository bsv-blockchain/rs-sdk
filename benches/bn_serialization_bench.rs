use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bsv::primitives::big_number::{BigNumber, Endian};

fn bn_serialization_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("bn_serialization");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));

    // Mirror TS bn-serialization-bench.js: digits=200000
    let large_hex: String = "f".repeat(200000);
    let bn = BigNumber::from_hex(&large_hex).expect("valid hex");

    // Pre-compute serialized forms for from_* benchmarks
    let bytes_big = bn.to_array(Endian::Big, None);
    let bytes_little = bn.to_array(Endian::Little, None);
    let script_num = bn.to_script_num();

    // Correctness: round-trip assertion
    let rt = BigNumber::from_bytes(&bytes_big, Endian::Big);
    assert_eq!(
        rt.to_hex(),
        bn.to_hex(),
        "round-trip must produce same value"
    );

    // to_array big-endian (mirrors TS toSm('big'))
    group.bench_function("to_array_big", |bencher| {
        bencher.iter(|| {
            criterion::black_box(bn.to_array(Endian::Big, None));
        });
    });

    // to_array little-endian (mirrors TS toSm('little'))
    group.bench_function("to_array_little", |bencher| {
        bencher.iter(|| {
            criterion::black_box(bn.to_array(Endian::Little, None));
        });
    });

    // from_bytes big-endian (mirrors TS fromSm(big))
    group.bench_function("from_bytes_big", |bencher| {
        bencher.iter(|| {
            criterion::black_box(BigNumber::from_bytes(&bytes_big, Endian::Big));
        });
    });

    // from_bytes little-endian (mirrors TS fromSm(little, 'little'))
    group.bench_function("from_bytes_little", |bencher| {
        bencher.iter(|| {
            criterion::black_box(BigNumber::from_bytes(&bytes_little, Endian::Little));
        });
    });

    // from_script_num (mirrors TS fromScriptNum)
    group.bench_function("from_script_num", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                BigNumber::from_script_num(&script_num, false, None).expect("valid script num"),
            );
        });
    });

    group.finish();
}

criterion_group!(benches, bn_serialization_benchmarks);
criterion_main!(benches);
