//! Benchmark: Script binary serialization (fromBinary / toBinary).
//!
//! Mirrors ts-sdk/benchmarks/script-serialization-bench.js using the same
//! large script hex string for direct comparison.

use criterion::{criterion_group, criterion_main, Criterion};

use bsv::script::script::Script;

/// The same large hex script used in the TS benchmark (75266 hex chars = 37633 bytes).
const BIG_SCRIPT_HEX: &str = include_str!("data/large_script.hex");

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn bench_script_serialization(c: &mut Criterion) {
    let big_script_bytes = hex_to_bytes(BIG_SCRIPT_HEX);

    // Correctness: round-trip produces identical bytes
    let parsed = Script::from_binary(&big_script_bytes);
    let serialized = parsed.to_binary();
    assert_eq!(
        serialized, big_script_bytes,
        "round-trip (from_binary -> to_binary) must produce identical bytes"
    );

    let mut group = c.benchmark_group("script_serialization");

    group.bench_function("from_binary", |b| {
        b.iter(|| Script::from_binary(&big_script_bytes))
    });

    // Pre-parse the script for to_binary benchmark
    let pre_parsed = Script::from_binary(&big_script_bytes);
    group.bench_function("to_binary", |b| b.iter(|| pre_parsed.to_binary()));

    group.finish();
}

criterion_group!(benches, bench_script_serialization);
criterion_main!(benches);
