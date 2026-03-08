//! Benchmark: Script findAndDelete operation.
//!
//! Mirrors ts-sdk/benchmarks/script-findanddelete-bench.js with identical
//! xorshift PRNG, seeds, and scenario parameters for fair comparison.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::time::Duration;

use bsv::script::op::Op;
use bsv::script::script::Script;
use bsv::script::script_chunk::ScriptChunk;

// ---------------------------------------------------------------------------
// Deterministic xorshift PRNG matching the TS version exactly
// ---------------------------------------------------------------------------

struct Rng {
    x: u32,
}

impl Rng {
    fn new(seed: u32) -> Self {
        Rng { x: seed }
    }

    fn next(&mut self) -> u32 {
        self.x ^= self.x << 13;
        self.x ^= self.x >> 17;
        self.x ^= self.x << 5;
        self.x
    }
}

fn make_bytes(rng: &mut Rng, length: usize) -> Vec<u8> {
    (0..length).map(|_| (rng.next() & 0xff) as u8).collect()
}

fn make_push_chunk(data: Vec<u8>) -> ScriptChunk {
    let len = data.len();
    if len == 0 {
        ScriptChunk::new_opcode(Op::Op0)
    } else if len < 0x4c {
        ScriptChunk::new_raw(len as u8, Some(data))
    } else if len < 0x100 {
        ScriptChunk::new_raw(Op::OpPushData1.to_byte(), Some(data))
    } else if len < 0x10000 {
        ScriptChunk::new_raw(Op::OpPushData2.to_byte(), Some(data))
    } else {
        ScriptChunk::new_raw(Op::OpPushData4.to_byte(), Some(data))
    }
}

struct Scenario {
    name: &'static str,
    target_script: Script,
    chunks: Vec<ScriptChunk>,
}

fn make_scenario(
    name: &'static str,
    total_chunks: usize,
    match_ratio: f64,
    payload_bytes: usize,
    op_ratio: f64,
    op_return_ratio: f64,
    seed: u32,
) -> Scenario {
    let mut rng = Rng::new(seed);
    let target_data = make_bytes(&mut rng, payload_bytes);
    let target_chunk = make_push_chunk(target_data);
    let target_script = Script::from_chunks(vec![target_chunk.clone()]);

    let mut chunks = Vec::with_capacity(total_chunks);
    for _ in 0..total_chunks {
        let roll = rng.next() as f64 / 0xffffffff_u32 as f64;
        if roll < match_ratio {
            chunks.push(target_chunk.clone());
            continue;
        }
        if roll < match_ratio + op_return_ratio {
            let data = make_bytes(&mut rng, payload_bytes);
            chunks.push(ScriptChunk::new_raw(Op::OpReturn.to_byte(), Some(data)));
            continue;
        }
        if roll < match_ratio + op_return_ratio + op_ratio {
            // OP_1 (0x51) + (rng() % 16)
            let op_byte = Op::Op1.to_byte() + ((rng.next() % 16) as u8);
            chunks.push(ScriptChunk::new_raw(op_byte, None));
            continue;
        }
        let data = make_bytes(&mut rng, payload_bytes);
        chunks.push(make_push_chunk(data));
    }

    Scenario {
        name,
        target_script,
        chunks,
    }
}

fn bench_find_and_delete(c: &mut Criterion) {
    let scenarios = vec![
        make_scenario(
            "4000 chunks, 2% matches, 64B",
            4000,
            0.02,
            64,
            0.15,
            0.05,
            0x12345678,
        ),
        make_scenario(
            "8000 chunks, 5% matches, 72B",
            8000,
            0.05,
            72,
            0.1,
            0.05,
            0x9e3779b9,
        ),
        make_scenario(
            "8000 chunks, 20% matches, 72B",
            8000,
            0.2,
            72,
            0.1,
            0.05,
            0xdeadbeef,
        ),
        make_scenario(
            "2000 chunks, 5% matches, 300B",
            2000,
            0.05,
            300,
            0.1,
            0.05,
            0xa5a5a5a5,
        ),
        make_scenario(
            "12000 chunks, 1% matches, 32B",
            12000,
            0.01,
            32,
            0.2,
            0.05,
            0x0f1e2d3c,
        ),
    ];

    // Correctness assertions before benchmarking
    for scenario in &scenarios {
        let script = Script::from_chunks(scenario.chunks.clone());
        let original_len = script.chunks().len();
        let result = script.find_and_delete(&scenario.target_script);
        assert!(
            result.chunks().len() <= original_len,
            "find_and_delete should not increase chunk count for scenario: {}",
            scenario.name
        );
    }

    let mut group = c.benchmark_group("script_findanddelete");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(30);

    for scenario in &scenarios {
        group.bench_function(scenario.name, |b| {
            b.iter_batched(
                || Script::from_chunks(scenario.chunks.clone()),
                |script| script.find_and_delete_owned(&scenario.target_script),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, bench_find_and_delete);
criterion_main!(benches);
