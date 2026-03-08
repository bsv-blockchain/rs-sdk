//! Benchmark: Reader/Writer serialization operations.
//!
//! Mirrors ts-sdk/benchmarks/reader-writer-bench.js. The TS SDK uses custom
//! Reader/Writer classes; Rust uses std::io::Cursor<Vec<u8>> with Bitcoin
//! varint encoding matching the transaction module's format.

use criterion::{criterion_group, criterion_main, Criterion};
use std::io::{Cursor, Read, Write};

// ---------------------------------------------------------------------------
// Bitcoin varint helpers (same encoding as transaction module, reimplemented
// here because the transaction module's functions are pub(crate))
// ---------------------------------------------------------------------------

fn write_varint(writer: &mut impl Write, val: u64) -> std::io::Result<()> {
    if val < 0xfd {
        writer.write_all(&[val as u8])
    } else if val <= 0xffff {
        writer.write_all(&[0xfd])?;
        writer.write_all(&(val as u16).to_le_bytes())
    } else if val <= 0xffff_ffff {
        writer.write_all(&[0xfe])?;
        writer.write_all(&(val as u32).to_le_bytes())
    } else {
        writer.write_all(&[0xff])?;
        writer.write_all(&val.to_le_bytes())
    }
}

fn read_varint(reader: &mut impl Read) -> std::io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    match first[0] {
        0..=0xfc => Ok(first[0] as u64),
        0xfd => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

// ---------------------------------------------------------------------------
// Data generation matching TS: data(len, start) => [(start+i) & 0xff ...]
// ---------------------------------------------------------------------------

fn make_data(len: usize, start: usize) -> Vec<u8> {
    (0..len).map(|i| ((start + i) & 0xff) as u8).collect()
}

// ---------------------------------------------------------------------------
// Benchmark functions matching TS reader-writer-bench.js
// ---------------------------------------------------------------------------

fn mixed_ops() {
    let mut buf = Vec::with_capacity(64 * 1024);

    for i in 0u32..1000 {
        // writeUInt32LE
        buf.write_all(&i.to_le_bytes()).unwrap();
        // writeInt16BE
        let neg_i = -(i as i16);
        buf.write_all(&neg_i.to_be_bytes()).unwrap();
        // writeUInt8
        buf.write_all(&[(i & 0xff) as u8]).unwrap();
        // writeVarIntNum(i)
        write_varint(&mut buf, i as u64).unwrap();
        // writeVarIntNum(i % 10)
        write_varint(&mut buf, (i % 10) as u64).unwrap();
        // write(data(i % 10))
        let data = make_data((i % 10) as usize, 0);
        buf.write_all(&data).unwrap();
    }

    let mut reader = Cursor::new(&buf);
    for _ in 0u32..1000 {
        // readUInt32LE
        let mut u32_buf = [0u8; 4];
        reader.read_exact(&mut u32_buf).unwrap();
        let _ = u32::from_le_bytes(u32_buf);
        // readInt16BE
        let mut i16_buf = [0u8; 2];
        reader.read_exact(&mut i16_buf).unwrap();
        let _ = i16::from_be_bytes(i16_buf);
        // readUInt8
        let mut u8_buf = [0u8; 1];
        reader.read_exact(&mut u8_buf).unwrap();
        // readVarIntNum
        let _ = read_varint(&mut reader).unwrap();
        // readVarIntNum -> len, then read(len)
        let len = read_varint(&mut reader).unwrap() as usize;
        let mut discard = vec![0u8; len];
        if len > 0 {
            reader.read_exact(&mut discard).unwrap();
        }
    }
}

fn rw_large() {
    let payloads: Vec<Vec<u8>> = (0..3).map(|i| make_data(2 * 1024 * 1024, i)).collect();

    let mut buf = Vec::with_capacity(6 * 1024 * 1024 + 64);
    for p in &payloads {
        write_varint(&mut buf, p.len() as u64).unwrap();
        buf.write_all(p).unwrap();
    }

    let mut reader = Cursor::new(&buf);
    for _ in 0..payloads.len() {
        let len = read_varint(&mut reader).unwrap() as usize;
        let mut discard = vec![0u8; len];
        reader.read_exact(&mut discard).unwrap();
    }
}

fn rw_small() {
    let payloads: Vec<Vec<u8>> = (0..3000).map(|i| make_data(100, i)).collect();

    let mut buf = Vec::with_capacity(3000 * 110);
    for p in &payloads {
        write_varint(&mut buf, p.len() as u64).unwrap();
        buf.write_all(p).unwrap();
    }

    let mut reader = Cursor::new(&buf);
    for _ in 0..payloads.len() {
        let len = read_varint(&mut reader).unwrap() as usize;
        let mut discard = vec![0u8; len];
        reader.read_exact(&mut discard).unwrap();
    }
}

fn rw_medium() {
    let payloads: Vec<Vec<u8>> = (0..400).map(|i| make_data(10 * 1024, i)).collect();

    let mut buf = Vec::with_capacity(400 * 10 * 1024 + 400 * 5);
    for p in &payloads {
        write_varint(&mut buf, p.len() as u64).unwrap();
        buf.write_all(p).unwrap();
    }

    let mut reader = Cursor::new(&buf);
    for _ in 0..payloads.len() {
        let len = read_varint(&mut reader).unwrap() as usize;
        let mut discard = vec![0u8; len];
        reader.read_exact(&mut discard).unwrap();
    }
}

fn bench_reader_writer(c: &mut Criterion) {
    // Correctness: write then read back produces identical values
    {
        let mut buf = Vec::new();
        let test_val: u32 = 42;
        buf.write_all(&test_val.to_le_bytes()).unwrap();
        write_varint(&mut buf, 12345).unwrap();
        let data = make_data(10, 0);
        write_varint(&mut buf, data.len() as u64).unwrap();
        buf.write_all(&data).unwrap();

        let mut reader = Cursor::new(&buf);
        let mut u32_buf = [0u8; 4];
        reader.read_exact(&mut u32_buf).unwrap();
        assert_eq!(u32::from_le_bytes(u32_buf), 42);
        assert_eq!(read_varint(&mut reader).unwrap(), 12345);
        let len = read_varint(&mut reader).unwrap() as usize;
        let mut read_data = vec![0u8; len];
        reader.read_exact(&mut read_data).unwrap();
        assert_eq!(read_data, data);
    }

    let mut group = c.benchmark_group("reader_writer");

    group.bench_function("mixed_ops", |b| b.iter(mixed_ops));
    group.bench_function("rw_large", |b| b.iter(rw_large));
    group.bench_function("rw_small", |b| b.iter(rw_small));
    group.bench_function("rw_medium", |b| b.iter(rw_medium));

    group.finish();
}

criterion_group!(benches, bench_reader_writer);
criterion_main!(benches);
