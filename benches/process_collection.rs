//! Benchmarks for process collection

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_get_all_processes(c: &mut Criterion) {
    c.bench_function("get_all_processes", |b| {
        b.iter(|| {
            // Benchmark implementation
            black_box(());
        });
    });
}

criterion_group!(benches, benchmark_get_all_processes);
criterion_main!(benches);