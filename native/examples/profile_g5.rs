//! G5 cost: hint-free scan of a 150-signature module set (PLAN.md §2 G5).
//!
//! ```text
//! cargo run --release --example profile_g5 -- gen IMAGE SIGS.db [COUNT]
//! cargo run --release --example profile_g5 -- scan TARGET SIGS.db
//! ```
//!
//! `gen` picks up to COUNT (default 150) functions of IMAGE, evenly spaced over
//! its symbol starts (the unstripped image's symbols choose generation
//! addresses only), and writes their signatures to a DB. `scan` runs what
//! `scan --db --discovery hint-free` runs against TARGET (a stripped image of
//! another build): one shared context, frequencies, every signature in
//! parallel, then joint resolution. It reports per-phase wall time, the
//! process's peak memory, and a digest of every match, so two builds of the
//! scanner can be checked for identical output. The phases run in separate
//! processes so the scan's peak memory excludes generation.

use std::path::Path;
use std::time::Instant;

use sigtool_native::db::{MappedDb, SignatureDb};
use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{scan_in, Match, ScanContext};
use sigtool_native::memory::peak_memory_bytes;
use sigtool_native::source::ByteSource;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") if args.len() >= 3 => generate(&args[1], &args[2], args.get(3)),
        Some("scan") if args.len() >= 3 => scan(&args[1], &args[2]),
        _ => {
            eprintln!("usage: profile_g5 gen IMAGE SIGS.db [COUNT] | scan TARGET SIGS.db");
            std::process::exit(2);
        }
    }
}

fn generate(image: &str, output: &str, count: Option<&String>) {
    let count: usize = count.map_or(150, |value| value.parse().expect("count"));
    let clock = Instant::now();
    let image = FileSource::from_path(image).expect("image");
    let context = ScanContext::build(&image);
    let mut starts: Vec<u64> = image
        .function_starts()
        .into_iter()
        .filter(|start| image.is_executable(*start))
        .collect();
    starts.sort_unstable();
    starts.dedup();
    // Every start in an evenly spaced order, so the first COUNT successes
    // cover the whole image rather than its first functions.
    let stride = (starts.len() / count.max(1)).max(1);
    let ordered: Vec<u64> = (0..stride)
        .flat_map(|offset| starts.iter().skip(offset).step_by(stride).copied())
        .collect();
    let results = sigtool_native::parallel::map(ordered.len().min(4 * count), |index| {
        generate_in(
            &image,
            ordered[index],
            None,
            None,
            None,
            None,
            None,
            Some(&context),
        )
        .ok()
    });
    let mut db = SignatureDb::new();
    for result in results.into_iter().flatten() {
        if db.len() >= count {
            break;
        }
        db.push(&result.signature).expect("signature");
    }
    std::fs::write(output, db.encode()).expect("write db");
    println!(
        "generated {} signatures in {:.3}s",
        db.len(),
        clock.elapsed().as_secs_f64()
    );
}

fn scan(target: &str, signatures: &str) {
    let total = Instant::now();
    let mapped = MappedDb::open(Path::new(signatures)).expect("db");
    let signatures = mapped
        .view()
        .expect("db view")
        .signatures()
        .expect("signatures");

    let clock = Instant::now();
    let source = FileSource::from_path(target).expect("target");
    println!("load target      {:.3}s", clock.elapsed().as_secs_f64());
    let clock = Instant::now();
    let context = ScanContext::build(&source);
    println!("target context   {:.3}s", clock.elapsed().as_secs_f64());
    let clock = Instant::now();
    context.prepare_frequencies(&source, false);
    println!("frequencies      {:.3}s", clock.elapsed().as_secs_f64());
    let clock = Instant::now();
    let mut all: Vec<Vec<Match>> = sigtool_native::parallel::map(signatures.len(), |index| {
        scan_in(&source, &signatures[index], &context, false)
    });
    println!("scan signatures  {:.3}s", clock.elapsed().as_secs_f64());
    let clock = Instant::now();
    sigtool_native::joint::resolve(&source, &context, &signatures, &mut all, false);
    println!("joint resolve    {:.3}s", clock.elapsed().as_secs_f64());

    let mut digest = crc32fast::Hasher::new();
    let mut matches = 0usize;
    let mut found = 0usize;
    for (signature, list) in signatures.iter().zip(&all) {
        digest.update(signature.name.as_bytes());
        found += usize::from(!list.is_empty());
        for hit in list {
            matches += 1;
            let line = format!(
                "{:x} {:x} {:?} {:?} {:?}\n",
                hit.address, hit.end, hit.score, hit.similarity, hit.matched
            );
            digest.update(line.as_bytes());
        }
    }
    println!(
        "total            {:.3}s ({} signatures, {} with a match, {} matches, digest {:08x})",
        total.elapsed().as_secs_f64(),
        signatures.len(),
        found,
        matches,
        digest.finalize()
    );
    match peak_memory_bytes() {
        Some(bytes) => println!("peak memory      {:.1} MB", bytes as f64 / 1e6),
        None => println!("peak memory      unavailable"),
    }
}
