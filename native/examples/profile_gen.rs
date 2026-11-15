//! Phase timings for `gen` and hint-free `locate` on one image (G5 cost).
//!
//! ```text
//! cargo run --release --example profile_gen -- IMAGE ADDR [TARGET]
//! ```
//!
//! Times the whole-image indexes, one generation, and, when a target image is
//! given, a hint-free scan of that signature against it.

use std::time::Instant;

use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{scan_in, CodeIndex, ReferenceIndex, ScanContext};
use sigtool_native::source::ByteSource;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let clock = Instant::now();
    let image = FileSource::from_path(&args[0]).expect("image");
    println!("load image       {:.3}s", clock.elapsed().as_secs_f64());
    let addr = u64::from_str_radix(args[1].trim_start_matches("0x"), 16).expect("addr");

    let clock = Instant::now();
    let mut references = ReferenceIndex::default();
    for region in image.regions() {
        if region.executable {
            references.index_region(&image, region);
        }
    }
    println!("reference index  {:.3}s", clock.elapsed().as_secs_f64());
    let clock = Instant::now();
    let _code = CodeIndex::build(&image);
    println!("code index       {:.3}s", clock.elapsed().as_secs_f64());

    let clock = Instant::now();
    let context = ScanContext::build(&image);
    println!("context build    {:.3}s", clock.elapsed().as_secs_f64());
    let clock = Instant::now();
    let result =
        generate_in(&image, addr, None, None, None, None, None, Some(&context)).expect("generate");
    println!("generate_in      {:.3}s", clock.elapsed().as_secs_f64());

    if let Some(target) = args.get(2) {
        let clock = Instant::now();
        let target = FileSource::from_path(target).expect("target");
        println!("load target      {:.3}s", clock.elapsed().as_secs_f64());
        let clock = Instant::now();
        let context = ScanContext::build(&target);
        println!("target context   {:.3}s", clock.elapsed().as_secs_f64());
        let clock = Instant::now();
        let found = scan_in(&target, &result.signature, &context, false);
        println!(
            "hint-free scan   {:.3}s ({} matches)",
            clock.elapsed().as_secs_f64(),
            found.len()
        );
        let clock = Instant::now();
        let _ = scan_in(&target, &result.signature, &context, false);
        println!("second scan      {:.3}s", clock.elapsed().as_secs_f64());
    }
}
