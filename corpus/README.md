# Corpus

Ground truth for bounds recovery, recall, and false-positive rates. Binaries
are generated and ignored by git; only scripts, sources, and pinned hashes are
committed.

## Toy corpus (`build/`, CI gate)

```bash
python corpus/build.py      # needs clang, ld.lld, llvm-readelf (LLVM 22 for the baseline)
cd native && cargo run --release -- bench --baseline ../tests/baseline/native-bench.json
```

* Sources live in `corpus/src/`. They are freestanding (no libc) so they link
  for Linux targets with `ld.lld` and `-nostdlib`.
* Each source is built for x64, arm64, arm32, and thumb (`-mthumb`) at
  `-O0`, `-O2`, `-Os`.
* `build/ground_truth.json` maps each binary to `(name, start, size)` from the
  ELF `.symtab` (read with `llvm-readelf`). arm32 symbol sizes include the
  function's inline literal pool.
* The negative corpus lives in `corpus/negative/`: purpose-written code that is
  unrelated to `corpus/src/`, built at `-O2` into `build/negative/` and listed
  under the `negative` key. The bench scans strong signatures against it and
  gates the false-positive rate.
* The baseline depends on the compiler version; CI pins LLVM 22.

## Real corpus (`build-real/`)

```bash
docker build -t sigtool-gcc-cross corpus/docker   # GCC 12 cross compilers, once
python corpus/real.py                             # fetch, verify, build, strip
cd native && cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 \
    --baseline ../tests/baseline/native-real-bench.json
```

* zlib, lz4, cJSON, Lua, and SQLite at pinned versions, verified by sha256
  (`real.py`), unpacked into `third_party/`.
* Built as shared objects with clang (host, against the declarations-only libc
  shim in `shim/`) and gcc (in the Docker image), at `-O0`, `-O2`, `-Os`, for
  x64, arm64, arm32, and thumb.
* Every binary also gets a `llvm-strip --strip-all` copy under
  `build-real/stripped/`. Hint-free scans search the stripped copy, so they
  see only what survives stripping (unwind tables, dynamic symbols,
  relocations, code).
* `build-real/ground_truth.json` lists up to 150 functions per library, with
  `path`, `stripped`, `functions`, `arch`, and `library` keys.
