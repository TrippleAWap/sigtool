# Corpus

Ground truth for bounds recovery and, from M3, recall and false-positive rates.

```bash
python corpus/build.py      # cross-compile everything, write build/ground_truth.json
pytest tests/test_corpus_bounds.py
python bench.py --baseline tests/baseline/bench.json
```

* Sources live in `corpus/src/`. They are freestanding (no libc) so they link
  for Linux targets with `ld.lld` and `-nostdlib`.
* Each source is built for x64, arm64, arm32, and thumb (`-mthumb`) at
  `-O0`, `-O2`, `-Os`. arm32 and thumb binaries share the `arm32` arch id;
  Thumb functions are recognized per symbol via the ELF Thumb bit.
* `build/ground_truth.json` maps each binary to `(name, start, size)` from the
  ELF symbol table. Symbol sizes are exact for non-inlined, non-aliased
  functions, which is what the M1 exit criterion measures. arm32 symbol sizes
  include the function's inline literal pool, and recovery extends bounds over
  referenced pool cells to match.
* The negative corpus lives in `corpus/negative/`: purpose-written code that is
  unrelated to `corpus/src/`. It is built at `-O2` for all three targets into
  `build/negative/` and listed under the `negative` key of
  `ground_truth.json`; `bench.py` scans strong signatures against it and gates
  the false-positive rate in CI. No function ground truth is needed for it.
  Real-library negatives (zlib and friends) are deferred until the corpus
  licensing question in `PLAN.md` section 10 is decided.
* Binaries are ignored by git.
