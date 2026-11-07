# Corpus

Ground truth for bounds recovery and, from M3, recall and false-positive rates.

```bash
python corpus/build.py      # cross-compile everything, write build/ground_truth.json
pytest tests/test_corpus_bounds.py
```

* Sources live in `corpus/src/`. They are freestanding (no libc) so they link
  for Linux targets with `ld.lld` and `-nostdlib`.
* Each source is built for x64, arm64, and arm32 (Thumb) at `-O0`, `-O2`, `-Os`.
* `build/ground_truth.json` maps each binary to `(name, start, size)` from the
  ELF symbol table. Symbol sizes are exact for non-inlined, non-aliased
  functions, which is what the M1 exit criterion measures.
* Binaries are ignored by git. A negative corpus of unrelated clean binaries
  (M3) belongs here too, described by a manifest so it stays reproducible.
