# Testing policy

This workspace uses two test tiers:

1. the default test suite, run during ordinary development;
2. long conformance tests, run manually when deeper vector coverage is needed.

The default suite is intended to stay deterministic and reasonably fast. Long accumulated-vector tests are ignored by default.

## Default checks

Before committing ordinary changes, run:

```bash
cargo fmt --check
cargo check --workspace
cargo check --workspace --all-features
cargo check --workspace --no-default-features
cargo test --workspace
```

The default suite includes:

* unit tests for field arithmetic, NTTs, polynomial operations, encodings, sampling, and symmetric primitives;
* ML-KEM K-PKE and ML-KEM intermediate CCTV vector tests;
* ML-KEM public API roundtrip, boundary, negative-input, RBG failure, and RBG consumption tests;
* ML-DSA public API roundtrip, boundary, negative-input, RBG failure, and RBG consumption tests;
* workspace-level compilation of the `mlrust` facade crate

The `--no-default-features` check is important because caller-provided RBG APIs must compile without OS randomness. The `--all-features` check verifies the OS-random convenience APIs gated behind `getrandom`.

## Long conformance tests

Long accumulated-vector tests are marked `#[ignore]`.

Run them manually before releases, or after changing cryptographic internals such as arithmetic, NTTs, sampling, encoding, key generation, encapsulation, decapsulation, signing, or verification.

ML-DSA long accumulated tests:

```bash
cargo test -p ml_dsa cctv_accumulated -- --ignored --nocapture
```

ML-KEM legacy accumulated tests:

```bash
cargo test -p ml_kem cctv_accumulated_legacy -- --ignored --nocapture
```

## Test layout

Internal primitive tests live close to the implementation under `src/`.

Public API behavior tests live under each crate’s `tests/` directory.

ML-KEM legacy accumulated CCTV tests live in `crates/ml_kem/src/kem/tests.rs` because they use test-only legacy helpers matching the CCTV intermediate-vector convention.

ML-DSA accumulated CCTV tests live in `crates/ml_dsa/tests/ml_dsa_cctv_accumulated.rs`. They are ignored by default and should be run manually when conformance coverage is needed.