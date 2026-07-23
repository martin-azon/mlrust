# mlrust

Pure Rust implementation workspace for ML-KEM and ML-DSA.

This repository contains implementation crates for the NIST post-quantum cryptographic algorithms:

* **ML-KEM**, specified in FIPS 203;
* **ML-DSA**, specified in FIPS 204.

The workspace exposes a high-level facade crate, `mlrust`, plus lower-level implementation crates for ML-KEM, ML-DSA, and shared primitives.

## Status

This project is under active development.

The current implementation is correctness- and conformance-oriented. It includes deterministic tests, public API roundtrips, malformed-input tests, feature-gating checks, CCTV vector coverage, long ignored conformance tests, and selected side-channel-sensitive implementation checks.

It should **not** be described as formally audited, formally verified, masked, or fully hardened against local physical side-channel attacks.

## Workspace layout

```text
mlrust/
  crates/
    mlrust_core/   Shared finite-field, polynomial, NTT, encoding, sampling,
                   symmetric, random, and constant-time utilities.

    ml_kem/        ML-KEM implementation and public API.

    ml_dsa/        ML-DSA implementation and public API.

    mlrust/        High-level facade crate re-exporting the user-facing
                   ML-KEM and ML-DSA APIs.
```

## Crates

### `mlrust`

High-level application-facing API.

Use this crate if you want a single dependency exposing both ML-KEM and ML-DSA.

### `ml_kem`

ML-KEM implementation crate.

Supported parameter sets:

* ML-KEM-512;
* ML-KEM-768;
* ML-KEM-1024.

### `ml_dsa`

ML-DSA implementation crate.

Supported parameter sets:

* ML-DSA-44;
* ML-DSA-65;
* ML-DSA-87.

The crate currently exposes pure ML-DSA. HashML-DSA is not exposed as the default signing API.

### `mlrust_core`

Shared implementation primitives used by the protocol crates.

This crate contains finite-field arithmetic, polynomial and polynomial-vector types, NTT routines, encoding helpers, sampling helpers, symmetric SHAKE wrappers, constant-time utilities, and the random byte generator abstraction.

## Installation

Until the crates are published, use path dependencies from this repository.

```toml
[dependencies]
mlrust = { path = "crates/mlrust" }
```

For individual implementation crates:

```toml
[dependencies]
ml_kem = { path = "crates/ml_kem" }
ml_dsa = { path = "crates/ml_dsa" }
```

For caller-provided randomness, downstream code may also need:

```toml
[dependencies]
mlrust_core = { path = "crates/mlrust_core" }
```

## Features

Default features enable:

* `std`;
* OS randomness through `getrandom`.

The caller-provided random byte generator APIs are available without OS randomness.

With default features enabled, use the OS-random convenience APIs such as `ml_kem512_keygen`, `ml_kem512_encaps`, `ml_dsa44_keygen`, and `ml_dsa44_sign`.

Without OS randomness, use the `*_with_rbg` APIs and provide a random byte generator implementing `RandomByteGenerator`.

To disable default features:

```toml
[dependencies]
mlrust = { path = "crates/mlrust", default-features = false }
```

## ML-KEM example

```rust
use mlrust::kem::{
    ml_kem512_decaps,
    ml_kem512_encaps,
    ml_kem512_keygen,
};

fn main() {
    let keypair = ml_kem512_keygen().expect("key generation succeeds");

    let (shared_secret_sender, ciphertext) =
        ml_kem512_encaps(keypair.encapsulation_key())
            .expect("encapsulation succeeds");

    let shared_secret_receiver =
        ml_kem512_decaps(keypair.decapsulation_key(), &ciphertext);

    assert_eq!(
        shared_secret_sender.as_bytes(),
        shared_secret_receiver.as_bytes(),
    );
}
```

ML-KEM decapsulation is infallible at the public API level. Invalid ciphertexts are handled through the ML-KEM implicit-rejection path and still produce a shared secret.

## ML-DSA example

```rust
use mlrust::dsa::{
    ml_dsa44_keygen,
    ml_dsa44_sign,
    ml_dsa44_verify,
};

fn main() {
    let message = b"example message";
    let context = b"example context";

    let keypair = ml_dsa44_keygen().expect("key generation succeeds");

    let signature = ml_dsa44_sign(
        keypair.secret_key(),
        message,
        context,
    )
        .expect("signing succeeds");

    let valid = ml_dsa44_verify(
        keypair.public_key(),
        message,
        context,
        &signature,
    )
        .expect("verification should not fail on well-formed inputs");

    assert!(valid);
}
```

ML-DSA verification returns:

* `Ok(true)` for a valid signature;
* `Ok(false)` for a well-formed but cryptographically invalid signature;
* an error for malformed public keys, malformed signatures, malformed secret keys, randomness failures, or invalid contexts.

## Secret handling

Secret-bearing types zeroize their contents on drop where applicable.

This includes:

* ML-KEM decapsulation keys;
* ML-KEM shared secrets;
* ML-DSA secret keys.

Public values such as ML-KEM encapsulation keys, ML-KEM ciphertexts, ML-DSA public keys, and ML-DSA signatures are ordinary serialized byte wrappers.

Borrow serialized bytes with `as_bytes()`. If the bytes are copied elsewhere, the caller is responsible for protecting and clearing that copy.

## Side-channel notes

The implementation includes selected side-channel-conscious choices, including:

* no `unsafe` code;
* zeroization for first-pass secret-bearing public types;
* division-free ML-KEM compression;
* constant-time byte equality and conditional selection in relevant paths;
* constant-time signed-integer helper functions for selected ML-DSA checks;
* constant-work validation for selected secret-key coefficient checks.

This does not make the implementation masked, fixed-time, formally verified, or fully hardened against local timing, cache, power, or EM attacks.

ML-DSA signing uses a rejection-sampling loop. The number of signing attempts is data-dependent, as in the standard signing procedure.

## Documentation

API documentation can be generated locally with:

```bash
cargo doc --workspace --no-deps --open
```

When published, crate documentation will be available on docs.rs:

```text
mlrust_core
ml_kem
ml_dsa
mlrust
```

## Security

This project has not been independently audited.

Do not use it as the sole basis for production cryptographic security without an appropriate review, threat model, and deployment-specific side-channel assessment.

See `SECURITY.md` for vulnerability reporting guidance.

## License

Licensed under the Apache License, Version 2.0.

See `LICENSE` for details.