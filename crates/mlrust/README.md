## `crates/mlrust/README.md`

# mlrust

High-level public API for the `mlrust` workspace.

This crate re-exports the user-facing ML-KEM and ML-DSA APIs from the implementation crates:

* `mlrust::kem` for ML-KEM key encapsulation;
* `mlrust::dsa` for ML-DSA digital signatures.

The crate is intended as the main application-facing entry point.

## Status

This project is under active development.

The implementation is correctness- and conformance-oriented, with explicit tests for deterministic roundtrips, malformed inputs, known vector coverage, feature-gated randomness, and selected side-channel-sensitive operations.

It should not be described as formally audited, formally verified, masked, or fully hardened against local physical side-channel attacks.

## Features

Default features enable:

* `std`;
* OS randomness through `getrandom`.

The caller-provided RBG APIs are available without OS randomness.

```toml
[dependencies]
mlrust = { path = "crates/mlrust" }
```

For `no_std` / caller-provided randomness use:

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

## Security notes

Secret-bearing types zeroize their contents on drop where applicable.

Secret keys, decapsulation keys, and shared secrets should be treated as sensitive material. Borrow their serialized representation with `as_bytes()`. If the bytes are copied elsewhere, the caller is responsible for protecting and clearing that copy.

ML-KEM decapsulation is infallible at the public API level. Invalid ciphertexts are handled through the ML-KEM implicit-rejection path.

ML-DSA verification returns `Ok(false)` for well-formed but cryptographically invalid signatures. Malformed encodings and invalid contexts are reported as errors.

## Testing

See the workspace-level `TESTING.md` for the testing policy, default checks, and long conformance tests.
