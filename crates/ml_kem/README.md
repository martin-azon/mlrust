## `crates/ml_kem/README.md`

# ml_kem

ML-KEM implementation crate for the `mlrust` workspace.

This crate provides the implementation and public API for the three ML-KEM parameter sets:

* ML-KEM-512;
* ML-KEM-768;
* ML-KEM-1024.

The public API exposes key generation, encapsulation, and decapsulation using fixed-size serialized wrapper types.

## Status

This crate is under active development.

The implementation is correctness- and conformance-oriented. It includes public API roundtrip tests, malformed-input tests, RBG failure and consumption tests, intermediate CCTV vector tests, and long legacy accumulated-vector tests marked ignored by default.

It should not be described as formally audited, formally verified, masked, or fully hardened against local physical side-channel attacks.

## Features

Default features enable:

* `std`;
* OS randomness through `getrandom`.

The caller-provided RBG APIs are available without OS randomness.

```toml
[dependencies]
ml_kem = { path = "../ml_kem" }
```

For `no_std` / caller-provided randomness use:

```toml
[dependencies]
ml_kem = { path = "../ml_kem", default-features = false }
```

## Example: ML-KEM-512 with OS randomness

```rust
use ml_kem::{
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

## Example: caller-provided randomness

```rust
use ml_kem::{
    ml_kem512_decaps,
    ml_kem512_encaps_with_rbg,
    ml_kem512_keygen_with_rbg,
};
use mlrust_core::sampling::random::{
    RandomByteGenerator,
    RandomError,
};

struct ExampleRbg {
    byte: u8,
}

impl RandomByteGenerator for ExampleRbg {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        output.fill(self.byte);
        self.byte = self.byte.wrapping_add(1);
        Ok(())
    }
}

fn main() {
    let mut rbg = ExampleRbg { byte: 1 };

    let keypair =
        ml_kem512_keygen_with_rbg(&mut rbg)
            .expect("key generation succeeds");

    let (shared_secret_sender, ciphertext) =
        ml_kem512_encaps_with_rbg(
            keypair.encapsulation_key(),
            &mut rbg,
        )
        .expect("encapsulation succeeds");

    let shared_secret_receiver =
        ml_kem512_decaps(keypair.decapsulation_key(), &ciphertext);

    assert_eq!(
        shared_secret_sender.as_bytes(),
        shared_secret_receiver.as_bytes(),
    );
}
```

The `ExampleRbg` above is only for API illustration. Real deployments must use a cryptographically secure random byte generator.

## Public types

The public serialized wrapper types include:

* encapsulation keys;
* decapsulation keys;
* ciphertexts;
* shared secrets;
* keypairs.

Decapsulation keys and shared secrets contain secret material and zeroize their contents on drop.

## Error behavior

Key generation and encapsulation can fail if the random byte generator fails.

Decapsulation does not return an error. Invalid ciphertexts are handled through implicit rejection and produce a deterministic fallback shared secret.

## Side-channel notes

This crate avoids secret-dependent division in ML-KEM compression and uses constant-time byte comparison and selection in the implicit-rejection path.

This does not make the implementation a masked or formally verified side-channel-hardened implementation.

## Testing

Default tests cover public API behavior, error paths, internal K-PKE/ML-KEM intermediate vectors, and boundary cases.

Long legacy accumulated-vector tests are marked ignored by default. See the workspace-level `TESTING.md`.