## `crates/ml_dsa/README.md`

# ml_dsa

ML-DSA implementation crate for the `mlrust` workspace.

This crate provides the implementation and public API for the three ML-DSA parameter sets:

* ML-DSA-44;
* ML-DSA-65;
* ML-DSA-87.

The implementation currently exposes pure ML-DSA. HashML-DSA is not exposed as the default signing API.

## Status

This crate is under active development.

The implementation is correctness- and conformance-oriented. It includes public API roundtrip tests, malformed-input tests, RBG failure and consumption tests, deterministic signing tests, and accumulated CCTV conformance tests marked ignored by default.

It should not be described as formally audited, formally verified, masked, or fully hardened against local physical side-channel attacks.

## Features

Default features enable:

* `std`;
* OS randomness through `getrandom`.

The caller-provided RBG APIs are available without OS randomness.

```toml
[dependencies]
ml_dsa = { path = "../ml_dsa" }
```

For `no_std` / caller-provided randomness use:

```toml
[dependencies]
ml_dsa = { path = "../ml_dsa", default-features = false }
```

## Example: ML-DSA-44 with OS randomness

```rust
use ml_dsa::{
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

## Example: caller-provided randomness

```rust
use ml_dsa::{
    ml_dsa44_keygen_with_rbg,
    ml_dsa44_sign_with_rbg,
    ml_dsa44_verify,
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
    let message = b"example message";
    let context = b"example context";

    let mut rbg = ExampleRbg { byte: 1 };

    let keypair =
        ml_dsa44_keygen_with_rbg(&mut rbg)
            .expect("key generation succeeds");

    let signature =
        ml_dsa44_sign_with_rbg(
            keypair.secret_key(),
            message,
            context,
            &mut rbg,
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

The `ExampleRbg` above is only for API illustration. Real deployments must use a cryptographically secure random byte generator.

## Message and context handling

Signing and verification accept:

* an application message;
* a context byte string.

The context length must fit in one byte. Contexts longer than 255 bytes are rejected.

The pure ML-DSA message formatting is performed internally.

## Public types

The public serialized wrapper types include:

* public keys;
* secret keys;
* signatures;
* keypairs.

Secret keys contain secret material and zeroize their contents on drop. Public keys and signatures are public data.

## Error behavior

Signing can fail if:

* the random byte generator fails;
* the context is longer than 255 bytes;
* the secret key is malformed.

Verification returns:

* `Ok(true)` for a valid signature;
* `Ok(false)` for a well-formed but cryptographically invalid signature;
* an error for malformed public keys, malformed signatures, or invalid contexts.

## Side-channel notes

This crate uses constant-time helpers for selected secret-dependent comparisons and validates secret-key coefficient ranges without early return on the first malformed coefficient.

ML-DSA signing uses a rejection-sampling loop. The number of signing attempts is data-dependent. This implementation is not masked, fixed-time, or formally verified against local timing, cache, power, or EM attacks.

## Testing

Default tests cover public API behavior, error paths, deterministic signing behavior, internal primitive behavior, and boundary cases.

Long accumulated CCTV conformance tests are marked ignored by default. See the workspace-level `TESTING.md`.
