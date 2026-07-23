## `crates/mlrust_core/README.md`

# mlrust_core

Shared implementation primitives for the `mlrust` workspace.

This crate contains common functionality used by the ML-KEM and ML-DSA implementation crates.

It is primarily an internal support crate, but selected traits and utilities are part of the workspace’s public API surface. In particular, the random byte generator abstraction is used by the `*_with_rbg` APIs in the protocol crates.

## Contents

The crate includes:

* finite-field parameter definitions;
* polynomial and polynomial-vector types;
* NTT routines;
* byte encoding and bit-packing helpers;
* ML-KEM and ML-DSA sampling helpers;
* symmetric SHAKE-based helper functions;
* constant-time utility functions;
* random byte generation traits and adapters.

## Status

This crate is under active development.

It is designed to support the ML-KEM and ML-DSA crates in this workspace. It is not intended as a general-purpose cryptographic arithmetic library.

## Features

Default features enable:

* `std`;
* OS randomness through `getrandom`.

The core random byte generator trait is available without OS randomness.

```toml
[dependencies]
mlrust_core = { path = "../mlrust_core" }
```

For `no_std` use:

```toml
[dependencies]
mlrust_core = { path = "../mlrust_core", default-features = false }
```

## Random byte generation

The central trait is:

```rust
use mlrust_core::sampling::random::{
    RandomByteGenerator,
    RandomError,
};

struct ExampleRbg;

impl RandomByteGenerator for ExampleRbg {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        output.fill(0x42);
        Ok(())
    }
}
```

The example above is not cryptographically secure. Real deployments must use a cryptographically secure random byte generator.

When the `getrandom` feature is enabled, the crate also provides an OS-random adapter.

## Constant-time helpers

The `ct` module contains small wrappers used to avoid selected secret-dependent branches in higher-level ML-KEM and ML-DSA code.

These helpers are implementation building blocks. They do not by themselves make the full protocol implementations masked, fixed-time, or formally verified against physical side-channel attacks.

## Testing

This crate contains unit tests for field arithmetic, NTTs, polynomial operations, encodings, sampling, symmetric helpers, and constant-time utility behavior.

See the workspace-level `TESTING.md` for the testing policy.

