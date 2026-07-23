# Security Policy

## Status

`mlrust` is under active development.

The implementation is correctness- and conformance-oriented, but it has not been independently audited, formally verified, or proven secure against all relevant implementation-level attacks.

Do not use this project as the sole basis for production cryptographic security without an appropriate review, threat model, and deployment-specific side-channel assessment.

## Supported Versions

Security fixes are currently provided for the latest development version only.

Once versioned releases are published, this section will be updated to describe which release branches receive security fixes.

## Reporting a Vulnerability

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Please report vulnerabilities using GitHub’s private vulnerability reporting feature for this repository.

If private vulnerability reporting is unavailable, please contact the repository maintainer, `@martin-azon`.

## Security Scope

The following issues are in scope:

* incorrect ML-KEM shared-secret agreement;
* incorrect ML-KEM implicit rejection behavior;
* incorrect ML-DSA signing or verification behavior;
* acceptance of malformed encodings where rejection is required;
* rejection of valid encodings where acceptance is required;
* secret-dependent branches, memory accesses, or divisions in sensitive paths;
* missing zeroization for public secret-bearing types;
* panics or denial-of-service behavior on malformed public inputs.

The following are not currently claimed as implemented security properties:

* formal verification;
* masking;
* fixed-time ML-DSA signing;
* resistance to all local timing, cache, power, or electromagnetic side channels;
* resistance to fault-injection attacks;
* resistance to compiler, microarchitectural, or platform-specific leakage outside the implementation’s control.

## Side-Channel Statement

The implementation includes selected side-channel-conscious choices, including no `unsafe` code, zeroization for first-pass secret-bearing public types, division-free ML-KEM compression, and constant-time helper functions in selected paths.

These measures do not make the project a fully hardened cryptographic implementation.

## Cryptographic Review

This project has not received an independent cryptographic audit.

Users considering production use should arrange an independent review of:

* arithmetic and NTT implementations;
* sampling and rejection-sampling behavior;
* encoding and decoding routines;
* ML-KEM decapsulation and implicit rejection;
* ML-DSA signing and verification;
* randomness integration;
* zeroization and secret handling;
* side-channel behavior on the target platform.
