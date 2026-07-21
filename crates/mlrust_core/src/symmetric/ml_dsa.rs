//! ML-DSA symmetric primitives.
//!
//! This module provides the XOF-style wrappers used by ML-DSA.

use crate::symmetric::generic_funcs::{
    shake128, shake128_absorb, shake128_absorb_once, shake128_finalize, shake128_init,
    shake128_squeeze, shake256, shake256_absorb, shake256_absorb_once, shake256_finalize,
    shake256_init, shake256_squeeze,
};

pub use super::generic_funcs::{Shake128Reader, Shake128State, Shake256Reader, Shake256State};

/// ML-DSA XOF function `H`.
///
/// Computes SHAKE256.
pub fn h(input: &[u8], output: &mut [u8]) {
    shake256(input, output)
}

/// ML-DSA `H.Init`.
#[must_use]
pub fn h_init() -> Shake256State {
    shake256_init()
}

/// ML-DSA `H.Absorb`.
pub fn h_absorb(state: &mut Shake256State, input: &[u8]) {
    shake256_absorb(state, input);
}

/// ML-DSA `H.Finalize`.
#[must_use]
pub fn h_finalize(state: Shake256State) -> Shake256Reader {
    shake256_finalize(state)
}

/// ML-DSA `H.Absorb` convenience helper for one input.
#[must_use]
pub fn h_absorb_once(input: &[u8]) -> Shake256Reader {
    shake256_absorb_once(input)
}

/// ML-DSA `H.Squeeze`.
pub fn h_squeeze(reader: &mut Shake256Reader, output: &mut [u8]) {
    shake256_squeeze(reader, output);
}

/// ML-DSA XOF function `G`.
///
/// Computes SHAKE128.
pub fn g(input: &[u8], output: &mut [u8]) {
    shake128(input, output);
}

/// ML-DSA `G.Init`.
#[must_use]
pub fn g_init() -> Shake128State {
    shake128_init()
}

/// ML-DSA `G.Absorb`.
pub fn g_absorb(state: &mut Shake128State, input: &[u8]) {
    shake128_absorb(state, input);
}

/// ML-DSA `G.Finalize`.
#[must_use]
pub fn g_finalize(state: Shake128State) -> Shake128Reader {
    shake128_finalize(state)
}

/// ML-DSA `G.Absorb` convenience helper for one input.
#[must_use]
pub fn g_absorb_once(input: &[u8]) -> Shake128Reader {
    shake128_absorb_once(input)
}

/// ML-DSA `G.Squeeze`.
pub fn g_squeeze(reader: &mut Shake128Reader, output: &mut [u8]) {
    shake128_squeeze(reader, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::generic_funcs::{shake128, shake256};

    #[test]
    fn h_matches_shake256() {
        let input = b"ML-DSA H test input";

        let mut got = [0u8; 64];
        let mut expected = [0u8; 64];

        h(input, &mut got);
        shake256(input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn g_matches_shake128() {
        let input = b"ML-DSA G test input";

        let mut got = [0u8; 64];
        let mut expected = [0u8; 64];

        g(input, &mut got);
        shake128(input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn h_absorb_squeeze_matches_shake256_one_shot() {
        let input = b"ML-DSA H streaming input";

        let mut got = [0u8; 96];

        let mut reader = h_absorb_once(input);
        h_squeeze(&mut reader, &mut got);

        let mut expected = [0u8; 96];
        shake256(input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn h_multiple_squeezes_match_single_shake256_output() {
        let input = b"ML-DSA H multiple squeeze input";

        let mut expected = [0u8; 80];
        shake256(input, &mut expected);

        let mut reader = h_absorb_once(input);

        let mut first = [0u8; 16];
        let mut second = [0u8; 64];

        h_squeeze(&mut reader, &mut first);
        h_squeeze(&mut reader, &mut second);

        assert_eq!(&first, &expected[..16]);
        assert_eq!(&second, &expected[16..]);
    }

    #[test]
    fn g_absorb_squeeze_matches_shake128_one_shot() {
        let input = b"ML-DSA G streaming input";

        let mut got = [0u8; 96];

        let mut reader = g_absorb_once(input);
        g_squeeze(&mut reader, &mut got);

        let mut expected = [0u8; 96];
        shake128(input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn g_multiple_squeezes_match_single_shake128_output() {
        let input = b"ML-DSA G multiple squeeze input";

        let mut expected = [0u8; 80];
        shake128(input, &mut expected);

        let mut reader = g_absorb_once(input);

        let mut first = [0u8; 16];
        let mut second = [0u8; 64];

        g_squeeze(&mut reader, &mut first);
        g_squeeze(&mut reader, &mut second);

        assert_eq!(&first, &expected[..16]);
        assert_eq!(&second, &expected[16..]);
    }

    #[test]
    fn h_and_g_use_different_xofs() {
        let input = b"same ML-DSA input";

        let mut h_out = [0u8; 64];
        let mut g_out = [0u8; 64];

        h(input, &mut h_out);
        g(input, &mut g_out);

        assert_ne!(h_out, g_out);
    }

    #[test]
    fn h_outputs_respect_requested_length() {
        let input = b"same ML-DSA H input";

        let mut short = [0u8; 16];
        let mut long = [0u8; 64];

        h(input, &mut short);
        h(input, &mut long);

        assert_eq!(&short, &long[..16]);
    }

    #[test]
    fn g_outputs_respect_requested_length() {
        let input = b"same ML-DSA G input";

        let mut short = [0u8; 16];
        let mut long = [0u8; 64];

        g(input, &mut short);
        g(input, &mut long);

        assert_eq!(&short, &long[..16]);
    }

    #[test]
    fn different_h_inputs_give_different_outputs() {
        let mut out0 = [0u8; 64];
        let mut out1 = [0u8; 64];

        h(b"input A", &mut out0);
        h(b"input B", &mut out1);

        assert_ne!(out0, out1);
    }

    #[test]
    fn different_g_inputs_give_different_outputs() {
        let mut out0 = [0u8; 64];
        let mut out1 = [0u8; 64];

        g(b"input A", &mut out0);
        g(b"input B", &mut out1);

        assert_ne!(out0, out1);
    }

    #[test]
    fn h_multiple_absorbs_match_one_shot_concatenation() {
        let a = b"tr";
        let b = b"formatted message";

        let mut input = Vec::new();
        input.extend_from_slice(a);
        input.extend_from_slice(b);

        let mut expected = [0u8; 64];
        h(&input, &mut expected);

        let mut state = h_init();
        h_absorb(&mut state, a);
        h_absorb(&mut state, b);

        let mut reader = h_finalize(state);

        let mut got = [0u8; 64];
        h_squeeze(&mut reader, &mut got);

        assert_eq!(got, expected);
    }
}
