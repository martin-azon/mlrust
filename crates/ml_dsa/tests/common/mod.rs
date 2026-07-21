pub fn decode_hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);

    let mut out = [0u8; 32];

    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[2 * i]);
        let lo = hex_nibble(hex.as_bytes()[2 * i + 1]);

        *byte = (hi << 4) | lo;
    }

    out
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

pub fn expected_hash(vectors: &str, iterations: usize) -> [u8; 32] {
    for line in vectors.lines() {
        let line = line.split('#').next().unwrap_or("").trim();

        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();

        let Some(iterations_text) = parts.next() else {
            continue;
        };

        let parsed_iterations = iterations_text
            .parse::<usize>()
            .expect("valid CCTV iteration count");

        let hash = parts.next().expect("CCTV hash");

        if parsed_iterations == iterations {
            return decode_hex_32(hash);
        }
    }

    panic!("missing CCTV vector for {iterations} iterations");
}

use mlrust_core::sampling::random::{RandomByteGenerator, RandomError};

/// Deterministic random byte generator that returns caller-provided chunks.
pub struct FixedChunksRbg<'a> {
    chunks: &'a [&'a [u8]],
    index: usize,
}

impl<'a> FixedChunksRbg<'a> {
    /// Creates a deterministic random byte generator from fixed chunks.
    pub fn new(chunks: &'a [&'a [u8]]) -> Self {
        Self { chunks, index: 0 }
    }
}

impl RandomByteGenerator for FixedChunksRbg<'_> {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        let chunk = self
            .chunks
            .get(self.index)
            .ok_or(RandomError::GeneratorFailure)?;

        if chunk.len() != output.len() {
            return Err(RandomError::GeneratorFailure);
        }

        output.copy_from_slice(chunk);
        self.index += 1;

        Ok(())
    }
}

/// Random byte generator that always fails.
pub struct FailingRbg;

impl RandomByteGenerator for FailingRbg {
    fn fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError::GeneratorFailure)
    }
}
