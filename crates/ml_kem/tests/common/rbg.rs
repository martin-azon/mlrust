use mlrust_core::sampling::random::{RandomByteGenerator, RandomError};

pub struct FixedChunksRbg<'a> {
    chunks: &'a [&'a [u8]],
    index: usize,
}

impl<'a> FixedChunksRbg<'a> {
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

pub struct FailingRbg;

impl RandomByteGenerator for FailingRbg {
    fn fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError::GeneratorFailure)
    }
}
