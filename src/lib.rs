pub struct ChaCha20 {
    state: [u32; 16],
    copy: [u32; 16],
}

impl ChaCha20 {
    #[rustfmt::skip]
    pub fn new(key: &[u32; 8], nonce: &[u32; 3]) -> ChaCha20 {
        ChaCha20 {
            state: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                key[0],     key[1],     key[2],     key[3],
                key[4],     key[5],     key[6],     key[7],
                0,          nonce[0],   nonce[1],   nonce[2],
            ],
            copy: [0u32; 16],
        }
    }

    pub fn next(&mut self, input: &[u32; 16], output: &mut [u32; 16]) {
        self.state[12] += 1;
        self.copy.copy_from_slice(&self.state);
        for _ in 0..10 {
            // TODO: 8 qround calls
        }
        for i in 0..16 {
            self.copy[i] += self.state[i];
        }
        for i in 0..16 {
            output[i] = input[i] ^ self.state[i];
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ChaCha20;

    #[test]
    fn test_chacha20_enc() {
        let mut chacha20 = ChaCha20::new(&[0u32; 8], &[0u32; 3]);
        let input = [12u32; 16];
        let mut output = [0u32; 16];
        chacha20.next(&input, &mut output);
        // of course this test makes no sense
        // TODO: make a proper test
        assert_ne!(input, output);
    }
}
