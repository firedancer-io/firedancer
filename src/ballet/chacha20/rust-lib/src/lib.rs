use rand::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

#[no_mangle]
pub extern "C" fn fd_chacha20_ffi_random_number(key: &[u8; 32], random_number_buffer: &mut u32) {
    // Create the RNG with the seed (key), nonce is provided internally as &[0u8; 8]
    let mut rng: ChaCha20Rng = ChaCha20Rng::from_seed(*key);
    // Generate a random number
    *random_number_buffer = rng.gen();

    // Print algorithm params
    let stream = rng.get_stream();
    let counter = rng.get_word_pos();
    let seed = rng.get_seed();

    println!("-- Rust ChaCha20 params --");
    println!("stream (nonce): {}", stream);
    println!("word_pos (counter): {}", counter);
    println!("seed (key): {:?}", seed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector (key)
    const TEST_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const EXPECTED_RANDOM_NUMBER: u32 = 2100034873;

    #[test]
    fn test_fd_chacha20_generate_random_number() {
        let mut result: u32 = 0;

        fd_chacha20_ffi_random_number(&TEST_KEY, &mut result);
        assert_eq!(result, EXPECTED_RANDOM_NUMBER);
    }
}
