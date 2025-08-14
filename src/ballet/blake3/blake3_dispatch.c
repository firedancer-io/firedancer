// Source originally from https://github.com/BLAKE3-team/BLAKE3
// From commit: 34d293eb2aa75005406d8a7d78687896f714e89a

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blake3_impl.h"

#include <immintrin.h>

#define MAYBE_UNUSED(x) (void)((x))

void blake3_compress_in_place(uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags) {
#if FD_HAS_AVX512
  blake3_compress_in_place_avx512(cv, block, block_len, counter, flags);
#elif FD_HAS_AVX
  blake3_compress_in_place_sse41(cv, block, block_len, counter, flags);
#elif FD_HAS_SSE
  blake3_compress_in_place_sse2(cv, block, block_len, counter, flags);
#else
  blake3_compress_in_place_portable(cv, block, block_len, counter, flags);
#endif
}

void blake3_compress_xof(const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64]) {
#if FD_HAS_AVX512
  blake3_compress_xof_avx512(cv, block, block_len, counter, flags, out);
#elif FD_HAS_AVX
  blake3_compress_xof_sse41(cv, block, block_len, counter, flags, out);
#elif FD_HAS_SSE
  blake3_compress_xof_sse2(cv, block, block_len, counter, flags, out);
#else
  blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
#endif
}


void blake3_xof_many(const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint8_t block_len, uint64_t counter, uint8_t flags,
                     uint8_t out[64], size_t outblocks) {
  if (outblocks == 0) {
    // The current assembly implementation always outputs at least 1 block.
    return;
  }
#if FD_HAS_AVX512
  blake3_xof_many_avx512(cv, block, block_len, counter, flags, out, outblocks);
#else
  for(size_t i = 0; i < outblocks; ++i) {
    blake3_compress_xof(cv, block, block_len, counter + i, flags, out + 64*i);
  }
#endif
}

void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t *out) {
#if FD_HAS_AVX512
  blake3_hash_many_avx512(inputs, num_inputs, blocks, key, counter,
                          increment_counter, flags, flags_start, flags_end,
                          out);
#elif FD_HAS_AVX
  blake3_hash_many_avx2(inputs, num_inputs, blocks, key, counter,
                        increment_counter, flags, flags_start, flags_end,
                        out);
#elif FD_HAS_SSE
  /* TODO use sse4.1 here? */
  blake3_hash_many_sse2(inputs, num_inputs, blocks, key, counter,
                        increment_counter, flags, flags_start, flags_end,
                        out);
#else
  blake3_hash_many_portable(inputs, num_inputs, blocks, key, counter,
                            increment_counter, flags, flags_start, flags_end,
                            out);
#endif
}

// The dynamically detected SIMD degree of the current platform.
size_t blake3_simd_degree(void) {
#if FD_HAS_AVX512
  return 16;
#elif FD_HAS_AVX
  return 8;
#elif FD_HAS_SSE
  return 4;
#else
  return 1;
#endif
}
