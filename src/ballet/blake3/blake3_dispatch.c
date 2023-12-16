// Source originally from https://github.com/BLAKE3-team/BLAKE3
// From commit: 64747d48ffe9d1fbf4b71e94cabeb8a211461081

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blake3_impl.h"

#if defined(IS_X86)
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__)
#include <immintrin.h>
#else
#undef IS_X86 /* Unimplemented! */
#endif
#endif

#define BLAKE3_NO_AVX512
#define BLAKE3_NO_SSE41
#define BLAKE3_NO_SSE2

#define MAYBE_UNUSED(x) (void)((x))

void blake3_compress_in_place(uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags) {
  /* TODO: bring in AVX512/SSE41/SSE2 variants */
  blake3_compress_in_place_portable(cv, block, block_len, counter, flags);
}

void blake3_compress_xof(const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64]) {
  /* TODO: bring in AVX512/SSE41/SSE2 variants */
  blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
}

void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t *out) {

  /* TODO: bring in AVX512/SSE41/SSE2/NEON variants */
#if FD_HAS_AVX
  blake3_hash_many_avx2(inputs, num_inputs, blocks, key, counter,
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
#if FD_HAS_AVX
  return 8;
#else
  return 1;
#endif
}
