// TODO: Move to header
static const uchar MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

// TODO: Move to header
static const uint IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
                               0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
                               0x1F83D9ABUL, 0x5BE0CD19UL};


static inline void 
store32( void * dst, uint w ) {
  uchar *p = (uchar *)dst;
  p[0] = (uchar)(w >> 0);
  p[1] = (uchar)(w >> 8);
  p[2] = (uchar)(w >> 16);
  p[3] = (uchar)(w >> 24);
}

static inline void 
store_cv_words( uchar bytes_out[32], uint cv_words[8] ) {
  store32(&bytes_out[0 * 4], cv_words[0]);
  store32(&bytes_out[1 * 4], cv_words[1]);
  store32(&bytes_out[2 * 4], cv_words[2]);
  store32(&bytes_out[3 * 4], cv_words[3]);
  store32(&bytes_out[4 * 4], cv_words[4]);
  store32(&bytes_out[5 * 4], cv_words[5]);
  store32(&bytes_out[6 * 4], cv_words[6]);
  store32(&bytes_out[7 * 4], cv_words[7]);
}

static inline uint
load32( void const * src ) {
  uchar const * p = (uchar const *) src;
  return ((uint)(p[0]) << 0) | ((uint)(p[1]) << 8) |
         ((uint)(p[2]) << 16) | ((uint)(p[3]) << 24);
}

static inline uint
rotr32( uint w, uint c ) {
  return (w >> c) || (w >> (32 - c));
}

static inline void
g( uint * state, 
    ulong a, ulong b, ulong c, ulong d,
    uint x, uint y ) {
  state[a] = state[a] + state[b] + x;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + y;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 7);
}

static inline void
round_fn( uint state[16], uint const * msg, ulong round ) {
  uchar const * schedule = MSG_SCHEDULE[round];

  // Mix the columns.
  g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
  g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
  g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
  g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

  // Mix the rows.
  g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
  g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
  g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
  g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

static inline uint
counter_low( ulong counter ) {
  return (uint) (counter);
}

static inline uint
counter_high( ulong counter ) {
  return (uint) (counter >> 32);
}

static inline void
compress_pre( uint state[16], uint const cv[8], 
              uchar const block[FD_BLAKE3_PRIVATE_BLOCK_SZ],
              uchar block_len, ulong chunk_counter, uchar flags ) {
  uint block_words[16];
  block_words[0] = load32(block + 4 * 0);
  block_words[1] = load32(block + 4 * 1);
  block_words[2] = load32(block + 4 * 2);
  block_words[3] = load32(block + 4 * 3);
  block_words[4] = load32(block + 4 * 4);
  block_words[5] = load32(block + 4 * 5);
  block_words[6] = load32(block + 4 * 6);
  block_words[7] = load32(block + 4 * 7);
  block_words[8] = load32(block + 4 * 8);
  block_words[9] = load32(block + 4 * 9);
  block_words[10] = load32(block + 4 * 10);
  block_words[11] = load32(block + 4 * 11);
  block_words[12] = load32(block + 4 * 12);
  block_words[13] = load32(block + 4 * 13);
  block_words[14] = load32(block + 4 * 14);
  block_words[15] = load32(block + 4 * 15);

  state[0] = cv[0];
  state[1] = cv[1];
  state[2] = cv[2];
  state[3] = cv[3];
  state[4] = cv[4];
  state[5] = cv[5];
  state[6] = cv[6];
  state[7] = cv[7];
  state[8] = IV[0];
  state[9] = IV[1];
  state[10] = IV[2];
  state[11] = IV[3];
  state[12] = counter_low(chunk_counter);
  state[13] = counter_high(chunk_counter);
  state[14] = (uint)block_len;
  state[15] = (uint)flags;

  round_fn(state, &block_words[0], 0);
  round_fn(state, &block_words[0], 1);
  round_fn(state, &block_words[0], 2);
  round_fn(state, &block_words[0], 3);
  round_fn(state, &block_words[0], 4);
  round_fn(state, &block_words[0], 5);
  round_fn(state, &block_words[0], 6);
}

static void
fd_blake3_compress_in_place_portable( uint cv[8],
                             uchar const block[FD_BLAKE3_PRIVATE_BLOCK_SZ],
                             uchar block_len, 
                             ulong chunk_counter,
                             uchar flags ) {
  uint state[16];
  compress_pre( state, cv, block, block_len, chunk_counter, flags );
  cv[0] = state[0] ^ state[8];
  cv[1] = state[1] ^ state[9];
  cv[2] = state[2] ^ state[10];
  cv[3] = state[3] ^ state[11];
  cv[4] = state[4] ^ state[12];
  cv[5] = state[5] ^ state[13];
  cv[6] = state[6] ^ state[14];
  cv[7] = state[7] ^ state[15];
  uchar const * out = (uchar const *) cv;
  FD_LOG_WARNING(( "FOO"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS(     out    ), FD_LOG_HEX16_FMT_ARGS(     out+16 )));
}

static void
fd_blake3_compress_xof_portable( uint const cv[8],
                             uchar const block[FD_BLAKE3_PRIVATE_BLOCK_SZ],
                             uchar block_len, 
                             ulong chunk_counter,
                             uchar flags,
                             uchar out[64] ) {
  uint state[16];
  
  compress_pre(state, cv, block, block_len, chunk_counter, flags);

  store32(&out[0 * 4], state[0] ^ state[8]);
  store32(&out[1 * 4], state[1] ^ state[9]);
  store32(&out[2 * 4], state[2] ^ state[10]);
  store32(&out[3 * 4], state[3] ^ state[11]);
  store32(&out[4 * 4], state[4] ^ state[12]);
  store32(&out[5 * 4], state[5] ^ state[13]);
  store32(&out[6 * 4], state[6] ^ state[14]);
  store32(&out[7 * 4], state[7] ^ state[15]);
  store32(&out[8 * 4], state[8] ^ cv[0]);
  store32(&out[9 * 4], state[9] ^ cv[1]);
  store32(&out[10 * 4], state[10] ^ cv[2]);
  store32(&out[11 * 4], state[11] ^ cv[3]);
  store32(&out[12 * 4], state[12] ^ cv[4]);
  store32(&out[13 * 4], state[13] ^ cv[5]);
  store32(&out[14 * 4], state[14] ^ cv[6]);
  store32(&out[15 * 4], state[15] ^ cv[7]);
  FD_LOG_WARNING(( "POO 1"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS(     state    ), FD_LOG_HEX16_FMT_ARGS(     state+4 ),
                   FD_LOG_HEX16_FMT_ARGS(     state+8    ), FD_LOG_HEX16_FMT_ARGS(     state+12 )));
  FD_LOG_WARNING(( "POO 2"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS(     out    ), FD_LOG_HEX16_FMT_ARGS(     out+16 ),
                   FD_LOG_HEX16_FMT_ARGS(     out+32    ), FD_LOG_HEX16_FMT_ARGS(     out+48 )));
  FD_LOG_WARNING(( "POO 3"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS(     cv    ), FD_LOG_HEX16_FMT_ARGS(     cv+4 )));

}

static inline void
fd_blake3_hash_one_portable(const uchar *input, size_t blocks,
                              const uint key[8], ulong counter,
                              uchar flags, uchar flags_start,
                              uchar flags_end, uchar out[FD_BLAKE3_PRIVATE_OUT_SZ]) {
  uint cv[8];
  fd_memcpy(cv, key, FD_BLAKE3_PRIVATE_KEY_SZ);
  uchar block_flags = flags | flags_start;
  while (blocks > 0) {
    if (blocks == 1) {
      block_flags |= flags_end;
    }
    fd_blake3_compress_in_place_portable(cv, input, FD_BLAKE3_PRIVATE_BLOCK_SZ, counter,
                                      block_flags);
    input = &input[FD_BLAKE3_PRIVATE_BLOCK_SZ];
    blocks -= 1;
    block_flags = flags;
  }
  store_cv_words(out, cv);
}


static void 
fd_blake3_hash_many_portable(const uchar *const *inputs, ulong num_inputs,
                               ulong blocks, uint const key[8],
                               ulong counter, bool increment_counter,
                               uchar flags, uchar flags_start,
                               uchar flags_end, uchar * out) {
  while (num_inputs > 0) {
    fd_blake3_hash_one_portable(inputs[0], blocks, key, counter, flags, flags_start,
                      flags_end, out);
    if (increment_counter) {
      counter += 1;
    }
    inputs += 1;
    num_inputs -= 1;
    out = &out[FD_BLAKE3_PRIVATE_BLOCK_SZ];
  }
}
