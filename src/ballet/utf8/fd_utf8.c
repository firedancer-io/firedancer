#include "fd_utf8.h"

static uchar const fd_utf8_dfa[ 256 + 9*16 ] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3,
  0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,
  0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,
  1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,
  1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1,
  1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
};

#if defined(__AVX512BW__)
#include "../../util/simd/fd_avx512.h"

/* AVX512 UTF-8 validator based on https://arxiv.org/pdf/2010.03090
   "Validating UTF-8 In Less Than One Instruction Per Byte"  */

static inline wwb_t
prev_carry( wwb_t cur,
            wwb_t prev ) {
  wwb_t idx = _mm512_set_epi64( 5, 4, 3, 2, 1, 0, 15, 14 );
  return _mm512_permutex2var_epi64( cur, idx, prev );
}

static inline wwb_t
prev1_byte( wwb_t cur,
            wwb_t prev ) {
  return _mm512_alignr_epi8( cur, prev_carry( cur, prev ), 15 );
}

static inline wwb_t
prev2_byte( wwb_t cur,
            wwb_t prev ) {
  return _mm512_alignr_epi8( cur, prev_carry( cur, prev ), 14 );
}

static inline wwb_t
prev3_byte( wwb_t cur,
            wwb_t prev ) {
  return _mm512_alignr_epi8( cur, prev_carry( cur, prev ), 13 );
}

/* Check for special-case invalid byte sequences.  These arise from
   overlong encodings, surrogates, and codepoints > U+10FFFF.

   After certain lead bytes, the valid range of the next byte is
   restricted:
    E0 xx: second byte must be in [A0,BF] (not [80,9F] -> overlong)
    ED xx: second byte must be in [80,9F] (not [A0,BF] -> surrogates)
    F0 xx: second byte must be in [90,BF] (not [80,8F] -> overlong)
    F4 xx: second byte must be in [80,8F] (not [90,BF] -> out of range) */
static inline wwb_t
check_special( wwb_t cur,
               wwb_t prev ) {
  wwb_t prev_hi  = wwb_shr( prev, 4 );
  wwb_t prev_lo  = wwb_and( prev, wwb_bcast( 0x0F ) );
  wwb_t cur_hi   = wwb_shr( cur,  4 );

  /* High nibble of prev: which category of checks apply.
     nibble E -> bits 0,1 (overlong-3 / surrogate checks)
     nibble F -> bits 2,3 (overlong-4 / too-large checks) */
  wwb_t hi_lut = wwb_bcast_hex( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0C );

  /* Low nibble of prev: which specific byte within the category.
     0x0     -> bits 0,2   (E0 overlong-3, F0 overlong-4)
     0x4     -> bit  3     (F4 too-large)
     0x5-0xC -> bits 2,3   (F5-FC: entirely invalid, catch all conts)
     0xD     -> bits 1,2,3 (ED surrogate; FD entirely invalid)
     0xE-0xF -> bits 2,3   (FE-FF: entirely invalid)
     The E-nibble category uses bits 0,1 so the bits 2,3 entries for
     F5-FF do not interfere with E5-EF (0x03 & 0x0C == 0). */
  wwb_t lo_lut = wwb_bcast_hex( 0x05, 0x00, 0x00, 0x00, 0x08, 0x0C, 0x0C, 0x0C,
                                0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0E, 0x0C, 0x0C );

  /* High nibble of cur: which continuation byte ranges are bad.
     nibble 8 -> bits 0,2   (80..8F: bad after E0 and F0)
     nibble 9 -> bits 0,3   (90..9F: bad after E0 and F4+)
     nibble A -> bits 1,3   (A0..AF: bad after ED and F4+)
     nibble B -> bits 1,3   (B0..BF: bad after ED and F4+) */
  wwb_t cur_lut = wwb_bcast_hex( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x05, 0x09, 0x0A, 0x0A, 0x00, 0x00, 0x00, 0x00 );

  wwb_t r1 = _mm512_shuffle_epi8( hi_lut,  prev_hi );
  wwb_t r2 = _mm512_shuffle_epi8( lo_lut,  prev_lo );
  wwb_t r3 = _mm512_shuffle_epi8( cur_lut, cur_hi  );
  return _mm512_ternarylogic_epi64( r1, r2, r3, 0x80 ); /* r1 & r2 & r3 */
}

/* A 2-byte lead (110xxxxx, C2..DF) must be followed by 1 continuation.
   A 3-byte lead (1110xxxx, E0..EF) must be followed by 2 continuations.
   A 4-byte lead (11110xxx, F0..F4) must be followed by 3 continuations. */
static inline wwb_t
check_continuations( wwb_t cur,
                     wwb_t prev ) {
  wwb_t p1 = prev1_byte( cur, prev );
  wwb_t p2 = prev2_byte( cur, prev );
  wwb_t p3 = prev3_byte( cur, prev );

  /* 2+ byte lead: byte >= C2 (C0,C1 are overlong, never valid)
     3+ byte lead: byte >= E0
     4  byte lead: byte >= F0 (only F0..F4 valid, but DFA handles that) */
  wwb_t is_2_3_4_lead = wwb_subs( p1, wwb_bcast( 0xC1 ) );
  wwb_t is_3_4_lead   = wwb_subs( p2, wwb_bcast( 0xDF ) );
  wwb_t is_4_lead     = wwb_subs( p3, wwb_bcast( 0xEF ) );

  /* OR all together */
  wwb_t must_be_cont = _mm512_ternarylogic_epi64( is_2_3_4_lead,
                                                    is_3_4_lead,
                                                      is_4_lead, 0xFE );

  /* is_cont = sub(byte ^ 0x80, 0x3F). 0 means IS continuation, otherwise NOT. */
  wwb_t xor     = wwb_xor( cur, wwb_bcast( 0x80 ) );
  wwb_t is_cont = wwb_subs( xor, wwb_bcast( 0x3F ) );

  ulong must_mask = wwb_ne( must_be_cont, wwb_zero() );
  ulong cont_mask = wwb_eq( is_cont,      wwb_zero() );
  return _mm512_movm_epi8( must_mask ^ cont_mask );
}

FD_FN_PURE int
fd_utf8_verify( char const * str,
                ulong        sz ) {

  uchar const * cur = (uchar const *)str;
  if( FD_UNLIKELY( cur==NULL ) ) return !sz;
  uchar const * const end = cur + sz;

  wwb_t prev_chunk = wwb_zero();
  wwb_t error      = wwb_zero();

  while( cur+64<=end ) { /* While we have a zmm register of unicode left. */
    wwb_t chunk = wwb_ldu( cur );

    /* Fast path, we've loaded an entire chunk of ASCII */
    if( FD_LIKELY( !_mm512_test_epi8_mask( chunk, wwb_bcast( 0x80 ) ) ) ) {
      /* Make sure we aren't mid-sequence from the previous chunk.
         If prev_chunk ended with a lead byte (>= C2), that's an error
         because the expected continuations landed in this all-ASCII chunk.

         check_continuations() would have caught this, but we skip it on
         the fast path, so check if any byte in prev_chunk's last 3
         positions is a lead byte. */
      wwb_t p1 = prev1_byte( chunk, prev_chunk );
      wwb_t p2 = prev2_byte( chunk, prev_chunk );
      wwb_t p3 = prev3_byte( chunk, prev_chunk );

      error = wwb_or( error, wwb_subs( p1, wwb_bcast( 0xC1 ) ) );
      error = wwb_or( error, wwb_subs( p2, wwb_bcast( 0xDF ) ) );
      error = wwb_or( error, wwb_subs( p3, wwb_bcast( 0xEF ) ) );

      prev_chunk = chunk;
      cur += 64;
      continue;
    }

    error = wwb_or( error, check_special( chunk, prev1_byte( chunk, prev_chunk ) ) );
    error = wwb_or( error, check_continuations( chunk, prev_chunk ) );
    /* C0 and C1 are not valid in any context (overlong 2-byte leads).
       check_continuations skips them (threshold 0xC2), so detect them
       explicitly. (byte & 0xFE) == 0xC0 matches exactly C0 and C1. */
    error = wwb_or( error, _mm512_movm_epi8(
        wwb_eq( wwb_and( chunk, wwb_bcast( 0xFE ) ), wwb_bcast( 0xC0 ) ) ) );
    prev_chunk = chunk;
    cur += 64;
  }

  if( cur >= end ) {
    /* No tail bytes remain, so we check for an incomplete sequence at
       the end of the last chunk. We simply ignore all bytes other than
       the 4/3/2-byte leads. */
    wwb_t max_val = wwb(
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      (char)0xEF, (char)0xDF, (char)0xBF );
    error = wwb_or( error, wwb_subs( prev_chunk, max_val ) );
  }

  if( FD_UNLIKELY( _mm512_test_epi8_mask( error, error ) ) ) return 0;

  if( cur < end ) {
    /* There are still tail bytes left, which could contain an
       incomplete multi-byte sequence from the end of the last SIMD
       chunk. We need to backup the current pointer so that the DFA
       will re-validate, starting from a known valid point. */
    uchar const * base = (uchar const *)str;
    if( cur > base ) {
      if(      cur[-1] >= 0xC0U )
        cur -= 1;
      else if( cur[-1] >= 0x80U && cur > base+1 && cur[-2] >= 0xE0U )
        cur -= 2;
      else if( cur[-1] >= 0x80U && cur > base+2 &&
               cur[-2] >= 0x80U && cur[-3] >= 0xF0U )
        cur -= 3;
    }
    uint state = 0;
    while( cur<end ) {
      uint type = fd_utf8_dfa[ *cur++ ];
      state = fd_utf8_dfa[ 256 + state*16 + type ];
    }
    if( state!=0 ) return 0;
  }

  return 1;
}

#else

FD_FN_PURE int
fd_utf8_verify( char const * str,
                ulong        sz ) {

  uchar const * cur = (uchar const *)str;
  if( FD_UNLIKELY( cur==NULL ) ) return !sz;
  uchar const * const end = cur + sz;

  uint state = 0;
  while( cur<end ) {
    uint type = fd_utf8_dfa[ *cur++ ];
    state = fd_utf8_dfa[ 256 + state*16 + type ];
  }
  return state == 0;
}

#endif /* defined(__AVX512BW__) */
