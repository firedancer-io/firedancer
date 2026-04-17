#include "../fd_ballet_base.h"
#include "../keccak256/fd_shake256.h"
#include "fd_falcon.h"

#define Q 12289
#define N 512
#define LOGN 9

#define LENGTH 16
#define STRIDE (LENGTH / 4) * 7
#define K (1 << 16) / Q  /* K <- ⌊2^16 / Q⌋, as defined by the paper. */

#include "fd_falcon_fq.h"

#define HEADER (uchar)0x39

static inline short FD_FN_UNUSED
bit( uchar const *s, ulong idx ) {
    return (s[idx >> 3] >> (7 - (idx & 7))) & 1;
}

/* Returns 0 for success, and -1 for invalid pubkey. */
int
fd_falcon_pubkey_parse( fd_falcon_pubkey_t * pubkey,
                        uchar const          input[ static FD_FALCON_PUBKEY_SIZE ] ) {
  /* The first byte is the header, encoded as
     0 0 0 0 n n n n
     where the leftmost 4 bits are 0, and nnnn encodes logn. */
  if( input[0] != LOGN ) return -1;

#if FD_HAS_AVX512
  wwu_t mask     = wwu_bcast( (1U<<14) - 1 );
  wwu_t Qv       = wwu_bcast( Q );
  wwu_t offsets  = wwu( 18,4,14,0, 18,4,14,0, 18,4,14,0, 18,4,14,0 );

  /* The rest of the bytes are the public key polynomial.
     Each value, in [0, Q), is encoded as a 14-bit integer.
     The encoded values are compressed into a bit sequence of 14 * N
     bits, or (14*N)/8 bytes.

     The least-common-multiple of 14 and 8 is 56, meaning the smallest
     number of elements we can extract in parallel is 56/14=4 elements. */
  uchar const * h = input+1UL;
  for( int i=0; i < N/LENGTH; i++ ) {
    uchar const    * in  = h + (i * STRIDE);
    fd_falcon_fq_t * out = pubkey->h + (i * LENGTH);

    /* We know that an element could never be in more than 3 bytes at
       a time. The worst case is that the first bit is at index 7
       of byte 0, takes up the entire byte 1, and the last few bits
       are in byte 2.

       We can effectively work around this by performing fast 32-bit
       loads, and simply reading an extra byte each time. The loads
       are indifferent to which byte is the unused one, and we can
       easily make up for it with a shift later on.

       We perform 4 movs to load words at in, in+3, in+7, in+10.
       Each pair of elements has the same offset, since the first
       element will not use the 4th byte, but the second element will.

       The vector will contain 8 compressed elements (end-exclusive ranges):
				1. 00..14 (bytes 0, 1)
				2. 14..28 (bytes 1, 2, 3)
				3. 28..42 (bytes 3, 4, 5)
				4. 42..56 (bytes 5, 6)
				... */
    wwu_t compressed = wwu(
      fd_uint_load_4_fast( in+0UL  ), fd_uint_load_4_fast( in+0UL  ),
      fd_uint_load_4_fast( in+3UL  ), fd_uint_load_4_fast( in+3UL  ),
      fd_uint_load_4_fast( in+7UL  ), fd_uint_load_4_fast( in+7UL  ),
      fd_uint_load_4_fast( in+10UL ), fd_uint_load_4_fast( in+10UL ),
      fd_uint_load_4_fast( in+14UL ), fd_uint_load_4_fast( in+14UL ),
      fd_uint_load_4_fast( in+17UL ), fd_uint_load_4_fast( in+17UL ),
      fd_uint_load_4_fast( in+21UL ), fd_uint_load_4_fast( in+21UL ),
      fd_uint_load_4_fast( in+24UL ), fd_uint_load_4_fast( in+24UL )
    );
    /* We perform a byteswap on each 32-bit element, which compiles down
       into a single vpshufb. */
    wwu_t swapped = wwu_bswap( compressed );
    /* We perform shifts that align each of the elements, wherever they
       are within their byte-swapped 32-bit representation, to start at
       the first bit of the element. This makes up for the overlapping
       bytes that occur when having bit-packed elements. */
    wwu_t shifted = wwu_shr_vector( swapped, offsets );
    /* After aligning the elements, we simply mask them off to 14-bits. */
    wwu_t masked = wwu_and( shifted, mask );

    /* If any of our elements are greater-than-or-equal to Q, the
       predicate is true and we exit the decoding process, as it must
       be invalid. */
    int cmp = wwu_ge( masked, Qv );
    if( FD_UNLIKELY( cmp ) ) return -1;

    /* While the reference C implementation represents the Fqs as 16-bit
       elements, it is generally faster to store than in 32-bits, as we
       will be often performing wide-muls on the elements, which needs
       all 32-bits.

       Because every element is already known to be positive, we don't
       need to wrap around when converting from F_q to Z/qZ, it just
       maps directly. */
    wwu_stu( out, masked );
  }
#else
  uint pos = 0;
  uchar const * h = input+1UL;
  for( int i=0; i<N; i++ ) {
    ushort value = 0;
    for( int j=0; j<14; j++ ) {
      value = (ushort)((value << 1) | bit(h, pos));
      pos++;
    }
    if( FD_UNLIKELY( value>=Q ) ) return -1;
    pubkey->h[i] = (uint)value;
  }
#endif
  return 0;
}

int
fd_falcon_signature_parse( fd_falcon_signature_t * out,
                             uchar const           * input,
                             ulong                   len ) {
  if( FD_UNLIKELY( len<41UL ) ) return -1;
  if( FD_UNLIKELY( input[ 0 ]!=HEADER ) ) return -1;
  memcpy( out->nonce, input+1UL, 40UL );

  uchar const * s2     = input+41UL;
  ulong         s2_len = len - 41UL;
  ulong         length = s2_len * 8UL;

  uchar padded[ 1024 + 8 ] FD_ALIGNED;
  if( FD_UNLIKELY( s2_len + 8UL > sizeof(padded) ) ) return -1;
  memcpy( padded,          s2, s2_len );
  memset( padded + s2_len, 0,  8UL );

  int results[ N ] __attribute__((aligned(64)));

  ulong abs_bit = 0;
  ulong word    = fd_ulong_bswap( fd_ulong_load_8_fast( padded ) );
  int   avail   = 64;

  for( int i=0; i<N; i++ ) {
    if( FD_UNLIKELY( avail<16 ) ) {
      if( FD_UNLIKELY( abs_bit+16UL > length ) ) return -1;
      ulong bp = abs_bit >> 3;
      int   sb = (int)(abs_bit & 7UL);
      word  = fd_ulong_bswap( fd_ulong_load_8_fast( padded+bp ) ) << sb;
      avail = 64 - sb;
    }

    int sign = (int)(word >> 63);
    int low  = (int)((word >> 56) & 0x7FUL);
    ulong tail = word << 8;

    int high;
    if( FD_LIKELY( tail ) ) {
      high = (int)__builtin_clzl( tail );
      int advance = 9 + high;
      word   <<= advance;
      avail   -= advance;
      abs_bit += (ulong)advance;
    } else {
      high = avail - 8;
      abs_bit += 8;

      for(;;) {
        if( FD_UNLIKELY( abs_bit>=length ) ) return -1;
        ulong bp = abs_bit >> 3;
        int   sb = (int)(abs_bit & 7UL);
        word  = fd_ulong_bswap( fd_ulong_load_8_fast( padded+bp ) ) << sb;
        avail = 64 - sb;
        if( FD_LIKELY( word ) ) {
          int extra = (int)__builtin_clzl( word );
          high += extra;
          int advance = extra + 1;
          word   <<= advance;
          avail   -= advance;
          abs_bit += (ulong)advance;
          break;
        }
        if( FD_UNLIKELY( (uint)high >= (uint)(Q >> 7) ) ) return -1;
        high    += avail;
        abs_bit += (ulong)avail;
        avail    = 0;
      }
    }

    if( FD_UNLIKELY( abs_bit>length ) ) return -1;

    int mag = (high << 7) | low;
    if( FD_UNLIKELY( mag>=Q ) ) return -1;
    results[ i ] = sign ? -mag : mag;
  }

#if FD_HAS_AVX512
  for( int i=0; i<N; i+=16 ) {
    wwu_t v          = wwu_ldu( fd_type_pun_const( results + i ) );
    wwu_t neg_mask   = wwi_shr( v, 31 );
    wwu_t correction = wwu_and( wwu_bcast( Q ), neg_mask );
    wwu_t fq         = wwu_add( v, correction );
    wwu_stu( out->s2 + i, fq );
  }
#else
  for( int i=0; i<N; i++ ) {
    int v = results[ i ];
    out->s2[ i ] = (fd_falcon_fq_t)( v + ( Q & ( v >> 31 ) ) );
  }
#endif

  /* Verify unused trailing bits are zero.
     Algorithm 18, line 12.
      > Enforce trailing bits are 0. */
  if( abs_bit<length ) {
    ulong bp = abs_bit >> 3;
    int   sb = (int)(abs_bit & 7UL);
    if( sb ) {
      uchar trail_mask = (uchar)(0xFFU >> sb);
      if( FD_UNLIKELY( s2[bp] & trail_mask ) ) return -1;
      bp++;
    }
    for( ulong j=bp; j<s2_len; j++ ) {
      if( FD_UNLIKELY( s2[j] ) ) return -1;
    }
  }

  return 0;
}

#if FD_HAS_AVX512
#define C_LEN (N+16)
#else
#define C_LEN N
#endif

static void
fd_falcon_hash_to_point( fd_falcon_fq_t c[ C_LEN ],
                         uchar const *  msg,
                         ulong          len,
                         uchar const    r[ 40 ] ) {
  fd_shake256_t state[1];
  fd_shake256_init( state );
  fd_shake256_absorb( state, r, 40UL );
  fd_shake256_absorb( state, msg, len );
  fd_shake256_fini( state );

  /* We can amortize the cost of the shake by sampling many bytes at once,
     not needing to go through more branches every new sample. */
  uchar sample[ 128 ];
  ulong offset = sizeof(sample);

  for( int i=0; i<N; ) {
    if( FD_UNLIKELY( offset>=sizeof(sample) ) ) {
      fd_shake256_squeeze( state, sample, sizeof(sample) );
      offset = 0;
    }

#if FD_HAS_AVX512
    /* Loads our sample as 16 16-bit byteswapped elements, and then
       extends to 32-bits to fill the zmm register. */
    ws_t s = ws_ldu( sample + offset );
    ws_t a = ws_shru( s, 8 );
    ws_t b = ws_shl(  s, 8 );
    wwu_t batch = _mm512_cvtepu16_epi32( ws_or( a, b ) );

    /* After we've sampled a vector of elements, we need to check which
       ones reach the threshold of [0, K*Q). For elements where the
       mask is set, as x < K*Q, we will "compress" and move them to the
       start of the vector. The rest of the elements can be discarded.

       While they will still go through the reduction and store, we
       only increment i by the popcount of the mask, so in a later
       iteration the invalid elements will be overwritten, until we
       have a c full of at least N valid elements. */
    wwu_t kv = wwu_bcast( K * Q );
    __mmask16 mask = (__mmask16)wwu_lt( batch, kv );
    wwu_t compressed = _mm512_maskz_compress_epi32( mask, batch );

    /* We know that a valid element is within [0, K*Q), which fits into
       16-bits. We can perform a barret-style reduction, by getting
       a reciprocal of ((1 << 16) / Q) which gives us 5. Then we can
       compute the division with (x * 5) >> 16, and get the modulus
       by x - ((x / modulo) * modulo), aka. x - q * modulo. */
    wwu_t q = wwu_shr( wwu_mul( compressed, wwu_bcast( K ) ), 16 );
    wwu_t r = wwu_sub( compressed, wwu_mul( q, wwu_bcast( Q ) ) );
    /* r can be overflowed, so we correct in that case,
       through a simple r -= select(r >= Q, Q, 0). */
    int ov = wwu_ge( r, wwu_bcast( Q ) );
    wwu_t corrected = wwu_sub( r, wwu_if( ov, wwu_bcast( Q ), wwu_zero() ) );

    wwu_stu( c+i, corrected );
    offset += 32;
    i += fd_ushort_popcnt( mask );
#else
    uint t = (uint)(sample[ offset ] << 8) | sample[ offset+1 ];
    offset += 2;
    if( FD_LIKELY( t<K * Q ) ) {
      c[ i ] = t % Q;
      i += 1;
    }
#endif
  }
}

int
fd_falcon_verify( uchar const * msg,
                  ulong         len,
                  fd_falcon_signature_t const * sig,
                  fd_falcon_pubkey_t    const * pk ) {
  fd_falcon_fq_t c[ C_LEN ];
  fd_falcon_hash_to_point( c, msg, len, sig->nonce );

  /* The equation that the signature must fulfill is
       s1 = c - s2 * h

     s2 and h are moved into the evaluation basis, so we that can use
     a Hadamard multiplication for the operation, instead of the long
     regular result one usually gets when multiplying polynomials.

     We can avoid moving c into the domain, as subtraction is performed
     pointwise, no matter which basis the polynomial is represented in. */
  fd_falcon_fq_t s2_ntt[ N ];
  fd_falcon_fq_t h_ntt [ N ];
  fd_falcon_fq_t m_ntt[ N ];
  fd_falcon_fq_fft( s2_ntt, sig->s2 );
  fd_falcon_fq_fft( h_ntt,  pk->h );

  for( int i=0; i<N; i++ ) {
    m_ntt[ i ] = fd_falcon_fq_mul( s2_ntt[ i ], h_ntt[ i ] );
  }
  fd_falcon_fq_t m[ N ];
  fd_falcon_fq_ifft( m, m_ntt );

  fd_falcon_fq_t s1[ N ];
  for( int i=0; i<N; i++ ) {
    s1[ i ] = fd_falcon_fq_sub( c[ i ], m[ i ] );
  }

  /* ||(s1, s2)||^2 <= beta^2
     In order to avoid computing the square root, we use the squared norm
     and compare it to beta^2. */
  long norm = 0L;
  for( int i=0; i<N; i++ ) {
    /* Both s1 and s2 are in [0, Q), whereas we want to normalize them
       between -Q/2 to Q/2, so we shift the centre by Q/2. */
    int v1 = (int)s1[ i ];
    if( v1 > Q/2 ) v1 -= Q;
    int v2 = (int)sig->s2[ i ];
    if( v2 > Q/2 ) v2 -= Q;
    norm += (long)v1 * v1 + (long)v2 * v2;
  }

  if( FD_UNLIKELY( norm > 34034726L ) ) return -1;
  return 0;
}
