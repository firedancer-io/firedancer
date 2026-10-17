#include "fd_chacha_rng.h"
#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
#include "../../util/simd/fd_sse.h"
#endif

FD_FN_CONST ulong
fd_chacha_rng_align( void ) {
  return alignof(fd_chacha_rng_t);
}

FD_FN_CONST ulong
fd_chacha_rng_footprint( void ) {
  return sizeof(fd_chacha_rng_t);
}

void *
fd_chacha_rng_new( void * shmem, int mode ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, alignof(fd_chacha_rng_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  memset( shmem, 0, sizeof(fd_chacha_rng_t) );
  if( FD_UNLIKELY( (mode!=FD_CHACHA_RNG_MODE_MOD) & (mode!=FD_CHACHA_RNG_MODE_SHIFT) ) ) {
    FD_LOG_WARNING(( "invalid mode" ));
    return NULL;
  }
  ((fd_chacha_rng_t *)shmem)->mode = mode;
  ((fd_chacha_rng_t *)shmem)->algo = FD_CHACHA_RNG_ALGO_CHACHA20;
  return shmem;
}

fd_chacha_rng_t *
fd_chacha_rng_join( void * shrng ) {
  if( FD_UNLIKELY( !shrng ) ) {
    FD_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  return (fd_chacha_rng_t *)shrng;
}

void *
fd_chacha_rng_leave( fd_chacha_rng_t * rng ) {
  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }
  return (void *)rng;
}

void *
fd_chacha_rng_delete( void * shrng ) {
  if( FD_UNLIKELY( !shrng ) ) {
    FD_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  memset( shrng, 0, sizeof(fd_chacha_rng_t) );
  return shrng;
}

fd_chacha_rng_t *
fd_chacha_rng_init( fd_chacha_rng_t * rng,
                    void const *      key,
                    int               algo ) {
  memcpy( rng->key, key, FD_CHACHA_KEY_SZ );
  rng->buf_off  = 0UL;
  rng->buf_fill = 0UL;

  /* invalid algo defaults to chacha20 */
  rng->algo = algo;
  if( algo==FD_CHACHA_RNG_ALGO_CHACHA8 ) {
    fd_chacha8_rng_private_refill( rng );
  } else {
    fd_chacha20_rng_private_refill( rng );
  }

  return rng;
}

static void
fd_chacha_rng_refill_seq( fd_chacha_rng_t * rng,
                          void * (* block_fn)( void *, void const *, void const * ) ) {
  ulong fill_target = FD_CHACHA_RNG_BUFSZ - FD_CHACHA_BLOCK_SZ;

  ulong buf_avail;
  while( (buf_avail=(rng->buf_fill - rng->buf_off))<fill_target ) {
    ulong idx = rng->buf_fill >> 6;
    uint idx_nonce[4] __attribute__((aligned(16))) =
      { (uint)idx, (uint)(idx>>32), 0U, 0U };
    block_fn( rng->buf + (rng->buf_fill % FD_CHACHA_RNG_BUFSZ),
              rng->key,
              idx_nonce );
    rng->buf_fill += (uint)FD_CHACHA_BLOCK_SZ;
  }
}

void
fd_chacha8_rng_refill_seq( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_seq( rng, fd_chacha8_block );
}

void
fd_chacha20_rng_refill_seq( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_seq( rng, fd_chacha20_block );
}

void
fd_chacha_rng_ulong_roll_decreasing( fd_chacha_rng_t * rng,
                                     ulong             n_initial,
                                     ulong *           out,
                                     ulong             cnt ) {
#if !FD_HAS_AVX512
  int use_fast_path = 0;
#else
  int use_fast_path = (rng->mode==FD_CHACHA_RNG_MODE_SHIFT) & (cnt>=16UL) & (n_initial<(1UL<<40));
#endif

  if( use_fast_path ) {
#if FD_HAS_AVX512
  /* Using MODE_SHIFT, the expected probability of rejection is about
     25%, which is sadly pretty high.  We amortize that by guessing many
     values with AVX multiplication. wwv_mul is very slow on Intel CPUs
     but decent on recent AMD CPUs. */

    ulong buf_avail = fd_chacha_rng_avail( rng );
    while( cnt>=14UL ) {
      /* In this loop, we'll produce 0-8 samples and consume 8-15 ulongs
         from the stream.

         The loop invariant is that buf_avail is in [0,
         BUFSZ+6*sizeof(ulong)] at the start and end of each loop
         iteration.  We need 15 ulongs of contiguous bytes though, and
         the only way to get more random data is from a refill that
         produces BUFSZ more data.  That means buf_avail can peak at
         BUFSZ+14*sizeof(ulong), but then we always consume at least 8
         ulongs from the stream, so it ends at no more than
         BUFSZ+6*sizeof(ulong).

         We can't return from this function until buf_avail is <= BUFSZ,
         which means we need to exit this loop early enough to consume
         at least 6 more ulongs in the worst case.  Since each iteration
         of the loop might produce 8 random samples, cnt>=6 at the end
         means cnt>=14 at the start. */
      if( FD_UNLIKELY( buf_avail<15UL*sizeof(ulong) ) ) {
        memcpy( rng->pre_buf, rng->buf+FD_CHACHA_RNG_BUFSZ-128UL, 128UL );
        rng->buf_off = rng->buf_fill;
        if( rng->algo==FD_CHACHA_RNG_ALGO_CHACHA8 ) {
          fd_chacha8_rng_private_refill( rng );
        } else {
          fd_chacha20_rng_private_refill( rng );
        }
        buf_avail += FD_CHACHA_RNG_BUFSZ;
      }

      ulong const * load_base = (ulong const *)(rng->buf+FD_CHACHA_RNG_BUFSZ-buf_avail);
      wwv_t r0 = wwv_ldu( load_base+0UL );
      wwv_t r1 = wwv_ldu( load_base+1UL );
      wwv_t r2 = wwv_ldu( load_base+2UL );
      wwv_t r3 = wwv_ldu( load_base+3UL );
      wwv_t r4 = wwv_ldu( load_base+4UL );
      wwv_t r5 = wwv_ldu( load_base+5UL );
      wwv_t r6 = wwv_ldu( load_base+6UL );
      wwv_t r7 = wwv_ldu( load_base+7UL );

      wwv_t const ii = wwv( 0UL, 1UL, 2UL, 3UL, 4UL, 5UL, 6UL, 7UL );

      wwv_t n_initial_v = wwv_bcast( n_initial );
      wwv_t n           = wwv_sub( n_initial_v, ii );

      /* Recomputing in parallel seems to be faster than broadcasting
         from n... */
      wwv_t n_initial_0 = n_initial_v;
      wwv_t n_initial_1 = wwv_sub( n_initial_v, wwv_bcast( 1UL ) );
      wwv_t n_initial_2 = wwv_sub( n_initial_v, wwv_bcast( 2UL ) );
      wwv_t n_initial_3 = wwv_sub( n_initial_v, wwv_bcast( 3UL ) );
      wwv_t n_initial_4 = wwv_sub( n_initial_v, wwv_bcast( 4UL ) );
      wwv_t n_initial_5 = wwv_sub( n_initial_v, wwv_bcast( 5UL ) );
      wwv_t n_initial_6 = wwv_sub( n_initial_v, wwv_bcast( 6UL ) );
      wwv_t n_initial_7 = wwv_sub( n_initial_v, wwv_bcast( 7UL ) );

      /* Recall that we need to check lo<=zone, where zone is
         n<<lzcnt(n) - 1.  That's equivalent to lo<(n<<lzcnt(n)), but
         n<<lzcnt(n) could be 2^64.  However, that's equivalent to
         (lo>>lzcnt(n)) < n, which again is equivalent to
         (lo>>lzcnt(n)) - n < 0.  Given that n<2^40, we don't need to
         worry about overflow. */

      wwv_t prod0 = wwv_mul( r0, n_initial_0 );
      wwv_t prod1 = wwv_mul( r1, n_initial_1 );
      wwv_t prod2 = wwv_mul( r2, n_initial_2 );
      wwv_t prod3 = wwv_mul( r3, n_initial_3 );
      wwv_t prod4 = wwv_mul( r4, n_initial_4 );
      wwv_t prod5 = wwv_mul( r5, n_initial_5 );
      wwv_t prod6 = wwv_mul( r6, n_initial_6 );
      wwv_t prod7 = wwv_mul( r7, n_initial_7 );

      /* Only the high bit of each ulong is meaningful */
      wwv_t le0 = wwv_sub( wwv_shr_vector( prod0,  _mm512_lzcnt_epi64( n_initial_0 ) ), n_initial_0 );
      wwv_t le1 = wwv_sub( wwv_shr_vector( prod1,  _mm512_lzcnt_epi64( n_initial_1 ) ), n_initial_1 );
      wwv_t le2 = wwv_sub( wwv_shr_vector( prod2,  _mm512_lzcnt_epi64( n_initial_2 ) ), n_initial_2 );
      wwv_t le3 = wwv_sub( wwv_shr_vector( prod3,  _mm512_lzcnt_epi64( n_initial_3 ) ), n_initial_3 );
      wwv_t le4 = wwv_sub( wwv_shr_vector( prod4,  _mm512_lzcnt_epi64( n_initial_4 ) ), n_initial_4 );
      wwv_t le5 = wwv_sub( wwv_shr_vector( prod5,  _mm512_lzcnt_epi64( n_initial_5 ) ), n_initial_5 );
      wwv_t le6 = wwv_sub( wwv_shr_vector( prod6,  _mm512_lzcnt_epi64( n_initial_6 ) ), n_initial_6 );
      wwv_t le7 = wwv_sub( wwv_shr_vector( prod7,  _mm512_lzcnt_epi64( n_initial_7 ) ), n_initial_7 );

      /* We want to compute something like "if I had to consume k ulongs
         before getting to produce sample j, how many ulongs do I have
         to consume to produce sample j?"  If le_i is
         [ a 0 0 0... , b 0, c 0, d 0, e 0, f 0, g 0, h 0 ]
         Where the 0s are the rest of the ulong, then we want to produce
         [ abcdefgh, 0bcdefgh, 00cdefgh, ... ]
         which we can do with one permutexvar.  Then we lzcnt it, which
         gives us 8*(ignoring all lanes prior to the current one, what
         is the first non-zero lane in le).  That's only 8 pieces of
         information, each <=6 bits, so we compact it. */
#if 0
      static wwb_t const perm = wwb( 63, 55, 47, 39, 31, 23, 15,  7,
                                     63, 55, 47, 39, 31, 23, 15,  0,
                                     63, 55, 47, 39, 31, 23,  0,  0,
                                     63, 55, 47, 39, 31,  0,  0,  0,
                                     63, 55, 47, 39,  0,  0,  0,  0,
                                     63, 55, 47,  0,  0,  0,  0,  0,
                                     63, 55,  0,  0,  0,  0,  0,  0,
                                     63,  0,  0,  0,  0,  0,  0,  0 );
#else
      static ulong const perm_q[ 8 ] __attribute__((aligned(64))) = {
        0x070F171F272F373FUL,  /* lane 0 */
        0x000F171F272F373FUL,  /* lane 1 */
        0x0000171F272F373FUL,  /* lane 2 */
        0x0000001F272F373FUL,  /* lane 3 */
        0x00000000272F373FUL,  /* lane 4 */
        0x00000000002F373FUL,  /* lane 5 */
        0x000000000000373FUL,  /* lane 6 */
        0x000000000000003FUL,  /* lane 7 */
      };
      wwv_t perm = wwv_ld( perm_q );
#endif
      const ulong DIAG_MASK = 0x0103070F1F3F7FFFUL;
      wwv_t w_table0 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le0 ) ), 3 );
      wwv_t w_table1 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le1 ) ), 3 );
      wwv_t w_table2 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le2 ) ), 3 );
      wwv_t w_table3 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le3 ) ), 3 );
      wwv_t w_table4 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le4 ) ), 3 );
      wwv_t w_table5 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le5 ) ), 3 );
      wwv_t w_table6 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le6 ) ), 3 );
      wwv_t w_table7 = wwv_shr( _mm512_lzcnt_epi64( _mm512_maskz_permutexvar_epi8( DIAG_MASK, perm, le7 ) ), 3 );

      /* Compact to the low 8 bytes, filling the rest with 8 */
      wwb_t const compact = _mm512_castsi128_si512( vb(  0, 8, 16, 24, 32, 40, 48, 56,
                                                        64,64, 64, 64, 64, 64, 64, 64 ) );
      wwb_t const eight   = wwb_bcast( 8 );
      vb_t table0 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table0, compact, eight ) );
      vb_t table1 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table1, compact, eight ) );
      vb_t table2 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table2, compact, eight ) );
      vb_t table3 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table3, compact, eight ) );
      vb_t table4 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table4, compact, eight ) );
      vb_t table5 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table5, compact, eight ) );
      vb_t table6 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table6, compact, eight ) );
      vb_t table7 = _mm512_castsi512_si128( _mm512_permutex2var_epi8( w_table7, compact, eight ) );

      /* Up until this point, everything has been parallelizable, but
         now we need to combine all the information.  We've formatted it
         in such a way that we can do that with just shifting.  For
         example, if (suppressing all but the high bit)
         le0 = [ 0x80.., 0,      0x80.., 0x80.., 0    ... ]
         le1 = [ 0x80.., 0x80.., 0,      0,      0    ... ]
         le2 = [ 0,      0x80.., 0,      0x80.., 0    ... ]
         le3 = [ 0x80.., 0x80.., 0,      0x80.., 0    ... ]
         le4 = [ 0x80.., 0,      0,      0,      0x80 ... ]

         Then table are:
         table0 = [ 0,  2,  2,  3, ??, ... ]
         table1 = [ 0,  1, ??, ??, ??  ... ]
         table2 = [ 1,  1,  3,  3, ??  ... ]
         table3 = [ 0,  1,  3,  3, ??  ... ]
         table4 = [ 0,  4,  4,  4,  4  ... ]

         We can interpret these as a function, and applying them can be
         done with vpshufb, one of my favorite instructions.  Composing
         them can also be done with vpshufb, and we can apply the
         composition of the whole thing with lower latency using a tree. */

      vb_t table01    = _mm_shuffle_epi8( table1,    table0    );
      vb_t table23    = _mm_shuffle_epi8( table3,    table2    );
      vb_t table45    = _mm_shuffle_epi8( table5,    table4    );
      vb_t table67    = _mm_shuffle_epi8( table7,    table6    );
      vb_t table0123  = _mm_shuffle_epi8( table23,   table01   );
      vb_t table4567  = _mm_shuffle_epi8( table67,   table45   );
      vb_t table_all0 = _mm_maskz_shuffle_epi8( 1, table4567, table0123 ); /* Only need byte 1, shaves a cycle off critical path */

      /* Extract byte0 from table_all.  Once we do this, the next
         iteration can probably begin. */
      ulong final = (ulong)_mm_cvtsi128_si64( table_all0 );

      /* We need to produce the rest of the table values that aren't on
         the critical path. */
      vb_t table012     = _mm_shuffle_epi8( table2,  table01     );
      vb_t table01234   = _mm_shuffle_epi8( table4,  table0123   );
      vb_t table012345  = _mm_shuffle_epi8( table45, table0123   );
      vb_t table0123456 = _mm_shuffle_epi8( table6,  table012345 );

      /* Now combine all of the byte 0s from all these vectors. */
      vb_t counter01   = _mm_unpacklo_epi8 ( table0,       table01     );
      vb_t counter23   = _mm_unpacklo_epi8 ( table012,     table0123   );
      vb_t counter45   = _mm_unpacklo_epi8 ( table01234,   table012345 );
      vb_t counter67   = _mm_unpacklo_epi8 ( table0123456, table_all0  );
      vb_t counter0123 = _mm_unpacklo_epi16( counter01,    counter23   );
      vb_t counter4567 = _mm_unpacklo_epi16( counter45,    counter67   );
      vb_t counter_all = _mm_unpacklo_epi32( counter0123,  counter4567 );

      ulong produced;
      ulong consumed;
      if( FD_LIKELY( final<8 ) ) {
        /* About 95% at p=0.7 */
        produced = 8UL;
        consumed = final+8UL;
      } else {
        /* Find the first index where it's 8. */
        produced = (ulong)fd_ulong_find_lsb( (ulong)_mm_cvtsi128_si64( counter_all ) & 0x0808080808080808UL ) >> 3;
        /* If we didn't produce all 8, then we don't need to retry a
           bunch of bad random data on the last value that we did
           produce. */
        consumed = produced + 8UL;
      }
      /* The next iteration can definitely begin now while we compute
         the final values. */

      /* We want to construct the final r vector with
         _mm512_permutex2var_epi64, with the indices coming from the
         counter values we produced above.  Remember that lane j in
         vector i, is just lane i+j in r0, where values >=8 come from
         load_base+8. */
      wwv_t counter_wide = wwv_add( ii, _mm512_cvtepu8_epi64( counter_all ) );
      wwv_t r = _mm512_permutex2var_epi64( r0, counter_wide, wwv_ldu( load_base+8UL ) );


      /* Finally... we want the high part of r * n.  There's no mulhi
         instruction though, but it's not too bad.
         Let r = r_hi * 2^52 + r_lo, with r_lo<2^52.  n<2^52 by
         hypothesis.

         r*n = r_hi * n * 2^52 + r_lo*n
         r_lo*n = m52hi( r_lo, n )*2^52 + m52lo( r_lo, n ), where m52lo(-,-) < 2^52

         Since r_hi < 2^(64-52) and n<2^40, r_hi * n < 2^52, so
         r_hi * n = m52lo( r_hi, n ).  So then
         r*n = 2^52 * (m52hi( r_lo, n ) + m52lo( r_hi, n )) +
                                                m52lo( r_lo, n ),
         Since we want to discard the low 64 bits and we know the last
         term doesn't carry into the higher 52 bits, we can just omit
         it.
         r*n>>64 = (m52hi( r_lo, n ) + m52lo( r_hi, n ))>>12 */
      wwv_t high_product = wwv_madd52hi( wwv_madd52lo( wwv_zero(), wwv_shr( r, 52 ), n ),
                                                                            r,       n );

      wwv_t samples = wwv_shr( high_product, 12 );
      wwv_stu( out, samples );

      n_initial -= produced;
      out       += produced;
      cnt       -= produced;
      buf_avail -= consumed*sizeof(ulong);
    }
    while( (cnt>0) && (buf_avail>FD_CHACHA_RNG_BUFSZ) ) {
      ulong zone = (n_initial << (63 - fd_ulong_find_msb( n_initial) )) - 1UL;
      ulong const * load_base = (ulong const *)(rng->buf+FD_CHACHA_RNG_BUFSZ-buf_avail);
      ulong v = *load_base;
      ulong hi, lo;
      fd_uwide_mul( &hi, &lo, v, n_initial );
      *out = hi;

      ulong consumed = 1UL;
      ulong produced = (lo<=zone);

      n_initial -= produced;
      out       += produced;
      cnt       -= produced;
      buf_avail -= consumed*sizeof(ulong);
    }
    rng->buf_off = rng->buf_fill - buf_avail;
#endif
  }
  for( ulong i=0UL; i<cnt; i++ ) out[i] = fd_chacha_rng_ulong_roll( rng, n_initial-i );
}
