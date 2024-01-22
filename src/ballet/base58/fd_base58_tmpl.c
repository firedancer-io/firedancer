/* Declares conversion functions to/from base58 for a specific size of
   binary data.

   To use this template, define:

     N: the length of the binary data (in bytes) to convert.  N must be
         32 or 64 in the current implementation.
     INTERMEDIATE_SZ: ceil(log_(58^5) ( (256^N) - 1)). In an ideal
         world, this could be computed from N, but there's no way the
         preprocessor can do math like that.
     BINARY_SIZE: N/4.  Define it yourself to facilitate declaring the
         required tables.

   INTERMEDIATE_SZ and BINARY_SZ should expand to ulongs while N should
   be an integer literal.

   Expects that enc_table_N, dec_table_N, and FD_BASE58_ENCODED_N_SZ
   exist (substituting the numeric value of N).

   This file is safe for inclusion multiple times. */

#define BYTE_CNT     ((ulong) N)
#define SUFFIX(s)    FD_EXPAND_THEN_CONCAT3(s,_,N)
#define ENCODED_SZ() FD_EXPAND_THEN_CONCAT3(FD_BASE58_ENCODED_, N, _SZ)
#define RAW58_SZ     (INTERMEDIATE_SZ*5UL)

#if FD_HAS_AVX
#define INTERMEDIATE_SZ_W_PADDING FD_ULONG_ALIGN_UP( INTERMEDIATE_SZ, 4UL )
#else
#define INTERMEDIATE_SZ_W_PADDING INTERMEDIATE_SZ
#endif

char *
SUFFIX(fd_base58_encode)( uchar const * bytes,
                          ulong       * opt_len,
                          char        * out    ){

  /* Count leading zeros (needed for final output) */
#if FD_HAS_AVX
# if N==32
  wuc_t _bytes = wuc_ldu( bytes );
  ulong in_leading_0s = count_leading_zeros_32( _bytes );
# elif N==64
  wuc_t bytes_0 = wuc_ldu( bytes      );
  wuc_t bytes_1 = wuc_ldu( bytes+32UL );
  ulong in_leading_0s = count_leading_zeros_64( bytes_0, bytes_1 );
# endif
#else

  ulong in_leading_0s = 0UL;
  for( ; in_leading_0s<BYTE_CNT; in_leading_0s++ ) if( bytes[ in_leading_0s ] ) break;
#endif

  /* X = sum_i bytes[i] * 2^(8*(BYTE_CNT-1-i)) */

  /* Convert N to 32-bit limbs:
     X = sum_i binary[i] * 2^(32*(BINARY_SZ-1-i)) */
  uint binary[ BINARY_SZ ];
  for( ulong i=0UL; i<BINARY_SZ; i++ ) binary[ i ] = fd_uint_bswap( fd_uint_load_4( &bytes[ i*sizeof(uint) ] ) );

  ulong R1div = 656356768UL; /* = 58^5 */

  /* Convert to the intermediate format:
       X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i))
     Initially, we don't require intermediate[i] < 58^5, but we do want
     to make sure the sums don't overflow. */

#if FD_HAS_AVX
  ulong W_ATTR intermediate[ INTERMEDIATE_SZ_W_PADDING ];
#else
  ulong intermediate[ INTERMEDIATE_SZ_W_PADDING ];
#endif

  fd_memset( intermediate, 0, INTERMEDIATE_SZ_W_PADDING * sizeof(ulong) );

# if N==32

  /* The worst case is if binary[7] is (2^32)-1. In that case
     intermediate[8] will be be just over 2^63, which is fine. */

  for( ulong i=0UL; i < BINARY_SZ; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[ j+1UL ] += (ulong)binary[ i ] * (ulong)SUFFIX(enc_table)[ i ][ j ];

# elif N==64

  /* If we do it the same way as the 32B conversion, intermediate[16]
     can overflow when the input is sufficiently large.  We'll do a
     mini-reduction after the first 8 steps.  After the first 8 terms,
     the largest intermediate[16] can be is 2^63.87.  Then, after
     reduction it'll be at most 58^5, and after adding the last terms,
     it won't exceed 2^63.1.  We do need to be cautious that the
     mini-reduction doesn't cause overflow in intermediate[15] though.
     Pre-mini-reduction, it's at most 2^63.05.  The mini-reduction adds
     at most 2^64/58^5, which is negligible.  With the final terms, it
     won't exceed 2^63.69, which is fine. Other terms are less than
     2^63.76, so no problems there. */

  for( ulong i=0UL; i < 8UL; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[ j+1UL ] += (ulong)binary[ i ] * (ulong)SUFFIX(enc_table)[ i ][ j ];
  /* Mini-reduction */
  intermediate[ 15 ] += intermediate[ 16 ]/R1div;
  intermediate[ 16 ] %= R1div;
  /* Finish iterations */
  for( ulong i=8UL; i < BINARY_SZ; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[ j+1UL ] += (ulong)binary[ i ] * (ulong)SUFFIX(enc_table)[ i ][ j ];

# else
# error "Add support for this N"
# endif

  /* Now we make sure each term is less than 58^5. Again, we have to be
     a bit careful of overflow.

     For N==32, in the worst case, as before, intermediate[8] will be
     just over 2^63 and intermediate[7] will be just over 2^62.6.  In
     the first step, we'll add floor(intermediate[8]/58^5) to
     intermediate[7].  58^5 is pretty big though, so intermediate[7]
     barely budges, and this is still fine.

     For N==64, in the worst case, the biggest entry in intermediate at
     this point is 2^63.87, and in the worst case, we add (2^64-1)/58^5,
     which is still about 2^63.87. */

  for( ulong i=INTERMEDIATE_SZ-1UL; i>0UL; i-- ) {
    intermediate[ i-1UL ] += (intermediate[ i ]/R1div);
    intermediate[ i     ] %= R1div;
  }

#if !FD_HAS_AVX
  /* Convert intermediate form to base 58.  This form of conversion
     exposes tons of ILP, but it's more than the CPU can take advantage
     of.
       X = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */

  uchar raw_base58[ RAW58_SZ ];
  for( ulong i=0UL; i<INTERMEDIATE_SZ; i++) {
    /* We know intermediate[ i ] < 58^5 < 2^32 for all i, so casting to
       a uint is safe.  GCC doesn't seem to be able to realize this, so
       when it converts ulong/ulong to a magic multiplication, it
       generates the single-op 64b x 64b -> 128b mul instruction.  This
       hurts the CPU's ability to take advantage of the ILP here. */
    uint v = (uint)intermediate[ i ];
    raw_base58[ 5UL*i+4UL ] = (uchar)((v/1U       )%58U);
    raw_base58[ 5UL*i+3UL ] = (uchar)((v/58U      )%58U);
    raw_base58[ 5UL*i+2UL ] = (uchar)((v/3364U    )%58U);
    raw_base58[ 5UL*i+1UL ] = (uchar)((v/195112U  )%58U);
    raw_base58[ 5UL*i+0UL ] = (uchar)( v/11316496U); /* We know this one is less than 58 */
  }

  /* Finally, actually convert to the string.  We have to ignore all the
     leading zeros in raw_base58 and instead insert in_leading_0s
     leading '1' characters.  We can show that raw_base58 actually has
     at least in_leading_0s, so we'll do this by skipping the first few
     leading zeros in raw_base58. */

  ulong raw_leading_0s = 0UL;
  for( ; raw_leading_0s<RAW58_SZ; raw_leading_0s++ ) if( raw_base58[ raw_leading_0s ] ) break;

  /* It's not immediately obvious that raw_leading_0s >= in_leading_0s,
     but it's true.  In base b, X has floor(log_b X)+1 digits.  That
     means in_leading_0s = N-1-floor(log_256 X) and raw_leading_0s =
     RAW58_SZ-1-floor(log_58 X).  Let X<256^N be given and consider:

     raw_leading_0s - in_leading_0s =
       =  RAW58_SZ-N + floor( log_256 X ) - floor( log_58 X )
       >= RAW58_SZ-N - 1 + ( log_256 X - log_58 X ) .

     log_256 X - log_58 X is monotonically decreasing for X>0, so it
     achieves it minimum at the maximum possible value for X, i.e.
     256^N-1.
       >= RAW58_SZ-N-1 + log_256(256^N-1) - log_58(256^N-1)

     When N==32, RAW58_SZ is 45, so this gives skip >= 0.29
     When N==64, RAW58_SZ is 90, so this gives skip >= 1.59.

     Regardless, raw_leading_0s - in_leading_0s >= 0. */

  ulong skip = raw_leading_0s - in_leading_0s;
  for( ulong i=0UL; i<RAW58_SZ-skip; i++ )  out[ i ] = base58_chars[ raw_base58[ skip+i ] ];

#else /* FD_HAS_AVX */
# if N==32
  wl_t intermediate0 = wl_ld( (long*)intermediate     );
  wl_t intermediate1 = wl_ld( (long*)intermediate+4UL );
  wl_t intermediate2 = wl_ld( (long*)intermediate+8UL );
  wuc_t raw0 = intermediate_to_raw( intermediate0 );
  wuc_t raw1 = intermediate_to_raw( intermediate1 );
  wuc_t raw2 = intermediate_to_raw( intermediate2 );

  wuc_t compact0, compact1;
  ten_per_slot_down_32( raw0, raw1, raw2, compact0, compact1 );

  ulong raw_leading_0s = count_leading_zeros_45( compact0, compact1 );

  wuc_t base58_0 = raw_to_base58( compact0 );
  wuc_t base58_1 = raw_to_base58( compact1 );

  ulong skip = raw_leading_0s - in_leading_0s;
  /* We know the final string is between 32 and 44 characters, so skip
     has to be in [1, 13].

     Suppose base58_0 is [ a0 a1 a2 ... af | b0 b1 b2 ... bf ] and skip
     is 2.
     It would be nice if we had something like the 128-bit barrel shifts
     we used in ten_per_slot_down, but they require immediates.
     Instead, we'll shift each ulong right by (skip%8) bytes:

     [ a2 a3 .. a7 0 0 aa ab .. af 0 0 | b2 b3 .. b7 0 0 ba .. bf 0 0 ]
     and maskstore to write just 8 bytes, skipping the first
     floor(skip/8) ulongs, to a starting address of out-8*floor(skip/8).

           out
             V
           [ a2 a3 a4 a5 a6 a7  0  0 -- -- ... ]

     Now we use another maskstore on the original base58_0, masking out
     the first floor(skip/8)+1 ulongs, and writing to out-skip:
           out
             V
     [ -- -- -- -- -- -- -- -- a8 a9 aa ab ... bd be bf ]

     Finally, we need to write the low 13 bytes from base58_1 and a '\0'
     terminator, starting at out-skip+32.  The easiest way to do this is
     actually to shift in 3 more bytes, write the full 16B and do it
     prior to the previous write:
                                               out-skip+29
                                                V
                                              [ 0  0  0  c0 c1 c2 .. cc ]
    */
  wl_t w_skip    = wl_bcast( (long)skip );
  wl_t mod8_mask = wl_bcast(       7L   );
  wl_t compare   = wl( 0L, 1L, 2L, 3L );

  wl_t shift_qty = wl_shl( wl_and( w_skip, mod8_mask ), 3 ); /* bytes->bits */
  wl_t shifted = wl_shru_vector( base58_0, shift_qty );
  wl_t skip_div8 = wl_shru( w_skip, 3 );

  wc_t mask1 = wl_eq( skip_div8, compare );
  _mm256_maskstore_epi64(  (long long int*)(out - 8UL*(skip/8UL)), mask1, shifted );

  __m128i last = _mm_bslli_si128( _mm256_extractf128_si256( base58_1, 0 ), 3 );
  _mm_storeu_si128( (__m128i*)(out+29UL-skip), last);

  wc_t mask2 = wl_gt( compare, skip_div8 );
  _mm256_maskstore_epi64(  (long long int*)(out - skip), mask2, base58_0 );

# elif N==64
  wuc_t raw0 = intermediate_to_raw( wl_ld( (long*)intermediate      ) );
  wuc_t raw1 = intermediate_to_raw( wl_ld( (long*)intermediate+4UL  ) );
  wuc_t raw2 = intermediate_to_raw( wl_ld( (long*)intermediate+8UL  ) );
  wuc_t raw3 = intermediate_to_raw( wl_ld( (long*)intermediate+12UL ) );
  wuc_t raw4 = intermediate_to_raw( wl_ld( (long*)intermediate+16UL ) );

  wuc_t compact0, compact1, compact2;
  ten_per_slot_down_64( raw0, raw1, raw2, raw3, raw4, compact0, compact1, compact2 );

  ulong raw_leading_0s_part1 = count_leading_zeros_64( compact0, compact1 );
  ulong raw_leading_0s_part2 = count_leading_zeros_26( compact2 );
  ulong raw_leading_0s = fd_ulong_if( raw_leading_0s_part1<64UL, raw_leading_0s_part1, 64UL+raw_leading_0s_part2 );

  wuc_t base58_0 = raw_to_base58( compact0 );
  wuc_t base58_1 = raw_to_base58( compact1 );
  wuc_t base58_2 = raw_to_base58( compact2 );

  ulong skip = raw_leading_0s - in_leading_0s;
  /* We'll do something similar.  The final string is between 64 and 88
     characters, so skip is [2, 26].
     */
  wl_t w_skip    = wl_bcast( (long)skip );
  wl_t mod8_mask = wl_bcast(       7L   );
  wl_t compare   = wl( 0L, 1L, 2L, 3L );

  wl_t shift_qty = wl_shl( wl_and( w_skip, mod8_mask ), 3 ); /* bytes->bits */
  wl_t shifted = wl_shru_vector( base58_0, shift_qty );
  wl_t skip_div8 = wl_shru( w_skip, 3 );

  wc_t mask1 = wl_eq( skip_div8, compare );
  wc_t mask2 = wl_gt( compare, skip_div8 );
  _mm256_maskstore_epi64( (long long int*)(out - 8UL*(skip/8UL)), mask1, shifted  );

  _mm256_maskstore_epi64( (long long int*)(out - skip),           mask2, base58_0 );

  wuc_stu( (uchar*)out+32UL-skip, base58_1 );

  __m128i last = _mm_bslli_si128( _mm256_extractf128_si256( base58_2, 1 ), 6 );
  _mm_storeu_si128( (__m128i*)(out+64UL+16UL-6UL-skip), last                                    );
  _mm_storeu_si128( (__m128i*)(out+64UL-skip),          _mm256_extractf128_si256( base58_2, 0 ) );
# endif
#endif

  out[ RAW58_SZ-skip ] = '\0';
  fd_ulong_store_if( !!opt_len, opt_len, RAW58_SZ-skip );
  return out;
}

uchar *
SUFFIX(fd_base58_decode)( char const * encoded,
                          uchar      * out      ) {

  /* Validate string and count characters before the nul terminator */

  ulong char_cnt = 0UL;
  for( ; char_cnt<ENCODED_SZ(); char_cnt++ ) {
    char c = encoded[ char_cnt ];
    if( !c ) break;
    /* If c<'1', this will underflow and idx will be huge */
    ulong idx = (ulong)(uchar)c - (ulong)BASE58_INVERSE_TABLE_OFFSET;
    idx = fd_ulong_min( idx, BASE58_INVERSE_TABLE_SENTINEL );
    if( FD_UNLIKELY( base58_inverse[ idx ] == BASE58_INVALID_CHAR ) ) return NULL;
  }

  if( FD_UNLIKELY( char_cnt == ENCODED_SZ() ) ) return NULL; /* too long */

  /* X = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */

  uchar raw_base58[ RAW58_SZ ];

  /* Prepend enough 0s to make it exactly RAW58_SZ characters */

  ulong prepend_0 = RAW58_SZ-char_cnt;
  for( ulong j=0UL; j<RAW58_SZ; j++ )
    raw_base58[ j ] = (j<prepend_0) ? (uchar)0 : base58_inverse[ encoded[ j-prepend_0 ] - BASE58_INVERSE_TABLE_OFFSET ];

  /* Convert to the intermediate format (base 58^5):
       X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i)) */

  ulong intermediate[ INTERMEDIATE_SZ ];
  for( ulong i=0UL; i<INTERMEDIATE_SZ; i++ )
    intermediate[ i ] = (ulong)raw_base58[ 5UL*i+0UL ] * 11316496UL +
                        (ulong)raw_base58[ 5UL*i+1UL ] * 195112UL   +
                        (ulong)raw_base58[ 5UL*i+2UL ] * 3364UL     +
                        (ulong)raw_base58[ 5UL*i+3UL ] * 58UL       +
                        (ulong)raw_base58[ 5UL*i+4UL ] * 1UL;


  /* Using the table, convert to overcomplete base 2^32 (terms can be
     larger than 2^32).  We need to be careful about overflow.

     For N==32, the largest anything in binary can get is binary[7]:
     even if intermediate[i]==58^5-1 for all i, then binary[7] < 2^63.

     For N==64, the largest anything in binary can get is binary[13]:
     even if intermediate[i]==58^5-1 for all i, then binary[13] <
     2^63.998.  Hanging in there, just by a thread! */

  ulong binary[ BINARY_SZ ];
  for( ulong j=0UL; j<BINARY_SZ; j++ ) {
    ulong acc=0UL;
    for( ulong i=0UL; i<INTERMEDIATE_SZ; i++ )
      acc += (ulong)intermediate[ i ] * (ulong)SUFFIX(dec_table)[ i ][ j ];
    binary[ j ] = acc;
  }

  /* Make sure each term is less than 2^32.

     For N==32, we have plenty of headroom in binary, so overflow is
     not a concern this time.

     For N==64, even if we add 2^32 to binary[13], it is still 2^63.998,
     so this won't overflow. */

  for( ulong i=BINARY_SZ-1UL; i>0UL; i-- ) {
    binary[ i-1UL ] += (binary[i] >> 32);
    binary[ i     ] &= 0xFFFFFFFFUL;
  }

  /* If the largest term is 2^32 or bigger, it means N is larger than
     what can fit in BYTE_CNT bytes.  This can be triggered, by passing
     a base58 string of all 'z's for example. */

  if( FD_UNLIKELY( binary[ 0UL ] > 0xFFFFFFFFUL ) ) return NULL;

  /* Convert each term to big endian for the final output */

  uint * out_as_uint = (uint*)out;
  for( ulong i=0UL; i<BINARY_SZ; i++ ) {
    out_as_uint[ i ] = fd_uint_bswap( (uint)binary[ i ] );
  }
  /* Make sure the encoded version has the same number of leading '1's
     as the decoded version has leading 0s. The check doesn't read past
     the end of encoded, because '\0' != '1', so it will return NULL. */

  ulong leading_zero_cnt = 0UL;
  for( ; leading_zero_cnt<BYTE_CNT; leading_zero_cnt++ ) {
    if( out[ leading_zero_cnt ] ) break;
    if( FD_UNLIKELY( encoded[ leading_zero_cnt ] != '1' ) ) return NULL;
  }
  if( FD_UNLIKELY( encoded[ leading_zero_cnt ] == '1' ) ) return NULL;
  return out;
}

#undef RAW58_SZ
#undef ENCODED_SZ
#undef SUFFIX

#undef BINARY_SZ
#undef BYTE_CNT
#undef INTERMEDIATE_SZ
#undef N
