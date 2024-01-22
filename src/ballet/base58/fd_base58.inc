
#define SUFFIX(s) FD_EXPAND_THEN_CONCAT2(s, N)
#define ENCODED_SZ() FD_EXPAND_THEN_CONCAT3(FD_BASE58_ENCODED_, N, _SZ)
#define RAW58_SZ        (INTERMEDIATE_SZ*5UL)

char *
SUFFIX(fd_base58_encode_) ( uchar const * bytes,
                            char        * out    ){
  /* Count leading zeros (needed for final output) */
  ulong zero_cnt = 0UL;
  while( zero_cnt<BYTE_CNT && !bytes[ zero_cnt ] ) zero_cnt++;

  /* N = sum_i bytes[i] * 2^(8*(BYTE_CNT-1-i)) */

  /* Convert N to 32-bit limbs:
     N = sum_i binary[i] * 2^(32*(BINARY_SZ-1-i)) */
  uint binary[ BINARY_SZ ];
  uint const * bytes_as_uint = (uint const *)bytes;
  for( ulong i=0UL; i<BINARY_SZ; i++ ) binary[i] = fd_uint_bswap( bytes_as_uint[ i ] );


  ulong R1div = 656356768UL; /* = 58^5 */
  /* Convert to the intermediate format:
       N = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i))
     Initially, we don't require intermediate[i] < 58^5, but we do want to make
     sure the sums don't overflow. */
  ulong intermediate[INTERMEDIATE_SZ] = { 0UL };
#if N==32
     /* The worst case is if binary[7] is (2^32)-1. In that case
        intermediate[8] will be be just over 2^63, which is fine. */
  for( ulong i=0UL; i < BINARY_SZ; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[j+1UL] += (ulong)binary[i] * (ulong)SUFFIX(enc_table)[i][j];
#elif N==64
  /* If we do it the same way as the 32B conversion, intermediate[16] can
     overflow when the input is sufficiently large.  We'll do a mini-reduction
     after the first 8 steps.  After the first 8 terms, the largest
     intermediate[16] can be is 2^63.87.  Then, after reduction it'll be at
     most 58^5, and after adding the last terms, it won't exceed 2^63.1.  We do
     need to be cautious that the mini-reduction doesn't cause overflow in
     intermediate[15] though.  Pre-mini-reduction, it's at most 2^63.05.  The
     mini-reduction adds at most 2^64/58^5, which is negligible.  With the
     final terms, it won't exceed 2^63.69, which is fine. */
  for( ulong i=0UL; i < 8UL; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[j+1UL] += (ulong)binary[i] * (ulong)SUFFIX(enc_table)[i][j];
  /* Mini-reduction */
  intermediate[15] += intermediate[16]/R1div;
  intermediate[16] %= R1div;
  /* Finish iterations */
  for( ulong i=8UL; i < BINARY_SZ; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[j+1UL] += (ulong)binary[i] * (ulong)SUFFIX(enc_table)[i][j];
#else
#error "Check overflow"
#endif

  /* Now we make sure each term is less than 58^5. Again, we have to be a bit
     careful of overflow. */
#if N==32
  /* In the worst case, as before, intermediate[8] will be just over 2^63 and
     intermediate[7] will be just over 2^62.6.  In the first step, we'll add
     floor(intermediate[8]/58^5) to intermediate[7].  58^5 is pretty big
     though, so intermediate[7] barely budges, and this is still fine. */
#elif N==64
  /* In the worst case, the biggest entry in intermediate at this point is
     2^63.87, and in the worst case, we add (2^64-1)/58^5, which is still about
     2^63.87. */
#endif
  for( ulong i=INTERMEDIATE_SZ-1UL; i>0UL; i-- ) {
    intermediate[i-1UL] += (intermediate[i]/R1div);
    intermediate[i] %= R1div;
  }


  /* Convert intermediate form to base 58.  This form of conversion exposes
     tons of ILP.
       N = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */
  uchar raw_base58[ RAW58_SZ ];
  for( ulong i=0UL; i<INTERMEDIATE_SZ; i++) {
    ulong v = intermediate[i];
    raw_base58[5UL*i+4UL] = (uchar)((v/1UL       )%58UL);
    raw_base58[5UL*i+3UL] = (uchar)((v/58UL      )%58UL);
    raw_base58[5UL*i+2UL] = (uchar)((v/3364UL    )%58UL);
    raw_base58[5UL*i+1UL] = (uchar)((v/195112UL  )%58UL);
    raw_base58[5UL*i+0UL] = (uchar)( v/11316496UL); /* We know this one is less than 58 */
  }


  /* Finally, actually convert to the string.  We have to ignore all the
     leading zeros in raw_base58 and instead insert zero_cnt leading '1'
     characters */
  ulong skip = 0UL;
  while( skip<RAW58_SZ && !raw_base58[ skip ] ) skip++;

  for( ulong i=0UL; i<(zero_cnt+RAW58_SZ-skip); i++ )
    out[ i ] = fd_char_if( i<zero_cnt, '1', base58_chars[ raw_base58[ i-zero_cnt+skip ] ] );
  out[ zero_cnt+RAW58_SZ-skip ] = '\0';

  return out;
}

uchar *
SUFFIX(fd_base58_decode_)( char const * encoded,
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


  /* N = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */
  uchar raw_base58[ RAW58_SZ ];
  /* Prepend enough 0s to make it exactly RAW58_SZ characters */
  ulong prepend_0 = RAW58_SZ-char_cnt;
  for( ulong j=0UL; j<RAW58_SZ; j++ )
    raw_base58[ j ] = (j<prepend_0) ? (uchar)0 : base58_inverse[ encoded[ j-prepend_0 ] - BASE58_INVERSE_TABLE_OFFSET ];


  /* Convert to the intermediate format (base 58^5):
       N = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i)) */
  ulong intermediate[ INTERMEDIATE_SZ ];
  for( ulong i=0UL; i<INTERMEDIATE_SZ; i++ )
    intermediate[ i ] = (ulong)raw_base58[ 5UL*i+0UL ] * 11316496UL +
                        (ulong)raw_base58[ 5UL*i+1UL ] * 195112UL   +
                        (ulong)raw_base58[ 5UL*i+2UL ] * 3364UL     +
                        (ulong)raw_base58[ 5UL*i+3UL ] * 58UL       +
                        (ulong)raw_base58[ 5UL*i+4UL ] * 1UL;


  /* Using the table, convert to overcomplete base 2^32 (terms can be larger
     than 2^32).  We need to be careful about overflow. */
# if   N==32
  /* The largest anything in binary can get is binary[7]: if
     intermediate[i]==58^5-1 for all i, then binary[7] will be < 2^63. */
# elif N==64
  /* The largest anything in binary can get is binary[13]: if
     intermediate[i]==58^5-1 for all i, then binary[13] will be 2^63.998.
     Hanging in there, just by a thread! */
# else
#   error "Check overflow"
# endif
  ulong binary[BINARY_SZ];
  for( ulong j=0UL; j<BINARY_SZ; j++ ) {
    ulong acc=0UL;
    for( ulong i=0UL; i<INTERMEDIATE_SZ; i++ )
      acc += (ulong)intermediate[ i ] * (ulong)SUFFIX(dec_table)[i][j];
    binary[ j ] = acc;
  }

  /* Make sure each term is less than 2^32. */
# if   N==32
  /* We have plenty of headroom, in binary, so overflow is not a concern this
     time. */
# elif N==64
  /* Even if we add 2^32 to binary[13], it is still 2^63.998, so this won't
     overflow. */
# endif
  for( ulong i=BINARY_SZ-1UL; i>0UL; i-- ) {
    binary[ i-1UL ] += (binary[i] >> 32);
    binary[ i     ] &= 0xFFFFFFFFUL;
  }
  /* If the largest term is 2^32 or bigger, it means N is larger than what can
     fit in BYTE_CNT bytes.  This can be triggered, by passing a base58 string
     of all 'z's for example. */
  if( FD_UNLIKELY( binary[ 0UL ] > 0xFFFFFFFFUL ) ) return NULL;

  /* Convert each term to big endian for the final output */
  uint * out_as_uint = (uint*)out;
  for( ulong i=0UL; i<BINARY_SZ; i++ ) {
    out_as_uint[ i ] = fd_uint_bswap( (uint)binary[ i ] );
  }
  /* Make sure the encoded version has the same number of leading '1's as the
     decoded version has leading 0s */
  ulong leading_zero_cnt = 0UL;
  while( !out[ leading_zero_cnt ] ) if( FD_UNLIKELY( encoded[ leading_zero_cnt++ ] != '1' ) ) return NULL;
  if( FD_UNLIKELY( encoded[ leading_zero_cnt ] == '1' ) ) return NULL;
  return out;
}

#undef RAW58_SZ
#undef BINARY_SZ
#undef ENCODED_SZ
#undef SUFFIX
#undef N
#undef BYTE_CNT
#undef INTERMEDIATE_SZ
