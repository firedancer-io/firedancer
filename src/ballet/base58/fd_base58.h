#include "../fd_ballet_base.h"

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const uchar base58_inverse[] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 255, 255, 255, 255, 255, 255, 255,
  9, 10, 11, 12, 13, 14, 15, 16, 255, 17, 18, 19, 20, 21, 255, 22,
  23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 255, 255, 255, 255, 255, 255,
  33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 255, 44, 45, 46, 47,
  48, 49, 50, 51, 52, 53, 54, 55, 56, 57 };

#define FD_BASE58_ENCODED_32_LEN (44UL) /* Computed as ceil(log_58(256^32 - 1)) */
#define FD_BASE58_ENCODED_32_SZ  (FD_BASE58_ENCODED_32_LEN+1UL) /* Including the nul terminator */
#define FD_BASE58_ENCODED_64_LEN (88UL) /* Computed as ceil(log_58(256^64 - 1)) */
#define FD_BASE58_ENCODED_64_SZ  (FD_BASE58_ENCODED_64_LEN+1UL) /* Including the nul terminator */

/* Interprets the supplied 32 bytes as a large big-endian integer, and converts
   it to a nul-terminated base58 string of at least 32 and at most most 44
   characters, storing the output in out.  Returns out.
   This conversion is suitable for printing Solana account addresses.  This is
   high performance (~100 ns), but base58 is an inherently slow format and
   should not be used in any performance critical places except where
   absolutely necessary. */
char *
fd_base58_encode_32(
    const uchar bytes[32],
    char out[FD_BASE58_ENCODED_32_SZ] ) {
#define BYTE_CNT        (32UL)
#define BINARY_SZ       (BYTE_CNT/4UL)
#define INTERMEDIATE_SZ (9UL) /* Computed by ceil(log_(58^5) (256^32-1)) */
#define RAW58_SZ        (INTERMEDIATE_SZ*5UL)
  /* Contains the unique values less than 58^5 such that
     2^(32*(7-j)) = sum_k table[j][k]*58^(5*(7-k)) */
  /* The second dimension of this table is actually 
     ceil(log_(58^5) (2^(32*(BINARY_SZ-1))), but that's almost always
     INTERMEDIATE_SZ-1 */
  static const uint table[BINARY_SZ][INTERMEDIATE_SZ-1UL] = {
    {513735, 77223048, 437087610, 300156666, 605448490, 214625350, 141436834, 379377856},
    {     0,    78508, 646269101, 118408823,  91512303, 209184527, 413102373, 153715680},
    {     0,        0,     11997, 486083817,   3737691, 294005210, 247894721, 289024608},
    {     0,        0,         0,      1833, 324463681, 385795061, 551597588,  21339008},
    {     0,        0,         0,         0,       280, 127692781, 389432875, 357132832},
    {     0,        0,         0,         0,         0,        42, 537767569, 410450016},
    {     0,        0,         0,         0,         0,         0,         6, 356826688},
    {     0,        0,         0,         0,         0,         0,         0,         1}
  };
  /* Count leading zeros (needed for final output) */
  ulong zero_cnt = 0UL;
  while( zero_cnt<BYTE_CNT && !bytes[ zero_cnt ] ) zero_cnt++;

  /* N = sum_i acct_addr[i] * 2^(8*(31-i)) */

  /* Convert N to 32-bit limbs */
  uint binary[BINARY_SZ];
  for( ulong i=0UL; i<BINARY_SZ; i++ ) {
    binary[i] = fd_uint_bswap( *(uint*)(&bytes[ 4UL*i ]) );
  }
  /* Now N = sum_i binary[i] * 2^(32*(7-i)) */
  ulong R1div = 656356768UL; /* = 58^5 */
  /* Convert to the intermediate format:
       N = sum_i intermediate[i] * 58^(5*(8-i))
     Initially, we don't require intermediate[i] < 58^5, but we do want to make
     sure the sums don't overflow.  The worst case is if binary[7] is (2^32)-1.
     In that case intermediate[8] will be be just over 2^63, which is fine. */
  ulong intermediate[INTERMEDIATE_SZ] = { 0UL };
  for( ulong i=0UL; i < BINARY_SZ; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[j+1UL] += (ulong)binary[i] * (ulong)table[i][j];
  /* Now we make sure each term is less than 58^5. Again, we have to be a bit
     careful of overflow. In the worst case, as before, intermediate[8] will be
     just over 2^63 and intermediate[7] will be just over 2^62.6.  In the first
     step, we'll add floor(intermediate[8]/58^5) to intermediate[7].  58^5 is
     pretty big though, so intermediate[7] barely budges, and this is still
     fine. */
  for( ulong i=INTERMEDIATE_SZ-1UL; i>0UL; i-- ) {
    intermediate[i-1UL] += (intermediate[i]/R1div);
    intermediate[i] %= R1div;
  }
  /* Convert intermediate form to base 58.  This form of conversion exposes
     tons of ILP.
       N = sum_i raw_base58[i] * 58^(44-i) */
  uchar raw_base58[RAW58_SZ];
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
  ulong b58_zero_cnt = 0UL;
  while( b58_zero_cnt<RAW58_SZ && !raw_base58[ b58_zero_cnt ] ) b58_zero_cnt++;
  ulong out_i = 0UL;
  ulong raw_j = b58_zero_cnt;
  for( ; out_i<zero_cnt; out_i++ ) out[ out_i   ] = '1';
  for( ; raw_j<RAW58_SZ; raw_j++ ) out[ out_i++ ] = base58_chars[ raw_base58[ raw_j ] ];
  out[ out_i ] = '\0';
  return out;
#undef BYTE_CNT
#undef BINARY_SZ
#undef INTERMEDIATE_SZ
#undef RAW58_SZ
}

/* Converts the base58 encoded number stored in the cstr encoded to a 256 bit
   number, which is written to out (big endian).  Returns out on success and
   NULL if the input string is invalid in some way (illegal base58 character or
   decodes to something other than 32 bytes). */
uchar *
fd_base58_decode_32(
    const char * encoded,
    uchar out[32] ) {
#define BYTE_CNT        (32UL)
#define BINARY_SZ       (BYTE_CNT/4UL)
#define INTERMEDIATE_SZ (9UL) /* Computed by ceil(log_(58^5) (256^32-1)) */
#define RAW58_SZ        (INTERMEDIATE_SZ*5UL)

  /* Contains the unique values less than 2^32 such that
     58^(5*(8-j)) = sum_k table[j][k]*2^(32*(7-k)) */
  static const uint table[INTERMEDIATE_SZ][BINARY_SZ] = {
    { 1277U,2650397687U,3801011509U,2074386530U,3248244966U, 687255411U,2959155456U,         0U},
    {    0U,      8360U,1184754854U,3047609191U,3418394749U, 132556120U,1199103528U,         0U},
    {    0U,         0U,     54706U,2996985344U,1834629191U,3964963911U, 485140318U,1073741824U},
    {    0U,         0U,         0U,    357981U,1476998812U,3337178590U,1483338760U,4194304000U},
    {    0U,         0U,         0U,         0U,   2342503U,3052466824U,2595180627U,  17825792U},
    {    0U,         0U,         0U,         0U,         0U,  15328518U,1933902296U,4063920128U},
    {    0U,         0U,         0U,         0U,         0U,         0U, 100304420U,3355157504U},
    {    0U,         0U,         0U,         0U,         0U,         0U,         0U, 656356768U},
    {    0U,         0U,         0U,         0U,         0U,         0U,         0U,         1U}
  };

  /* Validate string and count characters before the nul terminator */
  ulong char_cnt = 0UL;
  char c;
  while( (c=encoded[ char_cnt ]) ) {
    char_cnt++;
    if( FD_UNLIKELY( (c<'1') | (c>'z')                     ) ) return NULL;
    if( FD_UNLIKELY( 255==base58_inverse[ (ulong)(c-'1') ] ) ) return NULL;
    if( FD_UNLIKELY( char_cnt > FD_BASE58_ENCODED_32_LEN   ) ) return NULL;
  }

  /* N = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */
  uchar raw_base58[RAW58_SZ];
  ulong raw_j = 0UL;
  for(            ; raw_j<RAW58_SZ - char_cnt; raw_j++ ) raw_base58[ raw_j   ] = (uchar)0;
  for( ulong i=0UL; i<char_cnt;                i++     ) raw_base58[ raw_j++ ] = base58_inverse[ (ulong)(encoded[ i ] - '1') ];

  /* Convert to the intermediate format (base 58^5):
       N = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i)) */
  ulong intermediate[INTERMEDIATE_SZ] = { 0UL };
  for( ulong i=0UL; i<INTERMEDIATE_SZ; i++ ) {
    intermediate[ i ] = (ulong)raw_base58[ 5UL*i+0UL ] * 11316496UL +
                        (ulong)raw_base58[ 5UL*i+1UL ] * 195112UL   +
                        (ulong)raw_base58[ 5UL*i+2UL ] * 3364UL     +
                        (ulong)raw_base58[ 5UL*i+3UL ] * 58UL       +
                        (ulong)raw_base58[ 5UL*i+4UL ] * 1UL;
  }

  /* Using the table, convert to overcomplete base 2^32 (terms can be larger
     than 2^32).  We need to be careful about overflow, but the largest
     anything in binary can get is binary[7]: if intermediate[i]==58^5-1 for
     all i, then binary[7] will be < 2^63. */
  ulong binary[BINARY_SZ] = { 0UL };
  for( ulong i=0UL; i < INTERMEDIATE_SZ; i++ )
    for( ulong j=0UL; j < BINARY_SZ; j++ )
      binary[ j ] += (ulong)intermediate[ i ] * (ulong)table[i][j];

  /* Make sure each term is less than 2^32.  We have plenty of headroom, in
     binary, so overflow is not a concern this time. */
  for( ulong i=BINARY_SZ-1UL; i>0UL; i-- ) {
    binary[ i-1UL ] += (binary[i] >> 32);
    binary[ i     ] &= 0xFFFFFFFFUL;
  }
  /* If the largest term is 2^32 or bigger, it means N is larger than what can
     fit in BYTE_CNT bytes.  This can be triggered, by passing a base58 string
     of all 'z's for example. */
  if( FD_UNLIKELY( binary[ 0UL ] > 0xFFFFFFFFUL ) ) return NULL;

  /* Convert each term to big endian for the final output */
  for( ulong i=0UL; i<BINARY_SZ; i++ ) {
    *(uint*)(&out[ 4UL*i ]) = fd_uint_bswap( (uint)binary[ i ] );
  }
  /* Make sure the encoded version has the same number of leading '1's as the
     decoded version has leading 0s */
  ulong leading_zero_cnt = 0UL;
  while( !out[ leading_zero_cnt ] ) if( FD_UNLIKELY( encoded[ leading_zero_cnt++ ] != '1' ) ) return NULL;
  if( FD_UNLIKELY( encoded[ leading_zero_cnt ] == '1' ) ) return NULL;
  return out;
#undef BYTE_CNT
#undef BINARY_SZ
#undef INTERMEDIATE_SZ
#undef RAW58_SZ
}

/* Interprets the supplied 64 bytes as a large big-endian integer, and converts
   it to a nul-terminated base58 string of at least 64 and at most most 88
   characters, storing the output in out.  Returns out.
   This conversion is suitable for printing Solana transaction signatures.
   This is high performance (~200ns), but base58 is an inherently slow format
   and should not be used in any performance critical places except where
   absolutely necessary. */
char *
fd_base58_encode_64(
    uchar bytes[64],
    char out[FD_BASE58_ENCODED_64_SZ] ) {
#define BYTE_CNT        (64UL)
#define BINARY_SZ       (BYTE_CNT/4UL)
#define INTERMEDIATE_SZ (18UL) /* Computed by ceil(log_(58^5) (256^64-1)) */
#define RAW58_SZ        (INTERMEDIATE_SZ*5UL)
  /* Contains the unique values less than 58^5 such that
     2^(32*(15-j)) = sum_k table[j][k]*58^(5*(16-k)) */
  static const uint table[BINARY_SZ][INTERMEDIATE_SZ-1UL] = {
    { 2631,149457141,577092685,632289089, 81912456,221591423,502967496,403284731,377738089,492128779,   746799,366351977,190199623, 38066284,526403762,650603058,454901440},
    {    0,      402, 68350375, 30641941,266024478,208884256,571208415,337765723,215140626,129419325,480359048,398051646,635841659,214020719,136986618,626219915, 49699360},
    {    0,        0,       61,295059608,141201404,517024870,239296485,527697587,212906911,453637228,467589845,144614682, 45134568,184514320,644355351,104784612,308625792},
    {    0,        0,        0,        9,256449755,500124311,479690581,372802935,413254725,487877412,520263169,176791855, 78190744,291820402, 74998585,496097732, 59100544},
    {    0,        0,        0,        0,        1,285573662,455976778,379818553,100001224,448949512,109507367,117185012,347328982,522665809, 36908802,577276849, 64504928},
    {    0,        0,        0,        0,        0,        0,143945778,651677945,281429047,535878743,264290972,526964023,199595821,597442702,499113091,424550935,458949280},
    {    0,        0,        0,        0,        0,        0,        0, 21997789,294590275,148640294,595017589,210481832,404203788,574729546,160126051,430102516, 44963712},
    {    0,        0,        0,        0,        0,        0,        0,        0,  3361701,325788598, 30977630,513969330,194569730,164019635,136596846,626087230,503769920},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,   513735, 77223048,437087610,300156666,605448490,214625350,141436834,379377856},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,        0,    78508,646269101,118408823, 91512303,209184527,413102373,153715680},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,    11997,486083817,  3737691,294005210,247894721,289024608},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,     1833,324463681,385795061,551597588, 21339008},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,      280,127692781,389432875,357132832},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,       42,537767569,410450016},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        6,356826688},
    {    0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        0,        1}
  };
  /* Count leading zeros (needed for final output) */
  ulong zero_cnt = 0UL;
  while( zero_cnt<BYTE_CNT && !bytes[ zero_cnt ] ) zero_cnt++;

  /* N = sum_i acct_addr[i] * 2^(8*(63-i)) */

  /* Convert N to 32-bit limbs */
  uint binary[BINARY_SZ];
  for( ulong i=0UL; i<BINARY_SZ; i++ ) {
    binary[i] = fd_uint_bswap( *(uint*)(&bytes[ 4UL*i ]) );
  }
  /* Now N = sum_i binary[i] * 2^(32*(15-i)) */
  ulong R1div = 656356768UL; /* = 58^5 */
  /* Convert to the intermediate format:
       N = sum_i intermediate[i] * 58^(5*(17-i))
     Initially, we don't require intermediate[i] < 58^5, but we do want to make
     sure the sums don't overflow.  If we do it the same way as the 32B
     conversion, the intermediate[16] can overflow when the input is
     sufficiently large.  We'll do a mini-reduction after the first 8 steps.
     After the first 8 terms, the largest intermediate[16] can be is 2^63.87.
     Then, after reduction it'll be at most 58^5, and after adding the last
     terms, it won't exceed 2^63.1.  We do need to be cautious that the
     mini-reduction doesn't cause overflow in intermediate[15] though.
     Pre-mini-reduction, it's at most 2^63.05.  The mini-reduction adds at most
     2^64/58^5, which is negligible.  With the final terms, it won't exceed
     2^63.69, which is fine. */
  ulong intermediate[INTERMEDIATE_SZ] = { 0UL };
  for( ulong i=0UL; i < 8UL; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[j+1UL] += (ulong)binary[i] * (ulong)table[i][j];
  /* Mini-reduction */
  intermediate[15] += intermediate[16]/R1div;
  intermediate[16] %= R1div;
  /* Finish iterations */
  for( ulong i=8UL; i < BINARY_SZ; i++ )
    for( ulong j=0UL; j < INTERMEDIATE_SZ-1UL; j++ )
      intermediate[j+1UL] += (ulong)binary[i] * (ulong)table[i][j];
  /* Now we make sure each term is less than 58^5. Again, we have to be a bit
     careful of overflow.  In the worst case, the biggest entry in intermediate
     at this point is 2^63.87, and in the worst case, we add (2^64-1)/58^5,
     which is still about 2^63.87. */
  for( ulong i=INTERMEDIATE_SZ-1UL; i>0UL; i-- ) {
    intermediate[i-1UL] += (intermediate[i]/R1div);
    intermediate[i] %= R1div;
  }
  /* Convert intermediate form to base 58.  This form of conversion exposes
     tons of ILP.
       N = sum_i raw_base58[i] * 58^(44-i) */
  uchar raw_base58[RAW58_SZ];
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
     characters. Since 256^64 < 58^88, we know there are at most 88 characters
     in the base58 expression, which means there must be at least two leading
     zeros. */
  ulong b58_zero_cnt = 2UL;
  while( b58_zero_cnt<RAW58_SZ && !raw_base58[ b58_zero_cnt ] ) b58_zero_cnt++;
  ulong out_i = 0UL;
  ulong raw_j = b58_zero_cnt;
  for( ; out_i<zero_cnt; out_i++ ) out[ out_i   ] = '1';
  for( ; raw_j<RAW58_SZ; raw_j++ ) out[ out_i++ ] = base58_chars[raw_base58[ raw_j ]];
  out[ out_i ] = '\0';
  return out;
#undef BYTE_CNT
#undef BINARY_SZ
#undef INTERMEDIATE_SZ
#undef RAW58_SZ
}

/* Converts the base58 encoded number stored in the cstr encoded to a 512 bit
   number, which is written to out (big endian).  Returns out on success and
   NULL if the input string is invalid in some way (illegal base58 character or
   decodes to something other than 64 bytes). */
uchar *
fd_base58_decode_64(
    const char * encoded,
    uchar out[ 64 ] ) {
#define BYTE_CNT        (64UL)
#define BINARY_SZ       (BYTE_CNT/4UL)
#define INTERMEDIATE_SZ (18UL) /* Computed by ceil(log_(58^5) (256^64-1)) */
#define RAW58_SZ        (INTERMEDIATE_SZ*5UL)

  /* Contains the unique values less than 2^32 such that
     58^(5*(17-j)) = sum_k table[j][k]*2^(32*(15-k)) */
  static const uint table[INTERMEDIATE_SZ][BINARY_SZ] = {
    {    249448U,3719864065U, 173911550U,4021557284U,3115810883U,2498525019U,1035889824U, 627529458U,3840888383U,3728167192U,
                                                          2901437456U,3863405776U,1540739182U,1570766848U,         0U,         0U},
    {         0U,   1632305U,1882780341U,4128706713U,1023671068U,2618421812U,2005415586U,1062993857U,3577221846U,3960476767U,
                                                          1695615427U,2597060712U, 669472826U, 104923136U,         0U,         0U},
    {         0U,         0U,  10681231U,1422956801U,2406345166U,4058671871U,2143913881U,4169135587U,2414104418U,2549553452U,
                                                          997594232U, 713340517U,2290070198U,1103833088U,         0U,         0U},
    {         0U,         0U,         0U,  69894212U,1038812943U,1785020643U,1285619000U,2301468615U,3492037905U, 314610629U,
                                                          2761740102U,3410618104U,1699516363U, 910779968U,         0U,         0U},
    {         0U,         0U,         0U,         0U, 457363084U, 927569770U,3976106370U,1389513021U,2107865525U,3716679421U,
                                                          1828091393U,2088408376U, 439156799U,2579227194U,         0U,         0U},
    {         0U,         0U,         0U,         0U,         0U,2992822783U, 383623235U,3862831115U, 112778334U, 339767049U,
                                                          1447250220U, 486575164U,3495303162U,2209946163U, 268435456U,         0U},
    {         0U,         0U,         0U,         0U,         0U,         4U,2404108010U,2962826229U,3998086794U,1893006839U,
                                                          2266258239U,1429430446U, 307953032U,2361423716U, 176160768U,         0U},
    {         0U,         0U,         0U,         0U,         0U,         0U,        29U,3596590989U,3044036677U,1332209423U,
                                                          1014420882U, 868688145U,4264082837U,3688771808U,2485387264U,         0U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,       195U,1054003707U,3711696540U,
                                                          582574436U,3549229270U,1088536814U,2338440092U,1468637184U,         0U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,      1277U,2650397687U,
                                                          3801011509U,2074386530U,3248244966U, 687255411U,2959155456U,         0U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,      8360U,
                                                          1184754854U,3047609191U,3418394749U, 132556120U,1199103528U,         0U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,
                                                               54706U,2996985344U,1834629191U,3964963911U, 485140318U,1073741824U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,
                                                                   0U,    357981U,1476998812U,3337178590U,1483338760U,4194304000U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,
                                                                   0U,         0U,   2342503U,3052466824U,2595180627U,  17825792U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,
                                                                   0U,         0U,         0U,  15328518U,1933902296U,4063920128U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,
                                                                   0U,         0U,         0U,         0U, 100304420U,3355157504U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,
                                                                   0U,         0U,         0U,         0U,         0U, 656356768U},
    {         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,
                                                                   0U,         0U,         0U,         0U,         0U,         1U}

  };

  /* Validate string and count characters before the nul terminator */
  ulong char_cnt = 0UL;
  char c;
  while( (c=encoded[ char_cnt ]) ) {
    char_cnt++;
    if( FD_UNLIKELY( (c<'1') | (c>'z')                     ) ) return NULL;
    if( FD_UNLIKELY( 255==base58_inverse[ (ulong)(c-'1') ] ) ) return NULL;
    if( FD_UNLIKELY( char_cnt > FD_BASE58_ENCODED_64_LEN   ) ) return NULL;
  }

  /* N = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */
  uchar raw_base58[RAW58_SZ];
  ulong raw_j = 0UL;
  for(            ; raw_j<RAW58_SZ - char_cnt; raw_j++ ) raw_base58[ raw_j   ] = (uchar)0;
  for( ulong i=0UL; i<char_cnt;                i++     ) raw_base58[ raw_j++ ] = base58_inverse[ (ulong)(encoded[ i ] - '1') ];

  /* Convert to the intermediate format (base 58^5):
       N = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i)) */
  ulong intermediate[INTERMEDIATE_SZ] = { 0UL };
  for( ulong i=0UL; i<INTERMEDIATE_SZ; i++ ) {
    intermediate[ i ] = (ulong)raw_base58[ 5UL*i+0UL ] * 11316496UL +
                        (ulong)raw_base58[ 5UL*i+1UL ] * 195112UL   +
                        (ulong)raw_base58[ 5UL*i+2UL ] * 3364UL     +
                        (ulong)raw_base58[ 5UL*i+3UL ] * 58UL       +
                        (ulong)raw_base58[ 5UL*i+4UL ] * 1UL;
  }

  /* Using the table, convert to overcomplete base 2^32 (terms can be larger
     than 2^32).  We need to be careful about overflow, but the largest
     anything in binary can get is binary[13]: if intermediate[i]==58^5-1 for
     all i, then binary[13] will be 2^63.998. Hanging in there, just by a
     thread! */
  ulong binary[BINARY_SZ] = { 0UL };
  for( ulong i=0UL; i < INTERMEDIATE_SZ; i++ )
    for( ulong j=0UL; j < BINARY_SZ; j++ )
      binary[ j ] += (ulong)intermediate[ i ] * (ulong)table[i][j];

  /* Make sure each term is less than 2^32.  Even if we add 2^32 to binary[13],
     it is still 2^63.998, so this won't overflow. */
  for( ulong i=BINARY_SZ-1UL; i>0UL; i-- ) {
    binary[ i-1UL ] += (binary[i] >> 32);
    binary[ i     ] &= 0xFFFFFFFFUL;
  }
  /* If the largest term is 2^32 or bigger, it means N is larger than what can
     fit in BYTE_CNT bytes.  This can be triggered, by passing a base58 string
     of all 'z's for example. */
  if( FD_UNLIKELY( binary[ 0UL ] > 0xFFFFFFFFUL ) ) return NULL;

  /* Convert each term to big endian for the final output */
  for( ulong i=0UL; i<BINARY_SZ; i++ ) {
    *(uint*)(&out[ 4UL*i ]) = fd_uint_bswap( (uint)binary[ i ] );
  }
  /* Make sure the encoded version has the same number of leading '1's as the
     decoded version has leading 0s */
  ulong leading_zero_cnt = 0UL;
  while( !out[ leading_zero_cnt ] ) if( FD_UNLIKELY( encoded[ leading_zero_cnt++ ] != '1' ) ) return NULL;
  if( FD_UNLIKELY( encoded[ leading_zero_cnt ] == '1' ) ) return NULL;
  return out;
#undef BYTE_CNT
#undef BINARY_SZ
#undef INTERMEDIATE_SZ
#undef RAW58_SZ
}

#if FD_HAS_ALLOCA
/* Interprets byte_cnt bytes from bytes as a large big-endian integer, and
   converts it to a nul-terminated base58 string, storing the output in out.
   This writes at most out_cnt characters to out, including the nul terminator.
   Returns NULL if the supplied output buffer is not big enough, and returns
   out otherwise.  The length of a base58 string is data-dependent, but passing
   1+1.5*byte_cnt is sufficient (the actual coefficient is log_58(256)).
   This method is slow and the optimized fixed-size conversion methods should
   be used where possible. */
char *
fd_base58_encode_slow(
    const uchar * bytes,
    ulong byte_cnt,
    char * out,
    ulong out_cnt ) {
  /* Copy bytes to something we can clobber */
  ulong * quotient = fd_alloca( 16UL, byte_cnt * sizeof(ulong) );
  for( ulong j=0UL; j<byte_cnt; j++ ) quotient[j] = bytes[j];
  out_cnt--; /* Save room for nul */
  ulong * raw_base58 = fd_alloca( 16UL, out_cnt * sizeof(ulong) );

  ulong zero_cnt = 0UL;
  while( zero_cnt<byte_cnt && !bytes[ zero_cnt ] ) zero_cnt++;

  ulong last_nonzero = 0UL;
  /* Grade-school long division */
  ulong start_j = 0UL;
  for( ulong i=0UL; i<out_cnt; i++ ) {
    ulong remainder = 0UL;
    if( !quotient[ start_j ] ) start_j++;
    for( ulong j=start_j; j<byte_cnt; j++ ) {
      remainder = remainder*256UL + quotient[j];
      quotient[j] = remainder / 58UL;
      remainder %= 58UL;
    }
    raw_base58[ i ] = remainder;
    if( remainder ) last_nonzero = 1UL+i;
  }

  if( FD_UNLIKELY( last_nonzero + zero_cnt > out_cnt ) ) return NULL;
  for( ulong j=0UL; j<byte_cnt; j++ ) if( FD_UNLIKELY( quotient[ j ] ) ) return NULL; /* Output too small */

  /* Convert to base58 characters */
  ulong out_i = 0UL;
  ulong raw_j = 0UL;
  for( ; out_i<zero_cnt;     out_i++ ) out[ out_i   ] = '1';
  for( ; raw_j<last_nonzero; raw_j++ ) out[ out_i++ ] = base58_chars[ raw_base58[ last_nonzero-1UL-raw_j ] ];
  out[ out_i ] = '\0';

  return out;
}
/* Converts the base58-encoded number stored in the encoded_len length cstr
   encoded to a large integer which is written big-endian to out.  This writes
   exactly out_cnt bytes to out.  Returns out on success.  Returns NULL if
   encoded was not a valid base58 integer or if it decoded to a byte string
   with length not exactly out_cnt.
   This method is slow and the optimized fixed-size conversion methods should
   be used where possible. */
uchar *
fd_base58_decode_slow(
    const char * encoded,
    ulong encoded_len, /* excluding nul-terminator */
    uchar * out,
    ulong out_cnt ) {

  ulong zero_cnt = 0UL;
  while( zero_cnt<encoded_len && encoded[ zero_cnt ]=='1' ) out[ zero_cnt++ ] = (uchar)0;
  out += zero_cnt;
  encoded += zero_cnt;
  encoded_len -= zero_cnt;
  out_cnt -= zero_cnt;

  ulong * raw_base58 = fd_alloca( 16UL, encoded_len * sizeof(ulong) );

  for( ulong i=0UL; i<encoded_len; i++ ) {
    char c = encoded[ i ];
    if( FD_UNLIKELY( (c<'1') | (c>'z') ) ) return NULL;
    uchar raw = base58_inverse[ (ulong)(c-'1') ];
    if( FD_UNLIKELY( raw==255          ) ) return NULL;
    raw_base58[ i ] = raw;
  }

  /* Grade-school long division */
  ulong start_j = 0UL;
  for( ulong i=0UL; i<out_cnt; i++ ) {
    ulong remainder = 0UL;
    while( FD_LIKELY( start_j<encoded_len ) && !raw_base58[ start_j ] ) start_j++;
    for( ulong j=start_j; j<encoded_len; j++ ) {
      remainder = remainder*58UL + raw_base58[j];
      raw_base58[ j ] = remainder >> 8;
      remainder &= 0xFF;
    }
    out[ out_cnt-1UL-i ] = (uchar)remainder;
  }
  if( FD_UNLIKELY( !out[ 0UL ] ) ) return NULL; /* Wrong number of leading 1s */

  for( ulong j=start_j; j<encoded_len; j++ ) if( FD_UNLIKELY( raw_base58[ j ] ) ) return NULL; /* Output too small */

  return out-zero_cnt;
}
#endif /* FD_HAS_ALLOCA */
