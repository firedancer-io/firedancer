#include "../fd_ballet_base.h"

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Interprets the supplied 32 bytes as a large big-endian integer, and converts
   it to a nul-terminated base58 string of at least 32 and at most most 44
   characters.  Suitable for printing Solana account addresses.  This is high
   performance, but base58 is an inherently slow format and should not be used
   in any performance critical places except where absolutely necessary. */
char *
fd_base58_encode_32B(
    const uchar bytes[32],
    char out[45] ) {
  /* Contains the unique values less than 58^5 such that
     2^(32*(7-j)) = sum_k table[j][k]*58^(5*(7-k)) */
  static const uint table[8][8] = {
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
  ulong zero_cnt = 0;
  while( zero_cnt<32 && !bytes[ zero_cnt ] ) zero_cnt++;

  /* N = sum_i acct_addr[i] * 2^(8*(31-i)) */

  /* Convert N to 32-bit limbs */
  uint binary[8];
  for( ulong i=0UL; i<8; i++ ) {
    binary[i] = fd_uint_bswap( *(uint*)(&bytes[ 4UL*i ]) );
  }
  /* Now N = sum_i binary[i] * 2^(32*(7-i)) */
  ulong R1div = 656356768UL; /* = 58^5 */
  /* Convert to the intermediate format:
       N = sum_i intermediate[i] * 58^(5*(8-i))
     Initially, we don't require intermediate[i] < 58^5, but we do want to make
     sure the sums don't overflow.  The worst case is if binary[7] is (2^32)-1.
     In that case intermediate[8] will be be just over 2^63, which is fine. */
  ulong intermediate[9] = { 0UL };
  for( ulong i=0UL; i < 8UL; i++ )
    for( ulong j=0UL; j < 8UL; j++ )
      intermediate[j+1UL] += (ulong)binary[i] * (ulong)table[i][j];
  /* Now we make sure each term is less than 58^5. Again, we have to be a bit
     careful of overflow. In the worst case, as before, intermediate[8] will be
     just over 2^63 and intermediate[7] will be just over 2^62.6.  In the first
     step, we'll add floor(intermediate[8]/58^5) to intermediate[7].  58^5 is
     pretty big though, so intermediate[7] barely budges, and this is still
     fine. */
  for( ulong i=8UL; i>0UL; i-- ) {
    intermediate[i-1UL] += (intermediate[i]/R1div);
    intermediate[i] %= R1div;
  }
  /* Convert intermediate form to base 58.  This form of conversion exposes
     tons of ILP.
       N = sum_i raw_base58[i] * 58^(44-i) */
  uchar raw_base58[45];
  for( ulong i=0UL; i<9UL; i++) {
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
  ulong b58_zero_cnt = 0;
  while( b58_zero_cnt<45UL && !raw_base58[ b58_zero_cnt ] ) b58_zero_cnt++;
  ulong out_i = 0UL;
  ulong raw_j = b58_zero_cnt;
  for( ; out_i<zero_cnt; out_i++ ) out[ out_i   ] = '1';
  for( ; raw_j<45UL;     raw_j++ ) out[ out_i++ ] = base58_chars[raw_base58[ raw_j ]];
  out[ out_i ] = '\0';
  return out;
}

  /* FIXME: TODO */
/*
void
fd_base58_encode_64B(
    uchar bytes[64],
    char out[89] ) {
}
 * */
