static inline uint8x16_t
add_mod_255( uint8x16_t a,
             uint8x16_t b ) {
  uint8x16_t sum        = vaddq_u8( a, b );
  uint8x16_t overflowed = vcltq_u8( sum, a ); /* 0xFF where a+b>=256 */
  return vsubq_u8( sum, overflowed );        /* i.e. sum+1 */
}

static inline uint8x16_t
fwht_16( uint8x16_t x ) {
  static uchar const mask8[ 16 ] W_ATTR = { 0,0,0,0,0,0,0,0, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
  static uchar const mask4[ 16 ] W_ATTR = { 0,0,0,0, 0xFF,0xFF,0xFF,0xFF, 0,0,0,0, 0xFF,0xFF,0xFF,0xFF };
  static uchar const mask2[ 16 ] W_ATTR = { 0,0,0xFF,0xFF, 0,0,0xFF,0xFF, 0,0,0xFF,0xFF, 0,0,0xFF,0xFF };
  static uchar const mask1[ 16 ] W_ATTR = { 0,0xFF, 0,0xFF, 0,0xFF, 0,0xFF, 0,0xFF, 0,0xFF, 0,0xFF, 0,0xFF };
  /* Pair distance 8 */
  x = add_mod_255( veorq_u8( x, vld1q_u8( mask8 ) ), vextq_u8( x, x, 8 ) );
  /* Pair distance 4 */
  x = add_mod_255( veorq_u8( x, vld1q_u8( mask4 ) ), vreinterpretq_u8_u32( vrev64q_u32( vreinterpretq_u32_u8( x ) ) ) );
  /* Pair distance 2 */
  x = add_mod_255( veorq_u8( x, vld1q_u8( mask2 ) ), vreinterpretq_u8_u16( vrev32q_u16( vreinterpretq_u16_u8( x ) ) ) );
  /* Pair distance 1 */
  x = add_mod_255( veorq_u8( x, vld1q_u8( mask1 ) ), vrev16q_u8( x ) );
  return x;
}

/* fwht_vecs computes the unscaled 16*vec_cnt element FWHT mod 255 of
   the bytes in v[0..vec_cnt), in place.  vec_cnt must be a power of
   2 in [1, 16]. */
static inline void
fwht_vecs( uint8x16_t * v,
           ulong        vec_cnt ) {
  for( ulong h=1UL; h<vec_cnt; h<<=1 ) {
    for( ulong i=0UL; i<vec_cnt; i+=2UL*h ) for( ulong j=i; j<i+h; j++ ) {
      uint8x16_t a = v[ j   ];
      uint8x16_t b = v[ j+h ];
      v[ j   ] = add_mod_255( a, b );
      v[ j+h ] = add_mod_255( a, vmvnq_u8( b ) );
    }
  }
  for( ulong j=0UL; j<vec_cnt; j++ ) v[ j ] = fwht_16( v[ j ] );
}

/* mod255_u16 reduces each 16 bit lane mod 255 into [0, 255].  Since
   256==1 (mod 255), x == (x&0xFF) + (x>>8) (mod 255).  Applying that
   twice maps [0, 65535] to [0, 255]. */
static inline uint16x8_t
mod255_u16( uint16x8_t x ) {
  x = vaddq_u16( vandq_u16( x, vdupq_n_u16( 0xFF ) ), vshrq_n_u16( x, 8 ) ); /* <= 510 */
  x = vaddq_u16( vandq_u16( x, vdupq_n_u16( 0xFF ) ), vshrq_n_u16( x, 8 ) ); /* <= 255 */
  return x;
}

/* mul_twiddle multiplies each byte of x (a value mod 255) by the
   corresponding twiddle factor (a value in [0, 255]) and reduces the
   result mod 255 back to a byte. */
static inline uint8x16_t
mul_twiddle( uint8x16_t    x,
             short const * l_twiddle ) {
  uint16x8_t lo = vmovl_u8( vget_low_u8(  x ) );
  uint16x8_t hi = vmovl_u8( vget_high_u8( x ) );
  lo = vmulq_u16( lo, vreinterpretq_u16_s16( vld1q_s16( l_twiddle      ) ) ); /* <= 255*255 < 2^16 */
  hi = vmulq_u16( hi, vreinterpretq_u16_s16( vld1q_s16( l_twiddle+8UL ) ) );
  return vcombine_u8( vmovn_u16( mod255_u16( lo ) ), vmovn_u16( mod255_u16( hi ) ) );
}

/* exp_base( x, ... ) computes base^x_i in GF(2^8) for each byte x_i in
   the vector x, where x_i is interpreted as an integer mod 255.  See
   the AVX exp_{n} functions in fd_reedsol_pi.c for the derivation.
   exp_low[ i ] = base^i for i in [0,16), and m0..m3 are base^16,
   base^32, base^64, base^128 respectively. */
static inline uint8x16_t
exp_base( uint8x16_t    x,
          uchar const * exp_low,
          ulong         m0,
          ulong         m1,
          ulong         m2,
          ulong         m3 ) {
  uint8x16_t low  = vandq_u8( x, vdupq_n_u8( 0xF ) );
  uint8x16_t with = vqtbl1q_u8( vld1q_u8( exp_low ), low );
  with = vbslq_u8( vtstq_u8( x, vdupq_n_u8( 0x10 ) ), GF_MUL_VAR( with, m0 ), with );
  with = vbslq_u8( vtstq_u8( x, vdupq_n_u8( 0x20 ) ), GF_MUL_VAR( with, m1 ), with );
  with = vbslq_u8( vtstq_u8( x, vdupq_n_u8( 0x40 ) ), GF_MUL_VAR( with, m2 ), with );
  with = vbslq_u8( vtstq_u8( x, vdupq_n_u8( 0x80 ) ), GF_MUL_VAR( with, m3 ), with );
  return with;
}

static uchar const exp_low_76[ 16 ] W_ATTR = { 1,  76, 157,  70,  95, 253, 217, 129, 133, 168, 230, 227, 130,  81,  18,  44 };
static uchar const exp_low_29[ 16 ] W_ATTR = { 1,  29,  76, 143, 157, 106,  70,  93,  95, 101, 253, 254, 217,  13, 129,  59 };
static uchar const exp_low_16[ 16 ] W_ATTR = { 1,  16,  29, 205,  76, 180, 143,  24, 157,  37, 106, 238,  70,  20,  93, 185 };
static uchar const exp_low_4 [ 16 ] W_ATTR = { 1,   4,  16,  64,  29, 116, 205,  19,  76,  45, 180, 234, 143,   6,  24,  96 };
static uchar const exp_low_2 [ 16 ] W_ATTR = { 1,   2,   4,   8,  16,  32,  64, 128,  29,  58, 116, 232, 205, 135,  19,  38 };

/* gen_pi computes Pi and 1/Pi' for a size sz transform.  base must be
   2^(sz^-1 mod 255) in GF(2^8), which undoes the scaling of the two
   unscaled FWHTs implicitly in the exponentiation (see the AVX
   implementation for details). */
static inline void
gen_pi( uchar const * is_erased,
        uchar       * output,
        ulong         sz,
        short const * l_twiddle,
        uchar const * exp_low,
        ulong         m0,
        ulong         m1,
        ulong         m2,
        ulong         m3 ) {
  ulong vec_cnt = sz/16UL;
  uint8x16_t erased[ 16 ];
  uint8x16_t v[      16 ];

  for( ulong i=0UL; i<vec_cnt; i++ ) { erased[ i ] = vld1q_u8( is_erased + 16UL*i ); v[ i ] = erased[ i ]; }

  fwht_vecs( v, vec_cnt ); /* FWHT( R~ ) */

  /* v is congruent to FWHT( R~ ) * FWHT( L~ ) mod 255 */
  for( ulong i=0UL; i<vec_cnt; i++ ) v[ i ] = mul_twiddle( v[ i ], l_twiddle + 16UL*i );

  /* v is congruent (mod 255) to what the paper calls
     R_w = FWHT( FWHT( L~ ) * FWHT( R~ ) ) */
  fwht_vecs( v, vec_cnt );

  for( ulong i=0UL; i<vec_cnt; i++ ) {
    /* Negate the ones corresponding to erasures to compute 1/Pi' */
    uint8x16_t log_pi = vbslq_u8( vceqzq_u8( erased[ i ] ), v[ i ], vmvnq_u8( v[ i ] ) );
    vst1q_u8( output + 16UL*i, exp_base( log_pi, exp_low, m0, m1, m2, m3 ) );
  }
}

void
fd_reedsol_private_gen_pi_16( uchar const * is_erased,
                              uchar       * output ) {
  gen_pi( is_erased, output,  16UL, fwht_l_twiddle_16,  exp_low_76,   2UL,   4UL,  16UL,  29UL );
}

void
fd_reedsol_private_gen_pi_32( uchar const * is_erased,
                              uchar       * output ) {
  gen_pi( is_erased, output,  32UL, fwht_l_twiddle_32,  exp_low_29, 133UL,   2UL,   4UL,  16UL );
}

void
fd_reedsol_private_gen_pi_64( uchar const * is_erased,
                              uchar       * output ) {
  gen_pi( is_erased, output,  64UL, fwht_l_twiddle_64,  exp_low_16,  95UL, 133UL,   2UL,   4UL );
}

void
fd_reedsol_private_gen_pi_128( uchar const * is_erased,
                               uchar       * output ) {
  gen_pi( is_erased, output, 128UL, fwht_l_twiddle_128, exp_low_4,  157UL,  95UL, 133UL,   2UL );
}

void
fd_reedsol_private_gen_pi_256( uchar const * is_erased,
                               uchar       * output ) {
  gen_pi( is_erased, output, 256UL, fwht_l_twiddle_256, exp_low_2,   76UL, 157UL,  95UL, 133UL );
}
