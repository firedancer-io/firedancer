/* Keccak-f[1600] with each 64-bit lane as two uint32 limbs (LE: limb0 = bits
   0..31, limb1 = bits 32..63).  Matches JumpCrypto plonky2-crypto Keccak
   (hash/keccak256.rs: [[U32Target;2];25]).

   The sponge API stays ulong[25]; split/join only at the permutation boundary.
   The round function uses uint32 arithmetic only (no ulong / uint64_t in the
   inner steps) so it can run on 32-bit CPUs; Iota still reads round constants
   from fd_keccak256_rc (ulong) once per round.

   Included from fd_keccak256_private.h when FD_KECCAK256_USE_INTERLEAVED32 is
   defined (see keccak256/Local.mk). */

/* Same rho offsets and pi lane indices as the reference ulong core in
   fd_keccak256_private.h. */
static uchar const fd_keccak256_interleaved_rho[ 24 ] = {
  1,  3,   6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static uchar const fd_keccak256_interleaved_pi[ 24 ] = {
  10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

/* Logical 64-bit rotate-left by d on LE limbs (lo, hi); 0 <= d < 64. */
static inline void
fd_keccak256_rl64_u32( uint   lo,
                       uint   hi,
                       int    d,
                       uint * out_lo,
                       uint * out_hi ) {
  if( FD_UNLIKELY( d==0 ) ) {
    *out_lo = lo;
    *out_hi = hi;
    return;
  }
  if( d==32 ) {
    *out_lo = hi;
    *out_hi = lo;
    return;
  }
  if( d < 32 ) {
    uint const s = (uint)d;
    *out_lo = (uint)( (lo << s) | (hi >> (32U - s)) );
    *out_hi = (uint)( (hi << s) | (lo >> (32U - s)) );
  } else {
    uint const s = (uint)(d - 32);
    *out_lo = (uint)( (hi << s) | (lo >> (32U - s)) );
    *out_hi = (uint)( (lo << s) | (hi >> (32U - s)) );
  }
}

/* rol64 by 1 only — used in Theta (D lane). */
static inline void
fd_keccak256_rl64_1_u32( uint   lo,
                         uint   hi,
                         uint * out_lo,
                         uint * out_hi ) {
  *out_lo = (uint)( (lo << 1) | (hi >> 31) );
  *out_hi = (uint)( (hi << 1) | (lo >> 31) );
}

static inline ulong
fd_keccak256_pair_u64( uint lo,
                       uint hi ) {
  return ((ulong)hi << 32) | (ulong)lo;
}

static inline void
fd_keccak256_split_u64( ulong w,
                        uint * lo,
                        uint * hi ) {
  *lo = (uint)w;
  *hi = (uint)(w >> 32);
}

static inline void
fd_keccak256_core( ulong * state ) {
  uint a_lo[ 25 ] FD_ALIGNED;
  uint a_hi[ 25 ] FD_ALIGNED;

  for( int z=0; z<25; z++ ) {
    fd_keccak256_split_u64( state[ z ], a_lo+z, a_hi+z );
  }

  for( int round=0; round<24; round++ ) {

    /* Theta — column parities and D in uint32 only */
    uint C_lo[ 5 ];
    uint C_hi[ 5 ];
    for( int x=0; x<5; x++ ) {
      uint cl = a_lo[ x ];
      uint ch = a_hi[ x ];
      for( int y=1; y<5; y++ ) {
        int const idx = x + 5*y;
        cl ^= a_lo[ idx ];
        ch ^= a_hi[ idx ];
      }
      C_lo[ x ] = cl;
      C_hi[ x ] = ch;
    }

    uint D_lo[ 5 ];
    uint D_hi[ 5 ];
    for( int x=0; x<5; x++ ) {
      uint r_lo, r_hi;
      fd_keccak256_rl64_1_u32( C_lo[ (x+1)%5 ], C_hi[ (x+1)%5 ], &r_lo, &r_hi );
      D_lo[ x ] = (uint)( C_lo[ (x+4)%5 ] ^ r_lo );
      D_hi[ x ] = (uint)( C_hi[ (x+4)%5 ] ^ r_hi );
    }

    for( int x=0; x<5; x++ ) {
      for( int y=0; y<5; y++ ) {
        int const idx = x + 5*y;
        a_lo[ idx ] ^= D_lo[ x ];
        a_hi[ idx ] ^= D_hi[ x ];
      }
    }

    /* Rho + Pi */
    uint cur_lo = a_lo[ 1 ];
    uint cur_hi = a_hi[ 1 ];
    for( int i=0; i<24; i++ ) {
      int const j = (int)fd_keccak256_interleaved_pi[ i ];
      uint const tmp_lo = a_lo[ j ];
      uint const tmp_hi = a_hi[ j ];
      int const rho = (int)fd_keccak256_interleaved_rho[ i ];
      fd_keccak256_rl64_u32( cur_lo, cur_hi, rho, a_lo+j, a_hi+j );
      cur_lo = tmp_lo;
      cur_hi = tmp_hi;
    }

    /* Chi — bitwise on each limb separately */
    for( int y=0; y<5; y++ ) {
      uint b_lo[ 5 ];
      uint b_hi[ 5 ];
      for( int x=0; x<5; x++ ) {
        int const idx = x + 5*y;
        b_lo[ x ] = a_lo[ idx ];
        b_hi[ x ] = a_hi[ idx ];
      }
      for( int x=0; x<5; x++ ) {
        int const idx = x + 5*y;
        int const i1 = (x+1)%5;
        int const i2 = (x+2)%5;
        a_lo[ idx ] = (uint)( b_lo[ x ] ^ ( (uint)(~b_lo[ i1 ]) & b_lo[ i2 ] ) );
        a_hi[ idx ] = (uint)( b_hi[ x ] ^ ( (uint)(~b_hi[ i1 ]) & b_hi[ i2 ] ) );
      }
    }

    /* Iota */
    ulong const rct = fd_keccak256_rc[ round ];
    a_lo[ 0 ] ^= (uint)rct;
    a_hi[ 0 ] ^= (uint)(rct >> 32);
  }

  for( int z=0; z<25; z++ ) {
    state[ z ] = fd_keccak256_pair_u64( a_lo[ z ], a_hi[ z ] );
  }
}
