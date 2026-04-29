#ifndef HEADER_fd_src_ballet_falcon_fd_keccak8x_h
#define HEADER_fd_src_ballet_falcon_fd_keccak8x_h

#include "../keccak256/fd_keccak256_private.h"

#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"

static inline void
fd_keccak256_core_8( ulong state[8][25] ) {

# define LOAD(j) wwv( state[0][(j)], state[1][(j)], state[2][(j)], state[3][(j)], \
                      state[4][(j)], state[5][(j)], state[6][(j)], state[7][(j)] )

  wwv_t A00 = LOAD( 0); wwv_t A01 = LOAD( 1); wwv_t A02 = LOAD( 2); wwv_t A03 = LOAD( 3); wwv_t A04 = LOAD( 4);
  wwv_t A05 = LOAD( 5); wwv_t A06 = LOAD( 6); wwv_t A07 = LOAD( 7); wwv_t A08 = LOAD( 8); wwv_t A09 = LOAD( 9);
  wwv_t A10 = LOAD(10); wwv_t A11 = LOAD(11); wwv_t A12 = LOAD(12); wwv_t A13 = LOAD(13); wwv_t A14 = LOAD(14);
  wwv_t A15 = LOAD(15); wwv_t A16 = LOAD(16); wwv_t A17 = LOAD(17); wwv_t A18 = LOAD(18); wwv_t A19 = LOAD(19);
  wwv_t A20 = LOAD(20); wwv_t A21 = LOAD(21); wwv_t A22 = LOAD(22); wwv_t A23 = LOAD(23); wwv_t A24 = LOAD(24);

# undef LOAD

  for( ulong round=0UL; round<12UL; round++ ) {

    /* Theta */

    wwv_t C0 = wwv_xor( wwv_xor( A00, A05 ), wwv_xor( A10, wwv_xor( A15, A20 ) ) );
    wwv_t C1 = wwv_xor( wwv_xor( A01, A06 ), wwv_xor( A11, wwv_xor( A16, A21 ) ) );
    wwv_t C2 = wwv_xor( wwv_xor( A02, A07 ), wwv_xor( A12, wwv_xor( A17, A22 ) ) );
    wwv_t C3 = wwv_xor( wwv_xor( A03, A08 ), wwv_xor( A13, wwv_xor( A18, A23 ) ) );
    wwv_t C4 = wwv_xor( wwv_xor( A04, A09 ), wwv_xor( A14, wwv_xor( A19, A24 ) ) );

    wwv_t D0 = wwv_xor( C4, wwv_rol( C1, 1 ) );
    wwv_t D1 = wwv_xor( C0, wwv_rol( C2, 1 ) );
    wwv_t D2 = wwv_xor( C1, wwv_rol( C3, 1 ) );
    wwv_t D3 = wwv_xor( C2, wwv_rol( C4, 1 ) );
    wwv_t D4 = wwv_xor( C3, wwv_rol( C0, 1 ) );

    A00 = wwv_xor( A00, D0 ); A05 = wwv_xor( A05, D0 ); A10 = wwv_xor( A10, D0 ); A15 = wwv_xor( A15, D0 ); A20 = wwv_xor( A20, D0 );
    A01 = wwv_xor( A01, D1 ); A06 = wwv_xor( A06, D1 ); A11 = wwv_xor( A11, D1 ); A16 = wwv_xor( A16, D1 ); A21 = wwv_xor( A21, D1 );
    A02 = wwv_xor( A02, D2 ); A07 = wwv_xor( A07, D2 ); A12 = wwv_xor( A12, D2 ); A17 = wwv_xor( A17, D2 ); A22 = wwv_xor( A22, D2 );
    A03 = wwv_xor( A03, D3 ); A08 = wwv_xor( A08, D3 ); A13 = wwv_xor( A13, D3 ); A18 = wwv_xor( A18, D3 ); A23 = wwv_xor( A23, D3 );
    A04 = wwv_xor( A04, D4 ); A09 = wwv_xor( A09, D4 ); A14 = wwv_xor( A14, D4 ); A19 = wwv_xor( A19, D4 ); A24 = wwv_xor( A24, D4 );

    /* Rho + Pi */

    wwv_t B00 = A00;
    wwv_t B01 = wwv_rol( A06, 44 );
    wwv_t B02 = wwv_rol( A12, 43 );
    wwv_t B03 = wwv_rol( A18, 21 );
    wwv_t B04 = wwv_rol( A24, 14 );
    wwv_t B05 = wwv_rol( A03, 28 );
    wwv_t B06 = wwv_rol( A09, 20 );
    wwv_t B07 = wwv_rol( A10,  3 );
    wwv_t B08 = wwv_rol( A16, 45 );
    wwv_t B09 = wwv_rol( A22, 61 );
    wwv_t B10 = wwv_rol( A01,  1 );
    wwv_t B11 = wwv_rol( A07,  6 );
    wwv_t B12 = wwv_rol( A13, 25 );
    wwv_t B13 = wwv_rol( A19,  8 );
    wwv_t B14 = wwv_rol( A20, 18 );
    wwv_t B15 = wwv_rol( A04, 27 );
    wwv_t B16 = wwv_rol( A05, 36 );
    wwv_t B17 = wwv_rol( A11, 10 );
    wwv_t B18 = wwv_rol( A17, 15 );
    wwv_t B19 = wwv_rol( A23, 56 );
    wwv_t B20 = wwv_rol( A02, 62 );
    wwv_t B21 = wwv_rol( A08, 55 );
    wwv_t B22 = wwv_rol( A14, 39 );
    wwv_t B23 = wwv_rol( A15, 41 );
    wwv_t B24 = wwv_rol( A21,  2 );

    /* Chi: A'[x+5y] = B[x+5y] ^ (~B[(x+1)%5+5y] & B[(x+2)%5+5y]) */

    A00 = wwv_xor( B00, wwv_andnot( B01, B02 ) );
    A01 = wwv_xor( B01, wwv_andnot( B02, B03 ) );
    A02 = wwv_xor( B02, wwv_andnot( B03, B04 ) );
    A03 = wwv_xor( B03, wwv_andnot( B04, B00 ) );
    A04 = wwv_xor( B04, wwv_andnot( B00, B01 ) );

    A05 = wwv_xor( B05, wwv_andnot( B06, B07 ) );
    A06 = wwv_xor( B06, wwv_andnot( B07, B08 ) );
    A07 = wwv_xor( B07, wwv_andnot( B08, B09 ) );
    A08 = wwv_xor( B08, wwv_andnot( B09, B05 ) );
    A09 = wwv_xor( B09, wwv_andnot( B05, B06 ) );

    A10 = wwv_xor( B10, wwv_andnot( B11, B12 ) );
    A11 = wwv_xor( B11, wwv_andnot( B12, B13 ) );
    A12 = wwv_xor( B12, wwv_andnot( B13, B14 ) );
    A13 = wwv_xor( B13, wwv_andnot( B14, B10 ) );
    A14 = wwv_xor( B14, wwv_andnot( B10, B11 ) );

    A15 = wwv_xor( B15, wwv_andnot( B16, B17 ) );
    A16 = wwv_xor( B16, wwv_andnot( B17, B18 ) );
    A17 = wwv_xor( B17, wwv_andnot( B18, B19 ) );
    A18 = wwv_xor( B18, wwv_andnot( B19, B15 ) );
    A19 = wwv_xor( B19, wwv_andnot( B15, B16 ) );

    A20 = wwv_xor( B20, wwv_andnot( B21, B22 ) );
    A21 = wwv_xor( B21, wwv_andnot( B22, B23 ) );
    A22 = wwv_xor( B22, wwv_andnot( B23, B24 ) );
    A23 = wwv_xor( B23, wwv_andnot( B24, B20 ) );
    A24 = wwv_xor( B24, wwv_andnot( B20, B21 ) );

    /* Iota */

    A00 = wwv_xor( A00, wwv_bcast( fd_keccak256_rc[round] ) );
  }

  /* Store back */

# define STORE(name, idx) do {                                                              \
    ulong _t0, _t1, _t2, _t3, _t4, _t5, _t6, _t7;                                         \
    wwv_unpack( name, _t0, _t1, _t2, _t3, _t4, _t5, _t6, _t7 );                            \
    state[0][idx] = _t0; state[1][idx] = _t1; state[2][idx] = _t2; state[3][idx] = _t3;     \
    state[4][idx] = _t4; state[5][idx] = _t5; state[6][idx] = _t6; state[7][idx] = _t7;     \
  } while(0)

  STORE(A00,  0); STORE(A01,  1); STORE(A02,  2); STORE(A03,  3); STORE(A04,  4);
  STORE(A05,  5); STORE(A06,  6); STORE(A07,  7); STORE(A08,  8); STORE(A09,  9);
  STORE(A10, 10); STORE(A11, 11); STORE(A12, 12); STORE(A13, 13); STORE(A14, 14);
  STORE(A15, 15); STORE(A16, 16); STORE(A17, 17); STORE(A18, 18); STORE(A19, 19);
  STORE(A20, 20); STORE(A21, 21); STORE(A22, 22); STORE(A23, 23); STORE(A24, 24);

# undef STORE
}

#else /* !FD_HAS_AVX512 */

static inline void
fd_keccak256_core_8( ulong state[8][25] ) {
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_keccak256_core( state[i] );
  }
}

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_falcon_fd_keccak8x_h */
