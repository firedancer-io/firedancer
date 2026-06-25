/* bench_keccak_lthash.c - measure XKCP AVX-512 Keccak-p[1600] throughput
 * (single-state and times8) at 12 and 24 rounds, and model a TurboSHAKE128
 * LtHash (2048-byte output) against the measured blake3 baseline.
 *
 * Links against the XKCP objects extracted by the falcon Makefile:
 *   vendor/xkcp/bin/AVX512/KeccakP-1600-AVX512.o        (single state)
 *   vendor/xkcp/bin/AVX512/KeccakP-1600-times8-AVX512.o (8-wide)
 *
 * Public domain. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ---- XKCP single-state AVX-512 ------------------------------------- */
extern void KeccakP1600_AVX512_Permute_12rounds( void * state );
extern void KeccakP1600_AVX512_Permute_24rounds( void * state );

/* ---- XKCP times8 AVX-512 ------------------------------------------- */
extern void KeccakP1600times8_AVX512_InitializeAll  ( void * states );
extern void KeccakP1600times8_AVX512_PermuteAll_12rounds( void * states );
extern void KeccakP1600times8_AVX512_PermuteAll_24rounds( void * states );
extern void KeccakP1600times8_AVX512_AddBytes( void * states, unsigned instanceIndex,
                                               const unsigned char * data,
                                               unsigned offset, unsigned length );
extern void KeccakP1600times8_AVX512_ExtractLanesAll( const void * states, unsigned char * data,
                                                      unsigned laneCount, unsigned laneOffset );

static inline double
now_ns( void ) {
  struct timespec t;
  clock_gettime( CLOCK_MONOTONIC, &t );
  return (double)t.tv_sec*1e9 + (double)t.tv_nsec;
}

/* times8 state: 25 lanes * 8 instances * 8 bytes = 1600 bytes, 64-aligned. */
_Alignas(64) static uint64_t st8 [ 25*8 ];
_Alignas(64) static uint64_t st1 [ 25    ];

#define BEST_OF 3

int main( void ) {
  /* deterministic non-zero init */
  for( int i=0;i<25*8;i++ ) st8[i] = 0x0123456789abcdefULL ^ (uint64_t)i;
  for( int i=0;i<25;  i++ ) st1[i] = 0x0123456789abcdefULL ^ (uint64_t)i;

  unsigned long  iter = 2000000UL;

  printf( "=== XKCP AVX-512 Keccak-p[1600] permutation throughput ===\n" );
  printf( "    (best of %d; ns/state = ns/call / lanes)\n\n", BEST_OF );
  printf( "    variant                        lanes   ns/call   ns/state\n" );

  /* single-state 24r */
  { double best=1e30;
    for(int r=0;r<BEST_OF;r++){ double t0=now_ns();
      for(unsigned long k=0;k<iter;k++) KeccakP1600_AVX512_Permute_24rounds(st1);
      double dt=(now_ns()-t0)/(double)iter; if(dt<best)best=dt; }
    printf( "    KeccakP1600_AVX512  24r           1   %8.2f   %8.2f\n", best, best ); }
  /* single-state 12r */
  { double best=1e30;
    for(int r=0;r<BEST_OF;r++){ double t0=now_ns();
      for(unsigned long k=0;k<iter;k++) KeccakP1600_AVX512_Permute_12rounds(st1);
      double dt=(now_ns()-t0)/(double)iter; if(dt<best)best=dt; }
    printf( "    KeccakP1600_AVX512  12r           1   %8.2f   %8.2f\n", best, best ); }
  /* times8 24r */
  double t8_24=0.0;
  { double best=1e30;
    for(int r=0;r<BEST_OF;r++){ double t0=now_ns();
      for(unsigned long k=0;k<iter;k++) KeccakP1600times8_AVX512_PermuteAll_24rounds(st8);
      double dt=(now_ns()-t0)/(double)iter; if(dt<best)best=dt; }
    t8_24=best;
    printf( "    KeccakP1600times8_AVX512  24r      8   %8.2f   %8.2f\n", best, best/8.0 ); }
  /* times8 12r */
  double t8_12=0.0;
  { double best=1e30;
    for(int r=0;r<BEST_OF;r++){ double t0=now_ns();
      for(unsigned long k=0;k<iter;k++) KeccakP1600times8_AVX512_PermuteAll_12rounds(st8);
      double dt=(now_ns()-t0)/(double)iter; if(dt<best)best=dt; }
    t8_12=best;
    printf( "    KeccakP1600times8_AVX512  12r      8   %8.2f   %8.2f\n", best, best/8.0 ); }

  /* XOF byte-generation throughput, directly comparable to blake3
     compress16_fast Gbps.  Gbps = lanes * rate_bytes * 8 bits / ns_per_call. */
  printf( "\n=== XOF throughput (Gbps/core) — compare to blake3 compress16_fast ===\n" );
  printf( "    TurboSHAKE128 (times8 12r, rate 168): %6.2f Gbps/core\n", (8.0*168.0*8.0)/t8_12 );
  printf( "    TurboSHAKE256 (times8 12r, rate 136): %6.2f Gbps/core\n", (8.0*136.0*8.0)/t8_12 );
  printf( "    SHAKE256      (times8 24r, rate 136): %6.2f Gbps/core\n", (8.0*136.0*8.0)/t8_24 );

  /* ---- LtHash structural model (2048-byte output) ----------------- *
   * LtHash hashes one account to a 2048-byte vector via XOF squeeze.
   * In counter mode the squeeze blocks are independent permutations, so
   * throughput-optimal batching packs them 8 per times8 call:
   *     squeeze perms / lthash = ceil(2048 / rate)
   *     ns/lthash (squeeze) = (squeeze_perms / 8) * t_times8_12r
   * plus ~1 absorb perm/lthash (amortized over the 8-wide batch).        */
  printf( "\n=== TurboSHAKE128 LtHash model (2048-byte output, 12 rounds) ===\n" );
  printf( "    blake3 AVX-512 lthash baseline (measured): 377 ns/lthash\n\n" );
  printf( "    construction          rate   squeeze   ns/lthash (squeeze-bound)\n" );

  struct { const char * name; int rate; } cfg[] = {
    { "TurboSHAKE128 (cap 256)", 168 },  /* (1600-256)/8 */
    { "TurboSHAKE256 (cap 512)", 136 },  /* (1600-512)/8  == our lthash2 rate */
  };
  for( unsigned c=0;c<2;c++ ) {
    int rate = cfg[c].rate;
    int sq   = (2048 + rate - 1) / rate;                 /* ceil */
    double ns_sq = ( (double)sq / 8.0 ) * t8_12;          /* throughput-optimal */
    double ns_1  = (double)( (sq + 7) / 8 ) * t8_12;      /* single-lthash counter mode (ceil to whole times8 calls) */
    printf( "    %-22s  %3d   %5d     %7.1f  (per-lthash batched)  %7.1f  (1 lthash, %d times8 calls)\n",
            cfg[c].name, rate, sq, ns_sq, ns_1, (sq+7)/8 );
  }

  printf( "\n    NOTE: our fd_lthash2 (keccak8, rate 136) measured: ~880 ns/lthash batch16.\n" );
  printf( "          Our keccak8 12r times8 call ~325 ns; XKCP times8 12r call = %.1f ns.\n", t8_12 );
  return 0;
}
