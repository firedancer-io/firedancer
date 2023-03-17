#include "../../util/fd_util.h"
#include "fd_reedsol_internal.h"
#define INCLUDE_CONSTANTS
#if FD_HAS_GFNI
#include "fd_reedsol_arith_gfni.h"
#elif FD_HAS_AVX
#include "fd_reedsol_arith_avx2.h"
#else
#include "fd_reedsol_arith_none.h"
#endif
#include "fd_reedsol_fft.h"
#include "fd_reedsol_ppt.h"


/* FALLTHRU: Tells the compiler that falling through to the next case
   of the switch statement is intentional and not a bug.  When brutality
   is turned on, this must be used.  Clang an GCC differ on what
   annotations they accept, but this works for both. */
#define FALLTHRU __attribute__((fallthrough));

void fd_reedsol_encode( ulong                 shred_sz,
                        uchar const * const * data_shred,
                        ulong                 data_shred_cnt,
                        uchar       * const * parity_shred,
                        ulong                 parity_shred_cnt ) {

  if( FD_UNLIKELY( (data_shred_cnt==0) | (parity_shred_cnt==0) ) ) return; /* TODO: Is that the right behavior? */

  for( ulong shred_pos=0UL; shred_pos<shred_sz; /* advanced manually at end of loop */ ) {
    if( FD_UNLIKELY( data_shred_cnt<=16UL ) ) {
      /* N=16 code path */
      gf_t in00 = gf_zero(); gf_t in01 = gf_zero(); gf_t in02 = gf_zero(); gf_t in03 = gf_zero();
      gf_t in04 = gf_zero(); gf_t in05 = gf_zero(); gf_t in06 = gf_zero(); gf_t in07 = gf_zero();
      gf_t in08 = gf_zero(); gf_t in09 = gf_zero(); gf_t in10 = gf_zero(); gf_t in11 = gf_zero();
      gf_t in12 = gf_zero(); gf_t in13 = gf_zero(); gf_t in14 = gf_zero(); gf_t in15 = gf_zero();
      switch( data_shred_cnt ) {
        case 16UL: in15 = gf_ldu( data_shred[ 15 ] + shred_pos ); FALLTHRU
        case 15UL: in14 = gf_ldu( data_shred[ 14 ] + shred_pos ); FALLTHRU
        case 14UL: in13 = gf_ldu( data_shred[ 13 ] + shred_pos ); FALLTHRU
        case 13UL: in12 = gf_ldu( data_shred[ 12 ] + shred_pos ); FALLTHRU
        case 12UL: in11 = gf_ldu( data_shred[ 11 ] + shred_pos ); FALLTHRU
        case 11UL: in10 = gf_ldu( data_shred[ 10 ] + shred_pos ); FALLTHRU
        case 10UL: in09 = gf_ldu( data_shred[  9 ] + shred_pos ); FALLTHRU
        case  9UL: in08 = gf_ldu( data_shred[  8 ] + shred_pos ); FALLTHRU
        case  8UL: in07 = gf_ldu( data_shred[  7 ] + shred_pos ); FALLTHRU
        case  7UL: in06 = gf_ldu( data_shred[  6 ] + shred_pos ); FALLTHRU
        case  6UL: in05 = gf_ldu( data_shred[  5 ] + shred_pos ); FALLTHRU
        case  5UL: in04 = gf_ldu( data_shred[  4 ] + shred_pos ); FALLTHRU
        case  4UL: in03 = gf_ldu( data_shred[  3 ] + shred_pos ); FALLTHRU
        case  3UL: in02 = gf_ldu( data_shred[  2 ] + shred_pos ); FALLTHRU
        case  2UL: in01 = gf_ldu( data_shred[  1 ] + shred_pos ); FALLTHRU
        case  1UL: in00 = gf_ldu( data_shred[  0 ] + shred_pos );
      }
#define ALL_VARS in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15
      switch( data_shred_cnt ) {
        case 16UL: FD_REEDSOL_GENERATE_IFFT( 16,  0, ALL_VARS ); break;
        case 15UL: FD_REEDSOL_GENERATE_PPT(  16, 15, ALL_VARS ); break;
        case 14UL: FD_REEDSOL_GENERATE_PPT(  16, 14, ALL_VARS ); break;
        case 13UL: FD_REEDSOL_GENERATE_PPT(  16, 13, ALL_VARS ); break;
        case 12UL: FD_REEDSOL_GENERATE_PPT(  16, 12, ALL_VARS ); break;
        case 11UL: FD_REEDSOL_GENERATE_PPT(  16, 11, ALL_VARS ); break;
        case 10UL: FD_REEDSOL_GENERATE_PPT(  16, 10, ALL_VARS ); break;
        case  9UL: FD_REEDSOL_GENERATE_PPT(  16,  9, ALL_VARS ); break;
        case  8UL: FD_REEDSOL_GENERATE_PPT(  16,  8, ALL_VARS ); break;
        case  7UL: FD_REEDSOL_GENERATE_PPT(  16,  7, ALL_VARS ); break;
        case  6UL: FD_REEDSOL_GENERATE_PPT(  16,  6, ALL_VARS ); break;
        case  5UL: FD_REEDSOL_GENERATE_PPT(  16,  5, ALL_VARS ); break;
        case  4UL: FD_REEDSOL_GENERATE_PPT(  16,  4, ALL_VARS ); break;
        case  3UL: FD_REEDSOL_GENERATE_PPT(  16,  3, ALL_VARS ); break;
        case  2UL: FD_REEDSOL_GENERATE_PPT(  16,  2, ALL_VARS ); break;
        case  1UL: FD_REEDSOL_GENERATE_PPT(  16,  1, ALL_VARS ); break;
      }
      /* That generated the first 16-data_shred_cnt parity shreds in the
         last 16-data_shred_cnt variables. We might only need
         parity_shred_cnt of them though. */
      ulong total_shreds = data_shred_cnt+parity_shred_cnt;
      switch( data_shred_cnt ) {
        case  1UL: if( total_shreds <=  1UL ) break; gf_stu( parity_shred[  1UL-data_shred_cnt ] + shred_pos, in01 ); in01 = gf_zero(); FALLTHRU
        case  2UL: if( total_shreds <=  2UL ) break; gf_stu( parity_shred[  2UL-data_shred_cnt ] + shred_pos, in02 ); in02 = gf_zero(); FALLTHRU
        case  3UL: if( total_shreds <=  3UL ) break; gf_stu( parity_shred[  3UL-data_shred_cnt ] + shred_pos, in03 ); in03 = gf_zero(); FALLTHRU
        case  4UL: if( total_shreds <=  4UL ) break; gf_stu( parity_shred[  4UL-data_shred_cnt ] + shred_pos, in04 ); in04 = gf_zero(); FALLTHRU
        case  5UL: if( total_shreds <=  5UL ) break; gf_stu( parity_shred[  5UL-data_shred_cnt ] + shred_pos, in05 ); in05 = gf_zero(); FALLTHRU
        case  6UL: if( total_shreds <=  6UL ) break; gf_stu( parity_shred[  6UL-data_shred_cnt ] + shred_pos, in06 ); in06 = gf_zero(); FALLTHRU
        case  7UL: if( total_shreds <=  7UL ) break; gf_stu( parity_shred[  7UL-data_shred_cnt ] + shred_pos, in07 ); in07 = gf_zero(); FALLTHRU
        case  8UL: if( total_shreds <=  8UL ) break; gf_stu( parity_shred[  8UL-data_shred_cnt ] + shred_pos, in08 ); in08 = gf_zero(); FALLTHRU
        case  9UL: if( total_shreds <=  9UL ) break; gf_stu( parity_shred[  9UL-data_shred_cnt ] + shred_pos, in09 ); in09 = gf_zero(); FALLTHRU
        case 10UL: if( total_shreds <= 10UL ) break; gf_stu( parity_shred[ 10UL-data_shred_cnt ] + shred_pos, in10 ); in10 = gf_zero(); FALLTHRU
        case 11UL: if( total_shreds <= 11UL ) break; gf_stu( parity_shred[ 11UL-data_shred_cnt ] + shred_pos, in11 ); in11 = gf_zero(); FALLTHRU
        case 12UL: if( total_shreds <= 12UL ) break; gf_stu( parity_shred[ 12UL-data_shred_cnt ] + shred_pos, in12 ); in12 = gf_zero(); FALLTHRU
        case 13UL: if( total_shreds <= 13UL ) break; gf_stu( parity_shred[ 13UL-data_shred_cnt ] + shred_pos, in13 ); in13 = gf_zero(); FALLTHRU
        case 14UL: if( total_shreds <= 14UL ) break; gf_stu( parity_shred[ 14UL-data_shred_cnt ] + shred_pos, in14 ); in14 = gf_zero(); FALLTHRU
        case 15UL: if( total_shreds <= 15UL ) break; gf_stu( parity_shred[ 15UL-data_shred_cnt ] + shred_pos, in15 ); in15 = gf_zero();
      }
      ulong parity_produced = fd_ulong_min( 16UL - data_shred_cnt, parity_shred_cnt );
      ulong parity_remaining = parity_shred_cnt - parity_produced;

      if( FD_LIKELY( parity_remaining>0UL ) ) {
        /* Produce another 16 parity shreds */
        FD_REEDSOL_GENERATE_FFT( 16, 16, ALL_VARS );
        switch( parity_remaining ) {
          default:
          case 16UL: gf_stu( parity_shred[ 15UL+parity_produced ] + shred_pos, in15 ); FALLTHRU
          case 15UL: gf_stu( parity_shred[ 14UL+parity_produced ] + shred_pos, in14 ); FALLTHRU
          case 14UL: gf_stu( parity_shred[ 13UL+parity_produced ] + shred_pos, in13 ); FALLTHRU
          case 13UL: gf_stu( parity_shred[ 12UL+parity_produced ] + shred_pos, in12 ); FALLTHRU
          case 12UL: gf_stu( parity_shred[ 11UL+parity_produced ] + shred_pos, in11 ); FALLTHRU
          case 11UL: gf_stu( parity_shred[ 10UL+parity_produced ] + shred_pos, in10 ); FALLTHRU
          case 10UL: gf_stu( parity_shred[  9UL+parity_produced ] + shred_pos, in09 ); FALLTHRU
          case  9UL: gf_stu( parity_shred[  8UL+parity_produced ] + shred_pos, in08 ); FALLTHRU
          case  8UL: gf_stu( parity_shred[  7UL+parity_produced ] + shred_pos, in07 ); FALLTHRU
          case  7UL: gf_stu( parity_shred[  6UL+parity_produced ] + shred_pos, in06 ); FALLTHRU
          case  6UL: gf_stu( parity_shred[  5UL+parity_produced ] + shred_pos, in05 ); FALLTHRU
          case  5UL: gf_stu( parity_shred[  4UL+parity_produced ] + shred_pos, in04 ); FALLTHRU
          case  4UL: gf_stu( parity_shred[  3UL+parity_produced ] + shred_pos, in03 ); FALLTHRU
          case  3UL: gf_stu( parity_shred[  2UL+parity_produced ] + shred_pos, in02 ); FALLTHRU
          case  2UL: gf_stu( parity_shred[  1UL+parity_produced ] + shred_pos, in01 ); FALLTHRU
          case  1UL: gf_stu( parity_shred[  0UL+parity_produced ] + shred_pos, in00 );
        }
        parity_produced += fd_ulong_min( 16UL, parity_remaining );
        parity_remaining = parity_shred_cnt - parity_produced;
      }

      /* We might need one more round */
      if( FD_UNLIKELY( parity_remaining>0UL ) ) {
        /* TODO: Is it faster to save the output of the ifft/ppt than to
           recompute? */
        FD_REEDSOL_GENERATE_IFFT( 16, 16, ALL_VARS );
        FD_REEDSOL_GENERATE_FFT(  16, 32, ALL_VARS );
        switch( parity_remaining ) {
          default:
          case 16UL: gf_stu( parity_shred[ 15UL+parity_produced ] + shred_pos, in15 ); FALLTHRU
          case 15UL: gf_stu( parity_shred[ 14UL+parity_produced ] + shred_pos, in14 ); FALLTHRU
          case 14UL: gf_stu( parity_shred[ 13UL+parity_produced ] + shred_pos, in13 ); FALLTHRU
          case 13UL: gf_stu( parity_shred[ 12UL+parity_produced ] + shred_pos, in12 ); FALLTHRU
          case 12UL: gf_stu( parity_shred[ 11UL+parity_produced ] + shred_pos, in11 ); FALLTHRU
          case 11UL: gf_stu( parity_shred[ 10UL+parity_produced ] + shred_pos, in10 ); FALLTHRU
          case 10UL: gf_stu( parity_shred[  9UL+parity_produced ] + shred_pos, in09 ); FALLTHRU
          case  9UL: gf_stu( parity_shred[  8UL+parity_produced ] + shred_pos, in08 ); FALLTHRU
          case  8UL: gf_stu( parity_shred[  7UL+parity_produced ] + shred_pos, in07 ); FALLTHRU
          case  7UL: gf_stu( parity_shred[  6UL+parity_produced ] + shred_pos, in06 ); FALLTHRU
          case  6UL: gf_stu( parity_shred[  5UL+parity_produced ] + shred_pos, in05 ); FALLTHRU
          case  5UL: gf_stu( parity_shred[  4UL+parity_produced ] + shred_pos, in04 ); FALLTHRU
          case  4UL: gf_stu( parity_shred[  3UL+parity_produced ] + shred_pos, in03 ); FALLTHRU
          case  3UL: gf_stu( parity_shred[  2UL+parity_produced ] + shred_pos, in02 ); FALLTHRU
          case  2UL: gf_stu( parity_shred[  1UL+parity_produced ] + shred_pos, in01 ); FALLTHRU
          case  1UL: gf_stu( parity_shred[  0UL+parity_produced ] + shred_pos, in00 );
        }
#undef ALL_VARS
      }
    } else {
      /* N==32 codepath */
      gf_t in00 = gf_zero(); gf_t in01 = gf_zero(); gf_t in02 = gf_zero(); gf_t in03 = gf_zero();
      gf_t in04 = gf_zero(); gf_t in05 = gf_zero(); gf_t in06 = gf_zero(); gf_t in07 = gf_zero();
      gf_t in08 = gf_zero(); gf_t in09 = gf_zero(); gf_t in10 = gf_zero(); gf_t in11 = gf_zero();
      gf_t in12 = gf_zero(); gf_t in13 = gf_zero(); gf_t in14 = gf_zero(); gf_t in15 = gf_zero();
      gf_t in16 = gf_zero(); gf_t in17 = gf_zero(); gf_t in18 = gf_zero(); gf_t in19 = gf_zero();
      gf_t in20 = gf_zero(); gf_t in21 = gf_zero(); gf_t in22 = gf_zero(); gf_t in23 = gf_zero();
      gf_t in24 = gf_zero(); gf_t in25 = gf_zero(); gf_t in26 = gf_zero(); gf_t in27 = gf_zero();
      gf_t in28 = gf_zero(); gf_t in29 = gf_zero(); gf_t in30 = gf_zero(); gf_t in31 = gf_zero();

      in15 = gf_ldu( data_shred[ 15 ] + shred_pos ); in14 = gf_ldu( data_shred[ 14 ] + shred_pos );
      in13 = gf_ldu( data_shred[ 13 ] + shred_pos ); in12 = gf_ldu( data_shred[ 12 ] + shred_pos );
      in11 = gf_ldu( data_shred[ 11 ] + shred_pos ); in10 = gf_ldu( data_shred[ 10 ] + shred_pos );
      in09 = gf_ldu( data_shred[  9 ] + shred_pos ); in08 = gf_ldu( data_shred[  8 ] + shred_pos );
      in07 = gf_ldu( data_shred[  7 ] + shred_pos ); in06 = gf_ldu( data_shred[  6 ] + shred_pos );
      in05 = gf_ldu( data_shred[  5 ] + shred_pos ); in04 = gf_ldu( data_shred[  4 ] + shred_pos );
      in03 = gf_ldu( data_shred[  3 ] + shred_pos ); in02 = gf_ldu( data_shred[  2 ] + shred_pos );
      in01 = gf_ldu( data_shred[  1 ] + shred_pos ); in00 = gf_ldu( data_shred[  0 ] + shred_pos );
#define ALL_VARS in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, \
                 in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31

      switch( data_shred_cnt ) {
        case 32UL: in31 = gf_ldu( data_shred[ 31 ] + shred_pos ); FALLTHRU
        case 31UL: in30 = gf_ldu( data_shred[ 30 ] + shred_pos ); FALLTHRU
        case 30UL: in29 = gf_ldu( data_shred[ 29 ] + shred_pos ); FALLTHRU
        case 29UL: in28 = gf_ldu( data_shred[ 28 ] + shred_pos ); FALLTHRU
        case 28UL: in27 = gf_ldu( data_shred[ 27 ] + shred_pos ); FALLTHRU
        case 27UL: in26 = gf_ldu( data_shred[ 26 ] + shred_pos ); FALLTHRU
        case 26UL: in25 = gf_ldu( data_shred[ 25 ] + shred_pos ); FALLTHRU
        case 25UL: in24 = gf_ldu( data_shred[ 24 ] + shred_pos ); FALLTHRU
        case 24UL: in23 = gf_ldu( data_shred[ 23 ] + shred_pos ); FALLTHRU
        case 23UL: in22 = gf_ldu( data_shred[ 22 ] + shred_pos ); FALLTHRU
        case 22UL: in21 = gf_ldu( data_shred[ 21 ] + shred_pos ); FALLTHRU
        case 21UL: in20 = gf_ldu( data_shred[ 20 ] + shred_pos ); FALLTHRU
        case 20UL: in19 = gf_ldu( data_shred[ 19 ] + shred_pos ); FALLTHRU
        case 19UL: in18 = gf_ldu( data_shred[ 18 ] + shred_pos ); FALLTHRU
        case 18UL: in17 = gf_ldu( data_shred[ 17 ] + shred_pos ); FALLTHRU
        case 17UL: in16 = gf_ldu( data_shred[ 16 ] + shred_pos );
      }
      switch( data_shred_cnt ) {
        case 32UL: FD_REEDSOL_GENERATE_IFFT( 32,  0, ALL_VARS ); break;
        case 31UL: FD_REEDSOL_GENERATE_PPT(  32, 31, ALL_VARS ); break;
        case 30UL: FD_REEDSOL_GENERATE_PPT(  32, 30, ALL_VARS ); break;
        case 29UL: FD_REEDSOL_GENERATE_PPT(  32, 29, ALL_VARS ); break;
        case 28UL: FD_REEDSOL_GENERATE_PPT(  32, 28, ALL_VARS ); break;
        case 27UL: FD_REEDSOL_GENERATE_PPT(  32, 27, ALL_VARS ); break;
        case 26UL: FD_REEDSOL_GENERATE_PPT(  32, 26, ALL_VARS ); break;
        case 25UL: FD_REEDSOL_GENERATE_PPT(  32, 25, ALL_VARS ); break;
        case 24UL: FD_REEDSOL_GENERATE_PPT(  32, 24, ALL_VARS ); break;
        case 23UL: FD_REEDSOL_GENERATE_PPT(  32, 23, ALL_VARS ); break;
        case 22UL: FD_REEDSOL_GENERATE_PPT(  32, 22, ALL_VARS ); break;
        case 21UL: FD_REEDSOL_GENERATE_PPT(  32, 21, ALL_VARS ); break;
        case 20UL: FD_REEDSOL_GENERATE_PPT(  32, 20, ALL_VARS ); break;
        case 19UL: FD_REEDSOL_GENERATE_PPT(  32, 19, ALL_VARS ); break;
        case 18UL: FD_REEDSOL_GENERATE_PPT(  32, 18, ALL_VARS ); break;
        case 17UL: FD_REEDSOL_GENERATE_PPT(  32, 17, ALL_VARS ); break;
      }
      /* That generated the first 32-data_shred_cnt parity shreds in the
         last 32-data_shred_cnt variables. We might only need
         parity_shred_cnt of them though. */
      ulong total_shreds = data_shred_cnt+parity_shred_cnt;
      switch( data_shred_cnt ) {
        case 17UL: if( total_shreds <= 17UL ) break; gf_stu( parity_shred[ 17UL-data_shred_cnt ] + shred_pos, in17 ); in17 = gf_zero(); FALLTHRU
        case 18UL: if( total_shreds <= 18UL ) break; gf_stu( parity_shred[ 18UL-data_shred_cnt ] + shred_pos, in18 ); in18 = gf_zero(); FALLTHRU
        case 19UL: if( total_shreds <= 19UL ) break; gf_stu( parity_shred[ 19UL-data_shred_cnt ] + shred_pos, in19 ); in19 = gf_zero(); FALLTHRU
        case 20UL: if( total_shreds <= 20UL ) break; gf_stu( parity_shred[ 20UL-data_shred_cnt ] + shred_pos, in20 ); in20 = gf_zero(); FALLTHRU
        case 21UL: if( total_shreds <= 21UL ) break; gf_stu( parity_shred[ 21UL-data_shred_cnt ] + shred_pos, in21 ); in21 = gf_zero(); FALLTHRU
        case 22UL: if( total_shreds <= 22UL ) break; gf_stu( parity_shred[ 22UL-data_shred_cnt ] + shred_pos, in22 ); in22 = gf_zero(); FALLTHRU
        case 23UL: if( total_shreds <= 23UL ) break; gf_stu( parity_shred[ 23UL-data_shred_cnt ] + shred_pos, in23 ); in23 = gf_zero(); FALLTHRU
        case 24UL: if( total_shreds <= 24UL ) break; gf_stu( parity_shred[ 24UL-data_shred_cnt ] + shred_pos, in24 ); in24 = gf_zero(); FALLTHRU
        case 25UL: if( total_shreds <= 25UL ) break; gf_stu( parity_shred[ 25UL-data_shred_cnt ] + shred_pos, in25 ); in25 = gf_zero(); FALLTHRU
        case 26UL: if( total_shreds <= 26UL ) break; gf_stu( parity_shred[ 26UL-data_shred_cnt ] + shred_pos, in26 ); in26 = gf_zero(); FALLTHRU
        case 27UL: if( total_shreds <= 27UL ) break; gf_stu( parity_shred[ 27UL-data_shred_cnt ] + shred_pos, in27 ); in27 = gf_zero(); FALLTHRU
        case 28UL: if( total_shreds <= 28UL ) break; gf_stu( parity_shred[ 28UL-data_shred_cnt ] + shred_pos, in28 ); in28 = gf_zero(); FALLTHRU
        case 29UL: if( total_shreds <= 29UL ) break; gf_stu( parity_shred[ 29UL-data_shred_cnt ] + shred_pos, in29 ); in29 = gf_zero(); FALLTHRU
        case 30UL: if( total_shreds <= 30UL ) break; gf_stu( parity_shred[ 30UL-data_shred_cnt ] + shred_pos, in30 ); in30 = gf_zero(); FALLTHRU
        case 31UL: if( total_shreds <= 31UL ) break; gf_stu( parity_shred[ 31UL-data_shred_cnt ] + shred_pos, in31 ); in31 = gf_zero();
      }
      ulong parity_produced = fd_ulong_min( 32UL - data_shred_cnt, parity_shred_cnt );
      ulong parity_remaining = parity_shred_cnt - parity_produced;
      if( FD_LIKELY( parity_remaining>0UL ) ) {
        /* Produce another 32 parity shreds */
        FD_REEDSOL_GENERATE_FFT( 32, 32, ALL_VARS );
#undef ALL_VARS
        switch( parity_remaining ) {
          case 32UL: gf_stu( parity_shred[ 31UL+parity_produced ] + shred_pos, in31 ); FALLTHRU
          case 31UL: gf_stu( parity_shred[ 30UL+parity_produced ] + shred_pos, in30 ); FALLTHRU
          case 30UL: gf_stu( parity_shred[ 29UL+parity_produced ] + shred_pos, in29 ); FALLTHRU
          case 29UL: gf_stu( parity_shred[ 28UL+parity_produced ] + shred_pos, in28 ); FALLTHRU
          case 28UL: gf_stu( parity_shred[ 27UL+parity_produced ] + shred_pos, in27 ); FALLTHRU
          case 27UL: gf_stu( parity_shred[ 26UL+parity_produced ] + shred_pos, in26 ); FALLTHRU
          case 26UL: gf_stu( parity_shred[ 25UL+parity_produced ] + shred_pos, in25 ); FALLTHRU
          case 25UL: gf_stu( parity_shred[ 24UL+parity_produced ] + shred_pos, in24 ); FALLTHRU
          case 24UL: gf_stu( parity_shred[ 23UL+parity_produced ] + shred_pos, in23 ); FALLTHRU
          case 23UL: gf_stu( parity_shred[ 22UL+parity_produced ] + shred_pos, in22 ); FALLTHRU
          case 22UL: gf_stu( parity_shred[ 21UL+parity_produced ] + shred_pos, in21 ); FALLTHRU
          case 21UL: gf_stu( parity_shred[ 20UL+parity_produced ] + shred_pos, in20 ); FALLTHRU
          case 20UL: gf_stu( parity_shred[ 19UL+parity_produced ] + shred_pos, in19 ); FALLTHRU
          case 19UL: gf_stu( parity_shred[ 18UL+parity_produced ] + shred_pos, in18 ); FALLTHRU
          case 18UL: gf_stu( parity_shred[ 17UL+parity_produced ] + shred_pos, in17 ); FALLTHRU
          case 17UL: gf_stu( parity_shred[ 16UL+parity_produced ] + shred_pos, in16 ); FALLTHRU
          case 16UL: gf_stu( parity_shred[ 15UL+parity_produced ] + shred_pos, in15 ); FALLTHRU
          case 15UL: gf_stu( parity_shred[ 14UL+parity_produced ] + shred_pos, in14 ); FALLTHRU
          case 14UL: gf_stu( parity_shred[ 13UL+parity_produced ] + shred_pos, in13 ); FALLTHRU
          case 13UL: gf_stu( parity_shred[ 12UL+parity_produced ] + shred_pos, in12 ); FALLTHRU
          case 12UL: gf_stu( parity_shred[ 11UL+parity_produced ] + shred_pos, in11 ); FALLTHRU
          case 11UL: gf_stu( parity_shred[ 10UL+parity_produced ] + shred_pos, in10 ); FALLTHRU
          case 10UL: gf_stu( parity_shred[  9UL+parity_produced ] + shred_pos, in09 ); FALLTHRU
          case  9UL: gf_stu( parity_shred[  8UL+parity_produced ] + shred_pos, in08 ); FALLTHRU
          case  8UL: gf_stu( parity_shred[  7UL+parity_produced ] + shred_pos, in07 ); FALLTHRU
          case  7UL: gf_stu( parity_shred[  6UL+parity_produced ] + shred_pos, in06 ); FALLTHRU
          case  6UL: gf_stu( parity_shred[  5UL+parity_produced ] + shred_pos, in05 ); FALLTHRU
          case  5UL: gf_stu( parity_shred[  4UL+parity_produced ] + shred_pos, in04 ); FALLTHRU
          case  4UL: gf_stu( parity_shred[  3UL+parity_produced ] + shred_pos, in03 ); FALLTHRU
          case  3UL: gf_stu( parity_shred[  2UL+parity_produced ] + shred_pos, in02 ); FALLTHRU
          case  2UL: gf_stu( parity_shred[  1UL+parity_produced ] + shred_pos, in01 ); FALLTHRU
          case  1UL: gf_stu( parity_shred[  0UL+parity_produced ] + shred_pos, in00 );
        }
      }
    }
    /* In order to handle shred sizes that are not divisible by 32, we clamp
       shred_pos to shred_sz-32 when shred_sz-32<shred_pos<shred_sz
       (after the increment). */
    shred_pos += GF_WIDTH;
    shred_pos = fd_ulong_if( ((shred_sz-GF_WIDTH)<shred_pos) & (shred_pos<shred_sz), shred_sz-GF_WIDTH, shred_pos );
  }
}

