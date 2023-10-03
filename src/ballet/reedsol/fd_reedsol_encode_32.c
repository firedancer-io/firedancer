#include "fd_reedsol_ppt.h"

void
fd_reedsol_private_encode_32( ulong                 shred_sz,
                              uchar const * const * data_shred,
                              ulong                 data_shred_cnt,
                              uchar       * const * parity_shred,
                              ulong                 parity_shred_cnt ) {
  for( ulong shred_pos=0UL; shred_pos<shred_sz; /* advanced manually at end of loop */ ) {
    gf_t in00 = gf_ldu( data_shred[  0 ] + shred_pos );  gf_t in01 = gf_ldu( data_shred[  1 ] + shred_pos );
    gf_t in02 = gf_ldu( data_shred[  2 ] + shred_pos );  gf_t in03 = gf_ldu( data_shred[  3 ] + shred_pos );
    gf_t in04 = gf_ldu( data_shred[  4 ] + shred_pos );  gf_t in05 = gf_ldu( data_shred[  5 ] + shred_pos );
    gf_t in06 = gf_ldu( data_shred[  6 ] + shred_pos );  gf_t in07 = gf_ldu( data_shred[  7 ] + shred_pos );
    gf_t in08 = gf_ldu( data_shred[  8 ] + shred_pos );  gf_t in09 = gf_ldu( data_shred[  9 ] + shred_pos );
    gf_t in10 = gf_ldu( data_shred[ 10 ] + shred_pos );  gf_t in11 = gf_ldu( data_shred[ 11 ] + shred_pos );
    gf_t in12 = gf_ldu( data_shred[ 12 ] + shred_pos );  gf_t in13 = gf_ldu( data_shred[ 13 ] + shred_pos );
    gf_t in14 = gf_ldu( data_shred[ 14 ] + shred_pos );  gf_t in15 = gf_ldu( data_shred[ 15 ] + shred_pos );
    gf_t in16 = gf_zero();  gf_t in17 = gf_zero();  gf_t in18 = gf_zero();  gf_t in19 = gf_zero();
    gf_t in20 = gf_zero();  gf_t in21 = gf_zero();  gf_t in22 = gf_zero();  gf_t in23 = gf_zero();
    gf_t in24 = gf_zero();  gf_t in25 = gf_zero();  gf_t in26 = gf_zero();  gf_t in27 = gf_zero();
    gf_t in28 = gf_zero();  gf_t in29 = gf_zero();  gf_t in30 = gf_zero();  gf_t in31 = gf_zero();
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
    #define ALL_VARS in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31
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
    ulong parity_produced  = fd_ulong_min( 32UL - data_shred_cnt, parity_shred_cnt );
    ulong parity_remaining = parity_shred_cnt - parity_produced;
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 32 parity shreds */
      FD_REEDSOL_GENERATE_FFT(  32, 32, ALL_VARS );
      switch( parity_remaining ) {
        default:
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
      parity_produced += fd_ulong_min( 32UL, parity_remaining );
      parity_remaining = parity_shred_cnt - parity_produced;
    }
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 32 parity shreds */
      FD_REEDSOL_GENERATE_IFFT( 32, 32, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  32, 64, ALL_VARS );
      switch( parity_remaining ) {
        default:
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
      parity_produced += fd_ulong_min( 32UL, parity_remaining );
      parity_remaining = parity_shred_cnt - parity_produced;
    }
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 32 parity shreds */
      FD_REEDSOL_GENERATE_IFFT( 32, 64, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  32, 96, ALL_VARS );
      switch( parity_remaining ) {
        default:
        case  4UL: gf_stu( parity_shred[  3UL+parity_produced ] + shred_pos, in03 ); FALLTHRU
        case  3UL: gf_stu( parity_shred[  2UL+parity_produced ] + shred_pos, in02 ); FALLTHRU
        case  2UL: gf_stu( parity_shred[  1UL+parity_produced ] + shred_pos, in01 ); FALLTHRU
        case  1UL: gf_stu( parity_shred[  0UL+parity_produced ] + shred_pos, in00 );
      }
      parity_produced += fd_ulong_min( 4UL, parity_remaining );
      parity_remaining = parity_shred_cnt - parity_produced;
    }
    #undef ALL_VARS
    /* In order to handle shred sizes that are not divisible by 32, we clamp
       shred_pos to shred_sz-32 when shred_sz-32<shred_pos<shred_sz
       (after the increment). */
    shred_pos += GF_WIDTH;
    shred_pos = fd_ulong_if( ((shred_sz-GF_WIDTH)<shred_pos) & (shred_pos<shred_sz), shred_sz-GF_WIDTH, shred_pos );
  }
}
