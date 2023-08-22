#include "fd_reedsol_ppt.h"

void
fd_reedsol_private_encode_16( ulong                 shred_sz,
                              uchar const * const * data_shred,
                              ulong                 data_shred_cnt,
                              uchar       * const * parity_shred,
                              ulong                 parity_shred_cnt ) {
  for( ulong shred_pos=0UL; shred_pos<shred_sz; /* advanced manually at end of loop */ ) {
    gf_t in00 = gf_zero();  gf_t in01 = gf_zero();  gf_t in02 = gf_zero();  gf_t in03 = gf_zero();
    gf_t in04 = gf_zero();  gf_t in05 = gf_zero();  gf_t in06 = gf_zero();  gf_t in07 = gf_zero();
    gf_t in08 = gf_zero();  gf_t in09 = gf_zero();  gf_t in10 = gf_zero();  gf_t in11 = gf_zero();
    gf_t in12 = gf_zero();  gf_t in13 = gf_zero();  gf_t in14 = gf_zero();  gf_t in15 = gf_zero();
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
    ulong parity_produced  = fd_ulong_min( 16UL - data_shred_cnt, parity_shred_cnt );
    ulong parity_remaining = parity_shred_cnt - parity_produced;
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 16 parity shreds */
      FD_REEDSOL_GENERATE_FFT(  16, 16, ALL_VARS );
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
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 16 parity shreds */
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
      parity_produced += fd_ulong_min( 16UL, parity_remaining );
      parity_remaining = parity_shred_cnt - parity_produced;
    }
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 16 parity shreds */
      FD_REEDSOL_GENERATE_IFFT( 16, 32, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  16, 48, ALL_VARS );
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
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 16 parity shreds */
      FD_REEDSOL_GENERATE_IFFT( 16, 48, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  16, 64, ALL_VARS );
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
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 16 parity shreds */
      FD_REEDSOL_GENERATE_IFFT( 16, 64, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  16, 80, ALL_VARS );
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
