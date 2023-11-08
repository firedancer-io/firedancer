/* Note: This file is auto generated. */
#include "fd_reedsol_ppt.h"
#include "fd_reedsol_fderiv.h"

FD_FN_UNSANITIZED int
fd_reedsol_private_recover_var_32( ulong           shred_sz,
                                   uchar * const * shred,
                                   ulong           data_shred_cnt,
                                   ulong           parity_shred_cnt,
                                   uchar const *   erased ) {
  uchar _erased[ 32 ] W_ATTR;
  uchar pi[      32 ] W_ATTR;
  ulong shred_cnt = data_shred_cnt + parity_shred_cnt;
  ulong loaded_cnt = 0UL;
  for( ulong i=0UL; i<32UL; i++) {
    int load_shred = ((i<shred_cnt)&(loaded_cnt<data_shred_cnt))&&( erased[ i ]==0 );
    _erased[ i ] = !load_shred;
    loaded_cnt += (ulong)load_shred;
  }
  if( FD_UNLIKELY( loaded_cnt<data_shred_cnt ) ) return FD_REEDSOL_ERR_PARTIAL;

  fd_reedsol_private_gen_pi_32( _erased, pi );

  /* Store the difference for each shred that was regenerated.  This
     must be 0.  Otherwise there's a corrupt shred. */
  gf_t diff = gf_zero();

  for( ulong shred_pos=0UL; shred_pos<shred_sz; /* advanced manually at end of loop */ ) {
    /* Load exactly data_shred_cnt un-erased input shreds into
       their respective vector.  Fill the erased vectors with 0. */
    gf_t in00 = _erased[  0 ] ? gf_zero() : gf_ldu( shred[  0 ] + shred_pos );
    gf_t in01 = _erased[  1 ] ? gf_zero() : gf_ldu( shred[  1 ] + shred_pos );
    gf_t in02 = _erased[  2 ] ? gf_zero() : gf_ldu( shred[  2 ] + shred_pos );
    gf_t in03 = _erased[  3 ] ? gf_zero() : gf_ldu( shred[  3 ] + shred_pos );
    gf_t in04 = _erased[  4 ] ? gf_zero() : gf_ldu( shred[  4 ] + shred_pos );
    gf_t in05 = _erased[  5 ] ? gf_zero() : gf_ldu( shred[  5 ] + shred_pos );
    gf_t in06 = _erased[  6 ] ? gf_zero() : gf_ldu( shred[  6 ] + shred_pos );
    gf_t in07 = _erased[  7 ] ? gf_zero() : gf_ldu( shred[  7 ] + shred_pos );
    gf_t in08 = _erased[  8 ] ? gf_zero() : gf_ldu( shred[  8 ] + shred_pos );
    gf_t in09 = _erased[  9 ] ? gf_zero() : gf_ldu( shred[  9 ] + shred_pos );
    gf_t in10 = _erased[ 10 ] ? gf_zero() : gf_ldu( shred[ 10 ] + shred_pos );
    gf_t in11 = _erased[ 11 ] ? gf_zero() : gf_ldu( shred[ 11 ] + shred_pos );
    gf_t in12 = _erased[ 12 ] ? gf_zero() : gf_ldu( shred[ 12 ] + shred_pos );
    gf_t in13 = _erased[ 13 ] ? gf_zero() : gf_ldu( shred[ 13 ] + shred_pos );
    gf_t in14 = _erased[ 14 ] ? gf_zero() : gf_ldu( shred[ 14 ] + shred_pos );
    gf_t in15 = _erased[ 15 ] ? gf_zero() : gf_ldu( shred[ 15 ] + shred_pos );
    gf_t in16 = _erased[ 16 ] ? gf_zero() : gf_ldu( shred[ 16 ] + shred_pos );
    gf_t in17 = _erased[ 17 ] ? gf_zero() : gf_ldu( shred[ 17 ] + shred_pos );
    gf_t in18 = _erased[ 18 ] ? gf_zero() : gf_ldu( shred[ 18 ] + shred_pos );
    gf_t in19 = _erased[ 19 ] ? gf_zero() : gf_ldu( shred[ 19 ] + shred_pos );
    gf_t in20 = _erased[ 20 ] ? gf_zero() : gf_ldu( shred[ 20 ] + shred_pos );
    gf_t in21 = _erased[ 21 ] ? gf_zero() : gf_ldu( shred[ 21 ] + shred_pos );
    gf_t in22 = _erased[ 22 ] ? gf_zero() : gf_ldu( shred[ 22 ] + shred_pos );
    gf_t in23 = _erased[ 23 ] ? gf_zero() : gf_ldu( shred[ 23 ] + shred_pos );
    gf_t in24 = _erased[ 24 ] ? gf_zero() : gf_ldu( shred[ 24 ] + shred_pos );
    gf_t in25 = _erased[ 25 ] ? gf_zero() : gf_ldu( shred[ 25 ] + shred_pos );
    gf_t in26 = _erased[ 26 ] ? gf_zero() : gf_ldu( shred[ 26 ] + shred_pos );
    gf_t in27 = _erased[ 27 ] ? gf_zero() : gf_ldu( shred[ 27 ] + shred_pos );
    gf_t in28 = _erased[ 28 ] ? gf_zero() : gf_ldu( shred[ 28 ] + shred_pos );
    gf_t in29 = _erased[ 29 ] ? gf_zero() : gf_ldu( shred[ 29 ] + shred_pos );
    gf_t in30 = _erased[ 30 ] ? gf_zero() : gf_ldu( shred[ 30 ] + shred_pos );
    gf_t in31 = _erased[ 31 ] ? gf_zero() : gf_ldu( shred[ 31 ] + shred_pos );
    /* Technically, we only need to multiply the non-erased ones, since
       the erased ones are 0, but we know at least half of them are
       non-erased, and the branch is going to be just as costly as the
       multiply. */
    in00 = GF_MUL_VAR( in00, pi[  0 ] );
    in01 = GF_MUL_VAR( in01, pi[  1 ] );
    in02 = GF_MUL_VAR( in02, pi[  2 ] );
    in03 = GF_MUL_VAR( in03, pi[  3 ] );
    in04 = GF_MUL_VAR( in04, pi[  4 ] );
    in05 = GF_MUL_VAR( in05, pi[  5 ] );
    in06 = GF_MUL_VAR( in06, pi[  6 ] );
    in07 = GF_MUL_VAR( in07, pi[  7 ] );
    in08 = GF_MUL_VAR( in08, pi[  8 ] );
    in09 = GF_MUL_VAR( in09, pi[  9 ] );
    in10 = GF_MUL_VAR( in10, pi[ 10 ] );
    in11 = GF_MUL_VAR( in11, pi[ 11 ] );
    in12 = GF_MUL_VAR( in12, pi[ 12 ] );
    in13 = GF_MUL_VAR( in13, pi[ 13 ] );
    in14 = GF_MUL_VAR( in14, pi[ 14 ] );
    in15 = GF_MUL_VAR( in15, pi[ 15 ] );
    in16 = GF_MUL_VAR( in16, pi[ 16 ] );
    in17 = GF_MUL_VAR( in17, pi[ 17 ] );
    in18 = GF_MUL_VAR( in18, pi[ 18 ] );
    in19 = GF_MUL_VAR( in19, pi[ 19 ] );
    in20 = GF_MUL_VAR( in20, pi[ 20 ] );
    in21 = GF_MUL_VAR( in21, pi[ 21 ] );
    in22 = GF_MUL_VAR( in22, pi[ 22 ] );
    in23 = GF_MUL_VAR( in23, pi[ 23 ] );
    in24 = GF_MUL_VAR( in24, pi[ 24 ] );
    in25 = GF_MUL_VAR( in25, pi[ 25 ] );
    in26 = GF_MUL_VAR( in26, pi[ 26 ] );
    in27 = GF_MUL_VAR( in27, pi[ 27 ] );
    in28 = GF_MUL_VAR( in28, pi[ 28 ] );
    in29 = GF_MUL_VAR( in29, pi[ 29 ] );
    in30 = GF_MUL_VAR( in30, pi[ 30 ] );
    in31 = GF_MUL_VAR( in31, pi[ 31 ] );
    #define ALL_VARS in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31

    FD_REEDSOL_GENERATE_IFFT( 32, 0, ALL_VARS );

    FD_REEDSOL_GENERATE_FDERIV( 32, ALL_VARS );

    FD_REEDSOL_GENERATE_FFT( 32, 0, ALL_VARS );

    /* Again, we only need to multiply the erased ones, since we don't
       use the value of the non-erased ones anymore, but I'll take
       multiplies over branches most days. */
    in00 = GF_MUL_VAR( in00, pi[  0 ] );
    in01 = GF_MUL_VAR( in01, pi[  1 ] );
    in02 = GF_MUL_VAR( in02, pi[  2 ] );
    in03 = GF_MUL_VAR( in03, pi[  3 ] );
    in04 = GF_MUL_VAR( in04, pi[  4 ] );
    in05 = GF_MUL_VAR( in05, pi[  5 ] );
    in06 = GF_MUL_VAR( in06, pi[  6 ] );
    in07 = GF_MUL_VAR( in07, pi[  7 ] );
    in08 = GF_MUL_VAR( in08, pi[  8 ] );
    in09 = GF_MUL_VAR( in09, pi[  9 ] );
    in10 = GF_MUL_VAR( in10, pi[ 10 ] );
    in11 = GF_MUL_VAR( in11, pi[ 11 ] );
    in12 = GF_MUL_VAR( in12, pi[ 12 ] );
    in13 = GF_MUL_VAR( in13, pi[ 13 ] );
    in14 = GF_MUL_VAR( in14, pi[ 14 ] );
    in15 = GF_MUL_VAR( in15, pi[ 15 ] );
    in16 = GF_MUL_VAR( in16, pi[ 16 ] );
    in17 = GF_MUL_VAR( in17, pi[ 17 ] );
    in18 = GF_MUL_VAR( in18, pi[ 18 ] );
    in19 = GF_MUL_VAR( in19, pi[ 19 ] );
    in20 = GF_MUL_VAR( in20, pi[ 20 ] );
    in21 = GF_MUL_VAR( in21, pi[ 21 ] );
    in22 = GF_MUL_VAR( in22, pi[ 22 ] );
    in23 = GF_MUL_VAR( in23, pi[ 23 ] );
    in24 = GF_MUL_VAR( in24, pi[ 24 ] );
    in25 = GF_MUL_VAR( in25, pi[ 25 ] );
    in26 = GF_MUL_VAR( in26, pi[ 26 ] );
    in27 = GF_MUL_VAR( in27, pi[ 27 ] );
    in28 = GF_MUL_VAR( in28, pi[ 28 ] );
    in29 = GF_MUL_VAR( in29, pi[ 29 ] );
    in30 = GF_MUL_VAR( in30, pi[ 30 ] );
    in31 = GF_MUL_VAR( in31, pi[ 31 ] );
    /* There are a couple of cases we have to handle:
        - If i<shred_cnt and erased[ i ], it's an actual erasure, so we
            need to store the generated value.
        - If i<shred_cnt and _erased[ i ] but not erased[ i ], it was a
            value that we ignored to ensure the data lies on a
            polynomial of the right order, so we need to compare the
            value we generated to the one that was there.
        - If i<shred_cnt and !_erased[ i ], then this is a value we
            actually used in the computation, but we destroyed it, so we
            need to reload the actual value of the shred in order to use the
            IFFT in the next step.
        - If i>=shred_cnt, do nothing, which will keep the value of the
            shred if it existed in the variable. */
  #define STORE_COMPARE_RELOAD( n, var ) do{                                                        \
            if(       erased[ n ] )        gf_stu( shred[ n ] + shred_pos, var );                            \
            else if( _erased[ n ] ) diff = GF_OR( diff, GF_ADD( var, gf_ldu( shred[ n ] + shred_pos ) ) );       \
            else                    var  = gf_ldu( shred[ n ] + shred_pos );                                     \
          } while( 0 )
  #define STORE_COMPARE( n, var ) do{                                                         \
        if(       erased[ n ] )        gf_stu( shred[ n ] + shred_pos, var );                          \
        else                    diff = GF_OR( diff, GF_ADD( var, gf_ldu( shred[ n ] + shred_pos ) ) ); \
      } while( 0 )
    switch( fd_ulong_min( shred_cnt, 32UL ) ) {
      case 32UL: STORE_COMPARE_RELOAD( 31, in31 ); FALLTHRU
      case 31UL: STORE_COMPARE_RELOAD( 30, in30 ); FALLTHRU
      case 30UL: STORE_COMPARE_RELOAD( 29, in29 ); FALLTHRU
      case 29UL: STORE_COMPARE_RELOAD( 28, in28 ); FALLTHRU
      case 28UL: STORE_COMPARE_RELOAD( 27, in27 ); FALLTHRU
      case 27UL: STORE_COMPARE_RELOAD( 26, in26 ); FALLTHRU
      case 26UL: STORE_COMPARE_RELOAD( 25, in25 ); FALLTHRU
      case 25UL: STORE_COMPARE_RELOAD( 24, in24 ); FALLTHRU
      case 24UL: STORE_COMPARE_RELOAD( 23, in23 ); FALLTHRU
      case 23UL: STORE_COMPARE_RELOAD( 22, in22 ); FALLTHRU
      case 22UL: STORE_COMPARE_RELOAD( 21, in21 ); FALLTHRU
      case 21UL: STORE_COMPARE_RELOAD( 20, in20 ); FALLTHRU
      case 20UL: STORE_COMPARE_RELOAD( 19, in19 ); FALLTHRU
      case 19UL: STORE_COMPARE_RELOAD( 18, in18 ); FALLTHRU
      case 18UL: STORE_COMPARE_RELOAD( 17, in17 ); FALLTHRU
      case 17UL: STORE_COMPARE_RELOAD( 16, in16 ); FALLTHRU
      case 16UL: STORE_COMPARE_RELOAD( 15, in15 ); FALLTHRU
      case 15UL: STORE_COMPARE_RELOAD( 14, in14 ); FALLTHRU
      case 14UL: STORE_COMPARE_RELOAD( 13, in13 ); FALLTHRU
      case 13UL: STORE_COMPARE_RELOAD( 12, in12 ); FALLTHRU
      case 12UL: STORE_COMPARE_RELOAD( 11, in11 ); FALLTHRU
      case 11UL: STORE_COMPARE_RELOAD( 10, in10 ); FALLTHRU
      case 10UL: STORE_COMPARE_RELOAD(  9, in09 ); FALLTHRU
      case  9UL: STORE_COMPARE_RELOAD(  8, in08 ); FALLTHRU
      case  8UL: STORE_COMPARE_RELOAD(  7, in07 ); FALLTHRU
      case  7UL: STORE_COMPARE_RELOAD(  6, in06 ); FALLTHRU
      case  6UL: STORE_COMPARE_RELOAD(  5, in05 ); FALLTHRU
      case  5UL: STORE_COMPARE_RELOAD(  4, in04 ); FALLTHRU
      case  4UL: STORE_COMPARE_RELOAD(  3, in03 ); FALLTHRU
      case  3UL: STORE_COMPARE_RELOAD(  2, in02 ); FALLTHRU
      case  2UL: STORE_COMPARE_RELOAD(  1, in01 ); FALLTHRU
      case  1UL: STORE_COMPARE_RELOAD(  0, in00 );
    }

    ulong shreds_remaining = shred_cnt-fd_ulong_min( shred_cnt, 32UL );
    if( shreds_remaining>0UL ) {
      FD_REEDSOL_GENERATE_IFFT( 32,  0, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  32, 32, ALL_VARS );

      switch( fd_ulong_min( shreds_remaining, 32UL ) ) {
        case 32UL: STORE_COMPARE( 63, in31 ); FALLTHRU
        case 31UL: STORE_COMPARE( 62, in30 ); FALLTHRU
        case 30UL: STORE_COMPARE( 61, in29 ); FALLTHRU
        case 29UL: STORE_COMPARE( 60, in28 ); FALLTHRU
        case 28UL: STORE_COMPARE( 59, in27 ); FALLTHRU
        case 27UL: STORE_COMPARE( 58, in26 ); FALLTHRU
        case 26UL: STORE_COMPARE( 57, in25 ); FALLTHRU
        case 25UL: STORE_COMPARE( 56, in24 ); FALLTHRU
        case 24UL: STORE_COMPARE( 55, in23 ); FALLTHRU
        case 23UL: STORE_COMPARE( 54, in22 ); FALLTHRU
        case 22UL: STORE_COMPARE( 53, in21 ); FALLTHRU
        case 21UL: STORE_COMPARE( 52, in20 ); FALLTHRU
        case 20UL: STORE_COMPARE( 51, in19 ); FALLTHRU
        case 19UL: STORE_COMPARE( 50, in18 ); FALLTHRU
        case 18UL: STORE_COMPARE( 49, in17 ); FALLTHRU
        case 17UL: STORE_COMPARE( 48, in16 ); FALLTHRU
        case 16UL: STORE_COMPARE( 47, in15 ); FALLTHRU
        case 15UL: STORE_COMPARE( 46, in14 ); FALLTHRU
        case 14UL: STORE_COMPARE( 45, in13 ); FALLTHRU
        case 13UL: STORE_COMPARE( 44, in12 ); FALLTHRU
        case 12UL: STORE_COMPARE( 43, in11 ); FALLTHRU
        case 11UL: STORE_COMPARE( 42, in10 ); FALLTHRU
        case 10UL: STORE_COMPARE( 41, in09 ); FALLTHRU
        case  9UL: STORE_COMPARE( 40, in08 ); FALLTHRU
        case  8UL: STORE_COMPARE( 39, in07 ); FALLTHRU
        case  7UL: STORE_COMPARE( 38, in06 ); FALLTHRU
        case  6UL: STORE_COMPARE( 37, in05 ); FALLTHRU
        case  5UL: STORE_COMPARE( 36, in04 ); FALLTHRU
        case  4UL: STORE_COMPARE( 35, in03 ); FALLTHRU
        case  3UL: STORE_COMPARE( 34, in02 ); FALLTHRU
        case  2UL: STORE_COMPARE( 33, in01 ); FALLTHRU
        case  1UL: STORE_COMPARE( 32, in00 );
      }
      shreds_remaining -= fd_ulong_min( shreds_remaining, 32UL );
    }
    if( shreds_remaining>0UL ) {
      FD_REEDSOL_GENERATE_IFFT( 32, 32, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  32, 64, ALL_VARS );

      switch( fd_ulong_min( shreds_remaining, 32UL ) ) {
        case 32UL: STORE_COMPARE( 95, in31 ); FALLTHRU
        case 31UL: STORE_COMPARE( 94, in30 ); FALLTHRU
        case 30UL: STORE_COMPARE( 93, in29 ); FALLTHRU
        case 29UL: STORE_COMPARE( 92, in28 ); FALLTHRU
        case 28UL: STORE_COMPARE( 91, in27 ); FALLTHRU
        case 27UL: STORE_COMPARE( 90, in26 ); FALLTHRU
        case 26UL: STORE_COMPARE( 89, in25 ); FALLTHRU
        case 25UL: STORE_COMPARE( 88, in24 ); FALLTHRU
        case 24UL: STORE_COMPARE( 87, in23 ); FALLTHRU
        case 23UL: STORE_COMPARE( 86, in22 ); FALLTHRU
        case 22UL: STORE_COMPARE( 85, in21 ); FALLTHRU
        case 21UL: STORE_COMPARE( 84, in20 ); FALLTHRU
        case 20UL: STORE_COMPARE( 83, in19 ); FALLTHRU
        case 19UL: STORE_COMPARE( 82, in18 ); FALLTHRU
        case 18UL: STORE_COMPARE( 81, in17 ); FALLTHRU
        case 17UL: STORE_COMPARE( 80, in16 ); FALLTHRU
        case 16UL: STORE_COMPARE( 79, in15 ); FALLTHRU
        case 15UL: STORE_COMPARE( 78, in14 ); FALLTHRU
        case 14UL: STORE_COMPARE( 77, in13 ); FALLTHRU
        case 13UL: STORE_COMPARE( 76, in12 ); FALLTHRU
        case 12UL: STORE_COMPARE( 75, in11 ); FALLTHRU
        case 11UL: STORE_COMPARE( 74, in10 ); FALLTHRU
        case 10UL: STORE_COMPARE( 73, in09 ); FALLTHRU
        case  9UL: STORE_COMPARE( 72, in08 ); FALLTHRU
        case  8UL: STORE_COMPARE( 71, in07 ); FALLTHRU
        case  7UL: STORE_COMPARE( 70, in06 ); FALLTHRU
        case  6UL: STORE_COMPARE( 69, in05 ); FALLTHRU
        case  5UL: STORE_COMPARE( 68, in04 ); FALLTHRU
        case  4UL: STORE_COMPARE( 67, in03 ); FALLTHRU
        case  3UL: STORE_COMPARE( 66, in02 ); FALLTHRU
        case  2UL: STORE_COMPARE( 65, in01 ); FALLTHRU
        case  1UL: STORE_COMPARE( 64, in00 );
      }
      shreds_remaining -= fd_ulong_min( shreds_remaining, 32UL );
    }
    if( shreds_remaining>0UL ) {
      FD_REEDSOL_GENERATE_IFFT( 32, 64, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  32, 96, ALL_VARS );

      switch( fd_ulong_min( shreds_remaining, 32UL ) ) {
        case 32UL: STORE_COMPARE( 127, in31 ); FALLTHRU
        case 31UL: STORE_COMPARE( 126, in30 ); FALLTHRU
        case 30UL: STORE_COMPARE( 125, in29 ); FALLTHRU
        case 29UL: STORE_COMPARE( 124, in28 ); FALLTHRU
        case 28UL: STORE_COMPARE( 123, in27 ); FALLTHRU
        case 27UL: STORE_COMPARE( 122, in26 ); FALLTHRU
        case 26UL: STORE_COMPARE( 121, in25 ); FALLTHRU
        case 25UL: STORE_COMPARE( 120, in24 ); FALLTHRU
        case 24UL: STORE_COMPARE( 119, in23 ); FALLTHRU
        case 23UL: STORE_COMPARE( 118, in22 ); FALLTHRU
        case 22UL: STORE_COMPARE( 117, in21 ); FALLTHRU
        case 21UL: STORE_COMPARE( 116, in20 ); FALLTHRU
        case 20UL: STORE_COMPARE( 115, in19 ); FALLTHRU
        case 19UL: STORE_COMPARE( 114, in18 ); FALLTHRU
        case 18UL: STORE_COMPARE( 113, in17 ); FALLTHRU
        case 17UL: STORE_COMPARE( 112, in16 ); FALLTHRU
        case 16UL: STORE_COMPARE( 111, in15 ); FALLTHRU
        case 15UL: STORE_COMPARE( 110, in14 ); FALLTHRU
        case 14UL: STORE_COMPARE( 109, in13 ); FALLTHRU
        case 13UL: STORE_COMPARE( 108, in12 ); FALLTHRU
        case 12UL: STORE_COMPARE( 107, in11 ); FALLTHRU
        case 11UL: STORE_COMPARE( 106, in10 ); FALLTHRU
        case 10UL: STORE_COMPARE( 105, in09 ); FALLTHRU
        case  9UL: STORE_COMPARE( 104, in08 ); FALLTHRU
        case  8UL: STORE_COMPARE( 103, in07 ); FALLTHRU
        case  7UL: STORE_COMPARE( 102, in06 ); FALLTHRU
        case  6UL: STORE_COMPARE( 101, in05 ); FALLTHRU
        case  5UL: STORE_COMPARE( 100, in04 ); FALLTHRU
        case  4UL: STORE_COMPARE( 99, in03 ); FALLTHRU
        case  3UL: STORE_COMPARE( 98, in02 ); FALLTHRU
        case  2UL: STORE_COMPARE( 97, in01 ); FALLTHRU
        case  1UL: STORE_COMPARE( 96, in00 );
      }
      shreds_remaining -= fd_ulong_min( shreds_remaining, 32UL );
    }
    if( shreds_remaining>0UL ) {
      FD_REEDSOL_GENERATE_IFFT( 32, 96, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  32, 128, ALL_VARS );

      switch( fd_ulong_min( shreds_remaining, 32UL ) ) {
        case  7UL: STORE_COMPARE( 134, in06 ); FALLTHRU
        case  6UL: STORE_COMPARE( 133, in05 ); FALLTHRU
        case  5UL: STORE_COMPARE( 132, in04 ); FALLTHRU
        case  4UL: STORE_COMPARE( 131, in03 ); FALLTHRU
        case  3UL: STORE_COMPARE( 130, in02 ); FALLTHRU
        case  2UL: STORE_COMPARE( 129, in01 ); FALLTHRU
        case  1UL: STORE_COMPARE( 128, in00 );
      }
      shreds_remaining -= fd_ulong_min( shreds_remaining, 32UL );
    }
    if( FD_UNLIKELY( GF_ANY( diff ) ) ) return FD_REEDSOL_ERR_CORRUPT;
    shred_pos += GF_WIDTH;
    shred_pos = fd_ulong_if( ((shred_sz-GF_WIDTH)<shred_pos) & (shred_pos<shred_sz), shred_sz-GF_WIDTH, shred_pos );
  }
  return FD_REEDSOL_SUCCESS;
}
