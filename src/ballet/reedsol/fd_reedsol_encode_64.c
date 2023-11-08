/* Note: This file is auto generated. */
#include "fd_reedsol_ppt.h"

FD_FN_UNSANITIZED void
fd_reedsol_private_encode_64( ulong                 shred_sz,
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
    gf_t in16 = gf_ldu( data_shred[ 16 ] + shred_pos );  gf_t in17 = gf_ldu( data_shred[ 17 ] + shred_pos );
    gf_t in18 = gf_ldu( data_shred[ 18 ] + shred_pos );  gf_t in19 = gf_ldu( data_shred[ 19 ] + shred_pos );
    gf_t in20 = gf_ldu( data_shred[ 20 ] + shred_pos );  gf_t in21 = gf_ldu( data_shred[ 21 ] + shred_pos );
    gf_t in22 = gf_ldu( data_shred[ 22 ] + shred_pos );  gf_t in23 = gf_ldu( data_shred[ 23 ] + shred_pos );
    gf_t in24 = gf_ldu( data_shred[ 24 ] + shred_pos );  gf_t in25 = gf_ldu( data_shred[ 25 ] + shred_pos );
    gf_t in26 = gf_ldu( data_shred[ 26 ] + shred_pos );  gf_t in27 = gf_ldu( data_shred[ 27 ] + shred_pos );
    gf_t in28 = gf_ldu( data_shred[ 28 ] + shred_pos );  gf_t in29 = gf_ldu( data_shred[ 29 ] + shred_pos );
    gf_t in30 = gf_ldu( data_shred[ 30 ] + shred_pos );  gf_t in31 = gf_ldu( data_shred[ 31 ] + shred_pos );
    gf_t in32 = gf_zero();  gf_t in33 = gf_zero();  gf_t in34 = gf_zero();  gf_t in35 = gf_zero();
    gf_t in36 = gf_zero();  gf_t in37 = gf_zero();  gf_t in38 = gf_zero();  gf_t in39 = gf_zero();
    gf_t in40 = gf_zero();  gf_t in41 = gf_zero();  gf_t in42 = gf_zero();  gf_t in43 = gf_zero();
    gf_t in44 = gf_zero();  gf_t in45 = gf_zero();  gf_t in46 = gf_zero();  gf_t in47 = gf_zero();
    gf_t in48 = gf_zero();  gf_t in49 = gf_zero();  gf_t in50 = gf_zero();  gf_t in51 = gf_zero();
    gf_t in52 = gf_zero();  gf_t in53 = gf_zero();  gf_t in54 = gf_zero();  gf_t in55 = gf_zero();
    gf_t in56 = gf_zero();  gf_t in57 = gf_zero();  gf_t in58 = gf_zero();  gf_t in59 = gf_zero();
    gf_t in60 = gf_zero();  gf_t in61 = gf_zero();  gf_t in62 = gf_zero();  gf_t in63 = gf_zero();
    switch( data_shred_cnt ) {
      case 64UL: in63 = gf_ldu( data_shred[ 63 ] + shred_pos ); FALLTHRU
      case 63UL: in62 = gf_ldu( data_shred[ 62 ] + shred_pos ); FALLTHRU
      case 62UL: in61 = gf_ldu( data_shred[ 61 ] + shred_pos ); FALLTHRU
      case 61UL: in60 = gf_ldu( data_shred[ 60 ] + shred_pos ); FALLTHRU
      case 60UL: in59 = gf_ldu( data_shred[ 59 ] + shred_pos ); FALLTHRU
      case 59UL: in58 = gf_ldu( data_shred[ 58 ] + shred_pos ); FALLTHRU
      case 58UL: in57 = gf_ldu( data_shred[ 57 ] + shred_pos ); FALLTHRU
      case 57UL: in56 = gf_ldu( data_shred[ 56 ] + shred_pos ); FALLTHRU
      case 56UL: in55 = gf_ldu( data_shred[ 55 ] + shred_pos ); FALLTHRU
      case 55UL: in54 = gf_ldu( data_shred[ 54 ] + shred_pos ); FALLTHRU
      case 54UL: in53 = gf_ldu( data_shred[ 53 ] + shred_pos ); FALLTHRU
      case 53UL: in52 = gf_ldu( data_shred[ 52 ] + shred_pos ); FALLTHRU
      case 52UL: in51 = gf_ldu( data_shred[ 51 ] + shred_pos ); FALLTHRU
      case 51UL: in50 = gf_ldu( data_shred[ 50 ] + shred_pos ); FALLTHRU
      case 50UL: in49 = gf_ldu( data_shred[ 49 ] + shred_pos ); FALLTHRU
      case 49UL: in48 = gf_ldu( data_shred[ 48 ] + shred_pos ); FALLTHRU
      case 48UL: in47 = gf_ldu( data_shred[ 47 ] + shred_pos ); FALLTHRU
      case 47UL: in46 = gf_ldu( data_shred[ 46 ] + shred_pos ); FALLTHRU
      case 46UL: in45 = gf_ldu( data_shred[ 45 ] + shred_pos ); FALLTHRU
      case 45UL: in44 = gf_ldu( data_shred[ 44 ] + shred_pos ); FALLTHRU
      case 44UL: in43 = gf_ldu( data_shred[ 43 ] + shred_pos ); FALLTHRU
      case 43UL: in42 = gf_ldu( data_shred[ 42 ] + shred_pos ); FALLTHRU
      case 42UL: in41 = gf_ldu( data_shred[ 41 ] + shred_pos ); FALLTHRU
      case 41UL: in40 = gf_ldu( data_shred[ 40 ] + shred_pos ); FALLTHRU
      case 40UL: in39 = gf_ldu( data_shred[ 39 ] + shred_pos ); FALLTHRU
      case 39UL: in38 = gf_ldu( data_shred[ 38 ] + shred_pos ); FALLTHRU
      case 38UL: in37 = gf_ldu( data_shred[ 37 ] + shred_pos ); FALLTHRU
      case 37UL: in36 = gf_ldu( data_shred[ 36 ] + shred_pos ); FALLTHRU
      case 36UL: in35 = gf_ldu( data_shred[ 35 ] + shred_pos ); FALLTHRU
      case 35UL: in34 = gf_ldu( data_shred[ 34 ] + shred_pos ); FALLTHRU
      case 34UL: in33 = gf_ldu( data_shred[ 33 ] + shred_pos ); FALLTHRU
      case 33UL: in32 = gf_ldu( data_shred[ 32 ] + shred_pos );
    }
    #define ALL_VARS in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31, in32, in33, in34, in35, in36, in37, in38, in39, in40, in41, in42, in43, in44, in45, in46, in47, in48, in49, in50, in51, in52, in53, in54, in55, in56, in57, in58, in59, in60, in61, in62, in63
    #define ALL_VARS_REF &in00, &in01, &in02, &in03, &in04, &in05, &in06, &in07, &in08, &in09, &in10, &in11, &in12, &in13, &in14, &in15, &in16, &in17, &in18, &in19, &in20, &in21, &in22, &in23, &in24, &in25, &in26, &in27, &in28, &in29, &in30, &in31, &in32, &in33, &in34, &in35, &in36, &in37, &in38, &in39, &in40, &in41, &in42, &in43, &in44, &in45, &in46, &in47, &in48, &in49, &in50, &in51, &in52, &in53, &in54, &in55, &in56, &in57, &in58, &in59, &in60, &in61, &in62, &in63
    switch( data_shred_cnt ) {
      case 64UL: FD_REEDSOL_GENERATE_IFFT( 64,  0, ALL_VARS ); break;
      case 63UL: fd_reedsol_ppt_64_63( ALL_VARS_REF ); break;
      case 62UL: fd_reedsol_ppt_64_62( ALL_VARS_REF ); break;
      case 61UL: fd_reedsol_ppt_64_61( ALL_VARS_REF ); break;
      case 60UL: fd_reedsol_ppt_64_60( ALL_VARS_REF ); break;
      case 59UL: fd_reedsol_ppt_64_59( ALL_VARS_REF ); break;
      case 58UL: fd_reedsol_ppt_64_58( ALL_VARS_REF ); break;
      case 57UL: fd_reedsol_ppt_64_57( ALL_VARS_REF ); break;
      case 56UL: fd_reedsol_ppt_64_56( ALL_VARS_REF ); break;
      case 55UL: fd_reedsol_ppt_64_55( ALL_VARS_REF ); break;
      case 54UL: fd_reedsol_ppt_64_54( ALL_VARS_REF ); break;
      case 53UL: fd_reedsol_ppt_64_53( ALL_VARS_REF ); break;
      case 52UL: fd_reedsol_ppt_64_52( ALL_VARS_REF ); break;
      case 51UL: fd_reedsol_ppt_64_51( ALL_VARS_REF ); break;
      case 50UL: fd_reedsol_ppt_64_50( ALL_VARS_REF ); break;
      case 49UL: fd_reedsol_ppt_64_49( ALL_VARS_REF ); break;
      case 48UL: fd_reedsol_ppt_64_48( ALL_VARS_REF ); break;
      case 47UL: fd_reedsol_ppt_64_47( ALL_VARS_REF ); break;
      case 46UL: fd_reedsol_ppt_64_46( ALL_VARS_REF ); break;
      case 45UL: fd_reedsol_ppt_64_45( ALL_VARS_REF ); break;
      case 44UL: fd_reedsol_ppt_64_44( ALL_VARS_REF ); break;
      case 43UL: fd_reedsol_ppt_64_43( ALL_VARS_REF ); break;
      case 42UL: fd_reedsol_ppt_64_42( ALL_VARS_REF ); break;
      case 41UL: fd_reedsol_ppt_64_41( ALL_VARS_REF ); break;
      case 40UL: fd_reedsol_ppt_64_40( ALL_VARS_REF ); break;
      case 39UL: fd_reedsol_ppt_64_39( ALL_VARS_REF ); break;
      case 38UL: fd_reedsol_ppt_64_38( ALL_VARS_REF ); break;
      case 37UL: fd_reedsol_ppt_64_37( ALL_VARS_REF ); break;
      case 36UL: fd_reedsol_ppt_64_36( ALL_VARS_REF ); break;
      case 35UL: fd_reedsol_ppt_64_35( ALL_VARS_REF ); break;
      case 34UL: fd_reedsol_ppt_64_34( ALL_VARS_REF ); break;
      case 33UL: fd_reedsol_ppt_64_33( ALL_VARS_REF ); break;
    }
    /* That generated the first 64-data_shred_cnt parity shreds in the
       last 64-data_shred_cnt variables. We might only need
       parity_shred_cnt of them though. */
    ulong total_shreds = data_shred_cnt+parity_shred_cnt;
    switch( data_shred_cnt ) {
      case 33UL: if( total_shreds <= 33UL ) break; gf_stu( parity_shred[ 33UL-data_shred_cnt ] + shred_pos, in33 ); in33 = gf_zero(); FALLTHRU
      case 34UL: if( total_shreds <= 34UL ) break; gf_stu( parity_shred[ 34UL-data_shred_cnt ] + shred_pos, in34 ); in34 = gf_zero(); FALLTHRU
      case 35UL: if( total_shreds <= 35UL ) break; gf_stu( parity_shred[ 35UL-data_shred_cnt ] + shred_pos, in35 ); in35 = gf_zero(); FALLTHRU
      case 36UL: if( total_shreds <= 36UL ) break; gf_stu( parity_shred[ 36UL-data_shred_cnt ] + shred_pos, in36 ); in36 = gf_zero(); FALLTHRU
      case 37UL: if( total_shreds <= 37UL ) break; gf_stu( parity_shred[ 37UL-data_shred_cnt ] + shred_pos, in37 ); in37 = gf_zero(); FALLTHRU
      case 38UL: if( total_shreds <= 38UL ) break; gf_stu( parity_shred[ 38UL-data_shred_cnt ] + shred_pos, in38 ); in38 = gf_zero(); FALLTHRU
      case 39UL: if( total_shreds <= 39UL ) break; gf_stu( parity_shred[ 39UL-data_shred_cnt ] + shred_pos, in39 ); in39 = gf_zero(); FALLTHRU
      case 40UL: if( total_shreds <= 40UL ) break; gf_stu( parity_shred[ 40UL-data_shred_cnt ] + shred_pos, in40 ); in40 = gf_zero(); FALLTHRU
      case 41UL: if( total_shreds <= 41UL ) break; gf_stu( parity_shred[ 41UL-data_shred_cnt ] + shred_pos, in41 ); in41 = gf_zero(); FALLTHRU
      case 42UL: if( total_shreds <= 42UL ) break; gf_stu( parity_shred[ 42UL-data_shred_cnt ] + shred_pos, in42 ); in42 = gf_zero(); FALLTHRU
      case 43UL: if( total_shreds <= 43UL ) break; gf_stu( parity_shred[ 43UL-data_shred_cnt ] + shred_pos, in43 ); in43 = gf_zero(); FALLTHRU
      case 44UL: if( total_shreds <= 44UL ) break; gf_stu( parity_shred[ 44UL-data_shred_cnt ] + shred_pos, in44 ); in44 = gf_zero(); FALLTHRU
      case 45UL: if( total_shreds <= 45UL ) break; gf_stu( parity_shred[ 45UL-data_shred_cnt ] + shred_pos, in45 ); in45 = gf_zero(); FALLTHRU
      case 46UL: if( total_shreds <= 46UL ) break; gf_stu( parity_shred[ 46UL-data_shred_cnt ] + shred_pos, in46 ); in46 = gf_zero(); FALLTHRU
      case 47UL: if( total_shreds <= 47UL ) break; gf_stu( parity_shred[ 47UL-data_shred_cnt ] + shred_pos, in47 ); in47 = gf_zero(); FALLTHRU
      case 48UL: if( total_shreds <= 48UL ) break; gf_stu( parity_shred[ 48UL-data_shred_cnt ] + shred_pos, in48 ); in48 = gf_zero(); FALLTHRU
      case 49UL: if( total_shreds <= 49UL ) break; gf_stu( parity_shred[ 49UL-data_shred_cnt ] + shred_pos, in49 ); in49 = gf_zero(); FALLTHRU
      case 50UL: if( total_shreds <= 50UL ) break; gf_stu( parity_shred[ 50UL-data_shred_cnt ] + shred_pos, in50 ); in50 = gf_zero(); FALLTHRU
      case 51UL: if( total_shreds <= 51UL ) break; gf_stu( parity_shred[ 51UL-data_shred_cnt ] + shred_pos, in51 ); in51 = gf_zero(); FALLTHRU
      case 52UL: if( total_shreds <= 52UL ) break; gf_stu( parity_shred[ 52UL-data_shred_cnt ] + shred_pos, in52 ); in52 = gf_zero(); FALLTHRU
      case 53UL: if( total_shreds <= 53UL ) break; gf_stu( parity_shred[ 53UL-data_shred_cnt ] + shred_pos, in53 ); in53 = gf_zero(); FALLTHRU
      case 54UL: if( total_shreds <= 54UL ) break; gf_stu( parity_shred[ 54UL-data_shred_cnt ] + shred_pos, in54 ); in54 = gf_zero(); FALLTHRU
      case 55UL: if( total_shreds <= 55UL ) break; gf_stu( parity_shred[ 55UL-data_shred_cnt ] + shred_pos, in55 ); in55 = gf_zero(); FALLTHRU
      case 56UL: if( total_shreds <= 56UL ) break; gf_stu( parity_shred[ 56UL-data_shred_cnt ] + shred_pos, in56 ); in56 = gf_zero(); FALLTHRU
      case 57UL: if( total_shreds <= 57UL ) break; gf_stu( parity_shred[ 57UL-data_shred_cnt ] + shred_pos, in57 ); in57 = gf_zero(); FALLTHRU
      case 58UL: if( total_shreds <= 58UL ) break; gf_stu( parity_shred[ 58UL-data_shred_cnt ] + shred_pos, in58 ); in58 = gf_zero(); FALLTHRU
      case 59UL: if( total_shreds <= 59UL ) break; gf_stu( parity_shred[ 59UL-data_shred_cnt ] + shred_pos, in59 ); in59 = gf_zero(); FALLTHRU
      case 60UL: if( total_shreds <= 60UL ) break; gf_stu( parity_shred[ 60UL-data_shred_cnt ] + shred_pos, in60 ); in60 = gf_zero(); FALLTHRU
      case 61UL: if( total_shreds <= 61UL ) break; gf_stu( parity_shred[ 61UL-data_shred_cnt ] + shred_pos, in61 ); in61 = gf_zero(); FALLTHRU
      case 62UL: if( total_shreds <= 62UL ) break; gf_stu( parity_shred[ 62UL-data_shred_cnt ] + shred_pos, in62 ); in62 = gf_zero(); FALLTHRU
      case 63UL: if( total_shreds <= 63UL ) break; gf_stu( parity_shred[ 63UL-data_shred_cnt ] + shred_pos, in63 ); in63 = gf_zero();
    }
    ulong parity_produced  = fd_ulong_min( 64UL - data_shred_cnt, parity_shred_cnt );
    ulong parity_remaining = parity_shred_cnt - parity_produced;
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 64 parity shreds */
      FD_REEDSOL_GENERATE_FFT(  64, 64, ALL_VARS );
      switch( parity_remaining ) {
        default:
        case 64UL: gf_stu( parity_shred[ 63UL+parity_produced ] + shred_pos, in63 ); FALLTHRU
        case 63UL: gf_stu( parity_shred[ 62UL+parity_produced ] + shred_pos, in62 ); FALLTHRU
        case 62UL: gf_stu( parity_shred[ 61UL+parity_produced ] + shred_pos, in61 ); FALLTHRU
        case 61UL: gf_stu( parity_shred[ 60UL+parity_produced ] + shred_pos, in60 ); FALLTHRU
        case 60UL: gf_stu( parity_shred[ 59UL+parity_produced ] + shred_pos, in59 ); FALLTHRU
        case 59UL: gf_stu( parity_shred[ 58UL+parity_produced ] + shred_pos, in58 ); FALLTHRU
        case 58UL: gf_stu( parity_shred[ 57UL+parity_produced ] + shred_pos, in57 ); FALLTHRU
        case 57UL: gf_stu( parity_shred[ 56UL+parity_produced ] + shred_pos, in56 ); FALLTHRU
        case 56UL: gf_stu( parity_shred[ 55UL+parity_produced ] + shred_pos, in55 ); FALLTHRU
        case 55UL: gf_stu( parity_shred[ 54UL+parity_produced ] + shred_pos, in54 ); FALLTHRU
        case 54UL: gf_stu( parity_shred[ 53UL+parity_produced ] + shred_pos, in53 ); FALLTHRU
        case 53UL: gf_stu( parity_shred[ 52UL+parity_produced ] + shred_pos, in52 ); FALLTHRU
        case 52UL: gf_stu( parity_shred[ 51UL+parity_produced ] + shred_pos, in51 ); FALLTHRU
        case 51UL: gf_stu( parity_shred[ 50UL+parity_produced ] + shred_pos, in50 ); FALLTHRU
        case 50UL: gf_stu( parity_shred[ 49UL+parity_produced ] + shred_pos, in49 ); FALLTHRU
        case 49UL: gf_stu( parity_shred[ 48UL+parity_produced ] + shred_pos, in48 ); FALLTHRU
        case 48UL: gf_stu( parity_shred[ 47UL+parity_produced ] + shred_pos, in47 ); FALLTHRU
        case 47UL: gf_stu( parity_shred[ 46UL+parity_produced ] + shred_pos, in46 ); FALLTHRU
        case 46UL: gf_stu( parity_shred[ 45UL+parity_produced ] + shred_pos, in45 ); FALLTHRU
        case 45UL: gf_stu( parity_shred[ 44UL+parity_produced ] + shred_pos, in44 ); FALLTHRU
        case 44UL: gf_stu( parity_shred[ 43UL+parity_produced ] + shred_pos, in43 ); FALLTHRU
        case 43UL: gf_stu( parity_shred[ 42UL+parity_produced ] + shred_pos, in42 ); FALLTHRU
        case 42UL: gf_stu( parity_shred[ 41UL+parity_produced ] + shred_pos, in41 ); FALLTHRU
        case 41UL: gf_stu( parity_shred[ 40UL+parity_produced ] + shred_pos, in40 ); FALLTHRU
        case 40UL: gf_stu( parity_shred[ 39UL+parity_produced ] + shred_pos, in39 ); FALLTHRU
        case 39UL: gf_stu( parity_shred[ 38UL+parity_produced ] + shred_pos, in38 ); FALLTHRU
        case 38UL: gf_stu( parity_shred[ 37UL+parity_produced ] + shred_pos, in37 ); FALLTHRU
        case 37UL: gf_stu( parity_shred[ 36UL+parity_produced ] + shred_pos, in36 ); FALLTHRU
        case 36UL: gf_stu( parity_shred[ 35UL+parity_produced ] + shred_pos, in35 ); FALLTHRU
        case 35UL: gf_stu( parity_shred[ 34UL+parity_produced ] + shred_pos, in34 ); FALLTHRU
        case 34UL: gf_stu( parity_shred[ 33UL+parity_produced ] + shred_pos, in33 ); FALLTHRU
        case 33UL: gf_stu( parity_shred[ 32UL+parity_produced ] + shred_pos, in32 ); FALLTHRU
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
      parity_produced += fd_ulong_min( 64UL, parity_remaining );
      parity_remaining = parity_shred_cnt - parity_produced;
    }
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 64 parity shreds */
      FD_REEDSOL_GENERATE_IFFT( 64, 64, ALL_VARS );
      FD_REEDSOL_GENERATE_FFT(  64, 128, ALL_VARS );
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
