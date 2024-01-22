/* Note: This file is auto generated. */
#include "fd_reedsol_ppt.h"

FD_FN_UNSANITIZED void
fd_reedsol_private_encode_128( ulong                 shred_sz,
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
    gf_t in32 = gf_ldu( data_shred[ 32 ] + shred_pos );  gf_t in33 = gf_ldu( data_shred[ 33 ] + shred_pos );
    gf_t in34 = gf_ldu( data_shred[ 34 ] + shred_pos );  gf_t in35 = gf_ldu( data_shred[ 35 ] + shred_pos );
    gf_t in36 = gf_ldu( data_shred[ 36 ] + shred_pos );  gf_t in37 = gf_ldu( data_shred[ 37 ] + shred_pos );
    gf_t in38 = gf_ldu( data_shred[ 38 ] + shred_pos );  gf_t in39 = gf_ldu( data_shred[ 39 ] + shred_pos );
    gf_t in40 = gf_ldu( data_shred[ 40 ] + shred_pos );  gf_t in41 = gf_ldu( data_shred[ 41 ] + shred_pos );
    gf_t in42 = gf_ldu( data_shred[ 42 ] + shred_pos );  gf_t in43 = gf_ldu( data_shred[ 43 ] + shred_pos );
    gf_t in44 = gf_ldu( data_shred[ 44 ] + shred_pos );  gf_t in45 = gf_ldu( data_shred[ 45 ] + shred_pos );
    gf_t in46 = gf_ldu( data_shred[ 46 ] + shred_pos );  gf_t in47 = gf_ldu( data_shred[ 47 ] + shred_pos );
    gf_t in48 = gf_ldu( data_shred[ 48 ] + shred_pos );  gf_t in49 = gf_ldu( data_shred[ 49 ] + shred_pos );
    gf_t in50 = gf_ldu( data_shred[ 50 ] + shred_pos );  gf_t in51 = gf_ldu( data_shred[ 51 ] + shred_pos );
    gf_t in52 = gf_ldu( data_shred[ 52 ] + shred_pos );  gf_t in53 = gf_ldu( data_shred[ 53 ] + shred_pos );
    gf_t in54 = gf_ldu( data_shred[ 54 ] + shred_pos );  gf_t in55 = gf_ldu( data_shred[ 55 ] + shred_pos );
    gf_t in56 = gf_ldu( data_shred[ 56 ] + shred_pos );  gf_t in57 = gf_ldu( data_shred[ 57 ] + shred_pos );
    gf_t in58 = gf_ldu( data_shred[ 58 ] + shred_pos );  gf_t in59 = gf_ldu( data_shred[ 59 ] + shred_pos );
    gf_t in60 = gf_ldu( data_shred[ 60 ] + shred_pos );  gf_t in61 = gf_ldu( data_shred[ 61 ] + shred_pos );
    gf_t in62 = gf_ldu( data_shred[ 62 ] + shred_pos );  gf_t in63 = gf_ldu( data_shred[ 63 ] + shred_pos );
    gf_t in64 = gf_zero();  gf_t in65 = gf_zero();  gf_t in66 = gf_zero();  gf_t in67 = gf_zero();
    gf_t in68 = gf_zero();  gf_t in69 = gf_zero();  gf_t in70 = gf_zero();  gf_t in71 = gf_zero();
    gf_t in72 = gf_zero();  gf_t in73 = gf_zero();  gf_t in74 = gf_zero();  gf_t in75 = gf_zero();
    gf_t in76 = gf_zero();  gf_t in77 = gf_zero();  gf_t in78 = gf_zero();  gf_t in79 = gf_zero();
    gf_t in80 = gf_zero();  gf_t in81 = gf_zero();  gf_t in82 = gf_zero();  gf_t in83 = gf_zero();
    gf_t in84 = gf_zero();  gf_t in85 = gf_zero();  gf_t in86 = gf_zero();  gf_t in87 = gf_zero();
    gf_t in88 = gf_zero();  gf_t in89 = gf_zero();  gf_t in90 = gf_zero();  gf_t in91 = gf_zero();
    gf_t in92 = gf_zero();  gf_t in93 = gf_zero();  gf_t in94 = gf_zero();  gf_t in95 = gf_zero();
    gf_t in96 = gf_zero();  gf_t in97 = gf_zero();  gf_t in98 = gf_zero();  gf_t in99 = gf_zero();
    gf_t in100 = gf_zero();  gf_t in101 = gf_zero();  gf_t in102 = gf_zero();  gf_t in103 = gf_zero();
    gf_t in104 = gf_zero();  gf_t in105 = gf_zero();  gf_t in106 = gf_zero();  gf_t in107 = gf_zero();
    gf_t in108 = gf_zero();  gf_t in109 = gf_zero();  gf_t in110 = gf_zero();  gf_t in111 = gf_zero();
    gf_t in112 = gf_zero();  gf_t in113 = gf_zero();  gf_t in114 = gf_zero();  gf_t in115 = gf_zero();
    gf_t in116 = gf_zero();  gf_t in117 = gf_zero();  gf_t in118 = gf_zero();  gf_t in119 = gf_zero();
    gf_t in120 = gf_zero();  gf_t in121 = gf_zero();  gf_t in122 = gf_zero();  gf_t in123 = gf_zero();
    gf_t in124 = gf_zero();  gf_t in125 = gf_zero();  gf_t in126 = gf_zero();  gf_t in127 = gf_zero();
    switch( data_shred_cnt ) {
      case 68UL: in67 = gf_ldu( data_shred[ 67 ] + shred_pos ); FALLTHRU
      case 67UL: in66 = gf_ldu( data_shred[ 66 ] + shred_pos ); FALLTHRU
      case 66UL: in65 = gf_ldu( data_shred[ 65 ] + shred_pos ); FALLTHRU
      case 65UL: in64 = gf_ldu( data_shred[ 64 ] + shred_pos );
    }
    #define ALL_VARS in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31, in32, in33, in34, in35, in36, in37, in38, in39, in40, in41, in42, in43, in44, in45, in46, in47, in48, in49, in50, in51, in52, in53, in54, in55, in56, in57, in58, in59, in60, in61, in62, in63, in64, in65, in66, in67, in68, in69, in70, in71, in72, in73, in74, in75, in76, in77, in78, in79, in80, in81, in82, in83, in84, in85, in86, in87, in88, in89, in90, in91, in92, in93, in94, in95, in96, in97, in98, in99, in100, in101, in102, in103, in104, in105, in106, in107, in108, in109, in110, in111, in112, in113, in114, in115, in116, in117, in118, in119, in120, in121, in122, in123, in124, in125, in126, in127
    #define ALL_VARS_REF &in00, &in01, &in02, &in03, &in04, &in05, &in06, &in07, &in08, &in09, &in10, &in11, &in12, &in13, &in14, &in15, &in16, &in17, &in18, &in19, &in20, &in21, &in22, &in23, &in24, &in25, &in26, &in27, &in28, &in29, &in30, &in31, &in32, &in33, &in34, &in35, &in36, &in37, &in38, &in39, &in40, &in41, &in42, &in43, &in44, &in45, &in46, &in47, &in48, &in49, &in50, &in51, &in52, &in53, &in54, &in55, &in56, &in57, &in58, &in59, &in60, &in61, &in62, &in63, &in64, &in65, &in66, &in67, &in68, &in69, &in70, &in71, &in72, &in73, &in74, &in75, &in76, &in77, &in78, &in79, &in80, &in81, &in82, &in83, &in84, &in85, &in86, &in87, &in88, &in89, &in90, &in91, &in92, &in93, &in94, &in95, &in96, &in97, &in98, &in99, &in100, &in101, &in102, &in103, &in104, &in105, &in106, &in107, &in108, &in109, &in110, &in111, &in112, &in113, &in114, &in115, &in116, &in117, &in118, &in119, &in120, &in121, &in122, &in123, &in124, &in125, &in126, &in127
    switch( data_shred_cnt ) {
      case 67UL: fd_reedsol_ppt_128_67( ALL_VARS_REF ); break;
      case 66UL: fd_reedsol_ppt_128_66( ALL_VARS_REF ); break;
      case 65UL: fd_reedsol_ppt_128_65( ALL_VARS_REF ); break;
    }
    /* That generated the first 128-data_shred_cnt parity shreds in the
       last 128-data_shred_cnt variables. We might only need
       parity_shred_cnt of them though. */
    ulong total_shreds = data_shred_cnt+parity_shred_cnt;
    switch( data_shred_cnt ) {
      case 65UL: if( total_shreds <= 65UL ) break; gf_stu( parity_shred[ 65UL-data_shred_cnt ] + shred_pos, in65 ); in65 = gf_zero(); FALLTHRU
      case 66UL: if( total_shreds <= 66UL ) break; gf_stu( parity_shred[ 66UL-data_shred_cnt ] + shred_pos, in66 ); in66 = gf_zero(); FALLTHRU
      case 67UL: if( total_shreds <= 67UL ) break; gf_stu( parity_shred[ 67UL-data_shred_cnt ] + shred_pos, in67 ); in67 = gf_zero(); FALLTHRU
      case 68UL: if( total_shreds <= 68UL ) break; gf_stu( parity_shred[ 68UL-data_shred_cnt ] + shred_pos, in68 ); in68 = gf_zero(); FALLTHRU
      case 69UL: if( total_shreds <= 69UL ) break; gf_stu( parity_shred[ 69UL-data_shred_cnt ] + shred_pos, in69 ); in69 = gf_zero(); FALLTHRU
      case 70UL: if( total_shreds <= 70UL ) break; gf_stu( parity_shred[ 70UL-data_shred_cnt ] + shred_pos, in70 ); in70 = gf_zero(); FALLTHRU
      case 71UL: if( total_shreds <= 71UL ) break; gf_stu( parity_shred[ 71UL-data_shred_cnt ] + shred_pos, in71 ); in71 = gf_zero(); FALLTHRU
      case 72UL: if( total_shreds <= 72UL ) break; gf_stu( parity_shred[ 72UL-data_shred_cnt ] + shred_pos, in72 ); in72 = gf_zero(); FALLTHRU
      case 73UL: if( total_shreds <= 73UL ) break; gf_stu( parity_shred[ 73UL-data_shred_cnt ] + shred_pos, in73 ); in73 = gf_zero(); FALLTHRU
      case 74UL: if( total_shreds <= 74UL ) break; gf_stu( parity_shred[ 74UL-data_shred_cnt ] + shred_pos, in74 ); in74 = gf_zero(); FALLTHRU
      case 75UL: if( total_shreds <= 75UL ) break; gf_stu( parity_shred[ 75UL-data_shred_cnt ] + shred_pos, in75 ); in75 = gf_zero(); FALLTHRU
      case 76UL: if( total_shreds <= 76UL ) break; gf_stu( parity_shred[ 76UL-data_shred_cnt ] + shred_pos, in76 ); in76 = gf_zero(); FALLTHRU
      case 77UL: if( total_shreds <= 77UL ) break; gf_stu( parity_shred[ 77UL-data_shred_cnt ] + shred_pos, in77 ); in77 = gf_zero(); FALLTHRU
      case 78UL: if( total_shreds <= 78UL ) break; gf_stu( parity_shred[ 78UL-data_shred_cnt ] + shred_pos, in78 ); in78 = gf_zero(); FALLTHRU
      case 79UL: if( total_shreds <= 79UL ) break; gf_stu( parity_shred[ 79UL-data_shred_cnt ] + shred_pos, in79 ); in79 = gf_zero(); FALLTHRU
      case 80UL: if( total_shreds <= 80UL ) break; gf_stu( parity_shred[ 80UL-data_shred_cnt ] + shred_pos, in80 ); in80 = gf_zero(); FALLTHRU
      case 81UL: if( total_shreds <= 81UL ) break; gf_stu( parity_shred[ 81UL-data_shred_cnt ] + shred_pos, in81 ); in81 = gf_zero(); FALLTHRU
      case 82UL: if( total_shreds <= 82UL ) break; gf_stu( parity_shred[ 82UL-data_shred_cnt ] + shred_pos, in82 ); in82 = gf_zero(); FALLTHRU
      case 83UL: if( total_shreds <= 83UL ) break; gf_stu( parity_shred[ 83UL-data_shred_cnt ] + shred_pos, in83 ); in83 = gf_zero(); FALLTHRU
      case 84UL: if( total_shreds <= 84UL ) break; gf_stu( parity_shred[ 84UL-data_shred_cnt ] + shred_pos, in84 ); in84 = gf_zero(); FALLTHRU
      case 85UL: if( total_shreds <= 85UL ) break; gf_stu( parity_shred[ 85UL-data_shred_cnt ] + shred_pos, in85 ); in85 = gf_zero(); FALLTHRU
      case 86UL: if( total_shreds <= 86UL ) break; gf_stu( parity_shred[ 86UL-data_shred_cnt ] + shred_pos, in86 ); in86 = gf_zero(); FALLTHRU
      case 87UL: if( total_shreds <= 87UL ) break; gf_stu( parity_shred[ 87UL-data_shred_cnt ] + shred_pos, in87 ); in87 = gf_zero(); FALLTHRU
      case 88UL: if( total_shreds <= 88UL ) break; gf_stu( parity_shred[ 88UL-data_shred_cnt ] + shred_pos, in88 ); in88 = gf_zero(); FALLTHRU
      case 89UL: if( total_shreds <= 89UL ) break; gf_stu( parity_shred[ 89UL-data_shred_cnt ] + shred_pos, in89 ); in89 = gf_zero(); FALLTHRU
      case 90UL: if( total_shreds <= 90UL ) break; gf_stu( parity_shred[ 90UL-data_shred_cnt ] + shred_pos, in90 ); in90 = gf_zero(); FALLTHRU
      case 91UL: if( total_shreds <= 91UL ) break; gf_stu( parity_shred[ 91UL-data_shred_cnt ] + shred_pos, in91 ); in91 = gf_zero(); FALLTHRU
      case 92UL: if( total_shreds <= 92UL ) break; gf_stu( parity_shred[ 92UL-data_shred_cnt ] + shred_pos, in92 ); in92 = gf_zero(); FALLTHRU
      case 93UL: if( total_shreds <= 93UL ) break; gf_stu( parity_shred[ 93UL-data_shred_cnt ] + shred_pos, in93 ); in93 = gf_zero(); FALLTHRU
      case 94UL: if( total_shreds <= 94UL ) break; gf_stu( parity_shred[ 94UL-data_shred_cnt ] + shred_pos, in94 ); in94 = gf_zero(); FALLTHRU
      case 95UL: if( total_shreds <= 95UL ) break; gf_stu( parity_shred[ 95UL-data_shred_cnt ] + shred_pos, in95 ); in95 = gf_zero(); FALLTHRU
      case 96UL: if( total_shreds <= 96UL ) break; gf_stu( parity_shred[ 96UL-data_shred_cnt ] + shred_pos, in96 ); in96 = gf_zero(); FALLTHRU
      case 97UL: if( total_shreds <= 97UL ) break; gf_stu( parity_shred[ 97UL-data_shred_cnt ] + shred_pos, in97 ); in97 = gf_zero(); FALLTHRU
      case 98UL: if( total_shreds <= 98UL ) break; gf_stu( parity_shred[ 98UL-data_shred_cnt ] + shred_pos, in98 ); in98 = gf_zero(); FALLTHRU
      case 99UL: if( total_shreds <= 99UL ) break; gf_stu( parity_shred[ 99UL-data_shred_cnt ] + shred_pos, in99 ); in99 = gf_zero(); FALLTHRU
      case 100UL: if( total_shreds <= 100UL ) break; gf_stu( parity_shred[ 100UL-data_shred_cnt ] + shred_pos, in100 ); in100 = gf_zero(); FALLTHRU
      case 101UL: if( total_shreds <= 101UL ) break; gf_stu( parity_shred[ 101UL-data_shred_cnt ] + shred_pos, in101 ); in101 = gf_zero(); FALLTHRU
      case 102UL: if( total_shreds <= 102UL ) break; gf_stu( parity_shred[ 102UL-data_shred_cnt ] + shred_pos, in102 ); in102 = gf_zero(); FALLTHRU
      case 103UL: if( total_shreds <= 103UL ) break; gf_stu( parity_shred[ 103UL-data_shred_cnt ] + shred_pos, in103 ); in103 = gf_zero(); FALLTHRU
      case 104UL: if( total_shreds <= 104UL ) break; gf_stu( parity_shred[ 104UL-data_shred_cnt ] + shred_pos, in104 ); in104 = gf_zero(); FALLTHRU
      case 105UL: if( total_shreds <= 105UL ) break; gf_stu( parity_shred[ 105UL-data_shred_cnt ] + shred_pos, in105 ); in105 = gf_zero(); FALLTHRU
      case 106UL: if( total_shreds <= 106UL ) break; gf_stu( parity_shred[ 106UL-data_shred_cnt ] + shred_pos, in106 ); in106 = gf_zero(); FALLTHRU
      case 107UL: if( total_shreds <= 107UL ) break; gf_stu( parity_shred[ 107UL-data_shred_cnt ] + shred_pos, in107 ); in107 = gf_zero(); FALLTHRU
      case 108UL: if( total_shreds <= 108UL ) break; gf_stu( parity_shred[ 108UL-data_shred_cnt ] + shred_pos, in108 ); in108 = gf_zero(); FALLTHRU
      case 109UL: if( total_shreds <= 109UL ) break; gf_stu( parity_shred[ 109UL-data_shred_cnt ] + shred_pos, in109 ); in109 = gf_zero(); FALLTHRU
      case 110UL: if( total_shreds <= 110UL ) break; gf_stu( parity_shred[ 110UL-data_shred_cnt ] + shred_pos, in110 ); in110 = gf_zero(); FALLTHRU
      case 111UL: if( total_shreds <= 111UL ) break; gf_stu( parity_shred[ 111UL-data_shred_cnt ] + shred_pos, in111 ); in111 = gf_zero(); FALLTHRU
      case 112UL: if( total_shreds <= 112UL ) break; gf_stu( parity_shred[ 112UL-data_shred_cnt ] + shred_pos, in112 ); in112 = gf_zero(); FALLTHRU
      case 113UL: if( total_shreds <= 113UL ) break; gf_stu( parity_shred[ 113UL-data_shred_cnt ] + shred_pos, in113 ); in113 = gf_zero(); FALLTHRU
      case 114UL: if( total_shreds <= 114UL ) break; gf_stu( parity_shred[ 114UL-data_shred_cnt ] + shred_pos, in114 ); in114 = gf_zero(); FALLTHRU
      case 115UL: if( total_shreds <= 115UL ) break; gf_stu( parity_shred[ 115UL-data_shred_cnt ] + shred_pos, in115 ); in115 = gf_zero(); FALLTHRU
      case 116UL: if( total_shreds <= 116UL ) break; gf_stu( parity_shred[ 116UL-data_shred_cnt ] + shred_pos, in116 ); in116 = gf_zero(); FALLTHRU
      case 117UL: if( total_shreds <= 117UL ) break; gf_stu( parity_shred[ 117UL-data_shred_cnt ] + shred_pos, in117 ); in117 = gf_zero(); FALLTHRU
      case 118UL: if( total_shreds <= 118UL ) break; gf_stu( parity_shred[ 118UL-data_shred_cnt ] + shred_pos, in118 ); in118 = gf_zero(); FALLTHRU
      case 119UL: if( total_shreds <= 119UL ) break; gf_stu( parity_shred[ 119UL-data_shred_cnt ] + shred_pos, in119 ); in119 = gf_zero(); FALLTHRU
      case 120UL: if( total_shreds <= 120UL ) break; gf_stu( parity_shred[ 120UL-data_shred_cnt ] + shred_pos, in120 ); in120 = gf_zero(); FALLTHRU
      case 121UL: if( total_shreds <= 121UL ) break; gf_stu( parity_shred[ 121UL-data_shred_cnt ] + shred_pos, in121 ); in121 = gf_zero(); FALLTHRU
      case 122UL: if( total_shreds <= 122UL ) break; gf_stu( parity_shred[ 122UL-data_shred_cnt ] + shred_pos, in122 ); in122 = gf_zero(); FALLTHRU
      case 123UL: if( total_shreds <= 123UL ) break; gf_stu( parity_shred[ 123UL-data_shred_cnt ] + shred_pos, in123 ); in123 = gf_zero(); FALLTHRU
      case 124UL: if( total_shreds <= 124UL ) break; gf_stu( parity_shred[ 124UL-data_shred_cnt ] + shred_pos, in124 ); in124 = gf_zero(); FALLTHRU
      case 125UL: if( total_shreds <= 125UL ) break; gf_stu( parity_shred[ 125UL-data_shred_cnt ] + shred_pos, in125 ); in125 = gf_zero(); FALLTHRU
      case 126UL: if( total_shreds <= 126UL ) break; gf_stu( parity_shred[ 126UL-data_shred_cnt ] + shred_pos, in126 ); in126 = gf_zero(); FALLTHRU
      case 127UL: if( total_shreds <= 127UL ) break; gf_stu( parity_shred[ 127UL-data_shred_cnt ] + shred_pos, in127 ); in127 = gf_zero();
    }
    ulong parity_produced  = fd_ulong_min( 128UL - data_shred_cnt, parity_shred_cnt );
    ulong parity_remaining = parity_shred_cnt - parity_produced;
    if( FD_UNLIKELY( parity_remaining>0UL ) ) {
      /* Produce another 128 parity shreds */
      FD_REEDSOL_GENERATE_FFT(  128, 128, ALL_VARS );
      switch( parity_remaining ) {
        default:
        case 68UL: gf_stu( parity_shred[ 67UL+parity_produced ] + shred_pos, in67 ); FALLTHRU
        case 67UL: gf_stu( parity_shred[ 66UL+parity_produced ] + shred_pos, in66 ); FALLTHRU
        case 66UL: gf_stu( parity_shred[ 65UL+parity_produced ] + shred_pos, in65 ); FALLTHRU
        case 65UL: gf_stu( parity_shred[ 64UL+parity_produced ] + shred_pos, in64 ); FALLTHRU
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
      parity_produced += fd_ulong_min( 68UL, parity_remaining );
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
