/* Note: This file is auto generated. */
#include "fd_reedsol_ppt.h"
#include "fd_reedsol_fderiv.h"

FD_FN_UNSANITIZED int
fd_reedsol_private_recover_var_256( ulong           shred_sz,
                                    uchar * const * shred,
                                    ulong           data_shred_cnt,
                                    ulong           parity_shred_cnt,
                                    uchar const *   erased ) {
  uchar _erased[ 256 ] W_ATTR;
  uchar pi[      256 ] W_ATTR;
  ulong shred_cnt = data_shred_cnt + parity_shred_cnt;
  ulong loaded_cnt = 0UL;
  for( ulong i=0UL; i<256UL; i++) {
    int load_shred = ((i<shred_cnt)&(loaded_cnt<data_shred_cnt))&&( erased[ i ]==0 );
    _erased[ i ] = !load_shred;
    loaded_cnt += (ulong)load_shred;
  }
  if( FD_UNLIKELY( loaded_cnt<data_shred_cnt ) ) return FD_REEDSOL_ERR_PARTIAL;

  fd_reedsol_private_gen_pi_256( _erased, pi );

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
    gf_t in32 = _erased[ 32 ] ? gf_zero() : gf_ldu( shred[ 32 ] + shred_pos );
    gf_t in33 = _erased[ 33 ] ? gf_zero() : gf_ldu( shred[ 33 ] + shred_pos );
    gf_t in34 = _erased[ 34 ] ? gf_zero() : gf_ldu( shred[ 34 ] + shred_pos );
    gf_t in35 = _erased[ 35 ] ? gf_zero() : gf_ldu( shred[ 35 ] + shred_pos );
    gf_t in36 = _erased[ 36 ] ? gf_zero() : gf_ldu( shred[ 36 ] + shred_pos );
    gf_t in37 = _erased[ 37 ] ? gf_zero() : gf_ldu( shred[ 37 ] + shred_pos );
    gf_t in38 = _erased[ 38 ] ? gf_zero() : gf_ldu( shred[ 38 ] + shred_pos );
    gf_t in39 = _erased[ 39 ] ? gf_zero() : gf_ldu( shred[ 39 ] + shred_pos );
    gf_t in40 = _erased[ 40 ] ? gf_zero() : gf_ldu( shred[ 40 ] + shred_pos );
    gf_t in41 = _erased[ 41 ] ? gf_zero() : gf_ldu( shred[ 41 ] + shred_pos );
    gf_t in42 = _erased[ 42 ] ? gf_zero() : gf_ldu( shred[ 42 ] + shred_pos );
    gf_t in43 = _erased[ 43 ] ? gf_zero() : gf_ldu( shred[ 43 ] + shred_pos );
    gf_t in44 = _erased[ 44 ] ? gf_zero() : gf_ldu( shred[ 44 ] + shred_pos );
    gf_t in45 = _erased[ 45 ] ? gf_zero() : gf_ldu( shred[ 45 ] + shred_pos );
    gf_t in46 = _erased[ 46 ] ? gf_zero() : gf_ldu( shred[ 46 ] + shred_pos );
    gf_t in47 = _erased[ 47 ] ? gf_zero() : gf_ldu( shred[ 47 ] + shred_pos );
    gf_t in48 = _erased[ 48 ] ? gf_zero() : gf_ldu( shred[ 48 ] + shred_pos );
    gf_t in49 = _erased[ 49 ] ? gf_zero() : gf_ldu( shred[ 49 ] + shred_pos );
    gf_t in50 = _erased[ 50 ] ? gf_zero() : gf_ldu( shred[ 50 ] + shred_pos );
    gf_t in51 = _erased[ 51 ] ? gf_zero() : gf_ldu( shred[ 51 ] + shred_pos );
    gf_t in52 = _erased[ 52 ] ? gf_zero() : gf_ldu( shred[ 52 ] + shred_pos );
    gf_t in53 = _erased[ 53 ] ? gf_zero() : gf_ldu( shred[ 53 ] + shred_pos );
    gf_t in54 = _erased[ 54 ] ? gf_zero() : gf_ldu( shred[ 54 ] + shred_pos );
    gf_t in55 = _erased[ 55 ] ? gf_zero() : gf_ldu( shred[ 55 ] + shred_pos );
    gf_t in56 = _erased[ 56 ] ? gf_zero() : gf_ldu( shred[ 56 ] + shred_pos );
    gf_t in57 = _erased[ 57 ] ? gf_zero() : gf_ldu( shred[ 57 ] + shred_pos );
    gf_t in58 = _erased[ 58 ] ? gf_zero() : gf_ldu( shred[ 58 ] + shred_pos );
    gf_t in59 = _erased[ 59 ] ? gf_zero() : gf_ldu( shred[ 59 ] + shred_pos );
    gf_t in60 = _erased[ 60 ] ? gf_zero() : gf_ldu( shred[ 60 ] + shred_pos );
    gf_t in61 = _erased[ 61 ] ? gf_zero() : gf_ldu( shred[ 61 ] + shred_pos );
    gf_t in62 = _erased[ 62 ] ? gf_zero() : gf_ldu( shred[ 62 ] + shred_pos );
    gf_t in63 = _erased[ 63 ] ? gf_zero() : gf_ldu( shred[ 63 ] + shred_pos );
    gf_t in64 = _erased[ 64 ] ? gf_zero() : gf_ldu( shred[ 64 ] + shred_pos );
    gf_t in65 = _erased[ 65 ] ? gf_zero() : gf_ldu( shred[ 65 ] + shred_pos );
    gf_t in66 = _erased[ 66 ] ? gf_zero() : gf_ldu( shred[ 66 ] + shred_pos );
    gf_t in67 = _erased[ 67 ] ? gf_zero() : gf_ldu( shred[ 67 ] + shred_pos );
    gf_t in68 = _erased[ 68 ] ? gf_zero() : gf_ldu( shred[ 68 ] + shred_pos );
    gf_t in69 = _erased[ 69 ] ? gf_zero() : gf_ldu( shred[ 69 ] + shred_pos );
    gf_t in70 = _erased[ 70 ] ? gf_zero() : gf_ldu( shred[ 70 ] + shred_pos );
    gf_t in71 = _erased[ 71 ] ? gf_zero() : gf_ldu( shred[ 71 ] + shred_pos );
    gf_t in72 = _erased[ 72 ] ? gf_zero() : gf_ldu( shred[ 72 ] + shred_pos );
    gf_t in73 = _erased[ 73 ] ? gf_zero() : gf_ldu( shred[ 73 ] + shred_pos );
    gf_t in74 = _erased[ 74 ] ? gf_zero() : gf_ldu( shred[ 74 ] + shred_pos );
    gf_t in75 = _erased[ 75 ] ? gf_zero() : gf_ldu( shred[ 75 ] + shred_pos );
    gf_t in76 = _erased[ 76 ] ? gf_zero() : gf_ldu( shred[ 76 ] + shred_pos );
    gf_t in77 = _erased[ 77 ] ? gf_zero() : gf_ldu( shred[ 77 ] + shred_pos );
    gf_t in78 = _erased[ 78 ] ? gf_zero() : gf_ldu( shred[ 78 ] + shred_pos );
    gf_t in79 = _erased[ 79 ] ? gf_zero() : gf_ldu( shred[ 79 ] + shred_pos );
    gf_t in80 = _erased[ 80 ] ? gf_zero() : gf_ldu( shred[ 80 ] + shred_pos );
    gf_t in81 = _erased[ 81 ] ? gf_zero() : gf_ldu( shred[ 81 ] + shred_pos );
    gf_t in82 = _erased[ 82 ] ? gf_zero() : gf_ldu( shred[ 82 ] + shred_pos );
    gf_t in83 = _erased[ 83 ] ? gf_zero() : gf_ldu( shred[ 83 ] + shred_pos );
    gf_t in84 = _erased[ 84 ] ? gf_zero() : gf_ldu( shred[ 84 ] + shred_pos );
    gf_t in85 = _erased[ 85 ] ? gf_zero() : gf_ldu( shred[ 85 ] + shred_pos );
    gf_t in86 = _erased[ 86 ] ? gf_zero() : gf_ldu( shred[ 86 ] + shred_pos );
    gf_t in87 = _erased[ 87 ] ? gf_zero() : gf_ldu( shred[ 87 ] + shred_pos );
    gf_t in88 = _erased[ 88 ] ? gf_zero() : gf_ldu( shred[ 88 ] + shred_pos );
    gf_t in89 = _erased[ 89 ] ? gf_zero() : gf_ldu( shred[ 89 ] + shred_pos );
    gf_t in90 = _erased[ 90 ] ? gf_zero() : gf_ldu( shred[ 90 ] + shred_pos );
    gf_t in91 = _erased[ 91 ] ? gf_zero() : gf_ldu( shred[ 91 ] + shred_pos );
    gf_t in92 = _erased[ 92 ] ? gf_zero() : gf_ldu( shred[ 92 ] + shred_pos );
    gf_t in93 = _erased[ 93 ] ? gf_zero() : gf_ldu( shred[ 93 ] + shred_pos );
    gf_t in94 = _erased[ 94 ] ? gf_zero() : gf_ldu( shred[ 94 ] + shred_pos );
    gf_t in95 = _erased[ 95 ] ? gf_zero() : gf_ldu( shred[ 95 ] + shred_pos );
    gf_t in96 = _erased[ 96 ] ? gf_zero() : gf_ldu( shred[ 96 ] + shred_pos );
    gf_t in97 = _erased[ 97 ] ? gf_zero() : gf_ldu( shred[ 97 ] + shred_pos );
    gf_t in98 = _erased[ 98 ] ? gf_zero() : gf_ldu( shred[ 98 ] + shred_pos );
    gf_t in99 = _erased[ 99 ] ? gf_zero() : gf_ldu( shred[ 99 ] + shred_pos );
    gf_t in100 = _erased[ 100 ] ? gf_zero() : gf_ldu( shred[ 100 ] + shred_pos );
    gf_t in101 = _erased[ 101 ] ? gf_zero() : gf_ldu( shred[ 101 ] + shred_pos );
    gf_t in102 = _erased[ 102 ] ? gf_zero() : gf_ldu( shred[ 102 ] + shred_pos );
    gf_t in103 = _erased[ 103 ] ? gf_zero() : gf_ldu( shred[ 103 ] + shred_pos );
    gf_t in104 = _erased[ 104 ] ? gf_zero() : gf_ldu( shred[ 104 ] + shred_pos );
    gf_t in105 = _erased[ 105 ] ? gf_zero() : gf_ldu( shred[ 105 ] + shred_pos );
    gf_t in106 = _erased[ 106 ] ? gf_zero() : gf_ldu( shred[ 106 ] + shred_pos );
    gf_t in107 = _erased[ 107 ] ? gf_zero() : gf_ldu( shred[ 107 ] + shred_pos );
    gf_t in108 = _erased[ 108 ] ? gf_zero() : gf_ldu( shred[ 108 ] + shred_pos );
    gf_t in109 = _erased[ 109 ] ? gf_zero() : gf_ldu( shred[ 109 ] + shred_pos );
    gf_t in110 = _erased[ 110 ] ? gf_zero() : gf_ldu( shred[ 110 ] + shred_pos );
    gf_t in111 = _erased[ 111 ] ? gf_zero() : gf_ldu( shred[ 111 ] + shred_pos );
    gf_t in112 = _erased[ 112 ] ? gf_zero() : gf_ldu( shred[ 112 ] + shred_pos );
    gf_t in113 = _erased[ 113 ] ? gf_zero() : gf_ldu( shred[ 113 ] + shred_pos );
    gf_t in114 = _erased[ 114 ] ? gf_zero() : gf_ldu( shred[ 114 ] + shred_pos );
    gf_t in115 = _erased[ 115 ] ? gf_zero() : gf_ldu( shred[ 115 ] + shred_pos );
    gf_t in116 = _erased[ 116 ] ? gf_zero() : gf_ldu( shred[ 116 ] + shred_pos );
    gf_t in117 = _erased[ 117 ] ? gf_zero() : gf_ldu( shred[ 117 ] + shred_pos );
    gf_t in118 = _erased[ 118 ] ? gf_zero() : gf_ldu( shred[ 118 ] + shred_pos );
    gf_t in119 = _erased[ 119 ] ? gf_zero() : gf_ldu( shred[ 119 ] + shred_pos );
    gf_t in120 = _erased[ 120 ] ? gf_zero() : gf_ldu( shred[ 120 ] + shred_pos );
    gf_t in121 = _erased[ 121 ] ? gf_zero() : gf_ldu( shred[ 121 ] + shred_pos );
    gf_t in122 = _erased[ 122 ] ? gf_zero() : gf_ldu( shred[ 122 ] + shred_pos );
    gf_t in123 = _erased[ 123 ] ? gf_zero() : gf_ldu( shred[ 123 ] + shred_pos );
    gf_t in124 = _erased[ 124 ] ? gf_zero() : gf_ldu( shred[ 124 ] + shred_pos );
    gf_t in125 = _erased[ 125 ] ? gf_zero() : gf_ldu( shred[ 125 ] + shred_pos );
    gf_t in126 = _erased[ 126 ] ? gf_zero() : gf_ldu( shred[ 126 ] + shred_pos );
    gf_t in127 = _erased[ 127 ] ? gf_zero() : gf_ldu( shred[ 127 ] + shred_pos );
    gf_t in128 = _erased[ 128 ] ? gf_zero() : gf_ldu( shred[ 128 ] + shred_pos );
    gf_t in129 = _erased[ 129 ] ? gf_zero() : gf_ldu( shred[ 129 ] + shred_pos );
    gf_t in130 = _erased[ 130 ] ? gf_zero() : gf_ldu( shred[ 130 ] + shred_pos );
    gf_t in131 = _erased[ 131 ] ? gf_zero() : gf_ldu( shred[ 131 ] + shred_pos );
    gf_t in132 = _erased[ 132 ] ? gf_zero() : gf_ldu( shred[ 132 ] + shred_pos );
    gf_t in133 = _erased[ 133 ] ? gf_zero() : gf_ldu( shred[ 133 ] + shred_pos );
    gf_t in134 = gf_zero();
    gf_t in135 = gf_zero();
    gf_t in136 = gf_zero();
    gf_t in137 = gf_zero();
    gf_t in138 = gf_zero();
    gf_t in139 = gf_zero();
    gf_t in140 = gf_zero();
    gf_t in141 = gf_zero();
    gf_t in142 = gf_zero();
    gf_t in143 = gf_zero();
    gf_t in144 = gf_zero();
    gf_t in145 = gf_zero();
    gf_t in146 = gf_zero();
    gf_t in147 = gf_zero();
    gf_t in148 = gf_zero();
    gf_t in149 = gf_zero();
    gf_t in150 = gf_zero();
    gf_t in151 = gf_zero();
    gf_t in152 = gf_zero();
    gf_t in153 = gf_zero();
    gf_t in154 = gf_zero();
    gf_t in155 = gf_zero();
    gf_t in156 = gf_zero();
    gf_t in157 = gf_zero();
    gf_t in158 = gf_zero();
    gf_t in159 = gf_zero();
    gf_t in160 = gf_zero();
    gf_t in161 = gf_zero();
    gf_t in162 = gf_zero();
    gf_t in163 = gf_zero();
    gf_t in164 = gf_zero();
    gf_t in165 = gf_zero();
    gf_t in166 = gf_zero();
    gf_t in167 = gf_zero();
    gf_t in168 = gf_zero();
    gf_t in169 = gf_zero();
    gf_t in170 = gf_zero();
    gf_t in171 = gf_zero();
    gf_t in172 = gf_zero();
    gf_t in173 = gf_zero();
    gf_t in174 = gf_zero();
    gf_t in175 = gf_zero();
    gf_t in176 = gf_zero();
    gf_t in177 = gf_zero();
    gf_t in178 = gf_zero();
    gf_t in179 = gf_zero();
    gf_t in180 = gf_zero();
    gf_t in181 = gf_zero();
    gf_t in182 = gf_zero();
    gf_t in183 = gf_zero();
    gf_t in184 = gf_zero();
    gf_t in185 = gf_zero();
    gf_t in186 = gf_zero();
    gf_t in187 = gf_zero();
    gf_t in188 = gf_zero();
    gf_t in189 = gf_zero();
    gf_t in190 = gf_zero();
    gf_t in191 = gf_zero();
    gf_t in192 = gf_zero();
    gf_t in193 = gf_zero();
    gf_t in194 = gf_zero();
    gf_t in195 = gf_zero();
    gf_t in196 = gf_zero();
    gf_t in197 = gf_zero();
    gf_t in198 = gf_zero();
    gf_t in199 = gf_zero();
    gf_t in200 = gf_zero();
    gf_t in201 = gf_zero();
    gf_t in202 = gf_zero();
    gf_t in203 = gf_zero();
    gf_t in204 = gf_zero();
    gf_t in205 = gf_zero();
    gf_t in206 = gf_zero();
    gf_t in207 = gf_zero();
    gf_t in208 = gf_zero();
    gf_t in209 = gf_zero();
    gf_t in210 = gf_zero();
    gf_t in211 = gf_zero();
    gf_t in212 = gf_zero();
    gf_t in213 = gf_zero();
    gf_t in214 = gf_zero();
    gf_t in215 = gf_zero();
    gf_t in216 = gf_zero();
    gf_t in217 = gf_zero();
    gf_t in218 = gf_zero();
    gf_t in219 = gf_zero();
    gf_t in220 = gf_zero();
    gf_t in221 = gf_zero();
    gf_t in222 = gf_zero();
    gf_t in223 = gf_zero();
    gf_t in224 = gf_zero();
    gf_t in225 = gf_zero();
    gf_t in226 = gf_zero();
    gf_t in227 = gf_zero();
    gf_t in228 = gf_zero();
    gf_t in229 = gf_zero();
    gf_t in230 = gf_zero();
    gf_t in231 = gf_zero();
    gf_t in232 = gf_zero();
    gf_t in233 = gf_zero();
    gf_t in234 = gf_zero();
    gf_t in235 = gf_zero();
    gf_t in236 = gf_zero();
    gf_t in237 = gf_zero();
    gf_t in238 = gf_zero();
    gf_t in239 = gf_zero();
    gf_t in240 = gf_zero();
    gf_t in241 = gf_zero();
    gf_t in242 = gf_zero();
    gf_t in243 = gf_zero();
    gf_t in244 = gf_zero();
    gf_t in245 = gf_zero();
    gf_t in246 = gf_zero();
    gf_t in247 = gf_zero();
    gf_t in248 = gf_zero();
    gf_t in249 = gf_zero();
    gf_t in250 = gf_zero();
    gf_t in251 = gf_zero();
    gf_t in252 = gf_zero();
    gf_t in253 = gf_zero();
    gf_t in254 = gf_zero();
    gf_t in255 = gf_zero();
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
    in32 = GF_MUL_VAR( in32, pi[ 32 ] );
    in33 = GF_MUL_VAR( in33, pi[ 33 ] );
    in34 = GF_MUL_VAR( in34, pi[ 34 ] );
    in35 = GF_MUL_VAR( in35, pi[ 35 ] );
    in36 = GF_MUL_VAR( in36, pi[ 36 ] );
    in37 = GF_MUL_VAR( in37, pi[ 37 ] );
    in38 = GF_MUL_VAR( in38, pi[ 38 ] );
    in39 = GF_MUL_VAR( in39, pi[ 39 ] );
    in40 = GF_MUL_VAR( in40, pi[ 40 ] );
    in41 = GF_MUL_VAR( in41, pi[ 41 ] );
    in42 = GF_MUL_VAR( in42, pi[ 42 ] );
    in43 = GF_MUL_VAR( in43, pi[ 43 ] );
    in44 = GF_MUL_VAR( in44, pi[ 44 ] );
    in45 = GF_MUL_VAR( in45, pi[ 45 ] );
    in46 = GF_MUL_VAR( in46, pi[ 46 ] );
    in47 = GF_MUL_VAR( in47, pi[ 47 ] );
    in48 = GF_MUL_VAR( in48, pi[ 48 ] );
    in49 = GF_MUL_VAR( in49, pi[ 49 ] );
    in50 = GF_MUL_VAR( in50, pi[ 50 ] );
    in51 = GF_MUL_VAR( in51, pi[ 51 ] );
    in52 = GF_MUL_VAR( in52, pi[ 52 ] );
    in53 = GF_MUL_VAR( in53, pi[ 53 ] );
    in54 = GF_MUL_VAR( in54, pi[ 54 ] );
    in55 = GF_MUL_VAR( in55, pi[ 55 ] );
    in56 = GF_MUL_VAR( in56, pi[ 56 ] );
    in57 = GF_MUL_VAR( in57, pi[ 57 ] );
    in58 = GF_MUL_VAR( in58, pi[ 58 ] );
    in59 = GF_MUL_VAR( in59, pi[ 59 ] );
    in60 = GF_MUL_VAR( in60, pi[ 60 ] );
    in61 = GF_MUL_VAR( in61, pi[ 61 ] );
    in62 = GF_MUL_VAR( in62, pi[ 62 ] );
    in63 = GF_MUL_VAR( in63, pi[ 63 ] );
    in64 = GF_MUL_VAR( in64, pi[ 64 ] );
    in65 = GF_MUL_VAR( in65, pi[ 65 ] );
    in66 = GF_MUL_VAR( in66, pi[ 66 ] );
    in67 = GF_MUL_VAR( in67, pi[ 67 ] );
    in68 = GF_MUL_VAR( in68, pi[ 68 ] );
    in69 = GF_MUL_VAR( in69, pi[ 69 ] );
    in70 = GF_MUL_VAR( in70, pi[ 70 ] );
    in71 = GF_MUL_VAR( in71, pi[ 71 ] );
    in72 = GF_MUL_VAR( in72, pi[ 72 ] );
    in73 = GF_MUL_VAR( in73, pi[ 73 ] );
    in74 = GF_MUL_VAR( in74, pi[ 74 ] );
    in75 = GF_MUL_VAR( in75, pi[ 75 ] );
    in76 = GF_MUL_VAR( in76, pi[ 76 ] );
    in77 = GF_MUL_VAR( in77, pi[ 77 ] );
    in78 = GF_MUL_VAR( in78, pi[ 78 ] );
    in79 = GF_MUL_VAR( in79, pi[ 79 ] );
    in80 = GF_MUL_VAR( in80, pi[ 80 ] );
    in81 = GF_MUL_VAR( in81, pi[ 81 ] );
    in82 = GF_MUL_VAR( in82, pi[ 82 ] );
    in83 = GF_MUL_VAR( in83, pi[ 83 ] );
    in84 = GF_MUL_VAR( in84, pi[ 84 ] );
    in85 = GF_MUL_VAR( in85, pi[ 85 ] );
    in86 = GF_MUL_VAR( in86, pi[ 86 ] );
    in87 = GF_MUL_VAR( in87, pi[ 87 ] );
    in88 = GF_MUL_VAR( in88, pi[ 88 ] );
    in89 = GF_MUL_VAR( in89, pi[ 89 ] );
    in90 = GF_MUL_VAR( in90, pi[ 90 ] );
    in91 = GF_MUL_VAR( in91, pi[ 91 ] );
    in92 = GF_MUL_VAR( in92, pi[ 92 ] );
    in93 = GF_MUL_VAR( in93, pi[ 93 ] );
    in94 = GF_MUL_VAR( in94, pi[ 94 ] );
    in95 = GF_MUL_VAR( in95, pi[ 95 ] );
    in96 = GF_MUL_VAR( in96, pi[ 96 ] );
    in97 = GF_MUL_VAR( in97, pi[ 97 ] );
    in98 = GF_MUL_VAR( in98, pi[ 98 ] );
    in99 = GF_MUL_VAR( in99, pi[ 99 ] );
    in100 = GF_MUL_VAR( in100, pi[ 100 ] );
    in101 = GF_MUL_VAR( in101, pi[ 101 ] );
    in102 = GF_MUL_VAR( in102, pi[ 102 ] );
    in103 = GF_MUL_VAR( in103, pi[ 103 ] );
    in104 = GF_MUL_VAR( in104, pi[ 104 ] );
    in105 = GF_MUL_VAR( in105, pi[ 105 ] );
    in106 = GF_MUL_VAR( in106, pi[ 106 ] );
    in107 = GF_MUL_VAR( in107, pi[ 107 ] );
    in108 = GF_MUL_VAR( in108, pi[ 108 ] );
    in109 = GF_MUL_VAR( in109, pi[ 109 ] );
    in110 = GF_MUL_VAR( in110, pi[ 110 ] );
    in111 = GF_MUL_VAR( in111, pi[ 111 ] );
    in112 = GF_MUL_VAR( in112, pi[ 112 ] );
    in113 = GF_MUL_VAR( in113, pi[ 113 ] );
    in114 = GF_MUL_VAR( in114, pi[ 114 ] );
    in115 = GF_MUL_VAR( in115, pi[ 115 ] );
    in116 = GF_MUL_VAR( in116, pi[ 116 ] );
    in117 = GF_MUL_VAR( in117, pi[ 117 ] );
    in118 = GF_MUL_VAR( in118, pi[ 118 ] );
    in119 = GF_MUL_VAR( in119, pi[ 119 ] );
    in120 = GF_MUL_VAR( in120, pi[ 120 ] );
    in121 = GF_MUL_VAR( in121, pi[ 121 ] );
    in122 = GF_MUL_VAR( in122, pi[ 122 ] );
    in123 = GF_MUL_VAR( in123, pi[ 123 ] );
    in124 = GF_MUL_VAR( in124, pi[ 124 ] );
    in125 = GF_MUL_VAR( in125, pi[ 125 ] );
    in126 = GF_MUL_VAR( in126, pi[ 126 ] );
    in127 = GF_MUL_VAR( in127, pi[ 127 ] );
    in128 = GF_MUL_VAR( in128, pi[ 128 ] );
    in129 = GF_MUL_VAR( in129, pi[ 129 ] );
    in130 = GF_MUL_VAR( in130, pi[ 130 ] );
    in131 = GF_MUL_VAR( in131, pi[ 131 ] );
    in132 = GF_MUL_VAR( in132, pi[ 132 ] );
    in133 = GF_MUL_VAR( in133, pi[ 133 ] );
    #define ALL_VARS in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31, in32, in33, in34, in35, in36, in37, in38, in39, in40, in41, in42, in43, in44, in45, in46, in47, in48, in49, in50, in51, in52, in53, in54, in55, in56, in57, in58, in59, in60, in61, in62, in63, in64, in65, in66, in67, in68, in69, in70, in71, in72, in73, in74, in75, in76, in77, in78, in79, in80, in81, in82, in83, in84, in85, in86, in87, in88, in89, in90, in91, in92, in93, in94, in95, in96, in97, in98, in99, in100, in101, in102, in103, in104, in105, in106, in107, in108, in109, in110, in111, in112, in113, in114, in115, in116, in117, in118, in119, in120, in121, in122, in123, in124, in125, in126, in127, in128, in129, in130, in131, in132, in133, in134, in135, in136, in137, in138, in139, in140, in141, in142, in143, in144, in145, in146, in147, in148, in149, in150, in151, in152, in153, in154, in155, in156, in157, in158, in159, in160, in161, in162, in163, in164, in165, in166, in167, in168, in169, in170, in171, in172, in173, in174, in175, in176, in177, in178, in179, in180, in181, in182, in183, in184, in185, in186, in187, in188, in189, in190, in191, in192, in193, in194, in195, in196, in197, in198, in199, in200, in201, in202, in203, in204, in205, in206, in207, in208, in209, in210, in211, in212, in213, in214, in215, in216, in217, in218, in219, in220, in221, in222, in223, in224, in225, in226, in227, in228, in229, in230, in231, in232, in233, in234, in235, in236, in237, in238, in239, in240, in241, in242, in243, in244, in245, in246, in247, in248, in249, in250, in251, in252, in253, in254, in255
    #define ALL_VARS_REF &in00, &in01, &in02, &in03, &in04, &in05, &in06, &in07, &in08, &in09, &in10, &in11, &in12, &in13, &in14, &in15, &in16, &in17, &in18, &in19, &in20, &in21, &in22, &in23, &in24, &in25, &in26, &in27, &in28, &in29, &in30, &in31, &in32, &in33, &in34, &in35, &in36, &in37, &in38, &in39, &in40, &in41, &in42, &in43, &in44, &in45, &in46, &in47, &in48, &in49, &in50, &in51, &in52, &in53, &in54, &in55, &in56, &in57, &in58, &in59, &in60, &in61, &in62, &in63, &in64, &in65, &in66, &in67, &in68, &in69, &in70, &in71, &in72, &in73, &in74, &in75, &in76, &in77, &in78, &in79, &in80, &in81, &in82, &in83, &in84, &in85, &in86, &in87, &in88, &in89, &in90, &in91, &in92, &in93, &in94, &in95, &in96, &in97, &in98, &in99, &in100, &in101, &in102, &in103, &in104, &in105, &in106, &in107, &in108, &in109, &in110, &in111, &in112, &in113, &in114, &in115, &in116, &in117, &in118, &in119, &in120, &in121, &in122, &in123, &in124, &in125, &in126, &in127, &in128, &in129, &in130, &in131, &in132, &in133, &in134, &in135, &in136, &in137, &in138, &in139, &in140, &in141, &in142, &in143, &in144, &in145, &in146, &in147, &in148, &in149, &in150, &in151, &in152, &in153, &in154, &in155, &in156, &in157, &in158, &in159, &in160, &in161, &in162, &in163, &in164, &in165, &in166, &in167, &in168, &in169, &in170, &in171, &in172, &in173, &in174, &in175, &in176, &in177, &in178, &in179, &in180, &in181, &in182, &in183, &in184, &in185, &in186, &in187, &in188, &in189, &in190, &in191, &in192, &in193, &in194, &in195, &in196, &in197, &in198, &in199, &in200, &in201, &in202, &in203, &in204, &in205, &in206, &in207, &in208, &in209, &in210, &in211, &in212, &in213, &in214, &in215, &in216, &in217, &in218, &in219, &in220, &in221, &in222, &in223, &in224, &in225, &in226, &in227, &in228, &in229, &in230, &in231, &in232, &in233, &in234, &in235, &in236, &in237, &in238, &in239, &in240, &in241, &in242, &in243, &in244, &in245, &in246, &in247, &in248, &in249, &in250, &in251, &in252, &in253, &in254, &in255

    fd_reedsol_ifft_256_0( ALL_VARS_REF );

    FD_REEDSOL_GENERATE_FDERIV( 256, ALL_VARS );

    fd_reedsol_fft_256_0( ALL_VARS_REF );

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
    in32 = GF_MUL_VAR( in32, pi[ 32 ] );
    in33 = GF_MUL_VAR( in33, pi[ 33 ] );
    in34 = GF_MUL_VAR( in34, pi[ 34 ] );
    in35 = GF_MUL_VAR( in35, pi[ 35 ] );
    in36 = GF_MUL_VAR( in36, pi[ 36 ] );
    in37 = GF_MUL_VAR( in37, pi[ 37 ] );
    in38 = GF_MUL_VAR( in38, pi[ 38 ] );
    in39 = GF_MUL_VAR( in39, pi[ 39 ] );
    in40 = GF_MUL_VAR( in40, pi[ 40 ] );
    in41 = GF_MUL_VAR( in41, pi[ 41 ] );
    in42 = GF_MUL_VAR( in42, pi[ 42 ] );
    in43 = GF_MUL_VAR( in43, pi[ 43 ] );
    in44 = GF_MUL_VAR( in44, pi[ 44 ] );
    in45 = GF_MUL_VAR( in45, pi[ 45 ] );
    in46 = GF_MUL_VAR( in46, pi[ 46 ] );
    in47 = GF_MUL_VAR( in47, pi[ 47 ] );
    in48 = GF_MUL_VAR( in48, pi[ 48 ] );
    in49 = GF_MUL_VAR( in49, pi[ 49 ] );
    in50 = GF_MUL_VAR( in50, pi[ 50 ] );
    in51 = GF_MUL_VAR( in51, pi[ 51 ] );
    in52 = GF_MUL_VAR( in52, pi[ 52 ] );
    in53 = GF_MUL_VAR( in53, pi[ 53 ] );
    in54 = GF_MUL_VAR( in54, pi[ 54 ] );
    in55 = GF_MUL_VAR( in55, pi[ 55 ] );
    in56 = GF_MUL_VAR( in56, pi[ 56 ] );
    in57 = GF_MUL_VAR( in57, pi[ 57 ] );
    in58 = GF_MUL_VAR( in58, pi[ 58 ] );
    in59 = GF_MUL_VAR( in59, pi[ 59 ] );
    in60 = GF_MUL_VAR( in60, pi[ 60 ] );
    in61 = GF_MUL_VAR( in61, pi[ 61 ] );
    in62 = GF_MUL_VAR( in62, pi[ 62 ] );
    in63 = GF_MUL_VAR( in63, pi[ 63 ] );
    in64 = GF_MUL_VAR( in64, pi[ 64 ] );
    in65 = GF_MUL_VAR( in65, pi[ 65 ] );
    in66 = GF_MUL_VAR( in66, pi[ 66 ] );
    in67 = GF_MUL_VAR( in67, pi[ 67 ] );
    in68 = GF_MUL_VAR( in68, pi[ 68 ] );
    in69 = GF_MUL_VAR( in69, pi[ 69 ] );
    in70 = GF_MUL_VAR( in70, pi[ 70 ] );
    in71 = GF_MUL_VAR( in71, pi[ 71 ] );
    in72 = GF_MUL_VAR( in72, pi[ 72 ] );
    in73 = GF_MUL_VAR( in73, pi[ 73 ] );
    in74 = GF_MUL_VAR( in74, pi[ 74 ] );
    in75 = GF_MUL_VAR( in75, pi[ 75 ] );
    in76 = GF_MUL_VAR( in76, pi[ 76 ] );
    in77 = GF_MUL_VAR( in77, pi[ 77 ] );
    in78 = GF_MUL_VAR( in78, pi[ 78 ] );
    in79 = GF_MUL_VAR( in79, pi[ 79 ] );
    in80 = GF_MUL_VAR( in80, pi[ 80 ] );
    in81 = GF_MUL_VAR( in81, pi[ 81 ] );
    in82 = GF_MUL_VAR( in82, pi[ 82 ] );
    in83 = GF_MUL_VAR( in83, pi[ 83 ] );
    in84 = GF_MUL_VAR( in84, pi[ 84 ] );
    in85 = GF_MUL_VAR( in85, pi[ 85 ] );
    in86 = GF_MUL_VAR( in86, pi[ 86 ] );
    in87 = GF_MUL_VAR( in87, pi[ 87 ] );
    in88 = GF_MUL_VAR( in88, pi[ 88 ] );
    in89 = GF_MUL_VAR( in89, pi[ 89 ] );
    in90 = GF_MUL_VAR( in90, pi[ 90 ] );
    in91 = GF_MUL_VAR( in91, pi[ 91 ] );
    in92 = GF_MUL_VAR( in92, pi[ 92 ] );
    in93 = GF_MUL_VAR( in93, pi[ 93 ] );
    in94 = GF_MUL_VAR( in94, pi[ 94 ] );
    in95 = GF_MUL_VAR( in95, pi[ 95 ] );
    in96 = GF_MUL_VAR( in96, pi[ 96 ] );
    in97 = GF_MUL_VAR( in97, pi[ 97 ] );
    in98 = GF_MUL_VAR( in98, pi[ 98 ] );
    in99 = GF_MUL_VAR( in99, pi[ 99 ] );
    in100 = GF_MUL_VAR( in100, pi[ 100 ] );
    in101 = GF_MUL_VAR( in101, pi[ 101 ] );
    in102 = GF_MUL_VAR( in102, pi[ 102 ] );
    in103 = GF_MUL_VAR( in103, pi[ 103 ] );
    in104 = GF_MUL_VAR( in104, pi[ 104 ] );
    in105 = GF_MUL_VAR( in105, pi[ 105 ] );
    in106 = GF_MUL_VAR( in106, pi[ 106 ] );
    in107 = GF_MUL_VAR( in107, pi[ 107 ] );
    in108 = GF_MUL_VAR( in108, pi[ 108 ] );
    in109 = GF_MUL_VAR( in109, pi[ 109 ] );
    in110 = GF_MUL_VAR( in110, pi[ 110 ] );
    in111 = GF_MUL_VAR( in111, pi[ 111 ] );
    in112 = GF_MUL_VAR( in112, pi[ 112 ] );
    in113 = GF_MUL_VAR( in113, pi[ 113 ] );
    in114 = GF_MUL_VAR( in114, pi[ 114 ] );
    in115 = GF_MUL_VAR( in115, pi[ 115 ] );
    in116 = GF_MUL_VAR( in116, pi[ 116 ] );
    in117 = GF_MUL_VAR( in117, pi[ 117 ] );
    in118 = GF_MUL_VAR( in118, pi[ 118 ] );
    in119 = GF_MUL_VAR( in119, pi[ 119 ] );
    in120 = GF_MUL_VAR( in120, pi[ 120 ] );
    in121 = GF_MUL_VAR( in121, pi[ 121 ] );
    in122 = GF_MUL_VAR( in122, pi[ 122 ] );
    in123 = GF_MUL_VAR( in123, pi[ 123 ] );
    in124 = GF_MUL_VAR( in124, pi[ 124 ] );
    in125 = GF_MUL_VAR( in125, pi[ 125 ] );
    in126 = GF_MUL_VAR( in126, pi[ 126 ] );
    in127 = GF_MUL_VAR( in127, pi[ 127 ] );
    in128 = GF_MUL_VAR( in128, pi[ 128 ] );
    in129 = GF_MUL_VAR( in129, pi[ 129 ] );
    in130 = GF_MUL_VAR( in130, pi[ 130 ] );
    in131 = GF_MUL_VAR( in131, pi[ 131 ] );
    in132 = GF_MUL_VAR( in132, pi[ 132 ] );
    in133 = GF_MUL_VAR( in133, pi[ 133 ] );
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
    switch( fd_ulong_min( shred_cnt, 256UL ) ) {
      case 134UL: STORE_COMPARE_RELOAD( 133, in133 ); FALLTHRU
      case 133UL: STORE_COMPARE_RELOAD( 132, in132 ); FALLTHRU
      case 132UL: STORE_COMPARE_RELOAD( 131, in131 ); FALLTHRU
      case 131UL: STORE_COMPARE_RELOAD( 130, in130 ); FALLTHRU
      case 130UL: STORE_COMPARE_RELOAD( 129, in129 ); FALLTHRU
      case 129UL: STORE_COMPARE_RELOAD( 128, in128 ); FALLTHRU
      case 128UL: STORE_COMPARE_RELOAD( 127, in127 ); FALLTHRU
      case 127UL: STORE_COMPARE_RELOAD( 126, in126 ); FALLTHRU
      case 126UL: STORE_COMPARE_RELOAD( 125, in125 ); FALLTHRU
      case 125UL: STORE_COMPARE_RELOAD( 124, in124 ); FALLTHRU
      case 124UL: STORE_COMPARE_RELOAD( 123, in123 ); FALLTHRU
      case 123UL: STORE_COMPARE_RELOAD( 122, in122 ); FALLTHRU
      case 122UL: STORE_COMPARE_RELOAD( 121, in121 ); FALLTHRU
      case 121UL: STORE_COMPARE_RELOAD( 120, in120 ); FALLTHRU
      case 120UL: STORE_COMPARE_RELOAD( 119, in119 ); FALLTHRU
      case 119UL: STORE_COMPARE_RELOAD( 118, in118 ); FALLTHRU
      case 118UL: STORE_COMPARE_RELOAD( 117, in117 ); FALLTHRU
      case 117UL: STORE_COMPARE_RELOAD( 116, in116 ); FALLTHRU
      case 116UL: STORE_COMPARE_RELOAD( 115, in115 ); FALLTHRU
      case 115UL: STORE_COMPARE_RELOAD( 114, in114 ); FALLTHRU
      case 114UL: STORE_COMPARE_RELOAD( 113, in113 ); FALLTHRU
      case 113UL: STORE_COMPARE_RELOAD( 112, in112 ); FALLTHRU
      case 112UL: STORE_COMPARE_RELOAD( 111, in111 ); FALLTHRU
      case 111UL: STORE_COMPARE_RELOAD( 110, in110 ); FALLTHRU
      case 110UL: STORE_COMPARE_RELOAD( 109, in109 ); FALLTHRU
      case 109UL: STORE_COMPARE_RELOAD( 108, in108 ); FALLTHRU
      case 108UL: STORE_COMPARE_RELOAD( 107, in107 ); FALLTHRU
      case 107UL: STORE_COMPARE_RELOAD( 106, in106 ); FALLTHRU
      case 106UL: STORE_COMPARE_RELOAD( 105, in105 ); FALLTHRU
      case 105UL: STORE_COMPARE_RELOAD( 104, in104 ); FALLTHRU
      case 104UL: STORE_COMPARE_RELOAD( 103, in103 ); FALLTHRU
      case 103UL: STORE_COMPARE_RELOAD( 102, in102 ); FALLTHRU
      case 102UL: STORE_COMPARE_RELOAD( 101, in101 ); FALLTHRU
      case 101UL: STORE_COMPARE_RELOAD( 100, in100 ); FALLTHRU
      case 100UL: STORE_COMPARE_RELOAD( 99, in99 ); FALLTHRU
      case 99UL: STORE_COMPARE_RELOAD( 98, in98 ); FALLTHRU
      case 98UL: STORE_COMPARE_RELOAD( 97, in97 ); FALLTHRU
      case 97UL: STORE_COMPARE_RELOAD( 96, in96 ); FALLTHRU
      case 96UL: STORE_COMPARE_RELOAD( 95, in95 ); FALLTHRU
      case 95UL: STORE_COMPARE_RELOAD( 94, in94 ); FALLTHRU
      case 94UL: STORE_COMPARE_RELOAD( 93, in93 ); FALLTHRU
      case 93UL: STORE_COMPARE_RELOAD( 92, in92 ); FALLTHRU
      case 92UL: STORE_COMPARE_RELOAD( 91, in91 ); FALLTHRU
      case 91UL: STORE_COMPARE_RELOAD( 90, in90 ); FALLTHRU
      case 90UL: STORE_COMPARE_RELOAD( 89, in89 ); FALLTHRU
      case 89UL: STORE_COMPARE_RELOAD( 88, in88 ); FALLTHRU
      case 88UL: STORE_COMPARE_RELOAD( 87, in87 ); FALLTHRU
      case 87UL: STORE_COMPARE_RELOAD( 86, in86 ); FALLTHRU
      case 86UL: STORE_COMPARE_RELOAD( 85, in85 ); FALLTHRU
      case 85UL: STORE_COMPARE_RELOAD( 84, in84 ); FALLTHRU
      case 84UL: STORE_COMPARE_RELOAD( 83, in83 ); FALLTHRU
      case 83UL: STORE_COMPARE_RELOAD( 82, in82 ); FALLTHRU
      case 82UL: STORE_COMPARE_RELOAD( 81, in81 ); FALLTHRU
      case 81UL: STORE_COMPARE_RELOAD( 80, in80 ); FALLTHRU
      case 80UL: STORE_COMPARE_RELOAD( 79, in79 ); FALLTHRU
      case 79UL: STORE_COMPARE_RELOAD( 78, in78 ); FALLTHRU
      case 78UL: STORE_COMPARE_RELOAD( 77, in77 ); FALLTHRU
      case 77UL: STORE_COMPARE_RELOAD( 76, in76 ); FALLTHRU
      case 76UL: STORE_COMPARE_RELOAD( 75, in75 ); FALLTHRU
      case 75UL: STORE_COMPARE_RELOAD( 74, in74 ); FALLTHRU
      case 74UL: STORE_COMPARE_RELOAD( 73, in73 ); FALLTHRU
      case 73UL: STORE_COMPARE_RELOAD( 72, in72 ); FALLTHRU
      case 72UL: STORE_COMPARE_RELOAD( 71, in71 ); FALLTHRU
      case 71UL: STORE_COMPARE_RELOAD( 70, in70 ); FALLTHRU
      case 70UL: STORE_COMPARE_RELOAD( 69, in69 ); FALLTHRU
      case 69UL: STORE_COMPARE_RELOAD( 68, in68 ); FALLTHRU
      case 68UL: STORE_COMPARE_RELOAD( 67, in67 ); FALLTHRU
      case 67UL: STORE_COMPARE_RELOAD( 66, in66 ); FALLTHRU
      case 66UL: STORE_COMPARE_RELOAD( 65, in65 ); FALLTHRU
      case 65UL: STORE_COMPARE_RELOAD( 64, in64 ); FALLTHRU
      case 64UL: STORE_COMPARE_RELOAD( 63, in63 ); FALLTHRU
      case 63UL: STORE_COMPARE_RELOAD( 62, in62 ); FALLTHRU
      case 62UL: STORE_COMPARE_RELOAD( 61, in61 ); FALLTHRU
      case 61UL: STORE_COMPARE_RELOAD( 60, in60 ); FALLTHRU
      case 60UL: STORE_COMPARE_RELOAD( 59, in59 ); FALLTHRU
      case 59UL: STORE_COMPARE_RELOAD( 58, in58 ); FALLTHRU
      case 58UL: STORE_COMPARE_RELOAD( 57, in57 ); FALLTHRU
      case 57UL: STORE_COMPARE_RELOAD( 56, in56 ); FALLTHRU
      case 56UL: STORE_COMPARE_RELOAD( 55, in55 ); FALLTHRU
      case 55UL: STORE_COMPARE_RELOAD( 54, in54 ); FALLTHRU
      case 54UL: STORE_COMPARE_RELOAD( 53, in53 ); FALLTHRU
      case 53UL: STORE_COMPARE_RELOAD( 52, in52 ); FALLTHRU
      case 52UL: STORE_COMPARE_RELOAD( 51, in51 ); FALLTHRU
      case 51UL: STORE_COMPARE_RELOAD( 50, in50 ); FALLTHRU
      case 50UL: STORE_COMPARE_RELOAD( 49, in49 ); FALLTHRU
      case 49UL: STORE_COMPARE_RELOAD( 48, in48 ); FALLTHRU
      case 48UL: STORE_COMPARE_RELOAD( 47, in47 ); FALLTHRU
      case 47UL: STORE_COMPARE_RELOAD( 46, in46 ); FALLTHRU
      case 46UL: STORE_COMPARE_RELOAD( 45, in45 ); FALLTHRU
      case 45UL: STORE_COMPARE_RELOAD( 44, in44 ); FALLTHRU
      case 44UL: STORE_COMPARE_RELOAD( 43, in43 ); FALLTHRU
      case 43UL: STORE_COMPARE_RELOAD( 42, in42 ); FALLTHRU
      case 42UL: STORE_COMPARE_RELOAD( 41, in41 ); FALLTHRU
      case 41UL: STORE_COMPARE_RELOAD( 40, in40 ); FALLTHRU
      case 40UL: STORE_COMPARE_RELOAD( 39, in39 ); FALLTHRU
      case 39UL: STORE_COMPARE_RELOAD( 38, in38 ); FALLTHRU
      case 38UL: STORE_COMPARE_RELOAD( 37, in37 ); FALLTHRU
      case 37UL: STORE_COMPARE_RELOAD( 36, in36 ); FALLTHRU
      case 36UL: STORE_COMPARE_RELOAD( 35, in35 ); FALLTHRU
      case 35UL: STORE_COMPARE_RELOAD( 34, in34 ); FALLTHRU
      case 34UL: STORE_COMPARE_RELOAD( 33, in33 ); FALLTHRU
      case 33UL: STORE_COMPARE_RELOAD( 32, in32 ); FALLTHRU
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

    if( FD_UNLIKELY( GF_ANY( diff ) ) ) return FD_REEDSOL_ERR_CORRUPT;
    shred_pos += GF_WIDTH;
    shred_pos = fd_ulong_if( ((shred_sz-GF_WIDTH)<shred_pos) & (shred_pos<shred_sz), shred_sz-GF_WIDTH, shred_pos );
  }
  return FD_REEDSOL_SUCCESS;
}
