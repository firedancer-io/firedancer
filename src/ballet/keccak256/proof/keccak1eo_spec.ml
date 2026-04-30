(* ========================================================================= *)
(*  EO (even/odd bit-deinterleave) spec layer for the keccak1eo proof.       *)
(*                                                                           *)
(*  Each 64-bit Keccak lane w decomposes as a pair of 32-bit halves:         *)
(*    pack_eo_E w :: int32 — bits w[0], w[2], w[4], ..., w[62]               *)
(*    pack_eo_O w :: int32 — bits w[1], w[3], w[5], ..., w[63]               *)
(*    unpack_eo_word E O :: int64 — interleave bits back together            *)
(*                                                                           *)
(*  Loaded after x86/proofs/utils/keccak_spec.ml.                            *)
(* ========================================================================= *)

let unpack_eo_word = define
 `(unpack_eo_word:int32 -> int32 -> int64) E O =
    word_of_bits { i | i < 64 /\
                       (if EVEN i then bit (i DIV 2) E else bit (i DIV 2) O) }`;;

let pack_eo_E = define
 `(pack_eo_E:int64 -> int32) w = word_of_bits { k | k < 32 /\ bit (2 * k) w }`;;

let pack_eo_O = define
 `(pack_eo_O:int64 -> int32) w = word_of_bits { k | k < 32 /\ bit (2 * k + 1) w }`;;

(* ------------------------------------------------------------------------- *)
(* Bit lookups.                                                              *)
(* ------------------------------------------------------------------------- *)

let BIT_PACK_EO_E = prove
 (`!w:int64 k. bit k (pack_eo_E w) <=> k < 32 /\ bit (2 * k) w`,
  REWRITE_TAC[pack_eo_E; BIT_WORD_OF_BITS; IN_ELIM_THM; DIMINDEX_32] THEN
  CONV_TAC TAUT);;

let BIT_PACK_EO_O = prove
 (`!w:int64 k. bit k (pack_eo_O w) <=> k < 32 /\ bit (2 * k + 1) w`,
  REWRITE_TAC[pack_eo_O; BIT_WORD_OF_BITS; IN_ELIM_THM; DIMINDEX_32] THEN
  CONV_TAC TAUT);;

let BIT_UNPACK_EO_WORD = prove
 (`!E O i. bit i (unpack_eo_word E O) <=>
           i < 64 /\
           (if EVEN i then bit (i DIV 2) E else bit (i DIV 2) O)`,
  REWRITE_TAC[unpack_eo_word; BIT_WORD_OF_BITS; IN_ELIM_THM; DIMINDEX_64] THEN
  REPEAT GEN_TAC THEN COND_CASES_TAC THEN ASM_REWRITE_TAC[CONJ_ACI]);;

(* ------------------------------------------------------------------------- *)
(* Inverses.                                                                 *)
(* ------------------------------------------------------------------------- *)

let UNPACK_PACK_EO = prove
 (`!w:int64. unpack_eo_word (pack_eo_E w) (pack_eo_O w) = w`,
  GEN_TAC THEN
  REWRITE_TAC[WORD_EQ_BITS_ALT; unpack_eo_word; pack_eo_E; pack_eo_O;
              BIT_WORD_OF_BITS; IN_ELIM_THM; DIMINDEX_64; DIMINDEX_32] THEN
  X_GEN_TAC `i:num` THEN DISCH_TAC THEN ASM_REWRITE_TAC[] THEN
  ASM_CASES_TAC `EVEN i` THEN ASM_REWRITE_TAC[] THENL
   [FIRST_X_ASSUM(MP_TAC o REWRITE_RULE[EVEN_EXISTS]) THEN
    DISCH_THEN(fun th -> POP_ASSUM MP_TAC THEN ASSUME_TAC th) THEN
    ASM_REWRITE_TAC[] THEN
    ASM_MESON_TAC[ARITH_RULE `i = 2 * m /\ i < 64 ==> m < 32`;
                  ARITH_RULE `(2 * m) DIV 2 = m`];
    FIRST_X_ASSUM(MP_TAC o REWRITE_RULE[NOT_EVEN; ODD_EXISTS]) THEN STRIP_TAC THEN
    ASM_REWRITE_TAC[ARITH_RULE `SUC(2 * m) DIV 2 = m`;
                    ARITH_RULE `2 * m + 1 = SUC(2 * m)`] THEN
    ASM_MESON_TAC[ARITH_RULE `i = SUC(2 * m) /\ i < 64 ==> m < 32`]]);;

let PACK_UNPACK_EO_E = prove
 (`!E O. pack_eo_E (unpack_eo_word E O) = E`,
  REPEAT GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  X_GEN_TAC `k:num` THEN DISCH_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_E; BIT_UNPACK_EO_WORD] THEN
  ASM_SIMP_TAC[ARITH_RULE `k < 32 ==> 2 * k < 64`; EVEN_DOUBLE;
               ARITH_RULE `(2 * k) DIV 2 = k`]);;

let PACK_UNPACK_EO_O = prove
 (`!E O. pack_eo_O (unpack_eo_word E O) = O`,
  REPEAT GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  X_GEN_TAC `k:num` THEN DISCH_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_O; BIT_UNPACK_EO_WORD] THEN
  ASM_SIMP_TAC[ARITH_RULE `k < 32 ==> 2 * k + 1 < 64`;
               ARITH_RULE `(2 * k + 1) DIV 2 = k`;
               EVEN_ADD; EVEN_MULT; ARITH_EVEN]);;

(* ------------------------------------------------------------------------- *)
(* Distributivity over bitwise ops.                                          *)
(* ------------------------------------------------------------------------- *)

let PACK_EO_E_XOR = prove
 (`!w1 w2:int64. pack_eo_E (w1 ^^ w2) = pack_eo_E w1 ^^ pack_eo_E w2`,
  REPEAT GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_E; BIT_WORD_XOR; DIMINDEX_64; DIMINDEX_32] THEN
  ASM_SIMP_TAC[ARITH_RULE `i < 32 ==> 2 * i < 64`] THEN CONV_TAC TAUT);;

let PACK_EO_O_XOR = prove
 (`!w1 w2:int64. pack_eo_O (w1 ^^ w2) = pack_eo_O w1 ^^ pack_eo_O w2`,
  REPEAT GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_O; BIT_WORD_XOR; DIMINDEX_64; DIMINDEX_32] THEN
  ASM_SIMP_TAC[ARITH_RULE `i < 32 ==> 2 * i + 1 < 64`] THEN CONV_TAC TAUT);;

let PACK_EO_E_AND = prove
 (`!w1 w2:int64.
        pack_eo_E (word_and w1 w2) = word_and (pack_eo_E w1) (pack_eo_E w2)`,
  REPEAT GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_E; BIT_WORD_AND; DIMINDEX_64; DIMINDEX_32] THEN
  ASM_SIMP_TAC[ARITH_RULE `i < 32 ==> 2 * i < 64`] THEN CONV_TAC TAUT);;

let PACK_EO_O_AND = prove
 (`!w1 w2:int64.
        pack_eo_O (word_and w1 w2) = word_and (pack_eo_O w1) (pack_eo_O w2)`,
  REPEAT GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_O; BIT_WORD_AND; DIMINDEX_64; DIMINDEX_32] THEN
  ASM_SIMP_TAC[ARITH_RULE `i < 32 ==> 2 * i + 1 < 64`] THEN CONV_TAC TAUT);;

let PACK_EO_E_NOT = prove
 (`!w:int64. pack_eo_E (word_not w) = word_not (pack_eo_E w)`,
  GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_E; BIT_WORD_NOT; DIMINDEX_64; DIMINDEX_32] THEN
  ASM_SIMP_TAC[ARITH_RULE `i < 32 ==> 2 * i < 64`] THEN CONV_TAC TAUT);;

let PACK_EO_O_NOT = prove
 (`!w:int64. pack_eo_O (word_not w) = word_not (pack_eo_O w)`,
  GEN_TAC THEN REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_32] THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[BIT_PACK_EO_O; BIT_WORD_NOT; DIMINDEX_64; DIMINDEX_32] THEN
  ASM_SIMP_TAC[ARITH_RULE `i < 32 ==> 2 * i + 1 < 64`] THEN CONV_TAC TAUT);;

(* ------------------------------------------------------------------------- *)
(* Lifted to 25-element state lists.                                         *)
(* ------------------------------------------------------------------------- *)

let unpack_eo_state = define
 `unpack_eo_state (Es:int32 list) (Os:int32 list) =
    MAP2 unpack_eo_word Es Os`;;

let pack_eo_state = define
 `pack_eo_state (A:int64 list) =
    APPEND (MAP pack_eo_E A) (MAP pack_eo_O A)`;;

let PACK_E_MAP2_UNPACK = prove
 (`!Es Os:int32 list.
        LENGTH Es = LENGTH Os
        ==> MAP pack_eo_E (MAP2 unpack_eo_word Es Os) = Es`,
  LIST_INDUCT_TAC THEN LIST_INDUCT_TAC THEN
  REWRITE_TAC[LENGTH; MAP2; MAP; SUC_INJ; NOT_SUC; ARITH_EQ; CONS_11] THEN
  ASM_SIMP_TAC[PACK_UNPACK_EO_E]);;

let PACK_O_MAP2_UNPACK = prove
 (`!Es Os:int32 list.
        LENGTH Es = LENGTH Os
        ==> MAP pack_eo_O (MAP2 unpack_eo_word Es Os) = Os`,
  LIST_INDUCT_TAC THEN LIST_INDUCT_TAC THEN
  REWRITE_TAC[LENGTH; MAP2; MAP; SUC_INJ; NOT_SUC; ARITH_EQ; CONS_11] THEN
  ASM_SIMP_TAC[PACK_UNPACK_EO_O]);;

let PACK_UNPACK_EO_STATE = prove
 (`!Es Os:int32 list.
        LENGTH Es = LENGTH Os
        ==> pack_eo_state (unpack_eo_state Es Os) = APPEND Es Os`,
  REWRITE_TAC[pack_eo_state; unpack_eo_state] THEN
  SIMP_TAC[PACK_E_MAP2_UNPACK; PACK_O_MAP2_UNPACK]);;
