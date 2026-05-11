/*
The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _KeccakP_1600_times8_SnP_h_
#define _KeccakP_1600_times8_SnP_h_

#include "KeccakP-1600-times8-AVX512.h"

typedef KeccakP1600times8_SIMD512_states KeccakP1600times8_states;

#define KeccakP1600times8_GetImplementation         KeccakP1600times8_AVX512_GetImplementation
#define KeccakP1600times8_GetFeatures               KeccakP1600times8_AVX512_GetFeatures

#define KeccakP1600times8_StaticInitialize          KeccakP1600times8_AVX512_StaticInitialize
#define KeccakP1600times8_InitializeAll             KeccakP1600times8_AVX512_InitializeAll
#define KeccakP1600times8_AddByte                   KeccakP1600times8_AVX512_AddByte
#define KeccakP1600times8_AddBytes                  KeccakP1600times8_AVX512_AddBytes
#define KeccakP1600times8_AddLanesAll               KeccakP1600times8_AVX512_AddLanesAll
#define KeccakP1600times8_OverwriteBytes            KeccakP1600times8_AVX512_OverwriteBytes
#define KeccakP1600times8_OverwriteLanesAll         KeccakP1600times8_AVX512_OverwriteLanesAll
#define KeccakP1600times8_OverwriteWithZeroes       KeccakP1600times8_AVX512_OverwriteWithZeroes
#define KeccakP1600times8_PermuteAll_4rounds        KeccakP1600times8_AVX512_PermuteAll_4rounds
#define KeccakP1600times8_PermuteAll_6rounds        KeccakP1600times8_AVX512_PermuteAll_6rounds
#define KeccakP1600times8_PermuteAll_12rounds       KeccakP1600times8_AVX512_PermuteAll_12rounds
#define KeccakP1600times8_PermuteAll_24rounds       KeccakP1600times8_AVX512_PermuteAll_24rounds
#define KeccakP1600times8_ExtractBytes              KeccakP1600times8_AVX512_ExtractBytes
#define KeccakP1600times8_ExtractLanesAll           KeccakP1600times8_AVX512_ExtractLanesAll
#define KeccakP1600times8_ExtractAndAddBytes        KeccakP1600times8_AVX512_ExtractAndAddBytes
#define KeccakP1600times8_ExtractAndAddLanesAll     KeccakP1600times8_AVX512_ExtractAndAddLanesAll

#define KeccakF1600times8_FastLoop_Absorb           KeccakF1600times8_AVX512_FastLoop_Absorb
#define KeccakP1600times8_12rounds_FastLoop_Absorb  KeccakP1600times8_12rounds_AVX512_FastLoop_Absorb

#define KeccakP1600times8_KravatteCompress          KeccakP1600times8_AVX512_KravatteCompress
#define KeccakP1600times8_KravatteExpand            KeccakP1600times8_AVX512_KravatteExpand

#define KeccakP1600times8_KT128ProcessLeaves        KeccakP1600times8_AVX512_KT128ProcessLeaves
#define KeccakP1600times8_KT256ProcessLeaves        KeccakP1600times8_AVX512_KT256ProcessLeaves

#endif
