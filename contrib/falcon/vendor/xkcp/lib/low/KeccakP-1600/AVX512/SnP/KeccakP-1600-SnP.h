/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to SnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_SnP_h_
#define _KeccakP_1600_SnP_h_

#include "KeccakP-1600-AVX512.h"

typedef KeccakP1600_plain64_state KeccakP1600_state;

#define KeccakP1600_GetImplementation               KeccakP1600_AVX512_GetImplementation
#define KeccakP1600_GetFeatures                     KeccakP1600_AVX512_GetFeatures
#define KeccakP1600_StaticInitialize                KeccakP1600_AVX512_StaticInitialize
#define KeccakP1600_Initialize                      KeccakP1600_AVX512_Initialize
#define KeccakP1600_AddByte                         KeccakP1600_AVX512_AddByte
#define KeccakP1600_AddBytes                        KeccakP1600_AVX512_AddBytes
#define KeccakP1600_OverwriteBytes                  KeccakP1600_AVX512_OverwriteBytes
#define KeccakP1600_OverwriteWithZeroes             KeccakP1600_AVX512_OverwriteWithZeroes
#define KeccakP1600_Permute_Nrounds                 KeccakP1600_AVX512_Permute_Nrounds
#define KeccakP1600_Permute_12rounds                KeccakP1600_AVX512_Permute_12rounds
#define KeccakP1600_Permute_24rounds                KeccakP1600_AVX512_Permute_24rounds
#define KeccakP1600_ExtractBytes                    KeccakP1600_AVX512_ExtractBytes
#define KeccakP1600_ExtractAndAddBytes              KeccakP1600_AVX512_ExtractAndAddBytes
#define KeccakF1600_FastLoop_Absorb                 KeccakF1600_AVX512_FastLoop_Absorb
#define KeccakP1600_12rounds_FastLoop_Absorb        KeccakP1600_12rounds_AVX512_FastLoop_Absorb

#define KeccakP1600_ODDuplexingFastInOut(...)           0
#define KeccakP1600_12rounds_ODDuplexingFastInOut(...)  0
#define KeccakP1600_ODDuplexingFastOut(...)             0
#define KeccakP1600_12rounds_ODDuplexingFastOut(...)    0
#define KeccakP1600_ODDuplexingFastIn(...)              0
#define KeccakP1600_12rounds_ODDuplexingFastIn(...)     0

#endif
