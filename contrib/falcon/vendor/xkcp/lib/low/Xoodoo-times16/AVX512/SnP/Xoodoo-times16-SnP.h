/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Xoodoo permutation, designed by Joan Daemen, Seth Hoffert, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _Xoodoo_times16_SnP_h_
#define _Xoodoo_times16_SnP_h_

#include "Xoodoo-times16-AVX512.h"

typedef Xoodootimes16_SIMD512_states Xoodootimes16_states;

#define Xoodootimes16_GetImplementation             Xoodootimes16_AVX512_GetImplementation
#define Xoodootimes16_GetFeatures                   Xoodootimes16_AVX512_GetFeatures

#define Xoodootimes16_StaticInitialize              Xoodootimes16_AVX512_StaticInitialize
#define Xoodootimes16_InitializeAll                 Xoodootimes16_AVX512_InitializeAll
#define Xoodootimes16_AddByte                       Xoodootimes16_AVX512_AddByte
#define Xoodootimes16_AddBytes                      Xoodootimes16_AVX512_AddBytes
#define Xoodootimes16_AddLanesAll                   Xoodootimes16_AVX512_AddLanesAll
#define Xoodootimes16_OverwriteBytes                Xoodootimes16_AVX512_OverwriteBytes
#define Xoodootimes16_OverwriteLanesAll             Xoodootimes16_AVX512_OverwriteLanesAll
#define Xoodootimes16_OverwriteWithZeroes           Xoodootimes16_AVX512_OverwriteWithZeroes
#define Xoodootimes16_PermuteAll_6rounds            Xoodootimes16_AVX512_PermuteAll_6rounds
#define Xoodootimes16_PermuteAll_12rounds           Xoodootimes16_AVX512_PermuteAll_12rounds
#define Xoodootimes16_ExtractBytes                  Xoodootimes16_AVX512_ExtractBytes
#define Xoodootimes16_ExtractLanesAll               Xoodootimes16_AVX512_ExtractLanesAll
#define Xoodootimes16_ExtractAndAddBytes            Xoodootimes16_AVX512_ExtractAndAddBytes
#define Xoodootimes16_ExtractAndAddLanesAll         Xoodootimes16_AVX512_ExtractAndAddLanesAll

#define Xooffftimes16_AddIs                         Xooffftimes16_AVX512_AddIs
#define Xooffftimes16_CompressFastLoop              Xooffftimes16_AVX512_CompressFastLoop
#define Xooffftimes16_ExpandFastLoop                Xooffftimes16_AVX512_ExpandFastLoop

#endif
