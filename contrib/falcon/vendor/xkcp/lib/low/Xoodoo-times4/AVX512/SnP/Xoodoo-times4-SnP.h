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

#ifndef _Xoodoo_times4_SnP_h_
#define _Xoodoo_times4_SnP_h_

#include "Xoodoo-times4-AVX512.h"

typedef Xoodootimes4_align512SIMD128_states Xoodootimes4_states;

#define Xoodootimes4_GetImplementation              Xoodootimes4_AVX512_GetImplementation
#define Xoodootimes4_GetFeatures                    Xoodootimes4_AVX512_GetFeatures

#define Xoodootimes4_StaticInitialize               Xoodootimes4_AVX512_StaticInitialize
#define Xoodootimes4_InitializeAll                  Xoodootimes4_AVX512_InitializeAll
#define Xoodootimes4_AddByte                        Xoodootimes4_AVX512_AddByte
#define Xoodootimes4_AddBytes                       Xoodootimes4_AVX512_AddBytes
#define Xoodootimes4_AddLanesAll                    Xoodootimes4_AVX512_AddLanesAll
#define Xoodootimes4_OverwriteBytes                 Xoodootimes4_AVX512_OverwriteBytes
#define Xoodootimes4_OverwriteLanesAll              Xoodootimes4_AVX512_OverwriteLanesAll
#define Xoodootimes4_OverwriteWithZeroes            Xoodootimes4_AVX512_OverwriteWithZeroes
#define Xoodootimes4_PermuteAll_6rounds             Xoodootimes4_AVX512_PermuteAll_6rounds
#define Xoodootimes4_PermuteAll_12rounds            Xoodootimes4_AVX512_PermuteAll_12rounds
#define Xoodootimes4_ExtractBytes                   Xoodootimes4_AVX512_ExtractBytes
#define Xoodootimes4_ExtractLanesAll                Xoodootimes4_AVX512_ExtractLanesAll
#define Xoodootimes4_ExtractAndAddBytes             Xoodootimes4_AVX512_ExtractAndAddBytes
#define Xoodootimes4_ExtractAndAddLanesAll          Xoodootimes4_AVX512_ExtractAndAddLanesAll

#define Xooffftimes4_AddIs                          Xooffftimes4_AVX512_AddIs
#define Xooffftimes4_CompressFastLoop               Xooffftimes4_AVX512_CompressFastLoop
#define Xooffftimes4_ExpandFastLoop                 Xooffftimes4_AVX512_ExpandFastLoop

#endif
