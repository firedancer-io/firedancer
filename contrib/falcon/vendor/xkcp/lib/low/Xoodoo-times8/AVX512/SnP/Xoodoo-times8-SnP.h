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

#ifndef _Xoodoo_times8_SnP_h_
#define _Xoodoo_times8_SnP_h_

#include "Xoodoo-times8-AVX512.h"

typedef Xoodootimes8_align512SIMD256_states Xoodootimes8_states;

#define Xoodootimes8_GetImplementation              Xoodootimes8_AVX512_GetImplementation
#define Xoodootimes8_GetFeatures                    Xoodootimes8_AVX512_GetFeatures

#define Xoodootimes8_StaticInitialize               Xoodootimes8_AVX512_StaticInitialize
#define Xoodootimes8_InitializeAll                  Xoodootimes8_AVX512_InitializeAll
#define Xoodootimes8_AddByte                        Xoodootimes8_AVX512_AddByte
#define Xoodootimes8_AddBytes                       Xoodootimes8_AVX512_AddBytes
#define Xoodootimes8_AddLanesAll                    Xoodootimes8_AVX512_AddLanesAll
#define Xoodootimes8_OverwriteBytes                 Xoodootimes8_AVX512_OverwriteBytes
#define Xoodootimes8_OverwriteLanesAll              Xoodootimes8_AVX512_OverwriteLanesAll
#define Xoodootimes8_OverwriteWithZeroes            Xoodootimes8_AVX512_OverwriteWithZeroes
#define Xoodootimes8_PermuteAll_6rounds             Xoodootimes8_AVX512_PermuteAll_6rounds
#define Xoodootimes8_PermuteAll_12rounds            Xoodootimes8_AVX512_PermuteAll_12rounds
#define Xoodootimes8_ExtractBytes                   Xoodootimes8_AVX512_ExtractBytes
#define Xoodootimes8_ExtractLanesAll                Xoodootimes8_AVX512_ExtractLanesAll
#define Xoodootimes8_ExtractAndAddBytes             Xoodootimes8_AVX512_ExtractAndAddBytes
#define Xoodootimes8_ExtractAndAddLanesAll          Xoodootimes8_AVX512_ExtractAndAddLanesAll

#define Xooffftimes8_AddIs                          Xooffftimes8_AVX512_AddIs
#define Xooffftimes8_CompressFastLoop               Xooffftimes8_AVX512_CompressFastLoop
#define Xooffftimes8_ExpandFastLoop                 Xooffftimes8_AVX512_ExpandFastLoop

#endif
