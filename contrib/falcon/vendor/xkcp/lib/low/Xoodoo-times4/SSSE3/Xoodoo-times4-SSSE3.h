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

#ifndef _Xoodoo_times4_SSSE3_h_
#define _Xoodoo_times4_SSSE3_h_

#include <stdint.h>
#include <emmintrin.h>
#include "PlSnP-common.h"

typedef __m128i V128;

typedef struct {
    V128 A[12];
} Xoodootimes4_SIMD128_states;

#define Xoodootimes4_SSSE3_GetImplementation()      ("SSSE3 implementation")
#define Xoodootimes4_SSSE3_GetFeatures()            PlSnP_Feature_Main

#define Xoodootimes4_SSSE3_StaticInitialize()
void Xoodootimes4_SSSE3_InitializeAll(Xoodootimes4_SIMD128_states *states);
#define Xoodootimes4_SSSE3_AddByte(states, instanceIndex, byte, offset) \
    ((unsigned char*)(states))[(instanceIndex)*4 + ((offset)/4)*4*4 + (offset)%4] ^= (byte)
void Xoodootimes4_SSSE3_AddBytes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes4_SSSE3_AddLanesAll(Xoodootimes4_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes4_SSSE3_OverwriteBytes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes4_SSSE3_OverwriteLanesAll(Xoodootimes4_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes4_SSSE3_OverwriteWithZeroes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, unsigned int byteCount);
void Xoodootimes4_SSSE3_PermuteAll_6rounds(Xoodootimes4_SIMD128_states *states);
void Xoodootimes4_SSSE3_PermuteAll_12rounds(Xoodootimes4_SIMD128_states *states);
void Xoodootimes4_SSSE3_ExtractBytes(const Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes4_SSSE3_ExtractLanesAll(const Xoodootimes4_SIMD128_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes4_SSSE3_ExtractAndAddBytes(const Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void Xoodootimes4_SSSE3_ExtractAndAddLanesAll(const Xoodootimes4_SIMD128_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);

#endif
