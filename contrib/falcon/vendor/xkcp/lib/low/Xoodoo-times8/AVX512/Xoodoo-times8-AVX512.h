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

#ifndef _Xoodoo_times8_AVX512_h_
#define _Xoodoo_times8_AVX512_h_

#include <stdint.h>
#include <immintrin.h>
#include "align.h"
#include "PlSnP-common.h"

typedef __m256i V256;

typedef struct {
    ALIGN(64) V256 A[12];
} Xoodootimes8_align512SIMD256_states;

#define Xoodootimes8_AVX512_GetImplementation()      ("AVX512 implementation")
#define Xoodootimes8_AVX512_GetFeatures()           (PlSnP_Feature_Main | PlSnP_Feature_Farfalle)

#define Xoodootimes8_AVX512_StaticInitialize()
void Xoodootimes8_AVX512_InitializeAll(Xoodootimes8_align512SIMD256_states *states);
#define Xoodootimes8_AVX512_AddByte(states, instanceIndex, byte, offset) \
    ((unsigned char*)(states))[(instanceIndex)*4 + ((offset)/4)*8*4 + (offset)%4] ^= (byte)
void Xoodootimes8_AVX512_AddBytes(Xoodootimes8_align512SIMD256_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes8_AVX512_AddLanesAll(Xoodootimes8_align512SIMD256_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes8_AVX512_OverwriteBytes(Xoodootimes8_align512SIMD256_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes8_AVX512_OverwriteLanesAll(Xoodootimes8_align512SIMD256_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes8_AVX512_OverwriteWithZeroes(Xoodootimes8_align512SIMD256_states *states, unsigned int instanceIndex, unsigned int byteCount);
void Xoodootimes8_AVX512_PermuteAll_6rounds(Xoodootimes8_align512SIMD256_states *states);
void Xoodootimes8_AVX512_PermuteAll_12rounds(Xoodootimes8_align512SIMD256_states *states);
void Xoodootimes8_AVX512_ExtractBytes(const Xoodootimes8_align512SIMD256_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes8_AVX512_ExtractLanesAll(const Xoodootimes8_align512SIMD256_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes8_AVX512_ExtractAndAddBytes(const Xoodootimes8_align512SIMD256_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void Xoodootimes8_AVX512_ExtractAndAddLanesAll(const Xoodootimes8_align512SIMD256_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);

void Xooffftimes8_AVX512_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen);
size_t Xooffftimes8_AVX512_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length);
size_t Xooffftimes8_AVX512_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length);

#endif
