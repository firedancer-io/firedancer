/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Xoodoo permutation, designed by Joan Daemen, Seth Hoffert, Gilles Van Assche and Ronny Van Keer.

Implementation by Conno Boel, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _Xoodoo_times4_SnP_h_
#define _Xoodoo_times4_SnP_h_

#include <stdint.h>
#include "align.h"
#include "PlSnP-common.h"

/** For the documentation, see PlSnP-documentation.h. */

typedef struct {
     ALIGN(16) uint32_t A[12][4];
} Xoodootimes4_SIMD128_states;

typedef Xoodootimes4_SIMD128_states Xoodootimes4_states;

#define Xoodootimes4_GetImplementation()            "Optimized ARM Cortex-A7(/A8/A9) NEON assembler implementation"
#define Xoodootimes4_GetFeatures()           (PlSnP_Feature_Main | PlSnP_Feature_Farfalle)

#define Xoodootimes4_StaticInitialize()
void Xoodootimes4_InitializeAll(Xoodootimes4_SIMD128_states *states);
// TODO: Rewrite to assembly
void Xoodootimes4_AddByte(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, const unsigned char byte, unsigned int offset);
void Xoodootimes4_AddBytes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes4_AddLanesAll(Xoodootimes4_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes4_OverwriteBytes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes4_OverwriteLanesAll(Xoodootimes4_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes4_OverwriteWithZeroes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, unsigned int byteCount);
//void Xoodootimes4_PermuteAll_Nrounds(Xoodootimes4_SIMD128_states *states, unsigned int nr);
void Xoodootimes4_PermuteAll_6rounds(Xoodootimes4_SIMD128_states *states);
void Xoodootimes4_PermuteAll_12rounds(Xoodootimes4_SIMD128_states *states);
void Xoodootimes4_ExtractBytes(const Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes4_ExtractLanesAll(const Xoodootimes4_SIMD128_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes4_ExtractAndAddBytes(const Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void Xoodootimes4_ExtractAndAddLanesAll(const Xoodootimes4_SIMD128_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);

void Xooffftimes4_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen);
size_t Xooffftimes4_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length);
size_t Xooffftimes4_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length);

#endif
