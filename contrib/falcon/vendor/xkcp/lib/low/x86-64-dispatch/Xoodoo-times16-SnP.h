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
#include "PlSnP-common.h"

typedef union {
    Xoodootimes16_SIMD512_states AVX512_states;
} Xoodootimes16_states;

const char * Xoodootimes16_GetImplementation();
int Xoodootimes16_GetFeatures();

void Xoodootimes16_StaticInitialize();
void Xoodootimes16_InitializeAll(Xoodootimes16_states *states);

void Xoodootimes16_AddByte(Xoodootimes16_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset);
void Xoodootimes16_AddBytes(Xoodootimes16_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes16_AddLanesAll(Xoodootimes16_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes16_OverwriteBytes(Xoodootimes16_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes16_OverwriteLanesAll(Xoodootimes16_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes16_OverwriteWithZeroes(Xoodootimes16_states *states, unsigned int instanceIndex, unsigned int byteCount);
void Xoodootimes16_PermuteAll_6rounds(Xoodootimes16_states *states);
void Xoodootimes16_PermuteAll_12rounds(Xoodootimes16_states *states);
void Xoodootimes16_ExtractBytes(const Xoodootimes16_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void Xoodootimes16_ExtractLanesAll(const Xoodootimes16_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void Xoodootimes16_ExtractAndAddBytes(const Xoodootimes16_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void Xoodootimes16_ExtractAndAddLanesAll(const Xoodootimes16_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);

void Xooffftimes16_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen);
size_t Xooffftimes16_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length);
size_t Xooffftimes16_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length);

#endif
