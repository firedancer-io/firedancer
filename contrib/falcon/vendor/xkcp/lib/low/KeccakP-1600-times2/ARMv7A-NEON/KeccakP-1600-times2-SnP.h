/*
The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to PlSnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_times2_SnP_h_
#define _KeccakP_1600_times2_SnP_h_

#include <stdint.h>
#include "config.h"
#include "PlSnP-common.h"

typedef struct {
    ALIGN(32) uint64_t A[25][2];
} KeccakP1600times2_align256SIMD128_states;

typedef KeccakP1600times2_align256SIMD128_states KeccakP1600times2_states;

#define KeccakP1600times2_GetImplementation()   "64-bit optimized ARM NEON assembler implementation"
#define KeccakP1600times2_GetFeatures()         PlSnP_Feature_Main
#define KeccakP1600times2_statesAlignment       32

void KeccakP1600times2_StaticInitialize( void );
void KeccakP1600times2_InitializeAll(KeccakP1600times2_states *states);
void KeccakP1600times2_AddByte(KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset);
void KeccakP1600times2_AddBytes(KeccakP1600times2_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times2_AddLanesAll(KeccakP1600times2_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times2_OverwriteBytes(KeccakP1600times2_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times2_OverwriteLanesAll(KeccakP1600times2_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times2_OverwriteWithZeroes(KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned int byteCount);
void KeccakP1600times2_PermuteAll_4rounds(KeccakP1600times2_states *states);
void KeccakP1600times2_PermuteAll_6rounds(KeccakP1600times2_states *states);
void KeccakP1600times2_PermuteAll_12rounds(KeccakP1600times2_states *states);
void KeccakP1600times2_PermuteAll_24rounds(KeccakP1600times2_states *states);
void KeccakP1600times2_ExtractBytes(const KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times2_ExtractLanesAll(const KeccakP1600times2_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times2_ExtractAndAddBytes(const KeccakP1600times2_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void KeccakP1600times2_ExtractAndAddLanesAll(const KeccakP1600times2_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);

#define KeccakF1600times2_FastLoop_Absorb(...)          0
#define KeccakP1600times2_12rounds_FastLoop_Absorb(...) 0

#define KeccakP1600times2_KravatteCompress(...)         0
#define KeccakP1600times2_KravatteExpand(...)           0

#define KeccakP1600times2_KT128ProcessLeaves(...)
#define KeccakP1600times2_KT256ProcessLeaves(...)

#endif
