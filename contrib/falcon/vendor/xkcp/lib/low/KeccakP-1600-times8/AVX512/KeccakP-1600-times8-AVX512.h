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

#ifndef _KeccakP_1600_times8_AVX512_h_
#define _KeccakP_1600_times8_AVX512_h_

#include <stdint.h>
#include <immintrin.h>
#include "config.h"
#include "PlSnP-common.h"

typedef __m512i  V512;

typedef struct {
    V512 A[25];
} KeccakP1600times8_SIMD512_states;

#ifndef KeccakP1600times8_AVX512_implementation_config
    #define KeccakP1600times8_AVX512_implementation_config "default: 12 rounds unrolled"
    #define KeccakP1600times8_AVX512_unrolling 12
#endif

#define KeccakP1600times8_AVX512_GetImplementation() \
    ("AVX512 implementation (" KeccakP1600times8_AVX512_implementation_config ")")
#define KeccakP1600times8_AVX512_GetFeatures() \
    (PlSnP_Feature_Main | PlSnP_Feature_SpongeAbsorb | PlSnP_Feature_Farfalle | PlSnP_Feature_KangarooTwelve)

#define KeccakP1600times8_AVX512_StaticInitialize()
void KeccakP1600times8_AVX512_InitializeAll(KeccakP1600times8_SIMD512_states *states);
#define KeccakP1600times8_AVX512_AddByte(states, instanceIndex, byte, offset) \
    ((unsigned char*)(states))[(instanceIndex)*8 + ((offset)/8)*8*8 + (offset)%8] ^= (byte)
void KeccakP1600times8_AVX512_AddBytes(KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times8_AVX512_AddLanesAll(KeccakP1600times8_SIMD512_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times8_AVX512_OverwriteBytes(KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times8_AVX512_OverwriteLanesAll(KeccakP1600times8_SIMD512_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times8_AVX512_OverwriteWithZeroes(KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, unsigned int byteCount);
void KeccakP1600times8_AVX512_PermuteAll_4rounds(KeccakP1600times8_SIMD512_states *states);
void KeccakP1600times8_AVX512_PermuteAll_6rounds(KeccakP1600times8_SIMD512_states *states);
void KeccakP1600times8_AVX512_PermuteAll_12rounds(KeccakP1600times8_SIMD512_states *states);
void KeccakP1600times8_AVX512_PermuteAll_24rounds(KeccakP1600times8_SIMD512_states *states);
void KeccakP1600times8_AVX512_ExtractBytes(const KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times8_AVX512_ExtractLanesAll(const KeccakP1600times8_SIMD512_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times8_AVX512_ExtractAndAddBytes(const KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void KeccakP1600times8_AVX512_ExtractAndAddLanesAll(const KeccakP1600times8_SIMD512_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);
size_t KeccakF1600times8_AVX512_FastLoop_Absorb(KeccakP1600times8_SIMD512_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen);
size_t KeccakP1600times8_12rounds_AVX512_FastLoop_Absorb(KeccakP1600times8_SIMD512_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen);
size_t KeccakP1600times8_AVX512_KravatteCompress(uint64_t *xAccu, uint64_t *kRoll, const unsigned char *input, size_t inputByteLen);
size_t KeccakP1600times8_AVX512_KravatteExpand(uint64_t *yAccu, const uint64_t *kRoll, unsigned char *output, size_t outputByteLen);
void KeccakP1600times8_AVX512_KT128ProcessLeaves(const unsigned char *input, unsigned char *output);
void KeccakP1600times8_AVX512_KT256ProcessLeaves(const unsigned char *input, unsigned char *output);

#endif
