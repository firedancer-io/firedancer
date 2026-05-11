/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".

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

#include "KeccakP-1600-plain64.h"
#include "KeccakP-1600-AVX2.h"
#include "KeccakP-1600-AVX512.h"

typedef union {
    KeccakP1600_plain64_state plain64_state;
    KeccakP1600_AVX2_state AVX2_state;
    KeccakP1600_plain64_state AVX512_state;
} KeccakP1600_state;

const char * KeccakP1600_GetImplementation();
int KeccakP1600_GetFeatures();

void KeccakP1600_StaticInitialize();
void KeccakP1600_Initialize(KeccakP1600_state *state);
void KeccakP1600_AddByte(KeccakP1600_state *state, unsigned char data, unsigned int offset);
void KeccakP1600_AddBytes(KeccakP1600_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteBytes(KeccakP1600_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteWithZeroes(KeccakP1600_state *state, unsigned int byteCount);
void KeccakP1600_Permute_Nrounds(KeccakP1600_state *state, unsigned int nrounds);
void KeccakP1600_Permute_12rounds(KeccakP1600_state *state);
void KeccakP1600_Permute_24rounds(KeccakP1600_state *state);
void KeccakP1600_ExtractBytes(const KeccakP1600_state *state, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
size_t KeccakF1600_FastLoop_Absorb(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);
size_t KeccakP1600_12rounds_FastLoop_Absorb(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);
size_t KeccakP1600_ODDuplexingFastInOut(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *idata, size_t len, unsigned char *odata, const unsigned char *odataAdd, uint64_t trailencAsLane);
size_t KeccakP1600_12rounds_ODDuplexingFastInOut(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *idata, size_t len, unsigned char *odata, const unsigned char *odataAdd, uint64_t trailencAsLane);
size_t KeccakP1600_ODDuplexingFastOut(KeccakP1600_state *state, unsigned int laneCount, unsigned char *odata, size_t len, const unsigned char *odataAdd, uint64_t trailencAsLane);
size_t KeccakP1600_12rounds_ODDuplexingFastOut(KeccakP1600_state *state, unsigned int laneCount, unsigned char *odata, size_t len, const unsigned char *odataAdd, uint64_t trailencAsLane);
size_t KeccakP1600_ODDuplexingFastIn(KeccakP1600_state *state, unsigned int laneCount, const uint8_t *idata, size_t len, uint64_t trailencAsLane);
size_t KeccakP1600_12rounds_ODDuplexingFastIn(KeccakP1600_state *state, unsigned int laneCount, const uint8_t *idata, size_t len, uint64_t trailencAsLane);

#endif
