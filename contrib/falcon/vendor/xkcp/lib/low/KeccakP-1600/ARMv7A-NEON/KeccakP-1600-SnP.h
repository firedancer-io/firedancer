/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

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

#include <stdint.h>
#include "align.h"
#include "SnP-common.h"

typedef struct {
    ALIGN(32) uint64_t A[25];
} KeccakP1600_align256plain64_state;

typedef KeccakP1600_align256plain64_state KeccakP1600_state;

#define KeccakP1600_GetImplementation()             "64-bit optimized ARM assembler implementation"
#define KeccakP1600_GetFeatures()                   (SnP_Feature_Main)
#define KeccakP1600_stateAlignment      32

/* void KeccakP1600_StaticInitialize( void ); */
#define KeccakP1600_StaticInitialize()
void KeccakP1600_Initialize(KeccakP1600_align256plain64_state *state);
/* void KeccakP1600_AddByte(KeccakP1600_align256plain64_state *state, unsigned char data, unsigned int offset); */
#define KeccakP1600_AddByte(argS, argData, argOffset)   ((unsigned char*)argS)[argOffset] ^= (argData)
void KeccakP1600_AddBytes(KeccakP1600_align256plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteBytes(KeccakP1600_align256plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteWithZeroes(KeccakP1600_align256plain64_state *state, unsigned int byteCount);
void KeccakP1600_Permute_Nrounds(KeccakP1600_align256plain64_state *state, unsigned int nrounds);
void KeccakP1600_Permute_12rounds(KeccakP1600_align256plain64_state *state);
void KeccakP1600_Permute_24rounds(KeccakP1600_align256plain64_state *state);
void KeccakP1600_ExtractBytes(const KeccakP1600_align256plain64_state *state, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_align256plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);

#define KeccakF1600_FastLoop_Absorb(...)                0
#define KeccakP1600_12rounds_FastLoop_Absorb(...)       0
#define KeccakP1600_ODDuplexingFastInOut(...)           0
#define KeccakP1600_12rounds_ODDuplexingFastInOut(...)  0
#define KeccakP1600_ODDuplexingFastOut(...)             0
#define KeccakP1600_12rounds_ODDuplexingFastOut(...)    0
#define KeccakP1600_ODDuplexingFastIn(...)              0
#define KeccakP1600_12rounds_ODDuplexingFastIn(...)     0

#endif
