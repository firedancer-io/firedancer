/*
The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to PlSnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_times4_SnP_h_
#define _KeccakP_1600_times4_SnP_h_

#include "KeccakP-1600-SnP.h"
#include "PlSnP-common.h"

typedef struct {
    KeccakP1600_state states[4];
} KeccakP1600times4_states;

#define KeccakP1600times4_GetImplementation()       "fallback on serial implementation"
#define KeccakP1600times4_GetFeatures()             PlSnP_Feature_Main

void KeccakP1600times4_StaticInitialize(void);
void KeccakP1600times4_InitializeAll(KeccakP1600times4_states *states);
void KeccakP1600times4_AddByte(KeccakP1600times4_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset);
void KeccakP1600times4_AddBytes(KeccakP1600times4_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times4_AddLanesAll(KeccakP1600times4_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times4_OverwriteBytes(KeccakP1600times4_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times4_OverwriteLanesAll(KeccakP1600times4_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times4_OverwriteWithZeroes(KeccakP1600times4_states *states, unsigned int instanceIndex, unsigned int byteCount);
void KeccakP1600times4_PermuteAll_4rounds(KeccakP1600times4_states *states);
void KeccakP1600times4_PermuteAll_6rounds(KeccakP1600times4_states *states);
void KeccakP1600times4_PermuteAll_12rounds(KeccakP1600times4_states *states);
void KeccakP1600times4_PermuteAll_24rounds(KeccakP1600times4_states *states);
void KeccakP1600times4_ExtractBytes(const KeccakP1600times4_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times4_ExtractLanesAll(const KeccakP1600times4_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times4_ExtractAndAddBytes(const KeccakP1600times4_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void KeccakP1600times4_ExtractAndAddLanesAll(const KeccakP1600times4_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);

#define KeccakF1600times4_FastLoop_Absorb(...)              0
#define KeccakP1600times4_12rounds_FastLoop_Absorb(...)     0
#define KeccakP1600times4_KravatteCompress(...)             0
#define KeccakP1600times4_KravatteExpand(...)               0
#define KeccakP1600times4_KT128ProcessLeaves(...)
#define KeccakP1600times4_KT256ProcessLeaves(...)


#endif
