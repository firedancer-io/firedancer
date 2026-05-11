/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <assert.h>
#include <string.h>
#include "config.h"

int XKCP_SSSE3_requested_disabled = 0;
int XKCP_AVX2_requested_disabled = 0;
int XKCP_AVX512_requested_disabled = 0;
int XKCP_enableSSSE3 = 0;
int XKCP_enableAVX2 = 0;
int XKCP_enableAVX512 = 0;
void XKCP_SetProcessorCapabilities();

#ifdef XKCP_has_KeccakP1600

#include "KeccakP-1600-SnP.h"

const char * KeccakP1600_GetImplementation()
{
    if (XKCP_enableAVX512)
        return KeccakP1600_AVX512_GetImplementation();
    else if (XKCP_enableAVX2)
        return KeccakP1600_AVX2_GetImplementation();
    else
        return KeccakP1600_plain64_GetImplementation();
}

int KeccakP1600_GetFeatures()
{
    if (XKCP_enableAVX512)
        return KeccakP1600_AVX512_GetFeatures();
    else if (XKCP_enableAVX2)
        return KeccakP1600_AVX2_GetFeatures();
    else
        return KeccakP1600_plain64_GetFeatures();
}

void KeccakP1600_StaticInitialize()
{
}

void KeccakP1600_Initialize(KeccakP1600_state *state)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_Initialize(&state->AVX512_state);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_Initialize(&state->AVX2_state);
    else
        KeccakP1600_plain64_Initialize(&state->plain64_state);
}

void KeccakP1600_AddByte(KeccakP1600_state *state, unsigned char data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_AddByte(&state->AVX512_state, data, offset);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_AddByte(&state->AVX2_state, data, offset);
    else
        KeccakP1600_plain64_AddByte(&state->plain64_state, data, offset);
}

void KeccakP1600_AddBytes(KeccakP1600_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_AddBytes(&state->AVX512_state, data, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_AddBytes(&state->AVX2_state, data, offset, length);
    else
        KeccakP1600_plain64_AddBytes(&state->plain64_state, data, offset, length);
}

void KeccakP1600_OverwriteBytes(KeccakP1600_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_OverwriteBytes(&state->AVX512_state, data, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_OverwriteBytes(&state->AVX2_state, data, offset, length);
    else
        KeccakP1600_plain64_OverwriteBytes(&state->plain64_state, data, offset, length);
}

void KeccakP1600_OverwriteWithZeroes(KeccakP1600_state *state, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_OverwriteWithZeroes(&state->AVX512_state, byteCount);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_OverwriteWithZeroes(&state->AVX2_state, byteCount);
    else
        KeccakP1600_plain64_OverwriteWithZeroes(&state->plain64_state, byteCount);
}

void KeccakP1600_Permute_Nrounds(KeccakP1600_state *state, unsigned int nrounds)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_Permute_Nrounds(&state->AVX512_state, nrounds);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_Permute_Nrounds(&state->AVX2_state, nrounds);
    else
        KeccakP1600_plain64_Permute_Nrounds(&state->plain64_state, nrounds);
}

void KeccakP1600_Permute_12rounds(KeccakP1600_state *state)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_Permute_12rounds(&state->AVX512_state);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_Permute_12rounds(&state->AVX2_state);
    else
        KeccakP1600_plain64_Permute_12rounds(&state->plain64_state);
}

void KeccakP1600_Permute_24rounds(KeccakP1600_state *state)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_Permute_24rounds(&state->AVX512_state);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_Permute_24rounds(&state->AVX2_state);
    else
        KeccakP1600_plain64_Permute_24rounds(&state->plain64_state);
}

void KeccakP1600_ExtractBytes(const KeccakP1600_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_ExtractBytes(&state->AVX512_state, data, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_ExtractBytes(&state->AVX2_state, data, offset, length);
    else
        KeccakP1600_plain64_ExtractBytes(&state->plain64_state, data, offset, length);
}

void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600_AVX512_ExtractAndAddBytes(&state->AVX512_state, input, output, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600_AVX2_ExtractAndAddBytes(&state->AVX2_state, input, output, offset, length);
    else
        KeccakP1600_plain64_ExtractAndAddBytes(&state->plain64_state, input, output, offset, length);
}

size_t KeccakF1600_FastLoop_Absorb(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakF1600_AVX512_FastLoop_Absorb(&state->AVX512_state, laneCount, data, dataByteLen);
    else if (XKCP_enableAVX2)
        return KeccakF1600_AVX2_FastLoop_Absorb(&state->AVX2_state, laneCount, data, dataByteLen);
    else
        return KeccakF1600_plain64_FastLoop_Absorb(&state->plain64_state, laneCount, data, dataByteLen);
}

size_t KeccakP1600_12rounds_FastLoop_Absorb(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakP1600_12rounds_AVX512_FastLoop_Absorb(&state->AVX512_state, laneCount, data, dataByteLen);
    else if (XKCP_enableAVX2)
        return KeccakP1600_12rounds_AVX2_FastLoop_Absorb(&state->AVX2_state, laneCount, data, dataByteLen);
    else
        return KeccakP1600_12rounds_plain64_FastLoop_Absorb(&state->plain64_state, laneCount, data, dataByteLen);
}

size_t KeccakP1600_ODDuplexingFastInOut(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *idata, size_t len, unsigned char *odata, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    if (XKCP_enableAVX2 || XKCP_enableAVX512)
        assert(0);
    else
        return KeccakP1600_plain64_ODDuplexingFastInOut(&state->plain64_state, laneCount, idata, len, odata, odataAdd, trailencAsLane);
}

size_t KeccakP1600_12rounds_ODDuplexingFastInOut(KeccakP1600_state *state, unsigned int laneCount, const unsigned char *idata, size_t len, unsigned char *odata, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    if (XKCP_enableAVX2 || XKCP_enableAVX512)
        assert(0);
    else
        return KeccakP1600_12rounds_plain64_ODDuplexingFastInOut(&state->plain64_state, laneCount, idata, len, odata, odataAdd, trailencAsLane);
}

size_t KeccakP1600_ODDuplexingFastOut(KeccakP1600_state *state, unsigned int laneCount, unsigned char *odata, size_t len, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    if (XKCP_enableAVX2 || XKCP_enableAVX512)
        assert(0);
    else
        return KeccakP1600_plain64_ODDuplexingFastOut(&state->plain64_state, laneCount, odata, len, odataAdd, trailencAsLane);
}

size_t KeccakP1600_12rounds_ODDuplexingFastOut(KeccakP1600_state *state, unsigned int laneCount, unsigned char *odata, size_t len, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    if (XKCP_enableAVX2 || XKCP_enableAVX512)
        assert(0);
    else
        return KeccakP1600_12rounds_plain64_ODDuplexingFastOut(&state->plain64_state, laneCount, odata, len, odataAdd, trailencAsLane);
}

size_t KeccakP1600_ODDuplexingFastIn(KeccakP1600_state *state, unsigned int laneCount, const uint8_t *idata, size_t len, uint64_t trailencAsLane)
{
    if (XKCP_enableAVX2 || XKCP_enableAVX512)
        assert(0);
    else
        return KeccakP1600_plain64_ODDuplexingFastIn(&state->plain64_state, laneCount, idata, len, trailencAsLane);
}

size_t KeccakP1600_12rounds_ODDuplexingFastIn(KeccakP1600_state *state, unsigned int laneCount, const uint8_t *idata, size_t len, uint64_t trailencAsLane)
{
    if (XKCP_enableAVX2 || XKCP_enableAVX512)
        assert(0);
    else
        return KeccakP1600_12rounds_plain64_ODDuplexingFastIn(&state->plain64_state, laneCount, idata, len, trailencAsLane);
}

#endif

#ifdef XKCP_has_KeccakP1600times2

#include "KeccakP-1600-times2-SnP.h"

const char * KeccakP1600times2_GetImplementation()
{
    if (XKCP_enableAVX512)
        return KeccakP1600times2_AVX512_GetImplementation();
    else if (XKCP_enableSSSE3)
        return KeccakP1600times2_SSSE3_GetImplementation();
    else
        return "none";
}

int KeccakP1600times2_GetFeatures()
{
    if (XKCP_enableAVX512)
        return KeccakP1600times2_AVX512_GetFeatures();
    else if (XKCP_enableSSSE3)
        return KeccakP1600times2_SSSE3_GetFeatures();
    else
        return 0;
}

void KeccakP1600times2_StaticInitialize()
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_StaticInitialize();
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_StaticInitialize();
    else
        assert(0);
}

void KeccakP1600times2_InitializeAll(KeccakP1600times2_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_InitializeAll(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_InitializeAll(&states->SSSE3_states);
    else
        assert(0);
}

void KeccakP1600times2_AddByte(KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_AddByte(&states->AVX512_states, instanceIndex, data, offset);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_AddByte(&states->SSSE3_states, instanceIndex, data, offset);
    else
        assert(0);
}

void KeccakP1600times2_AddBytes(KeccakP1600times2_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_AddBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_AddBytes(&states->SSSE3_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times2_AddLanesAll(KeccakP1600times2_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_AddLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_AddLanesAll(&states->SSSE3_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times2_OverwriteBytes(KeccakP1600times2_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_OverwriteBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_OverwriteBytes(&states->SSSE3_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times2_OverwriteLanesAll(KeccakP1600times2_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_OverwriteLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_OverwriteLanesAll(&states->SSSE3_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times2_OverwriteWithZeroes(KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_OverwriteWithZeroes(&states->AVX512_states, instanceIndex, byteCount);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_OverwriteWithZeroes(&states->SSSE3_states, instanceIndex, byteCount);
    else
        assert(0);
}

void KeccakP1600times2_PermuteAll_4rounds(KeccakP1600times2_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_PermuteAll_4rounds(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_PermuteAll_4rounds(&states->SSSE3_states);
    else
        assert(0);
}

void KeccakP1600times2_PermuteAll_6rounds(KeccakP1600times2_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_PermuteAll_6rounds(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_PermuteAll_6rounds(&states->SSSE3_states);
    else
        assert(0);
}

void KeccakP1600times2_PermuteAll_12rounds(KeccakP1600times2_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_PermuteAll_12rounds(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_PermuteAll_12rounds(&states->SSSE3_states);
    else
        assert(0);
}

void KeccakP1600times2_PermuteAll_24rounds(KeccakP1600times2_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_PermuteAll_24rounds(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_PermuteAll_24rounds(&states->SSSE3_states);
    else
        assert(0);
}

void KeccakP1600times2_ExtractBytes(const KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_ExtractBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_ExtractBytes(&states->SSSE3_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times2_ExtractLanesAll(const KeccakP1600times2_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_ExtractLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_ExtractLanesAll(&states->SSSE3_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times2_ExtractAndAddBytes(const KeccakP1600times2_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_ExtractAndAddBytes(&states->AVX512_states, instanceIndex, input, output, offset, length);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_ExtractAndAddBytes(&states->SSSE3_states, instanceIndex, input, output, offset, length);
    else
        assert(0);
}

void KeccakP1600times2_ExtractAndAddLanesAll(const KeccakP1600times2_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times2_AVX512_ExtractAndAddLanesAll(&states->AVX512_states, input, output,laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        KeccakP1600times2_SSSE3_ExtractAndAddLanesAll(&states->SSSE3_states, input, output,laneCount, laneOffset);
    else
        assert(0);
}

size_t KeccakF1600times2_FastLoop_Absorb(KeccakP1600times2_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakF1600times2_AVX512_FastLoop_Absorb(&states->AVX512_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else if (XKCP_enableSSSE3)
        return KeccakF1600times2_SSSE3_FastLoop_Absorb(&states->SSSE3_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else
        assert(0);
}

size_t KeccakP1600times2_12rounds_FastLoop_Absorb(KeccakP1600times2_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakP1600times2_12rounds_AVX512_FastLoop_Absorb(&states->AVX512_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else if (XKCP_enableSSSE3)
        return KeccakP1600times2_12rounds_SSSE3_FastLoop_Absorb(&states->SSSE3_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else
        assert(0);
}

size_t KeccakP1600times2_KravatteCompress(uint64_t *xAccu, uint64_t *kRoll, const unsigned char *input, size_t inputByteLen)
{
    if (XKCP_enableSSSE3)
        assert(0);
    else
        assert(0);
}

size_t KeccakP1600times2_KravatteExpand(uint64_t *yAccu, const uint64_t *kRoll, unsigned char *output, size_t outputByteLen)
{
    if (XKCP_enableSSSE3)
        assert(0);
    else
        assert(0);
}

void KeccakP1600times2_KT128ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    if (XKCP_enableSSSE3)
        assert(0);
    else
        assert(0);
}

void KeccakP1600times2_KT256ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    if (XKCP_enableSSSE3)
        assert(0);
    else
        assert(0);
}

#endif

#ifdef XKCP_has_KeccakP1600times4

#include "KeccakP-1600-times4-SnP.h"

const char * KeccakP1600times4_GetImplementation()
{
    if (XKCP_enableAVX512)
        return KeccakP1600times4_AVX512_GetImplementation();
    else if (XKCP_enableAVX2)
        return KeccakP1600times4_AVX2_GetImplementation();
    else
        return "none";
}

int KeccakP1600times4_GetFeatures()
{
    if (XKCP_enableAVX512)
        return KeccakP1600times4_AVX512_GetFeatures();
    else if (XKCP_enableAVX2)
        return KeccakP1600times4_AVX2_GetFeatures();
    else
        return 0;
}

void KeccakP1600times4_StaticInitialize()
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_StaticInitialize();
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_StaticInitialize();
    else
        assert(0);
}

void KeccakP1600times4_InitializeAll(KeccakP1600times4_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_InitializeAll(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_InitializeAll(&states->AVX2_states);
    else
        assert(0);
}

void KeccakP1600times4_AddByte(KeccakP1600times4_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_AddByte(&states->AVX512_states, instanceIndex, data, offset);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_AddByte(&states->AVX2_states, instanceIndex, data, offset);
    else
        assert(0);
}

void KeccakP1600times4_AddBytes(KeccakP1600times4_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_AddBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_AddBytes(&states->AVX2_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times4_AddLanesAll(KeccakP1600times4_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_AddLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_AddLanesAll(&states->AVX2_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times4_OverwriteBytes(KeccakP1600times4_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_OverwriteBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_OverwriteBytes(&states->AVX2_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times4_OverwriteLanesAll(KeccakP1600times4_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_OverwriteLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_OverwriteLanesAll(&states->AVX2_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times4_OverwriteWithZeroes(KeccakP1600times4_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_OverwriteWithZeroes(&states->AVX512_states, instanceIndex, byteCount);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_OverwriteWithZeroes(&states->AVX2_states, instanceIndex, byteCount);
    else
        assert(0);
}

void KeccakP1600times4_PermuteAll_4rounds(KeccakP1600times4_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_PermuteAll_4rounds(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_PermuteAll_4rounds(&states->AVX2_states);
    else
        assert(0);
}

void KeccakP1600times4_PermuteAll_6rounds(KeccakP1600times4_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_PermuteAll_6rounds(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_PermuteAll_6rounds(&states->AVX2_states);
    else
        assert(0);
}

void KeccakP1600times4_PermuteAll_12rounds(KeccakP1600times4_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_PermuteAll_12rounds(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_PermuteAll_12rounds(&states->AVX2_states);
    else
        assert(0);
}

void KeccakP1600times4_PermuteAll_24rounds(KeccakP1600times4_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_PermuteAll_24rounds(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_PermuteAll_24rounds(&states->AVX2_states);
    else
        assert(0);
}

void KeccakP1600times4_ExtractBytes(const KeccakP1600times4_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_ExtractBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_ExtractBytes(&states->AVX2_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times4_ExtractLanesAll(const KeccakP1600times4_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_ExtractLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_ExtractLanesAll(&states->AVX2_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times4_ExtractAndAddBytes(const KeccakP1600times4_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_ExtractAndAddBytes(&states->AVX512_states, instanceIndex, input, output, offset, length);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_ExtractAndAddBytes(&states->AVX2_states, instanceIndex, input, output, offset, length);
    else
        assert(0);
}

void KeccakP1600times4_ExtractAndAddLanesAll(const KeccakP1600times4_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times4_AVX512_ExtractAndAddLanesAll(&states->AVX512_states, input, output,laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_ExtractAndAddLanesAll(&states->AVX2_states, input, output,laneCount, laneOffset);
    else
        assert(0);
}

size_t KeccakF1600times4_FastLoop_Absorb(KeccakP1600times4_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakF1600times4_AVX512_FastLoop_Absorb(&states->AVX512_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else if (XKCP_enableAVX2)
        return KeccakF1600times4_AVX2_FastLoop_Absorb(&states->AVX2_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else
        assert(0);
}

size_t KeccakP1600times4_12rounds_FastLoop_Absorb(KeccakP1600times4_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakP1600times4_12rounds_AVX512_FastLoop_Absorb(&states->AVX512_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else if (XKCP_enableAVX2)
        return KeccakP1600times4_12rounds_AVX2_FastLoop_Absorb(&states->AVX2_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else
        assert(0);
}

size_t KeccakP1600times4_KravatteCompress(uint64_t *xAccu, uint64_t *kRoll, const unsigned char *input, size_t inputByteLen)
{
    if (XKCP_enableAVX2)
        return KeccakP1600times4_AVX2_KravatteCompress(xAccu, kRoll, input, inputByteLen);
    else
        assert(0);
}

size_t KeccakP1600times4_KravatteExpand(uint64_t *yAccu, const uint64_t *kRoll, unsigned char *output, size_t outputByteLen)
{
    if (XKCP_enableAVX2)
        return KeccakP1600times4_AVX2_KravatteExpand(yAccu, kRoll, output, outputByteLen);
    else
        assert(0);
}

void KeccakP1600times4_KT128ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_KT128ProcessLeaves(input, output);
    else
        assert(0);
}

void KeccakP1600times4_KT256ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    if (XKCP_enableAVX2)
        KeccakP1600times4_AVX2_KT256ProcessLeaves(input, output);
    else
        assert(0);
}

#endif

#ifdef XKCP_has_KeccakP1600times8

#include "KeccakP-1600-times8-SnP.h"

const char * KeccakP1600times8_GetImplementation()
{
    if (XKCP_enableAVX512)
        return KeccakP1600times8_AVX512_GetImplementation();
    else
        return "none";
}

int KeccakP1600times8_GetFeatures()
{
    if (XKCP_enableAVX512)
        return KeccakP1600times8_AVX512_GetFeatures();
    else
        return 0;
}

void KeccakP1600times8_StaticInitialize()
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_StaticInitialize();
    else
        assert(0);
}

void KeccakP1600times8_InitializeAll(KeccakP1600times8_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_InitializeAll(&states->AVX512_states);
    else
        assert(0);
}

void KeccakP1600times8_AddByte(KeccakP1600times8_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_AddByte(&states->AVX512_states, instanceIndex, data, offset);
    else
        assert(0);
}

void KeccakP1600times8_AddBytes(KeccakP1600times8_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_AddBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times8_AddLanesAll(KeccakP1600times8_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_AddLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times8_OverwriteBytes(KeccakP1600times8_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_OverwriteBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times8_OverwriteLanesAll(KeccakP1600times8_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_OverwriteLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times8_OverwriteWithZeroes(KeccakP1600times8_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_OverwriteWithZeroes(&states->AVX512_states, instanceIndex, byteCount);
    else
        assert(0);
}

void KeccakP1600times8_PermuteAll_4rounds(KeccakP1600times8_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_PermuteAll_4rounds(&states->AVX512_states);
    else
        assert(0);
}

void KeccakP1600times8_PermuteAll_6rounds(KeccakP1600times8_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_PermuteAll_6rounds(&states->AVX512_states);
    else
        assert(0);
}

void KeccakP1600times8_PermuteAll_12rounds(KeccakP1600times8_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_PermuteAll_12rounds(&states->AVX512_states);
    else
        assert(0);
}

void KeccakP1600times8_PermuteAll_24rounds(KeccakP1600times8_states *states)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_PermuteAll_24rounds(&states->AVX512_states);
    else
        assert(0);
}

void KeccakP1600times8_ExtractBytes(const KeccakP1600times8_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_ExtractBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void KeccakP1600times8_ExtractLanesAll(const KeccakP1600times8_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_ExtractLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void KeccakP1600times8_ExtractAndAddBytes(const KeccakP1600times8_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_ExtractAndAddBytes(&states->AVX512_states, instanceIndex, input, output, offset, length);
    else
        assert(0);
}

void KeccakP1600times8_ExtractAndAddLanesAll(const KeccakP1600times8_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_ExtractAndAddLanesAll(&states->AVX512_states, input, output,laneCount, laneOffset);
    else
        assert(0);
}

size_t KeccakF1600times8_FastLoop_Absorb(KeccakP1600times8_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakF1600times8_AVX512_FastLoop_Absorb(&states->AVX512_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else
        assert(0);
}

size_t KeccakP1600times8_12rounds_FastLoop_Absorb(KeccakP1600times8_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakP1600times8_12rounds_AVX512_FastLoop_Absorb(&states->AVX512_states, laneCount, laneOffsetParallel, laneOffsetSerial, data, dataByteLen);
    else
        assert(0);
}

size_t KeccakP1600times8_KravatteCompress(uint64_t *xAccu, uint64_t *kRoll, const unsigned char *input, size_t inputByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakP1600times8_AVX512_KravatteCompress(xAccu, kRoll, input, inputByteLen);
    else
        assert(0);
}

size_t KeccakP1600times8_KravatteExpand(uint64_t *yAccu, const uint64_t *kRoll, unsigned char *output, size_t outputByteLen)
{
    if (XKCP_enableAVX512)
        return KeccakP1600times8_AVX512_KravatteExpand(yAccu, kRoll, output, outputByteLen);
    else
        assert(0);
}

void KeccakP1600times8_KT128ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_KT128ProcessLeaves(input, output);
    else
        assert(0);
}

void KeccakP1600times8_KT256ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    if (XKCP_enableAVX512)
        KeccakP1600times8_AVX512_KT256ProcessLeaves(input, output);
    else
        assert(0);
}

#endif

#ifdef XKCP_has_Xoodoo

#include "Xoodoo-SnP.h"

const char * Xoodoo_GetImplementation()
{
    if (XKCP_enableAVX512)
        return Xoodoo_AVX512_GetImplementation();
    else if (XKCP_enableSSSE3)
        return Xoodoo_SSSE3_GetImplementation();
    else
        return Xoodoo_plain_GetImplementation();
}

int Xoodoo_GetFeatures()
{
    if (XKCP_enableAVX512)
        return Xoodoo_AVX512_GetFeatures();
    else if (XKCP_enableSSSE3)
        return Xoodoo_SSSE3_GetFeatures();
    else
        return Xoodoo_plain_GetFeatures();
}

void Xoodoo_StaticInitialize()
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_StaticInitialize();
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_StaticInitialize();
    else
        Xoodoo_plain_StaticInitialize();
}

void Xoodoo_Initialize(Xoodoo_state *state)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_Initialize(&state->align128plain32_state);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_Initialize(&state->align128plain32_state);
    else
        Xoodoo_plain_Initialize(&state->plain32_state);
}

void Xoodoo_AddByte(Xoodoo_state *state, uint8_t data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_AddByte(&state->align128plain32_state, data, offset);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_AddByte(&state->align128plain32_state, data, offset);
    else
        Xoodoo_plain_AddByte(&state->plain32_state, data, offset);
}

void Xoodoo_AddBytes(Xoodoo_state *state, const uint8_t *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_AddBytes(&state->align128plain32_state, data, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_AddBytes(&state->align128plain32_state, data, offset, length);
    else
        Xoodoo_plain_AddBytes(&state->plain32_state, data, offset, length);
}

void Xoodoo_OverwriteBytes(Xoodoo_state *state, const uint8_t *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_OverwriteBytes(&state->align128plain32_state, data, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_OverwriteBytes(&state->align128plain32_state, data, offset, length);
    else
        Xoodoo_plain_OverwriteBytes(&state->plain32_state, data, offset, length);
}

void Xoodoo_OverwriteWithZeroes(Xoodoo_state *state, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_OverwriteWithZeroes(&state->align128plain32_state, byteCount);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_OverwriteWithZeroes(&state->align128plain32_state, byteCount);
    else
        Xoodoo_plain_OverwriteWithZeroes(&state->plain32_state, byteCount);
}

void Xoodoo_Permute_Nrounds(Xoodoo_state *state, unsigned int nrounds)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_Permute_Nrounds(&state->align128plain32_state, nrounds);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_Permute_Nrounds(&state->align128plain32_state, nrounds);
    else
        Xoodoo_plain_Permute_Nrounds(&state->plain32_state, nrounds);
}

void Xoodoo_Permute_6rounds(Xoodoo_state *state)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_Permute_6rounds(&state->align128plain32_state);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_Permute_6rounds(&state->align128plain32_state);
    else
        Xoodoo_plain_Permute_6rounds(&state->plain32_state);
}

void Xoodoo_Permute_12rounds(Xoodoo_state *state)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_Permute_12rounds(&state->align128plain32_state);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_Permute_12rounds(&state->align128plain32_state);
    else
        Xoodoo_plain_Permute_12rounds(&state->plain32_state);
}

void Xoodoo_ExtractBytes(const Xoodoo_state *state, uint8_t *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_ExtractBytes(&state->align128plain32_state, data, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_ExtractBytes(&state->align128plain32_state, data, offset, length);
    else
        Xoodoo_plain_ExtractBytes(&state->plain32_state, data, offset, length);
}

void Xoodoo_ExtractAndAddBytes(const Xoodoo_state *state, const uint8_t *input, uint8_t *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodoo_AVX512_ExtractAndAddBytes(&state->align128plain32_state, input, output, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodoo_SSSE3_ExtractAndAddBytes(&state->align128plain32_state, input, output, offset, length);
    else
        Xoodoo_plain_ExtractAndAddBytes(&state->plain32_state, input, output, offset, length);
}

void Xoofff_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen)
{
    if (XKCP_enableAVX512)
        Xoofff_AVX512_AddIs(output, input, bitLen);
    else
        assert(0);
}

size_t Xoofff_CompressFastLoop(unsigned char *kRoll, unsigned char *xAccu, const unsigned char *input, size_t length)
{
    if (XKCP_enableAVX512)
        Xoofff_AVX512_CompressFastLoop(kRoll, xAccu, input, length);
    else
        assert(0);
}

size_t Xoofff_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    if (XKCP_enableAVX512)
        Xoofff_AVX512_ExpandFastLoop(yAccu, kRoll, output, length);
    else
        assert(0);
}

size_t Xoodyak_AbsorbKeyedFullBlocks(Xoodoo_state *state, const uint8_t *X, size_t XLen)
{
    if (XKCP_enableAVX512)
        return Xoodyak_AVX512_AbsorbKeyedFullBlocks(&state->align128plain32_state, X, XLen);
    else if (XKCP_enableSSSE3)
        return Xoodyak_SSSE3_AbsorbKeyedFullBlocks(&state->align128plain32_state, X, XLen);
    else
        return Xoodyak_plain_AbsorbKeyedFullBlocks(&state->plain32_state, X, XLen);
}

size_t Xoodyak_AbsorbHashFullBlocks(Xoodoo_state *state, const uint8_t *X, size_t XLen)
{
    if (XKCP_enableAVX512)
        return Xoodyak_AVX512_AbsorbHashFullBlocks(&state->align128plain32_state, X, XLen);
    else if (XKCP_enableSSSE3)
        return Xoodyak_SSSE3_AbsorbHashFullBlocks(&state->align128plain32_state, X, XLen);
    else
        return Xoodyak_plain_AbsorbHashFullBlocks(&state->plain32_state, X, XLen);
}

size_t Xoodyak_SqueezeHashFullBlocks(Xoodoo_state *state, uint8_t *Y, size_t YLen)
{
    if (XKCP_enableAVX512)
        return Xoodyak_AVX512_SqueezeHashFullBlocks(&state->align128plain32_state, Y, YLen);
    else if (XKCP_enableSSSE3)
        return Xoodyak_SSSE3_SqueezeHashFullBlocks(&state->align128plain32_state, Y, YLen);
    else
        return Xoodyak_plain_SqueezeHashFullBlocks(&state->plain32_state, Y, YLen);
}

size_t Xoodyak_SqueezeKeyedFullBlocks(Xoodoo_state *state, uint8_t *Y, size_t YLen)
{
    if (XKCP_enableAVX512)
        return Xoodyak_AVX512_SqueezeKeyedFullBlocks(&state->align128plain32_state, Y, YLen);
    else if (XKCP_enableSSSE3)
        return Xoodyak_SSSE3_SqueezeKeyedFullBlocks(&state->align128plain32_state, Y, YLen);
    else
        return Xoodyak_plain_SqueezeKeyedFullBlocks(&state->plain32_state, Y, YLen);
}

size_t Xoodyak_EncryptFullBlocks(Xoodoo_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
{
    if (XKCP_enableAVX512)
        return Xoodyak_AVX512_EncryptFullBlocks(&state->align128plain32_state, I, O, IOLen);
    else if (XKCP_enableSSSE3)
        return Xoodyak_SSSE3_EncryptFullBlocks(&state->align128plain32_state, I, O, IOLen);
    else
        return Xoodyak_plain_EncryptFullBlocks(&state->plain32_state, I, O, IOLen);
}

size_t Xoodyak_DecryptFullBlocks(Xoodoo_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
{
    if (XKCP_enableAVX512)
        return Xoodyak_AVX512_DecryptFullBlocks(&state->align128plain32_state, I, O, IOLen);
    else if (XKCP_enableSSSE3)
        return Xoodyak_SSSE3_DecryptFullBlocks(&state->align128plain32_state, I, O, IOLen);
    else
        return Xoodyak_plain_DecryptFullBlocks(&state->plain32_state, I, O, IOLen);
}

#endif

#ifdef XKCP_has_Xoodootimes4

#include "Xoodoo-times4-SnP.h"

const char * Xoodootimes4_GetImplementation()
{
    if (XKCP_enableAVX512)
        return Xoodootimes4_AVX512_GetImplementation();
    else if (XKCP_enableSSSE3)
        return Xoodootimes4_SSSE3_GetImplementation();
    else
        return "none";
}

int Xoodootimes4_GetFeatures()
{
    if (XKCP_enableAVX512)
        return Xoodootimes4_AVX512_GetFeatures();
    else if (XKCP_enableSSSE3)
        return Xoodootimes4_SSSE3_GetFeatures();
    else
        return 0;
}

void Xoodootimes4_StaticInitialize()
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_StaticInitialize();
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_StaticInitialize();
    else
        assert(0);
}

void Xoodootimes4_InitializeAll(Xoodootimes4_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_InitializeAll(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_InitializeAll(&states->SSSE3_states);
    else
        assert(0);
}

void Xoodootimes4_AddByte(Xoodootimes4_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_AddByte(&states->AVX512_states, instanceIndex, data, offset);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_AddByte(&states->SSSE3_states, instanceIndex, data, offset);
    else
        assert(0);
}

void Xoodootimes4_AddBytes(Xoodootimes4_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_AddBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_AddBytes(&states->SSSE3_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes4_AddLanesAll(Xoodootimes4_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_AddLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_AddLanesAll(&states->SSSE3_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes4_OverwriteBytes(Xoodootimes4_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_OverwriteBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_OverwriteBytes(&states->SSSE3_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes4_OverwriteLanesAll(Xoodootimes4_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_OverwriteLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_OverwriteLanesAll(&states->SSSE3_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes4_OverwriteWithZeroes(Xoodootimes4_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_OverwriteWithZeroes(&states->AVX512_states, instanceIndex, byteCount);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_OverwriteWithZeroes(&states->SSSE3_states, instanceIndex, byteCount);
    else
        assert(0);
}

void Xoodootimes4_PermuteAll_6rounds(Xoodootimes4_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_PermuteAll_6rounds(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_PermuteAll_6rounds(&states->SSSE3_states);
    else
        assert(0);
}

void Xoodootimes4_PermuteAll_12rounds(Xoodootimes4_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_PermuteAll_12rounds(&states->AVX512_states);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_PermuteAll_12rounds(&states->SSSE3_states);
    else
        assert(0);
}

void Xoodootimes4_ExtractBytes(const Xoodootimes4_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_ExtractBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_ExtractBytes(&states->SSSE3_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes4_ExtractLanesAll(const Xoodootimes4_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_ExtractLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_ExtractLanesAll(&states->SSSE3_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes4_ExtractAndAddBytes(const Xoodootimes4_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_ExtractAndAddBytes(&states->AVX512_states, instanceIndex, input, output, offset, length);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_ExtractAndAddBytes(&states->SSSE3_states, instanceIndex, input, output, offset, length);
    else
        assert(0);
}

void Xoodootimes4_ExtractAndAddLanesAll(const Xoodootimes4_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes4_AVX512_ExtractAndAddLanesAll(&states->AVX512_states, input, output,laneCount, laneOffset);
    else if (XKCP_enableSSSE3)
        Xoodootimes4_SSSE3_ExtractAndAddLanesAll(&states->SSSE3_states, input, output,laneCount, laneOffset);
    else
        assert(0);
}

void Xooffftimes4_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen)
{
    if (XKCP_enableAVX512)
        Xooffftimes4_AVX512_AddIs(output, input, bitLen);
    else
        assert(0);
}

size_t Xooffftimes4_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length)
{
    if (XKCP_enableAVX512)
        return Xooffftimes4_AVX512_CompressFastLoop(k, x, input, length);
    else
        assert(0);
}

size_t Xooffftimes4_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    if (XKCP_enableAVX512)
        return Xooffftimes4_AVX512_ExpandFastLoop(yAccu, kRoll, output, length);
    else
        assert(0);
}

#endif

#ifdef XKCP_has_Xoodootimes8

#include "Xoodoo-times8-SnP.h"

const char * Xoodootimes8_GetImplementation()
{
    if (XKCP_enableAVX512)
        return Xoodootimes8_AVX512_GetImplementation();
    else if (XKCP_enableAVX2)
        return Xoodootimes8_AVX2_GetImplementation();
    else
        return "none";
}

int Xoodootimes8_GetFeatures()
{
    if (XKCP_enableAVX512)
        return Xoodootimes8_AVX512_GetFeatures();
    else if (XKCP_enableAVX2)
        return Xoodootimes8_AVX2_GetFeatures();
    else
        return 0;
}

void Xoodootimes8_StaticInitialize()
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_StaticInitialize();
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_StaticInitialize();
    else
        assert(0);
}

void Xoodootimes8_InitializeAll(Xoodootimes8_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_InitializeAll(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_InitializeAll(&states->AVX2_states);
    else
        assert(0);
}

void Xoodootimes8_AddByte(Xoodootimes8_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_AddByte(&states->AVX512_states, instanceIndex, data, offset);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_AddByte(&states->AVX2_states, instanceIndex, data, offset);
    else
        assert(0);
}

void Xoodootimes8_AddBytes(Xoodootimes8_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_AddBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_AddBytes(&states->AVX2_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes8_AddLanesAll(Xoodootimes8_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_AddLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_AddLanesAll(&states->AVX2_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes8_OverwriteBytes(Xoodootimes8_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_OverwriteBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_OverwriteBytes(&states->AVX2_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes8_OverwriteLanesAll(Xoodootimes8_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_OverwriteLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_OverwriteLanesAll(&states->AVX2_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes8_OverwriteWithZeroes(Xoodootimes8_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_OverwriteWithZeroes(&states->AVX512_states, instanceIndex, byteCount);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_OverwriteWithZeroes(&states->AVX2_states, instanceIndex, byteCount);
    else
        assert(0);
}

void Xoodootimes8_PermuteAll_6rounds(Xoodootimes8_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_PermuteAll_6rounds(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_PermuteAll_6rounds(&states->AVX2_states);
    else
        assert(0);
}

void Xoodootimes8_PermuteAll_12rounds(Xoodootimes8_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_PermuteAll_12rounds(&states->AVX512_states);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_PermuteAll_12rounds(&states->AVX2_states);
    else
        assert(0);
}

void Xoodootimes8_ExtractBytes(const Xoodootimes8_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_ExtractBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_ExtractBytes(&states->AVX2_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes8_ExtractLanesAll(const Xoodootimes8_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_ExtractLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_ExtractLanesAll(&states->AVX2_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes8_ExtractAndAddBytes(const Xoodootimes8_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_ExtractAndAddBytes(&states->AVX512_states, instanceIndex, input, output, offset, length);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_ExtractAndAddBytes(&states->AVX2_states, instanceIndex, input, output, offset, length);
    else
        assert(0);
}

void Xoodootimes8_ExtractAndAddLanesAll(const Xoodootimes8_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes8_AVX512_ExtractAndAddLanesAll(&states->AVX512_states, input, output,laneCount, laneOffset);
    else if (XKCP_enableAVX2)
        Xoodootimes8_AVX2_ExtractAndAddLanesAll(&states->AVX2_states, input, output,laneCount, laneOffset);
    else
        assert(0);
}

void Xooffftimes8_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen)
{
    if (XKCP_enableAVX512)
        Xooffftimes8_AVX512_AddIs(output, input, bitLen);
    else if (XKCP_enableAVX2)
        Xooffftimes8_AVX2_AddIs(output, input, bitLen);
    else
        assert(0);
}

size_t Xooffftimes8_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length)
{
    if (XKCP_enableAVX512)
        return Xooffftimes8_AVX512_CompressFastLoop(k, x, input, length);
    else if (XKCP_enableAVX2)
        return Xooffftimes8_AVX2_CompressFastLoop(k, x, input, length);
    else
        assert(0);
}

size_t Xooffftimes8_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    if (XKCP_enableAVX512)
        return Xooffftimes8_AVX512_ExpandFastLoop(yAccu, kRoll, output, length);
    else if (XKCP_enableAVX2)
        return Xooffftimes8_AVX2_ExpandFastLoop(yAccu, kRoll, output, length);
    else
        assert(0);
}

#endif

#ifdef XKCP_has_Xoodootimes16

#include "Xoodoo-times16-SnP.h"

const char * Xoodootimes16_GetImplementation()
{
    if (XKCP_enableAVX512)
        return Xoodootimes16_AVX512_GetImplementation();
    else
        return "none";
}

int Xoodootimes16_GetFeatures()
{
    if (XKCP_enableAVX512)
        return Xoodootimes16_AVX512_GetFeatures();
    else
        return 0;
}

void Xoodootimes16_StaticInitialize()
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_StaticInitialize();
    else
        assert(0);
}

void Xoodootimes16_InitializeAll(Xoodootimes16_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_InitializeAll(&states->AVX512_states);
    else
        assert(0);
}

void Xoodootimes16_AddByte(Xoodootimes16_states *states, unsigned int instanceIndex, unsigned char data, unsigned int offset)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_AddByte(&states->AVX512_states, instanceIndex, data, offset);
    else
        assert(0);
}

void Xoodootimes16_AddBytes(Xoodootimes16_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_AddBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes16_AddLanesAll(Xoodootimes16_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_AddLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes16_OverwriteBytes(Xoodootimes16_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_OverwriteBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes16_OverwriteLanesAll(Xoodootimes16_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_OverwriteLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes16_OverwriteWithZeroes(Xoodootimes16_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_OverwriteWithZeroes(&states->AVX512_states, instanceIndex, byteCount);
    else
        assert(0);
}

void Xoodootimes16_PermuteAll_6rounds(Xoodootimes16_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_PermuteAll_6rounds(&states->AVX512_states);
    else
        assert(0);
}

void Xoodootimes16_PermuteAll_12rounds(Xoodootimes16_states *states)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_PermuteAll_12rounds(&states->AVX512_states);
    else
        assert(0);
}

void Xoodootimes16_ExtractBytes(const Xoodootimes16_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_ExtractBytes(&states->AVX512_states, instanceIndex, data, offset, length);
    else
        assert(0);
}

void Xoodootimes16_ExtractLanesAll(const Xoodootimes16_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_ExtractLanesAll(&states->AVX512_states, data, laneCount, laneOffset);
    else
        assert(0);
}

void Xoodootimes16_ExtractAndAddBytes(const Xoodootimes16_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_ExtractAndAddBytes(&states->AVX512_states, instanceIndex, input, output, offset, length);
    else
        assert(0);
}

void Xoodootimes16_ExtractAndAddLanesAll(const Xoodootimes16_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    if (XKCP_enableAVX512)
        Xoodootimes16_AVX512_ExtractAndAddLanesAll(&states->AVX512_states, input, output,laneCount, laneOffset);
    else
        assert(0);
}

void Xooffftimes16_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen)
{
    if (XKCP_enableAVX512)
        Xooffftimes16_AVX512_AddIs(output, input, bitLen);
    else
        assert(0);
}

size_t Xooffftimes16_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length)
{
    if (XKCP_enableAVX512)
        return Xooffftimes16_AVX512_CompressFastLoop(k, x, input, length);
    else
        assert(0);
}

size_t Xooffftimes16_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    if (XKCP_enableAVX512)
        return Xooffftimes16_AVX512_ExpandFastLoop(yAccu, kRoll, output, length);
    else
        assert(0);
}

#endif

/* ---------------------------------------------------------------- */

/* Processor capability detection code by Samuel Neves and Jack O'Connor, see
 * https://github.com/BLAKE3-team/BLAKE3/blob/master/c/blake3_dispatch.c
 */

#if defined(__x86_64__) || defined(_M_X64)
#define IS_X86
#define IS_X86_64
#endif

#if defined(__i386__) || defined(_M_IX86)
#define IS_X86
#define IS_X86_32
#endif

#if defined(IS_X86)
static uint64_t xgetbv() {
#if defined(_MSC_VER)
  return _xgetbv(0);
#else
  uint32_t eax = 0, edx = 0;
  __asm__ __volatile__("xgetbv\n" : "=a"(eax), "=d"(edx) : "c"(0));
  return ((uint64_t)edx << 32) | eax;
#endif
}

static void cpuid(uint32_t out[4], uint32_t id) {
#if defined(_MSC_VER)
  __cpuid((int *)out, id);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#endif
}

static void cpuidex(uint32_t out[4], uint32_t id, uint32_t sid) {
#if defined(_MSC_VER)
  __cpuidex((int *)out, id, sid);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#endif
}

#endif

enum cpu_feature {
  SSE2 = 1 << 0,
  SSSE3 = 1 << 1,
  SSE41 = 1 << 2,
  AVX = 1 << 3,
  AVX2 = 1 << 4,
  AVX512F = 1 << 5,
  AVX512VL = 1 << 6,
  /* ... */
  UNDEFINED = 1 << 30
};

static enum cpu_feature g_cpu_features = UNDEFINED;

static enum cpu_feature
    get_cpu_features(void) {

  if (g_cpu_features != UNDEFINED) {
    return g_cpu_features;
  } else {
#if defined(IS_X86)
    uint32_t regs[4] = {0};
    uint32_t *eax = &regs[0], *ebx = &regs[1], *ecx = &regs[2], *edx = &regs[3];
    (void)edx;
    enum cpu_feature features = 0;
    cpuid(regs, 0);
    const int max_id = *eax;
    cpuid(regs, 1);
#if defined(__amd64__) || defined(_M_X64)
    features |= SSE2;
#else
    if (*edx & (1UL << 26))
      features |= SSE2;
#endif
    if (*ecx & (1UL << 9))
      features |= SSSE3;
    if (*ecx & (1UL << 19))
      features |= SSE41;

    if (*ecx & (1UL << 27)) { // OSXSAVE
      const uint64_t mask = xgetbv();
      if ((mask & 6) == 6) { // SSE and AVX states
        if (*ecx & (1UL << 28))
          features |= AVX;
        if (max_id >= 7) {
          cpuidex(regs, 7, 0);
          if (*ebx & (1UL << 5))
            features |= AVX2;
          if ((mask & 224) == 224) { // Opmask, ZMM_Hi256, Hi16_Zmm
            if (*ebx & (1UL << 31))
              features |= AVX512VL;
            if (*ebx & (1UL << 16))
              features |= AVX512F;
          }
        }
      }
    }
    g_cpu_features = features;
    return features;
#else
    /* How to detect NEON? */
    return 0;
#endif
  }
}

void XKCP_SetProcessorCapabilities()
{
    enum cpu_feature features = get_cpu_features();
    XKCP_enableSSSE3 = (features & SSSE3);
    XKCP_enableAVX2 = (features & AVX2);
    XKCP_enableAVX512 = (features & AVX512F) && (features & AVX512VL);
    XKCP_enableSSSE3 = XKCP_enableSSSE3 && !XKCP_SSSE3_requested_disabled;
    XKCP_enableAVX2 = XKCP_enableAVX2 && !XKCP_AVX2_requested_disabled;
    XKCP_enableAVX512 = XKCP_enableAVX512 && !XKCP_AVX512_requested_disabled;
}

int XKCP_DisableSSSE3(void) {
    XKCP_SetProcessorCapabilities();
    XKCP_SSSE3_requested_disabled = 1;
    if (XKCP_enableSSSE3) {
        XKCP_SetProcessorCapabilities();
        return 1;  // SSSE3 was disabled on this call.
    } else {
        return 0;  // Nothing changed.
    }
}

int XKCP_DisableAVX2(void) {
    XKCP_SetProcessorCapabilities();
    XKCP_AVX2_requested_disabled = 1;
    if (XKCP_enableAVX2) {
        XKCP_SetProcessorCapabilities();
        return 1;  // AVX2 was disabled on this call.
    } else {
        return 0;  // Nothing changed.
    }
}

int XKCP_DisableAVX512(void) {
    XKCP_SetProcessorCapabilities();
    XKCP_AVX512_requested_disabled = 1;
    if (XKCP_enableAVX512) {
        XKCP_SetProcessorCapabilities();
        return 1;  // AVX512 was disabled on this call.
    } else {
        return 0;  // Nothing changed.
    }
}

void XKCP_EnableAllCpuFeatures(void) {
    XKCP_SSSE3_requested_disabled = 0;
    XKCP_AVX2_requested_disabled = 0;
    XKCP_AVX512_requested_disabled = 0;
    XKCP_SetProcessorCapabilities();
}

int XKCP_ProcessCpuFeatureCommandLineOption(const char * arg)
{
    if (strcmp("--disableSSSE3", arg) == 0) {
        XKCP_DisableSSSE3();
        return 1;
    }
    else if (strcmp("--disableAVX2", arg) == 0) {
        XKCP_DisableAVX2();
        return 1;
    }
    else if (strcmp("--disableAVX512", arg) == 0) {
        XKCP_DisableAVX512();
        return 1;
    }
    else
        return 0;
}
