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

This file implements Keccak-p[1600] in a SnP-compatible way.
Please refer to SnP-documentation.h for more details.

This implementation comes with KeccakP-1600-SnP.h in the same folder.
Please refer to LowLevel.build for the exact list of other files it must be combined with.
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "brg_endian.h"
#include "KeccakP-1600-SnP.h"

#if defined(KeccakP1600_plain64_useLaneComplementing)
#define UseBebigokimisa
#endif

#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(KeccakP1600_plain64_useSHLD)
    #define ROL64(x,N) ({ \
    register uint64_t __out; \
    register uint64_t __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#else
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#endif

#include "KeccakP-1600-64.macros"
#ifdef KeccakP1600_plain64_fullUnrolling
#define FullUnrolling
#else
#define Unrolling KeccakP1600_plain64_unrolling
#endif
#include "KeccakP-1600-unrolling.macros"
#include "SnP-Relaned.h"

static const uint64_t KeccakF1600RoundConstants[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL };

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Initialize(KeccakP1600_plain64_state *state)
{
    memset(state, 0, 200);
#ifdef KeccakP1600_plain64_useLaneComplementing
    state->A[ 1] = ~(uint64_t)0;
    state->A[ 2] = ~(uint64_t)0;
    state->A[ 8] = ~(uint64_t)0;
    state->A[12] = ~(uint64_t)0;
    state->A[17] = ~(uint64_t)0;
    state->A[20] = ~(uint64_t)0;
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_AddBytesInLane(KeccakP1600_plain64_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    uint64_t lane;
    if (length == 0)
        return;
    if (length == 1)
        lane = data[0];
    else {
        lane = 0;
        memcpy(&lane, data, length);
    }
    lane <<= offset*8;
#else
    uint64_t lane = 0;
    unsigned int i;
    for(i=0; i<length; i++)
        lane |= ((uint64_t)data[i]) << ((i+offset)*8);
#endif
    state->A[lanePosition] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_AddLanes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned int i = 0;
#ifdef NO_MISALIGNED_ACCESSES
    /* If either pointer is misaligned, fall back to byte-wise xor. */
    if (((((uintptr_t)state) & 7) != 0) || ((((uintptr_t)data) & 7) != 0)) {
      for (i = 0; i < laneCount * 8; i++) {
        ((unsigned char*)state)[i] ^= data[i];
      }
    }
    else
#endif
    {
      /* Otherwise... */
      for( ; (i+8)<=laneCount; i+=8) {
          state->A[i+0] ^= ((uint64_t*)data)[i+0];
          state->A[i+1] ^= ((uint64_t*)data)[i+1];
          state->A[i+2] ^= ((uint64_t*)data)[i+2];
          state->A[i+3] ^= ((uint64_t*)data)[i+3];
          state->A[i+4] ^= ((uint64_t*)data)[i+4];
          state->A[i+5] ^= ((uint64_t*)data)[i+5];
          state->A[i+6] ^= ((uint64_t*)data)[i+6];
          state->A[i+7] ^= ((uint64_t*)data)[i+7];
      }
      for( ; (i+4)<=laneCount; i+=4) {
          state->A[i+0] ^= ((uint64_t*)data)[i+0];
          state->A[i+1] ^= ((uint64_t*)data)[i+1];
          state->A[i+2] ^= ((uint64_t*)data)[i+2];
          state->A[i+3] ^= ((uint64_t*)data)[i+3];
      }
      for( ; (i+2)<=laneCount; i+=2) {
          state->A[i+0] ^= ((uint64_t*)data)[i+0];
          state->A[i+1] ^= ((uint64_t*)data)[i+1];
      }
      if (i<laneCount) {
          state->A[i+0] ^= ((uint64_t*)data)[i+0];
      }
    }
#else
    unsigned int i;
    const uint8_t *curData = data;
    for(i=0; i<laneCount; i++, curData+=8) {
        uint64_t lane = (uint64_t)curData[0]
            | ((uint64_t)curData[1] <<  8)
            | ((uint64_t)curData[2] << 16)
            | ((uint64_t)curData[3] << 24)
            | ((uint64_t)curData[4] << 32)
            | ((uint64_t)curData[5] << 40)
            | ((uint64_t)curData[6] << 48)
            | ((uint64_t)curData[7] << 56);
        state->A[i] ^= lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
void KeccakP1600_plain64_AddByte(KeccakP1600_plain64_state *state, unsigned char byte, unsigned int offset)
{
    uint64_t lane = byte;
    lane <<= (offset%8)*8;
    state->A[offset/8] ^= lane;
}
#endif

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_AddBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_AddBytes(state, data, offset, length, KeccakP1600_plain64_AddLanes, KeccakP1600_plain64_AddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteBytesInLane(KeccakP1600_plain64_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#ifdef KeccakP1600_plain64_useLaneComplementing
    if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20)) {
        unsigned int i;
        for(i=0; i<length; i++)
            ((unsigned char*)state)[lanePosition*8+offset+i] = ~data[i];
    }
    else
#endif
    {
        memcpy((unsigned char*)state+lanePosition*8+offset, data, length);
    }
#else
    uint64_t lane = state->A[lanePosition];
    unsigned int i;
    for(i=0; i<length; i++) {
        lane &= ~((uint64_t)0xFF << ((offset+i)*8));
#ifdef KeccakP1600_plain64_useLaneComplementing
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            lane |= (uint64_t)(data[i] ^ 0xFF) << ((offset+i)*8);
        else
#endif
            lane |= (uint64_t)data[i] << ((offset+i)*8);
    }
    state->A[lanePosition] = lane;
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteLanes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#ifdef KeccakP1600_plain64_useLaneComplementing
    unsigned int lanePosition;

    for(lanePosition=0; lanePosition<laneCount; lanePosition++)
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            state->A[lanePosition] = ~((const uint64_t*)data)[lanePosition];
        else
            state->A[lanePosition] = ((const uint64_t*)data)[lanePosition];
#else
    memcpy(state, data, laneCount*8);
#endif
#else
    unsigned int lanePosition;
    const uint8_t *curData = data;
    for(lanePosition=0; lanePosition<laneCount; lanePosition++, curData+=8) {
        uint64_t lane = (uint64_t)curData[0]
            | ((uint64_t)curData[1] <<  8)
            | ((uint64_t)curData[2] << 16)
            | ((uint64_t)curData[3] << 24)
            | ((uint64_t)curData[4] << 32)
            | ((uint64_t)curData[5] << 40)
            | ((uint64_t)curData[6] << 48)
            | ((uint64_t)curData[7] << 56);
#ifdef KeccakP1600_plain64_useLaneComplementing
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            state->A[lanePosition] = ~lane;
        else
#endif
            state->A[lanePosition] = lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_OverwriteBytes(state, data, offset, length, KeccakP1600_plain64_OverwriteLanes, KeccakP1600_plain64_OverwriteBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteWithZeroes(KeccakP1600_plain64_state *state, unsigned int byteCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#ifdef KeccakP1600_plain64_useLaneComplementing
    unsigned int lanePosition;

    for(lanePosition=0; lanePosition<byteCount/8; lanePosition++)
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            state->A[lanePosition] = ~0;
        else
            state->A[lanePosition] = 0;
    if (byteCount%8 != 0) {
        lanePosition = byteCount/8;
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            memset((unsigned char*)state+lanePosition*8, 0xFF, byteCount%8);
        else
            memset((unsigned char*)state+lanePosition*8, 0, byteCount%8);
    }
#else
    memset(state, 0, byteCount);
#endif
#else
    unsigned int i, j;
    for(i=0; i<byteCount; i+=8) {
        unsigned int lanePosition = i/8;
        if (i+8 <= byteCount) {
#ifdef KeccakP1600_plain64_useLaneComplementing
            if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
                state->A[lanePosition] = ~(uint64_t)0;
            else
#endif
                state->A[lanePosition] = 0;
        }
        else {
            uint64_t lane = state->A[lanePosition];
            for(j=0; j<byteCount%8; j++) {
#ifdef KeccakP1600_plain64_useLaneComplementing
                if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
                    lane |= (uint64_t)0xFF << (j*8);
                else
#endif
                    lane &= ~((uint64_t)0xFF << (j*8));
            }
            state->A[lanePosition] = lane;
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Permute_Nrounds(KeccakP1600_plain64_state *state, unsigned int nr)
{
    declareABCDE
    unsigned int i;
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    roundsN(nr)
    copyToState(stateAsLanes, A)

}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Permute_24rounds(KeccakP1600_plain64_state *state)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    rounds24
    copyToState(stateAsLanes, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Permute_12rounds(KeccakP1600_plain64_state *state)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    rounds12
    copyToState(stateAsLanes, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractBytesInLane(const KeccakP1600_plain64_state *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length)
{
    uint64_t lane = state->A[lanePosition];
#ifdef KeccakP1600_plain64_useLaneComplementing
    if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
        lane = ~lane;
#endif
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    {
        uint64_t lane1[1];
        lane1[0] = lane;
        memcpy(data, (uint8_t*)lane1+offset, length);
    }
#else
    unsigned int i;
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        data[i] = lane & 0xFF;
        lane >>= 8;
    }
#endif
}

/* ---------------------------------------------------------------- */

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
static void fromWordToBytes(uint8_t *bytes, const uint64_t word)
{
    unsigned int i;

    for(i=0; i<(64/8); i++)
        bytes[i] = (word >> (8*i)) & 0xFF;
}
#endif

void KeccakP1600_plain64_ExtractLanes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, state, laneCount*8);
#else
    unsigned int i;

    for(i=0; i<laneCount; i++)
        fromWordToBytes(data+(i*8), ((const uint64_t*)state)[i]);
#endif
#ifdef KeccakP1600_plain64_useLaneComplementing
    if (laneCount > 1) {
        ((uint64_t*)data)[ 1] = ~((uint64_t*)data)[ 1];
        if (laneCount > 2) {
            ((uint64_t*)data)[ 2] = ~((uint64_t*)data)[ 2];
            if (laneCount > 8) {
                ((uint64_t*)data)[ 8] = ~((uint64_t*)data)[ 8];
                if (laneCount > 12) {
                    ((uint64_t*)data)[12] = ~((uint64_t*)data)[12];
                    if (laneCount > 17) {
                        ((uint64_t*)data)[17] = ~((uint64_t*)data)[17];
                        if (laneCount > 20) {
                            ((uint64_t*)data)[20] = ~((uint64_t*)data)[20];
                        }
                    }
                }
            }
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractBytes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_ExtractBytes(state, data, offset, length, KeccakP1600_plain64_ExtractLanes, KeccakP1600_plain64_ExtractBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractAndAddBytesInLane(const KeccakP1600_plain64_state *state, unsigned int lanePosition, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    uint64_t lane = state->A[lanePosition];
#ifdef KeccakP1600_plain64_useLaneComplementing
    if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
        lane = ~lane;
#endif
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    {
        unsigned int i;
        uint64_t lane1[1];
        lane1[0] = lane;
        for(i=0; i<length; i++)
            output[i] = input[i] ^ ((uint8_t*)lane1)[offset+i];
    }
#else
    unsigned int i;
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        output[i] = input[i] ^ (lane & 0xFF);
        lane >>= 8;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractAndAddLanes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int laneCount)
{
    unsigned int i;
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
    unsigned char temp[8];
    unsigned int j;
#endif

    for(i=0; i<laneCount; i++) {
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
        ((uint64_t*)output)[i] = ((uint64_t*)input)[i] ^ ((const uint64_t*)state)[i];
#else
        fromWordToBytes(temp, ((const uint64_t*)state)[i]);
        for(j=0; j<8; j++)
            output[i*8+j] = input[i*8+j] ^ temp[j];
#endif
    }
#ifdef KeccakP1600_plain64_useLaneComplementing
    if (laneCount > 1) {
        ((uint64_t*)output)[ 1] = ~((uint64_t*)output)[ 1];
        if (laneCount > 2) {
            ((uint64_t*)output)[ 2] = ~((uint64_t*)output)[ 2];
            if (laneCount > 8) {
                ((uint64_t*)output)[ 8] = ~((uint64_t*)output)[ 8];
                if (laneCount > 12) {
                    ((uint64_t*)output)[12] = ~((uint64_t*)output)[12];
                    if (laneCount > 17) {
                        ((uint64_t*)output)[17] = ~((uint64_t*)output)[17];
                        if (laneCount > 20) {
                            ((uint64_t*)output)[20] = ~((uint64_t*)output)[20];
                        }
                    }
                }
            }
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractAndAddBytes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    SnP_ExtractAndAddBytes(state, input, output, offset, length, KeccakP1600_plain64_ExtractAndAddLanes, KeccakP1600_plain64_ExtractAndAddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

size_t KeccakF1600_plain64_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen)
{
    size_t originalDataByteLen = dataByteLen;
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;
    uint64_t *inDataAsLanes = (uint64_t*)data;

    copyFromState(A, stateAsLanes)
    while(dataByteLen >= laneCount*8) {
        addInput(A, inDataAsLanes, laneCount)
        rounds24
        inDataAsLanes += laneCount;
        dataByteLen -= laneCount*8;
    }
    copyToState(stateAsLanes, A)
    return originalDataByteLen - dataByteLen;
}

/* ---------------------------------------------------------------- */

size_t KeccakP1600_12rounds_plain64_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen)
{
    size_t originalDataByteLen = dataByteLen;
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;
    uint64_t *inDataAsLanes = (uint64_t*)data;

    copyFromState(A, stateAsLanes)
    while(dataByteLen >= laneCount*8) {
        addInput(A, inDataAsLanes, laneCount)
        rounds12
        inDataAsLanes += laneCount;
        dataByteLen -= laneCount*8;
    }
    copyToState(stateAsLanes, A)
    return originalDataByteLen - dataByteLen;
}

/* ---------------------------------------------------------------- */

// r = 160
#define mStateIn160( __s )          Asa = __s[20]; Ase = __s[21]; Asi = __s[22]; Aso = __s[23]; Asu = __s[24]

#define mStateOut160( __s )         __s[20] = Asa; __s[21] = Ase; __s[22] = Asi; __s[23] = Aso; __s[24] = Asu

#define mStateOver160( __i )        Aba = __i[ 0]; Abe = __i[ 1]; Abi = __i[ 2]; Abo = __i[ 3]; Abu = __i[ 4]; \
                                    Aga = __i[ 5]; Age = __i[ 6]; Agi = __i[ 7]; Ago = __i[ 8]; Agu = __i[ 9]; \
                                    Aka = __i[10]; Ake = __i[11]; Aki = __i[12]; Ako = __i[13]; Aku = __i[14]; \
                                    Ama = __i[15]; Ame = __i[16]; Ami = __i[17]; Amo = __i[18]; Amu = __i[19]

#define mStateNoInput160()          Aba = 1; Abe = 0; Abi = 0; Abo = 0; Abu = 0; \
                                    Aga = 0; Age = 0; Agi = 0; Ago = 0; Agu = 0; \
                                    Aka = 0; Ake = 0; Aki = 0; Ako = 0; Aku = 0; \
                                    Ama = 0; Ame = 0; Ami = 0; Amo = 0; Amu = 0

#define mStateExtr160( __o, __oA )  __o[ 0] = Aba ^ __oA[ 0]; __o[ 1] = Abe ^ __oA[ 1]; __o[ 2] = Abi ^ __oA[ 2]; __o[ 3] = Abo ^ __oA[ 3]; __o[ 4] = Abu ^ __oA[ 4]; \
                                    __o[ 5] = Aga ^ __oA[ 5]; __o[ 6] = Age ^ __oA[ 6]; __o[ 7] = Agi ^ __oA[ 7]; __o[ 8] = Ago ^ __oA[ 8]; __o[ 9] = Agu ^ __oA[ 9]; \
                                    __o[10] = Aka ^ __oA[10]; __o[11] = Ake ^ __oA[11]; __o[12] = Aki ^ __oA[12]; __o[13] = Ako ^ __oA[13]; __o[14] = Aku ^ __oA[14]; \
                                    __o[15] = Ama ^ __oA[15]; __o[16] = Ame ^ __oA[16]; __o[17] = Ami ^ __oA[17]; __o[18] = Amo ^ __oA[18]; __o[19] = Amu ^ __oA[19]

// r = 128
#define mStateIn128( __s )          mStateIn160( __s ); Ame = __s[16]; Ami = __s[17]; Amo = __s[18]; Amu = __s[19]

#define mStateOut128( __s )         mStateOut160( __s ); __s[16] = Ame; __s[17] = Ami; __s[18] = Amo; __s[19] = Amu

#define mStateOver128( __i )        Aba = __i[ 0]; Abe = __i[ 1]; Abi = __i[ 2]; Abo = __i[ 3]; Abu = __i[ 4]; \
                                    Aga = __i[ 5]; Age = __i[ 6]; Agi = __i[ 7]; Ago = __i[ 8]; Agu = __i[ 9]; \
                                    Aka = __i[10]; Ake = __i[11]; Aki = __i[12]; Ako = __i[13]; Aku = __i[14]; \
                                    Ama = __i[15]

#define mStateNoInput128()          Aba = 1; Abe = 0; Abi = 0; Abo = 0; Abu = 0; \
                                    Aga = 0; Age = 0; Agi = 0; Ago = 0; Agu = 0; \
                                    Aka = 0; Ake = 0; Aki = 0; Ako = 0; Aku = 0; \
                                    Ama = 0

#define mStateExtr128( __o, __oA )  __o[ 0] = Aba ^ __oA[ 0]; __o[ 1] = Abe ^ __oA[ 1]; __o[ 2] = Abi ^ __oA[ 2]; __o[ 3] = Abo ^ __oA[ 3]; __o[ 4] = Abu ^ __oA[ 4]; \
                                    __o[ 5] = Aga ^ __oA[ 5]; __o[ 6] = Age ^ __oA[ 6]; __o[ 7] = Agi ^ __oA[ 7]; __o[ 8] = Ago ^ __oA[ 8]; __o[ 9] = Agu ^ __oA[ 9]; \
                                    __o[10] = Aka ^ __oA[10]; __o[11] = Ake ^ __oA[11]; __o[12] = Aki ^ __oA[12]; __o[13] = Ako ^ __oA[13]; __o[14] = Aku ^ __oA[14]; \
                                    __o[15] = Ama ^ __oA[15]

// Whole state
#define mStateOutAll( __s )         __s[ 0] = Aba; __s[ 1] = Abe; __s[ 2] = Abi; __s[ 3] = Abo; __s[ 4] = Abu; \
                                    __s[ 5] = Aga; __s[ 6] = Age; __s[ 7] = Agi; __s[ 8] = Ago; __s[ 9] = Agu; \
                                    __s[10] = Aka; __s[11] = Ake; __s[12] = Aki; __s[13] = Ako; __s[14] = Aku; \
                                    __s[15] = Ama; __s[16] = Ame; __s[17] = Ami; __s[18] = Amo; __s[19] = Amu; \
                                    __s[20] = Asa; __s[21] = Ase; __s[22] = Asi; __s[23] = Aso; __s[24] = Asu;

/* ---------------------------------------------------------------- */

#define ODDuplexingFastInOut(RHO, trailerLane, rounds) \
    size_t originalDataByteLen = len; \
    uint64_t        *stateAsLanes       = (uint64_t*)state; \
    const uint64_t  *inDataAsLanes      = (const uint64_t*)idata; \
    uint64_t        *outDataAsLanes     = (uint64_t*)odata; \
    const uint64_t  *outDataAddAsLanes  = (const uint64_t*)odataAdd; \
    \
    mStateIn##RHO( stateAsLanes ); \
    while ( len >= RHO ) { \
        mStateOver##RHO( inDataAsLanes ); \
        trailerLane ^= trailencAsLane; \
        rounds \
        mStateExtr##RHO( outDataAsLanes, outDataAddAsLanes ); \
        inDataAsLanes       += RHO / 8; \
        outDataAsLanes      += RHO / 8; \
        outDataAddAsLanes   += RHO / 8; \
        len                 -= RHO; \
    } \
    mStateOut##RHO( stateAsLanes ); \
    \
    return originalDataByteLen - len;

size_t KeccakP1600_plain64_ODDuplexingFastInOut(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *idata, size_t len, unsigned char *odata, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif

    if (laneCount == 16) {
        ODDuplexingFastInOut(128, Ame, rounds24)
    }
    else if (laneCount == 20) {
        ODDuplexingFastInOut(160, Asa, rounds24)
    }
    else {
        abort();
    }
}

size_t KeccakP1600_12rounds_plain64_ODDuplexingFastInOut(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *idata, size_t len, unsigned char *odata, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif

    if (laneCount == 16) {
        ODDuplexingFastInOut(128, Ame, rounds12)
    }
    else if (laneCount == 20) {
        ODDuplexingFastInOut(160, Asa, rounds12)
    }
    else {
        abort();
    }
}

/* ---------------------------------------------------------------- */

#define ODDuplexingFastOut(RHO, trailerLane, rounds) \
    size_t originalDataByteLen = len; \
    uint64_t        *stateAsLanes       = (uint64_t*)state; \
    uint64_t        *outDataAsLanes     = (uint64_t*)odata; \
    const uint64_t  *outDataAddAsLanes  = (const uint64_t*)odataAdd; \
    \
    mStateIn##RHO( stateAsLanes ); \
    while ( len >= RHO ) { \
        mStateNoInput##RHO(); \
        trailerLane ^= trailencAsLane; \
        rounds \
        mStateExtr##RHO( outDataAsLanes, outDataAddAsLanes ); \
        outDataAsLanes      += RHO / 8; \
        outDataAddAsLanes   += RHO / 8; \
        len                 -= RHO; \
    } \
    mStateOut##RHO( stateAsLanes ); \
    \
    return originalDataByteLen - len;

size_t KeccakP1600_plain64_ODDuplexingFastOut(KeccakP1600_plain64_state *state, unsigned int laneCount, unsigned char *odata, size_t len, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif

    if (laneCount == 16) {
        ODDuplexingFastOut(128, Ame, rounds24)
    }
    else if (laneCount == 20) {
        ODDuplexingFastOut(160, Asa, rounds24)
    }
    else {
        abort();
    }
}

size_t KeccakP1600_12rounds_plain64_ODDuplexingFastOut(KeccakP1600_plain64_state *state, unsigned int laneCount, unsigned char *odata, size_t len, const unsigned char *odataAdd, uint64_t trailencAsLane)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif

    if (laneCount == 16) {
        ODDuplexingFastOut(128, Ame, rounds12)
    }
    else if (laneCount == 20) {
        ODDuplexingFastOut(160, Asa, rounds12)
    }
    else {
        abort();
    }
}

/* ---------------------------------------------------------------- */

#define ODDuplexingFastIn(RHO, trailerLane, rounds) \
    size_t originalDataByteLen = len; \
    uint64_t        *stateAsLanes       = (uint64_t*)state; \
    const uint64_t  *inDataAsLanes      = (const uint64_t*)idata; \
    \
    mStateIn##RHO( stateAsLanes ); \
    while ( len > RHO ) { \
        mStateOver##RHO( inDataAsLanes ); \
        trailerLane ^= trailencAsLane; \
        rounds \
        inDataAsLanes   += RHO / 8; \
        len             -= RHO; \
    } \
    mStateOutAll( stateAsLanes ); \
    \
    return originalDataByteLen - len;

size_t KeccakP1600_plain64_ODDuplexingFastIn(KeccakP1600_plain64_state *state, unsigned int laneCount, const uint8_t *idata, size_t len, uint64_t trailencAsLane)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif

    if (laneCount == 16) {
        ODDuplexingFastIn(128, Ame, rounds24)
    }
    else if (laneCount == 20) {
        ODDuplexingFastIn(160, Asa, rounds24)
    }
    else {
        abort();
    }
}

size_t KeccakP1600_12rounds_plain64_ODDuplexingFastIn(KeccakP1600_plain64_state *state, unsigned int laneCount, const uint8_t *idata, size_t len, uint64_t trailencAsLane)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif

    if (laneCount == 16) {
        ODDuplexingFastIn(128, Ame, rounds12)
    }
    else if (laneCount == 20) {
        ODDuplexingFastIn(160, Asa, rounds12)
    }
    else {
        abort();
    }
}
