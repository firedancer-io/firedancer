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
#include "SnP-Relaned.h"

#define USE_MEMSET
/* #define DIVISION_INSTRUCTION */ /* comment if no division instruction or more compact when not using division */
#define UNROLL_CHILOOP        /* comment more compact using for loop */

typedef uint_fast8_t tSmallUInt;
typedef uint64_t tKeccakLane;

#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(UseSHLD)
    #define ROL64(x,N) ({ \
    register uint64_t __out; \
    register uint64_t __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#else
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#endif

#define    cKeccakNumberOfRounds    24

const uint8_t KeccakP1600_RotationConstants[25] =
{
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

const uint8_t KeccakP1600_PiLane[25] =
{
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

#if    defined(DIVISION_INSTRUCTION)
#define    MOD5(argValue)    ((argValue) % 5)
#else
const uint8_t KeccakP1600_Mod5[10] =
{
    0, 1, 2, 3, 4, 0, 1, 2, 3, 4
};
#define    MOD5(argValue)    KeccakP1600_Mod5[argValue]
#endif

/* ---------------------------------------------------------------- */

static tKeccakLane KeccakF1600_GetNextRoundConstant( uint8_t *LFSR );
static tKeccakLane KeccakF1600_GetNextRoundConstant( uint8_t *LFSR )
{
    tSmallUInt i;
    tKeccakLane    roundConstant;
    tSmallUInt doXOR;
    tSmallUInt tempLSFR;

    roundConstant = 0;
    tempLSFR = *LFSR;
    for(i=1; i<128; i <<= 1)
    {
        doXOR = tempLSFR & 1;
        if ((tempLSFR & 0x80) != 0)
            /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
            tempLSFR = (tempLSFR << 1) ^ 0x71;
        else
            tempLSFR <<= 1;

        if ( doXOR != 0 )
            roundConstant ^= (tKeccakLane)1ULL << (i - 1);
    }
    *LFSR = (uint8_t)tempLSFR;
    return ( roundConstant );
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Initialize(KeccakP1600_plain64_state *argState)
{
    #if defined(USE_MEMSET)
    memset( argState, 0, 25 * 8 );
    #else
    tSmallUInt i;
    tKeccakLane *state;

    state = argState;
    i = 25;
    do
    {
        *(state++) = 0;
    }
    while ( --i != 0 );
    #endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytesInLane(KeccakP1600_plain64_state *argState, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int i;
    #if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned char * state = (unsigned char*)argState + lanePosition * sizeof(tKeccakLane) + offset;
    for(i=0; i<length; i++)
        ((unsigned char *)state)[i] ^= data[i];
    #else
    tKeccakLane lane = 0;
    for(i=0; i<length; i++)
        lane |= ((tKeccakLane)data[i]) << ((i+offset)*8);
    ((tKeccakLane*)argState)[lanePosition] ^= lane;
    #endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddLanes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    tSmallUInt i;
    laneCount *= sizeof(tKeccakLane);
    for( i = 0; i < laneCount; ++i) {
        ((unsigned char*)state)[i] ^= data[i];
    }
#else
    tSmallUInt i;
    const uint8_t *curData = data;
    for(i=0; i<laneCount; i++, curData+=8) {
        tKeccakLane lane = (tKeccakLane)curData[0]
            | ((tKeccakLane)curData[1] << 8)
            | ((tKeccakLane)curData[2] << 16)
            | ((tKeccakLane)curData[3] << 24)
            | ((tKeccakLane)curData[4] << 32)
            | ((tKeccakLane)curData[5] << 40)
            | ((tKeccakLane)curData[6] << 48)
            | ((tKeccakLane)curData[7] << 56);
        ((tKeccakLane*)state)[i] ^= lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddByte(KeccakP1600_plain64_state *state, unsigned char byte, unsigned int offset)
{
    uint64_t lane = byte;
    lane <<= (offset%8)*8;
    ((uint64_t*)state)[offset/8] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_AddBytes(state, data, offset, length, KeccakP1600_AddLanes, KeccakP1600_AddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteBytesInLane(KeccakP1600_plain64_state *argState, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy((unsigned char*)argState+lanePosition*8+offset, data, length);
#else
    unsigned int i;
    tKeccakLane *state = (tKeccakLane*)argState;
    tKeccakLane lane = state[lanePosition];
    for(i=0; i<length; i++) {
        lane &= ~(((tKeccakLane)0xFF) << ((i+offset)*8));
        lane |= ((tKeccakLane)data[i]) << ((i+offset)*8);
    }
    state[lanePosition] = lane;
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteLanes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy((unsigned char*)state, data, laneCount*8);
#else
    tSmallUInt i;
    const uint8_t *curData = data;
    for(i=0; i<laneCount; i++, curData+=8) {
        tKeccakLane lane = (tKeccakLane)curData[0]
            | ((tKeccakLane)curData[1] << 8)
            | ((tKeccakLane)curData[2] << 16)
            | ((tKeccakLane)curData[3] << 24)
            | ((tKeccakLane)curData[4] << 32)
            | ((tKeccakLane)curData[5] << 40)
            | ((tKeccakLane)curData[6] << 48)
            | ((tKeccakLane)curData[7] << 56);
        ((tKeccakLane*)state)[i] = lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_OverwriteBytes(state, data, offset, length, KeccakP1600_OverwriteLanes, KeccakP1600_OverwriteBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteWithZeroes(KeccakP1600_plain64_state *argState, unsigned int byteCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memset((unsigned char*)argState, 0, byteCount);
#else
    tKeccakLane *state = (tKeccakLane*)argState;
    unsigned int i, j;
    for(i=0; i<byteCount/8; i++)
        state[i] = 0;
    for(j=0; j<byteCount%8; j++)
        state[i] &= ~(((tKeccakLane)0xFF) << (j*8));
#endif
}

/* ---------------------------------------------------------------- */

static void KeccakP1600_Permute_NroundsLFSR(KeccakP1600_plain64_state *argState, uint8_t rounds, uint8_t LFSRinitialState)
{
    tSmallUInt x, y, round;
    tKeccakLane        temp;
    tKeccakLane        BC[5];
    tKeccakLane     *state;
    uint8_t           LFSRstate;

    state = (tKeccakLane*)argState;
    LFSRstate = LFSRinitialState;
    round = rounds;
    do
    {
        /* Theta */
        for ( x = 0; x < 5; ++x )
        {
            BC[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
        }
        for ( x = 0; x < 5; ++x )
        {
            temp = BC[MOD5(x+4)] ^ ROL64(BC[MOD5(x+1)], 1);
            for ( y = 0; y < 25; y += 5 )
            {
                state[y + x] ^= temp;
            }
        }

        /* Rho Pi */
        temp = state[1];
        for ( x = 0; x < 24; ++x )
        {
            BC[0] = state[KeccakP1600_PiLane[x]];
            state[KeccakP1600_PiLane[x]] = ROL64( temp, KeccakP1600_RotationConstants[x] );
            temp = BC[0];
        }

        /*    Chi */
        for ( y = 0; y < 25; y += 5 )
        {
#if defined(UNROLL_CHILOOP)
            BC[0] = state[y + 0];
            BC[1] = state[y + 1];
            BC[2] = state[y + 2];
            BC[3] = state[y + 3];
            BC[4] = state[y + 4];
#else
            for ( x = 0; x < 5; ++x )
            {
                BC[x] = state[y + x];
            }
#endif
            for ( x = 0; x < 5; ++x )
            {
                state[y + x] = BC[x] ^((~BC[MOD5(x+1)]) & BC[MOD5(x+2)]);
            }
        }

        /*    Iota */
        state[0] ^= KeccakF1600_GetNextRoundConstant(&LFSRstate);
    }
    while( --round != 0 );
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_Nrounds(KeccakP1600_plain64_state *state, unsigned int nrounds)
{
	uint8_t LFSRstate;
	uint8_t nr;

	LFSRstate = 0x01;
	for ( nr = 24 - nrounds; nr != 0; --nr )
        KeccakF1600_GetNextRoundConstant(&LFSRstate);
    KeccakP1600_Permute_NroundsLFSR(state, nrounds, LFSRstate);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_12rounds(KeccakP1600_plain64_state *state)
{
    KeccakP1600_Permute_NroundsLFSR(state, 12, 0xD5);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_24rounds(KeccakP1600_plain64_state *state)
{
    KeccakP1600_Permute_NroundsLFSR(state, 24, 0x01);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractBytesInLane(const KeccakP1600_plain64_state *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, ((uint8_t*)&((tKeccakLane*)state)[lanePosition])+offset, length);
#else
    tSmallUInt i;
    tKeccakLane lane = ((tKeccakLane*)state)[lanePosition];
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        data[i] = lane & 0xFF;
        lane >>= 8;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractLanes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, state, laneCount*8);
#else
    tSmallUInt i, j;
    for(i=0; i<laneCount; i++)
    {
        for(j=0; j<(64/8); j++)
        {
            data[(i*8)+j] = (((const tKeccakLane*)state)[i] >> (8*j)) & 0xFF;
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractBytes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_ExtractBytes(state, data, offset, length, KeccakP1600_ExtractLanes, KeccakP1600_ExtractBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddBytesInLane(const KeccakP1600_plain64_state *state, unsigned int lanePosition, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    tSmallUInt i;
    tKeccakLane lane = ((tKeccakLane*)state)[lanePosition];
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        output[i] = input[i] ^ (lane & 0xFF);
        lane >>= 8;
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddLanes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    tSmallUInt i;
    for(i=0; i<laneCount; i++)
        ((tKeccakLane*)output)[i] = ((tKeccakLane*)input)[i] ^ ((const tKeccakLane*)state)[i];
#else
    tSmallUInt i, j;
    for(i=0; i<laneCount; i++)
    {
        for(j=0; j<(64/8); j++)
        {
            output[(i*8)+j] = input[(i*8)+j] ^ ((((const tKeccakLane*)state)[i] >> (8*j)) & 0xFF);
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    SnP_ExtractAndAddBytes(state, input, output, offset, length, KeccakP1600_ExtractAndAddLanes, KeccakP1600_ExtractAndAddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */
