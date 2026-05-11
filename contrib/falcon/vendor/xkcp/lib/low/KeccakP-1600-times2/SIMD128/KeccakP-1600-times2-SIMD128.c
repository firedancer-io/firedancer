/*
The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements Keccak-p[1600]×2 in a PlSnP-compatible way.
Please refer to PlSnP-documentation.h for more details.

This implementation comes with KeccakP-1600-times2-SnP.h in the same folder.
Please refer to LowLevel.build for the exact list of other files it must be combined with.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>
#include <pmmintrin.h>
#include <tmmintrin.h>
#include "align.h"
#include "KeccakP-1600-times2-SIMD128.h"
#if defined(KeccakP1600times2_SSSE3_useXOP)
#include <x86intrin.h>
#endif

#include "brg_endian.h"
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

#define laneIndex(instanceIndex, lanePosition) ((lanePosition)*2 + instanceIndex)

#define ANDnu128(a, b)      _mm_andnot_si128(a, b)
#define CONST128(a)         _mm_load_si128((const V128 *)&(a))
#define LOAD128(a)          _mm_load_si128((const V128 *)&(a))
#define LOAD128u(a)         _mm_loadu_si128((const V128 *)&(a))
#define LOAD6464(a, b)      _mm_set_epi64x(a, b)
#define CONST128_64(a)      _mm_set1_epi64x(a)
#if defined(KeccakP1600times2_SSSE3_useXOP)
    #define ROL64in128(a, o)    _mm_roti_epi64(a, o)
    #define ROL64in128_8(a)     ROL64in128(a, 8)
    #define ROL64in128_56(a)    ROL64in128(a, 56)
#else
    #define ROL64in128(a, o)    _mm_or_si128(_mm_slli_epi64(a, o), _mm_srli_epi64(a, 64-(o)))
    #define ROL64in128_8(a)     _mm_shuffle_epi8(a, CONST128(rho8))
    #define ROL64in128_56(a)    _mm_shuffle_epi8(a, CONST128(rho56))
static const uint64_t rho8[2] = {0x0605040302010007, 0x0E0D0C0B0A09080F};
static const uint64_t rho56[2] = {0x0007060504030201, 0x080F0E0D0C0B0A09};
#endif
#define STORE128(a, b)      _mm_store_si128((V128 *)&(a), b)
#define STORE128u(a, b)     _mm_storeu_si128((V128 *)&(a), b)
#define STORE64L(a, b)      _mm_storel_epi64((__m128i *)&(a), b)
#define STORE64H(a, b)      _mm_storeh_pi((__m64 *)&(a), _mm_castsi128_ps(b))
#define XOR128(a, b)        _mm_xor_si128(a, b)
#define XOReq128(a, b)      a = _mm_xor_si128(a, b)
#define ZERO128()           _mm_setzero_si128()
#define UNPACKL( a, b )     _mm_unpacklo_epi64((a), (b))
#define UNPACKH( a, b )     _mm_unpackhi_epi64((a), (b))

#define SnP_laneLengthInBytes 8

void KeccakP1600times2_SSSE3_InitializeAll(KeccakP1600times2_SIMD128_states *states)
{
    memset(states, 0, sizeof(KeccakP1600times2_SIMD128_states));
}

void KeccakP1600times2_SSSE3_AddBytes(KeccakP1600times2_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curData = data;
    uint64_t *statesAsLanes = (uint64_t *)states->A;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        uint64_t lane = 0;
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        memcpy((unsigned char*)&lane + offsetInLane, curData, bytesInLane);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
        sizeLeft -= bytesInLane;
        lanePosition++;
        curData += bytesInLane;
    }

    while(sizeLeft >= SnP_laneLengthInBytes) {
        uint64_t lane = *((const uint64_t*)curData);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        uint64_t lane = 0;
        memcpy(&lane, curData, sizeLeft);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
    }
}

void KeccakP1600times2_SSSE3_AddLanesAll(KeccakP1600times2_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes = states->A;
    unsigned int i;
    const uint64_t *curData0 = (const uint64_t *)data;
    const uint64_t *curData1 = (const uint64_t *)(data+laneOffset*SnP_laneLengthInBytes);
    #define XOR_In( argIndex )  XOReq128( stateAsLanes[argIndex], LOAD6464(curData1[argIndex], curData0[argIndex]))
    if ( laneCount >= 17 )  {
        XOR_In( 0 );
        XOR_In( 1 );
        XOR_In( 2 );
        XOR_In( 3 );
        XOR_In( 4 );
        XOR_In( 5 );
        XOR_In( 6 );
        XOR_In( 7 );
        XOR_In( 8 );
        XOR_In( 9 );
        XOR_In( 10 );
        XOR_In( 11 );
        XOR_In( 12 );
        XOR_In( 13 );
        XOR_In( 14 );
        XOR_In( 15 );
        XOR_In( 16 );
        if ( laneCount >= 21 )  {
            XOR_In( 17 );
            XOR_In( 18 );
            XOR_In( 19 );
            XOR_In( 20 );
            for(i=21; i<laneCount; i++)
                XOR_In( i );
        }
        else {
            for(i=17; i<laneCount; i++)
                XOR_In( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            XOR_In( i );
    }
    #undef  XOR_In
}

void KeccakP1600times2_SSSE3_OverwriteBytes(KeccakP1600times2_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curData = data;
    uint64_t *statesAsLanes = (uint64_t *)states->A;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        memcpy( ((unsigned char *)&statesAsLanes[laneIndex(instanceIndex, lanePosition)]) + offsetInLane, curData, bytesInLane);
        sizeLeft -= bytesInLane;
        lanePosition++;
        curData += bytesInLane;
    }

    while(sizeLeft >= SnP_laneLengthInBytes) {
        uint64_t lane = *((const uint64_t*)curData);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] = lane;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        memcpy(&statesAsLanes[laneIndex(instanceIndex, lanePosition)], curData, sizeLeft);
    }
}

void KeccakP1600times2_SSSE3_OverwriteLanesAll(KeccakP1600times2_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes = states->A;
    unsigned int i;
    const uint64_t *curData0 = (const uint64_t *)data;
    const uint64_t *curData1 = (const uint64_t *)(data+laneOffset*SnP_laneLengthInBytes);
    #define OverWr( argIndex )  STORE128(stateAsLanes[argIndex], LOAD6464(curData1[argIndex], curData0[argIndex]))
    if ( laneCount >= 17 )  {
        OverWr( 0 );
        OverWr( 1 );
        OverWr( 2 );
        OverWr( 3 );
        OverWr( 4 );
        OverWr( 5 );
        OverWr( 6 );
        OverWr( 7 );
        OverWr( 8 );
        OverWr( 9 );
        OverWr( 10 );
        OverWr( 11 );
        OverWr( 12 );
        OverWr( 13 );
        OverWr( 14 );
        OverWr( 15 );
        OverWr( 16 );
        if ( laneCount >= 21 )  {
            OverWr( 17 );
            OverWr( 18 );
            OverWr( 19 );
            OverWr( 20 );
            for(i=21; i<laneCount; i++)
                OverWr( i );
        }
        else {
            for(i=17; i<laneCount; i++)
                OverWr( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            OverWr( i );
    }
    #undef  OverWr
}

void KeccakP1600times2_SSSE3_OverwriteWithZeroes(KeccakP1600times2_SIMD128_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    unsigned int sizeLeft = byteCount;
    unsigned int lanePosition = 0;
    uint64_t *statesAsLanes = (uint64_t *)states->A;

    while(sizeLeft >= SnP_laneLengthInBytes) {
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] = 0;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
    }

    if (sizeLeft > 0) {
        memset(&statesAsLanes[laneIndex(instanceIndex, lanePosition)], 0, sizeLeft);
    }
}

void KeccakP1600times2_SSSE3_ExtractBytes(const KeccakP1600times2_SIMD128_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    unsigned char *curData = data;
    const uint64_t *statesAsLanes = (const uint64_t *)states->A;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        memcpy( curData, ((unsigned char *)&statesAsLanes[laneIndex(instanceIndex, lanePosition)]) + offsetInLane, bytesInLane);
        sizeLeft -= bytesInLane;
        lanePosition++;
        curData += bytesInLane;
    }

    while(sizeLeft >= SnP_laneLengthInBytes) {
        *(uint64_t*)curData = statesAsLanes[laneIndex(instanceIndex, lanePosition)];
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        memcpy( curData, &statesAsLanes[laneIndex(instanceIndex, lanePosition)], sizeLeft);
    }
}

void KeccakP1600times2_SSSE3_ExtractLanesAll(const KeccakP1600times2_SIMD128_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    const V128 *stateAsLanes = states->A;
    V128 lanes;
    unsigned int i;
    uint64_t *curData0 = (uint64_t *)data;
    uint64_t *curData1 = (uint64_t *)(data+laneOffset*SnP_laneLengthInBytes);

    #define Extr( argIndex )    lanes = LOAD128( stateAsLanes[argIndex] ),          \
                                STORE64L( curData0[argIndex], lanes ),              \
                                STORE64H( curData1[argIndex], lanes )

    #define Extr2( argIndex )   lanes0 = LOAD128( stateAsLanes[argIndex] ),         \
                                lanes1 = LOAD128( stateAsLanes[(argIndex)+1] ),     \
                                lanes =  UNPACKL( lanes0, lanes1 ),                 \
                                lanes0 = UNPACKH( lanes0, lanes1 ),                 \
                                STORE128u( *(V128*)&curData0[argIndex], lanes ),    \
                                STORE128u( *(V128*)&curData1[argIndex], lanes0 )
    if ( laneCount >= 16 )  {
        V128 lanes0, lanes1;
        Extr2( 0 );
        Extr2( 2 );
        Extr2( 4 );
        Extr2( 6 );
        Extr2( 8 );
        Extr2( 10 );
        Extr2( 12 );
        Extr2( 14 );
        if ( laneCount >= 20 )  {
            Extr2( 16 );
            Extr2( 18 );
            for(i=20; i<laneCount; i++)
                Extr( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                Extr( i );
        }
    }
    #undef  Extr2
    else {
        for(i=0; i<laneCount; i++)
            Extr( i );
    }
    #undef  Extr
}

void KeccakP1600times2_SSSE3_ExtractAndAddBytes(const KeccakP1600times2_SIMD128_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curInput = input;
    unsigned char *curOutput = output;
    const uint64_t *statesAsLanes = (const uint64_t *)states->A;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        uint64_t lane = statesAsLanes[laneIndex(instanceIndex, lanePosition)] >> (8 * offsetInLane);
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        sizeLeft -= bytesInLane;
        do {
            *(curOutput++) = *(curInput++) ^ (unsigned char)lane;
            lane >>= 8;
        } while ( --bytesInLane != 0);
        lanePosition++;
    }

    while(sizeLeft >= SnP_laneLengthInBytes) {
        *((uint64_t*)curOutput) = *((uint64_t*)curInput) ^ statesAsLanes[laneIndex(instanceIndex, lanePosition)];
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curInput += SnP_laneLengthInBytes;
        curOutput += SnP_laneLengthInBytes;
    }

    if (sizeLeft != 0) {
        uint64_t lane = statesAsLanes[laneIndex(instanceIndex, lanePosition)];
        do {
            *(curOutput++) = *(curInput++) ^ (unsigned char)lane;
            lane >>= 8;
        } while ( --sizeLeft != 0);
    }
}

void KeccakP1600times2_SSSE3_ExtractAndAddLanesAll(const KeccakP1600times2_SIMD128_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    const uint64_t *stateAsLanes = (const uint64_t *)states->A;
    unsigned int i;
    const uint64_t *curInput0 = (uint64_t *)input;
    const uint64_t *curInput1 = (uint64_t *)(input+laneOffset*SnP_laneLengthInBytes);
    uint64_t *curOutput0 = (uint64_t *)output;
    uint64_t *curOutput1 = (uint64_t *)(output+laneOffset*SnP_laneLengthInBytes);

    #define ExtrXOR( argIndex ) curOutput0[argIndex] = curInput0[argIndex] ^ stateAsLanes[2*(argIndex)], curOutput1[argIndex] = curInput1[argIndex] ^ stateAsLanes[2*(argIndex)+1]

    if ( laneCount >= 17 )  {
        ExtrXOR( 0 );
        ExtrXOR( 1 );
        ExtrXOR( 2 );
        ExtrXOR( 3 );
        ExtrXOR( 4 );
        ExtrXOR( 5 );
        ExtrXOR( 6 );
        ExtrXOR( 7 );
        ExtrXOR( 8 );
        ExtrXOR( 9 );
        ExtrXOR( 10 );
        ExtrXOR( 11 );
        ExtrXOR( 12 );
        ExtrXOR( 13 );
        ExtrXOR( 14 );
        ExtrXOR( 15 );
        ExtrXOR( 16 );
        if ( laneCount >= 21 )  {
            ExtrXOR( 17 );
            ExtrXOR( 18 );
            ExtrXOR( 19 );
            ExtrXOR( 20 );
            for(i=21; i<laneCount; i++)
                ExtrXOR( i );
        }
        else {
            for(i=17; i<laneCount; i++)
                ExtrXOR( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            ExtrXOR( i );
    }
    #undef  ExtrXOR
}

#define declareABCDE \
    V128 Aba, Abe, Abi, Abo, Abu; \
    V128 Aga, Age, Agi, Ago, Agu; \
    V128 Aka, Ake, Aki, Ako, Aku; \
    V128 Ama, Ame, Ami, Amo, Amu; \
    V128 Asa, Ase, Asi, Aso, Asu; \
    V128 Bba, Bbe, Bbi, Bbo, Bbu; \
    V128 Bga, Bge, Bgi, Bgo, Bgu; \
    V128 Bka, Bke, Bki, Bko, Bku; \
    V128 Bma, Bme, Bmi, Bmo, Bmu; \
    V128 Bsa, Bse, Bsi, Bso, Bsu; \
    V128 Ca, Ce, Ci, Co, Cu; \
    V128 Da, De, Di, Do, Du; \
    V128 Eba, Ebe, Ebi, Ebo, Ebu; \
    V128 Ega, Ege, Egi, Ego, Egu; \
    V128 Eka, Eke, Eki, Eko, Eku; \
    V128 Ema, Eme, Emi, Emo, Emu; \
    V128 Esa, Ese, Esi, Eso, Esu; \

#define prepareTheta \
    Ca = XOR128(Aba, XOR128(Aga, XOR128(Aka, XOR128(Ama, Asa)))); \
    Ce = XOR128(Abe, XOR128(Age, XOR128(Ake, XOR128(Ame, Ase)))); \
    Ci = XOR128(Abi, XOR128(Agi, XOR128(Aki, XOR128(Ami, Asi)))); \
    Co = XOR128(Abo, XOR128(Ago, XOR128(Ako, XOR128(Amo, Aso)))); \
    Cu = XOR128(Abu, XOR128(Agu, XOR128(Aku, XOR128(Amu, Asu)))); \

/* --- Theta Rho Pi Chi Iota Prepare-theta */
/* --- 64-bit lanes mapped to 64-bit words */
#define thetaRhoPiChiIotaPrepareTheta(i, A, E) \
    Da = XOR128(Cu, ROL64in128(Ce, 1)); \
    De = XOR128(Ca, ROL64in128(Ci, 1)); \
    Di = XOR128(Ce, ROL64in128(Co, 1)); \
    Do = XOR128(Ci, ROL64in128(Cu, 1)); \
    Du = XOR128(Co, ROL64in128(Ca, 1)); \
\
    XOReq128(A##ba, Da); \
    Bba = A##ba; \
    XOReq128(A##ge, De); \
    Bbe = ROL64in128(A##ge, 44); \
    XOReq128(A##ki, Di); \
    Bbi = ROL64in128(A##ki, 43); \
    E##ba = XOR128(Bba, ANDnu128(Bbe, Bbi)); \
    XOReq128(E##ba, CONST128_64(KeccakF1600RoundConstants[i])); \
    Ca = E##ba; \
    XOReq128(A##mo, Do); \
    Bbo = ROL64in128(A##mo, 21); \
    E##be = XOR128(Bbe, ANDnu128(Bbi, Bbo)); \
    Ce = E##be; \
    XOReq128(A##su, Du); \
    Bbu = ROL64in128(A##su, 14); \
    E##bi = XOR128(Bbi, ANDnu128(Bbo, Bbu)); \
    Ci = E##bi; \
    E##bo = XOR128(Bbo, ANDnu128(Bbu, Bba)); \
    Co = E##bo; \
    E##bu = XOR128(Bbu, ANDnu128(Bba, Bbe)); \
    Cu = E##bu; \
\
    XOReq128(A##bo, Do); \
    Bga = ROL64in128(A##bo, 28); \
    XOReq128(A##gu, Du); \
    Bge = ROL64in128(A##gu, 20); \
    XOReq128(A##ka, Da); \
    Bgi = ROL64in128(A##ka, 3); \
    E##ga = XOR128(Bga, ANDnu128(Bge, Bgi)); \
    XOReq128(Ca, E##ga); \
    XOReq128(A##me, De); \
    Bgo = ROL64in128(A##me, 45); \
    E##ge = XOR128(Bge, ANDnu128(Bgi, Bgo)); \
    XOReq128(Ce, E##ge); \
    XOReq128(A##si, Di); \
    Bgu = ROL64in128(A##si, 61); \
    E##gi = XOR128(Bgi, ANDnu128(Bgo, Bgu)); \
    XOReq128(Ci, E##gi); \
    E##go = XOR128(Bgo, ANDnu128(Bgu, Bga)); \
    XOReq128(Co, E##go); \
    E##gu = XOR128(Bgu, ANDnu128(Bga, Bge)); \
    XOReq128(Cu, E##gu); \
\
    XOReq128(A##be, De); \
    Bka = ROL64in128(A##be, 1); \
    XOReq128(A##gi, Di); \
    Bke = ROL64in128(A##gi, 6); \
    XOReq128(A##ko, Do); \
    Bki = ROL64in128(A##ko, 25); \
    E##ka = XOR128(Bka, ANDnu128(Bke, Bki)); \
    XOReq128(Ca, E##ka); \
    XOReq128(A##mu, Du); \
    Bko = ROL64in128_8(A##mu); \
    E##ke = XOR128(Bke, ANDnu128(Bki, Bko)); \
    XOReq128(Ce, E##ke); \
    XOReq128(A##sa, Da); \
    Bku = ROL64in128(A##sa, 18); \
    E##ki = XOR128(Bki, ANDnu128(Bko, Bku)); \
    XOReq128(Ci, E##ki); \
    E##ko = XOR128(Bko, ANDnu128(Bku, Bka)); \
    XOReq128(Co, E##ko); \
    E##ku = XOR128(Bku, ANDnu128(Bka, Bke)); \
    XOReq128(Cu, E##ku); \
\
    XOReq128(A##bu, Du); \
    Bma = ROL64in128(A##bu, 27); \
    XOReq128(A##ga, Da); \
    Bme = ROL64in128(A##ga, 36); \
    XOReq128(A##ke, De); \
    Bmi = ROL64in128(A##ke, 10); \
    E##ma = XOR128(Bma, ANDnu128(Bme, Bmi)); \
    XOReq128(Ca, E##ma); \
    XOReq128(A##mi, Di); \
    Bmo = ROL64in128(A##mi, 15); \
    E##me = XOR128(Bme, ANDnu128(Bmi, Bmo)); \
    XOReq128(Ce, E##me); \
    XOReq128(A##so, Do); \
    Bmu = ROL64in128_56(A##so); \
    E##mi = XOR128(Bmi, ANDnu128(Bmo, Bmu)); \
    XOReq128(Ci, E##mi); \
    E##mo = XOR128(Bmo, ANDnu128(Bmu, Bma)); \
    XOReq128(Co, E##mo); \
    E##mu = XOR128(Bmu, ANDnu128(Bma, Bme)); \
    XOReq128(Cu, E##mu); \
\
    XOReq128(A##bi, Di); \
    Bsa = ROL64in128(A##bi, 62); \
    XOReq128(A##go, Do); \
    Bse = ROL64in128(A##go, 55); \
    XOReq128(A##ku, Du); \
    Bsi = ROL64in128(A##ku, 39); \
    E##sa = XOR128(Bsa, ANDnu128(Bse, Bsi)); \
    XOReq128(Ca, E##sa); \
    XOReq128(A##ma, Da); \
    Bso = ROL64in128(A##ma, 41); \
    E##se = XOR128(Bse, ANDnu128(Bsi, Bso)); \
    XOReq128(Ce, E##se); \
    XOReq128(A##se, De); \
    Bsu = ROL64in128(A##se, 2); \
    E##si = XOR128(Bsi, ANDnu128(Bso, Bsu)); \
    XOReq128(Ci, E##si); \
    E##so = XOR128(Bso, ANDnu128(Bsu, Bsa)); \
    XOReq128(Co, E##so); \
    E##su = XOR128(Bsu, ANDnu128(Bsa, Bse)); \
    XOReq128(Cu, E##su); \
\

/* --- Theta Rho Pi Chi Iota */
/* --- 64-bit lanes mapped to 64-bit words */
#define thetaRhoPiChiIota(i, A, E) \
    Da = XOR128(Cu, ROL64in128(Ce, 1)); \
    De = XOR128(Ca, ROL64in128(Ci, 1)); \
    Di = XOR128(Ce, ROL64in128(Co, 1)); \
    Do = XOR128(Ci, ROL64in128(Cu, 1)); \
    Du = XOR128(Co, ROL64in128(Ca, 1)); \
\
    XOReq128(A##ba, Da); \
    Bba = A##ba; \
    XOReq128(A##ge, De); \
    Bbe = ROL64in128(A##ge, 44); \
    XOReq128(A##ki, Di); \
    Bbi = ROL64in128(A##ki, 43); \
    E##ba = XOR128(Bba, ANDnu128(Bbe, Bbi)); \
    XOReq128(E##ba, CONST128_64(KeccakF1600RoundConstants[i])); \
    XOReq128(A##mo, Do); \
    Bbo = ROL64in128(A##mo, 21); \
    E##be = XOR128(Bbe, ANDnu128(Bbi, Bbo)); \
    XOReq128(A##su, Du); \
    Bbu = ROL64in128(A##su, 14); \
    E##bi = XOR128(Bbi, ANDnu128(Bbo, Bbu)); \
    E##bo = XOR128(Bbo, ANDnu128(Bbu, Bba)); \
    E##bu = XOR128(Bbu, ANDnu128(Bba, Bbe)); \
\
    XOReq128(A##bo, Do); \
    Bga = ROL64in128(A##bo, 28); \
    XOReq128(A##gu, Du); \
    Bge = ROL64in128(A##gu, 20); \
    XOReq128(A##ka, Da); \
    Bgi = ROL64in128(A##ka, 3); \
    E##ga = XOR128(Bga, ANDnu128(Bge, Bgi)); \
    XOReq128(A##me, De); \
    Bgo = ROL64in128(A##me, 45); \
    E##ge = XOR128(Bge, ANDnu128(Bgi, Bgo)); \
    XOReq128(A##si, Di); \
    Bgu = ROL64in128(A##si, 61); \
    E##gi = XOR128(Bgi, ANDnu128(Bgo, Bgu)); \
    E##go = XOR128(Bgo, ANDnu128(Bgu, Bga)); \
    E##gu = XOR128(Bgu, ANDnu128(Bga, Bge)); \
\
    XOReq128(A##be, De); \
    Bka = ROL64in128(A##be, 1); \
    XOReq128(A##gi, Di); \
    Bke = ROL64in128(A##gi, 6); \
    XOReq128(A##ko, Do); \
    Bki = ROL64in128(A##ko, 25); \
    E##ka = XOR128(Bka, ANDnu128(Bke, Bki)); \
    XOReq128(A##mu, Du); \
    Bko = ROL64in128_8(A##mu); \
    E##ke = XOR128(Bke, ANDnu128(Bki, Bko)); \
    XOReq128(A##sa, Da); \
    Bku = ROL64in128(A##sa, 18); \
    E##ki = XOR128(Bki, ANDnu128(Bko, Bku)); \
    E##ko = XOR128(Bko, ANDnu128(Bku, Bka)); \
    E##ku = XOR128(Bku, ANDnu128(Bka, Bke)); \
\
    XOReq128(A##bu, Du); \
    Bma = ROL64in128(A##bu, 27); \
    XOReq128(A##ga, Da); \
    Bme = ROL64in128(A##ga, 36); \
    XOReq128(A##ke, De); \
    Bmi = ROL64in128(A##ke, 10); \
    E##ma = XOR128(Bma, ANDnu128(Bme, Bmi)); \
    XOReq128(A##mi, Di); \
    Bmo = ROL64in128(A##mi, 15); \
    E##me = XOR128(Bme, ANDnu128(Bmi, Bmo)); \
    XOReq128(A##so, Do); \
    Bmu = ROL64in128_56(A##so); \
    E##mi = XOR128(Bmi, ANDnu128(Bmo, Bmu)); \
    E##mo = XOR128(Bmo, ANDnu128(Bmu, Bma)); \
    E##mu = XOR128(Bmu, ANDnu128(Bma, Bme)); \
\
    XOReq128(A##bi, Di); \
    Bsa = ROL64in128(A##bi, 62); \
    XOReq128(A##go, Do); \
    Bse = ROL64in128(A##go, 55); \
    XOReq128(A##ku, Du); \
    Bsi = ROL64in128(A##ku, 39); \
    E##sa = XOR128(Bsa, ANDnu128(Bse, Bsi)); \
    XOReq128(A##ma, Da); \
    Bso = ROL64in128(A##ma, 41); \
    E##se = XOR128(Bse, ANDnu128(Bsi, Bso)); \
    XOReq128(A##se, De); \
    Bsu = ROL64in128(A##se, 2); \
    E##si = XOR128(Bsi, ANDnu128(Bso, Bsu)); \
    E##so = XOR128(Bso, ANDnu128(Bsu, Bsa)); \
    E##su = XOR128(Bsu, ANDnu128(Bsa, Bse)); \
\

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
    0x8000000080008008ULL};

#define copyFromState(X, state) \
    X##ba = LOAD128(state[ 0]); \
    X##be = LOAD128(state[ 1]); \
    X##bi = LOAD128(state[ 2]); \
    X##bo = LOAD128(state[ 3]); \
    X##bu = LOAD128(state[ 4]); \
    X##ga = LOAD128(state[ 5]); \
    X##ge = LOAD128(state[ 6]); \
    X##gi = LOAD128(state[ 7]); \
    X##go = LOAD128(state[ 8]); \
    X##gu = LOAD128(state[ 9]); \
    X##ka = LOAD128(state[10]); \
    X##ke = LOAD128(state[11]); \
    X##ki = LOAD128(state[12]); \
    X##ko = LOAD128(state[13]); \
    X##ku = LOAD128(state[14]); \
    X##ma = LOAD128(state[15]); \
    X##me = LOAD128(state[16]); \
    X##mi = LOAD128(state[17]); \
    X##mo = LOAD128(state[18]); \
    X##mu = LOAD128(state[19]); \
    X##sa = LOAD128(state[20]); \
    X##se = LOAD128(state[21]); \
    X##si = LOAD128(state[22]); \
    X##so = LOAD128(state[23]); \
    X##su = LOAD128(state[24]); \

#define copyToState(state, X) \
    STORE128(state[ 0], X##ba); \
    STORE128(state[ 1], X##be); \
    STORE128(state[ 2], X##bi); \
    STORE128(state[ 3], X##bo); \
    STORE128(state[ 4], X##bu); \
    STORE128(state[ 5], X##ga); \
    STORE128(state[ 6], X##ge); \
    STORE128(state[ 7], X##gi); \
    STORE128(state[ 8], X##go); \
    STORE128(state[ 9], X##gu); \
    STORE128(state[10], X##ka); \
    STORE128(state[11], X##ke); \
    STORE128(state[12], X##ki); \
    STORE128(state[13], X##ko); \
    STORE128(state[14], X##ku); \
    STORE128(state[15], X##ma); \
    STORE128(state[16], X##me); \
    STORE128(state[17], X##mi); \
    STORE128(state[18], X##mo); \
    STORE128(state[19], X##mu); \
    STORE128(state[20], X##sa); \
    STORE128(state[21], X##se); \
    STORE128(state[22], X##si); \
    STORE128(state[23], X##so); \
    STORE128(state[24], X##su); \

#define copyStateVariables(X, Y) \
    X##ba = Y##ba; \
    X##be = Y##be; \
    X##bi = Y##bi; \
    X##bo = Y##bo; \
    X##bu = Y##bu; \
    X##ga = Y##ga; \
    X##ge = Y##ge; \
    X##gi = Y##gi; \
    X##go = Y##go; \
    X##gu = Y##gu; \
    X##ka = Y##ka; \
    X##ke = Y##ke; \
    X##ki = Y##ki; \
    X##ko = Y##ko; \
    X##ku = Y##ku; \
    X##ma = Y##ma; \
    X##me = Y##me; \
    X##mi = Y##mi; \
    X##mo = Y##mo; \
    X##mu = Y##mu; \
    X##sa = Y##sa; \
    X##se = Y##se; \
    X##si = Y##si; \
    X##so = Y##so; \
    X##su = Y##su; \

#ifdef KeccakP1600times2_SSSE3_fullUnrolling
#define FullUnrolling
#else
#define Unrolling KeccakP1600times2_SSSE3_unrolling
#endif
#include "KeccakP-1600-unrolling.macros"

void KeccakP1600times2_SSSE3_PermuteAll_24rounds(KeccakP1600times2_SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    declareABCDE
    #ifndef KeccakP1600times2_SSSE3_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(A, statesAsLanes)
    rounds24
    copyToState(statesAsLanes, A)
#if defined(UseMMX)
    _mm_empty();
#endif
}

void KeccakP1600times2_SSSE3_PermuteAll_12rounds(KeccakP1600times2_SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    declareABCDE
    #ifndef KeccakP1600times2_SSSE3_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(A, statesAsLanes)
    rounds12
    copyToState(statesAsLanes, A)
#if defined(UseMMX)
    _mm_empty();
#endif
}

void KeccakP1600times2_SSSE3_PermuteAll_6rounds(KeccakP1600times2_SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    declareABCDE
    #ifndef KeccakP1600times2_SSSE3_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(A, statesAsLanes)
    rounds6
    copyToState(statesAsLanes, A)
#if defined(UseMMX)
    _mm_empty();
#endif
}

void KeccakP1600times2_SSSE3_PermuteAll_4rounds(KeccakP1600times2_SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    declareABCDE
    #ifndef KeccakP1600times2_SSSE3_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(A, statesAsLanes)
    rounds4
    copyToState(statesAsLanes, A)
#if defined(UseMMX)
    _mm_empty();
#endif
}

size_t KeccakF1600times2_SSSE3_FastLoop_Absorb(KeccakP1600times2_SIMD128_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (laneCount == 21) {
#if 1
        const unsigned char *dataStart = data;

        while(dataByteLen >= (laneOffsetParallel + laneCount)*8) {
            V128 *stateAsLanes = states->A;
            const uint64_t *curData0 = (const uint64_t *)data;
            const uint64_t *curData1 = (const uint64_t *)(data+laneOffsetParallel*SnP_laneLengthInBytes);
            #define XOR_In( argIndex )  XOReq128( stateAsLanes[argIndex], LOAD6464(curData1[argIndex], curData0[argIndex]))
            XOR_In( 0 );
            XOR_In( 1 );
            XOR_In( 2 );
            XOR_In( 3 );
            XOR_In( 4 );
            XOR_In( 5 );
            XOR_In( 6 );
            XOR_In( 7 );
            XOR_In( 8 );
            XOR_In( 9 );
            XOR_In( 10 );
            XOR_In( 11 );
            XOR_In( 12 );
            XOR_In( 13 );
            XOR_In( 14 );
            XOR_In( 15 );
            XOR_In( 16 );
            XOR_In( 17 );
            XOR_In( 18 );
            XOR_In( 19 );
            XOR_In( 20 );
            #undef  XOR_In
            KeccakP1600times2_SSSE3_PermuteAll_24rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
#else
        unsigned int i;
        const unsigned char *dataStart = data;
        const uint64_t *curData0 = (const uint64_t *)data;
        const uint64_t *curData1 = (const uint64_t *)(data+laneOffsetParallel*SnP_laneLengthInBytes);
        V128 *statesAsLanes = states->A;
        declareABCDE

        copyFromState(A, statesAsLanes)
        while(dataByteLen >= (laneOffsetParallel + laneCount)*8) {
            #define XOR_In( Xxx, argIndex )  XOReq128( Xxx, LOAD6464(curData1[argIndex], curData0[argIndex]))
            XOR_In( Aba, 0 );
            XOR_In( Abe, 1 );
            XOR_In( Abi, 2 );
            XOR_In( Abo, 3 );
            XOR_In( Abu, 4 );
            XOR_In( Aga, 5 );
            XOR_In( Age, 6 );
            XOR_In( Agi, 7 );
            XOR_In( Ago, 8 );
            XOR_In( Agu, 9 );
            XOR_In( Aka, 10 );
            XOR_In( Ake, 11 );
            XOR_In( Aki, 12 );
            XOR_In( Ako, 13 );
            XOR_In( Aku, 14 );
            XOR_In( Ama, 15 );
            XOR_In( Ame, 16 );
            XOR_In( Ami, 17 );
            XOR_In( Amo, 18 );
            XOR_In( Amu, 19 );
            XOR_In( Asa, 20 );
            #undef XOR_In
            rounds24
            curData0 += laneOffsetSerial;
            curData1 += laneOffsetSerial;
            dataByteLen -= laneOffsetSerial*8;
        }
        copyToState(statesAsLanes, A)
        return (const unsigned char *)curData0 - dataStart;
#endif
    }
    else {
        const unsigned char *dataStart = data;

        while(dataByteLen >= (laneOffsetParallel + laneCount)*8) {
            KeccakP1600times2_SSSE3_AddLanesAll(states, data, laneCount, laneOffsetParallel);
            KeccakP1600times2_SSSE3_PermuteAll_24rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
    }
}

size_t KeccakP1600times2_12rounds_SSSE3_FastLoop_Absorb(KeccakP1600times2_SIMD128_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    if (laneCount == 21) {
        #if 1
        const unsigned char *dataStart = data;

        while(dataByteLen >= (laneOffsetParallel + laneCount)*8) {
            V128 *stateAsLanes = states->A;
            const uint64_t *curData0 = (const uint64_t *)data;
            const uint64_t *curData1 = (const uint64_t *)(data+laneOffsetParallel*SnP_laneLengthInBytes);
            #define XOR_In( argIndex )  XOReq128( stateAsLanes[argIndex], LOAD6464(curData1[argIndex], curData0[argIndex]))
            XOR_In( 0 );
            XOR_In( 1 );
            XOR_In( 2 );
            XOR_In( 3 );
            XOR_In( 4 );
            XOR_In( 5 );
            XOR_In( 6 );
            XOR_In( 7 );
            XOR_In( 8 );
            XOR_In( 9 );
            XOR_In( 10 );
            XOR_In( 11 );
            XOR_In( 12 );
            XOR_In( 13 );
            XOR_In( 14 );
            XOR_In( 15 );
            XOR_In( 16 );
            XOR_In( 17 );
            XOR_In( 18 );
            XOR_In( 19 );
            XOR_In( 20 );
            #undef  XOR_In
            KeccakP1600times2_SSSE3_PermuteAll_12rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
        #else
        unsigned int i;
        const unsigned char *dataStart = data;
        const uint64_t *curData0 = (const uint64_t *)data;
        const uint64_t *curData1 = (const uint64_t *)(data+laneOffsetParallel*SnP_laneLengthInBytes);
        V128 *statesAsLanes = states->A;
        declareABCDE

        copyFromState(A, statesAsLanes)
        while(dataByteLen >= (laneOffsetParallel + laneCount)*8) {
            #define XOR_In( Xxx, argIndex )  XOReq128( Xxx, LOAD6464(curData1[argIndex], curData0[argIndex]))
            XOR_In( Aba, 0 );
            XOR_In( Abe, 1 );
            XOR_In( Abi, 2 );
            XOR_In( Abo, 3 );
            XOR_In( Abu, 4 );
            XOR_In( Aga, 5 );
            XOR_In( Age, 6 );
            XOR_In( Agi, 7 );
            XOR_In( Ago, 8 );
            XOR_In( Agu, 9 );
            XOR_In( Aka, 10 );
            XOR_In( Ake, 11 );
            XOR_In( Aki, 12 );
            XOR_In( Ako, 13 );
            XOR_In( Aku, 14 );
            XOR_In( Ama, 15 );
            XOR_In( Ame, 16 );
            XOR_In( Ami, 17 );
            XOR_In( Amo, 18 );
            XOR_In( Amu, 19 );
            XOR_In( Asa, 20 );
            #undef XOR_In
            rounds12
            curData0 += laneOffsetSerial;
            curData1 += laneOffsetSerial;
            dataByteLen -= laneOffsetSerial*8;
        }
        copyToState(statesAsLanes, A)
        return (const unsigned char *)curData0 - dataStart;
        #endif
    }
    else {
        const unsigned char *dataStart = data;

        while(dataByteLen >= (laneOffsetParallel + laneCount)*8) {
            KeccakP1600times2_SSSE3_AddLanesAll(states, data, laneCount, laneOffsetParallel);
            KeccakP1600times2_SSSE3_PermuteAll_12rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
    }
}
