/*
The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include "align.h"
#include "KeccakP-1600-times2-AVX512.h"

#include "brg_endian.h"
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

typedef __m128i     V128;
typedef __m256i     V256;
typedef __m512i     V512;

#define XOR(a,b)                    _mm_xor_si128(a,b)
#define XOR3(a,b,c)                 _mm_ternarylogic_epi64(a,b,c,0x96)
#define XOR5(a,b,c,d,e)             XOR3(XOR3(a,b,c),d,e)
#define XOR512(a,b)                 _mm512_xor_si512(a,b)
#define ROL(a,offset)               _mm_rol_epi64(a,offset)
#define Chi(a,b,c)                  _mm_ternarylogic_epi64(a,b,c,0xD2)

#define CONST128_64(a)              _mm_set1_epi64x(a)
#define LOAD4_32(a,b,c,d)           _mm_set_epi32((uint64_t)(a), (uint32_t)(b), (uint32_t)(c), (uint32_t)(d))
#define LOAD8_32(a,b,c,d,e,f,g,h)   _mm256_set_epi32((uint64_t)(a), (uint32_t)(b), (uint32_t)(c), (uint32_t)(d), (uint32_t)(e), (uint32_t)(f), (uint32_t)(g), (uint32_t)(h))
#define LOAD_GATHER2_64(idx,p)      _mm_i32gather_epi64( (const long long int*)(p), idx, 8)
#define LOAD_GATHER8_64(idx,p)      _mm512_i32gather_epi64( idx, (const void*)(p), 8)
#define STORE_SCATTER2_64(p,idx, v) _mm_i32scatter_epi64( (void*)(p), idx, v, 8)
#define STORE_SCATTER8_64(p,idx, v) _mm512_i32scatter_epi64( (void*)(p), idx, v, 8)

#define laneIndex(instanceIndex, lanePosition)  ((lanePosition)*2 + instanceIndex)
#define SnP_laneLengthInBytes                   8

void KeccakP1600times2_AVX512_InitializeAll(KeccakP1600times2_align512SIMD128_states *states)
{
    memset(states, 0, sizeof(KeccakP1600times2_align512SIMD128_states));
}

void KeccakP1600times2_AVX512_AddBytes(KeccakP1600times2_align512SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curData = data;
    uint64_t *statesAsLanes = (uint64_t*)states->A;

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

void KeccakP1600times2_AVX512_AddLanesAll(KeccakP1600times2_align512SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes128 = states->A;
    V512 *stateAsLanes512 = (V512*)states->A;
    const uint64_t *dataAsLanes = (const uint64_t *)data;
    unsigned int i;
    V128 index128 = LOAD4_32(0, 0, 1*laneOffset, 0*laneOffset);
    V256 index512 = LOAD8_32(1*laneOffset+3, 0*laneOffset+3, 1*laneOffset+2, 0*laneOffset+2, 1*laneOffset+1, 0*laneOffset+1, 1*laneOffset, 0*laneOffset);

    #define Add_In1( argIndex )  stateAsLanes128[argIndex] = XOR(stateAsLanes128[argIndex], LOAD_GATHER2_64(index128, dataAsLanes+argIndex))
    #define Add_In4( argIndex )  stateAsLanes512[argIndex/4] = XOR512(stateAsLanes512[argIndex/4], LOAD_GATHER8_64(index512, dataAsLanes+argIndex))
    if ( laneCount >= 16 )  {
        Add_In4( 0 );
        Add_In4( 4 );
        Add_In4( 8 );
        Add_In4( 12 );
        if ( laneCount >= 20 )  {
            Add_In4( 16 );
            for(i=20; i<laneCount; i++)
                Add_In1( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                Add_In1( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            Add_In1( i );
    }
    #undef  Add_In1
    #undef  Add_In4
}

void KeccakP1600times2_AVX512_OverwriteBytes(KeccakP1600times2_align512SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curData = data;
    uint64_t *statesAsLanes = (uint64_t*)states->A;

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

void KeccakP1600times2_AVX512_OverwriteLanesAll(KeccakP1600times2_align512SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes128 = states->A;
    V512 *stateAsLanes512 = (V512*)states->A;
    const uint64_t *dataAsLanes = (const uint64_t *)data;
    unsigned int i;
    V128 index128 = LOAD4_32(0, 0, 1*laneOffset, 0*laneOffset);
    V256 index512 = LOAD8_32(1*laneOffset+3, 0*laneOffset+3, 1*laneOffset+2, 0*laneOffset+2, 1*laneOffset+1, 0*laneOffset+1, 1*laneOffset, 0*laneOffset);

    #define OverWr1( argIndex )  stateAsLanes128[argIndex] = LOAD_GATHER2_64(index128, dataAsLanes+argIndex)
    #define OverWr4( argIndex )  stateAsLanes512[argIndex/4] = LOAD_GATHER8_64(index512, dataAsLanes+argIndex)
    if ( laneCount >= 16 )  {
        OverWr4( 0 );
        OverWr4( 4 );
        OverWr4( 8 );
        OverWr4( 12 );
        if ( laneCount >= 20 )  {
            OverWr4( 16 );
            for(i=20; i<laneCount; i++)
                OverWr1( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                OverWr1( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            OverWr1( i );
    }
    #undef  OverWr1
    #undef  OverWr4
}

void KeccakP1600times2_AVX512_OverwriteWithZeroes(KeccakP1600times2_align512SIMD128_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    unsigned int sizeLeft = byteCount;
    unsigned int lanePosition = 0;
    uint64_t *statesAsLanes = (uint64_t*)states->A;

    while(sizeLeft >= SnP_laneLengthInBytes) {
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] = 0;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
    }

    if (sizeLeft > 0) {
        memset(&statesAsLanes[laneIndex(instanceIndex, lanePosition)], 0, sizeLeft);
    }
}

void KeccakP1600times2_AVX512_ExtractBytes(const KeccakP1600times2_align512SIMD128_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    unsigned char *curData = data;
    const uint64_t *statesAsLanes = (const uint64_t*)states->A;

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

void KeccakP1600times2_AVX512_ExtractLanesAll(const KeccakP1600times2_align512SIMD128_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    const V128 *stateAsLanes128 = states->A;
    const V512 *stateAsLanes512 = (V512*)states->A;
    uint64_t *dataAsLanes = (uint64_t *)data;
    unsigned int i;
    V128 index128 = LOAD4_32(0, 0, 1*laneOffset, 0*laneOffset);
    V256 index512 = LOAD8_32(1*laneOffset+3, 0*laneOffset+3, 1*laneOffset+2, 0*laneOffset+2, 1*laneOffset+1, 0*laneOffset+1, 1*laneOffset, 0*laneOffset);

    #define Extr1( argIndex )  STORE_SCATTER2_64(dataAsLanes+argIndex, index128, stateAsLanes128[argIndex])
    #define Extr4( argIndex )  STORE_SCATTER8_64(dataAsLanes+argIndex, index512, stateAsLanes512[argIndex/4])
    if ( laneCount >= 16 )  {
        Extr4( 0 );
        Extr4( 4 );
        Extr4( 8 );
        Extr4( 12 );
        if ( laneCount >= 20 )  {
            Extr4( 16 );
            for(i=20; i<laneCount; i++)
                Extr1( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                Extr1( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            Extr1( i );
    }
    #undef  Extr1
    #undef  Extr4
}

void KeccakP1600times2_AVX512_ExtractAndAddBytes(const KeccakP1600times2_align512SIMD128_states *states, unsigned int instanceIndex, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curInput = input;
    unsigned char *curOutput = output;
    const uint64_t *statesAsLanes = (const uint64_t*)states->A;

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

void KeccakP1600times2_AVX512_ExtractAndAddLanesAll(const KeccakP1600times2_align512SIMD128_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    const V128 *stateAsLanes128 = states->A;
    const V512 *stateAsLanes512 = (V512*)states->A;
    const uint64_t *inAsLanes = (const uint64_t *)input;
    uint64_t *outAsLanes = (uint64_t *)output;
    unsigned int i;
    V128 index128 = LOAD4_32(0, 0, 1*laneOffset, 0*laneOffset);
    V256 index512 = LOAD8_32(1*laneOffset+3, 0*laneOffset+3, 1*laneOffset+2, 0*laneOffset+2, 1*laneOffset+1, 0*laneOffset+1, 1*laneOffset, 0*laneOffset);

    #define ExtrAdd1( argIndex )  STORE_SCATTER2_64(outAsLanes+argIndex, index128, XOR(stateAsLanes128[argIndex], LOAD_GATHER2_64(index128, inAsLanes+argIndex)))
    #define ExtrAdd4( argIndex )  STORE_SCATTER8_64(outAsLanes+argIndex, index512, XOR512(stateAsLanes512[argIndex/4], LOAD_GATHER8_64(index512, inAsLanes+argIndex)))
    if ( laneCount >= 16 )  {
        ExtrAdd4( 0 );
        ExtrAdd4( 4 );
        ExtrAdd4( 8 );
        ExtrAdd4( 12 );
        if ( laneCount >= 20 )  {
            ExtrAdd4( 16 );
            for(i=20; i<laneCount; i++)
                ExtrAdd1( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                ExtrAdd1( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            ExtrAdd1( i );
    }
    #undef  ExtrAdd1
    #undef  ExtrAdd4

}

static ALIGN(64) const uint64_t KeccakP1600RoundConstants[24] = {
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

#define KeccakP_DeclareVars \
    V128    _Ba, _Be, _Bi, _Bo, _Bu; \
    V128    _Da, _De, _Di, _Do, _Du; \
    V128    _ba, _be, _bi, _bo, _bu; \
    V128    _ga, _ge, _gi, _go, _gu; \
    V128    _ka, _ke, _ki, _ko, _ku; \
    V128    _ma, _me, _mi, _mo, _mu; \
    V128    _sa, _se, _si, _so, _su

#define KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bb1, _Bb2, _Bb3, _Bb4, _Bb5, _Rr1, _Rr2, _Rr3, _Rr4, _Rr5 ) \
    _Bb1 = XOR(_L1, _Da); \
    _Bb2 = XOR(_L2, _De); \
    _Bb3 = XOR(_L3, _Di); \
    _Bb4 = XOR(_L4, _Do); \
    _Bb5 = XOR(_L5, _Du); \
    if (_Rr1 != 0) _Bb1 = ROL(_Bb1, _Rr1); \
    _Bb2 = ROL(_Bb2, _Rr2); \
    _Bb3 = ROL(_Bb3, _Rr3); \
    _Bb4 = ROL(_Bb4, _Rr4); \
    _Bb5 = ROL(_Bb5, _Rr5); \
    _L1 = Chi( _Ba, _Be, _Bi); \
    _L2 = Chi( _Be, _Bi, _Bo); \
    _L3 = Chi( _Bi, _Bo, _Bu); \
    _L4 = Chi( _Bo, _Bu, _Ba); \
    _L5 = Chi( _Bu, _Ba, _Be);

#define KeccakP_ThetaRhoPiChiIota0( _L1, _L2, _L3, _L4, _L5, _rc ) \
    _Ba = XOR5( _ba, _ga, _ka, _ma, _sa ); /* Theta effect */ \
    _Be = XOR5( _be, _ge, _ke, _me, _se ); \
    _Bi = XOR5( _bi, _gi, _ki, _mi, _si ); \
    _Bo = XOR5( _bo, _go, _ko, _mo, _so ); \
    _Bu = XOR5( _bu, _gu, _ku, _mu, _su ); \
    _Da = ROL( _Be, 1 ); \
    _De = ROL( _Bi, 1 ); \
    _Di = ROL( _Bo, 1 ); \
    _Do = ROL( _Bu, 1 ); \
    _Du = ROL( _Ba, 1 ); \
    _Da = XOR( _Da, _Bu ); \
    _De = XOR( _De, _Ba ); \
    _Di = XOR( _Di, _Be ); \
    _Do = XOR( _Do, _Bi ); \
    _Du = XOR( _Du, _Bo ); \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Ba, _Be, _Bi, _Bo, _Bu,  0, 44, 43, 21, 14 ); \
    _L1 = XOR(_L1, _rc) /* Iota */

#define KeccakP_ThetaRhoPiChi1( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bi, _Bo, _Bu, _Ba, _Be,  3, 45, 61, 28, 20 )

#define KeccakP_ThetaRhoPiChi2( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bu, _Ba, _Be, _Bi, _Bo, 18,  1,  6, 25,  8 )

#define KeccakP_ThetaRhoPiChi3( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Be, _Bi, _Bo, _Bu, _Ba, 36, 10, 15, 56, 27 )

#define KeccakP_ThetaRhoPiChi4( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bo, _Bu, _Ba, _Be, _Bi, 41,  2, 62, 55, 39 )

#define KeccakP_4rounds( i ) \
    KeccakP_ThetaRhoPiChiIota0(_ba, _ge, _ki, _mo, _su, CONST128_64(KeccakP1600RoundConstants[i]) ); \
    KeccakP_ThetaRhoPiChi1(    _ka, _me, _si, _bo, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _sa, _be, _gi, _ko, _mu ); \
    KeccakP_ThetaRhoPiChi3(    _ga, _ke, _mi, _so, _bu ); \
    KeccakP_ThetaRhoPiChi4(    _ma, _se, _bi, _go, _ku ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _me, _gi, _so, _ku, CONST128_64(KeccakP1600RoundConstants[i+1]) ); \
    KeccakP_ThetaRhoPiChi1(    _sa, _ke, _bi, _mo, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ma, _ge, _si, _ko, _bu ); \
    KeccakP_ThetaRhoPiChi3(    _ka, _be, _mi, _go, _su ); \
    KeccakP_ThetaRhoPiChi4(    _ga, _se, _ki, _bo, _mu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _ke, _si, _go, _mu, CONST128_64(KeccakP1600RoundConstants[i+2]) ); \
    KeccakP_ThetaRhoPiChi1(    _ma, _be, _ki, _so, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ga, _me, _bi, _ko, _su ); \
    KeccakP_ThetaRhoPiChi3(    _sa, _ge, _mi, _bo, _ku ); \
    KeccakP_ThetaRhoPiChi4(    _ka, _se, _gi, _mo, _bu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _be, _bi, _bo, _bu, CONST128_64(KeccakP1600RoundConstants[i+3]) ); \
    KeccakP_ThetaRhoPiChi1(    _ga, _ge, _gi, _go, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ka, _ke, _ki, _ko, _ku ); \
    KeccakP_ThetaRhoPiChi3(    _ma, _me, _mi, _mo, _mu ); \
    KeccakP_ThetaRhoPiChi4(    _sa, _se, _si, _so, _su )

#define KeccakP_2rounds( i ) \
    KeccakP_ThetaRhoPiChiIota0(_ba, _ke, _si, _go, _mu, CONST128_64(KeccakP1600RoundConstants[i]) ); \
    KeccakP_ThetaRhoPiChi1(    _ma, _be, _ki, _so, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ga, _me, _bi, _ko, _su ); \
    KeccakP_ThetaRhoPiChi3(    _sa, _ge, _mi, _bo, _ku ); \
    KeccakP_ThetaRhoPiChi4(    _ka, _se, _gi, _mo, _bu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _be, _bi, _bo, _bu, CONST128_64(KeccakP1600RoundConstants[i+1]) ); \
    KeccakP_ThetaRhoPiChi1(    _ga, _ge, _gi, _go, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ka, _ke, _ki, _ko, _ku ); \
    KeccakP_ThetaRhoPiChi3(    _ma, _me, _mi, _mo, _mu ); \
    KeccakP_ThetaRhoPiChi4(    _sa, _se, _si, _so, _su )

#ifdef KeccakP1600times2_AVX512_fullUnrolling

#define rounds12 \
    KeccakP_4rounds( 12 ); \
    KeccakP_4rounds( 16 ); \
    KeccakP_4rounds( 20 )

#define rounds24 \
    KeccakP_4rounds( 0 ); \
    KeccakP_4rounds( 4 ); \
    KeccakP_4rounds( 8 ); \
    KeccakP_4rounds( 12 ); \
    KeccakP_4rounds( 16 ); \
    KeccakP_4rounds( 20 )

#elif (KeccakP1600times2_AVX512_unrolling == 4)

#define rounds12 \
    i = 12; \
    do { \
        KeccakP_4rounds( i ); \
    } while( (i += 4) < 24 )

#define rounds24 \
    i = 0; \
    do { \
        KeccakP_4rounds( i ); \
    } while( (i += 4) < 24 )

#elif (KeccakP1600times2_AVX512_unrolling == 12)

#define rounds12 \
    KeccakP_4rounds( 12 ); \
    KeccakP_4rounds( 16 ); \
    KeccakP_4rounds( 20 )

#define rounds24 \
    i = 0; \
    do { \
        KeccakP_4rounds( i ); \
        KeccakP_4rounds( i+4 ); \
        KeccakP_4rounds( i+8 ); \
    } while( (i += 12) < 24 )

#else
#error "Unrolling is not correctly specified!"
#endif

#define copyFromState2rounds(pState) \
    _ba = pState[ 0]; \
    _be = pState[16]; /* me */ \
    _bi = pState[ 7]; /* gi */ \
    _bo = pState[23]; /* so */ \
    _bu = pState[14]; /* ku */ \
    _ga = pState[20]; /* sa */ \
    _ge = pState[11]; /* ke */ \
    _gi = pState[ 2]; /* bi */ \
    _go = pState[18]; /* mo */ \
    _gu = pState[ 9]; \
    _ka = pState[15]; /* ma */ \
    _ke = pState[ 6]; /* ge */ \
    _ki = pState[22]; /* si */ \
    _ko = pState[13]; \
    _ku = pState[ 4]; /* bu */ \
    _ma = pState[10]; /* ka */ \
    _me = pState[ 1]; /* be */ \
    _mi = pState[17]; \
    _mo = pState[ 8]; /* go */ \
    _mu = pState[24]; /* su */ \
    _sa = pState[ 5]; /* ga */ \
    _se = pState[21]; \
    _si = pState[12]; /* ki */ \
    _so = pState[ 3]; /* bo */ \
    _su = pState[19]  /* mu */

#define copyFromState(pState) \
    _ba = pState[ 0]; \
    _be = pState[ 1]; \
    _bi = pState[ 2]; \
    _bo = pState[ 3]; \
    _bu = pState[ 4]; \
    _ga = pState[ 5]; \
    _ge = pState[ 6]; \
    _gi = pState[ 7]; \
    _go = pState[ 8]; \
    _gu = pState[ 9]; \
    _ka = pState[10]; \
    _ke = pState[11]; \
    _ki = pState[12]; \
    _ko = pState[13]; \
    _ku = pState[14]; \
    _ma = pState[15]; \
    _me = pState[16]; \
    _mi = pState[17]; \
    _mo = pState[18]; \
    _mu = pState[19]; \
    _sa = pState[20]; \
    _se = pState[21]; \
    _si = pState[22]; \
    _so = pState[23]; \
    _su = pState[24]

#define copyToState(pState) \
    pState[ 0] = _ba; \
    pState[ 1] = _be; \
    pState[ 2] = _bi; \
    pState[ 3] = _bo; \
    pState[ 4] = _bu; \
    pState[ 5] = _ga; \
    pState[ 6] = _ge; \
    pState[ 7] = _gi; \
    pState[ 8] = _go; \
    pState[ 9] = _gu; \
    pState[10] = _ka; \
    pState[11] = _ke; \
    pState[12] = _ki; \
    pState[13] = _ko; \
    pState[14] = _ku; \
    pState[15] = _ma; \
    pState[16] = _me; \
    pState[17] = _mi; \
    pState[18] = _mo; \
    pState[19] = _mu; \
    pState[20] = _sa; \
    pState[21] = _se; \
    pState[22] = _si; \
    pState[23] = _so; \
    pState[24] = _su

void KeccakP1600times2_AVX512_PermuteAll_24rounds(KeccakP1600times2_align512SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    KeccakP_DeclareVars;
    #ifndef KeccakP1600times2_AVX512_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(statesAsLanes);
    rounds24;
    copyToState(statesAsLanes);
}

void KeccakP1600times2_AVX512_PermuteAll_12rounds(KeccakP1600times2_align512SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    KeccakP_DeclareVars;
    #if (KeccakP1600times2_AVX512_unrolling < 12)
    unsigned int i;
    #endif

    copyFromState(statesAsLanes);
    rounds12;
    copyToState(statesAsLanes);
}

void KeccakP1600times2_AVX512_PermuteAll_6rounds(KeccakP1600times2_align512SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    KeccakP_DeclareVars;

    copyFromState2rounds(statesAsLanes);
    KeccakP_2rounds( 18 );
    KeccakP_4rounds( 20 );
    copyToState(statesAsLanes);
}

void KeccakP1600times2_AVX512_PermuteAll_4rounds(KeccakP1600times2_align512SIMD128_states *states)
{
    V128 *statesAsLanes = states->A;
    KeccakP_DeclareVars;

    copyFromState(statesAsLanes);
    KeccakP_4rounds( 20 );
    copyToState(statesAsLanes);
}

size_t KeccakF1600times2_AVX512_FastLoop_Absorb(KeccakP1600times2_align512SIMD128_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    size_t dataMinimumSize = (laneOffsetParallel*1 + laneCount)*8;

    if (laneCount == 21) {
        #ifndef KeccakP1600times2_AVX512_fullUnrolling
        unsigned int i;
        #endif
        const unsigned char *dataStart = data;
        V128 *statesAsLanes = states->A;
        const uint64_t *dataAsLanes = (const uint64_t *)data;
        KeccakP_DeclareVars;
	    V128 index = LOAD4_32(0, 0, 1*laneOffsetParallel, 0*laneOffsetParallel);

        copyFromState(statesAsLanes);
        while(dataByteLen >= dataMinimumSize) {
            #define Add_In( argLane, argIndex )  argLane = XOR(argLane, LOAD_GATHER2_64(index, dataAsLanes+argIndex))
            Add_In( _ba, 0 );
            Add_In( _be, 1 );
            Add_In( _bi, 2 );
            Add_In( _bo, 3 );
            Add_In( _bu, 4 );
            Add_In( _ga, 5 );
            Add_In( _ge, 6 );
            Add_In( _gi, 7 );
            Add_In( _go, 8 );
            Add_In( _gu, 9 );
            Add_In( _ka, 10 );
            Add_In( _ke, 11 );
            Add_In( _ki, 12 );
            Add_In( _ko, 13 );
            Add_In( _ku, 14 );
            Add_In( _ma, 15 );
            Add_In( _me, 16 );
            Add_In( _mi, 17 );
            Add_In( _mo, 18 );
            Add_In( _mu, 19 );
            Add_In( _sa, 20 );
            #undef  Add_In
            rounds24;
            dataAsLanes += laneOffsetSerial;
            dataByteLen -= laneOffsetSerial*8;
        }
        copyToState(statesAsLanes);
        return (const unsigned char *)dataAsLanes - dataStart;
    }
    else {
        const unsigned char *dataStart = data;

        while(dataByteLen >= dataMinimumSize) {
            KeccakP1600times2_AVX512_AddLanesAll(states, data, laneCount, laneOffsetParallel);
            KeccakP1600times2_AVX512_PermuteAll_24rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
    }
}

size_t KeccakP1600times2_12rounds_AVX512_FastLoop_Absorb(KeccakP1600times2_align512SIMD128_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    size_t dataMinimumSize = (laneOffsetParallel*1 + laneCount)*8;

    if (laneCount == 21) {
        #if (KeccakP1600times2_AVX512_unrolling < 12)
        unsigned int i;
        #endif
        const unsigned char *dataStart = data;
        V128 *statesAsLanes = states->A;
        const uint64_t *dataAsLanes = (const uint64_t *)data;
        KeccakP_DeclareVars;
	    V128 index = LOAD4_32(0, 0, 1*laneOffsetParallel, 0*laneOffsetParallel);

        copyFromState(statesAsLanes);
        while(dataByteLen >= dataMinimumSize) {
            #define Add_In( argLane, argIndex )  argLane = XOR(argLane, LOAD_GATHER2_64(index, dataAsLanes+argIndex))
            Add_In( _ba, 0 );
            Add_In( _be, 1 );
            Add_In( _bi, 2 );
            Add_In( _bo, 3 );
            Add_In( _bu, 4 );
            Add_In( _ga, 5 );
            Add_In( _ge, 6 );
            Add_In( _gi, 7 );
            Add_In( _go, 8 );
            Add_In( _gu, 9 );
            Add_In( _ka, 10 );
            Add_In( _ke, 11 );
            Add_In( _ki, 12 );
            Add_In( _ko, 13 );
            Add_In( _ku, 14 );
            Add_In( _ma, 15 );
            Add_In( _me, 16 );
            Add_In( _mi, 17 );
            Add_In( _mo, 18 );
            Add_In( _mu, 19 );
            Add_In( _sa, 20 );
            #undef  Add_In
            rounds12;
            dataAsLanes += laneOffsetSerial;
            dataByteLen -= laneOffsetSerial*8;
        }
        copyToState(statesAsLanes);
        return (const unsigned char *)dataAsLanes - dataStart;
    }
    else {
        const unsigned char *dataStart = data;

        while(dataByteLen >= dataMinimumSize) {
            KeccakP1600times2_AVX512_AddLanesAll(states, data, laneCount, laneOffsetParallel);
            KeccakP1600times2_AVX512_PermuteAll_12rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
    }
}
