/*
The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements Keccak-p[1600]×8 in a PlSnP-compatible way.
Please refer to PlSnP-documentation.h for more details.

This implementation comes with KeccakP-1600-times8-SnP.h in the same folder.
Please refer to LowLevel.build for the exact list of other files it must be combined with.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include "align.h"
#include "KeccakP-1600-times8-AVX512.h"

#include "brg_endian.h"
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

#define    VERBOSE        0

typedef __m128i     V128;
typedef __m256i     V256;

#define XOR(a,b)                    _mm512_xor_si512(a,b)
#define XOR3(a,b,c)                 _mm512_ternarylogic_epi64(a,b,c,0x96)
#define XOR5(a,b,c,d,e)             XOR3(XOR3(a,b,c),d,e)
#define XOReq512(a, b)              a = XOR(a,b)

#define ROL(a,offset)               _mm512_rol_epi64(a,offset)
#define Chi(a,b,c)                  _mm512_ternarylogic_epi64(a,b,c,0xD2)

#define CONST8_64(a)                _mm512_set1_epi64(a)

#define LOAD512(a)                  _mm512_load_si512((const V512 *)&(a))
#define LOAD512u(a)                 _mm512_loadu_si512((const V512 *)&(a))
#define LOAD8_32(a,b,c,d,e,f,g,h)   _mm256_set_epi32((uint64_t)(a), (uint32_t)(b), (uint32_t)(c), (uint32_t)(d), (uint32_t)(e), (uint32_t)(f), (uint32_t)(g), (uint32_t)(h))
#define LOAD8_64(a,b,c,d,e,f,g,h)   _mm512_set_epi64((uint64_t)(a), (uint64_t)(b), (uint64_t)(c), (uint64_t)(d), (uint64_t)(e), (uint64_t)(f), (uint64_t)(g), (uint64_t)(h))
#define LOAD_GATHER8_64(idx,p)      _mm512_i32gather_epi64( idx, (const void*)(p), 8)

#define STORE_SCATTER8_64(p,idx, v) _mm512_i32scatter_epi64( (void*)(p), idx, v, 8)

#if (VERBOSE > 0)
    #define     DumpMem(__t, buf, __n) { \
                                        uint32_t i; \
                                        printf("%s ", __t); \
                                        for (i = 0; i < __n; ++i) { \
                                            printf("%016lx ", (buf)[i]); \
                                            /*if ((i%5) == 4) printf("\n"); */\
                                        } \
                                            printf("\n"); \
                                        }

    #define     DumpOne(__v,__i) {  \
                                    uint64_t    buf[8];    \
                                    _mm512_storeu_si512((V512*)buf, __v##__i); \
                                    printf("%016lx %016lx %016lx %016lx %016lx %016lx %016lx %016lx\n", \
                                      buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                }

    #define     Dump(__t,__v)    {                  \
                            printf("%s\n", __t);    \
                            DumpOne(__v, ba);  \
                            DumpOne(__v, be);  \
                            DumpOne(__v, bi);  \
                            DumpOne(__v, bo);  \
                            DumpOne(__v, bu);  \
                            DumpOne(__v, ga);  \
                            DumpOne(__v, ge);  \
                            DumpOne(__v, gi);  \
                            DumpOne(__v, go);  \
                            DumpOne(__v, gu);  \
                            DumpOne(__v, ka);  \
                            DumpOne(__v, ke);  \
                            DumpOne(__v, ki);  \
                            DumpOne(__v, ko);  \
                            DumpOne(__v, ku);  \
                            DumpOne(__v, ma);  \
                            DumpOne(__v, me);  \
                            DumpOne(__v, mi);  \
                            DumpOne(__v, mo);  \
                            DumpOne(__v, mu);  \
                            DumpOne(__v, sa);  \
                            DumpOne(__v, se);  \
                            DumpOne(__v, si);  \
                            DumpOne(__v, so);  \
                            DumpOne(__v, su);  \
                            printf("\n");      \
                        }

    #define     DumpReg(__t,__v,__i)  printf("%s ", __t); DumpOne(__v,__i)

#else
    #define     DumpMem(__t, buf,len)
    #define     DumpOne(__v,__i)
    #define     Dump(__t,__v)
    #define     DumpReg(__t,__v,__i)
#endif


#define laneIndex(instanceIndex, lanePosition)  ((lanePosition)*8 + instanceIndex)
#define SnP_laneLengthInBytes                   8

void KeccakP1600times8_AVX512_InitializeAll(KeccakP1600times8_SIMD512_states *states)
{
    memset(states, 0, sizeof(KeccakP1600times8_SIMD512_states));
}

void KeccakP1600times8_AVX512_AddBytes(KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
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

void KeccakP1600times8_AVX512_AddLanesAll(KeccakP1600times8_SIMD512_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V512 *stateAsLanes = states->A;
    const uint64_t *dataAsLanes = (const uint64_t *)data;
    unsigned int i;
    V256 index;

    #define Add_In( argIndex )  stateAsLanes[argIndex] = XOR(stateAsLanes[argIndex], LOAD_GATHER8_64(index, dataAsLanes+argIndex))
    index = LOAD8_32(7*laneOffset, 6*laneOffset, 5*laneOffset, 4*laneOffset, 3*laneOffset, 2*laneOffset, 1*laneOffset, 0*laneOffset);
    if ( laneCount >= 16 )  {
        Add_In( 0 );
        Add_In( 1 );
        Add_In( 2 );
        Add_In( 3 );
        Add_In( 4 );
        Add_In( 5 );
        Add_In( 6 );
        Add_In( 7 );
        Add_In( 8 );
        Add_In( 9 );
        Add_In( 10 );
        Add_In( 11 );
        Add_In( 12 );
        Add_In( 13 );
        Add_In( 14 );
        Add_In( 15 );
        if ( laneCount >= 20 )  {
            Add_In( 16 );
            Add_In( 17 );
            Add_In( 18 );
            Add_In( 19 );
            for(i=20; i<laneCount; i++)
                Add_In( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                Add_In( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            Add_In( i );
    }
    #undef  Add_In
}

void KeccakP1600times8_AVX512_OverwriteBytes(KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
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

void KeccakP1600times8_AVX512_OverwriteLanesAll(KeccakP1600times8_SIMD512_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V512 *stateAsLanes = states->A;
    const uint64_t *dataAsLanes = (const uint64_t *)data;
    unsigned int i;
    V256 index;

    #define OverWr( argIndex )  stateAsLanes[argIndex] = LOAD_GATHER8_64(index, dataAsLanes+argIndex)
    index = LOAD8_32(7*laneOffset, 6*laneOffset, 5*laneOffset, 4*laneOffset, 3*laneOffset, 2*laneOffset, 1*laneOffset, 0*laneOffset);
    if ( laneCount >= 16 )  {
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
        if ( laneCount >= 20 )  {
            OverWr( 16 );
            OverWr( 17 );
            OverWr( 18 );
            OverWr( 19 );
            for(i=20; i<laneCount; i++)
                OverWr( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                OverWr( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            OverWr( i );
    }
    #undef  OverWr
}

void KeccakP1600times8_AVX512_OverwriteWithZeroes(KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, unsigned int byteCount)
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

void KeccakP1600times8_AVX512_ExtractBytes(const KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
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

void KeccakP1600times8_AVX512_ExtractLanesAll(const KeccakP1600times8_SIMD512_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    const V512 *stateAsLanes = states->A;
    uint64_t *dataAsLanes = (uint64_t *)data;
    unsigned int i;
    V256 index;

    #define Extr( argIndex )  STORE_SCATTER8_64(dataAsLanes+argIndex, index, stateAsLanes[argIndex])
    index = LOAD8_32(7*laneOffset, 6*laneOffset, 5*laneOffset, 4*laneOffset, 3*laneOffset, 2*laneOffset, 1*laneOffset, 0*laneOffset);
    if ( laneCount >= 16 )  {
        Extr( 0 );
        Extr( 1 );
        Extr( 2 );
        Extr( 3 );
        Extr( 4 );
        Extr( 5 );
        Extr( 6 );
        Extr( 7 );
        Extr( 8 );
        Extr( 9 );
        Extr( 10 );
        Extr( 11 );
        Extr( 12 );
        Extr( 13 );
        Extr( 14 );
        Extr( 15 );
        if ( laneCount >= 20 )  {
            Extr( 16 );
            Extr( 17 );
            Extr( 18 );
            Extr( 19 );
            for(i=20; i<laneCount; i++)
                Extr( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                Extr( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            Extr( i );
    }
    #undef  Extr
}

void KeccakP1600times8_AVX512_ExtractAndAddBytes(const KeccakP1600times8_SIMD512_states *states, unsigned int instanceIndex, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
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

void KeccakP1600times8_AVX512_ExtractAndAddLanesAll(const KeccakP1600times8_SIMD512_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    const V512 *stateAsLanes = states->A;
    const uint64_t *inAsLanes = (const uint64_t *)input;
    uint64_t *outAsLanes = (uint64_t *)output;
    unsigned int i;
    V256 index;

    #define ExtrAdd( argIndex )  STORE_SCATTER8_64(outAsLanes+argIndex, index, XOR(stateAsLanes[argIndex], LOAD_GATHER8_64(index, inAsLanes+argIndex)))
    index = LOAD8_32(7*laneOffset, 6*laneOffset, 5*laneOffset, 4*laneOffset, 3*laneOffset, 2*laneOffset, 1*laneOffset, 0*laneOffset);
    if ( laneCount >= 16 )  {
        ExtrAdd( 0 );
        ExtrAdd( 1 );
        ExtrAdd( 2 );
        ExtrAdd( 3 );
        ExtrAdd( 4 );
        ExtrAdd( 5 );
        ExtrAdd( 6 );
        ExtrAdd( 7 );
        ExtrAdd( 8 );
        ExtrAdd( 9 );
        ExtrAdd( 10 );
        ExtrAdd( 11 );
        ExtrAdd( 12 );
        ExtrAdd( 13 );
        ExtrAdd( 14 );
        ExtrAdd( 15 );
        if ( laneCount >= 20 )  {
            ExtrAdd( 16 );
            ExtrAdd( 17 );
            ExtrAdd( 18 );
            ExtrAdd( 19 );
            for(i=20; i<laneCount; i++)
                ExtrAdd( i );
        }
        else {
            for(i=16; i<laneCount; i++)
                ExtrAdd( i );
        }
    }
    else {
        for(i=0; i<laneCount; i++)
            ExtrAdd( i );
    }
    #undef  ExtrAdd

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
    V512    _Ba, _Be, _Bi, _Bo, _Bu; \
    V512    _Da, _De, _Di, _Do, _Du; \
    V512    _ba, _be, _bi, _bo, _bu; \
    V512    _ga, _ge, _gi, _go, _gu; \
    V512    _ka, _ke, _ki, _ko, _ku; \
    V512    _ma, _me, _mi, _mo, _mu; \
    V512    _sa, _se, _si, _so, _su

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
    KeccakP_ThetaRhoPiChiIota0(_ba, _ge, _ki, _mo, _su, CONST8_64(KeccakP1600RoundConstants[i]) ); \
    KeccakP_ThetaRhoPiChi1(    _ka, _me, _si, _bo, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _sa, _be, _gi, _ko, _mu ); \
    KeccakP_ThetaRhoPiChi3(    _ga, _ke, _mi, _so, _bu ); \
    KeccakP_ThetaRhoPiChi4(    _ma, _se, _bi, _go, _ku ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _me, _gi, _so, _ku, CONST8_64(KeccakP1600RoundConstants[i+1]) ); \
    KeccakP_ThetaRhoPiChi1(    _sa, _ke, _bi, _mo, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ma, _ge, _si, _ko, _bu ); \
    KeccakP_ThetaRhoPiChi3(    _ka, _be, _mi, _go, _su ); \
    KeccakP_ThetaRhoPiChi4(    _ga, _se, _ki, _bo, _mu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _ke, _si, _go, _mu, CONST8_64(KeccakP1600RoundConstants[i+2]) ); \
    KeccakP_ThetaRhoPiChi1(    _ma, _be, _ki, _so, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ga, _me, _bi, _ko, _su ); \
    KeccakP_ThetaRhoPiChi3(    _sa, _ge, _mi, _bo, _ku ); \
    KeccakP_ThetaRhoPiChi4(    _ka, _se, _gi, _mo, _bu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _be, _bi, _bo, _bu, CONST8_64(KeccakP1600RoundConstants[i+3]) ); \
    KeccakP_ThetaRhoPiChi1(    _ga, _ge, _gi, _go, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ka, _ke, _ki, _ko, _ku ); \
    KeccakP_ThetaRhoPiChi3(    _ma, _me, _mi, _mo, _mu ); \
    KeccakP_ThetaRhoPiChi4(    _sa, _se, _si, _so, _su )

#define KeccakP_2rounds( i ) \
    KeccakP_ThetaRhoPiChiIota0(_ba, _ke, _si, _go, _mu, CONST8_64(KeccakP1600RoundConstants[i]) ); \
    KeccakP_ThetaRhoPiChi1(    _ma, _be, _ki, _so, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ga, _me, _bi, _ko, _su ); \
    KeccakP_ThetaRhoPiChi3(    _sa, _ge, _mi, _bo, _ku ); \
    KeccakP_ThetaRhoPiChi4(    _ka, _se, _gi, _mo, _bu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _be, _bi, _bo, _bu, CONST8_64(KeccakP1600RoundConstants[i+1]) ); \
    KeccakP_ThetaRhoPiChi1(    _ga, _ge, _gi, _go, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ka, _ke, _ki, _ko, _ku ); \
    KeccakP_ThetaRhoPiChi3(    _ma, _me, _mi, _mo, _mu ); \
    KeccakP_ThetaRhoPiChi4(    _sa, _se, _si, _so, _su )

#ifdef KeccakP1600times8_AVX512_fullUnrolling

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

#elif (KeccakP1600times8_AVX512_unrolling == 4)

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

#elif (KeccakP1600times8_AVX512_unrolling == 12)

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

#define rounds6 \
    KeccakP_2rounds( 18 ); \
    KeccakP_4rounds( 20 )

#define rounds4 \
    KeccakP_4rounds( 20 )

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

void KeccakP1600times8_AVX512_PermuteAll_24rounds(KeccakP1600times8_SIMD512_states *states)
{
    V512 *statesAsLanes = states->A;
    KeccakP_DeclareVars;
    #ifndef KeccakP1600times8_AVX512_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(statesAsLanes);
    rounds24;
    copyToState(statesAsLanes);
}

void KeccakP1600times8_AVX512_PermuteAll_12rounds(KeccakP1600times8_SIMD512_states *states)
{
    V512 *statesAsLanes = states->A;
    KeccakP_DeclareVars;
    #if (KeccakP1600times8_AVX512_unrolling < 12)
    unsigned int i;
    #endif

    copyFromState(statesAsLanes);
    rounds12;
    copyToState(statesAsLanes);
} 

void KeccakP1600times8_AVX512_PermuteAll_6rounds(KeccakP1600times8_SIMD512_states *states)
{
    V512 *statesAsLanes = states->A;
    KeccakP_DeclareVars;

    copyFromState2rounds(statesAsLanes);
    rounds6;
    copyToState(statesAsLanes);
}

void KeccakP1600times8_AVX512_PermuteAll_4rounds(KeccakP1600times8_SIMD512_states *states)
{
    V512 *statesAsLanes = states->A;
    KeccakP_DeclareVars;

    copyFromState(statesAsLanes);
    rounds4;
    copyToState(statesAsLanes);
}

size_t KeccakF1600times8_AVX512_FastLoop_Absorb(KeccakP1600times8_SIMD512_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    size_t dataMinimumSize = (laneOffsetParallel*7 + laneCount)*8;

    if (laneCount == 21) {
        #ifndef KeccakP1600times8_AVX512_fullUnrolling
        unsigned int i;
        #endif
        const unsigned char *dataStart = data;
        V512 *statesAsLanes = states->A;
        const uint64_t *dataAsLanes = (const uint64_t *)data;
        KeccakP_DeclareVars;
        V256 index;

        copyFromState(statesAsLanes);
        index = LOAD8_32(7*laneOffsetParallel, 6*laneOffsetParallel, 5*laneOffsetParallel, 4*laneOffsetParallel, 3*laneOffsetParallel, 2*laneOffsetParallel, 1*laneOffsetParallel, 0*laneOffsetParallel);
        while(dataByteLen >= dataMinimumSize) {
            #define Add_In( argLane, argIndex )  argLane = XOR(argLane, LOAD_GATHER8_64(index, dataAsLanes+argIndex))
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
            KeccakP1600times8_AVX512_AddLanesAll(states, data, laneCount, laneOffsetParallel);
            KeccakP1600times8_AVX512_PermuteAll_24rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
    }
}

size_t KeccakP1600times8_12rounds_AVX512_FastLoop_Absorb(KeccakP1600times8_SIMD512_states *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen)
{
    size_t dataMinimumSize = (laneOffsetParallel*7 + laneCount)*8;

    if (laneCount == 21) {
        #if (KeccakP1600times8_AVX512_unrolling < 12)
        unsigned int i;
        #endif
        const unsigned char *dataStart = data;
        V512 *statesAsLanes = states->A;
        const uint64_t *dataAsLanes = (const uint64_t *)data;
        KeccakP_DeclareVars;
        V256 index;

        copyFromState(statesAsLanes);
        index = LOAD8_32(7*laneOffsetParallel, 6*laneOffsetParallel, 5*laneOffsetParallel, 4*laneOffsetParallel, 3*laneOffsetParallel, 2*laneOffsetParallel, 1*laneOffsetParallel, 0*laneOffsetParallel);
        while(dataByteLen >= dataMinimumSize) {
            #define Add_In( argLane, argIndex )  argLane = XOR(argLane, LOAD_GATHER8_64(index, dataAsLanes+argIndex))
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
            KeccakP1600times8_AVX512_AddLanesAll(states, data, laneCount, laneOffsetParallel);
            KeccakP1600times8_AVX512_PermuteAll_12rounds(states);
            data += laneOffsetSerial*8;
            dataByteLen -= laneOffsetSerial*8;
        }
        return data - dataStart;
    }
}

/* ------------------------------------------------------------------------- */

#define LOAD(p)                     _mm512_loadu_si512(p)
#define XOReq(a,b)                  a = _mm512_xor_si512(a,b)
#define ZERO()                      _mm512_setzero_si512()
#define CONST_64(a)                 _mm512_set1_epi64(a)

#define chunkSize 8192
#define KT128_rateInBytes (21*8)
#define KT256_rateInBytes (17*8)

#define initializeState(X) \
    X##ba = ZERO(); \
    X##be = ZERO(); \
    X##bi = ZERO(); \
    X##bo = ZERO(); \
    X##bu = ZERO(); \
    X##ga = ZERO(); \
    X##ge = ZERO(); \
    X##gi = ZERO(); \
    X##go = ZERO(); \
    X##gu = ZERO(); \
    X##ka = ZERO(); \
    X##ke = ZERO(); \
    X##ki = ZERO(); \
    X##ko = ZERO(); \
    X##ku = ZERO(); \
    X##ma = ZERO(); \
    X##me = ZERO(); \
    X##mi = ZERO(); \
    X##mo = ZERO(); \
    X##mu = ZERO(); \
    X##sa = ZERO(); \
    X##se = ZERO(); \
    X##si = ZERO(); \
    X##so = ZERO(); \
    X##su = ZERO(); \

#define LoadAndTranspose8(dataAsLanes, offset) \
    t0 = LOAD((dataAsLanes) + (offset) + 0*chunkSize/8); \
    t1 = LOAD((dataAsLanes) + (offset) + 1*chunkSize/8); \
    t2 = LOAD((dataAsLanes) + (offset) + 2*chunkSize/8); \
    t3 = LOAD((dataAsLanes) + (offset) + 3*chunkSize/8); \
    t4 = LOAD((dataAsLanes) + (offset) + 4*chunkSize/8); \
    t5 = LOAD((dataAsLanes) + (offset) + 5*chunkSize/8); \
    t6 = LOAD((dataAsLanes) + (offset) + 6*chunkSize/8); \
    t7 = LOAD((dataAsLanes) + (offset) + 7*chunkSize/8); \
    r0 = _mm512_unpacklo_epi64(t0, t1); \
    r1 = _mm512_unpackhi_epi64(t0, t1); \
    r2 = _mm512_unpacklo_epi64(t2, t3); \
    r3 = _mm512_unpackhi_epi64(t2, t3); \
    r4 = _mm512_unpacklo_epi64(t4, t5); \
    r5 = _mm512_unpackhi_epi64(t4, t5); \
    r6 = _mm512_unpacklo_epi64(t6, t7); \
    r7 = _mm512_unpackhi_epi64(t6, t7); \
    t0 = _mm512_shuffle_i32x4(r0, r2, 0x88); \
    t1 = _mm512_shuffle_i32x4(r1, r3, 0x88); \
    t2 = _mm512_shuffle_i32x4(r0, r2, 0xdd); \
    t3 = _mm512_shuffle_i32x4(r1, r3, 0xdd); \
    t4 = _mm512_shuffle_i32x4(r4, r6, 0x88); \
    t5 = _mm512_shuffle_i32x4(r5, r7, 0x88); \
    t6 = _mm512_shuffle_i32x4(r4, r6, 0xdd); \
    t7 = _mm512_shuffle_i32x4(r5, r7, 0xdd); \
    r0 = _mm512_shuffle_i32x4(t0, t4, 0x88); \
    r1 = _mm512_shuffle_i32x4(t1, t5, 0x88); \
    r2 = _mm512_shuffle_i32x4(t2, t6, 0x88); \
    r3 = _mm512_shuffle_i32x4(t3, t7, 0x88); \
    r4 = _mm512_shuffle_i32x4(t0, t4, 0xdd); \
    r5 = _mm512_shuffle_i32x4(t1, t5, 0xdd); \
    r6 = _mm512_shuffle_i32x4(t2, t6, 0xdd); \
    r7 = _mm512_shuffle_i32x4(t3, t7, 0xdd); \

#define XORdata4(X, index, dataAsLanes) \
    XOReq(X##ba, LOAD_GATHER8_64(index, (dataAsLanes) + 0)); \
    XOReq(X##be, LOAD_GATHER8_64(index, (dataAsLanes) + 1)); \
    XOReq(X##bi, LOAD_GATHER8_64(index, (dataAsLanes) + 2)); \
    XOReq(X##bo, LOAD_GATHER8_64(index, (dataAsLanes) + 3)); \

#define XORdata16(X, index, dataAsLanes) \
    LoadAndTranspose8(dataAsLanes, 0) \
    XOReq(X##ba, r0); \
    XOReq(X##be, r1); \
    XOReq(X##bi, r2); \
    XOReq(X##bo, r3); \
    XOReq(X##bu, r4); \
    XOReq(X##ga, r5); \
    XOReq(X##ge, r6); \
    XOReq(X##gi, r7); \
    LoadAndTranspose8(dataAsLanes, 8) \
    XOReq(X##go, r0); \
    XOReq(X##gu, r1); \
    XOReq(X##ka, r2); \
    XOReq(X##ke, r3); \
    XOReq(X##ki, r4); \
    XOReq(X##ko, r5); \
    XOReq(X##ku, r6); \
    XOReq(X##ma, r7); \

#define XORdata17(X, index, dataAsLanes) \
    XORdata16(X, index, dataAsLanes) \
    XOReq(X##me, LOAD_GATHER8_64(index, (dataAsLanes) + 16)); \

#define XORdata21(X, index, dataAsLanes) \
    XORdata17(X, index, dataAsLanes) \
    XOReq(X##mi, LOAD_GATHER8_64(index, (dataAsLanes) + 17)); \
    XOReq(X##mo, LOAD_GATHER8_64(index, (dataAsLanes) + 18)); \
    XOReq(X##mu, LOAD_GATHER8_64(index, (dataAsLanes) + 19)); \
    XOReq(X##sa, LOAD_GATHER8_64(index, (dataAsLanes) + 20)); \

void KeccakP1600times8_AVX512_KT128ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    KeccakP_DeclareVars;
    unsigned int j;
    const uint64_t *outputAsLanes = (const uint64_t *)output;
    __m256i index;
    __m512i t0, t1, t2, t3, t4, t5, t6, t7;
    __m512i r0, r1, r2, r3, r4, r5, r6, r7;

    initializeState(_);

    index = LOAD8_32(7*(chunkSize / 8), 6*(chunkSize / 8), 5*(chunkSize / 8), 4*(chunkSize / 8), 3*(chunkSize / 8), 2*(chunkSize / 8), 1*(chunkSize / 8), 0*(chunkSize / 8));
    for(j = 0; j < (chunkSize - KT128_rateInBytes); j += KT128_rateInBytes) {
        XORdata21(_, index, (const uint64_t *)input);
        rounds12
        input += KT128_rateInBytes;
    }

    XORdata16(_, index, (const uint64_t *)input);
    XOReq(_me, CONST_64(0x0BULL));
    XOReq(_sa, CONST_64(0x8000000000000000ULL));
    rounds12

    index = LOAD8_32(7*4, 6*4, 5*4, 4*4, 3*4, 2*4, 1*4, 0*4);
    STORE_SCATTER8_64(outputAsLanes+0, index, _ba);
    STORE_SCATTER8_64(outputAsLanes+1, index, _be);
    STORE_SCATTER8_64(outputAsLanes+2, index, _bi);
    STORE_SCATTER8_64(outputAsLanes+3, index, _bo);
}

void KeccakP1600times8_AVX512_KT256ProcessLeaves(const unsigned char *input, unsigned char *output)
{
    KeccakP_DeclareVars;
    unsigned int j;
    const uint64_t *outputAsLanes = (const uint64_t *)output;
    __m256i index;
    __m512i t0, t1, t2, t3, t4, t5, t6, t7;
    __m512i r0, r1, r2, r3, r4, r5, r6, r7;

    initializeState(_);

    index = LOAD8_32(7*(chunkSize / 8), 6*(chunkSize / 8), 5*(chunkSize / 8), 4*(chunkSize / 8), 3*(chunkSize / 8), 2*(chunkSize / 8), 1*(chunkSize / 8), 0*(chunkSize / 8));
    for(j = 0; j < (chunkSize - KT256_rateInBytes); j += KT256_rateInBytes) {
        XORdata17(_, index, (const uint64_t *)input);
        rounds12
        input += KT256_rateInBytes;
    }

    XORdata4(_, index, (const uint64_t *)input);
    XOReq(_bu, CONST_64(0x0BULL));
    XOReq(_me, CONST_64(0x8000000000000000ULL));
    rounds12

    index = LOAD8_32(7*8, 6*8, 5*8, 4*8, 3*8, 2*8, 1*8, 0*8);
    STORE_SCATTER8_64(outputAsLanes+0, index, _ba);
    STORE_SCATTER8_64(outputAsLanes+1, index, _be);
    STORE_SCATTER8_64(outputAsLanes+2, index, _bi);
    STORE_SCATTER8_64(outputAsLanes+3, index, _bo);
    STORE_SCATTER8_64(outputAsLanes+4, index, _bu);
    STORE_SCATTER8_64(outputAsLanes+5, index, _ga);
    STORE_SCATTER8_64(outputAsLanes+6, index, _ge);
    STORE_SCATTER8_64(outputAsLanes+7, index, _gi);
}

#undef LOAD
#undef XOReq
#undef ZERO
#undef CONST_64
#undef chunkSize
#undef rateInBytes

/* ------------------------------------------------------------------------- */

/* Remap lanes to start after two rounds */
#define Iba _ba
#define Ibe _me
#define Ibi _gi
#define Ibo _so
#define Ibu _ku
#define Iga _sa
#define Ige _ke
#define Igi _bi
#define Igo _mo
#define Igu _gu
#define Ika _ma
#define Ike _ge
#define Iki _si
#define Iko _ko
#define Iku _bu
#define Ima _ka
#define Ime _be
#define Imi _mi
#define Imo _go
#define Imu _su
#define Isa _ga
#define Ise _se
#define Isi _ki
#define Iso _bo
#define Isu _mu

#define LoadInput(argIndex) _mm512_i32gather_epi64(gather, (const long long int *)&in64[argIndex], 8)
#define AddInput(argIndex)  XOR( LoadInput(argIndex), CONST8_64(kRoll[argIndex]))


ALIGN(64) static const uint64_t     oLow256[]       = {   0,   1,   2,   3, 8+0, 8+1, 8+2, 8+3 };
ALIGN(64) static const uint64_t     oHigh256[]      = {   4,   5,   6,   7, 8+4, 8+5, 8+6, 8+7 };

ALIGN(64) static const uint64_t     oLow128[]       = {   0,   1, 8+0, 8+1,   4,   5, 8+4, 8+5 };
ALIGN(64) static const uint64_t     oHigh128[]      = {   2,   3, 8+2, 8+3,   6,   7, 8+6, 8+7 };

ALIGN(64) static const uint64_t     oLow64[]        = {   0, 8+0,   2, 8+2,   4, 8+4,   6, 8+6 };
ALIGN(64) static const uint64_t     oHigh64[]       = {   1, 8+1,   3, 8+3,   5, 8+5,   7, 8+7 };

ALIGN(64) static const uint64_t     o01234_012[]    = {   0,   1,   2,   3,   4, 8+0, 8+1, 8+2 };
ALIGN(64) static const uint64_t     o1234_0123[]    = {   1,   2,   3,   4, 8+0, 8+1, 8+2, 8+3 };
ALIGN(64) static const uint64_t     o1234567_0[]    = {   1,   2,   3,   4,   5,   6,   7, 8+0 };
ALIGN(64) static const uint64_t     o1234567_3[]    = {   1,   2,   3,   4,   5,   6,   7, 8+3 };
ALIGN(64) static const uint64_t     o1234567_4[]    = {   1,   2,   3,   4,   5,   6,   7, 8+4 };
ALIGN(64) static const uint64_t     o234567_45[]    = {   2,   3,   4,   5,   6,   7, 8+4, 8+5 };
ALIGN(64) static const uint64_t     o34567_456[]    = {   3,   4,   5,   6,   7, 8+4, 8+5, 8+6 };

ALIGN(32) static const uint32_t     oGatherScatter[]= {0*25, 1*25, 2*25, 3*25, 4*25, 5*25, 6*25, 7*25};

#if defined(__i386__) || defined(_M_IX86)
#define _mm256_extract_epi64(a, index) \
    ((uint64_t)_mm256_extract_epi32((a), (index)*2) || ((uint64_t)_mm256_extract_epi32((a), (index)*2+1) << 32))
#endif

size_t KeccakP1600times8_AVX512_KravatteCompress(uint64_t *xAccu, uint64_t *kRoll, const unsigned char *input, size_t inputByteLen)
{
    #if    !defined(KeccakP1600times4_fullUnrolling)
    unsigned int i;
    #endif
    uint64_t *in64 = (uint64_t *)input;
    size_t    nBlocks = inputByteLen / (8 * 200);
    KeccakP_DeclareVars;
    V512    x01234567, x12345678;
    V512    Xba, Xbe, Xbi, Xbo, Xbu;
    V512    Xga, Xge, Xgi, Xgo, Xgu;
    V512    Xka, Xke, Xki, Xko, Xku;
    V512    Xma, Xme, Xmi, Xmo, Xmu;
    V512    Xsa, Xse, Xsi, Xso, Xsu;
    V256    v1;
    V512    p1, p2;
    V256    gather = *(V256*)oGatherScatter;

    /* Clear internal X accu */
    Xba = _mm512_setzero_si512();
    Xbe = _mm512_setzero_si512();
    Xbi = _mm512_setzero_si512();
    Xbo = _mm512_setzero_si512();
    Xbu = _mm512_setzero_si512();
    Xga = _mm512_setzero_si512();
    Xge = _mm512_setzero_si512();
    Xgi = _mm512_setzero_si512();
    Xgo = _mm512_setzero_si512();
    Xgu = _mm512_setzero_si512();
    Xka = _mm512_setzero_si512();
    Xke = _mm512_setzero_si512();
    Xki = _mm512_setzero_si512();
    Xko = _mm512_setzero_si512();
    Xku = _mm512_setzero_si512();
    Xma = _mm512_setzero_si512();
    Xme = _mm512_setzero_si512();
    Xmi = _mm512_setzero_si512();
    Xmo = _mm512_setzero_si512();
    Xmu = _mm512_setzero_si512();
    Xsa = _mm512_setzero_si512();
    Xse = _mm512_setzero_si512();
    Xsi = _mm512_setzero_si512();
    Xso = _mm512_setzero_si512();
    Xsu = _mm512_setzero_si512();

    /* prepare 8 lanes for roll-c */
    x01234567 = _mm512_maskz_loadu_epi64(0x1F, &kRoll[20]); /* 5 lanes ok */
    _ba = _mm512_maskz_loadu_epi64(0x0F, &kRoll[21]); /* 4 lanes ok */
    _be = XOR3(ROL(x01234567, 7), _ba, _mm512_srli_epi64(_ba, 3));
    x01234567 = _mm512_permutex2var_epi64(x01234567, *(V512*)o01234_012, _be);
    x12345678 = _mm512_permutex2var_epi64(x01234567, *(V512*)o1234_0123, _be);

    do {
        Iba = AddInput( 0);
        Ibe = AddInput( 1);
        Ibi = AddInput( 2);
        Ibo = AddInput( 3);
        Ibu = AddInput( 4);
        Iga = AddInput( 5);
        Ige = AddInput( 6);
        Igi = AddInput( 7);
        Igo = AddInput( 8);
        Igu = AddInput( 9);
        Ika = AddInput(10);
        Ike = AddInput(11);
        Iki = AddInput(12);
        Iko = AddInput(13);
        Iku = AddInput(14);
        Ima = AddInput(15);
        Ime = AddInput(16);
        Imi = AddInput(17);
        Imo = AddInput(18);
        Imu = AddInput(19);

        /* Roll-c */
        Isa = x01234567;
        Ise = x12345678;
        Isu = XOR3(ROL(x01234567, 7), x12345678, _mm512_srli_epi64(x12345678, 3));
        Ise = _mm512_permutex2var_epi64(x01234567, *(V512*)o1234567_3, Isu);
        Isi = _mm512_permutex2var_epi64(Ise, *(V512*)o1234567_4, Isu);
        Iso = _mm512_permutex2var_epi64(Ise, *(V512*)o234567_45, Isu);
        Isu = _mm512_permutex2var_epi64(Ise, *(V512*)o34567_456, Isu);

        x01234567 = XOR3(ROL(Iso, 7), Isu, _mm512_srli_epi64(Isu, 3));
        x12345678 = _mm512_permutex2var_epi64(x01234567, *(V512*)o1234567_4, x01234567);

        XOReq512(Isa, LoadInput(20));
        XOReq512(Ise, LoadInput(21));
        XOReq512(Isi, LoadInput(22));
        XOReq512(Iso, LoadInput(23));
        XOReq512(Isu, LoadInput(24));

        rounds6
        Dump( "P-out", _);

        /*    Accumulate in X */
        XOReq512(Xba, _ba);
        XOReq512(Xbe, _be);
        XOReq512(Xbi, _bi);
        XOReq512(Xbo, _bo);
        XOReq512(Xbu, _bu);
        XOReq512(Xga, _ga);
        XOReq512(Xge, _ge);
        XOReq512(Xgi, _gi);
        XOReq512(Xgo, _go);
        XOReq512(Xgu, _gu);
        XOReq512(Xka, _ka);
        XOReq512(Xke, _ke);
        XOReq512(Xki, _ki);
        XOReq512(Xko, _ko);
        XOReq512(Xku, _ku);
        XOReq512(Xma, _ma);
        XOReq512(Xme, _me);
        XOReq512(Xmi, _mi);
        XOReq512(Xmo, _mo);
        XOReq512(Xmu, _mu);
        XOReq512(Xsa, _sa);
        XOReq512(Xse, _se);
        XOReq512(Xsi, _si);
        XOReq512(Xso, _so);
        XOReq512(Xsu, _su);
        Dump( "X", X);

        in64 += 8 * 25;
    }
    while(--nBlocks != 0);

    /* Add horizontally Xba ... Xgi Reduce from lanes 8 to 4 */
    p1 = *(V512*)oLow256;
    p2 = *(V512*)oHigh256;
    Xba = XOR(_mm512_permutex2var_epi64(Xba, p1, Xbu), _mm512_permutex2var_epi64(Xba, p2, Xbu));
    Xbe = XOR(_mm512_permutex2var_epi64(Xbe, p1, Xga), _mm512_permutex2var_epi64(Xbe, p2, Xga));
    Xbi = XOR(_mm512_permutex2var_epi64(Xbi, p1, Xge), _mm512_permutex2var_epi64(Xbi, p2, Xge));
    Xbo = XOR(_mm512_permutex2var_epi64(Xbo, p1, Xgi), _mm512_permutex2var_epi64(Xbo, p2, Xgi));

    /* Add horizontally Xgo ... Xma Reduce from lanes 8 to 4 */
    Xgo = XOR(_mm512_permutex2var_epi64(Xgo, p1, Xki), _mm512_permutex2var_epi64(Xgo, p2, Xki));
    Xgu = XOR(_mm512_permutex2var_epi64(Xgu, p1, Xko), _mm512_permutex2var_epi64(Xgu, p2, Xko));
    Xka = XOR(_mm512_permutex2var_epi64(Xka, p1, Xku), _mm512_permutex2var_epi64(Xka, p2, Xku));
    Xke = XOR(_mm512_permutex2var_epi64(Xke, p1, Xma), _mm512_permutex2var_epi64(Xke, p2, Xma));

    /* Add horizontally Xme ... Xso Reduce from lanes 8 to 4 */
    Xme = XOR(_mm512_permutex2var_epi64(Xme, p1, Xsa), _mm512_permutex2var_epi64(Xme, p2, Xsa));
    Xmi = XOR(_mm512_permutex2var_epi64(Xmi, p1, Xse), _mm512_permutex2var_epi64(Xmi, p2, Xse));
    Xmo = XOR(_mm512_permutex2var_epi64(Xmo, p1, Xsi), _mm512_permutex2var_epi64(Xmo, p2, Xsi));
    Xmu = XOR(_mm512_permutex2var_epi64(Xmu, p1, Xso), _mm512_permutex2var_epi64(Xmu, p2, Xso));

    /* Add horizontally Xba ... Xbo Reduce from lanes 4 to 2 */
    p1 = *(V512*)oLow128;
    p2 = *(V512*)oHigh128;
    Xba = XOR(_mm512_permutex2var_epi64(Xba, p1, Xbi), _mm512_permutex2var_epi64(Xba, p2, Xbi));
    Xbe = XOR(_mm512_permutex2var_epi64(Xbe, p1, Xbo), _mm512_permutex2var_epi64(Xbe, p2, Xbo));

    /* Add horizontally Xgo ... Xke Reduce from lanes 4 to 2 */
    Xgo = XOR(_mm512_permutex2var_epi64(Xgo, p1, Xka), _mm512_permutex2var_epi64(Xgo, p2, Xka));
    Xgu = XOR(_mm512_permutex2var_epi64(Xgu, p1, Xke), _mm512_permutex2var_epi64(Xgu, p2, Xke));

    /* Add horizontally Xme ... Xmu Reduce from lanes 4 to 2 */
    Xme = XOR(_mm512_permutex2var_epi64(Xme, p1, Xmo), _mm512_permutex2var_epi64(Xme, p2, Xmo));
    Xmi = XOR(_mm512_permutex2var_epi64(Xmi, p1, Xmu), _mm512_permutex2var_epi64(Xmi, p2, Xmu));

    /* Add horizontally Xba ... Xbe Reduce from lanes 2 to 1 */
    p1 = *(V512*)oLow64;
    p2 = *(V512*)oHigh64;
    Xba = XOR(_mm512_permutex2var_epi64(Xba, p1, Xbe), _mm512_permutex2var_epi64(Xba, p2, Xbe));

    /* Add horizontally Xgo ... Xgu Reduce from lanes 2 to 1 */
    Xgo = XOR(_mm512_permutex2var_epi64(Xgo, p1, Xgu), _mm512_permutex2var_epi64(Xgo, p2, Xgu));

    /* Add horizontally Xme ... Xmi Reduce from lanes 2 to 1 */
    Xme = XOR(_mm512_permutex2var_epi64(Xme, p1, Xmi), _mm512_permutex2var_epi64(Xme, p2, Xmi));

    /* Add and store in xAccu */
    Xba = XOR( Xba, LOAD512u(xAccu[0]));
    Xgo = XOR( Xgo, LOAD512u(xAccu[8]));
    Xme = XOR( Xme, LOAD512u(xAccu[16]));
    _mm512_storeu_si512((V512*)&xAccu[0], Xba);
    _mm512_storeu_si512((V512*)&xAccu[8], Xgo);
    _mm512_storeu_si512((V512*)&xAccu[16], Xme);

    /* Add horizontally Xsu */
    v1 = _mm256_xor_si256( _mm512_extracti64x4_epi64(Xsu, 0), _mm512_extracti64x4_epi64(Xsu, 1));
    v1 = _mm256_xor_si256( v1, _mm256_permute4x64_epi64(v1, 0xEE));
    xAccu[24] ^= _mm256_extract_epi64(v1, 0) ^ _mm256_extract_epi64(v1, 1);
    DumpMem("xAccu", xAccu, 5*5);

    /*    Store new kRoll */
    _mm512_mask_storeu_epi64(&kRoll[20], 0x1F, x01234567);
    DumpMem("Next kRoll", kRoll+20, 5);

    return (size_t)in64 - (size_t)input;
}

#undef LoadInput
#undef AddInput

ALIGN(64) static const uint64_t     o1234567_6[]    = {   1,   2,   3,   4,   5,   6,   7, 8+6 };
ALIGN(64) static const uint64_t     o234567_01[]    = {   2,   3,   4,   5,   6,   7, 8+0, 8+1 };
ALIGN(64) static const uint64_t     o34567_012[]    = {   3,   4,   5,   6,   7, 8+0, 8+1, 8+2 };
ALIGN(64) static const uint64_t     o4567_0123[]    = {   4,   5,   6,   7, 8+0, 8+1, 8+2, 8+3 };
ALIGN(64) static const uint64_t     o567_01234[]    = {   5,   6,   7, 8+0, 8+1, 8+2, 8+3, 8+4 };
ALIGN(64) static const uint64_t     o67_012345[]    = {   6,   7, 8+0, 8+1, 8+2, 8+3, 8+4, 8+5 };
ALIGN(64) static const uint64_t     o7_0123456[]    = {   7, 8+0, 8+1, 8+2, 8+3, 8+4, 8+5, 8+6 };

size_t KeccakP1600times8_AVX512_KravatteExpand(uint64_t *yAccu, const uint64_t *kRoll, unsigned char *output, size_t outputByteLen)
{
    uint64_t *o64 = (uint64_t *)output;
    size_t    nBlocks = outputByteLen / (8 * 200);
    KeccakP_DeclareVars;
    #if    !defined(KeccakP1600times4_fullUnrolling)
    unsigned int i;
    #endif
    V512    x01234567, x23456789;
    V256    scatter = *(V256*)oGatherScatter;

    x01234567 = LOAD512u(yAccu[15]);
    x23456789 = LOAD512u(yAccu[17]);

    do {
        Iba = CONST8_64(yAccu[0]);
        Ibe = CONST8_64(yAccu[1]);
        Ibi = CONST8_64(yAccu[2]);
        Ibo = CONST8_64(yAccu[3]);
        Ibu = CONST8_64(yAccu[4]);

        Iga = CONST8_64(yAccu[5]);
        Ige = CONST8_64(yAccu[6]);
        Igi = CONST8_64(yAccu[7]);
        Igo = CONST8_64(yAccu[8]);
        Igu = CONST8_64(yAccu[9]);

        Ika = CONST8_64(yAccu[10]);
        Ike = CONST8_64(yAccu[11]);
        Iki = CONST8_64(yAccu[12]);
        Iko = CONST8_64(yAccu[13]);
        Iku = CONST8_64(yAccu[14]);

        /*  roll-e */
        Ima = x01234567;
        Ime = _mm512_permutex2var_epi64(x01234567, *(V512*)o1234567_6, x23456789);
        Imi = x23456789;

        x23456789 = XOR3(ROL(Ima, 7), ROL(Ime, 18), _mm512_and_si512(Imi, _mm512_srli_epi64(Ime, 1)));
        Imo = _mm512_permutex2var_epi64(Imi, *(V512*)o1234567_0, x23456789);
        Imu = _mm512_permutex2var_epi64(Imi, *(V512*)o234567_01, x23456789);
        Isa = _mm512_permutex2var_epi64(Imi, *(V512*)o34567_012, x23456789);
        Ise = _mm512_permutex2var_epi64(Imi, *(V512*)o4567_0123, x23456789);
        Isi = _mm512_permutex2var_epi64(Imi, *(V512*)o567_01234, x23456789);
        Iso = _mm512_permutex2var_epi64(Imi, *(V512*)o67_012345, x23456789);
        Isu = _mm512_permutex2var_epi64(Imi, *(V512*)o7_0123456, x23456789);
        x01234567 = Iso;
        Dump( "After roll-e", I);

        rounds6

        /*  Add kRoll */
        _ba = XOR(_ba, CONST8_64(kRoll[0]));
        _be = XOR(_be, CONST8_64(kRoll[1]));
        _bi = XOR(_bi, CONST8_64(kRoll[2]));
        _bo = XOR(_bo, CONST8_64(kRoll[3]));
        _bu = XOR(_bu, CONST8_64(kRoll[4]));
        _ga = XOR(_ga, CONST8_64(kRoll[5]));
        _ge = XOR(_ge, CONST8_64(kRoll[6]));
        _gi = XOR(_gi, CONST8_64(kRoll[7]));
        _go = XOR(_go, CONST8_64(kRoll[8]));
        _gu = XOR(_gu, CONST8_64(kRoll[9]));
        _ka = XOR(_ka, CONST8_64(kRoll[10]));
        _ke = XOR(_ke, CONST8_64(kRoll[11]));
        _ki = XOR(_ki, CONST8_64(kRoll[12]));
        _ko = XOR(_ko, CONST8_64(kRoll[13]));
        _ku = XOR(_ku, CONST8_64(kRoll[14]));
        _ma = XOR(_ma, CONST8_64(kRoll[15]));
        _me = XOR(_me, CONST8_64(kRoll[16]));
        _mi = XOR(_mi, CONST8_64(kRoll[17]));
        _mo = XOR(_mo, CONST8_64(kRoll[18]));
        _mu = XOR(_mu, CONST8_64(kRoll[19]));
        _sa = XOR(_sa, CONST8_64(kRoll[20]));
        _se = XOR(_se, CONST8_64(kRoll[21]));
        _si = XOR(_si, CONST8_64(kRoll[22]));
        _so = XOR(_so, CONST8_64(kRoll[23]));
        _su = XOR(_su, CONST8_64(kRoll[24]));
        Dump( "After add kRoll", _);

        /*  Extract */
        STORE_SCATTER8_64(o64+0, scatter, _ba);
        STORE_SCATTER8_64(o64+1, scatter, _be);
        STORE_SCATTER8_64(o64+2, scatter, _bi);
        STORE_SCATTER8_64(o64+3, scatter, _bo);
        STORE_SCATTER8_64(o64+4, scatter, _bu);
        STORE_SCATTER8_64(o64+5, scatter, _ga);
        STORE_SCATTER8_64(o64+6, scatter, _ge);
        STORE_SCATTER8_64(o64+7, scatter, _gi);
        STORE_SCATTER8_64(o64+8, scatter, _go);
        STORE_SCATTER8_64(o64+9, scatter, _gu);
        STORE_SCATTER8_64(o64+10, scatter, _ka);
        STORE_SCATTER8_64(o64+11, scatter, _ke);
        STORE_SCATTER8_64(o64+12, scatter, _ki);
        STORE_SCATTER8_64(o64+13, scatter, _ko);
        STORE_SCATTER8_64(o64+14, scatter, _ku);
        STORE_SCATTER8_64(o64+15, scatter, _ma);
        STORE_SCATTER8_64(o64+16, scatter, _me);
        STORE_SCATTER8_64(o64+17, scatter, _mi);
        STORE_SCATTER8_64(o64+18, scatter, _mo);
        STORE_SCATTER8_64(o64+19, scatter, _mu);
        STORE_SCATTER8_64(o64+20, scatter, _sa);
        STORE_SCATTER8_64(o64+21, scatter, _se);
        STORE_SCATTER8_64(o64+22, scatter, _si);
        STORE_SCATTER8_64(o64+23, scatter, _so);
        STORE_SCATTER8_64(o64+24, scatter, _su);
        DumpMem("Output", o64, 8*25);

        o64 += 8 * 25;
    }
    while(--nBlocks != 0);

    /*    Store new yAccu */
    _mm512_mask_storeu_epi64(&yAccu[15], 0xFF, x01234567);
    _mm512_mask_storeu_epi64(&yAccu[17], 0xC0, x23456789);
    DumpMem("yAccu", yAccu, 25);

    return (size_t)o64 - (size_t)output;
}
