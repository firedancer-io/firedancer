/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Xoodoo permutation, designed by Joan Daemen, Seth Hoffert, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <stdio.h>
#include <string.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include "align.h"
#include "brg_endian.h"
#include "Xoodoo.h"
#include "Xoodoo-times4-AVX512.h"

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

#define    VERBOSE        0

typedef __m128i V128;
typedef __m256i V256;
typedef __m512i V512;

#define SnP_laneLengthInBytes   4
#define laneIndex(instanceIndex, lanePosition) ((lanePosition)*4 + instanceIndex)

#define Chi(a,b,c)                  _mm_ternarylogic_epi32(a,b,c,0xD2)

#define CONST4_32(a)                _mm_set1_epi32(a)
#define LOAD256u(a)                 _mm256_loadu_si256((const V256 *)&(a))

#define LOAD512(a)                  _mm512_load_si512((const V512 *)&(a))
#define LOAD512u(a)                 _mm512_loadu_si512((const V512 *)&(a))

#define LOAD_GATHER4_32(idx,p)      _mm_i32gather_epi32((const int*)(p), idx, 4)
#define STORE_SCATTER4_32(idx,a,p)  _mm_i32scatter_epi32((void*)(p), idx, a, 4)
#define LOAD4_32(a,b,c,d)           _mm_setr_epi32(a,b,c,d)


#define SHUFFLE_LANES_RIGHT(idx, a) _mm_permutexvar_epi32(idx, a)

#define ROL32(a, o)                 _mm_rol_epi32(a, o)
#define SHL32(a, o)                 _mm_slli_epi32(a, o)

#define SET4_32                     _mm_setr_epi32

#define STORE128(a, b)              _mm_store_si128((V128 *)&(a), b)
#define STORE128u(a, b)             _mm_storeu_si128((V128 *)&(a), b)
#define STORE256u(a, b)             _mm256_storeu_si256((V256 *)&(a), b)
#define STORE256(a, b)              _mm256_store_si256((V256 *)&(a), b)
#define STORE512(a, b)              _mm512_store_si512((V512 *)&(a), b)
#define STORE512u(a, b)             _mm512_storeu_si512((V512 *)&(a), b)

#define AND(a, b)                   _mm_and_si128(a, b)
#define XOR(a, b)                   _mm_xor_si128(a, b)
#define XOR256(a, b)                _mm256_xor_si256(a, b)
#define XOR512(a, b)                _mm512_xor_si512(a, b)
#define XOR3(a,b,c)                 _mm_ternarylogic_epi32(a,b,c,0x96)

#if (VERBOSE > 0)
    #define    DumpOne(__b,__v,__i) STORE128(__b, __v##__i); \
                                    printf("%02u %08x %08x %08x %08x\n", __i, buf[0], buf[1], buf[2], buf[3])

    #define    Dump(__t,__v)    {                   \
                            uint32_t    buf[8];     \
                            printf("%s\n", __t);    \
                            DumpOne(buf, __v, 00);  \
                            DumpOne(buf, __v, 01);  \
                            DumpOne(buf, __v, 02);  \
                            DumpOne(buf, __v, 03);  \
                            DumpOne(buf, __v, 10);  \
                            DumpOne(buf, __v, 11);  \
                            DumpOne(buf, __v, 12);  \
                            DumpOne(buf, __v, 13);  \
                            DumpOne(buf, __v, 20);  \
                            DumpOne(buf, __v, 21);  \
                            DumpOne(buf, __v, 22);  \
                            DumpOne(buf, __v, 23);  \
                        }
#else
    #define    Dump(__t,__v)
#endif

#if (VERBOSE >= 1)
    #define    Dump1(__t,__v)    Dump(__t,__v)
#else
    #define    Dump1(__t,__v)
#endif

#if (VERBOSE >= 2)
    #define    Dump2(__t,__v)    Dump(__t,__v)
#else
    #define    Dump2(__t,__v)
#endif

#if (VERBOSE >= 3)
    #define    Dump3(__t,__v)    Dump(__t,__v)
#else
    #define    Dump3(__t,__v)
#endif

#if (VERBOSE > 0)
#define    DUMP32(tt, buf)    printf("%s %08x %08x %08x %08x %08x %08x %08x %08x\n", tt, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7])

#define    DUMP32_12(tt, buf) printf("%s %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n", tt, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11])

#define    DumpLane(__t,__v) {  uint32_t buf[8]; \
                                STORE128(buf[0], __v); \
                                printf("%s %08x %08x %08x %08x\n", __t, buf[0], buf[1], buf[2], buf[3]); }

#else
#define    DUMP32(__t, buf)
#define    DUMP32_12(__t, buf)
#define    DumpLane(__t,__v)
#endif

ALIGN(32) static const uint32_t     oAllFrom1_0[]   = { 1,   2,   3, 4+0 };
ALIGN(32) static const uint32_t     oAllFrom2_0[]   = { 2,   3, 4+0, 4+1 };
ALIGN(32) static const uint32_t     oAllFrom3_0[]   = { 3, 4+0, 4+1, 4+2 };

ALIGN(32) static const uint32_t     oLow64[]        = { 0,   1, 4+0, 4+1 };
ALIGN(32) static const uint32_t     oHigh64[]       = { 2,   3, 4+2, 4+3 };

ALIGN(32) static const uint32_t     oLow32[]        = { 0, 4+0,   2, 4+2 };
ALIGN(32) static const uint32_t     oHigh32[]       = { 1, 4+1,   3, 4+3 };

ALIGN(32) static const uint32_t     oGatherScatterOffsets[] = { 0*12, 1*12, 2*12, 3*12 };

void Xoodootimes4_AVX512_InitializeAll(Xoodootimes4_align512SIMD128_states *states)
{
    memset(states, 0, sizeof(Xoodootimes4_align512SIMD128_states));
}

void Xoodootimes4_AVX512_AddBytes(Xoodootimes4_align512SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curData = data;
    uint32_t *statesAsLanes = (uint32_t *)states->A;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        uint32_t lane = 0;
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        memcpy((unsigned char*)&lane + offsetInLane, curData, bytesInLane);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
        sizeLeft -= bytesInLane;
        lanePosition++;
        curData += bytesInLane;
    }

    while(sizeLeft >= SnP_laneLengthInBytes) {
        uint32_t lane = *((const uint32_t*)curData);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        uint32_t lane = 0;
        memcpy(&lane, curData, sizeLeft);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
    }
}

void Xoodootimes4_AVX512_AddLanesAll(Xoodootimes4_align512SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes = states->A;
    unsigned int i;
    const uint32_t *data32 = (const uint32_t *)data;
    V128 offsets = SET4_32(0*laneOffset, 1*laneOffset, 2*laneOffset, 3*laneOffset);

    #define Xor_In( argIndex )  stateAsLanes[argIndex] = XOR(stateAsLanes[argIndex], LOAD_GATHER4_32(offsets, &data32[argIndex]))

    if ( laneCount == 12 )  {
        Xor_In( 0 );
        Xor_In( 1 );
        Xor_In( 2 );
        Xor_In( 3 );
        Xor_In( 4 );
        Xor_In( 5 );
        Xor_In( 6 );
        Xor_In( 7 );
        Xor_In( 8 );
        Xor_In( 9 );
        Xor_In( 10 );
        Xor_In( 11 );
    }
    else {
        for(i=0; i<laneCount; i++)
            Xor_In( i );
    }
    #undef  Xor_In
}

void Xoodootimes4_AVX512_OverwriteBytes(Xoodootimes4_align512SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curData = data;
    uint32_t *statesAsLanes = (uint32_t *)states->A;

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
        uint32_t lane = *((const uint32_t*)curData);
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] = lane;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        memcpy(&statesAsLanes[laneIndex(instanceIndex, lanePosition)], curData, sizeLeft);
    }
}

void Xoodootimes4_AVX512_OverwriteLanesAll(Xoodootimes4_align512SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes = states->A;
    unsigned int i;
    const uint32_t *data32 = (const uint32_t *)data;
    V128 offsets = SET4_32(0*laneOffset, 1*laneOffset, 2*laneOffset, 3*laneOffset);

    #define OverWr( argIndex )  stateAsLanes[argIndex] = LOAD_GATHER4_32(offsets, &data32[argIndex])

    if ( laneCount == 12 )  {
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
    }
    else {
        for(i=0; i<laneCount; i++)
            OverWr( i );
    }
    #undef  OverWr
}

void Xoodootimes4_AVX512_OverwriteWithZeroes(Xoodootimes4_align512SIMD128_states *states, unsigned int instanceIndex, unsigned int byteCount)
{
    unsigned int sizeLeft = byteCount;
    unsigned int lanePosition = 0;
    uint32_t *statesAsLanes = (uint32_t *)states->A;

    while(sizeLeft >= SnP_laneLengthInBytes) {
        statesAsLanes[laneIndex(instanceIndex, lanePosition)] = 0;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
    }

    if (sizeLeft > 0) {
        memset(&statesAsLanes[laneIndex(instanceIndex, lanePosition)], 0, sizeLeft);
    }
}

void Xoodootimes4_AVX512_ExtractBytes(const Xoodootimes4_align512SIMD128_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    unsigned char *curData = data;
    const uint32_t *statesAsLanes = (const uint32_t *)states->A;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        memcpy( curData, ((const unsigned char *)&statesAsLanes[laneIndex(instanceIndex, lanePosition)]) + offsetInLane, bytesInLane);
        sizeLeft -= bytesInLane;
        lanePosition++;
        curData += bytesInLane;
    }

    while(sizeLeft >= SnP_laneLengthInBytes) {
        *(uint32_t*)curData = statesAsLanes[laneIndex(instanceIndex, lanePosition)];
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        memcpy( curData, &statesAsLanes[laneIndex(instanceIndex, lanePosition)], sizeLeft);
    }
}

void Xoodootimes4_AVX512_ExtractLanesAll(const Xoodootimes4_align512SIMD128_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    const V128 *stateAsLanes = states->A;
    unsigned int i;
    uint32_t *data32 = (uint32_t *)data;
    V128 offsets = SET4_32(0*laneOffset, 1*laneOffset, 2*laneOffset, 3*laneOffset);

    #define Extr( argIndex )        STORE_SCATTER4_32(offsets, stateAsLanes[argIndex], &data32[argIndex])

    if ( laneCount == 12 )  {
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
    }
    else {
        for(i=0; i<laneCount; i++)
            Extr( i );
    }
    #undef  Extr
}

void Xoodootimes4_AVX512_ExtractAndAddBytes(const Xoodootimes4_align512SIMD128_states *states, unsigned int instanceIndex, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
    const unsigned char *curInput = input;
    unsigned char *curOutput = output;
    const uint32_t *statesAsLanes = (const uint32_t *)states->A;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        uint32_t lane = statesAsLanes[laneIndex(instanceIndex, lanePosition)] >> (8 * offsetInLane);
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
        *((uint32_t*)curOutput) = *((const uint32_t*)curInput) ^ statesAsLanes[laneIndex(instanceIndex, lanePosition)];
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curInput += SnP_laneLengthInBytes;
        curOutput += SnP_laneLengthInBytes;
    }

    if (sizeLeft != 0) {
        uint32_t lane = statesAsLanes[laneIndex(instanceIndex, lanePosition)];
        do {
            *(curOutput++) = *(curInput++) ^ (unsigned char)lane;
            lane >>= 8;
        } while ( --sizeLeft != 0);
    }
}

void Xoodootimes4_AVX512_ExtractAndAddLanesAll(const Xoodootimes4_align512SIMD128_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    const V128 *stateAsLanes = states->A;
    unsigned int i;
    const uint32_t *datai32 = (const uint32_t *)input;
    uint32_t *datao32 = (uint32_t *)output;
    V128 offsets = SET4_32(0*laneOffset, 1*laneOffset, 2*laneOffset, 3*laneOffset);

    #define ExtrXor( argIndex ) STORE_SCATTER4_32(offsets, XOR( stateAsLanes[argIndex], LOAD_GATHER4_32(offsets, &datai32[argIndex])), &datao32[argIndex])

    if ( laneCount == 12 )  {
        ExtrXor( 0 );
        ExtrXor( 1 );
        ExtrXor( 2 );
        ExtrXor( 3 );
        ExtrXor( 4 );
        ExtrXor( 5 );
        ExtrXor( 6 );
        ExtrXor( 7 );
        ExtrXor( 8 );
        ExtrXor( 9 );
        ExtrXor( 10 );
        ExtrXor( 11 );
    }
    else {
        for(i=0; i<laneCount; i++) {
            ExtrXor( i );
        }
    }
    #undef  ExtrXor
}

#define DeclareVars     V128    a00, a01, a02, a03; \
                        V128    a10, a11, a12, a13; \
                        V128    a20, a21, a22, a23; \
                        V128    v1, v2;

#define State2Vars2     a00 = states[0], a01 = states[1], a02 = states[ 2], a03 = states[ 3]; \
                        a12 = states[4], a13 = states[5], a10 = states[ 6], a11 = states[ 7]; \
                        a20 = states[8], a21 = states[9], a22 = states[10], a23 = states[11]

#define State2Vars      a00 = states[0], a01 = states[1], a02 = states[ 2], a03 = states[ 3]; \
                        a10 = states[4], a11 = states[5], a12 = states[ 6], a13 = states[ 7]; \
                        a20 = states[8], a21 = states[9], a22 = states[10], a23 = states[11]

#define Vars2State      states[0] = a00, states[1] = a01, states[ 2] = a02, states[ 3] = a03; \
                        states[4] = a10, states[5] = a11, states[ 6] = a12, states[ 7] = a13; \
                        states[8] = a20, states[9] = a21, states[10] = a22, states[11] = a23

#define Round(a10i, a11i, a12i, a13i, a10w, a11w, a12w, a13w, a20i, a21i, a22i, a23i, __rc) \
                                                            \
    /* Theta: Column Parity Mixer */                        \
    /* Iota: round constants */                             \
    v1 = XOR3( a03, a13i, a23i );                           \
    v2 = XOR3( a00, a10i, a20i );                           \
    v1 = XOR( ROL32(v1, 5), ROL32(v1, 14) );               \
    a00  = XOR3( a00,  v1, CONST4_32(__rc) ); /* Iota */    \
    a10i = XOR( a10i, v1 );                                 \
    a20i = XOR( a20i, v1 );                                 \
    v1 = XOR3( a01, a11i, a21i );                           \
    v2 = XOR( ROL32(v2, 5), ROL32(v2, 14) );               \
    a01  = XOR( a01,  v2 );                                 \
    a11i = XOR( a11i, v2 );                                 \
    a21i = XOR( a21i, v2 );                                 \
    v2 = XOR3( a02, a12i, a22i );                           \
    v1 = XOR( ROL32(v1, 5), ROL32(v1, 14) );               \
    a02  = XOR( a02,  v1 );                                 \
    a12i = XOR( a12i, v1 );                                 \
    a22i = XOR( a22i, v1 );                                 \
    v2 = XOR( ROL32(v2, 5), ROL32(v2, 14) );               \
    a03  = XOR( a03,  v2 );                                 \
    a13i = XOR( a13i, v2 );                                 \
    a23i = XOR( a23i, v2 );                                 \
    Dump3("Theta",a);                                       \
                                                            \
    /* Rho-west: Plane shift */                             \
    a20i = ROL32(a20i, 11);                                 \
    a21i = ROL32(a21i, 11);                                 \
    a22i = ROL32(a22i, 11);                                 \
    a23i = ROL32(a23i, 11);                                 \
    Dump3("Rho-west",a);                                    \
                                                            \
    /* Chi: non linear step, on colums */                   \
    a00  = Chi(a00,  a10w, a20i);                           \
    a01  = Chi(a01,  a11w, a21i);                           \
    a02  = Chi(a02,  a12w, a22i);                           \
    a03  = Chi(a03,  a13w, a23i);                           \
    a10w = Chi(a10w, a20i, a00);                            \
    a11w = Chi(a11w, a21i, a01);                            \
    a12w = Chi(a12w, a22i, a02);                            \
    a13w = Chi(a13w, a23i, a03);                            \
    a20i = Chi(a20i, a00,  a10w);                           \
    a21i = Chi(a21i, a01,  a11w);                           \
    a22i = Chi(a22i, a02,  a12w);                           \
    a23i = Chi(a23i, a03,  a13w);                           \
    Dump3("Chi",a);                                         \
                                                            \
    /* Rho-east: Plane shift */                             \
    a10w = ROL32(a10w, 1);                                  \
    a11w = ROL32(a11w, 1);                                  \
    a12w = ROL32(a12w, 1);                                  \
    a13w = ROL32(a13w, 1);                                  \
    a20i = ROL32(a20i, 8);                                  \
    a21i = ROL32(a21i, 8);                                  \
    a22i = ROL32(a22i, 8);                                  \
    a23i = ROL32(a23i, 8);                                  \
    Dump3("Rho-east",a)

void Xoodootimes4_AVX512_PermuteAll_6rounds(Xoodootimes4_align512SIMD128_states *argstates)
{
    V128 * states = argstates->A;
    DeclareVars;

    State2Vars2;
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
    Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
    Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
    Dump2("Permutation\n", a);
    Vars2State;
}

void Xoodootimes4_AVX512_PermuteAll_12rounds(Xoodootimes4_align512SIMD128_states *argstates)
{
    V128 * states = argstates->A;
    DeclareVars;

    State2Vars;
    Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc12 );
    Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc11 );
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc10 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc9 );
    Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc8 );
    Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc7 );
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
    Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
    Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
    Dump2("Permutation\n", a);
    Vars2State;
}

void Xooffftimes4_AVX512_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen)
{
    size_t  byteLen = bitLen / 8;
    V512    lanes1, lanes2, lanes3, lanes4;
    V256    lanesA, lanesB;

    while ( byteLen >= 128 ) {
        lanes1 = LOAD512u(input[ 0]);
        lanes2 = LOAD512u(input[64]);
        lanes3 = LOAD512u(output[ 0]);
        lanes4 = LOAD512u(output[64]);
        lanes1 = XOR512(lanes1, lanes3);
        lanes2 = XOR512(lanes2, lanes4);
        STORE512u(output[ 0], lanes1);
        STORE512u(output[64], lanes2);
        input += 128;
        output += 128;
        byteLen -= 128;
    }
    while ( byteLen >= 32 ) {
        lanesA = LOAD256u(input[0]);
        lanesB = LOAD256u(output[0]);
        input += 32;
        lanesA = XOR256(lanesA, lanesB);
        byteLen -= 32;
        STORE256u(output[0], lanesA);
        output += 32;
    }
   while ( byteLen >= 8 ) {
        *((uint64_t*)output) ^= *((const uint64_t*)input);
        input += 8;
        output += 8;
        byteLen -= 8;
    }
    while ( byteLen-- != 0 ) {
        *output++ ^= *input++;
    }

    bitLen &= 7;
    if (bitLen != 0)
    {
        *output ^= *input;
        *output &= (1 << bitLen) - 1;
    }
}

size_t Xooffftimes4_AVX512_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length)
{
    DeclareVars;
    uint32_t       *k32 = (uint32_t*)k;
    uint32_t       *x32 = (uint32_t*)x;
    const uint32_t *i32 = (const uint32_t*)input;
    size_t      initialLength;
    V128        r0481;
    V128        r5926;
    V128        ra37b;
    V128        offsets;
    V128        x00, x01, x02, x03, x10, x11, x12, x13, x20, x21, x22, x23;
    V256        x256;
    V512        x512;

    DUMP32("k32",k32);
    r0481 = LOAD_GATHER4_32(LOAD4_32(  0,  4,  8,  1), k32);
    r5926 = LOAD_GATHER4_32(LOAD4_32(  5,  9,  2,  6), k32);
    ra37b = LOAD_GATHER4_32(LOAD4_32( 10,  3,  7, 11), k32);

    offsets = *(const V128*)oGatherScatterOffsets;

    x00 = _mm_setzero_si128();
    x01 = _mm_setzero_si128();
    x02 = _mm_setzero_si128();
    x03 = _mm_setzero_si128();
    x10 = _mm_setzero_si128();
    x11 = _mm_setzero_si128();
    x12 = _mm_setzero_si128();
    x13 = _mm_setzero_si128();
    x20 = _mm_setzero_si128();
    x21 = _mm_setzero_si128();
    x22 = _mm_setzero_si128();
    x23 = _mm_setzero_si128();
    initialLength = length;
    do {
        #define        rCGKD    ra37b

        /*    Note that a10-a12 and a11-a13 are swapped */
        a00 = r0481;
        a13 = r5926;
        a22 = ra37b;

        a12 = _mm_permutex2var_epi32(a00, *(const V128*)oAllFrom1_0, r5926);    /* 481 5 */

        r0481 = r5926;
        r5926 = ra37b;
        rCGKD = XOR3(a00, SHL32(a00, 13), ROL32(a12, 3));

        a01 = _mm_permutex2var_epi32(a00, *(const V128*)oAllFrom3_0, a13);        /* 1 592 */
        a02 = _mm_permutex2var_epi32(a13, *(const V128*)oAllFrom2_0, a22);        /* 26 a3 */
        a03 = _mm_permutex2var_epi32(a22, *(const V128*)oAllFrom1_0, rCGKD);    /* 37b c */
            
        a10 = _mm_permutex2var_epi32(a13, *(const V128*)oAllFrom3_0, a22);        /* 6 a37 */
        a11 = _mm_permutex2var_epi32(a22, *(const V128*)oAllFrom2_0, rCGKD);    /* 7b cg */
        
        a20 = _mm_permutex2var_epi32(a00, *(const V128*)oAllFrom2_0, a13);      /* 81 59  */
        a21 = _mm_permutex2var_epi32(a13, *(const V128*)oAllFrom1_0, a22);        /* 926 a  */
        a23 = _mm_permutex2var_epi32(a22, *(const V128*)oAllFrom3_0, rCGKD);    /* b cgk */
        Dump("Roll-c", a);

        a00 = XOR( a00, LOAD_GATHER4_32(offsets, i32+0));
        a01 = XOR( a01, LOAD_GATHER4_32(offsets, i32+1));
        a02 = XOR( a02, LOAD_GATHER4_32(offsets, i32+2));
        a03 = XOR( a03, LOAD_GATHER4_32(offsets, i32+3));
        a12 = XOR( a12, LOAD_GATHER4_32(offsets, i32+4));
        a13 = XOR( a13, LOAD_GATHER4_32(offsets, i32+5));
        a10 = XOR( a10, LOAD_GATHER4_32(offsets, i32+6));
        a11 = XOR( a11, LOAD_GATHER4_32(offsets, i32+7));
        a20 = XOR( a20, LOAD_GATHER4_32(offsets, i32+8));
        a21 = XOR( a21, LOAD_GATHER4_32(offsets, i32+9));
        a22 = XOR( a22, LOAD_GATHER4_32(offsets, i32+10));
        a23 = XOR( a23, LOAD_GATHER4_32(offsets, i32+11));
        Dump("Input Xoodoo (after add)", a);

        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
        Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
        Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
        Dump("Output Xoodoo", a);

        x00 = XOR(x00, a00);
        x01 = XOR(x01, a01);
        x02 = XOR(x02, a02);
        x03 = XOR(x03, a03);
        x10 = XOR(x10, a10);
        x11 = XOR(x11, a11);
        x12 = XOR(x12, a12);
        x13 = XOR(x13, a13);
        x20 = XOR(x20, a20);
        x21 = XOR(x21, a21);
        x22 = XOR(x22, a22);
        x23 = XOR(x23, a23);
        Dump("Accu x", x);

        i32 += NLANES*4;
        length -= NLANES*4*4;
    }
    while (length >= (NLANES*4*4));

    /*    Reduce from 4 lanes to 2 */
    v1 = *(const V128*)oLow64;
    v2 = *(const V128*)oHigh64;
    x00 = XOR(_mm_permutex2var_epi32(x00, v1, x02), _mm_permutex2var_epi32(x00, v2, x02));
    x01 = XOR(_mm_permutex2var_epi32(x01, v1, x03), _mm_permutex2var_epi32(x01, v2, x03));
    x10 = XOR(_mm_permutex2var_epi32(x10, v1, x12), _mm_permutex2var_epi32(x10, v2, x12));
    x11 = XOR(_mm_permutex2var_epi32(x11, v1, x13), _mm_permutex2var_epi32(x11, v2, x13));
    x20 = XOR(_mm_permutex2var_epi32(x20, v1, x22), _mm_permutex2var_epi32(x20, v2, x22));
    x21 = XOR(_mm_permutex2var_epi32(x21, v1, x23), _mm_permutex2var_epi32(x21, v2, x23));

    /*    Reduce from 2 lanes to 1 */
    v1 = *(const V128*)oLow32;
    v2 = *(const V128*)oHigh32;
    x00 = XOR(_mm_permutex2var_epi32(x00, v1, x01), _mm_permutex2var_epi32(x00, v2, x01));
    x10 = XOR(_mm_permutex2var_epi32(x10, v1, x11), _mm_permutex2var_epi32(x10, v2, x11));
    x20 = XOR(_mm_permutex2var_epi32(x20, v1, x21), _mm_permutex2var_epi32(x20, v2, x21));

    /*    Combine x00 and x20 */
    x256 = _mm256_inserti128_si256 (_mm256_castsi128_si256(x00), x10, 1);

    /*    Combine (x00,x01) and x20 */
    x512 = _mm512_inserti64x4 (_mm512_castsi256_si512(x256), _mm256_castsi128_si256(x20), 1);

    /*  load xAccu, xor and store 12 lanes */
    x512 = XOR512(x512, _mm512_maskz_load_epi64(0x3F, x32));
    _mm512_mask_store_epi64(x32, 0x3F, x512);
    DUMP32_12("x32",x32);

    /* Save new k */
    _mm_i32scatter_epi32(k32, LOAD4_32( 0,  4,  8,  1), r0481, 4);
    _mm_i32scatter_epi32(k32, LOAD4_32( 5,  9,  2,  6), r5926, 4);
    _mm_i32scatter_epi32(k32, LOAD4_32(10,  3,  7, 11), ra37b, 4);
    DUMP32_12( "k32", k32);

    return initialLength - length;
}

size_t Xooffftimes4_AVX512_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    DeclareVars;
    const uint32_t *k32 = (const uint32_t*)kRoll;
    uint32_t       *y32 = (uint32_t*)yAccu;
    uint32_t       *o32 = (uint32_t*)output;
    size_t      initialLength;
    V128        r0481;
    V128        r5926;
    V128        ra37b;
    V128        offsets;

    r0481 = LOAD_GATHER4_32(LOAD4_32(  0,  4,  8,  1), y32);
    r5926 = LOAD_GATHER4_32(LOAD4_32(  5,  9,  2,  6), y32);
    ra37b = LOAD_GATHER4_32(LOAD4_32( 10,  3,  7, 11), y32);

    offsets = *(const V128*)oGatherScatterOffsets;

    initialLength = length;
    do {
        #define        rCGKD    ra37b

        /*    Note that a10-a12 and a11-a13 are swapped */
        a00 = r0481;
        a13 = r5926;
        a22 = ra37b;

        a12 = _mm_permutex2var_epi32(a00, *(const V128*)oAllFrom1_0, r5926);    /* 481 5 */
        a20 = _mm_permutex2var_epi32(a00, *(const V128*)oAllFrom2_0, a13);      /* 81 59  */

        r0481 = r5926;
        r5926 = ra37b;
        rCGKD = XOR3(ROL32(a00, 5), ROL32(a12, 13), AND(a20, a12));
        rCGKD = XOR(rCGKD, CONST4_32(7));

        a01 = _mm_permutex2var_epi32(a00, *(const V128*)oAllFrom3_0, a13);      /* 1 592 */
        a02 = _mm_permutex2var_epi32(a13, *(const V128*)oAllFrom2_0, a22);      /* 26 a3 */
        a03 = _mm_permutex2var_epi32(a22, *(const V128*)oAllFrom1_0, rCGKD);    /* 37b c */
            
        a10 = _mm_permutex2var_epi32(a13, *(const V128*)oAllFrom3_0, a22);      /* 6 a37 */
        a11 = _mm_permutex2var_epi32(a22, *(const V128*)oAllFrom2_0, rCGKD);    /* 7b cg */
        
        a21 = _mm_permutex2var_epi32(a13, *(const V128*)oAllFrom1_0, a22);      /* 926 a */
        a23 = _mm_permutex2var_epi32(a22, *(const V128*)oAllFrom3_0, rCGKD);    /* b cgk */
        Dump("Roll-e", a);

        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
        Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
        Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
        Dump("Xoodoo(y)", a);

        a00 = XOR(a00, CONST4_32(k32[0]));
        a01 = XOR(a01, CONST4_32(k32[1]));
        a02 = XOR(a02, CONST4_32(k32[2]));
        a03 = XOR(a03, CONST4_32(k32[3]));
        a10 = XOR(a10, CONST4_32(k32[4]));
        a11 = XOR(a11, CONST4_32(k32[5]));
        a12 = XOR(a12, CONST4_32(k32[6]));
        a13 = XOR(a13, CONST4_32(k32[7]));
        a20 = XOR(a20, CONST4_32(k32[8]));
        a21 = XOR(a21, CONST4_32(k32[9]));
        a22 = XOR(a22, CONST4_32(k32[10]));
        a23 = XOR(a23, CONST4_32(k32[11]));
        Dump("Xoodoo(y) + kRoll", a);

        /*  Extract */
        STORE_SCATTER4_32(offsets, a00, o32+0);
        STORE_SCATTER4_32(offsets, a01, o32+1);
        STORE_SCATTER4_32(offsets, a02, o32+2);
        STORE_SCATTER4_32(offsets, a03, o32+3);
        STORE_SCATTER4_32(offsets, a10, o32+4);
        STORE_SCATTER4_32(offsets, a11, o32+5);
        STORE_SCATTER4_32(offsets, a12, o32+6);
        STORE_SCATTER4_32(offsets, a13, o32+7);
        STORE_SCATTER4_32(offsets, a20, o32+8);
        STORE_SCATTER4_32(offsets, a21, o32+9);
        STORE_SCATTER4_32(offsets, a22, o32+10);
        STORE_SCATTER4_32(offsets, a23, o32+11);

        o32 += NLANES*4;
        length -= NLANES*4*4;
    }
    while (length >= (NLANES*4*4));

    /* Save new y */
    _mm_i32scatter_epi32(y32, LOAD4_32( 0,  4,  8,  1), r0481, 4);
    _mm_i32scatter_epi32(y32, LOAD4_32( 5,  9,  2,  6), r5926, 4);
    _mm_i32scatter_epi32(y32, LOAD4_32(10,  3,  7, 11), ra37b, 4);
    DUMP32_12( "y32", y32);

    return initialLength - length;
}
