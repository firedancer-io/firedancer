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
#include <emmintrin.h>
#include "align.h"
#include "brg_endian.h"
#include "Xoodoo.h"
#include "Xoodoo-times4-SSSE3.h"

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

#define VERBOSE 0

#define    SnP_laneLengthInBytes    4
#define laneIndex(instanceIndex, lanePosition) ((lanePosition)*4 + instanceIndex)

#define ANDnu128(a, b)              _mm_andnot_si128(a, b)
#define LOAD128(a)                  _mm_load_si128((const V128 *)&(a))
#define LOAD4_32(a,b,c,d)           _mm_setr_epi32(a,b,c,d)
#if defined(Waffel_useXOP)
    #define ROL32in128(a, o)    _mm_roti_epi32(a, o)
//        #define ROL32in128_8(a)     ROL32in128(a, 8)
#else
    #define ROL32in128(a, o)        _mm_or_si128(_mm_slli_epi32(a, o), _mm_srli_epi32(a, 32-(o)))
//        #define ROL32in128_8(a)     _mm_shuffle_epi8(a, CONST128(rho8))
//static const uint64_t rho8[2] = {0x0605040302010007, 0x0E0D0C0B0A09080F};
#endif
#define STORE128(a, b)              _mm_store_si128((V128 *)&(a), b)
#if defined(__SSE41__) || defined(__SSE4_1__)
#define STORE4_32(r, a, b, c, d)    a = _mm_extract_epi32(r, 0), b = _mm_extract_epi32(r, 1), c = _mm_extract_epi32(r, 2), d = _mm_extract_epi32(r, 3)
#else
#define STORE4_32(r, a, b, c, d)    a = _mm_cvtsi128_si32(r), b = _mm_cvtsi128_si32(_mm_srli_si128(r,4)), c = _mm_cvtsi128_si32(_mm_srli_si128(r,8)), d = _mm_cvtsi128_si32(_mm_srli_si128(r,12))
#endif
#define XOR128(a, b)                _mm_xor_si128(a, b)
#define XOReq128(a, b)              a = XOR128(a, b)

#if (VERBOSE > 0)
    #define    Dump(__t)    printf(__t "\n");    \
                            Vars2State;          \
                            printf("a00 %08x, a01 %08x, a02 %08x, a03 %08x\n",   states[4*(0+0)], states[4*(0+1)], states[4*(0+2)], states[4*(0+3)] ); \
                            printf("a10 %08x, a11 %08x, a12 %08x, a13 %08x\n",   states[4*(4+0)], states[4*(4+1)], states[4*(4+2)], states[4*(4+3)] ); \
                            printf("a20 %08x, a21 %08x, a22 %08x, a23 %08x\n\n", states[4*(8+0)], states[4*(8+1)], states[4*(8+2)], states[4*(8+3)] );
#else
    #define    Dump(__t)
#endif

#if (VERBOSE >= 1)
    #define    Dump1(__t)    Dump(__t)
#else
    #define    Dump1(__t)
#endif

#if (VERBOSE >= 2)
    #define    Dump2(__t)    Dump(__t)
#else
    #define    Dump2(__t)
#endif

#if (VERBOSE >= 3)
    #define    Dump3(__t)    Dump(__t)
#else
    #define    Dump3(__t)
#endif

void Xoodootimes4_SSSE3_InitializeAll(Xoodootimes4_SIMD128_states *states)
{
    memset(states, 0, sizeof(Xoodootimes4_SIMD128_states));
}

void Xoodootimes4_SSSE3_AddBytes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
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

void Xoodootimes4_SSSE3_AddLanesAll(Xoodootimes4_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes = states->A;
    unsigned int i;
    const uint32_t *curData0 = (const uint32_t *)(data+0*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curData1 = (const uint32_t *)(data+1*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curData2 = (const uint32_t *)(data+2*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curData3 = (const uint32_t *)(data+3*laneOffset*SnP_laneLengthInBytes);
    #define XOR_In( argIndex )  XOReq128( stateAsLanes[argIndex], LOAD4_32(curData0[argIndex], curData1[argIndex], curData2[argIndex], curData3[argIndex]))
    if ( laneCount == 12 )  {
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
    }
    else {
        for(i=0; i<laneCount; i++)
            XOR_In( i );
    }
    #undef  XOR_In
}

void Xoodootimes4_SSSE3_OverwriteBytes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
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

void Xoodootimes4_SSSE3_OverwriteLanesAll(Xoodootimes4_SIMD128_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V128 *stateAsLanes = states->A;
    unsigned int i;
    const uint32_t *curData0 = (const uint32_t *)(data+0*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curData1 = (const uint32_t *)(data+1*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curData2 = (const uint32_t *)(data+2*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curData3 = (const uint32_t *)(data+3*laneOffset*SnP_laneLengthInBytes);
    #define OverWr( argIndex )  STORE128(stateAsLanes[argIndex], LOAD4_32(curData0[argIndex], curData1[argIndex], curData2[argIndex], curData3[argIndex]))
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

void Xoodootimes4_SSSE3_OverwriteWithZeroes(Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, unsigned int byteCount)
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

void Xoodootimes4_SSSE3_ExtractBytes(const Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
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

void Xoodootimes4_SSSE3_ExtractLanesAll(const Xoodootimes4_SIMD128_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    const V128 *stateAsLanes = states->A;
    V128 lanes;
    unsigned int i;
    uint32_t *curData0 = (uint32_t *)(data+0*laneOffset*SnP_laneLengthInBytes);
    uint32_t *curData1 = (uint32_t *)(data+1*laneOffset*SnP_laneLengthInBytes);
    uint32_t *curData2 = (uint32_t *)(data+2*laneOffset*SnP_laneLengthInBytes);
    uint32_t *curData3 = (uint32_t *)(data+3*laneOffset*SnP_laneLengthInBytes);

    #define Extr( argIndex )    lanes = LOAD128( stateAsLanes[argIndex] ),          \
                                STORE4_32(lanes, curData0[argIndex], curData1[argIndex], curData2[argIndex], curData3[argIndex])

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

void Xoodootimes4_SSSE3_ExtractAndAddBytes(const Xoodootimes4_SIMD128_states *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
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

void Xoodootimes4_SSSE3_ExtractAndAddLanesAll(const Xoodootimes4_SIMD128_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    const uint32_t *stateAsLanes = (const uint32_t *)states->A;
    unsigned int i;
    const uint32_t *curInput0 = (const uint32_t *)(input+0*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curInput1 = (const uint32_t *)(input+1*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curInput2 = (const uint32_t *)(input+2*laneOffset*SnP_laneLengthInBytes);
    const uint32_t *curInput3 = (const uint32_t *)(input+3*laneOffset*SnP_laneLengthInBytes);
    uint32_t *curOutput0 = (uint32_t *)(output+0*laneOffset*SnP_laneLengthInBytes);
    uint32_t *curOutput1 = (uint32_t *)(output+1*laneOffset*SnP_laneLengthInBytes);
    uint32_t *curOutput2 = (uint32_t *)(output+2*laneOffset*SnP_laneLengthInBytes);
    uint32_t *curOutput3 = (uint32_t *)(output+3*laneOffset*SnP_laneLengthInBytes);

    #define ExtrXOR( argIndex )    curOutput0[argIndex] = curInput0[argIndex] ^ stateAsLanes[4*(argIndex)+0], curOutput1[argIndex] = curInput1[argIndex] ^ stateAsLanes[4*(argIndex)+1], \
                                curOutput2[argIndex] = curInput2[argIndex] ^ stateAsLanes[4*(argIndex)+2], curOutput3[argIndex] = curInput3[argIndex] ^ stateAsLanes[4*(argIndex)+3]

    if ( laneCount == 12 )  {
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
    }
    else {
        for(i=0; i<laneCount; i++)
            ExtrXOR( i );
    }
    #undef  ExtrXOR
}

#define DeclareVars     V128    a00, a01, a02, a03; \
                        V128    a10, a11, a12, a13; \
                        V128    a20, a21, a22, a23; \
                        V128    v1, v2

#define State2Vars      a00 = LOAD128(states[4*(0+0)]), a01 = LOAD128(states[4*(0+1)]), a02 = LOAD128(states[4*(0+2)]), a03 = LOAD128(states[4*(0+3)]); \
                        a10 = LOAD128(states[4*(4+0)]), a11 = LOAD128(states[4*(4+1)]), a12 = LOAD128(states[4*(4+2)]), a13 = LOAD128(states[4*(4+3)]); \
                        a20 = LOAD128(states[4*(8+0)]), a21 = LOAD128(states[4*(8+1)]), a22 = LOAD128(states[4*(8+2)]), a23 = LOAD128(states[4*(8+3)])

#define State2Vars2     a00 = LOAD128(states[4*(0+0)]), a01 = LOAD128(states[4*(0+1)]), a02 = LOAD128(states[4*(0+2)]), a03 = LOAD128(states[4*(0+3)]); \
                        a12 = LOAD128(states[4*(4+0)]), a13 = LOAD128(states[4*(4+1)]), a10 = LOAD128(states[4*(4+2)]), a11 = LOAD128(states[4*(4+3)]); \
                        a20 = LOAD128(states[4*(8+0)]), a21 = LOAD128(states[4*(8+1)]), a22 = LOAD128(states[4*(8+2)]), a23 = LOAD128(states[4*(8+3)])

#define Vars2State      STORE128(states[4*(0+0)], a00), STORE128(states[4*(0+1)], a01), STORE128(states[4*(0+2)], a02), STORE128(states[4*(0+3)], a03); \
                        STORE128(states[4*(4+0)], a10), STORE128(states[4*(4+1)], a11), STORE128(states[4*(4+2)], a12), STORE128(states[4*(4+3)], a13); \
                        STORE128(states[4*(8+0)], a20), STORE128(states[4*(8+1)], a21), STORE128(states[4*(8+2)], a22), STORE128(states[4*(8+3)], a23)

#define Round(a10i, a11i, a12i, a13i, a10w, a11w, a12w, a13w, a20i, a21i, a22i, a23i, __rc) \
                                                            \
    /* Theta: Column Parity Mixer */                        \
    v1 = XOR128( a03, XOR128( a13i, a23i ) );               \
    v2 = XOR128( a00, XOR128( a10i, a20i ) );               \
    v1 = XOR128( ROL32in128(v1, 5), ROL32in128(v1, 14) );  \
    a00 = XOR128( a00, v1 );                                \
    a10i = XOR128( a10i, v1 );                              \
    a20i = XOR128( a20i, v1 );                              \
    v1 = XOR128( a01, XOR128( a11i, a21i ) );               \
    v2 = XOR128( ROL32in128(v2, 5), ROL32in128(v2, 14) );  \
    a01 = XOR128( a01, v2 );                                \
    a11i = XOR128( a11i, v2 );                              \
    a21i = XOR128( a21i, v2 );                              \
    v2 = XOR128( a02, XOR128( a12i, a22i ) );               \
    v1 = XOR128( ROL32in128(v1, 5), ROL32in128(v1, 14) );  \
    a02 = XOR128( a02, v1 );                                \
    a12i = XOR128( a12i, v1 );                              \
    a22i = XOR128( a22i, v1 );                              \
    v2 = XOR128( ROL32in128(v2, 5), ROL32in128(v2, 14) );  \
    a03 = XOR128( a03, v2 );                                \
    a13i = XOR128( a13i, v2 );                              \
    a23i = XOR128( a23i, v2 );                              \
    Dump3("Theta");                                         \
                                                            \
    /* Rho-west: Plane shift */                             \
    a20i = ROL32in128(a20i, 11);                            \
    a21i = ROL32in128(a21i, 11);                            \
    a22i = ROL32in128(a22i, 11);                            \
    a23i = ROL32in128(a23i, 11);                            \
    Dump3("Rho-west");                                      \
                                                            \
    /* Iota: round constants */                             \
    a00 = XOR128( a00, _mm_set1_epi32( __rc ) );            \
    Dump3("Iota");                                          \
                                                            \
    /* Chi: non linear step, on colums */                   \
    a00 = XOR128( a00, ANDnu128( a10w, a20i ) );            \
    a01 = XOR128( a01, ANDnu128( a11w, a21i ) );            \
    a02 = XOR128( a02, ANDnu128( a12w, a22i ) );            \
    a03 = XOR128( a03, ANDnu128( a13w, a23i ) );            \
    a10w = XOR128( a10w, ANDnu128( a20i, a00 ) );           \
    a11w = XOR128( a11w, ANDnu128( a21i, a01 ) );           \
    a12w = XOR128( a12w, ANDnu128( a22i, a02 ) );           \
    a13w = XOR128( a13w, ANDnu128( a23i, a03 ) );           \
    a20i = XOR128( a20i, ANDnu128( a00, a10w ) );           \
    a21i = XOR128( a21i, ANDnu128( a01, a11w ) );           \
    a22i = XOR128( a22i, ANDnu128( a02, a12w ) );           \
    a23i = XOR128( a23i, ANDnu128( a03, a13w ) );           \
    Dump3("Chi");                                           \
                                                            \
    /* Rho-east: Plane shift */                             \
    a10w = ROL32in128(a10w, 1);                             \
    a11w = ROL32in128(a11w, 1);                             \
    a12w = ROL32in128(a12w, 1);                             \
    a13w = ROL32in128(a13w, 1);                             \
    /* todo!! optimization for ROTL multiple of 8  */       \
    a20i = ROL32in128(a20i, 8);                             \
    a21i = ROL32in128(a21i, 8);                             \
    a22i = ROL32in128(a22i, 8);                             \
    a23i = ROL32in128(a23i, 8);                             \
    Dump3("Rho-east");

void Xoodootimes4_SSSE3_PermuteAll_6rounds(Xoodootimes4_SIMD128_states *argStates)
{
    uint32_t *states = (uint32_t*)argStates->A;
    DeclareVars;

    State2Vars2;
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
    Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
    Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
    Dump1("Permutation\n");
    Vars2State;
}

void Xoodootimes4_SSSE3_PermuteAll_12rounds(Xoodootimes4_SIMD128_states *argStates)
{
    uint32_t *states = (uint32_t*)argStates->A;
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
    Dump1("Permutation\n");
    Vars2State;
}
