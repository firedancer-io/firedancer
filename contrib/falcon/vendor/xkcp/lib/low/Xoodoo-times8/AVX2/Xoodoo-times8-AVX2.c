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
#include "Xoodoo-times8-AVX2.h"

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

typedef __m128i V128;
typedef __m256i V256;

#define SnP_laneLengthInBytes    4
#define laneIndex(instanceIndex, lanePosition) ((lanePosition)*8 + instanceIndex)

#define AND256(a, b)                _mm256_and_si256(a, b)
#define ANDnu256(a, b)              _mm256_andnot_si256(a, b)
#define CONST8_32(a)                _mm256_set1_epi32(a)
#define LOAD256(a)                  _mm256_load_si256((const V256 *)&(a))
#define LOAD256u(a)                 _mm256_loadu_si256((const V256 *)&(a))
#define LOAD8_32(a,b,c,d,e,f,g,h)   _mm256_setr_epi32(a,b,c,d,e,f,g,h)
#define LOAD_GATHER8_32(idx,p)      _mm256_i32gather_epi32((const int*)(p), idx, 4)

#define SHUFFLE_LANES_RIGHT(a, n)   _mm256_permutevar8x32_epi32(a, shuffleR_##n)
#define SHUFFLE_LANES_RIGHT_2(a)    _mm256_permute4x64_epi64(a, 0x39)
#define INSERT_LANE( a, val, n)     _mm256_insert_epi32(a, val, n)
#define EXTRACT_LANE( a, n)         _mm256_extract_epi32(a, n)
#define INSERT_2LANES( a, val, n)   _mm256_insert_epi64(a, val, (n)/2)
#define EXTRACT_2LANES( a, n)       _mm256_extract_epi64(a, (n)/2)


#define ROL32in256(a, o)            _mm256_or_si256(_mm256_slli_epi32(a, o), _mm256_srli_epi32(a, 32-(o)))
#define ROL32in256_8(a)             _mm256_shuffle_epi8(a, rho8)
#define SHL32in256(a, o)            _mm256_slli_epi32(a, o)

#define STORE128(a, b)              _mm_store_si128((V128 *)&(a), b)
#define STORE128u(a, b)             _mm_storeu_si128((V128 *)&(a), b)
#define STORE256(a, b)              _mm256_store_si256((V256 *)&(a), b)
#define STORE256u(a, b)             _mm256_storeu_si256((V256 *)&(a), b)

#define XOR256(a, b)                _mm256_xor_si256(a, b)
#define XOReq256(a, b)              a = XOR256(a, b)
#define XOR128(a, b)                _mm_xor_si128(a, b)
#define XOReq128(a, b)              a = XOR128(a, b)

#ifndef _mm256_storeu2_m128i
#define _mm256_storeu2_m128i(hi, lo, a)    _mm_storeu_si128((V128*)(lo), _mm256_castsi256_si128(a)), _mm_storeu_si128((V128*)(hi), _mm256_extracti128_si256(a, 1))
#endif

#define VERBOSE         0

#if (VERBOSE > 0)
    #define    Dump(__t,__v)    {                   \
                            uint32_t    buf[8];     \
                            printf("%s\n", __t);    \
                            STORE256(buf, __v##00); printf("00 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##01); printf("01 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##02); printf("02 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##03); printf("03 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##10); printf("10 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##11); printf("11 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##12); printf("12 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##13); printf("13 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##20); printf("20 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##21); printf("21 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##22); printf("22 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
                            STORE256(buf, __v##23); printf("23 %08x %08x %08x %08x %08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]); \
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

ALIGN(32) static const uint32_t    oshuffleR_1[] = {1, 2, 3, 4, 5, 6, 7, 0};
ALIGN(32) static const uint32_t    oshuffleR_3[] = {3, 4, 5, 6, 7, 0, 1, 2};
ALIGN(32) static const uint32_t    oshuffleR_5[] = {5, 6, 7, 0, 1, 2, 3, 4};
ALIGN(32) static const uint32_t    oshuffleR_7[] = {7, 0, 1, 2, 3, 4, 5, 6};
ALIGN(32) static const uint32_t    shufflePack[] = {0, 2, 4, 6, 1, 3, 5, 7};


void Xoodootimes8_AVX2_InitializeAll(Xoodootimes8_SIMD256_states *states)
{
    memset(states, 0, sizeof(Xoodootimes8_SIMD256_states));
}

void Xoodootimes8_AVX2_AddBytes(Xoodootimes8_SIMD256_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
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

void Xoodootimes8_AVX2_AddLanesAll(Xoodootimes8_SIMD256_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V256 *stateAsLanes = states->A;
    unsigned int i;
    const uint32_t *curData0 = (const uint32_t *)(data+laneOffset*0*SnP_laneLengthInBytes);
    const uint32_t *curData1 = (const uint32_t *)(data+laneOffset*1*SnP_laneLengthInBytes);
    const uint32_t *curData2 = (const uint32_t *)(data+laneOffset*2*SnP_laneLengthInBytes);
    const uint32_t *curData3 = (const uint32_t *)(data+laneOffset*3*SnP_laneLengthInBytes);
    const uint32_t *curData4 = (const uint32_t *)(data+laneOffset*4*SnP_laneLengthInBytes);
    const uint32_t *curData5 = (const uint32_t *)(data+laneOffset*5*SnP_laneLengthInBytes);
    const uint32_t *curData6 = (const uint32_t *)(data+laneOffset*6*SnP_laneLengthInBytes);
    const uint32_t *curData7 = (const uint32_t *)(data+laneOffset*7*SnP_laneLengthInBytes);

    #define Xor_In( argIndex )  XOReq256(stateAsLanes[argIndex], LOAD8_32(curData0[argIndex], curData1[argIndex], curData2[argIndex], curData3[argIndex], curData4[argIndex], curData5[argIndex], curData6[argIndex], curData7[argIndex]))

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

void Xoodootimes8_AVX2_OverwriteBytes(Xoodootimes8_SIMD256_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length)
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

void Xoodootimes8_AVX2_OverwriteLanesAll(Xoodootimes8_SIMD256_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    V256 *stateAsLanes = states->A;
    unsigned int i;
    const uint32_t *curData0 = (const uint32_t *)(data+laneOffset*0*SnP_laneLengthInBytes);
    const uint32_t *curData1 = (const uint32_t *)(data+laneOffset*1*SnP_laneLengthInBytes);
    const uint32_t *curData2 = (const uint32_t *)(data+laneOffset*2*SnP_laneLengthInBytes);
    const uint32_t *curData3 = (const uint32_t *)(data+laneOffset*3*SnP_laneLengthInBytes);
    const uint32_t *curData4 = (const uint32_t *)(data+laneOffset*4*SnP_laneLengthInBytes);
    const uint32_t *curData5 = (const uint32_t *)(data+laneOffset*5*SnP_laneLengthInBytes);
    const uint32_t *curData6 = (const uint32_t *)(data+laneOffset*6*SnP_laneLengthInBytes);
    const uint32_t *curData7 = (const uint32_t *)(data+laneOffset*7*SnP_laneLengthInBytes);

    #define OverWr( argIndex )  STORE256(stateAsLanes[argIndex], LOAD8_32(curData0[argIndex], curData1[argIndex], curData2[argIndex], curData3[argIndex], curData4[argIndex], curData5[argIndex], curData6[argIndex], curData7[argIndex]))

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

void Xoodootimes8_AVX2_OverwriteWithZeroes(Xoodootimes8_SIMD256_states *states, unsigned int instanceIndex, unsigned int byteCount)
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

void Xoodootimes8_AVX2_ExtractBytes(const Xoodootimes8_SIMD256_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
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

void Xoodootimes8_AVX2_ExtractLanesAll(const Xoodootimes8_SIMD256_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
{
    uint32_t *curData0 = (uint32_t *)(data+laneOffset*0*SnP_laneLengthInBytes);
    uint32_t *curData1 = (uint32_t *)(data+laneOffset*1*SnP_laneLengthInBytes);
    uint32_t *curData2 = (uint32_t *)(data+laneOffset*2*SnP_laneLengthInBytes);
    uint32_t *curData3 = (uint32_t *)(data+laneOffset*3*SnP_laneLengthInBytes);
    uint32_t *curData4 = (uint32_t *)(data+laneOffset*4*SnP_laneLengthInBytes);
    uint32_t *curData5 = (uint32_t *)(data+laneOffset*5*SnP_laneLengthInBytes);
    uint32_t *curData6 = (uint32_t *)(data+laneOffset*6*SnP_laneLengthInBytes);
    uint32_t *curData7 = (uint32_t *)(data+laneOffset*7*SnP_laneLengthInBytes);
    const uint32_t *stateAsLanes32 = (const uint32_t*)states->A;
    unsigned int i;

    #define Extr( argIndex )    curData0[argIndex] = stateAsLanes32[8*(argIndex)],      \
                                curData1[argIndex] = stateAsLanes32[8*(argIndex)+1],    \
                                curData2[argIndex] = stateAsLanes32[8*(argIndex)+2],    \
                                curData3[argIndex] = stateAsLanes32[8*(argIndex)+3],    \
                                curData4[argIndex] = stateAsLanes32[8*(argIndex)+4],    \
                                curData5[argIndex] = stateAsLanes32[8*(argIndex)+5],    \
                                curData6[argIndex] = stateAsLanes32[8*(argIndex)+6],    \
                                curData7[argIndex] = stateAsLanes32[8*(argIndex)+7]

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

void Xoodootimes8_AVX2_ExtractAndAddBytes(const Xoodootimes8_SIMD256_states *states, unsigned int instanceIndex, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
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

void Xoodootimes8_AVX2_ExtractAndAddLanesAll(const Xoodootimes8_SIMD256_states *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset)
{
    const uint32_t *curInput0 = (const uint32_t *)(input+laneOffset*0*SnP_laneLengthInBytes);
    const uint32_t *curInput1 = (const uint32_t *)(input+laneOffset*1*SnP_laneLengthInBytes);
    const uint32_t *curInput2 = (const uint32_t *)(input+laneOffset*2*SnP_laneLengthInBytes);
    const uint32_t *curInput3 = (const uint32_t *)(input+laneOffset*3*SnP_laneLengthInBytes);
    const uint32_t *curInput4 = (const uint32_t *)(input+laneOffset*4*SnP_laneLengthInBytes);
    const uint32_t *curInput5 = (const uint32_t *)(input+laneOffset*5*SnP_laneLengthInBytes);
    const uint32_t *curInput6 = (const uint32_t *)(input+laneOffset*6*SnP_laneLengthInBytes);
    const uint32_t *curInput7 = (const uint32_t *)(input+laneOffset*7*SnP_laneLengthInBytes);
    uint32_t *curOutput0 = (uint32_t *)(output+laneOffset*0*SnP_laneLengthInBytes);
    uint32_t *curOutput1 = (uint32_t *)(output+laneOffset*1*SnP_laneLengthInBytes);
    uint32_t *curOutput2 = (uint32_t *)(output+laneOffset*2*SnP_laneLengthInBytes);
    uint32_t *curOutput3 = (uint32_t *)(output+laneOffset*3*SnP_laneLengthInBytes);
    uint32_t *curOutput4 = (uint32_t *)(output+laneOffset*4*SnP_laneLengthInBytes);
    uint32_t *curOutput5 = (uint32_t *)(output+laneOffset*5*SnP_laneLengthInBytes);
    uint32_t *curOutput6 = (uint32_t *)(output+laneOffset*6*SnP_laneLengthInBytes);
    uint32_t *curOutput7 = (uint32_t *)(output+laneOffset*7*SnP_laneLengthInBytes);

    const uint32_t *stateAsLanes32 = (const uint32_t*)states->A;
    unsigned int i;

    #define ExtrXor( argIndex ) \
                                curOutput0[argIndex] = curInput0[argIndex] ^ stateAsLanes32[8*(argIndex)+0],\
                                curOutput1[argIndex] = curInput1[argIndex] ^ stateAsLanes32[8*(argIndex)+1],\
                                curOutput2[argIndex] = curInput2[argIndex] ^ stateAsLanes32[8*(argIndex)+2],\
                                curOutput3[argIndex] = curInput3[argIndex] ^ stateAsLanes32[8*(argIndex)+3],\
                                curOutput4[argIndex] = curInput4[argIndex] ^ stateAsLanes32[8*(argIndex)+4],\
                                curOutput5[argIndex] = curInput5[argIndex] ^ stateAsLanes32[8*(argIndex)+5],\
                                curOutput6[argIndex] = curInput6[argIndex] ^ stateAsLanes32[8*(argIndex)+6],\
                                curOutput7[argIndex] = curInput7[argIndex] ^ stateAsLanes32[8*(argIndex)+7]

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

#define DeclareVars     V256    a00, a01, a02, a03; \
                        V256    a10, a11, a12, a13; \
                        V256    a20, a21, a22, a23; \
                        V256    v1, v2;             \
                        V256    rho8 = LOAD8_32(0x02010003, 0x06050407, 0x0A09080B, 0x0E0D0C0F, 0x12111013, 0x16151417, 0x1A19181B, 0x1E1D1C1F)

#define State2Vars2     a00 = LOAD256(states[8*(0+0)]), a01 = LOAD256(states[8*(0+1)]), a02 = LOAD256(states[8*(0+2)]), a03 = LOAD256(states[8*(0+3)]); \
                        a12 = LOAD256(states[8*(4+0)]), a13 = LOAD256(states[8*(4+1)]), a10 = LOAD256(states[8*(4+2)]), a11 = LOAD256(states[8*(4+3)]); \
                        a20 = LOAD256(states[8*(8+0)]), a21 = LOAD256(states[8*(8+1)]), a22 = LOAD256(states[8*(8+2)]), a23 = LOAD256(states[8*(8+3)])

#define State2Vars      a00 = LOAD256(states[8*(0+0)]), a01 = LOAD256(states[8*(0+1)]), a02 = LOAD256(states[8*(0+2)]), a03 = LOAD256(states[8*(0+3)]); \
                        a10 = LOAD256(states[8*(4+0)]), a11 = LOAD256(states[8*(4+1)]), a12 = LOAD256(states[8*(4+2)]), a13 = LOAD256(states[8*(4+3)]); \
                        a20 = LOAD256(states[8*(8+0)]), a21 = LOAD256(states[8*(8+1)]), a22 = LOAD256(states[8*(8+2)]), a23 = LOAD256(states[8*(8+3)])

#define Vars2State      STORE256(states[8*(0+0)], a00), STORE256(states[8*(0+1)], a01), STORE256(states[8*(0+2)], a02), STORE256(states[8*(0+3)], a03); \
                        STORE256(states[8*(4+0)], a10), STORE256(states[8*(4+1)], a11), STORE256(states[8*(4+2)], a12), STORE256(states[8*(4+3)], a13); \
                        STORE256(states[8*(8+0)], a20), STORE256(states[8*(8+1)], a21), STORE256(states[8*(8+2)], a22), STORE256(states[8*(8+3)], a23)

#define Round(a10i, a11i, a12i, a13i, a10w, a11w, a12w, a13w, a20i, a21i, a22i, a23i, __rc) \
                                                            \
    /* Theta: Column Parity Mixer */                        \
    v1 = XOR256( a03, XOR256( a13i, a23i ) );               \
    v2 = XOR256( a00, XOR256( a10i, a20i ) );               \
    v1 = XOR256( ROL32in256(v1, 5), ROL32in256(v1, 14) );  \
    a00 = XOR256( a00, v1 );                                \
    a10i = XOR256( a10i, v1 );                              \
    a20i = XOR256( a20i, v1 );                              \
    v1 = XOR256( a01, XOR256( a11i, a21i ) );               \
    v2 = XOR256( ROL32in256(v2, 5), ROL32in256(v2, 14) );  \
    a01 = XOR256( a01, v2 );                                \
    a11i = XOR256( a11i, v2 );                              \
    a21i = XOR256( a21i, v2 );                              \
    v2 = XOR256( a02, XOR256( a12i, a22i ) );               \
    v1 = XOR256( ROL32in256(v1, 5), ROL32in256(v1, 14) );  \
    a02 = XOR256( a02, v1 );                                \
    a12i = XOR256( a12i, v1 );                              \
    a22i = XOR256( a22i, v1 );                              \
    v2 = XOR256( ROL32in256(v2, 5), ROL32in256(v2, 14) );  \
    a03 = XOR256( a03, v2 );                                \
    a13i = XOR256( a13i, v2 );                              \
    a23i = XOR256( a23i, v2 );                              \
    Dump3("Theta",a);                                       \
                                                            \
    /* Rho-west: Plane shift */                             \
    a20i = ROL32in256(a20i, 11);                            \
    a21i = ROL32in256(a21i, 11);                            \
    a22i = ROL32in256(a22i, 11);                            \
    a23i = ROL32in256(a23i, 11);                            \
    Dump3("Rho-west",a);                                    \
                                                            \
    /* Iota: round constants */                             \
    a00 = XOR256( a00, CONST8_32(__rc));                    \
    Dump3("Iota",a);                                        \
                                                            \
    /* Chi: non linear step, on colums */                   \
    a00 = XOR256( a00, ANDnu256( a10w, a20i ) );            \
    a01 = XOR256( a01, ANDnu256( a11w, a21i ) );            \
    a02 = XOR256( a02, ANDnu256( a12w, a22i ) );            \
    a03 = XOR256( a03, ANDnu256( a13w, a23i ) );            \
    a10w = XOR256( a10w, ANDnu256( a20i, a00 ) );           \
    a11w = XOR256( a11w, ANDnu256( a21i, a01 ) );           \
    a12w = XOR256( a12w, ANDnu256( a22i, a02 ) );           \
    a13w = XOR256( a13w, ANDnu256( a23i, a03 ) );           \
    a20i = XOR256( a20i, ANDnu256( a00, a10w ) );           \
    a21i = XOR256( a21i, ANDnu256( a01, a11w ) );           \
    a22i = XOR256( a22i, ANDnu256( a02, a12w ) );           \
    a23i = XOR256( a23i, ANDnu256( a03, a13w ) );           \
    Dump3("Chi",a);                                         \
                                                            \
    /* Rho-east: Plane shift */                             \
    a10w = ROL32in256(a10w, 1);                             \
    a11w = ROL32in256(a11w, 1);                             \
    a12w = ROL32in256(a12w, 1);                             \
    a13w = ROL32in256(a13w, 1);                             \
    a20i = ROL32in256_8(a20i);                              \
    a21i = ROL32in256_8(a21i);                              \
    a22i = ROL32in256_8(a22i);                              \
    a23i = ROL32in256_8(a23i);                              \
    Dump3("Rho-east",a)

void Xoodootimes8_AVX2_PermuteAll_6rounds(Xoodootimes8_SIMD256_states *argstates)
{
    uint32_t * states = (uint32_t *)argstates->A;
    DeclareVars;

    State2Vars2;
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
    Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
    Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
    Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
    Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
    //Dump1("Permutation\n", a);
    Vars2State;
}

void Xoodootimes8_AVX2_PermuteAll_12rounds(Xoodootimes8_SIMD256_states *argstates)
{
    uint32_t * states = (uint32_t *)argstates->A;
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
    //Dump1("Permutation\n", a);
    Vars2State;
}

void Xooffftimes8_AVX2_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen)
{
    size_t  byteLen = bitLen / 8;
    V256    lanes1, lanes2, lanes3, lanes4, lanes5, lanes6, lanes7, lanes8;

    while ( byteLen >= 128 ) {
        lanes1 = LOAD256u(input[ 0]);
        lanes2 = LOAD256u(input[32]);
        lanes3 = LOAD256u(input[64]);
        lanes4 = LOAD256u(input[96]);
        lanes5 = LOAD256u(output[ 0]);
        lanes6 = LOAD256u(output[32]);
        lanes7 = LOAD256u(output[64]);
        lanes8 = LOAD256u(output[96]);
        lanes1 = XOR256(lanes1, lanes5);
        lanes2 = XOR256(lanes2, lanes6);
        lanes3 = XOR256(lanes3, lanes7);
        lanes4 = XOR256(lanes4, lanes8);
        STORE256u(output[ 0], lanes1);
        STORE256u(output[32], lanes2);
        STORE256u(output[64], lanes3);
        STORE256u(output[96], lanes4);
        input += 128;
        output += 128;
        byteLen -= 128;
    }
    while ( byteLen >= 32 ) {
        lanes1 = LOAD256u(input[0]);
        lanes2 = LOAD256u(output[0]);
        input += 32;
        lanes1 = XOR256(lanes1, lanes2);
        byteLen -= 32;
        STORE256u(output[0], lanes1);
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

size_t Xooffftimes8_AVX2_CompressFastLoop(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length)
{
    DeclareVars;
    uint32_t       *k32 = (uint32_t*)k;
    uint32_t       *x32 = (uint32_t*)x;
    const uint32_t *i32 = (const uint32_t*)input;
    size_t      initialLength;
    V256        r04815926;
    V256        r5926a37b;
    V256        t;
    V256        x00, x01, x02, x03, x10, x11, x12, x13, x20, x21, x22, x23;
    V128        x4;
    V256        shuffleR_1 = *(const V256*)oshuffleR_1;
    V256        shuffleR_3 = *(const V256*)oshuffleR_3;
    V256        shuffleR_5 = *(const V256*)oshuffleR_5;
    V256        shuffleR_7 = *(const V256*)oshuffleR_7;

    r04815926 = LOAD_GATHER8_32(LOAD8_32( 0,  4,  8,  1,  5,  9,  2,  6), k32);
    r5926a37b = LOAD_GATHER8_32(LOAD8_32( 5,  9,  2,  6, 10,  3,  7, 11), k32);
    t = LOAD8_32( 0*12, 1*12, 2*12, 3*12, 4*12, 5*12, 6*12, 7*12);

    initialLength = length;

    /* Clear x accumulator */
    x00 = _mm256_setzero_si256();
    x01 = _mm256_setzero_si256();
    x02 = _mm256_setzero_si256();
    x03 = _mm256_setzero_si256();
    x10 = _mm256_setzero_si256();
    x11 = _mm256_setzero_si256();
    x12 = _mm256_setzero_si256();
    x13 = _mm256_setzero_si256();
    x20 = _mm256_setzero_si256();
    x21 = _mm256_setzero_si256();
    x22 = _mm256_setzero_si256();
    x23 = _mm256_setzero_si256();

    #define        rCGKDHLEI    r5926a37b
    #define        aCGKDHLEI    ((uint32_t*)&rCGKDHLEI)
    do {
        /*    Note that a10-a12 and a11-a13 are swapped */
        a00 = r04815926;
        a01 = _mm256_blend_epi32(SHUFFLE_LANES_RIGHT(r04815926, 3), SHUFFLE_LANES_RIGHT(r5926a37b, 7), 0xE0); /* 15926  */
        a02 = SHUFFLE_LANES_RIGHT_2(r5926a37b); /* 26a37b */

        a12 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a00, 1), EXTRACT_LANE(a01, 5), 7);       /* 4815926 A */

        rCGKDHLEI = XOR256(a00, XOR256(SHL32in256(a00, 13), ROL32in256(a12, 3)));

        a02 = _mm256_blend_epi32(a02, SHUFFLE_LANES_RIGHT_2(rCGKDHLEI), 0xC0);
        a03 = _mm256_blend_epi32(SHUFFLE_LANES_RIGHT(a02, 3), SHUFFLE_LANES_RIGHT(rCGKDHLEI, 5), 0xF8);

        a13 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a01, 1), EXTRACT_LANE(a02, 5), 7);       /* B */
        a10 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a02, 1), aCGKDHLEI[2], 7); /* K */
        a11 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a03, 1), aCGKDHLEI[5], 7); /* L */

        a20 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a12, 1), EXTRACT_LANE(a01, 6), 7);       /* 815926A+3 */
        a21 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a13, 1), aCGKDHLEI[0], 7); /* C */
        a22 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a10, 1), aCGKDHLEI[3], 7); /* D */
        a23 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a11, 1), aCGKDHLEI[6], 7); /* E */
        r04815926 = a22;
        Dump("Roll-c", a);

        a00 = XOR256( a00, LOAD_GATHER8_32(t, i32+0));
        a01 = XOR256( a01, LOAD_GATHER8_32(t, i32+1));
        a02 = XOR256( a02, LOAD_GATHER8_32(t, i32+2));
        a03 = XOR256( a03, LOAD_GATHER8_32(t, i32+3));

        a12 = XOR256( a12, LOAD_GATHER8_32(t, i32+4));
        a13 = XOR256( a13, LOAD_GATHER8_32(t, i32+5));
        a10 = XOR256( a10, LOAD_GATHER8_32(t, i32+6));
        a11 = XOR256( a11, LOAD_GATHER8_32(t, i32+7));

        a20 = XOR256( a20, LOAD_GATHER8_32(t, i32+8));
        a21 = XOR256( a21, LOAD_GATHER8_32(t, i32+9));
        a22 = XOR256( a22, LOAD_GATHER8_32(t, i32+10));
        a23 = XOR256( a23, LOAD_GATHER8_32(t, i32+11));
        Dump("Add input", a);

        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
        Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
        Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
        Dump("Xoodoo", a);

        x00 = XOR256(x00, a00);
        x01 = XOR256(x01, a01);
        x02 = XOR256(x02, a02);
        x03 = XOR256(x03, a03);
        x10 = XOR256(x10, a10);
        x11 = XOR256(x11, a11);
        x12 = XOR256(x12, a12);
        x13 = XOR256(x13, a13);
        x20 = XOR256(x20, a20);
        x21 = XOR256(x21, a21);
        x22 = XOR256(x22, a22);
        x23 = XOR256(x23, a23);
        Dump("Accu x", x);

        i32 += NLANES*8;
        length -= NLANES*4*8;
    }
    while (length >= (NLANES*4*8));

    /*    Reduce from 8 to 4 lanes (x00 - x13), reduce from 4 to 2 lanes (x20 - x23) */
    x00 = XOR256(x00, _mm256_permute4x64_epi64(x00, 0x4e));
    x01 = XOR256(x01, _mm256_permute4x64_epi64(x01, 0x4e));
    x02 = XOR256(x02, _mm256_permute4x64_epi64(x02, 0x4e));
    x03 = XOR256(x03, _mm256_permute4x64_epi64(x03, 0x4e));
    x10 = XOR256(x10, _mm256_permute4x64_epi64(x10, 0x4e));
    x11 = XOR256(x11, _mm256_permute4x64_epi64(x11, 0x4e));
    x12 = XOR256(x12, _mm256_permute4x64_epi64(x12, 0x4e));
    x13 = XOR256(x13, _mm256_permute4x64_epi64(x13, 0x4e));
    x20 = XOR256(x20, _mm256_permute4x64_epi64(x20, 0x4e));
    x21 = XOR256(x21, _mm256_permute4x64_epi64(x21, 0x4e));
    x22 = XOR256(x22, _mm256_permute4x64_epi64(x22, 0x4e));
    x23 = XOR256(x23, _mm256_permute4x64_epi64(x23, 0x4e));
    x00 = _mm256_permute2x128_si256( x00, x10, 0x20);
    x01 = _mm256_permute2x128_si256( x01, x11, 0x20);
    x02 = _mm256_permute2x128_si256( x02, x12, 0x20);
    x03 = _mm256_permute2x128_si256( x03, x13, 0x20);
    x20 = _mm256_permute2x128_si256( x20, x22, 0x20);
    x21 = _mm256_permute2x128_si256( x21, x23, 0x20);

    /*    Reduce from 4 to 2 lanes (x00 - x03), reduce from 2 to 1 lane (x20 - x21) */
    x00 = XOR256(x00, _mm256_permute4x64_epi64(x00, 0xB1));
    x01 = XOR256(x01, _mm256_permute4x64_epi64(x01, 0xB1));
    x02 = XOR256(x02, _mm256_permute4x64_epi64(x02, 0xB1));
    x03 = XOR256(x03, _mm256_permute4x64_epi64(x03, 0xB1));
    x20 = XOR256(x20, _mm256_permute4x64_epi64(x20, 0xB1));
    x21 = XOR256(x21, _mm256_permute4x64_epi64(x21, 0xB1));
    x00 = _mm256_blend_epi32( x00, x02, 0xCC);
    x01 = _mm256_blend_epi32( x01, x03, 0xCC);
    x20 = _mm256_blend_epi32( x20, x21, 0xCC);

    /*    Reduce from 2 to 1 lane (x00 - x01), 1 to half lane (x20) */
    x00 = XOR256(x00, SHUFFLE_LANES_RIGHT(x00, 1));
    x01 = XOR256(x01, SHUFFLE_LANES_RIGHT(x01, 1));
    x20 = XOR256(x20, SHUFFLE_LANES_RIGHT(x20, 1));
    x00 = _mm256_blend_epi32( x00, SHUFFLE_LANES_RIGHT(x01, 7), 0xAA);
    x20 = _mm256_permutevar8x32_epi32( x20, *(const V256*)shufflePack);

    x00 = XOR256(x00, *(V256*)&x32[0]);
    x4 = XOR128(_mm256_castsi256_si128(x20), *(const V128*)&x32[8]);

    STORE256u( *(V256*)&x32[0], x00);
    STORE128u( *(V128*)&x32[8], x4);

    /*    Save new k from r04815926 and rCGKDHLEI */
    k32[ 0] = _mm256_extract_epi32(r04815926, 0);
    k32[ 1] = _mm256_extract_epi32(r04815926, 3);
    k32[ 2] = _mm256_extract_epi32(rCGKDHLEI, 2); /* K */
    k32[ 3] = _mm256_extract_epi32(rCGKDHLEI, 5); /* L */
    k32[ 4] = _mm256_extract_epi32(r04815926, 1);
    k32[ 5] = _mm256_extract_epi32(rCGKDHLEI, 0); /* C */
    k32[ 6] = _mm256_extract_epi32(rCGKDHLEI, 3); /* D */
    k32[ 7] = _mm256_extract_epi32(rCGKDHLEI, 6); /* E */
    k32[ 8] = _mm256_extract_epi32(r04815926, 2);
    k32[ 9] = _mm256_extract_epi32(rCGKDHLEI, 1); /* G */
    k32[10] = _mm256_extract_epi32(rCGKDHLEI, 4); /* H */
    k32[11] = _mm256_extract_epi32(rCGKDHLEI, 7); /* I */
    #undef        rCGKDHLEI

    return initialLength - length;
}

size_t Xooffftimes8_AVX2_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    DeclareVars;
    const uint32_t  *k32 = (const uint32_t*)kRoll;
    uint32_t        *y32 = (uint32_t*)yAccu;
    uint32_t        *o32 = (uint32_t*)output;
    size_t      initialLength;
    V256        r04815926;
    V256        r5926a37b;
    V256        v3, v4;
    V256        shuffleR_1 = *(const V256*)oshuffleR_1;
    V256        shuffleR_3 = *(const V256*)oshuffleR_3;
    V256        shuffleR_5 = *(const V256*)oshuffleR_5;
    V256        shuffleR_7 = *(const V256*)oshuffleR_7;

    r04815926 = LOAD_GATHER8_32(LOAD8_32( 0,  4,  8,  1,  5,  9,  2,  6), y32);
    r5926a37b = LOAD_GATHER8_32(LOAD8_32( 5,  9,  2,  6, 10,  3,  7, 11), y32);

    initialLength = length;

    #define        rCGKDHLEI    r5926a37b
    #define        aCGKDHLEI    ((uint32_t*)&rCGKDHLEI)
    do {
        a00 = r04815926;
        a01 = _mm256_blend_epi32(SHUFFLE_LANES_RIGHT(r04815926, 3), SHUFFLE_LANES_RIGHT(r5926a37b, 7), 0xE0); /* 15926+A37 */
        a02 = SHUFFLE_LANES_RIGHT_2(r5926a37b); /* 26a37b+-- */

        a12 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a00, 1), EXTRACT_LANE(a01, 5), 7);       /* 4815926+A */
        a20 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a12, 1), EXTRACT_LANE(a01, 6), 7);       /* 815926A+3 */

        rCGKDHLEI = XOR256(ROL32in256(a00, 5), ROL32in256(a12, 13));
        rCGKDHLEI = XOR256(rCGKDHLEI, AND256(a20, a12));
        rCGKDHLEI = XOR256(rCGKDHLEI, CONST8_32(7));

        a02 = _mm256_blend_epi32(a02, SHUFFLE_LANES_RIGHT_2(rCGKDHLEI), 0xC0);
        a03 = _mm256_blend_epi32(SHUFFLE_LANES_RIGHT(a02, 3), SHUFFLE_LANES_RIGHT(rCGKDHLEI, 5), 0xF8);

        a13 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a01, 1), EXTRACT_LANE(a02, 5), 7);       /* B */
        a10 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a02, 1), aCGKDHLEI[2], 7); /* K */
        a11 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a03, 1), aCGKDHLEI[5], 7); /* L */

        a21 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a13, 1), aCGKDHLEI[0], 7); /* C */
        a22 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a10, 1), aCGKDHLEI[3], 7); /* D */
        a23 = INSERT_LANE(SHUFFLE_LANES_RIGHT(a11, 1), aCGKDHLEI[6], 7); /* E */
        r04815926 = a22;
        Dump("Roll-e", a);

        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc6 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc5 );
        Round(  a10, a11, a12, a13,    a13, a10, a11, a12,    a20, a21, a22, a23,    _rc4 );
        Round(  a13, a10, a11, a12,    a12, a13, a10, a11,    a22, a23, a20, a21,    _rc3 );
        Round(  a12, a13, a10, a11,    a11, a12, a13, a10,    a20, a21, a22, a23,    _rc2 );
        Round(  a11, a12, a13, a10,    a10, a11, a12, a13,    a22, a23, a20, a21,    _rc1 );
        Dump("Xoodoo(y)", a);

        a00 = XOR256(a00, CONST8_32(k32[0]));
        a01 = XOR256(a01, CONST8_32(k32[1]));
        a02 = XOR256(a02, CONST8_32(k32[2]));
        a03 = XOR256(a03, CONST8_32(k32[3]));
        a10 = XOR256(a10, CONST8_32(k32[4]));
        a11 = XOR256(a11, CONST8_32(k32[5]));
        a12 = XOR256(a12, CONST8_32(k32[6]));
        a13 = XOR256(a13, CONST8_32(k32[7]));
        a20 = XOR256(a20, CONST8_32(k32[8]));
        a21 = XOR256(a21, CONST8_32(k32[9]));
        a22 = XOR256(a22, CONST8_32(k32[10]));
        a23 = XOR256(a23, CONST8_32(k32[11]));
        Dump("Xoodoo(y) + kRoll", a);

        /*  Extract */
        #define    UNPACKL32(a, b)    _mm256_unpacklo_epi32(a, b)
        #define    UNPACKH32(a, b)    _mm256_unpackhi_epi32(a, b)
        #define    UNPACKL64(a, b)    _mm256_unpacklo_epi64(a, b)
        #define    UNPACKH64(a, b)    _mm256_unpackhi_epi64(a, b)
        #define    UNPACKL128(a, b)    _mm256_permute2x128_si256(a, b, 0x20)
        #define    UNPACKH128(a, b)    _mm256_permute2x128_si256(a, b, 0x31)
        #define    lanesL01 v1
        #define    lanesH01 v2
        #define    lanesL23 v3
        #define    lanesH23 v4
        
        lanesL01 = UNPACKL32( a00, a01 );
        lanesH01 = UNPACKH32( a00, a01 );
        lanesL23 = UNPACKL32( a02, a03 );
        lanesH23 = UNPACKH32( a02, a03 );
        a00 = UNPACKL64( lanesL01, lanesL23 );
        a01 = UNPACKH64( lanesL01, lanesL23 );
        a02 = UNPACKL64( lanesH01, lanesH23 );
        a03 = UNPACKH64( lanesH01, lanesH23 );

        lanesL01 = UNPACKL32( a10, a11 );
        lanesH01 = UNPACKH32( a10, a11 );
        lanesL23 = UNPACKL32( a12, a13 );
        lanesH23 = UNPACKH32( a12, a13 );
        a10 = UNPACKL64( lanesL01, lanesL23 );
        a11 = UNPACKH64( lanesL01, lanesL23 );
        a12 = UNPACKL64( lanesH01, lanesH23 );
        a13 = UNPACKH64( lanesH01, lanesH23 );

        lanesL01 = UNPACKL128( a00, a10 );
        lanesH01 = UNPACKH128( a00, a10 );
        lanesL23 = UNPACKL128( a01, a11 );
        lanesH23 = UNPACKH128( a01, a11 );
        STORE256u(o32[0*12+0], lanesL01);
        STORE256u(o32[4*12+0], lanesH01);
        STORE256u(o32[1*12+0], lanesL23);
        STORE256u(o32[5*12+0], lanesH23);
        
        lanesL01 = UNPACKL128( a02, a12 );
        lanesH01 = UNPACKH128( a02, a12 );
        lanesL23 = UNPACKL128( a03, a13 );
        lanesH23 = UNPACKH128( a03, a13 );
        STORE256u(o32[2*12+0], lanesL01);
        STORE256u(o32[6*12+0], lanesH01);
        STORE256u(o32[3*12+0], lanesL23);
        STORE256u(o32[7*12+0], lanesH23);
        
        lanesL01 = UNPACKL32( a20, a21 );
        lanesH01 = UNPACKH32( a20, a21 );
        lanesL23 = UNPACKL32( a22, a23 );
        lanesH23 = UNPACKH32( a22, a23 );
        a20 = UNPACKL64( lanesL01, lanesL23 );
        a21 = UNPACKH64( lanesL01, lanesL23 );
        a22 = UNPACKL64( lanesH01, lanesH23 );
        a23 = UNPACKH64( lanesH01, lanesH23 );
        _mm256_storeu2_m128i((__m128i*)(o32+4*12+8), (__m128i*)(o32+0*12+8), a20);
        _mm256_storeu2_m128i((__m128i*)(o32+5*12+8), (__m128i*)(o32+1*12+8), a21);
        _mm256_storeu2_m128i((__m128i*)(o32+6*12+8), (__m128i*)(o32+2*12+8), a22);
        _mm256_storeu2_m128i((__m128i*)(o32+7*12+8), (__m128i*)(o32+3*12+8), a23);
        Dump("shuffle", a);

        o32 += NLANES*8;
        length -= NLANES*4*8;
    }
    while (length >= (NLANES*4*8));

    /*    Save new y from r04815926 and rCGKDHLEI */
    y32[ 0] = _mm256_extract_epi32(r04815926, 0);
    y32[ 1] = _mm256_extract_epi32(r04815926, 3);
    y32[ 2] = _mm256_extract_epi32(rCGKDHLEI, 2); /* K */
    y32[ 3] = _mm256_extract_epi32(rCGKDHLEI, 5); /* L */
    y32[ 4] = _mm256_extract_epi32(r04815926, 1);
    y32[ 5] = _mm256_extract_epi32(rCGKDHLEI, 0); /* C */
    y32[ 6] = _mm256_extract_epi32(rCGKDHLEI, 3); /* D */
    y32[ 7] = _mm256_extract_epi32(rCGKDHLEI, 6); /* E */
    y32[ 8] = _mm256_extract_epi32(r04815926, 2);
    y32[ 9] = _mm256_extract_epi32(rCGKDHLEI, 1); /* G */
    y32[10] = _mm256_extract_epi32(rCGKDHLEI, 4); /* H */
    y32[11] = _mm256_extract_epi32(rCGKDHLEI, 7); /* I */
    #undef        rCGKDHLEI

    return initialLength - length;
}
