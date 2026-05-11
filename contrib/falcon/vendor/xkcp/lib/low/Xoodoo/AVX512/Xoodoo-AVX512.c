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

#define    VERBOSE    0

#include <stdio.h>
#include <string.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include "align.h"
#include "brg_endian.h"
#include "Xoodoo.h"
#include "Xoodoo-SnP.h"

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

#if (VERBOSE > 0)
    #define    Dump(__t)    Vars2State; \
                        printf(__t "\n"); \
                        printf("a00 %08x, a01 %08x, a02 %08x, a03 %08x\n", state[0+0], state[0+1], state[0+2], state[0+3] ); \
                        printf("a10 %08x, a11 %08x, a12 %08x, a13 %08x\n", state[4+0], state[4+1], state[4+2], state[4+3] ); \
                        printf("a20 %08x, a21 %08x, a22 %08x, a23 %08x\n\n", state[8+0], state[8+1], state[8+2], state[8+3] );

    #define    DumpLanes(__t, l0, l1, l2) { \
                        uint32_t buf[4]; \
                        printf(__t "\n"); \
                        STORE128u(buf[0], l0); printf("%08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3] ); \
                        STORE128u(buf[0], l1); printf("%08x %08x %08x %08x\n", buf[0], buf[1], buf[2], buf[3] ); \
                        STORE128u(buf[0], l2); printf("%08x %08x %08x %08x\n\n", buf[0], buf[1], buf[2], buf[3] ); }
#else
    #define    Dump(__t)
    #define    DumpLanes(__t, l0, l1, l2)
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


/* ---------------------------------------------------------------- */

void Xoodoo_AVX512_Initialize(Xoodoo_align128plain32_state *state)
{
    memset(state, 0, sizeof(Xoodoo_align128plain32_state));
}

/* ---------------------------------------------------------------- */

void Xoodoo_AVX512_AddBytes(Xoodoo_align128plain32_state *argState, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/4;
    unsigned int offsetInLane = offset%4;
    const unsigned char *curData = data;
    uint32_t *state = argState->A;

    state += lanePosition;
    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = 4 - offsetInLane;
        uint32_t lane = 0;
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        memcpy((unsigned char*)&lane + offsetInLane, curData, bytesInLane);
        *state++ ^= lane;
        sizeLeft -= bytesInLane;
        curData += bytesInLane;
    }

    while(sizeLeft >= 4) {
        *state++ ^= READ32_UNALIGNED( curData );
        sizeLeft -= 4;
        curData += 4;
    }

    if (sizeLeft > 0) {
        uint32_t lane = 0;
        memcpy(&lane, curData, sizeLeft);
        *state ^= lane;
    }
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_AVX512_OverwriteBytes(Xoodoo_align128plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy((unsigned char*)state+offset, data, length);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_AVX512_OverwriteWithZeroes(Xoodoo_align128plain32_state *state, unsigned int byteCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memset(state, 0, byteCount);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_AVX512_ExtractBytes(const Xoodoo_align128plain32_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, (const unsigned char*)state+offset, length);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_AVX512_ExtractAndAddBytes(const Xoodoo_align128plain32_state *argState, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset/4;
    unsigned int offsetInLane = offset%4;
    const unsigned char *curInput = input;
    unsigned char *curOutput = output;
    const uint32_t *state = argState->A;

    state += lanePosition;
    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = 4 - offsetInLane;
        uint32_t  lane = *state++ >> (offsetInLane * 8);
        if (bytesInLane > sizeLeft)
            bytesInLane = sizeLeft;
        sizeLeft -= bytesInLane;
        do {
            *curOutput++ = (*curInput++) ^ (unsigned char)lane;
            lane >>= 8;
        }
        while ( --bytesInLane != 0);
    }

    while(sizeLeft >= 4) {
        WRITE32_UNALIGNED( curOutput, READ32_UNALIGNED( curInput ) ^ *state++ );
        sizeLeft -= 4;
        curInput += 4;
        curOutput += 4;
    }

    if (sizeLeft > 0) {
        uint32_t  lane = *state;
        do {
            *curOutput++ = (*curInput++) ^ (unsigned char)lane;
            lane >>= 8;
        }
        while ( --sizeLeft != 0 );
    }
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

typedef __m128i V128;
typedef __m256i V256;
typedef __m512i V512;

ALIGN(16) static const uint8_t maskRhoEast2[16] = {
    11,  8,  9, 10,
    15, 12, 13, 14,
     3,  0,  1,  2,
     7,  4,  5,  6,
};

#define CONST128(a)             _mm_load_si128((const V128 *)&(a))
#define LOAD128(a)              _mm_load_si128((const V128 *)&(a))
#define LOAD128u(a)             _mm_loadu_si128((const V128 *)&(a))
#define LOAD4_32(a,b,c,d)       _mm_setr_epi32(a,b,c,d)
#define ROL32(a, o)             _mm_rol_epi32(a, o)
#define SHL32(a, o)             _mm_slli_epi32(a, o)
#define STORE128(a, b)          _mm_store_si128((V128 *)&(a), b)
#define STORE128u(a, b)         _mm_storeu_si128((V128 *)&(a), b)
#define AND(a, b)               _mm_and_si128(a, b)
#define XOR(a, b)               _mm_xor_si128(a, b)
#define XOR3(a,b,c)             _mm_ternarylogic_epi32(a,b,c,0x96)
#define Chi(a,b,c)              _mm_ternarylogic_epi32(a,b,c,0xD2)

#define LOAD256u(a)             _mm256_loadu_si256((const V256 *)&(a))
#define STORE256u(a, b)         _mm256_storeu_si256((V256 *)&(a), b)
#define XOR256(a, b)            _mm256_xor_si256(a, b)

#define LOAD512u(a)             _mm512_loadu_si512((const V512 *)&(a))
#define STORE512u(a, b)         _mm512_storeu_si512((V512 *)&(a), b)
#define XOR512(a, b)            _mm512_xor_si512(a, b)

#define DeclareVars             V128    a0, a1, a2, p, e, rhoEast2 = CONST128(maskRhoEast2);
#define State2Vars              a0 = LOAD128(state->A[0]), a1 = LOAD128(state->A[4]), a2 = LOAD128(state->A[8]);
#define Vars2State              STORE128(state->A[0], a0), STORE128(state->A[4], a1), STORE128(state->A[8], a2);

#define Round(__rc)                                                             \
                        /* Theta: Column Parity Mixer */                        \
                        p = XOR3( a0, a1, a2 );                                 \
                        p = _mm_shuffle_epi32( p, 0x93);                        \
                        e = ROL32( p, 5 );                                      \
                        p = ROL32( p, 14 );                                     \
                        a0 = XOR3( a0, e, p);                                   \
                        a1 = XOR3( a1, e, p);                                   \
                        a2 = XOR3( a2, e, p);                                   \
                        Dump3("Theta");                                         \
                                                                                \
                        /* Rho-west: Plane shift */                             \
                        a1 = _mm_shuffle_epi32( a1, 0x93);                      \
                        a2 = ROL32(a2, 11);                                     \
                        Dump3("Rho-west");                                      \
                                                                                \
                        /* Iota: round constants */                             \
                        a0 = XOR(a0, _mm_set_epi32(0, 0, 0, (__rc)));           \
                        Dump3("Iota");                                          \
                                                                                \
                        /* Chi: non linear step, on colums */                   \
                        a0 = Chi(a0, a1, a2);                                   \
                        a1 = Chi(a1, a2, a0);                                   \
                        a2 = Chi(a2, a0, a1);                                   \
                        Dump3("Chi");                                           \
                                                                                \
                        /* Rho-east: Plane shift */                             \
                        a1 = ROL32(a1, 1);                                      \
                        a2 = _mm_shuffle_epi8( a2, rhoEast2);                   \
                        Dump3("Rho-east")

static const uint32_t    RC[MAXROUNDS] = {
    _rc12,
    _rc11,
    _rc10,
    _rc9,
    _rc8,
    _rc7,
    _rc6,
    _rc5,
    _rc4,
    _rc3,
    _rc2,
    _rc1
};

void Xoodoo_AVX512_Permute_Nrounds(Xoodoo_align128plain32_state *state, unsigned int nr)
{
    DeclareVars;
    uint32_t    i;

    State2Vars;
    for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i ) {
        Round(RC[i]);
        Dump2("Round");
    }
    Dump1("Permutation");
    Vars2State;
}

void Xoodoo_AVX512_Permute_6rounds(Xoodoo_align128plain32_state *state)
{
    DeclareVars;

    State2Vars;
    Round(_rc6);
    Round(_rc5);
    Round(_rc4);
    Round(_rc3);
    Round(_rc2);
    Round(_rc1);
    Dump2("Permutation");
    Vars2State;
}

void Xoodoo_AVX512_Permute_12rounds(Xoodoo_align128plain32_state *state)
{
    DeclareVars;

    State2Vars;
    Round(_rc12);
    Round(_rc11);
    Round(_rc10);
    Round(_rc9);
    Round(_rc8);
    Round(_rc7);
    Round(_rc6);
    Round(_rc5);
    Round(_rc4);
    Round(_rc3);
    Round(_rc2);
    Round(_rc1);
    Dump2("Permutation");
    Vars2State;
}

void Xoofff_AVX512_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen)
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

size_t Xoofff_AVX512_CompressFastLoop(unsigned char *kRoll, unsigned char *xAccu, const unsigned char *input, size_t length)
{
    DeclareVars;
    V128    r0, r1, r2;
    V128    x0, x1, x2;
    V128    rr = LOAD4_32(1, 2, 3, 4+0);
    size_t  initialLength = length;

    r0 = LOAD128(kRoll[0]);
    r1 = LOAD128(kRoll[4*4]);
    r2 = LOAD128(kRoll[8*4]);

    x0 = LOAD128(xAccu[0]);
    x1 = LOAD128(xAccu[4*4]);
    x2 = LOAD128(xAccu[8*4]);

    do {
        a0 = XOR( r0, LOAD128u(input[0]));
        a1 = XOR( r1, LOAD128u(input[4*4]));
        a2 = XOR( r2, LOAD128u(input[8*4]));

        DumpLanes("iperm", a0, a1, a2);
        Round(_rc6);
        Round(_rc5);
        Round(_rc4);
        Round(_rc3);
        Round(_rc2);
        Round(_rc1);
        DumpLanes("operm", a0, a1, a2);

        x0 = XOR(x0, a0);
        x1 = XOR(x1, a1);
        x2 = XOR(x2, a2);
        DumpLanes("xAccu", x0, x1, x2);

        /* roll-c */
        p = XOR3( r0, SHL32(r0, 13), ROL32(r1, 3)); 
        p = _mm_permutex2var_epi32(r0, rr, p);
        r0 = r1;
        r1 = r2;
        r2 = p;
        DumpLanes("rollc", r0, r1, r2);

        input += NLANES*4;
        length -= NLANES*4;
    }
    while (length >= (NLANES*4));

    STORE128(kRoll[0], r0);
    STORE128(kRoll[4*4], r1);
    STORE128(kRoll[8*4], r2);

    STORE128(xAccu[0], x0);
    STORE128(xAccu[4*4], x1);
    STORE128(xAccu[8*4], x2);

    return initialLength - length;
}

size_t Xoofff_AVX512_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    DeclareVars;
    V128    r0, r1, r2;
    V128    k0, k1, k2;
    V128    rr = LOAD4_32(1, 2, 3, 4+0);
    V128    c7 = LOAD4_32(7, 0, 0, 0);
    size_t  initialLength = length;

    r0 = LOAD128(yAccu[0]);
    r1 = LOAD128(yAccu[4*4]);
    r2 = LOAD128(yAccu[8*4]);

    k0 = LOAD128(kRoll[0]);
    k1 = LOAD128(kRoll[4*4]);
    k2 = LOAD128(kRoll[8*4]);

    do {
        a0 = r0;
        a1 = r1;
        a2 = r2;

        DumpLanes("iperm", a0, a1, a2);
        Round(_rc6);
        Round(_rc5);
        Round(_rc4);
        Round(_rc3);
        Round(_rc2);
        Round(_rc1);
        DumpLanes("operm", a0, a1, a2);

        STORE128u(output[0],   XOR(k0, a0));
        STORE128u(output[4*4], XOR(k1, a1));
        STORE128u(output[8*4], XOR(k2, a2));

        /* roll-e */
        p = XOR3( ROL32(r0, 5), ROL32(r1, 13), AND(r2, r1)); 
        p = XOR( p, c7); 
        p = _mm_permutex2var_epi32(r0, rr, p);
        r0 = r1;
        r1 = r2;
        r2 = p;
        DumpLanes("rolle", r0, r1, r2);

        output += NLANES*4;
        length -= NLANES*4;
    } while (length >= (NLANES*4));

    STORE128(yAccu[0], r0);
    STORE128(yAccu[4*4], r1);
    STORE128(yAccu[8*4], r2);

    return initialLength - length;
}
