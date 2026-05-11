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
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>
#include <pmmintrin.h>
#include <tmmintrin.h>
#include "align.h"
#include "Xoodoo.h"
#include "Xoodoo-SSSE3.h"

#include "brg_endian.h"
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
#error Expecting a little-endian platform
#endif

#if (VERBOSE > 0)
    #define    Dump(__t)    Vars2State; \
                        printf(__t "\n"); \
                        printf("a00 %08x, a01 %08x, a02 %08x, a03 %08x\n", state[0+0], state[0+1], state[0+2], state[0+3] ); \
                        printf("a10 %08x, a11 %08x, a12 %08x, a13 %08x\n", state[4+0], state[4+1], state[4+2], state[4+3] ); \
                        printf("a20 %08x, a21 %08x, a22 %08x, a23 %08x\n\n", state[8+0], state[8+1], state[8+2], state[8+3] );
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


/* ---------------------------------------------------------------- */

void Xoodoo_SSSE3_Initialize(Xoodoo_align128plain32_state *state)
{
    memset(state, 0, NLANES*sizeof(tXoodooLane));
}

/* ---------------------------------------------------------------- */

void Xoodoo_SSSE3_AddBytes(Xoodoo_align128plain32_state *argState, const unsigned char *data, unsigned int offset, unsigned int length)
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

void Xoodoo_SSSE3_OverwriteBytes(Xoodoo_align128plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy((unsigned char*)state+offset, data, length);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_SSSE3_OverwriteWithZeroes(Xoodoo_align128plain32_state *state, unsigned int byteCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memset(state, 0, byteCount);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_SSSE3_ExtractBytes(const Xoodoo_align128plain32_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, (const unsigned char*)state+offset, length);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_SSSE3_ExtractAndAddBytes(const Xoodoo_align128plain32_state *argState, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
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

ALIGN(16) static const uint8_t maskRhoEast2[16] = {
    11,  8,  9, 10,
    15, 12, 13, 14,
     3,  0,  1,  2,
     7,  4,  5,  6,
};

#define ANDnu128(a, b)          _mm_andnot_si128(a, b)
#define CONST128(a)             _mm_load_si128((const V128 *)&(a))
#define LOAD128(a)              _mm_load_si128((const V128 *)&(a))
#if defined(Waffel_useXOP)
    #define ROL32in128(a, o)    _mm_roti_epi32(a, o)
#else
    #define ROL32in128(a, o)    _mm_or_si128(_mm_slli_epi32(a, o), _mm_srli_epi32(a, 32-(o)))
#endif
#define STORE128(a, b)          _mm_store_si128((V128 *)&(a), b)
#define XOR128(a, b)            _mm_xor_si128(a, b)

#define    DeclareVars          V128    a0, a1, a2, p, e; \
                                V128    rhoEast2 = CONST128(maskRhoEast2)

#define    State2Vars           a0 = LOAD128(state->A[0]), a1 = LOAD128(state->A[4]), a2 = LOAD128(state->A[8]);

#define    Vars2State           STORE128(state->A[0], a0), STORE128(state->A[4], a1), STORE128(state->A[8], a2);

/*
** Theta: Column Parity Mixer
*/
#define    Theta()      p = XOR128( a0, a1 );               \
                        p = XOR128(  p, a2 );               \
                        p = _mm_shuffle_epi32( p, 0x93);    \
                        e = ROL32in128( p, 5 );             \
                        p = ROL32in128( p, 14 );            \
                        e =  XOR128( e, p );                \
                        a0 = XOR128( a0, e );               \
                        a1 = XOR128( a1, e );               \
                        a2 = XOR128( a2, e );

/*
** Rho-west: Plane shift
*/
#define    Rho_west()   a1 = _mm_shuffle_epi32( a1, 0x93);  \
                        a2 = ROL32in128(a2, 11);

/*
** Iota: round constants
*/
#define    Iota(__rc)   a0 = XOR128(a0, _mm_set_epi32(0, 0, 0, (__rc)));

/*
** Chi: non linear step, on colums
*/
#define    Chi()        a0 = XOR128(a0, ANDnu128(a1, a2)); \
                        a1 = XOR128(a1, ANDnu128(a2, a0)); \
                        a2 = XOR128(a2, ANDnu128(a0, a1));

/*
** Rho-east: Plane shift
*/
#define    Rho_east()   a1 = ROL32in128(a1, 1); \
                        a2 = _mm_shuffle_epi8( a2, rhoEast2);


#define    Round(__rc)                          \
                        Theta();                \
                        Dump3("Theta");         \
                        Rho_west();             \
                        Dump3("Rho-west");      \
                        Iota(__rc);             \
                        Dump3("Iota");          \
                        Chi();                  \
                        Dump3("Chi");           \
                        Rho_east();             \
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

void Xoodoo_SSSE3_Permute_Nrounds(Xoodoo_align128plain32_state *state, unsigned int nr)
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

void Xoodoo_SSSE3_Permute_6rounds(Xoodoo_align128plain32_state *state)
{
    DeclareVars;

    State2Vars;
    Round(_rc6);
    Round(_rc5);
    Round(_rc4);
    Round(_rc3);
    Round(_rc2);
    Round(_rc1);
    Dump1("Permutation");
    Vars2State;
}

void Xoodoo_SSSE3_Permute_12rounds(Xoodoo_align128plain32_state *state)
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
    Dump1("Permutation");
    Vars2State;
}
