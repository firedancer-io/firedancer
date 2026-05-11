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
#include "Xoodyak-parameters.h"

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
#define LOAD128u(a)             _mm_loadu_si128((const V128 *)&(a))
#define ROL32(a, o)             _mm_rol_epi32(a, o)
#define STORE128(a, b)          _mm_store_si128((V128 *)&(a), b)
#define STORE128u(a, b)         _mm_storeu_si128((V128 *)&(a), b)
#define STORE64L(a, b)          _mm_storel_epi64((V128 *)&(a), b)
#define XOR(a, b)               _mm_xor_si128(a, b)
#define XOR3(a,b,c)             _mm_ternarylogic_epi32(a,b,c,0x96)
#define Chi(a,b,c)              _mm_ternarylogic_epi32(a,b,c,0xD2)

#define DeclareVars             V128    a0, a1, a2, p, e; \
                                V128    rhoEast2 = CONST128(maskRhoEast2)

#define State2Vars(state)       a0 = LOAD128(state->A[0]), a1 = LOAD128(state->A[4]), a2 = LOAD128(state->A[8]);

#define Vars2State(state)       STORE128(state->A[0], a0), STORE128(state->A[4], a1), STORE128(state->A[8], a2);

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

size_t Xoodyak_AVX512_AbsorbKeyedFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen)
{
    size_t  initialLength = XLen;
    DeclareVars;

    State2Vars(state);
    do {
        Round(_rc12);                      /* Xoodyak_Up(instance, NULL, 0, 0); */
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
        a0 = XOR(a0, LOAD128u(X[0]));  /* Xoodyak_Down(instance, X, Xoodyak_Rkin, 0); */
        a1 = XOR(a1, LOAD128u(X[16])); 
        a2 = XOR(a2, _mm_set_epi32(1, *(uint32_t*)(&X[40]), *(uint32_t*)(&X[36]), *(uint32_t*)(&X[32])));
        X       += Xoodyak_Rkin;
        XLen    -= Xoodyak_Rkin;
    } while (XLen >= Xoodyak_Rkin);
    Vars2State(state);

    return initialLength - XLen;
}

size_t Xoodyak_AVX512_AbsorbHashFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen)
{
    size_t  initialLength = XLen;
    V128    one = _mm_set_epi32(0, 0, 0, 1); 
    DeclareVars;

    State2Vars(state);
    do {
        Round(_rc12);               /* Xoodyak_Up(instance, NULL, 0, 0); */
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
        a0 = XOR(a0, LOAD128u(X[0]));  /* Xoodyak_Down(instance, X, Xoodyak_Rhash, 0); */
        a1 = XOR(a1, one); 
        X       += Xoodyak_Rhash;
        XLen    -= Xoodyak_Rhash;
    } while (XLen >= Xoodyak_Rhash);
    Vars2State(state);

    return initialLength - XLen;
}


size_t Xoodyak_AVX512_SqueezeKeyedFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen)
{
    size_t  initialLength = YLen;
    V128    one = _mm_set_epi32(0, 0, 0, 1); 
    DeclareVars;

    State2Vars(state);
    do {
        a0 = XOR(a0, one);      /* Xoodyak_Down(instance, NULL, 0, 0); */
        Round(_rc12);           /* Xoodyak_Up(instance, Y, Xoodyak_Rkout, 0); */
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
        STORE128u(Y[0], a0);
        STORE64L(Y[16], a1); 
        Y       += Xoodyak_Rkout;
        YLen    -= Xoodyak_Rkout;
    } while (YLen >= Xoodyak_Rkout);
    Vars2State(state);

    return initialLength - YLen;
}

size_t Xoodyak_AVX512_SqueezeHashFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen)
{
    size_t  initialLength = YLen;
    V128    one = _mm_set_epi32(0, 0, 0, 1); 
    DeclareVars;

    State2Vars(state);
    do {
        a0 = XOR(a0, one);      /* Xoodyak_Down(instance, NULL, 0, 0); */
        Round(_rc12);           /* Xoodyak_Up(instance, Y, Xoodyak_Rhash, 0); */
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
        STORE128u(Y[0], a0);
        Y       += Xoodyak_Rhash;
        YLen    -= Xoodyak_Rhash;
    } while (YLen >= Xoodyak_Rhash);
    Vars2State(state);

    return initialLength - YLen;
}

size_t Xoodyak_AVX512_EncryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
{
    size_t  initialLength = IOLen;
    DeclareVars;

    State2Vars(state);
    do {
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
        a0 = XOR(a0, LOAD128u(I[0]));
        a1 = XOR(a1, _mm_set_epi32(0, 1, *(uint32_t*)(&I[20]), *(uint32_t*)(&I[16])));
        STORE128u(O[0], a0);
        STORE64L(O[16], a1); 
        I       += Xoodyak_Rkout;
        O       += Xoodyak_Rkout;
        IOLen   -= Xoodyak_Rkout;
    } while (IOLen >= Xoodyak_Rkout);
    Vars2State(state);

    return initialLength - IOLen;
}

size_t Xoodyak_AVX512_DecryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
{
    size_t  initialLength = IOLen;
    V128    o0;
    V128    one = _mm_set_epi32(0, 1, 0, 0); 
    DeclareVars;

    State2Vars(state);
    do {
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
        o0 = XOR(a0, LOAD128u(I[0]));
#if defined(__i386__) || defined(_M_IX86)
        *((uint32_t*)(O+16)) = *((uint32_t*)(I+16)) ^ _mm_extract_epi32(a1, 0);
        *((uint32_t*)(O+20)) = *((uint32_t*)(I+20)) ^ _mm_extract_epi32(a1, 1);
        a1 = _mm_insert_epi32(a1, *((uint32_t*)(I+16)), 0);
        a1 = _mm_insert_epi32(a1, *((uint32_t*)(I+20)), 1);
#else
        *((uint64_t*)(O+16)) = *((uint64_t*)(I+16)) ^ _mm_extract_epi64(a1, 0);
        a1 = _mm_insert_epi64(a1, *((uint64_t*)(I+16)), 0);
#endif
        STORE128u(O[0], o0);
        a0 = XOR(a0, o0); 
        a1 = XOR(a1, one); 
        I       += Xoodyak_Rkout;
        O       += Xoodyak_Rkout;
        IOLen   -= Xoodyak_Rkout;
    } while (IOLen >= Xoodyak_Rkout);
    Vars2State(state);

    return initialLength - IOLen;
}
