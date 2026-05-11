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
#include "Xoodoo.h"
#include "Xoodoo-plain.h"

#define VERBOSE         0

#if (VERBOSE > 0)
    #define    Dump(__t)    printf(__t "\n"); \
                            printf("a00 %08x, a01 %08x, a02 %08x, a03 %08x\n", a00, a01, a02, a03 ); \
                            printf("a10 %08x, a11 %08x, a12 %08x, a13 %08x\n", a10, a11, a12, a13 ); \
                            printf("a20 %08x, a21 %08x, a22 %08x, a23 %08x\n\n", a20, a21, a22, a23 );
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

void Xoodoo_plain_Initialize(Xoodoo_plain32_state *state)
{
    memset(state, 0, sizeof(Xoodoo_plain32_state));
}

/* ---------------------------------------------------------------- */

void Xoodoo_plain_AddBytes(Xoodoo_plain32_state *argState, const unsigned char *argdata, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    if (length == (3*4*4)) {
        uint32_t *state = argState->A;
        uint32_t *data = (uint32_t *)argdata;
        state[0] ^= data[0];
        state[1] ^= data[1];
        state[2] ^= data[2];
        state[3] ^= data[3];
        state[4] ^= data[4];
        state[5] ^= data[5];
        state[6] ^= data[6];
        state[7] ^= data[7];
        state[8] ^= data[8];
        state[9] ^= data[9];
        state[10] ^= data[10];
        state[11] ^= data[11];
    }
    else {
        unsigned int sizeLeft = length;
        unsigned int lanePosition = offset/4;
        unsigned int offsetInLane = offset%4;
        const unsigned char *curData = argdata;
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
    }
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_plain_OverwriteBytes(Xoodoo_plain32_state *argstate, const unsigned char *argdata, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    if (length == (3*4*4)) {
        uint32_t *state = argstate->A;
        uint32_t *data = (uint32_t *)argdata;
        state[0] = data[0];
        state[1] = data[1];
        state[2] = data[2];
        state[3] = data[3];
        state[4] = data[4];
        state[5] = data[5];
        state[6] = data[6];
        state[7] = data[7];
        state[8] = data[8];
        state[9] = data[9];
        state[10] = data[10];
        state[11] = data[11];
    }
    else
        memcpy((unsigned char*)argstate+offset, argdata, length);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_plain_OverwriteWithZeroes(Xoodoo_plain32_state *argstate, unsigned int byteCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memset(argstate, 0, byteCount);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_plain_ExtractBytes(const Xoodoo_plain32_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, (unsigned char*)state+offset, length);
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

void Xoodoo_plain_ExtractAndAddBytes(const Xoodoo_plain32_state *argState, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    if (length == (3*4*4)) {
        const uint32_t *state = argState->A;
        const uint32_t *ii = (const uint32_t *)input;
        uint32_t *oo = (uint32_t *)output;

        oo[0] = state[0] ^ ii[0];
        oo[1] = state[1] ^ ii[1];
        oo[2] = state[2] ^ ii[2];
        oo[3] = state[3] ^ ii[3];
        oo[4] = state[4] ^ ii[4];
        oo[5] = state[5] ^ ii[5];
        oo[6] = state[6] ^ ii[6];
        oo[7] = state[7] ^ ii[7];
        oo[8] = state[8] ^ ii[8];
        oo[9] = state[9] ^ ii[9];
        oo[10] = state[10] ^ ii[10];
        oo[11] = state[11] ^ ii[11];
    }
    else {
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
    }
#else
    #error "Not yet implemented"
#endif
}

/* ---------------------------------------------------------------- */

#define    DeclareVars  uint32_t    a00, a01, a02, a03; \
                        uint32_t    a10, a11, a12, a13; \
                        uint32_t    a20, a21, a22, a23; \
                        uint32_t    v1, v2

#define    State2Vars   a00 = state->A[0+0], a01 = state->A[0+1], a02 = state->A[0+2], a03 = state->A[0+3]; \
                        a10 = state->A[4+0], a11 = state->A[4+1], a12 = state->A[4+2], a13 = state->A[4+3]; \
                        a20 = state->A[8+0], a21 = state->A[8+1], a22 = state->A[8+2], a23 = state->A[8+3]

#define    Vars2State   state->A[0+0] = a00, state->A[0+1] = a01, state->A[0+2] = a02, state->A[0+3] = a03; \
                        state->A[4+0] = a10, state->A[4+1] = a11, state->A[4+2] = a12, state->A[4+3] = a13; \
                        state->A[8+0] = a20, state->A[8+1] = a21, state->A[8+2] = a22, state->A[8+3] = a23

/*
** Theta: Column Parity Mixer
*/
#define Theta()                                             \
                    v1 = a03 ^ a13 ^ a23;                   \
                    v2 = a00 ^ a10 ^ a20;                   \
                    v1 = ROTL32(v1, 5) ^ ROTL32(v1, 14);    \
                    a00 ^= v1;                              \
                    a10 ^= v1;                              \
                    a20 ^= v1;                              \
                    v1 = a01 ^ a11 ^ a21;                   \
                    v2 = ROTL32(v2, 5) ^ ROTL32(v2, 14);    \
                    a01 ^= v2;                              \
                    a11 ^= v2;                              \
                    a21 ^= v2;                              \
                    v2 = a02 ^ a12 ^ a22;                   \
                    v1 = ROTL32(v1, 5) ^ ROTL32(v1, 14);    \
                    a02 ^= v1;                              \
                    a12 ^= v1;                              \
                    a22 ^= v1;                              \
                    v2 = ROTL32(v2, 5) ^ ROTL32(v2, 14);    \
                    a03 ^= v2;                              \
                    a13 ^= v2;                              \
                    a23 ^= v2

/*
** Rho-west: Plane shift
*/
#define Rho_west()                          \
                    a20 = ROTL32(a20, 11);  \
                    a21 = ROTL32(a21, 11);  \
                    a22 = ROTL32(a22, 11);  \
                    a23 = ROTL32(a23, 11);  \
                    v1 = a13;               \
                    a13 = a12;              \
                    a12 = a11;              \
                    a11 = a10;              \
                    a10 = v1

/*
** Iota: Round constants
*/
#define Iota(__rc)  a00 ^= __rc

/*
** Chi: Non linear step, on colums
*/
#define Chi()                               \
                    a00 ^= ~a10 & a20;      \
                    a10 ^= ~a20 & a00;      \
                    a20 ^= ~a00 & a10;      \
                                            \
                    a01 ^= ~a11 & a21;      \
                    a11 ^= ~a21 & a01;      \
                    a21 ^= ~a01 & a11;      \
                                            \
                    a02 ^= ~a12 & a22;      \
                    a12 ^= ~a22 & a02;      \
                    a22 ^= ~a02 & a12;      \
                                            \
                    a03 ^= ~a13 & a23;      \
                    a13 ^= ~a23 & a03;      \
                    a23 ^= ~a03 & a13

/*
** Rho-east: Plane shift
*/
#define Rho_east()                          \
                    a10 = ROTL32(a10, 1);   \
                    a11 = ROTL32(a11, 1);   \
                    a12 = ROTL32(a12, 1);   \
                    a13 = ROTL32(a13, 1);   \
                    v1  = ROTL32(a23, 8);   \
                    a23 = ROTL32(a21, 8);   \
                    a21 = v1;               \
                    v1  = ROTL32(a22, 8);   \
                    a22 = ROTL32(a20, 8);   \
                    a20 = v1

#define Round(__rc)                         \
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

void Xoodoo_plain_Permute_Nrounds(Xoodoo_plain32_state *state, unsigned int nr)
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

void Xoodoo_plain_Permute_6rounds(Xoodoo_plain32_state *state)
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

void Xoodoo_plain_Permute_12rounds(Xoodoo_plain32_state *state)
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
