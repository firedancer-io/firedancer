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

/* #define VERBOSE_LEVEL    0 */

#if DEBUG
#include <assert.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Xoodoo.h"
#include "Xoodoo-SnP.h"

/* ---------------------------------------------------------------- */

void Xoodoo_StaticInitialize( void )
{
}

/* ---------------------------------------------------------------- */

void Xoodoo_Initialize(Xoodoo_plain8_state *state)
{
    memset(state, 0, sizeof(Xoodoo_plain8_state));
}

/* ---------------------------------------------------------------- */

void Xoodoo_AddByte(Xoodoo_plain8_state *state, unsigned char byte, unsigned int offset)
{
    #if DEBUG
    assert(offset < NLANES*sizeof(tXoodooLane));
    #endif
    state->A[offset] ^= byte;
}

/* ---------------------------------------------------------------- */

void Xoodoo_AddBytes(Xoodoo_plain8_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int i;

    #if DEBUG
    assert(offset < NLANES*sizeof(tXoodooLane));
    assert(offset+length <= NLANES*sizeof(tXoodooLane));
    #endif
    for(i=0; i<length; i++)
        state->A[offset+i] ^= data[i];
}

/* ---------------------------------------------------------------- */

void Xoodoo_OverwriteBytes(Xoodoo_plain8_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    #if DEBUG
    assert(offset < NLANES*sizeof(tXoodooLane));
    assert(offset+length <= NLANES*sizeof(tXoodooLane));
    #endif
    memcpy(state->A+offset, data, length);
}

/* ---------------------------------------------------------------- */

void Xoodoo_OverwriteWithZeroes(Xoodoo_plain8_state *state, unsigned int byteCount)
{
    #if DEBUG
    assert(byteCount <= NLANES*sizeof(tXoodooLane));
    #endif
    memset(state, 0, byteCount);
}

/* ---------------------------------------------------------------- */

void Xoodoo_ExtractBytes(const Xoodoo_plain8_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    #if DEBUG
    assert(offset < NLANES*sizeof(tXoodooLane));
    assert(offset+length <= NLANES*sizeof(tXoodooLane));
    #endif
    memcpy(data, state->A+offset, length);
}

/* ---------------------------------------------------------------- */

void Xoodoo_ExtractAndAddBytes(const Xoodoo_plain8_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    unsigned int i;

    #if DEBUG
    assert(offset < NLANES*sizeof(tXoodooLane));
    assert(offset+length <= NLANES*sizeof(tXoodooLane));
    #endif
    for(i=0; i<length; i++)
        output[i] = input[i] ^ state->A[offset+i];
}

/* ---------------------------------------------------------------- */

#if defined(VERBOSE_LEVEL)

static void Dump(char * text, tXoodooLane * a, unsigned int level)
{
    if (level == VERBOSE_LEVEL) {
    #if 0
        printf("%-8.8s ", text);
        printf("%u %u %u %u - ", a[0+0], a[0+1], a[0+2], a[0+3] );
        printf("%u %u %u %u - ", a[4+0], a[4+1], a[4+2], a[4+3] );
        printf("%u %u %u %u\n", a[8+0], a[8+1], a[8+2], a[8+3] );
        if ((level == 2) && !strcmp(text, "Rho-east"))
            printf("\n");
    #elif 0
        printf("%-8.8s ", text);
        printf("%08x %08x %08x %08x - ", a[0+0], a[0+1], a[0+2], a[0+3] );
        printf("%08x %08x %08x %08x - ", a[4+0], a[4+1], a[4+2], a[4+3] );
        printf("%08x %08x %08x %08x\n", a[8+0], a[8+1], a[8+2], a[8+3] );
    #else
        printf("%s\n", text);
        printf("a00 %08x, a01 %08x, a02 %08x, a03 %08x\n", a[0+0], a[0+1], a[0+2], a[0+3] );
        printf("a10 %08x, a11 %08x, a12 %08x, a13 %08x\n", a[4+0], a[4+1], a[4+2], a[4+3] );
        printf("a20 %08x, a21 %08x, a22 %08x, a23 %08x\n\n", a[8+0], a[8+1], a[8+2], a[8+3] );
    #endif
    }
}

#else

#define Dump(text, a, level)

#endif


static void fromBytesToWords(tXoodooLane *stateAsWords, const uint8_t *state)
{
    unsigned int i, j;

    for(i=0; i<NLANES; i++) {
        stateAsWords[i] = 0;
        for(j=0; j<sizeof(tXoodooLane); j++)
            stateAsWords[i] |= (tXoodooLane)(state[i*sizeof(tXoodooLane)+j]) << (8*j);
    }
}

static void fromWordsToBytes(uint8_t *state, const tXoodooLane *stateAsWords)
{
    unsigned int i, j;

    for(i=0; i<NLANES; i++)
        for(j=0; j<sizeof(tXoodooLane); j++)
            state[i*sizeof(tXoodooLane)+j] = (stateAsWords[i] >> (8*j)) & 0xFF;
}

static void Xoodoo_Round( tXoodooLane * a, tXoodooLane rc )
{
    unsigned int x, y;
    tXoodooLane    b[NLANES];
    tXoodooLane    p[NCOLUMS];
    tXoodooLane    e[NCOLUMS];

    /* Theta: Column Parity Mixer */
    for (x=0; x<NCOLUMS; ++x)
        p[x] = a[index(x,0)] ^ a[index(x,1)] ^ a[index(x,2)];
    for (x=0; x<NCOLUMS; ++x)
        e[x] = ROTL32(p[(x-1)%4], 5) ^ ROTL32(p[(x-1)%4], 14);
    for (x=0; x<NCOLUMS; ++x)
        for (y=0; y<NROWS; ++y)
            a[index(x,y)] ^= e[x];
    Dump("Theta", a, 2);

    /* Rho-west: plane shift */
    for (x=0; x<NCOLUMS; ++x) {
        b[index(x,0)] = a[index(x,0)];
        b[index(x,1)] = a[index(x-1,1)];
        b[index(x,2)] = ROTL32(a[index(x,2)], 11);
    }
    memcpy( a, b, sizeof(b) );
    Dump("Rho-west", a, 2);
        
    /* Iota: round constant */
    a[0] ^= rc;
    Dump("Iota", a, 2);

    /* Chi: non linear layer */
    for (x=0; x<NCOLUMS; ++x)
        for (y=0; y<NROWS; ++y)
            b[index(x,y)] = a[index(x,y)] ^ (~a[index(x,y+1)] & a[index(x,y+2)]);
    memcpy( a, b, sizeof(b) );
    Dump("Chi", a, 2);

    /* Rho-east: plane shift */
    for (x=0; x<NCOLUMS; ++x) {
        b[index(x,0)] = a[index(x,0)];
        b[index(x,1)] = ROTL32(a[index(x,1)], 1);
        b[index(x,2)] = ROTL32(a[index(x+2,2)], 8);
    }
    memcpy( a, b, sizeof(b) );
    Dump("Rho-east", a, 2);

}

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

void Xoodoo_Permute_Nrounds(Xoodoo_plain8_state *state, unsigned int nr )
{
    tXoodooLane        a[NLANES];
    unsigned int    i;

    fromBytesToWords(a, state->A);

    for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i ) {
        Xoodoo_Round( a, RC[i] );
        Dump("Round", a, 1);
    }
    Dump("Permutation", a, 0);

    fromWordsToBytes(state->A, a);

}

void Xoodoo_Permute_6rounds(Xoodoo_plain8_state *state)
{
    Xoodoo_Permute_Nrounds( state, 6 );
}

void Xoodoo_Permute_12rounds(Xoodoo_plain8_state *state)
{
    Xoodoo_Permute_Nrounds( state, 12 );
}
