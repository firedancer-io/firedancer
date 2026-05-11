/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by the designers, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements Keccak-p[1600] in a SnP-compatible way.
Please refer to SnP-documentation.h for more details.

This implementation comes with KeccakP-1600-SnP.h in the same folder.
Please refer to LowLevel.build for the exact list of other files it must be combined with.
*/

#if DEBUG
#include <assert.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "brg_endian.h"
#ifdef KeccakReference
#include "displayIntermediateValues.h"
#endif
#include "KeccakP-1600-SnP.h"

#define maxNrRounds 24
#define nrLanes 25

#ifdef KeccakReference

static uint32_t KeccakRoundConstants[maxNrRounds][2];
static unsigned int KeccakRhoOffsets[nrLanes];

#endif

/* ---------------------------------------------------------------- */

void toBitInterleaving(uint32_t low, uint32_t high, uint32_t *even, uint32_t *odd);
void fromBitInterleaving(uint32_t even, uint32_t odd, uint32_t *low, uint32_t *high);

void toBitInterleaving(uint32_t low, uint32_t high, uint32_t *even, uint32_t *odd)
{
    unsigned int i;

    *even = 0;
    *odd = 0;
    for(i=0; i<64; i++) {
        unsigned int inBit;
        if (i < 32)
            inBit = (low >> i) & 1;
        else
            inBit = (high >> (i-32)) & 1;
        if ((i % 2) == 0)
            *even |= inBit << (i/2);
        else
            *odd |= inBit << ((i-1)/2);
    }
}

void fromBitInterleaving(uint32_t even, uint32_t odd, uint32_t *low, uint32_t *high)
{
    unsigned int i;

    *low = 0;
    *high = 0;
    for(i=0; i<64; i++) {
        unsigned int inBit;
        if ((i % 2) == 0)
            inBit = (even >> (i/2)) & 1;
        else
            inBit = (odd >> ((i-1)/2)) & 1;
        if (i < 32)
            *low |= inBit << i;
        else
            *high |= inBit << (i-32);
    }
}

#ifdef KeccakReference

/* ---------------------------------------------------------------- */

void KeccakP1600_InitializeRoundConstants(void);
void KeccakP1600_InitializeRhoOffsets(void);
static int LFSR86540(uint8_t *LFSR);

void KeccakP1600_StaticInitialize(void)
{
    KeccakP1600_InitializeRoundConstants();
    KeccakP1600_InitializeRhoOffsets();
}

void KeccakP1600_InitializeRoundConstants(void)
{
    uint8_t LFSRstate = 0x01;
    unsigned int i, j, bitPosition;
    uint32_t low, high;

    for(i=0; i<maxNrRounds; i++) {
        low = high = 0;
        for(j=0; j<7; j++) {
            bitPosition = (1<<j)-1; /* 2^j-1 */
            if (LFSR86540(&LFSRstate)) {
                if (bitPosition < 32)
                    low ^= (uint32_t)1 << bitPosition;
                else
                    high ^= (uint32_t)1 << (bitPosition-32);
            }
        }
        toBitInterleaving(low, high, &(KeccakRoundConstants[i][0]), &(KeccakRoundConstants[i][1]));
    }
}

void KeccakP1600_InitializeRhoOffsets(void)
{
    unsigned int x, y, t, newX, newY;

    KeccakRhoOffsets[0] = 0;
    x = 1;
    y = 0;
    for(t=0; t<24; t++) {
        KeccakRhoOffsets[5*y+x] = ((t+1)*(t+2)/2) % 64;
        newX = (0*x+1*y) % 5;
        newY = (2*x+3*y) % 5;
        x = newX;
        y = newY;
    }
}

static int LFSR86540(uint8_t *LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

#else

static const uint32_t KeccakRoundConstants[maxNrRounds][2] =
{
    0x00000001, 0x00000000,
    0x00000000, 0x00000089,
    0x00000000, 0x8000008B,
    0x00000000, 0x80008080,
    0x00000001, 0x0000008B,
    0x00000001, 0x00008000,
    0x00000001, 0x80008088,
    0x00000001, 0x80000082,
    0x00000000, 0x0000000B,
    0x00000000, 0x0000000A,
    0x00000001, 0x00008082,
    0x00000000, 0x00008003,
    0x00000001, 0x0000808B,
    0x00000001, 0x8000000B,
    0x00000001, 0x8000008A,
    0x00000001, 0x80000081,
    0x00000000, 0x80000081,
    0x00000000, 0x80000008,
    0x00000000, 0x00000083,
    0x00000000, 0x80008003,
    0x00000001, 0x80008088,
    0x00000000, 0x80000088,
    0x00000001, 0x00008000,
    0x00000000, 0x80008082
};

static const unsigned int KeccakRhoOffsets[nrLanes] =
{
     0,  1, 62, 28, 27, 36, 44,  6, 55, 20,  3, 10, 43, 25, 39, 41, 45, 15, 21,  8, 18,  2, 61, 56, 14
};

#endif

/* ---------------------------------------------------------------- */

void KeccakP1600_Initialize(KeccakP1600_plain32_state *state)
{
    memset(state, 0, 1600/8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytes(KeccakP1600_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length);

void KeccakP1600_AddByte(KeccakP1600_plain32_state *state, unsigned char byte, unsigned int offset)
{
    unsigned char data[1];

    #if DEBUG
    assert(offset < 200);
    #endif
    data[0] = byte;
    KeccakP1600_AddBytes(state, data, offset, 1);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytesInLane(KeccakP1600_plain32_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if ((lanePosition < 25) && (offset < 8) && (offset+length <= 8)) {
        uint8_t laneAsBytes[8];
        uint32_t low, high;
        uint32_t lane[2];

        memset(laneAsBytes, 0, 8);
        memcpy(laneAsBytes+offset, data, length);
        low = laneAsBytes[0]
            | ((uint32_t)(laneAsBytes[1]) << 8)
            | ((uint32_t)(laneAsBytes[2]) << 16)
            | ((uint32_t)(laneAsBytes[3]) << 24);
        high = laneAsBytes[4]
            | ((uint32_t)(laneAsBytes[5]) << 8)
            | ((uint32_t)(laneAsBytes[6]) << 16)
            | ((uint32_t)(laneAsBytes[7]) << 24);
        toBitInterleaving(low, high, lane, lane+1);
        state->A[lanePosition*2+0] ^= lane[0];
        state->A[lanePosition*2+1] ^= lane[1];
    }
}

void KeccakP1600_AddBytes(KeccakP1600_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int lanePosition = offset/8;
    unsigned int offsetInLane = offset%8;

    #if DEBUG
    assert(offset < 200);
    assert(offset+length <= 200);
    #endif
    while(length > 0) {
        unsigned int bytesInLane = 8 - offsetInLane;
        if (bytesInLane > length)
            bytesInLane = length;
        KeccakP1600_AddBytesInLane(state, lanePosition, data, offsetInLane, bytesInLane);
        length -= bytesInLane;
        lanePosition++;
        offsetInLane = 0;
        data += bytesInLane;
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractBytesInLane(const KeccakP1600_plain32_state *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length);

void KeccakP1600_OverwriteBytesInLane(KeccakP1600_plain32_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if ((lanePosition < 25) && (offset < 8) && (offset+length <= 8)) {
        uint8_t laneAsBytes[8];
        uint32_t low, high;
        uint32_t lane[2];

        KeccakP1600_ExtractBytesInLane(state, lanePosition, laneAsBytes, 0, 8);
        memcpy(laneAsBytes+offset, data, length);
        low = laneAsBytes[0]
            | ((uint32_t)(laneAsBytes[1]) << 8)
            | ((uint32_t)(laneAsBytes[2]) << 16)
            | ((uint32_t)(laneAsBytes[3]) << 24);
        high = laneAsBytes[4]
            | ((uint32_t)(laneAsBytes[5]) << 8)
            | ((uint32_t)(laneAsBytes[6]) << 16)
            | ((uint32_t)(laneAsBytes[7]) << 24);
        toBitInterleaving(low, high, lane, lane+1);
        state->A[lanePosition*2+0] = lane[0];
        state->A[lanePosition*2+1] = lane[1];
    }
}

void KeccakP1600_OverwriteBytes(KeccakP1600_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int lanePosition = offset/8;
    unsigned int offsetInLane = offset%8;

    #if DEBUG
    assert(offset < 200);
    assert(offset+length <= 200);
    #endif
    while(length > 0) {
        unsigned int bytesInLane = 8 - offsetInLane;
        if (bytesInLane > length)
            bytesInLane = length;
        KeccakP1600_OverwriteBytesInLane(state, lanePosition, data, offsetInLane, bytesInLane);
        length -= bytesInLane;
        lanePosition++;
        offsetInLane = 0;
        data += bytesInLane;
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteWithZeroes(KeccakP1600_plain32_state *state, unsigned int byteCount)
{
    uint8_t laneAsBytes[8];
    unsigned int lanePosition = 0;

    #if DEBUG
    assert(byteCount <= 200);
    #endif
    memset(laneAsBytes, 0, 8);
    while(byteCount > 0) {
        if (byteCount < 8) {
            KeccakP1600_OverwriteBytesInLane(state, lanePosition, laneAsBytes, 0, byteCount);
            byteCount = 0;
        }
        else {
            state->A[lanePosition*2+0] = 0;
            state->A[lanePosition*2+1] = 0;
            byteCount -= 8;
            lanePosition++;
        }
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_PermutationOnWords(uint32_t *state, unsigned int nrRounds);
static void theta(uint32_t *A);
static void rho(uint32_t *A);
static void pi(uint32_t *A);
static void chi(uint32_t *A);
static void iota(uint32_t *A, unsigned int indexRound);
void KeccakP1600_ExtractBytes(const KeccakP1600_plain32_state *state, unsigned char *data, unsigned int offset, unsigned int length);

void KeccakP1600_Permute_Nrounds(KeccakP1600_plain32_state *state, unsigned int nrounds)
{
    {
        uint8_t stateAsBytes[1600/8];
        KeccakP1600_ExtractBytes(state, stateAsBytes, 0, 1600/8);
#ifdef KeccakReference
        displayStateAsBytes(1, "Input of permutation", stateAsBytes, 1600);
#endif
    }
    KeccakP1600_PermutationOnWords(state->A, nrounds);
    {
        uint8_t stateAsBytes[1600/8];
        KeccakP1600_ExtractBytes(state, stateAsBytes, 0, 1600/8);
#ifdef KeccakReference
        displayStateAsBytes(1, "State after permutation", stateAsBytes, 1600);
#endif
    }
}


void KeccakP1600_Permute_12rounds(KeccakP1600_plain32_state *state)
{
    {
        uint8_t stateAsBytes[1600/8];
        KeccakP1600_ExtractBytes(state, stateAsBytes, 0, 1600/8);
#ifdef KeccakReference
        displayStateAsBytes(1, "Input of permutation", stateAsBytes, 1600);
#endif
    }
    KeccakP1600_PermutationOnWords(state->A, 12);
    {
        uint8_t stateAsBytes[1600/8];
        KeccakP1600_ExtractBytes(state, stateAsBytes, 0, 1600/8);
#ifdef KeccakReference
        displayStateAsBytes(1, "State after permutation", stateAsBytes, 1600);
#endif
    }
}

void KeccakP1600_Permute_24rounds(KeccakP1600_plain32_state *state)
{
    {
        uint8_t stateAsBytes[1600/8];
        KeccakP1600_ExtractBytes(state, stateAsBytes, 0, 1600/8);
#ifdef KeccakReference
        displayStateAsBytes(1, "Input of permutation", stateAsBytes, 1600);
#endif
    }
    KeccakP1600_PermutationOnWords(state->A, 24);
    {
        uint8_t stateAsBytes[1600/8];
        KeccakP1600_ExtractBytes(state, stateAsBytes, 0, 1600/8);
#ifdef KeccakReference
        displayStateAsBytes(1, "State after permutation", stateAsBytes, 1600);
#endif
    }
}

void KeccakP1600_PermutationOnWords(uint32_t *state, unsigned int nrRounds)
{
    unsigned int i;

#ifdef KeccakReference
    displayStateAs32bitWords(3, "Same, with lanes as pairs of 32-bit words (bit interleaving)", state);
#endif

    for(i=(maxNrRounds-nrRounds); i<maxNrRounds; i++) {
#ifdef KeccakReference
        displayRoundNumber(3, i);
#endif

        theta(state);
#ifdef KeccakReference
        displayStateAs32bitWords(3, "After theta", state);
#endif

        rho(state);
#ifdef KeccakReference
        displayStateAs32bitWords(3, "After rho", state);
#endif

        pi(state);
#ifdef KeccakReference
        displayStateAs32bitWords(3, "After pi", state);
#endif

        chi(state);
#ifdef KeccakReference
        displayStateAs32bitWords(3, "After chi", state);
#endif

        iota(state, i);
#ifdef KeccakReference
        displayStateAs32bitWords(3, "After iota", state);
#endif
    }
}

#define index(x, y,z) ((((x)%5)+5*((y)%5))*2 + z)
#define ROL32(a, offset) ((offset != 0) ? ((((uint32_t)a) << offset) ^ (((uint32_t)a) >> (32-offset))) : a)

void ROL64(uint32_t inEven, uint32_t inOdd, uint32_t *outEven, uint32_t *outOdd, unsigned int offset)
{
    if ((offset % 2) == 0) {
        *outEven = ROL32(inEven, offset/2);
        *outOdd = ROL32(inOdd, offset/2);
    }
    else {
        *outEven = ROL32(inOdd, (offset+1)/2);
        *outOdd = ROL32(inEven, (offset-1)/2);
    }
}

static void theta(uint32_t *A)
{
    unsigned int x, y, z;
    uint32_t C[5][2], D[5][2];

    for(x=0; x<5; x++) {
        for(z=0; z<2; z++) {
            C[x][z] = 0;
            for(y=0; y<5; y++)
                C[x][z] ^= A[index(x, y, z)];
        }
    }
    for(x=0; x<5; x++) {
        ROL64(C[(x+1)%5][0], C[(x+1)%5][1], &(D[x][0]), &(D[x][1]), 1);
        for(z=0; z<2; z++)
            D[x][z] ^= C[(x+4)%5][z];
    }
    for(x=0; x<5; x++)
        for(y=0; y<5; y++)
            for(z=0; z<2; z++)
                A[index(x, y, z)] ^= D[x][z];
}

static void rho(uint32_t *A)
{
    unsigned int x, y;

    for(x=0; x<5; x++) for(y=0; y<5; y++)
        ROL64(A[index(x, y, 0)], A[index(x, y, 1)], &(A[index(x, y, 0)]), &(A[index(x, y, 1)]), KeccakRhoOffsets[5*y+x]);
}

static void pi(uint32_t *A)
{
    unsigned int x, y, z;
    uint32_t tempA[50];

    for(x=0; x<5; x++) for(y=0; y<5; y++) for(z=0; z<2; z++)
        tempA[index(x, y, z)] = A[index(x, y, z)];
    for(x=0; x<5; x++) for(y=0; y<5; y++) for(z=0; z<2; z++)
        A[index(0*x+1*y, 2*x+3*y, z)] = tempA[index(x, y, z)];
}

static void chi(uint32_t *A)
{
    unsigned int x, y, z;
    uint32_t C[5][2];

    for(y=0; y<5; y++) {
        for(x=0; x<5; x++)
            for(z=0; z<2; z++)
                C[x][z] = A[index(x, y, z)] ^ ((~A[index(x+1, y, z)]) & A[index(x+2, y, z)]);
        for(x=0; x<5; x++)
            for(z=0; z<2; z++)
                A[index(x, y, z)] = C[x][z];
    }
}

static void iota(uint32_t *A, unsigned int indexRound)
{
    A[index(0, 0, 0)] ^= KeccakRoundConstants[indexRound][0];
    A[index(0, 0, 1)] ^= KeccakRoundConstants[indexRound][1];
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractBytesInLane(const KeccakP1600_plain32_state *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length)
{
    if ((lanePosition < 25) && (offset < 8) && (offset+length <= 8)) {
        uint32_t lane[2];
        uint8_t laneAsBytes[8];
        fromBitInterleaving(state->A[lanePosition*2], state->A[lanePosition*2+1], lane, lane+1);
        laneAsBytes[0] = lane[0] & 0xFF;
        laneAsBytes[1] = (lane[0] >> 8) & 0xFF;
        laneAsBytes[2] = (lane[0] >> 16) & 0xFF;
        laneAsBytes[3] = (lane[0] >> 24) & 0xFF;
        laneAsBytes[4] = lane[1] & 0xFF;
        laneAsBytes[5] = (lane[1] >> 8) & 0xFF;
        laneAsBytes[6] = (lane[1] >> 16) & 0xFF;
        laneAsBytes[7] = (lane[1] >> 24) & 0xFF;
        memcpy(data, laneAsBytes+offset, length);
    }
}

void KeccakP1600_ExtractBytes(const KeccakP1600_plain32_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int lanePosition = offset/8;
    unsigned int offsetInLane = offset%8;

    #if DEBUG
    assert(offset < 200);
    assert(offset+length <= 200);
    #endif
    while(length > 0) {
        unsigned int bytesInLane = 8 - offsetInLane;
        if (bytesInLane > length)
            bytesInLane = length;
        KeccakP1600_ExtractBytesInLane(state, lanePosition, data, offsetInLane, bytesInLane);
        length -= bytesInLane;
        lanePosition++;
        offsetInLane = 0;
        data += bytesInLane;
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddBytesInLane(const KeccakP1600_plain32_state *state, unsigned int lanePosition, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    if ((lanePosition < 25) && (offset < 8) && (offset+length <= 8)) {
        uint8_t laneAsBytes[8];
        unsigned int i;

        KeccakP1600_ExtractBytesInLane(state, lanePosition, laneAsBytes, offset, length);
        for(i=0; i<length; i++)
            output[i] = input[i] ^ laneAsBytes[i];
    }
}

void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_plain32_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    unsigned int lanePosition = offset/8;
    unsigned int offsetInLane = offset%8;

    #if DEBUG
    assert(offset < 200);
    assert(offset+length <= 200);
    #endif
    while(length > 0) {
        unsigned int bytesInLane = 8 - offsetInLane;
        if (bytesInLane > length)
            bytesInLane = length;
        KeccakP1600_ExtractAndAddBytesInLane(state, lanePosition, input, output, offsetInLane, bytesInLane);
        length -= bytesInLane;
        lanePosition++;
        offsetInLane = 0;
        input += bytesInLane;
        output += bytesInLane;
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_DisplayRoundConstants(FILE *f)
{
    unsigned int i;

    for(i=0; i<maxNrRounds; i++) {
        fprintf(f, "RC[%02i][0][0] = ", i);
        fprintf(f, "%08X:%08X", (unsigned int)(KeccakRoundConstants[i][0]), (unsigned int)(KeccakRoundConstants[i][1]));
        fprintf(f, "\n");
    }
    fprintf(f, "\n");
}

void KeccakP1600_DisplayRhoOffsets(FILE *f)
{
    unsigned int x, y;

    for(y=0; y<5; y++) for(x=0; x<5; x++) {
        fprintf(f, "RhoOffset[%i][%i] = ", x, y);
        fprintf(f, "%2i", KeccakRhoOffsets[5*y+x]);
        fprintf(f, "\n");
    }
    fprintf(f, "\n");
}
