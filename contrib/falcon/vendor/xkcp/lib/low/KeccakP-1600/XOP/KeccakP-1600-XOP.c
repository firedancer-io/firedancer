/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "KeccakP-1600-SnP.h"

#include "align.h"
#ifdef KeccakP1600_XOP_fullUnrolling
#define FullUnrolling
#else
#define Unrolling KeccakP1600_XOP_unrolling
#endif
#include "KeccakP-1600-unrolling.macros"
#include "SnP-Relaned.h"

#include <x86intrin.h>
typedef __m128i V64;
typedef __m128i V128;

#define LOAD64(a)           _mm_loadl_epi64((const V64 *)&(a))
#define CONST64(a)          _mm_loadl_epi64((const V64 *)&(a))
#define STORE64(a, b)       _mm_storel_epi64((V64 *)&(a), b)
#define XOR64(a, b)         _mm_xor_si128(a, b)
#define XOReq64(a, b)       a = _mm_xor_si128(a, b)

#define ANDnu128(a, b)      _mm_andnot_si128(a, b)
#define LOAD6464(a, b)      _mm_set_epi64((__m64)(a), (__m64)(b))
#define CONST128(a)         _mm_load_si128((const V128 *)&(a))
#define LOAD128(a)          _mm_load_si128((const V128 *)&(a))
#define LOAD128u(a)         _mm_loadu_si128((const V128 *)&(a))
#define STORE128(a, b)      _mm_store_si128((V128 *)&(a), b)
#define XOR128(a, b)        _mm_xor_si128(a, b)
#define XOReq128(a, b)      a = _mm_xor_si128(a, b)
#define ZERO128()           _mm_setzero_si128()

#define SWAP64(a)           _mm_shuffle_epi32(a, 0x4E)
#define GET64LOLO(a, b)     _mm_unpacklo_epi64(a, b)
#define GET64HIHI(a, b)     _mm_unpackhi_epi64(a, b)
#define GET64LOHI(a, b)     ((__m128i)_mm_blend_pd((__m128d)a, (__m128d)b, 2))
#define GET64HILO(a, b)     SWAP64(GET64LOHI(b, a))
#define COPY64HI2LO(a)      _mm_shuffle_epi32(a, 0xEE)
#define COPY64LO2HI(a)      _mm_shuffle_epi32(a, 0x44)

#define ROL6464same(a, o)   _mm_roti_epi64(a, o)
#define ROL6464(a, r1, r2)  _mm_rot_epi64(a, CONST128( rot_##r1##_##r2 ))
ALIGN(16) const uint64_t rot_0_20[2]  = { 0, 20};
ALIGN(16) const uint64_t rot_44_3[2]  = {44,  3};
ALIGN(16) const uint64_t rot_43_45[2] = {43, 45};
ALIGN(16) const uint64_t rot_21_61[2] = {21, 61};
ALIGN(16) const uint64_t rot_14_28[2] = {14, 28};
ALIGN(16) const uint64_t rot_1_36[2]  = { 1, 36};
ALIGN(16) const uint64_t rot_6_10[2]  = { 6, 10};
ALIGN(16) const uint64_t rot_25_15[2] = {25, 15};
ALIGN(16) const uint64_t rot_8_56[2]  = { 8, 56};
ALIGN(16) const uint64_t rot_18_27[2] = {18, 27};
ALIGN(16) const uint64_t rot_62_55[2] = {62, 55};
ALIGN(16) const uint64_t rot_39_41[2] = {39, 41};

/* ---------------------------------------------------------------- */

void KeccakP1600_Initialize(KeccakP1600_align128plain64_state *state)
{
    memset(state, 0, 200);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytesInLane(KeccakP1600_align128plain64_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
    if (length == 0)
        return;
    uint64_t lane;
    if (length == 1)
        lane = data[0];
    else {
        lane = 0;
        memcpy(&lane, data, length);
    }
    lane <<= offset*8;
    state->A[lanePosition] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddLanes(KeccakP1600_align128plain64_state *state, const unsigned char *data, unsigned int laneCount)
{
    unsigned int i = 0;
    for( ; (i+8)<=laneCount; i+=8) {
        state->A[i+0] ^= ((uint64_t*)data)[i+0];
        state->A[i+1] ^= ((uint64_t*)data)[i+1];
        state->A[i+2] ^= ((uint64_t*)data)[i+2];
        state->A[i+3] ^= ((uint64_t*)data)[i+3];
        state->A[i+4] ^= ((uint64_t*)data)[i+4];
        state->A[i+5] ^= ((uint64_t*)data)[i+5];
        state->A[i+6] ^= ((uint64_t*)data)[i+6];
        state->A[i+7] ^= ((uint64_t*)data)[i+7];
    }
    for( ; (i+4)<=laneCount; i+=4) {
        state->A[i+0] ^= ((uint64_t*)data)[i+0];
        state->A[i+1] ^= ((uint64_t*)data)[i+1];
        state->A[i+2] ^= ((uint64_t*)data)[i+2];
        state->A[i+3] ^= ((uint64_t*)data)[i+3];
    }
    for( ; (i+2)<=laneCount; i+=2) {
        state->A[i+0] ^= ((uint64_t*)data)[i+0];
        state->A[i+1] ^= ((uint64_t*)data)[i+1];
    }
    if (i<laneCount) {
        state->A[i+0] ^= ((uint64_t*)data)[i+0];
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddByte(KeccakP1600_align128plain64_state *state, unsigned char byte, unsigned int offset)
{
    uint64_t lane = byte;
    lane <<= (offset%8)*8;
    state->A[offset/8] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytes(KeccakP1600_align128plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_AddBytes(state, data, offset, length, KeccakP1600_AddLanes, KeccakP1600_AddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteBytes(KeccakP1600_align128plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    memcpy((unsigned char*)state+offset, data, length);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteWithZeroes(KeccakP1600_align128plain64_state *state, unsigned int byteCount)
{
    memset(state, 0, byteCount);
}

/* ---------------------------------------------------------------- */

#define declareABCDE \
    V128 Abage, Abegi, Abigo, Abogu, Abuga; \
    V128 Akame, Akemi, Akimo, Akomu, Akuma; \
    V128 Abae, Abio, Agae, Agio, Akae, Akio, Amae, Amio; \
    V64 Aba, Abe, Abi, Abo, Abu; \
    V64 Aga, Age, Agi, Ago, Agu; \
    V64 Aka, Ake, Aki, Ako, Aku; \
    V64 Ama, Ame, Ami, Amo, Amu; \
    V128 Asase, Asiso; \
    V64 Asu; \
    V128 Bbage, Bbegi, Bbigo, Bbogu, Bbuga; \
    V128 Bkame, Bkemi, Bkimo, Bkomu, Bkuma; \
    V128 Bsase, Bsesi, Bsiso, Bsosu, Bsusa; \
    V128 Cae, Cei, Cio, Cou, Cua; \
    V128 Dau, Dea, Die, Doi, Duo; \
    V128 Dua, Dae, Dei, Dio, Dou; \
    V128 Ebage, Ebegi, Ebigo, Ebogu, Ebuga; \
    V128 Ekame, Ekemi, Ekimo, Ekomu, Ekuma; \
    V128 Esase, Esiso; \
    V64 Esu; \
    V128 Zero;

#define prepareTheta

#define computeD \
    Cua = GET64LOLO(Cua, Cae); \
    Dei = XOR128(Cae, ROL6464same(Cio, 1)); \
    Dou = XOR128(Cio, ROL6464same(Cua, 1)); \
    Cei = GET64HILO(Cae, Cio); \
    Dae = XOR128(Cua, ROL6464same(Cei, 1)); \
    Dau = GET64LOHI(Dae, Dou); \
    Dea = SWAP64(Dae); \
    Die = SWAP64(Dei); \
    Doi = GET64LOLO(Dou, Die); \
    Duo = SWAP64(Dou);

/* --- Theta Rho Pi Chi Iota Prepare-theta */
/* --- 64-bit lanes mapped to 64-bit and 128-bit words */
#define thetaRhoPiChiIotaPrepareTheta(i, A, E) \
    computeD \
    \
    Bbage = XOR128(GET64LOHI(A##bage, A##bogu), Dau); \
    Bbage = ROL6464(Bbage, 0, 20); \
    Bbegi = XOR128(GET64HILO(A##bage, A##kame), Dea); \
    Bbegi = ROL6464(Bbegi, 44, 3); \
    Bbigo = XOR128(GET64LOHI(A##kimo, A##kame), Die); \
    Bbigo = ROL6464(Bbigo, 43, 45); \
    E##bage = XOR128(Bbage, ANDnu128(Bbegi, Bbigo)); \
    XOReq128(E##bage, CONST64(KeccakF1600RoundConstants[i])); \
    Cae = E##bage; \
    Bbogu = XOR128(GET64HILO(A##kimo, A##siso), Doi); \
    Bbogu = ROL6464(Bbogu, 21, 61); \
    E##begi = XOR128(Bbegi, ANDnu128(Bbigo, Bbogu)); \
    Cei = E##begi; \
    Bbuga = XOR128(GET64LOLO(A##su, A##bogu), Duo); \
    Bbuga = ROL6464(Bbuga, 14, 28); \
    E##bigo = XOR128(Bbigo, ANDnu128(Bbogu, Bbuga)); \
    Cio = E##bigo; \
    E##bogu = XOR128(Bbogu, ANDnu128(Bbuga, Bbage)); \
    Cou = E##bogu; \
    E##buga = XOR128(Bbuga, ANDnu128(Bbage, Bbegi)); \
    Cua = E##buga; \
\
    Bkame = XOR128(GET64LOHI(A##begi, A##buga), Dea); \
    Bkame = ROL6464(Bkame, 1, 36); \
    Bkemi = XOR128(GET64HILO(A##begi, A##kemi), Die); \
    Bkemi = ROL6464(Bkemi, 6, 10); \
    Bkimo = XOR128(GET64LOHI(A##komu, A##kemi), Doi); \
    Bkimo = ROL6464(Bkimo, 25, 15); \
    E##kame = XOR128(Bkame, ANDnu128(Bkemi, Bkimo)); \
    XOReq128(Cae, E##kame); \
    Bkomu = XOR128(GET64HIHI(A##komu, A##siso), Duo); \
    Bkomu = ROL6464(Bkomu, 8, 56); \
    E##kemi = XOR128(Bkemi, ANDnu128(Bkimo, Bkomu)); \
    XOReq128(Cei, E##kemi); \
    Bkuma = XOR128(GET64LOLO(A##sase, A##buga), Dau); \
    Bkuma = ROL6464(Bkuma, 18, 27); \
    E##kimo = XOR128(Bkimo, ANDnu128(Bkomu, Bkuma)); \
    XOReq128(Cio, E##kimo); \
    E##komu = XOR128(Bkomu, ANDnu128(Bkuma, Bkame)); \
    XOReq128(Cou, E##komu); \
    E##kuma = XOR128(Bkuma, ANDnu128(Bkame, Bkemi)); \
    XOReq128(Cua, E##kuma); \
\
    Bsase = XOR128(A##bigo, SWAP64(Doi)); \
    Bsase = ROL6464(Bsase, 62, 55); \
    Bsiso = XOR128(A##kuma, SWAP64(Dau)); \
    Bsiso = ROL6464(Bsiso, 39, 41); \
    Bsusa = XOR64(COPY64HI2LO(A##sase), Dei); \
    Bsusa = ROL6464same(Bsusa, 2); \
    Bsusa = GET64LOLO(Bsusa, Bsase); \
    Bsesi = GET64HILO(Bsase, Bsiso); \
    Bsosu = GET64HILO(Bsiso, Bsusa); \
    E##sase = XOR128(Bsase, ANDnu128(Bsesi, Bsiso)); \
    XOReq128(Cae, E##sase); \
    E##siso = XOR128(Bsiso, ANDnu128(Bsosu, Bsusa)); \
    XOReq128(Cio, E##siso); \
    Zero = ZERO128(); \
    E##su = GET64LOLO(XOR128(Bsusa, ANDnu128(Bsase, Bsesi)), Zero); \
    XOReq128(Cua, E##su); \
\
    XOReq128(Cae, GET64HIHI(Cua, Zero)); \
    XOReq128(Cae, GET64LOLO(Zero, Cei)); \
    XOReq128(Cio, GET64HIHI(Cei, Zero)); \
    XOReq128(Cio, GET64LOLO(Zero, Cou)); \
    XOReq128(Cua, GET64HIHI(Cou, Zero)); \

/* --- Theta Rho Pi Chi Iota */
/* --- 64-bit lanes mapped to 64-bit and 128-bit words */
#define thetaRhoPiChiIota(i, A, E) thetaRhoPiChiIotaPrepareTheta(i, A, E)

const uint64_t KeccakF1600RoundConstants[24] = {
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
    0x8000000080008008ULL };

#define copyFromState(X, state) \
    X##bae = LOAD128(state[ 0]); \
    X##ba = X##bae; \
    X##be = GET64HIHI(X##bae, X##bae); \
    Cae = X##bae; \
    X##bio = LOAD128(state[ 2]); \
    X##bi = X##bio; \
    X##bo = GET64HIHI(X##bio, X##bio); \
    Cio = X##bio; \
    X##bu = LOAD64(state[ 4]); \
    Cua = X##bu; \
    X##gae = LOAD128u(state[ 5]); \
    X##ga = X##gae; \
    X##buga = GET64LOLO(X##bu, X##ga); \
    X##ge = GET64HIHI(X##gae, X##gae); \
    X##bage = GET64LOLO(X##ba, X##ge); \
    XOReq128(Cae, X##gae); \
    X##gio = LOAD128u(state[ 7]); \
    X##gi = X##gio; \
    X##begi = GET64LOLO(X##be, X##gi); \
    X##go = GET64HIHI(X##gio, X##gio); \
    X##bigo = GET64LOLO(X##bi, X##go); \
    XOReq128(Cio, X##gio); \
    X##gu = LOAD64(state[ 9]); \
    X##bogu = GET64LOLO(X##bo, X##gu); \
    XOReq64(Cua, X##gu); \
    X##kae = LOAD128(state[10]); \
    X##ka = X##kae; \
    X##ke = GET64HIHI(X##kae, X##kae); \
    XOReq128(Cae, X##kae); \
    X##kio = LOAD128(state[12]); \
    X##ki = X##kio; \
    X##ko = GET64HIHI(X##kio, X##kio); \
    XOReq128(Cio, X##kio); \
    X##kuma = LOAD128(state[14]); \
    XOReq64(Cua, X##kuma); \
    X##me = LOAD64(state[16]); \
    X##kame = GET64LOLO(X##ka, X##me); \
    XOReq128(Cae, GET64HIHI(X##kuma, X##kame)); \
    X##mio = LOAD128u(state[17]); \
    X##mi = X##mio; \
    X##kemi = GET64LOLO(X##ke, X##mi); \
    X##mo = GET64HIHI(X##mio, X##mio); \
    X##kimo = GET64LOLO(X##ki, X##mo); \
    XOReq128(Cio, X##mio); \
    X##mu = LOAD64(state[19]); \
    X##komu = GET64LOLO(X##ko, X##mu); \
    XOReq64(Cua, X##mu); \
    X##sase = LOAD128(state[20]); \
    XOReq128(Cae, X##sase); \
    X##siso = LOAD128(state[22]); \
    XOReq128(Cio, X##siso); \
    X##su = LOAD64(state[24]); \
    XOReq64(Cua, X##su); \

#define copyToState(state, X) \
    STORE64(state[ 0], X##bage); \
    STORE64(state[ 1], X##begi); \
    STORE64(state[ 2], X##bigo); \
    STORE64(state[ 3], X##bogu); \
    STORE128(state[ 4], X##buga); \
    STORE64(state[ 6], COPY64HI2LO(X##bage)); \
    STORE64(state[ 7], COPY64HI2LO(X##begi)); \
    STORE64(state[ 8], COPY64HI2LO(X##bigo)); \
    STORE64(state[ 9], COPY64HI2LO(X##bogu)); \
    STORE64(state[10], X##kame); \
    STORE64(state[11], X##kemi); \
    STORE64(state[12], X##kimo); \
    STORE64(state[13], X##komu); \
    STORE128(state[14], X##kuma); \
    STORE64(state[16], COPY64HI2LO(X##kame)); \
    STORE64(state[17], COPY64HI2LO(X##kemi)); \
    STORE64(state[18], COPY64HI2LO(X##kimo)); \
    STORE64(state[19], COPY64HI2LO(X##komu)); \
    STORE128(state[20], X##sase); \
    STORE128(state[22], X##siso); \
    STORE64(state[24], X##su); \

#define copyStateVariables(X, Y) \
    X##bage = Y##bage; \
    X##begi = Y##begi; \
    X##bigo = Y##bigo; \
    X##bogu = Y##bogu; \
    X##buga = Y##buga; \
    X##kame = Y##kame; \
    X##kemi = Y##kemi; \
    X##kimo = Y##kimo; \
    X##komu = Y##komu; \
    X##kuma = Y##kuma; \
    X##sase = Y##sase; \
    X##siso = Y##siso; \
    X##su = Y##su; \

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_Nrounds(KeccakP1600_align128plain64_state *state, unsigned int nr)
{
    declareABCDE
    unsigned int i;
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    roundsN(nr)
    copyToState(stateAsLanes, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_12rounds(KeccakP1600_align128plain64_state *state)
{
    declareABCDE
    #ifndef KeccakP1600_XOP_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    rounds12
    copyToState(stateAsLanes, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_24rounds(KeccakP1600_align128plain64_state *state)
{
    declareABCDE
    #ifndef KeccakP1600_XOP_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    rounds24
    copyToState(stateAsLanes, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractBytes(const KeccakP1600_align128plain64_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    memcpy(data, (const unsigned char *)state+offset, length);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddBytesInLane(const KeccakP1600_align128plain64_state *state, unsigned int lanePosition, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    uint64_t lane = state->A[lanePosition];
    unsigned int i;
    uint64_t lane1[1];
    lane1[0] = lane;
    for(i=0; i<length; i++)
        output[i] = input[i] ^ ((uint8_t*)lane1)[offset+i];
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddLanes(const KeccakP1600_align128plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int laneCount)
{
    unsigned int i;

    for(i=0; i<laneCount; i++) {
        ((uint64_t*)output)[i] = ((uint64_t*)input)[i] ^ ((const uint64_t*)state)[i];
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_align128plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    SnP_ExtractAndAddBytes(state, input, output, offset, length, KeccakP1600_ExtractAndAddLanes, KeccakP1600_ExtractAndAddBytesInLane, 8);
}
