/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

KangarooTwelve, designed by Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, Ronny Van Keer and Benoît Viguier.

Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#if DEBUG
#include <assert.h>
#endif
#include <string.h>
#include <stdint.h>
#include "KangarooTwelve.h"

#ifdef XKCP_has_KeccakP1600times2
    #include "KeccakP-1600-times2-SnP.h"
#endif

#ifdef XKCP_has_KeccakP1600times4
    #include "KeccakP-1600-times4-SnP.h"
#endif

#ifdef XKCP_has_KeccakP1600times8
    #include "KeccakP-1600-times8-SnP.h"
#endif

#define chunkSize       8192
#define laneSize        8
#define suffixLeaf      0x0B /* '110': message hop, simple padding, inner node */

#define maxCapacityInBytes  64

#define ParallelSpongeFastLoop( Parallellism ) \
    while ( inLen >= Parallellism * chunkSize ) { \
        KeccakP1600times##Parallellism##_states states; \
        unsigned char intermediate[Parallellism*capacityInBytes]; \
        unsigned int localBlockLen = chunkSize; \
        const unsigned char * localInput = input; \
        unsigned int i; \
        unsigned int fastLoopOffset; \
        \
        KeccakP1600times##Parallellism##_StaticInitialize(); \
        KeccakP1600times##Parallellism##_InitializeAll(&states); \
        fastLoopOffset = (unsigned int)KeccakP1600times##Parallellism##_12rounds_FastLoop_Absorb(&states, rateInLanes, chunkSize / laneSize, rateInLanes, localInput, Parallellism * chunkSize); \
        localBlockLen -= fastLoopOffset; \
        localInput += fastLoopOffset; \
        for ( i = 0; i < Parallellism; ++i, localInput += chunkSize ) { \
            KeccakP1600times##Parallellism##_AddBytes(&states, i, localInput, 0, localBlockLen); \
            KeccakP1600times##Parallellism##_AddByte(&states, i, suffixLeaf, localBlockLen); \
            KeccakP1600times##Parallellism##_AddByte(&states, i, 0x80, rateInBytes-1); \
        } \
        KeccakP1600times##Parallellism##_PermuteAll_12rounds(&states); \
        input += Parallellism * chunkSize; \
        inLen -= Parallellism * chunkSize; \
        ktInstance->blockNumber += Parallellism; \
        KeccakP1600times##Parallellism##_ExtractLanesAll(&states, intermediate, capacityInLanes, capacityInLanes ); \
        if (TurboSHAKE_Absorb(&ktInstance->finalNode, intermediate, Parallellism * capacityInBytes) != 0) return 1; \
            }

#define ParallelSpongeLoop( Parallellism ) \
    while ( inLen >= Parallellism * chunkSize ) { \
        KeccakP1600times##Parallellism##_states states; \
        unsigned char intermediate[Parallellism*capacityInBytes]; \
        unsigned int localBlockLen = chunkSize; \
        const unsigned char * localInput = input; \
        unsigned int i; \
        \
        KeccakP1600times##Parallellism##_StaticInitialize(); \
        KeccakP1600times##Parallellism##_InitializeAll(&states); \
        while(localBlockLen >= rateInBytes) { \
            KeccakP1600times##Parallellism##_AddLanesAll(&states, localInput, rateInLanes, chunkSize / laneSize); \
            KeccakP1600times##Parallellism##_PermuteAll_12rounds(&states); \
            localBlockLen -= rateInBytes; \
            localInput += rateInBytes; \
           } \
        for ( i = 0; i < Parallellism; ++i, localInput += chunkSize ) { \
            KeccakP1600times##Parallellism##_AddBytes(&states, i, localInput, 0, localBlockLen); \
            KeccakP1600times##Parallellism##_AddByte(&states, i, suffixLeaf, localBlockLen); \
            KeccakP1600times##Parallellism##_AddByte(&states, i, 0x80, rateInBytes-1); \
        } \
        KeccakP1600times##Parallellism##_PermuteAll_12rounds(&states); \
        input += Parallellism * chunkSize; \
        inLen -= Parallellism * chunkSize; \
        ktInstance->blockNumber += Parallellism; \
        KeccakP1600times##Parallellism##_ExtractLanesAll(&states, intermediate, capacityInLanes, capacityInLanes ); \
        if (TurboSHAKE_Absorb(&ktInstance->finalNode, intermediate, Parallellism * capacityInBytes) != 0) return 1; \
}

#define ProcessLeavesKT128( Parallellism ) \
    while ( inLen >= Parallellism * chunkSize ) { \
        unsigned char intermediate[Parallellism*32]; \
        \
        KeccakP1600times##Parallellism##_KT128ProcessLeaves(input, intermediate); \
        input += Parallellism * chunkSize; \
        inLen -= Parallellism * chunkSize; \
        ktInstance->blockNumber += Parallellism; \
        if (TurboSHAKE_Absorb(&ktInstance->finalNode, intermediate, Parallellism * 32) != 0) return 1; \
    }

#define ProcessLeavesKT256( Parallellism ) \
    while ( inLen >= Parallellism * chunkSize ) { \
        unsigned char intermediate[Parallellism*64]; \
        \
        KeccakP1600times##Parallellism##_KT256ProcessLeaves(input, intermediate); \
        input += Parallellism * chunkSize; \
        inLen -= Parallellism * chunkSize; \
        ktInstance->blockNumber += Parallellism; \
        if (TurboSHAKE_Absorb(&ktInstance->finalNode, intermediate, Parallellism * 64) != 0) return 1; \
    }

static unsigned int right_encode(unsigned char * encbuf, size_t value)
{
    unsigned int n, i;
    size_t v;

    for (v = value, n = 0; v && (n < sizeof(size_t)); ++n, v >>= 8)
        ; /* empty */
    for (i = 1; i <= n; ++i) {
        encbuf[i-1] = (unsigned char)(value >> (8 * (n-i)));
    }
    encbuf[n] = (unsigned char)n;
    return n + 1;
}

int KangarooTwelve_Initialize(KangarooTwelve_Instance *ktInstance, int securityLevel, size_t outputByteLen)
{
    if ((securityLevel != 128) && (securityLevel != 256))
        return 1;
    ktInstance->fixedOutputLength = outputByteLen;
    ktInstance->queueAbsorbedLen = 0;
    ktInstance->blockNumber = 0;
    ktInstance->phase = ABSORBING;
    ktInstance->securityLevel = securityLevel;
    return TurboSHAKE_Initialize(&ktInstance->finalNode, 2*securityLevel);
}

int KangarooTwelve_Update(KangarooTwelve_Instance *ktInstance, const unsigned char *input, size_t inLen)
{
    unsigned int capacity = ktInstance->securityLevel*2;
    unsigned int capacityInBytes = capacity/8;
    unsigned int capacityInLanes = capacity/64;
    unsigned int rate = 1600 - capacity;
    unsigned int rateInBytes = rate/8;
    unsigned int rateInLanes = rate/64;

    if (ktInstance->phase != ABSORBING)
        return 1;

    if (ktInstance->blockNumber == 0) {
        /* First block, absorb in final node */
        unsigned int len = (inLen < (chunkSize - ktInstance->queueAbsorbedLen)) ? (unsigned int)inLen : (chunkSize - ktInstance->queueAbsorbedLen);
        if (TurboSHAKE_Absorb(&ktInstance->finalNode, input, len) != 0)
            return 1;
        input += len;
        inLen -= len;
        ktInstance->queueAbsorbedLen += len;
        if ( (ktInstance->queueAbsorbedLen == chunkSize) && (inLen != 0) ) {
            /* First block complete and more input data available, finalize it */
            const unsigned char padding = 0x03; /* '110^6': message hop, simple padding */
            ktInstance->queueAbsorbedLen = 0;
            ktInstance->blockNumber = 1;
            if (TurboSHAKE_Absorb(&ktInstance->finalNode, &padding, 1) != 0)
                return 1;
            ktInstance->finalNode.byteIOIndex = (ktInstance->finalNode.byteIOIndex + 7) & ~7; /* Zero padding up to 64 bits */
        }
    }
    else if ( ktInstance->queueAbsorbedLen != 0 ) {
        /* There is data in the queue, absorb further in queue until block complete */
        unsigned int len = (inLen < (chunkSize - ktInstance->queueAbsorbedLen)) ? (unsigned int)inLen : (chunkSize - ktInstance->queueAbsorbedLen);
        if (TurboSHAKE_Absorb(&ktInstance->queueNode, input, len) != 0)
            return 1;
        input += len;
        inLen -= len;
        ktInstance->queueAbsorbedLen += len;
        if ( ktInstance->queueAbsorbedLen == chunkSize ) {
            unsigned char intermediate[maxCapacityInBytes];
#if DEBUG
            assert(capacityInBytes <= maxCapacityInBytes);
#endif
            ktInstance->queueAbsorbedLen = 0;
            ++ktInstance->blockNumber;
            if (TurboSHAKE_AbsorbDomainSeparationByte(&ktInstance->queueNode, suffixLeaf) != 0)
                return 1;
            if (TurboSHAKE_Squeeze(&ktInstance->queueNode, intermediate, capacityInBytes) != 0)
                return 1;
            if (TurboSHAKE_Absorb(&ktInstance->finalNode, intermediate, capacityInBytes) != 0)
                return 1;
        }
    }

#ifdef XKCP_has_KeccakP1600times8
    if (KeccakP1600times8_GetFeatures()) {
        if (KeccakP1600times8_GetFeatures() & PlSnP_Feature_KangarooTwelve) {
            if (ktInstance->securityLevel == 128) {
                ProcessLeavesKT128( 8 )
            }
            else {
                ProcessLeavesKT256( 8 )
            }
        }
        else if (KeccakP1600times8_GetFeatures() & PlSnP_Feature_SpongeAbsorb) {
            ParallelSpongeFastLoop( 8 )
        }
        else {
            ParallelSpongeLoop( 8 )
        }
    }
#endif

#ifdef XKCP_has_KeccakP1600times4
    if (KeccakP1600times4_GetFeatures()) {
        if (KeccakP1600times4_GetFeatures() & PlSnP_Feature_KangarooTwelve) {
            if (ktInstance->securityLevel == 128) {
                ProcessLeavesKT128( 4 )
            }
            else {
                ProcessLeavesKT256( 4 )
            }
        }
        else if (KeccakP1600times4_GetFeatures() & PlSnP_Feature_SpongeAbsorb) {
            ParallelSpongeFastLoop( 4 )
        }
        else {
            ParallelSpongeLoop( 4 )
        }
    }
#endif

#ifdef XKCP_has_KeccakP1600times2
    if (KeccakP1600times2_GetFeatures()) {
        if (KeccakP1600times2_GetFeatures() & PlSnP_Feature_KangarooTwelve) {
            if (ktInstance->securityLevel == 128) {
                ProcessLeavesKT128( 2 )
            }
            else {
                ProcessLeavesKT256( 2 )
            }
        }
        else if (KeccakP1600times2_GetFeatures() & PlSnP_Feature_SpongeAbsorb) {
            ParallelSpongeFastLoop( 2 )
        }
        else {
            ParallelSpongeLoop( 2 )
        }
    }
#endif

    while ( inLen > 0 ) {
        unsigned int len = (inLen < chunkSize) ? (unsigned int)inLen : chunkSize;
        if (TurboSHAKE_Initialize(&ktInstance->queueNode, 2*ktInstance->securityLevel) != 0)
            return 1;
        if (TurboSHAKE_Absorb(&ktInstance->queueNode, input, len) != 0)
            return 1;
        input += len;
        inLen -= len;
        if ( len == chunkSize ) {
            unsigned char intermediate[maxCapacityInBytes];
#if DEBUG
            assert(capacityInBytes <= maxCapacityInBytes);
#endif
            ++ktInstance->blockNumber;
            if (TurboSHAKE_AbsorbDomainSeparationByte(&ktInstance->queueNode, suffixLeaf) != 0)
                return 1;
            if (TurboSHAKE_Squeeze(&ktInstance->queueNode, intermediate, capacityInBytes) != 0)
                return 1;
            if (TurboSHAKE_Absorb(&ktInstance->finalNode, intermediate, capacityInBytes) != 0)
                return 1;
        }
        else
            ktInstance->queueAbsorbedLen = len;
    }

    return 0;
}

int KangarooTwelve_Final(KangarooTwelve_Instance *ktInstance, unsigned char * output, const unsigned char * customization, size_t customLen)
{
    unsigned int capacity = ktInstance->securityLevel*2;
    unsigned int capacityInBytes = capacity/8;
    unsigned char encbuf[sizeof(size_t)+1+2];
    unsigned char padding;

    if (ktInstance->phase != ABSORBING)
        return 1;

    /* Absorb customization | right_encode(customLen) */
    if ((customLen != 0) && (KangarooTwelve_Update(ktInstance, customization, customLen) != 0))
        return 1;
    if (KangarooTwelve_Update(ktInstance, encbuf, right_encode(encbuf, customLen)) != 0)
        return 1;

    if (ktInstance->blockNumber == 0) {
        /* Non complete first block in final node, pad it */
        padding = 0x07; /*  '11': message hop, final node */
    }
    else {
        unsigned int n;

        if (ktInstance->queueAbsorbedLen != 0) {
            /* There is data in the queue node */
            unsigned char intermediate[maxCapacityInBytes];
#if DEBUG
            assert(capacityInBytes <= maxCapacityInBytes);
#endif
            ++ktInstance->blockNumber;
            if (TurboSHAKE_AbsorbDomainSeparationByte(&ktInstance->queueNode, suffixLeaf) != 0)
                return 1;
            if (TurboSHAKE_Squeeze(&ktInstance->queueNode, intermediate, capacityInBytes) != 0)
                return 1;
            if (TurboSHAKE_Absorb(&ktInstance->finalNode, intermediate, capacityInBytes) != 0)
                return 1;
        }
        --ktInstance->blockNumber; /* Absorb right_encode(number of Chaining Values) || 0xFF || 0xFF */
        n = right_encode(encbuf, ktInstance->blockNumber);
        encbuf[n++] = 0xFF;
        encbuf[n++] = 0xFF;
        if (TurboSHAKE_Absorb(&ktInstance->finalNode, encbuf, n) != 0)
            return 1;
        padding = 0x06; /* '01': chaining hop, final node */
    }
    if (TurboSHAKE_AbsorbDomainSeparationByte(&ktInstance->finalNode, padding) != 0)
        return 1;
    if (ktInstance->fixedOutputLength != 0) {
        ktInstance->phase = FINAL;
        return TurboSHAKE_Squeeze(&ktInstance->finalNode, output, ktInstance->fixedOutputLength);
    }
    ktInstance->phase = SQUEEZING;
    return 0;
}

int KangarooTwelve_Squeeze(KangarooTwelve_Instance *ktInstance, unsigned char * output, size_t outputLen)
{
    if (ktInstance->phase != SQUEEZING)
        return 1;
    return TurboSHAKE_Squeeze(&ktInstance->finalNode, output, outputLen);
}

int KangarooTwelve(int securityLevel, const unsigned char * input, size_t inLen, unsigned char * output, size_t outLen, const unsigned char * customization, size_t customLen)
{
    KangarooTwelve_Instance ktInstance;

    if (outLen == 0)
        return 1;
    if (KangarooTwelve_Initialize(&ktInstance, securityLevel, outLen) != 0)
        return 1;
    if (KangarooTwelve_Update(&ktInstance, input, inLen) != 0)
        return 1;
    return KangarooTwelve_Final(&ktInstance, output, customization, customLen);
}

/* ---------------------------------------------------------------- */

int KT128(const unsigned char *input, size_t inputByteLen,
                   unsigned char *output, size_t outputByteLen,
                   const unsigned char *customization, size_t customByteLen)
{
    return KangarooTwelve(128, input, inputByteLen, output, outputByteLen, customization, customByteLen);
}

int KT256(const unsigned char *input, size_t inputByteLen,
                   unsigned char *output, size_t outputByteLen,
                   const unsigned char *customization, size_t customByteLen)
{
    return KangarooTwelve(256, input, inputByteLen, output, outputByteLen, customization, customByteLen);
}
