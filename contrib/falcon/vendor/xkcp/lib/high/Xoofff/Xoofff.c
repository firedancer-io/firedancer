/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Xoofff, designed by Joan Daemen, Seth Hoffert, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

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
#include <stdio.h>
#include <stdlib.h>
#include "brg_endian.h"
#include "Xoofff.h"
#include "Xoodoo.h"
#ifdef XKCP_has_Xoodootimes16
#include "Xoodoo-times16-SnP.h"
#endif
#ifdef XKCP_has_Xoodootimes8
#include "Xoodoo-times8-SnP.h"
#endif
#ifdef XKCP_has_Xoodootimes4
#include "Xoodoo-times4-SnP.h"
#endif
#include "Xoodoo-SnP.h"

/*
** Uncomment this define if calls to Xoodoo_Initialize() and
** Xoodootimes##Parallellism##_InitializeAll() are mandatory to make it work,
** mostly not needed.
**
#define    NEED_INITIALIZE
*/

/*
** Uncomment this define for more debugging dumps.
**
#define    DEBUG_DUMP
*/

/*
 * Uncomment this define if your CPU can not handle misaligned memory accesses.
#define NO_MISALIGNED_ACCESSES
 */

#define laneSize        4
#define widthInLanes    (SnP_widthInBytes/laneSize)
#define SnP_width       (SnP_widthInBytes*8)

#define MyMin(a, b)     (((a) < (b)) ? (a) : (b))

#if defined(NEED_INITIALIZE)
#define mInitialize(argState)                   Xoodoo_Initialize(argState)
#define mInitializePl(argStates, Parallellism)  Xoodootimes##Parallellism##_InitializeAll(argStates)
#else
#define mInitialize(argState)
#define mInitializePl(argStates, Parallellism)
#endif

#if defined(DEBUG_DUMP)
static void DUMP( const unsigned char * pText, const unsigned char * pData, unsigned int size )
{
    unsigned int i;
    if (!(size % 4)) {
        uint32_t * p32 = (uint32_t*)pData;
        size /= 4;
        printf("%s:\n", pText, size);
        for(i=0; i<size; i++) {
            if (i&&!(i%12))
                printf("\n");
            printf(" %08x", p32[i]);
        }
        printf("\n");
    }
    else {
        printf("%s (%u bytes):", pText, size);
        for(i=0; i<size; i++)
            printf(" %02x", (int)pData[i]);
        printf("\n");
    }
}

static void DumpBuf( const unsigned char * pText, const unsigned char * pData, unsigned int size )
{
    unsigned int i;
    if (!(size % 4)) {
        uint32_t * p32 = (uint32_t*)pData;
        size /= 4;
        printf("%s:\n", pText, size);
        for(i=0; i<size; i++) {
            if (i&&!(i%12))
                printf("\n");
            printf(" %08x", p32[i]);
        }
        printf("\n");
    }
    else {
        printf("%s (%u bytes):", pText, size);
        for(i=0; i<size; i++)
            printf(" %02x", (int)pData[i]);
        printf("\n");
    }
}

#else
#define DUMP(pText, pData, size )
#define DumpBuf(pText, pData, size )
#endif


#define ParallelCompressLoopFast( Parallellism ) \
    if ( messageByteLen >= Parallellism * SnP_widthInBytes ) { \
        size_t processed = Xooffftimes##Parallellism##_CompressFastLoop((uint8_t*)k, (uint8_t*)x, message, messageByteLen); \
        message += processed; \
        messageByteLen -= processed; \
    }

#define ParallelExpandLoopFast( Parallellism ) \
    if ( outputByteLen >= Parallellism * SnP_widthInBytes ) { \
        size_t processed = Xooffftimes##Parallellism##_ExpandFastLoop((uint8_t*)xp->yAccu, (uint8_t*)xp->kRoll, output, outputByteLen); \
        output += processed; \
        outputByteLen -= processed; \
    }

#define ParallelCompressLoopPlSnP( Parallellism ) \
    if ( messageByteLen >= Parallellism * SnP_widthInBytes ) { \
        Xoodootimes##Parallellism##_states states; \
        unsigned int i; \
        \
        Xoodootimes##Parallellism##_StaticInitialize(); \
        mInitializePl(states, Parallellism); \
        do { \
            Xoofff_Rollc( (uint32_t*)k, encbuf, Parallellism ); \
            i = 0; \
            do { \
                Xoodootimes##Parallellism##_OverwriteBytes(&states, i, encbuf + i * Xoofff_RollSizeInBytes, Xoofff_RollOffset, Xoofff_RollSizeInBytes); \
            } while ( ++i < Parallellism ); \
            Xoodootimes##Parallellism##_AddLanesAll(&states, message, widthInLanes, widthInLanes); \
            DUMP("msg pn", message, Parallellism * SnP_widthInBytes); \
            Xoodootimes##Parallellism##_PermuteAll_6rounds(&states); \
            i = 0; \
            do { \
                Xoodootimes##Parallellism##_ExtractAndAddBytes(&states, i, x, x, 0, SnP_widthInBytes); \
                DUMP("xAc pn", x, SnP_widthInBytes); \
            } while ( ++i < Parallellism ); \
            message += Parallellism * SnP_widthInBytes; \
            messageByteLen -= Parallellism * SnP_widthInBytes; \
        } while ( messageByteLen >= Parallellism * SnP_widthInBytes ); \
    }

#define ParallelExpandLoopPlSnP( Parallellism ) \
    if ( outputByteLen >= Parallellism * SnP_widthInBytes ) { \
        Xoodootimes##Parallellism##_states states; \
        unsigned int i; \
        \
        Xoodootimes##Parallellism##_StaticInitialize(); \
        mInitializePl(states, Parallellism); \
        do { \
            Xoofff_Rolle( (uint32_t*)xp->yAccu, encbuf, Parallellism ); \
            i = 0; \
            do { \
                Xoodootimes##Parallellism##_OverwriteBytes(&states, i, encbuf + i * Xoofff_RollSizeInBytes, Xoofff_RollOffset, Xoofff_RollSizeInBytes); \
            } while ( ++i < Parallellism ); \
            Xoodootimes##Parallellism##_PermuteAll_6rounds(&states); \
            i = 0; \
            do { \
                Xoodootimes##Parallellism##_ExtractAndAddBytes(&states, i, xp->kRoll, output, 0, SnP_widthInBytes); \
                DUMP("out n", output, SnP_widthInBytes); \
                output += SnP_widthInBytes; \
            } while ( ++i < Parallellism ); \
            outputByteLen -= Parallellism * SnP_widthInBytes; \
        } while ( outputByteLen >= Parallellism * SnP_widthInBytes ); \
    }

static void Xoofff_Rollc( uint32_t *a, unsigned char *encbuf, unsigned int parallellism )
{
    uint32_t    b[NCOLUMS];
    #if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    uint32_t    *pEnc = (uint32_t*)encbuf;
    #endif

    do {
        #if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
        *(pEnc++) = a[0];
        *(pEnc++) = a[1];
        *(pEnc++) = a[2];
        *(pEnc++) = a[3];
        *(pEnc++) = a[4];
        *(pEnc++) = a[5];
        *(pEnc++) = a[6];
        *(pEnc++) = a[7];
        *(pEnc++) = a[8];
        *(pEnc++) = a[9];
        *(pEnc++) = a[10];
        *(pEnc++) = a[11];
        DUMP("Roll-c", pEnc - Xoofff_RollSizeInBytes/4, Xoofff_RollSizeInBytes);
        #else
        #error todo
        #endif

        a[0] ^= (a[0] << 13) ^ ROTL32(a[4], 3);
        b[0] = a[1];
        b[1] = a[2];
        b[2] = a[3];
        b[3] = a[0];

        a[0] = a[4+0];
        a[1] = a[4+1];
        a[2] = a[4+2];
        a[3] = a[4+3];

        a[4+0] = a[8+0];
        a[4+1] = a[8+1];
        a[4+2] = a[8+2];
        a[4+3] = a[8+3];

        a[8+0] = b[0];
        a[8+1] = b[1];
        a[8+2] = b[2];
        a[8+3] = b[3];
    } while(--parallellism != 0);
    DUMP("Roll-c next", a, Xoofff_RollSizeInBytes);
}

static void Xoofff_Rolle( uint32_t *a, unsigned char *encbuf, unsigned int parallellism )
{
    uint32_t    b[NCOLUMS];
    #if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    uint32_t    *pEnc = (uint32_t*)encbuf;
    #endif

    do {
        #if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
        *(pEnc++) = a[0];
        *(pEnc++) = a[1];
        *(pEnc++) = a[2];
        *(pEnc++) = a[3];
        *(pEnc++) = a[4];
        *(pEnc++) = a[5];
        *(pEnc++) = a[6];
        *(pEnc++) = a[7];
        *(pEnc++) = a[8];
        *(pEnc++) = a[9];
        *(pEnc++) = a[10];
        *(pEnc++) = a[11];
        DUMP("Roll-e", pEnc - Xoofff_RollSizeInBytes/4, Xoofff_RollSizeInBytes);
        #else
        #error todo
        #endif

        a[0] = ROTL32(a[0], 5) ^ ROTL32(a[4], 13) ^ (a[8] & a[4]) ^ 7;
        b[0] = a[1];
        b[1] = a[2];
        b[2] = a[3];
        b[3] = a[0];

        a[0] = a[4+0];
        a[1] = a[4+1];
        a[2] = a[4+2];
        a[3] = a[4+3];

        a[4+0] = a[8+0];
        a[4+1] = a[8+1];
        a[4+2] = a[8+2];
        a[4+3] = a[8+3];

        a[8+0] = b[0];
        a[8+1] = b[1];
        a[8+2] = b[2];
        a[8+3] = b[3];
    } while(--parallellism != 0);
    DUMP("Roll-e next", a, Xoofff_RollSizeInBytes);
}

void Xoofff_AddIs_dispatch(unsigned char *output, const unsigned char *input, size_t bitLen)
{
    if (Xoodoo_GetFeatures() & SnP_Feature_Farfalle)
        Xoofff_AddIs(output, input, bitLen);
    else {
        size_t  byteLen = bitLen / 8;

        #if !defined(NO_MISALIGNED_ACCESSES)
        while ( byteLen >= 32 ) {
            *((uint64_t*)(output+0)) ^= *((const uint64_t*)(input+0));
            *((uint64_t*)(output+8)) ^= *((const uint64_t*)(input+8));
            *((uint64_t*)(output+16)) ^= *((const uint64_t*)(input+16));
            *((uint64_t*)(output+24)) ^= *((const uint64_t*)(input+24));
            input += 32;
            output += 32;
            byteLen -= 32;
        }
        while ( byteLen >= 8 ) {
            *((uint64_t*)output) ^= *((const uint64_t*)input);
            input += 8;
            output += 8;
            byteLen -= 8;
        }
        #endif

        while ( byteLen-- != 0 )
        {
            *output++ ^= *input++;
        }

        bitLen &= 7;
        if (bitLen != 0)
        {
            *output ^= *input;
            *output &= (1 << bitLen) - 1;
        }
    }
}

size_t Xoofff_CompressFastLoop_dispatch(unsigned char *k, unsigned char *x, const unsigned char *input, size_t length)
{
    if (Xoodoo_GetFeatures() & SnP_Feature_Farfalle)
        return Xoofff_CompressFastLoop(k, x, input, length);
    else {
        unsigned char encbuf[Xoofff_RollSizeInBytes];
        Xoodoo_state state;
        size_t    initialLength = length;

        #if DEBUG
        assert(length >= SnP_widthInBytes);
        #endif
        Xoodoo_StaticInitialize();
        mInitialize(state);
        do {
            Xoodoo_OverwriteBytes(&state, k, 0, SnP_widthInBytes);
            Xoofff_Rollc((uint32_t*)k, encbuf, 1);
            Xoodoo_AddBytes(&state, input, 0, SnP_widthInBytes);
            DUMP("msg p1", input, SnP_widthInBytes);
            Xoodoo_Permute_6rounds(&state);
            Xoodoo_ExtractAndAddBytes(&state, x, x, 0, SnP_widthInBytes);
            DUMP("xAc p1", x, SnP_widthInBytes);
            input += SnP_widthInBytes;
            length -= SnP_widthInBytes;
        }
        while (length >= SnP_widthInBytes);

        return initialLength - length;
    }
}

size_t Xoofff_ExpandFastLoop_dispatch(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
{
    if (Xoodoo_GetFeatures() & SnP_Feature_Farfalle)
        return Xoofff_ExpandFastLoop(yAccu, kRoll, output, length);
    else {
        unsigned char encbuf[Xoofff_RollSizeInBytes];
        Xoodoo_state state;
        size_t    initialLength = length;

        #if DEBUG
        assert(length >= SnP_widthInBytes);
        #endif
        Xoodoo_StaticInitialize();
        mInitialize(state);
        do {
            Xoodoo_OverwriteBytes(&state, yAccu, 0, SnP_widthInBytes);
            Xoofff_Rolle((uint32_t*)yAccu, encbuf, 1);
            Xoodoo_Permute_6rounds(&state);
            Xoodoo_ExtractAndAddBytes(&state, kRoll, output, 0, SnP_widthInBytes);
            DUMP("out 1", output, SnP_widthInBytes);
            output += SnP_widthInBytes;
            length -= SnP_widthInBytes;
        } while (length >= SnP_widthInBytes);

        return initialLength - length;
    }
}

static const unsigned char * Xoodoo_CompressBlocks( unsigned char *k, unsigned char *x, const BitSequence *message, BitLength *messageBitLen, int lastFlag )
{
    ALIGN(XoodooAlignment) unsigned char encbuf[XoodooMaxParallellism*Xoofff_RollSizeInBytes];
    size_t messageByteLen = *messageBitLen / 8; /* do not include partial last byte */

    #if defined(XKCP_has_Xoodootimes16)
    if (Xoodootimes16_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelCompressLoopFast( 16 )
    }
    else if (Xoodootimes16_GetFeatures() & PlSnP_Feature_Main) {
        ParallelCompressLoopPlSnP( 16 )
    }
    #endif
    #if defined(XKCP_has_Xoodootimes8)
    if (Xoodootimes8_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelCompressLoopFast( 8 )
    }
    else if (Xoodootimes8_GetFeatures() & PlSnP_Feature_Main) {
        ParallelCompressLoopPlSnP( 8 )
    }
    #endif
    #if defined(XKCP_has_Xoodootimes4)
    if (Xoodootimes4_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelCompressLoopFast( 4 )
    }
    else if (Xoodootimes4_GetFeatures() & PlSnP_Feature_Main) {
        ParallelCompressLoopPlSnP( 4 )
    }
    #endif
    #if defined(XKCP_has_Xoodootimes2)
    if (Xoodootimes2_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelCompressLoopFast( 2 )
    }
    else if (Xoodootimes2_GetFeatures() & PlSnP_Feature_Main) {
        ParallelCompressLoopPlSnP( 2 )
    }
    #endif

    if (messageByteLen >= SnP_widthInBytes) {
        size_t processed = Xoofff_CompressFastLoop_dispatch(k, x, message, messageByteLen);
        message += processed;
        messageByteLen -= processed;
    }
    *messageBitLen %= SnP_width;
    if ( lastFlag != 0 ) {
        Xoodoo_state state;

        #if DEBUG
        assert(messageByteLen < SnP_widthInBytes);
        #endif
        Xoodoo_StaticInitialize();
        mInitialize(state);
        Xoodoo_OverwriteBytes(&state, k, 0, SnP_widthInBytes); /* write k */
        Xoofff_Rollc((uint32_t*)k, encbuf, 1);
        Xoodoo_AddBytes(&state, message, 0, (unsigned int)messageByteLen); /* add message */
        DUMP("msg pL", &state, SnP_widthInBytes);
        message += messageByteLen;
        *messageBitLen %= 8;
        if (*messageBitLen != 0) /* padding */
            Xoodoo_AddByte(&state, *message++ | (1 << *messageBitLen), messageByteLen);
        else
            Xoodoo_AddByte(&state, 1, messageByteLen);
        Xoodoo_Permute_6rounds(&state);
        Xoodoo_ExtractAndAddBytes(&state, x, x, 0, SnP_widthInBytes);
        DUMP("xAc pL", x, SnP_widthInBytes);
        Xoofff_Rollc((uint32_t*)k, encbuf, 1);
        *messageBitLen = 0;
    }
    return message;
}

int Xoofff_MaskDerivation(Xoofff_Instance *xp, const BitSequence *Key, BitLength KeyBitLen)
{
    Xoodoo_state state;
    BitSequence lastByte;
    unsigned int numberOfBits;

    /* Check max K length (b-1) */
    if (KeyBitLen >= SnP_width)
        return 1;
    /* Compute k from K */
    memset(xp->k, 0, SnP_widthInBytes);
    memcpy(xp->k, Key, KeyBitLen/8);
    numberOfBits = KeyBitLen & 7;
    if ((numberOfBits) != 0) {
        lastByte = (Key[KeyBitLen/8] & ((1 << numberOfBits) - 1)) | (1 << numberOfBits);
    }
    else {
        lastByte = 1;
    }
    xp->k[KeyBitLen/8] = lastByte;
    Xoodoo_StaticInitialize();
    mInitialize(state);
    Xoodoo_OverwriteBytes(&state, xp->k, 0, SnP_widthInBytes);
    Xoodoo_Permute_6rounds(&state);
    Xoodoo_ExtractBytes(&state, xp->k, 0, SnP_widthInBytes);
    memcpy(xp->kRoll, xp->k, SnP_widthInBytes);
    memset(xp->xAccu, 0, SnP_widthInBytes);
    xp->phase = COMPRESSING;
    xp->queueOffset = 0;

    return 0;
}

int Xoofff_Compress(Xoofff_Instance *xp, const BitSequence *input, BitLength inputBitLen, int flags)
{
    int finalFlag = flags & Xoofff_FlagLastPart;

    if ((finalFlag == 0) && ((inputBitLen & 7) != 0))
        return 1;
    if ( (flags & Xoofff_FlagInit) != 0 ) {
        memcpy(xp->kRoll, xp->k, SnP_widthInBytes);
        memset(xp->xAccu, 0, SnP_widthInBytes);
        xp->queueOffset = 0;
    }
    if (xp->phase != COMPRESSING) {
        xp->phase = COMPRESSING;
        xp->queueOffset = 0;
    }
    else if ( xp->queueOffset != 0 ) { /* we have already some data queued */
        unsigned int bitlen = (unsigned int)MyMin(inputBitLen, SnP_width - xp->queueOffset);
        unsigned int bytelen = (bitlen + 7) / 8;

        memcpy(xp->queue + xp->queueOffset / 8, input, bytelen);
        input += bytelen;
        inputBitLen -= bitlen;
        xp->queueOffset += bitlen;
        if ( xp->queueOffset == SnP_width ) { /* queue full */
            Xoodoo_CompressBlocks(xp->kRoll, xp->xAccu, xp->queue, &xp->queueOffset, 0);
            xp->queueOffset = 0;
        }
        else if ( finalFlag != 0 ) {
            Xoodoo_CompressBlocks(xp->kRoll, xp->xAccu, xp->queue, &xp->queueOffset, 1);
            return 0;
        }
    }
    if ( (inputBitLen >= SnP_width) || (finalFlag != 0) ) { /* Compress blocks */
        input = Xoodoo_CompressBlocks(xp->kRoll, xp->xAccu, input, &inputBitLen, finalFlag);
    }
    if ( inputBitLen != 0 ) { /* Queue eventual residual message bytes */
        #if DEBUG
        assert( inputBitLen < SnP_width );
        assert( finalFlag == 0 );
        #endif
        memcpy(xp->queue, input, inputBitLen/8);
        xp->queueOffset = inputBitLen;
    }
    return 0;
}

int Xoofff_Expand(Xoofff_Instance *xp, BitSequence *output, BitLength outputBitLen, int flags)
{
    size_t outputByteLen;
    ALIGN(XoodooAlignment) unsigned char encbuf[XoodooMaxParallellism*Xoofff_RollSizeInBytes];
    int finalFlag = flags & Xoofff_FlagLastPart;

    if ((finalFlag == 0) && ((outputBitLen & 7) != 0))
        return 1;
    if ( xp->phase == COMPRESSING) {
        if ( xp->queueOffset != 0 )
            return 1;
        if ((flags & Xoofff_FlagXoofffie) != 0) {
            memcpy(xp->yAccu, xp->xAccu, SnP_widthInBytes);
        }
        else {
            Xoodoo_state state;

            Xoodoo_StaticInitialize();
            mInitialize(state);
            Xoodoo_OverwriteBytes(&state, xp->xAccu, 0, SnP_widthInBytes);
            Xoodoo_Permute_6rounds(&state);
            Xoodoo_ExtractBytes(&state, xp->yAccu, 0, SnP_widthInBytes);
        }
        xp->phase = EXPANDING;
        DUMP("yAccu", xp->yAccu, SnP_widthInBytes);
        DUMP("key  ", xp->k, SnP_widthInBytes);
    }
    else if (xp->phase != EXPANDING)
        return 1;
    if ( xp->queueOffset != 0 ) { /* we have already some data for output in stock */
        unsigned int bitlen = (unsigned int)MyMin(outputBitLen, SnP_widthInBytes*8 - xp->queueOffset);
        unsigned int bytelen = (bitlen + 7) / 8;

        memcpy(output, xp->queue + xp->queueOffset / 8, bytelen);
        xp->queueOffset += bitlen;
        if (xp->queueOffset == SnP_widthInBytes*8)
            xp->queueOffset = 0;
        output += bytelen;
        outputBitLen -= bitlen;
        if ((finalFlag != 0) && (outputBitLen == 0)) {
            bitlen &= 7;
            if (bitlen != 0) /* cleanup last incomplete byte */
                *(output - 1) &= (1 << bitlen) - 1;
            xp->phase = EXPANDED;
            return 0;
        }
    }

    outputByteLen = (outputBitLen + 7) / 8;
    #if defined(XKCP_has_Xoodootimes16)
    if (Xoodootimes16_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelExpandLoopFast( 16 )
    }
    else if (Xoodootimes16_GetFeatures() & PlSnP_Feature_Main) {
        ParallelExpandLoopPlSnP( 16 )
    }
    #endif
    #if defined(XKCP_has_Xoodootimes8)
    if (Xoodootimes8_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelExpandLoopFast( 8 )
    }
    else if (Xoodootimes8_GetFeatures() & PlSnP_Feature_Main) {
        ParallelExpandLoopPlSnP( 8 )
    }
    #endif
    #if defined(XKCP_has_Xoodootimes4)
    if (Xoodootimes4_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelExpandLoopFast( 4 )
    }
    else if (Xoodootimes4_GetFeatures() & PlSnP_Feature_Main) {
        ParallelExpandLoopPlSnP( 4 )
    }
    #endif
    #if defined(XKCP_has_Xoodootimes2)
    if (Xoodootimes2_GetFeatures() & PlSnP_Feature_Farfalle) {
        ParallelExpandLoopFast( 2 )
    }
    else if (Xoodootimes2_GetFeatures() & PlSnP_Feature_Main) {
        ParallelExpandLoopPlSnP( 2 )
    }
    #endif

    if ( outputByteLen >= SnP_widthInBytes ) {
        size_t processed = Xoofff_ExpandFastLoop_dispatch(xp->yAccu, xp->kRoll, output, outputByteLen);
        output += processed;
        outputByteLen -= processed;
    }
    if ( outputByteLen != 0 ) {    /* Last incomplete block */
        Xoodoo_state state;

        #if DEBUG
        assert(outputByteLen <= SnP_widthInBytes);
        #endif
        Xoodoo_StaticInitialize();
        mInitialize(state);
        Xoodoo_OverwriteBytes(&state, xp->yAccu, 0, SnP_widthInBytes);
        Xoofff_Rolle((uint32_t*)xp->yAccu, encbuf, 1);
        Xoodoo_Permute_6rounds(&state);
        Xoodoo_ExtractAndAddBytes(&state, xp->kRoll, output, 0, (unsigned int)outputByteLen);
        DUMP("out 1", output, outputByteLen);
        output += outputByteLen;
        if (!finalFlag) { /* Put rest of expanded data into queue */
            unsigned int offset = (unsigned int)outputByteLen;
            Xoodoo_ExtractAndAddBytes(&state, xp->kRoll + offset, xp->queue + offset, offset, SnP_widthInBytes - (unsigned int)outputByteLen);
            xp->queueOffset = offset * 8; /* current bit offset in queue buffer */
        }
    }
    if (finalFlag != 0) {
        outputBitLen &= 7;
        if (outputBitLen != 0) { /* cleanup last incomplete byte */
            *(output - 1) &= (1 << outputBitLen) - 1;
            DUMP("out L", output - 1, 1);
        }
        xp->phase = EXPANDED;
    }
    return 0;
}

int Xoofff(Xoofff_Instance *xp, const BitSequence *input, BitLength inputBitLen, BitSequence *output, BitLength outputBitLen, int flags)
{

    flags |= Xoofff_FlagLastPart;
    if ( Xoofff_Compress(xp, input, inputBitLen, flags) != 0 )
        return 1;
    return Xoofff_Expand(xp, output, outputBitLen, flags);
}
