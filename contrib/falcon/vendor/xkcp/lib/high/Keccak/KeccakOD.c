/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

“Shaking up authenticated encryption”: Keccak-based duplex ciphers, deck ciphers and authenticated encryption schemes designed by Joan Daemen, Seth Hoffert, Silvia Mella, Gilles Van Assche and Ronny Van Keer

Implementation by Ronny Van Keer and Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "KeccakOD.h"
#include <assert.h>
#include <stdlib.h>

#if defined(DEBUG_DUMP)
#include <stdio.h>
static void DUMP( const unsigned char * pText, const unsigned char * pData, unsigned int size )
{
    unsigned int i;
    printf("%s (%u bytes):", pText, size);
    for(i=0; i<size; i++)
        printf(" %02x", (int)pData[i]);
    printf("\n");
}
#else
#define DUMP( pText, pData, size )
#endif

// OD -------------------------------------------------------------------------

#define MYMIN( a, b )   (((a) < (b)) ? (a) : (b))

static unsigned int OD_Concat( unsigned int E, unsigned int bt )
{
    assert( E >= 1u );
    assert( E <= 63u );
    assert( bt <= 1u );

    unsigned int top = 1u << 7u;
    while ( E < top ) {
        top >>= 1u;
    }
    return E + (top << bt);
}

#ifdef XKCP_has_KeccakP1600
    #define SnP_GetFeatures                 KeccakP1600_GetFeatures
    #define SnP_StaticInitialize            KeccakP1600_StaticInitialize
    #define SnP_Initialize                  KeccakP1600_Initialize
    #define SnP_AddByte                     KeccakP1600_AddByte
    #define SnP_AddBytes                    KeccakP1600_AddBytes
    #define SnP_OverwriteBytes              KeccakP1600_OverwriteBytes
    #define SnP_OverwriteWithZeroes         KeccakP1600_OverwriteWithZeroes
    #define SnP_ExtractBytes                KeccakP1600_ExtractBytes
    #define SnP_ExtractAndAddBytes          KeccakP1600_ExtractAndAddBytes

    #define SnP_Permute                     KeccakP1600_Permute_12rounds
    #define SnP_ODDuplexingFastInOut        KeccakP1600_12rounds_ODDuplexingFastInOut
    #define SnP_ODDuplexingFastOut          KeccakP1600_12rounds_ODDuplexingFastOut
    #define SnP_ODDuplexingFastIn           KeccakP1600_12rounds_ODDuplexingFastIn
    #define rounds                          rounds12
    #define prefix                          TurboSHAKE
    #define DOM_SEP                         0x00u
        #include "KeccakOD.inc"
    #undef SnP_Permute
    #undef SnP_ODDuplexingFastInOut
    #undef SnP_ODDuplexingFastOut
    #undef SnP_ODDuplexingFastIn
    #undef rounds
    #undef prefix
    #undef DOM_SEP

    #define SnP_Permute                     KeccakP1600_Permute_24rounds
    #define SnP_ODDuplexingFastInOut        KeccakP1600_ODDuplexingFastInOut
    #define SnP_ODDuplexingFastOut          KeccakP1600_ODDuplexingFastOut
    #define SnP_ODDuplexingFastIn           KeccakP1600_ODDuplexingFastIn
    #define rounds                          rounds24
    #define prefix                          SHAKE
    #define DOM_SEP                         0x1Fu
        #include "KeccakOD.inc"
    #undef SnP_Permute
    #undef SnP_ODDuplexingFastInOut
    #undef SnP_ODDuplexingFastOut
    #undef SnP_ODDuplexingFastIn
    #undef rounds
    #undef prefix
    #undef DOM_SEP
#endif
