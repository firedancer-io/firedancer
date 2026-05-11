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

#include "align.h"

#define JOIN0(a, b)                     a ## b
#define JOIN(a, b)                      JOIN0(a, b)

#define OD_TrailencAndXor               JOIN(prefix, _OD_TrailencAndXor)
#define OD_Initialize                   JOIN(prefix, _OD_Initialize)
#define OD_Clone                        JOIN(prefix, _OD_Clone)
#define OD_CloneCompact                 JOIN(prefix, _OD_CloneCompact)
#define OD_Duplexing                    JOIN(prefix, _OD_Duplexing)
#define OD_DuplexingFast                JOIN(prefix, _OD_DuplexingFast)
#define OD_DuplexingFastOnlyOut         JOIN(prefix, _OD_DuplexingFastOnlyOut)
#define OD_DuplexingFastOnlyIn          JOIN(prefix, _OD_DuplexingFastOnlyIn)
#define OD_Squeezing                    JOIN(prefix, _OD_Squeezing)

// OD -------------------------------------------------------------------------

static void OD_TrailencAndXor( KeccakWidth1600_ODInstance *od, uint8_t D )
{
    ALIGN(8) const uint8_t  trailenc[8] = { D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 + DOM_SEP };
    SnP_AddBytes( &od->s, trailenc, od->rho, sizeof(trailenc) );
}

void OD_Initialize( KeccakWidth1600_ODInstance *od, unsigned int rho, unsigned int c, const uint8_t *k, unsigned int klen )
{

    od->o       = rho;
    od->c       = c;
    od->rho     = rho;
    SnP_StaticInitialize();
    SnP_Initialize( &od->s );
    OD_Duplexing( od, NULL, 0, k, klen, 1, NULL );
}

void OD_Clone( KeccakWidth1600_ODInstance *odnew, const KeccakWidth1600_ODInstance *od )
{
    *odnew = *od;
}

void OD_CloneCompact( KeccakWidth1600_ODInstance *odnew, const KeccakWidth1600_ODInstance *od )
{
    *odnew = *od;
    odnew->o = odnew->rho;
    SnP_OverwriteWithZeroes( &odnew->s, odnew->rho );
}

size_t OD_DuplexingFast( KeccakWidth1600_ODInstance *od, const uint8_t *idata, size_t len, unsigned int E, uint8_t *odata, const uint8_t *odataAdd )
{
    assert( E >= 1u );
    assert( E <= 63u );
    assert( len >= od->rho );
    assert( odataAdd != NULL );

    ALIGN(8) const uint8_t  trailenc[8]     = { OD_Concat( E, 1u ), 0u, 0u, 0u, 0u, 0u, 0u, 0x80u + DOM_SEP };
    unsigned int            r               = od->rho;

    od->o = r;

    if (SnP_GetFeatures() & SnP_Feature_OD)
        return SnP_ODDuplexingFastInOut(&od->s, r/8, idata, len, odata, odataAdd, *(const uint64_t*)trailenc);

    size_t  initialLen = len;
    do {
        SnP_OverwriteBytes( &od->s, idata, 0, r );
        SnP_AddBytes( &od->s, trailenc, r, sizeof(trailenc) );
        SnP_Permute( &od->s );
        SnP_ExtractAndAddBytes( &od->s, odataAdd, odata, 0, r );
        odataAdd += r;
        odata += r;
        idata += r;
        len -= r;
    }
    while ( len >= od->rho );

    return initialLen - len; // bytes processed
}

size_t OD_DuplexingFastOnlyOut( KeccakWidth1600_ODInstance *od, unsigned int E, uint8_t *odata, size_t len, const uint8_t *odataAdd )
{
    assert( E >= 1u );
    assert( E <= 63u );
    assert( len >= od->rho );
    assert( odataAdd != NULL );

    ALIGN(8) const uint8_t  trailenc[8] = { OD_Concat( E, 0u ), 0u, 0u, 0u, 0u, 0u, 0u, 0x80u + DOM_SEP };
    unsigned int            r           = od->rho;

    od->o = r;

    if (SnP_GetFeatures() & SnP_Feature_OD)
        return SnP_ODDuplexingFastOut( &od->s, r/8, odata, len, odataAdd, *(const uint64_t*)trailenc );

    size_t  initialLen = len;
    do {
        SnP_OverwriteWithZeroes( &od->s, r );
        SnP_AddByte( &od->s, 1, 0 );
        SnP_AddBytes( &od->s, trailenc, r, sizeof(trailenc) );
        SnP_Permute( &od->s );
        SnP_ExtractAndAddBytes( &od->s, odataAdd, odata, 0, r );
        odataAdd += r;
        odata += r;
        len -= r;
    }
    while ( len >= od->rho );

    return initialLen - len; // bytes processed
}

size_t OD_DuplexingFastOnlyIn( KeccakWidth1600_ODInstance *od, const uint8_t *idata, size_t len, unsigned int E )
{
    assert( E >= 1u );
    assert( E <= 63u );
    assert( len > od->rho );

    ALIGN(8) const uint8_t  trailenc[8] = { OD_Concat( E, 1u ), 0u, 0u, 0u, 0u, 0u, 0u, 0x80u + DOM_SEP };
    unsigned int            r           = od->rho;

    od->o = 0;

    if (SnP_GetFeatures() & SnP_Feature_OD)
        return SnP_ODDuplexingFastIn( &od->s, r/8, idata, len, *(const uint64_t*)trailenc );

    size_t initialLen = len;
    do {
        SnP_OverwriteBytes( &od->s, idata, 0, r );
        SnP_AddBytes( &od->s, trailenc, r, sizeof(trailenc) );
        SnP_Permute( &od->s );
        idata += r;
        len -= r;
    }
    while ( len > od->rho );

    return initialLen - len; // bytes processed
}

void OD_Duplexing( KeccakWidth1600_ODInstance *od, uint8_t *odata, unsigned int olen, const uint8_t *idata, unsigned int ilen, unsigned int E, const uint8_t *odataAdd )
{

    assert( E >= 1u );
    assert( E <= 63u );
    assert( od->rho != 0u );
    assert( ilen <= od->rho );
    assert( olen <= od->rho );
    if ( ilen == od->rho ) {
        SnP_OverwriteBytes( &od->s, idata, 0u, ilen );
        OD_TrailencAndXor( od, OD_Concat( E, 1u ) );
    }
    else {
        SnP_OverwriteWithZeroes( &od->s, od->rho );
        SnP_OverwriteBytes( &od->s, idata, 0u, ilen );
        SnP_AddByte( &od->s, 1u, ilen );
        OD_TrailencAndXor( od, OD_Concat( E, 0u ) );
    }
    SnP_Permute( &od->s );
    if ( odataAdd != NULL ) {
        SnP_ExtractAndAddBytes( &od->s, odataAdd, odata, 0u, olen );
    }
    else {
        SnP_ExtractBytes( &od->s, odata, 0u, olen );
    }
    od->o = olen;
}

void OD_Squeezing( KeccakWidth1600_ODInstance *od, uint8_t *odata, unsigned int olen, const uint8_t *odataAdd )
{
    assert( od->rho != 0u );
    assert( olen <= (od->rho - od->o) );

    if ( odataAdd != NULL ) {
        SnP_ExtractAndAddBytes( &od->s, odataAdd, odata, od->o, olen );
    }
    else {
        SnP_ExtractBytes( &od->s, odata, od->o, olen );
    }
    od->o += olen;
}

#undef OD_TrailencAndXor
#undef OD_Initialize
#undef OD_Clone
#undef OD_CloneCompact
#undef OD_Duplexing
#undef OD_DuplexingFast
#undef OD_DuplexingFastOnlyOut
#undef OD_DuplexingFastOnlyIn
#undef OD_Squeezing
