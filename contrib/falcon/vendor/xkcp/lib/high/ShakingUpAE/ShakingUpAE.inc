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

#define OD_Initialize                   JOIN(prefix, _OD_Initialize)
#define OD_Clone                        JOIN(prefix, _OD_Clone)
#define OD_CloneCompact                 JOIN(prefix, _OD_CloneCompact)
#define OD_Duplexing                    JOIN(prefix, _OD_Duplexing)
#define OD_DuplexingFast                JOIN(prefix, _OD_DuplexingFast)
#define OD_DuplexingFastOnlyOut         JOIN(prefix, _OD_DuplexingFastOnlyOut)
#define OD_DuplexingFastOnlyIn          JOIN(prefix, _OD_DuplexingFastOnlyIn)
#define OD_Squeezing                    JOIN(prefix, _OD_Squeezing)
#define DWrap_Initialize                JOIN(prefix, _Wrap_Initialize)
#define DWrap_Clone                     JOIN(prefix, _Wrap_Clone)
#define DWrap_Wrap                      JOIN(prefix, _Wrap_Wrap)
#define DWrap_Unwrap                    JOIN(prefix, _Wrap_Unwrap)
#define UpperDeck_Initialize            JOIN(prefix, _UpperDeck_Initialize)
#define UpperDeck_Clone                 JOIN(prefix, _UpperDeck_Clone)
#define UpperDeck_CloneCompact          JOIN(prefix, _UpperDeck_CloneCompact)
#define UpperDeck_Duplexing             JOIN(prefix, _UpperDeck_Duplexing)
#define UpperDeck_Squeezing             JOIN(prefix, _UpperDeck_Squeezing)
#define DeckBO_Initialize               JOIN(prefix, _BO_Initialize)
#define DeckBO_Clone                    JOIN(prefix, _BO_Clone)
#define DeckBO_Wrap                     JOIN(prefix, _BO_Wrap)
#define DeckBO_Unwrap                   JOIN(prefix, _BO_Unwrap)

// DWrap ----------------------------------------------------------------------

void DWrap_Initialize( KeccakWidth1600_DWrapInstance *D, const uint8_t *k, unsigned int klen, unsigned int taglen, unsigned int rho, unsigned int c )
{
    assert( taglen <= TAG_LEN_MAX );
    assert( rho * 8u + c + 64u == 1600u );
    assert( rho <= RHO_LEN_MAX );
    assert( klen <= rho );

    D->taglen = taglen;
    OD_Initialize( &D->od, rho, c, k, klen );
}

void DWrap_Clone( KeccakWidth1600_DWrapInstance *Dnew, const KeccakWidth1600_DWrapInstance *D )
{
    *Dnew = *D;
}

void DWrap_Wrap( KeccakWidth1600_DWrapInstance *D, uint8_t *C, const uint8_t *A, size_t Alen, const uint8_t *P, size_t Plen )
{
    unsigned int    blocklen;
    unsigned int    lastBlockLen;

    // All A blocks except last one
    if ( Alen > D->od.rho ) {
        size_t bytesProcessed = OD_DuplexingFastOnlyIn( &D->od, A, Alen, 5u );
        A       += bytesProcessed;
        Alen    -= bytesProcessed;
        assert( Alen != 0u );
    }

    if ( Plen > 0u ) {
        if ( Alen > 0u ) {
            // Last A block, start wrap
            blocklen = MYMIN( Plen, D->od.rho );
            OD_Duplexing( &D->od, C, blocklen, A, Alen, 5u, P );
        }
        else {
            // Wrap first P block
            blocklen = MYMIN( Plen, D->od.rho - D->taglen );
            OD_Squeezing( &D->od, C, blocklen, P );
        }
        C += blocklen;
        P += blocklen;
        Plen -= blocklen;
        lastBlockLen = blocklen;

        // Second block with input length smaller than rho
        if ( (Plen > 0) && (lastBlockLen < D->od.rho) ) {
            blocklen = MYMIN( Plen, D->od.rho );
            OD_Duplexing( &D->od, C, blocklen, C - lastBlockLen, lastBlockLen, 4u, P );
            Plen -= blocklen;
            C    += blocklen;
            P    += blocklen;
            lastBlockLen = blocklen;
        }

        // Do all blocks with full rho
        if ( Plen >= D->od.rho )
        {
            assert( lastBlockLen == D->od.rho );
            size_t bytesProcessed = OD_DuplexingFast( &D->od, C - lastBlockLen, Plen, 4u, C, P );
            C += bytesProcessed;
            P += bytesProcessed;
            Plen -= bytesProcessed;
        }

        // Remaining block, if length not a multiple of rho
        assert( Plen < D->od.rho );
        if ( Plen > 0u ) {
            OD_Duplexing( &D->od, C, Plen, C - lastBlockLen, lastBlockLen, 4u, P );
            C += Plen;
            lastBlockLen = Plen;
        }

        // Generate tag
        OD_Duplexing( &D->od, C, D->taglen, C - lastBlockLen, lastBlockLen, 6u, NULL );
    }
    else {
        // No plaintext, last A block, generate tag in C
        OD_Duplexing( &D->od, C, D->taglen, A, Alen, 7u, NULL );
    }

}

int DWrap_Unwrap( KeccakWidth1600_DWrapInstance *D, uint8_t *P, const uint8_t *A, size_t Alen, const uint8_t *C, size_t Clen )
{
    KeccakWidth1600_DWrapInstance   Dprime;
    unsigned int                    blocklen;
    unsigned int                    lastBlockLen;
    ALIGN(8) uint8_t                tag[TAG_LEN_MAX];
    uint8_t                         *Pinitial   = P;
    const uint8_t                   *Ctag;
    size_t                          ClenInitial;

    if ( Clen < D->taglen ) {
        return -1;
    }
    ClenInitial = Clen -= D->taglen; // Remove tag length from C
    Ctag = C + Clen;
    DWrap_Clone( &Dprime, D );

    // All A blocks except last one
    if ( Alen > D->od.rho ) {
        size_t bytesProcessed = OD_DuplexingFastOnlyIn( &D->od, A, Alen, 5u );
        A       += bytesProcessed;
        Alen    -= bytesProcessed;
        assert( Alen != 0u );
    }
    if ( Clen > 0u ) {
        if ( Alen > 0u ) {
            // Last A block, start unwrap
            blocklen = MYMIN( Clen, D->od.rho );
            OD_Duplexing( &D->od, P, blocklen, A, Alen, 5u, C );
        }
        else {
           // Unwrap first C block
            blocklen = MYMIN( Clen, D->od.rho - D->taglen );
            OD_Squeezing( &D->od, P, blocklen, C );
        }
        C += blocklen;
        P += blocklen;
        Clen -= blocklen;
        lastBlockLen = blocklen;
        // Second block with input length smaller than rho
        if ( (Clen > 0) && (lastBlockLen < D->od.rho) ) {
            unsigned int   blklen  = MYMIN( Clen, D->od.rho );
            OD_Duplexing( &D->od, P, blklen, C - lastBlockLen, lastBlockLen, 4u, C );
            Clen -= blklen;
            C   += blklen;
            P   += blklen;
            lastBlockLen = blklen;
        }
        // All blocks with full rho
        if ( Clen >= D->od.rho ) {
            assert( lastBlockLen == D->od.rho );
            size_t bytesProcessed = OD_DuplexingFast( &D->od, C - lastBlockLen, Clen, 4u, P, C );
            Clen -= bytesProcessed;
            C   += bytesProcessed;
            P   += bytesProcessed;
        }
        // Remaining block, if length not a multiple of rho
        assert( Clen < D->od.rho );
        if ( Clen > 0 ) {
            OD_Duplexing( &D->od, P, Clen, C - lastBlockLen, lastBlockLen, 4u, C );
            C += Clen;
            lastBlockLen = Clen;
        }
        // Generate tag
        OD_Duplexing( &D->od, tag, D->taglen, C - lastBlockLen, lastBlockLen, 6u, NULL );
    }
    else {
        // Last A block, generate tag
        OD_Duplexing( &D->od, tag, D->taglen, A, Alen, 7u, NULL );
    }
    if ( memcmp( tag, Ctag, D->taglen ) == 0 ) {
        return 0;
    }
    // Wrong tag
    memset( Pinitial, 0, ClenInitial ); // wipe P
    DWrap_Clone( D, &Dprime );          // Restore initial state
    return -1;
}

// UpperDeck ------------------------------------------------------------------

void UpperDeck_Initialize( KeccakWidth1600_UpperDeckInstance *ud, const uint8_t *k, unsigned int klen, unsigned int rho, unsigned int c )
{
    assert( rho <= RHO_LEN_MAX );
    assert( klen <= rho );
    OD_Initialize( &ud->D, rho, c, k, klen );
    memset( &ud->Dsqueeze, 0u, sizeof(ud->Dsqueeze) ); // Deallocate by clearing rho
    ud->o = (size_t)-1;
}

void UpperDeck_Clone( KeccakWidth1600_UpperDeckInstance *udnew, const KeccakWidth1600_UpperDeckInstance *ud )
{
    udnew->o = ud->o;
    OD_Clone( &udnew->D,        &ud->D );
    OD_Clone( &udnew->Dsqueeze, &ud->D );
}

void UpperDeck_CloneCompact( KeccakWidth1600_UpperDeckInstance *udnew, const KeccakWidth1600_UpperDeckInstance *ud )
{
    udnew->o = (size_t)-1;
    OD_CloneCompact( &udnew->D, &ud->D );
    memset( &udnew->Dsqueeze, 0u, sizeof(udnew->Dsqueeze) ); // Deallocate by clearing rho
}

void UpperDeck_Duplexing( KeccakWidth1600_UpperDeckInstance *ud, uint8_t *Z, size_t Zlen, const uint8_t *X, size_t Xlen, unsigned int E, const uint8_t *Yadd )
{

    if ( Xlen > ud->D.rho ) {
        // All X blocks except last one
        size_t bytesProcessed = OD_DuplexingFastOnlyIn( &ud->D, X, Xlen, 2u );
        X       += bytesProcessed;
        Xlen    -= bytesProcessed;
        assert( Xlen != 0u );
    }
    // Last X block, [0 - rho] bytes
    assert( Xlen <= ud->D.rho );
    OD_Duplexing( &ud->D, NULL, 0, X, Xlen, OD_Concat( E, 1u ), NULL );
    ud->o = 0u;
    memset( &ud->Dsqueeze, 0u, sizeof(ud->Dsqueeze) ); // Deallocate by clearing rho
    UpperDeck_Squeezing( ud, Z, Zlen, Yadd );
}

void UpperDeck_Squeezing( KeccakWidth1600_UpperDeckInstance *ud, uint8_t *Z, size_t Zlen, const uint8_t *Yadd )
{

    if ( ud->o <= ud->D.rho ) {
        unsigned int x = MYMIN( ud->D.rho - ud->o, Zlen );
        OD_Squeezing( &ud->D, Z, x, Yadd );
        if ( (ud->o + Zlen) > ud->D.rho ) {
            OD_CloneCompact( &ud->Dsqueeze, &ud->D );
        }
        Zlen    -= x;
        Z       += x;
        if ( Yadd != NULL ) {
            Yadd += x;
        }
        ud->o += x;
    }
    while ( Zlen > 0u ) {
        if ( (ud->o % ud->Dsqueeze.rho) == 0u ) {
            if ( Zlen > ud->Dsqueeze.rho ) {
                size_t bytesProcessed = OD_DuplexingFastOnlyOut( &ud->Dsqueeze, 2u, Z, Zlen, Yadd );
                Zlen    -= bytesProcessed;
                Z       += bytesProcessed;
                if ( Yadd != NULL ) {
                    Yadd += bytesProcessed;
                }
                ud->o += bytesProcessed;
            }
            assert( Zlen <= ud->D.rho );
            if ( Zlen > 0u ) {
                OD_Duplexing( &ud->Dsqueeze, Z, Zlen, NULL, 0u, 2u, Yadd );
                ud->o += Zlen;
                Zlen = 0;
            }
        }
        else {
            unsigned int x = MYMIN( ud->Dsqueeze.rho - ud->o % ud->Dsqueeze.rho, Zlen );
            OD_Squeezing( &ud->Dsqueeze, Z, x, Yadd );
            Zlen    -= x;
            Z       += x;
            if ( Yadd != NULL ) {
                Yadd += x;
            }
            ud->o += x;
        }
    }
}

// DeckBO ---------------------------------------------------------------------

void DeckBO_Initialize( KeccakWidth1600_DeckBOInstance *dbo, const uint8_t *k, unsigned int klen, unsigned int taglen, unsigned int rho, unsigned int c )
{
    assert( taglen <= TAG_LEN_MAX );
    UpperDeck_Initialize( &dbo->D, k, klen, rho, c );
    dbo->taglen = taglen;
}

void DeckBO_Clone( KeccakWidth1600_DeckBOInstance *dbonew, const KeccakWidth1600_DeckBOInstance *dbo )
{
    *dbonew = *dbo;
}

void DeckBO_Wrap( KeccakWidth1600_DeckBOInstance *dbo, uint8_t *C, const uint8_t *A, size_t Alen, const uint8_t *P, size_t Plen )
{
    if ( Plen == 0 ) {
        UpperDeck_Duplexing( &dbo->D, C, dbo->taglen, A, Alen, 4u, NULL );
        return;
    }
    if ( Alen != 0 ) {
        UpperDeck_Duplexing( &dbo->D, NULL, 0, A, Alen, 5u, NULL );
    }
    KeccakWidth1600_UpperDeckInstance Dkey;
    UpperDeck_CloneCompact( &Dkey, &dbo->D );
    UpperDeck_Duplexing( &dbo->D, C + Plen, dbo->taglen, P, Plen, 14u, NULL );
    UpperDeck_Duplexing( &Dkey, C, Plen, C + Plen, dbo->taglen, 13u, P );
}

int DeckBO_Unwrap( KeccakWidth1600_DeckBOInstance *dbo, uint8_t *P, const uint8_t *A, size_t Alen, const uint8_t *C, size_t Clen )
{
    KeccakWidth1600_UpperDeckInstance  udSaved;
    ALIGN(8) uint8_t            tagPrime[TAG_LEN_MAX];

    if ( Clen < dbo->taglen ) {
        return -1;
    }
    UpperDeck_Clone( &udSaved, &dbo->D );
    if ( Clen == dbo->taglen ) {
        UpperDeck_Duplexing( &dbo->D, tagPrime, dbo->taglen, A, Alen, 4u, NULL );
        if ( memcmp( tagPrime, C, dbo->taglen ) != 0 ) {
            UpperDeck_Clone( &dbo->D, &udSaved );
            return -1;
        }
    }
    else {
        Clen -= dbo->taglen;
        if ( Alen != 0 ) {
            UpperDeck_Duplexing( &dbo->D, NULL, 0u, A, Alen, 5u, NULL );
        }
        KeccakWidth1600_UpperDeckInstance Dkey;
        UpperDeck_Clone( &Dkey, &dbo->D );
        UpperDeck_Duplexing( &Dkey, P, Clen, C + Clen, dbo->taglen, 13u, C );
        UpperDeck_Duplexing( &dbo->D, tagPrime, dbo->taglen, P, Clen, 14u, NULL );
        if ( memcmp( tagPrime, C + Clen, dbo->taglen ) != 0 ) {
            memset( P, 0, Clen ); // Wipe plaintext
            UpperDeck_Clone( &dbo->D, &udSaved );
            return -1;
        }
    }
    return 0;
}

#undef OD_Initialize
#undef OD_Clone
#undef OD_CloneCompact
#undef OD_Duplexing
#undef OD_DuplexingFast
#undef OD_DuplexingFastOnlyOut
#undef OD_DuplexingFastOnlyIn
#undef OD_Squeezing
#undef DWrap_Initialize
#undef DWrap_Clone
#undef DWrap_Wrap
#undef DWrap_Unwrap
#undef UpperDeck_Initialize
#undef UpperDeck_Clone
#undef UpperDeck_CloneCompact
#undef UpperDeck_Duplexing
#undef UpperDeck_Squeezing
#undef DeckBO_Initialize
#undef DeckBO_Clone
#undef DeckBO_Wrap
#undef DeckBO_Unwrap
