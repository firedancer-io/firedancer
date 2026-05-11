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

#ifndef _ShakingUpAE_h_
#define _ShakingUpAE_h_

#include "config.h"
#include "KeccakOD.h"

// DWrap ----------------------------------------------------------

#define XKCP_DeclareDWrapStructure(prefix) \
    typedef struct prefix##_DWrapInstanceStruct { \
        prefix##_ODInstance od; \
        unsigned int taglen; \
    } prefix##_DWrapInstance;

#define XKCP_DeclareDWrapFunctions(prefix, inst) \
    void prefix##_Wrap_Initialize(inst##_DWrapInstance *D, const uint8_t *k, unsigned int klen, unsigned int taglen, unsigned int rho, unsigned int c ); \
    void prefix##_Wrap_Clone(inst##_DWrapInstance *Dnew, const inst##_DWrapInstance *D ); \
    void prefix##_Wrap_Wrap(inst##_DWrapInstance *D, uint8_t *C, const uint8_t *A, size_t Alen, const uint8_t *P, size_t Plen ); \
    int prefix##_Wrap_Unwrap(inst##_DWrapInstance *D, uint8_t *P, const uint8_t *A, size_t Alen, const uint8_t *C, size_t Clen );

// Upper Deck --------------------------------------------------------------

#define XKCP_DeclareUpperDeckStructure(prefix) \
    typedef struct prefix##_UpperDeckInstanceStruct { \
        prefix##_ODInstance D; \
        prefix##_ODInstance Dsqueeze; \
        size_t o; \
    } prefix##_UpperDeckInstance;

#define XKCP_DeclareUpperDeckFunctions(prefix, inst) \
    void prefix##_UpperDeck_Initialize(inst##_UpperDeckInstance *ud, const uint8_t *k, unsigned int klen, unsigned int rho, unsigned int c ); \
    void prefix##_UpperDeck_Clone(inst##_UpperDeckInstance *udnew, const inst##_UpperDeckInstance *ud ); \
    void prefix##_UpperDeck_CloneCompact(inst##_UpperDeckInstance *udnew, const inst##_UpperDeckInstance *ud ); \
    void prefix##_UpperDeck_Duplexing(inst##_UpperDeckInstance *ud, uint8_t *Z, size_t Zlen, const uint8_t *X, size_t Xlen, unsigned int E, const uint8_t *Yadd ); \
    void prefix##_UpperDeck_Squeezing(inst##_UpperDeckInstance *ud, uint8_t *Z, size_t Zlen, const uint8_t *Yadd );

// Deck-BO -----------------------------------------------------------------

#define XKCP_DeclareDeckBOStructure(prefix) \
    typedef struct prefix##_DeckBOInstanceStruct { \
        prefix##_UpperDeckInstance D; \
        unsigned int taglen; \
    } prefix##_DeckBOInstance;

#define XKCP_DeclareDeckBOFunctions(prefix, inst) \
    void prefix##_BO_Initialize(inst##_DeckBOInstance *dbo, const uint8_t *k, unsigned int klen, unsigned int taglen, unsigned int rho, unsigned int c ); \
    void prefix##_BO_Clone(inst##_DeckBOInstance *dbonew, const inst##_DeckBOInstance *dbo ); \
    void prefix##_BO_Wrap(inst##_DeckBOInstance *dbo, uint8_t *C, const uint8_t *A, size_t Alen, const uint8_t *P, size_t Plen ); \
    int prefix##_BO_Unwrap(inst##_DeckBOInstance *dbo, uint8_t *P, const uint8_t *A, size_t Alen, const uint8_t *C, size_t Clen );

#ifdef XKCP_has_KeccakP1600
    #include "KeccakP-1600-SnP.h"
    XKCP_DeclareDWrapStructure(KeccakWidth1600)
    XKCP_DeclareDWrapFunctions(SHAKE, KeccakWidth1600)
    XKCP_DeclareDWrapFunctions(TurboSHAKE, KeccakWidth1600)
    XKCP_DeclareUpperDeckStructure(KeccakWidth1600)
    XKCP_DeclareUpperDeckFunctions(SHAKE, KeccakWidth1600)
    XKCP_DeclareUpperDeckFunctions(TurboSHAKE, KeccakWidth1600)
    XKCP_DeclareDeckBOStructure(KeccakWidth1600)
    XKCP_DeclareDeckBOFunctions(SHAKE, KeccakWidth1600)
    XKCP_DeclareDeckBOFunctions(TurboSHAKE, KeccakWidth1600)
#else
#error This requires an implementation of Keccak-p[1600]
#endif

#endif
