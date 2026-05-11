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

#ifndef _KeccakOD_h_
#define _KeccakOD_h_

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"

// Overwrite Duplex (OD) --------------------------------------------------------

#define XKCP_DeclareODStructure(prefix, state_t) \
    typedef struct prefix##_ODInstanceStruct { \
        state_t s; \
        unsigned int rho; \
        unsigned int c; \
        unsigned int o; \
    } prefix##_ODInstance;

#define XKCP_DeclareODFunctions(prefix, inst) \
    void prefix##_OD_Initialize(inst##_ODInstance *od, unsigned int rho, unsigned int c, const uint8_t *k, unsigned int klen ); \
    void prefix##_OD_Clone(inst##_ODInstance *odnew, const inst##_ODInstance *od ); \
    void prefix##_OD_CloneCompact(inst##_ODInstance *odnew, const inst##_ODInstance *od ); \
    void prefix##_OD_Duplexing(inst##_ODInstance *od, uint8_t *odata, unsigned int olen, const uint8_t *idata, unsigned int ilen, unsigned int E, const uint8_t *odataAdd ); \
    void prefix##_OD_Squeezing(inst##_ODInstance *od, uint8_t *odata, unsigned int olen, const uint8_t *odataAdd ); \
    size_t prefix##_OD_DuplexingFast(inst##_ODInstance *od, const uint8_t *idata, size_t len, unsigned int E, uint8_t *odata, const uint8_t *odataAdd ); \
    size_t prefix##_OD_DuplexingFastOnlyOut(inst##_ODInstance *od, unsigned int E, uint8_t *odata, size_t len, const uint8_t *odataAdd ); \
    size_t prefix##_OD_DuplexingFastOnlyIn(inst##_ODInstance *od, const uint8_t *idata, size_t len, unsigned int E ); \

#ifdef XKCP_has_KeccakP1600
    #include "KeccakP-1600-SnP.h"
    XKCP_DeclareODStructure(KeccakWidth1600, KeccakP1600_state)
    XKCP_DeclareODFunctions(SHAKE, KeccakWidth1600)
    XKCP_DeclareODFunctions(TurboSHAKE, KeccakWidth1600)

    #define XKCP_has_OD_Keccak_width1600
#endif

#endif
