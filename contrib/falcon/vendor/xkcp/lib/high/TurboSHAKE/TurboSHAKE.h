/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

TurboSHAKE, proposed by Guido Bertoni, Joan Daemen, Seth Hoffert, Michaël Peeters, Gilles Van Assche, Ronny Van Keer and Benoît Viguier.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _TurboSHAKE_h_
#define _TurboSHAKE_h_

#include <string.h>
#include "align.h"
#include "config.h"
#include "KeccakSponge.h"

#ifdef XKCP_has_KeccakP1600
    #include "KeccakP-1600-SnP.h"
    XKCP_DeclareSpongeStructure(TurboSHAKE, KeccakP1600_state)

typedef TurboSHAKE_SpongeInstance TurboSHAKE_Instance;

int TurboSHAKE(unsigned int capacity, const unsigned char *input, size_t inputByteLen, unsigned char domain, unsigned char *output, size_t outputByteLen);

int TurboSHAKE_Initialize(TurboSHAKE_Instance *instance, unsigned int capacity);

#define TurboSHAKE128_Initialize(instance) \
    TurboSHAKE_Initialize((instance), 256)

#define TurboSHAKE256_Initialize(instance) \
    TurboSHAKE_Initialize((instance), 512)

int TurboSHAKE_Absorb(TurboSHAKE_Instance *instance, const unsigned char *data, size_t dataByteLen);

int TurboSHAKE_AbsorbDomainSeparationByte(TurboSHAKE_Instance *instance, unsigned char domain);

int TurboSHAKE_Squeeze(TurboSHAKE_Instance *instance, unsigned char *data, size_t dataByteLen);

#endif

#endif
