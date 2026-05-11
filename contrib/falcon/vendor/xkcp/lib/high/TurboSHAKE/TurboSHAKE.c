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

#include "TurboSHAKE.h"

#ifdef KeccakReference
    #include "displayIntermediateValues.h"
#endif

#ifdef XKCP_has_KeccakP1600
    #include "KeccakP-1600-SnP.h"

    #define prefix TurboSHAKE
    #define SnP KeccakP1600
    #define SnP_state KeccakP1600_state
    #define SnP_width 1600
    #define SnP_Permute KeccakP1600_Permute_12rounds
    #define SnP_FastLoop_Absorb KeccakP1600_12rounds_FastLoop_Absorb
        #include "KeccakSponge.inc"
    #undef prefix
    #undef SnP
    #undef SnP_state
    #undef SnP_width
    #undef SnP_Permute
    #undef SnP_FastLoop_Absorb
#endif

XKCP_DeclareSpongeFunctions(TurboSHAKE)

int TurboSHAKE(unsigned int capacity, const unsigned char *input, size_t inputByteLen, unsigned char domain, unsigned char *output, size_t outputByteLen)
{
    TurboSHAKE_Instance instance;

    if (TurboSHAKE_Initialize(&instance, capacity)) return 1;
    if (TurboSHAKE_Absorb(&instance, input, inputByteLen)) return 1;
    if (TurboSHAKE_AbsorbDomainSeparationByte(&instance, domain)) return 1;
    if (TurboSHAKE_Squeeze(&instance, output, outputByteLen)) return 1;
    return 0;
}

int TurboSHAKE_Initialize(TurboSHAKE_Instance *instance, unsigned int capacity)
{
    if ((capacity > 512) || ((capacity % 8) != 0))
        return 1;
    else
        return TurboSHAKE_SpongeInitialize(instance, 1600-capacity, capacity);
}

int TurboSHAKE_Absorb(TurboSHAKE_Instance *instance, const unsigned char *data, size_t dataByteLen)
{
    return TurboSHAKE_SpongeAbsorb(instance, data, dataByteLen);
}

int TurboSHAKE_AbsorbDomainSeparationByte(TurboSHAKE_Instance *instance, unsigned char domain)
{
    return TurboSHAKE_SpongeAbsorbLastFewBits(instance, domain);
}

int TurboSHAKE_Squeeze(TurboSHAKE_Instance *instance, unsigned char *data, size_t dataByteLen)
{
    return TurboSHAKE_SpongeSqueeze(instance, data, dataByteLen);
}
