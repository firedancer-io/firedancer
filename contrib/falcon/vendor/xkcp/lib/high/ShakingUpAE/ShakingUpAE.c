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
#include "ShakingUpAE.h"
#include <assert.h>
#include <stdlib.h>

#define TAG_LEN_MAX     64u
#define RHO_LEN_MAX     ((1600u - 2u * 128u - 64u) / 8u)
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
    #define prefix                          TurboSHAKE
        #include "ShakingUpAE.inc"
    #undef prefix

    #define prefix                          SHAKE
        #include "ShakingUpAE.inc"
    #undef prefix
#endif
