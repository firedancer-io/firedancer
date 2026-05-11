/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Xoodyak, designed by Joan Daemen, Seth Hoffert, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifdef XoodooReference
    #include "displayIntermediateValues.h"
#endif

#if DEBUG
#include <assert.h>
#endif
#include <string.h>
#include "Xoodyak.h"

#ifdef OUTPUT
#include <stdlib.h>
#include <string.h>

static void displayByteString(FILE *f, const char* synopsis, const uint8_t *data, unsigned int length);
static void displayByteString(FILE *f, const char* synopsis, const uint8_t *data, unsigned int length)
{
    unsigned int i;

    fprintf(f, "%s:", synopsis);
    for(i=0; i<length; i++)
        fprintf(f, " %02x", (unsigned int)data[i]);
    fprintf(f, "\n");
}
#endif

#define MyMin(a,b)  (((a) < (b)) ? (a) : (b))

#ifdef XKCP_has_Xoodoo
    #include "Xoodoo-SnP.h"

    #define SnP                         Xoodoo
    #define SnP_Permute                 Xoodoo_Permute_12rounds
    #define prefix                      Xoodyak
        #include "Cyclist.inc"
    #undef  prefix
    #undef  SnP
    #undef  SnP_Permute
#endif
