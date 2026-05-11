/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Xoodoo permutation, designed by Joan Daemen, Seth Hoffert, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "Xoodoo-plain.h"
#include "Xoodyak-parameters.h"

#ifdef OUTPUT
#include <stdio.h>
#endif

#define SnP_AddByte             Xoodoo_plain_AddByte
#define SnP_AddBytes            Xoodoo_plain_AddBytes
#define SnP_ExtractBytes        Xoodoo_plain_ExtractBytes
#define SnP_ExtractAndAddBytes  Xoodoo_plain_ExtractAndAddBytes
#define SnP_Permute             Xoodoo_plain_Permute_12rounds
#define SnP_OverwriteBytes      Xoodoo_plain_OverwriteBytes

size_t Xoodyak_plain_AbsorbKeyedFullBlocks(Xoodoo_plain32_state *state, const uint8_t *X, size_t XLen)
{
    size_t  initialLength = XLen;

    do {
        SnP_Permute(state);                       /* Xoodyak_Up(instance, NULL, 0, 0); */
        SnP_AddBytes(state, X, 0, Xoodyak_Rkin);  /* Xoodyak_Down(instance, X, Xoodyak_Rkin, 0); */
        SnP_AddByte(state, 0x01, Xoodyak_Rkin);
        X       += Xoodyak_Rkin;
        XLen    -= Xoodyak_Rkin;
    } while (XLen >= Xoodyak_Rkin);

    return initialLength - XLen;
}

size_t Xoodyak_plain_AbsorbHashFullBlocks(Xoodoo_plain32_state *state, const uint8_t *X, size_t XLen)
{
    size_t  initialLength = XLen;

    do {
        SnP_Permute(state);                       /* Xoodyak_Up(instance, NULL, 0, 0); */
        SnP_AddBytes(state, X, 0, Xoodyak_Rhash); /* Xoodyak_Down(instance, X, Xoodyak_Rhash, 0); */
        SnP_AddByte(state, 0x01, Xoodyak_Rhash);
        X       += Xoodyak_Rhash;
        XLen    -= Xoodyak_Rhash;
    } while (XLen >= Xoodyak_Rhash);

    return initialLength - XLen;
}


size_t Xoodyak_plain_SqueezeKeyedFullBlocks(Xoodoo_plain32_state *state, uint8_t *Y, size_t YLen)
{
    size_t  initialLength = YLen;

    do {
        SnP_AddByte(state, 0x01, 0);  /* Xoodyak_Down(instance, NULL, 0, 0); */
        SnP_Permute(state);           /* Xoodyak_Up(instance, Y, Xoodyak_Rkout, 0); */
        SnP_ExtractBytes(state, Y, 0, Xoodyak_Rkout);
        Y    += Xoodyak_Rkout;
        YLen -= Xoodyak_Rkout;
    } while (YLen >= Xoodyak_Rkout);

    return initialLength - YLen;
}

size_t Xoodyak_plain_SqueezeHashFullBlocks(Xoodoo_plain32_state *state, uint8_t *Y, size_t YLen)
{
    size_t  initialLength = YLen;

    do {
        SnP_AddByte(state, 0x01, 0);  /* Xoodyak_Down(instance, NULL, 0, 0); */
        SnP_Permute(state);           /* Xoodyak_Up(instance, Y, Xoodyak_Rhash, 0); */
        SnP_ExtractBytes(state, Y, 0, Xoodyak_Rhash);
        Y    += Xoodyak_Rhash;
        YLen -= Xoodyak_Rhash;
    } while (YLen >= Xoodyak_Rhash);

    return initialLength - YLen;
}

size_t Xoodyak_plain_EncryptFullBlocks(Xoodoo_plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
{
    size_t  initialLength = IOLen;

    do {
        SnP_Permute(state);
        SnP_ExtractAndAddBytes(state, I, O, 0, Xoodyak_Rkout);
        SnP_OverwriteBytes(state, O, 0, Xoodyak_Rkout);
        SnP_AddByte(state, 0x01, Xoodyak_Rkout);
        I       += Xoodyak_Rkout;
        O       += Xoodyak_Rkout;
        IOLen   -= Xoodyak_Rkout;
    } while (IOLen >= Xoodyak_Rkout);

    return initialLength - IOLen;
}

size_t Xoodyak_plain_DecryptFullBlocks(Xoodoo_plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
{
    size_t  initialLength = IOLen;

    do {
        SnP_Permute(state);
        SnP_ExtractAndAddBytes(state, I, O, 0, Xoodyak_Rkout);
        SnP_AddBytes(state, O, 0, Xoodyak_Rkout);
        SnP_AddByte(state, 0x01, Xoodyak_Rkout);
        I       += Xoodyak_Rkout;
        O       += Xoodyak_Rkout;
        IOLen   -= Xoodyak_Rkout;
    } while (IOLen >= Xoodyak_Rkout);

    return initialLength - IOLen;
}
