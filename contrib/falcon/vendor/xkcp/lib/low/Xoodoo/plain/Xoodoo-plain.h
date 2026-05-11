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

#ifndef _Xoodoo_plain_h_
#define _Xoodoo_plain_h_

#include <stddef.h>
#include <stdint.h>
#include "SnP-common.h"

typedef struct {
    uint32_t A[12];
} Xoodoo_plain32_state;

#define Xoodoo_plain_GetImplementation() \
    "32-bit optimized implementation"
#define Xoodoo_plain_GetFeatures() \
    (SnP_Feature_Main \
        | SnP_Feature_Cyclist)

#define Xoodoo_plain_StaticInitialize()
void Xoodoo_plain_Initialize(Xoodoo_plain32_state *state);
#define Xoodoo_plain_AddByte(argS, argData, argOffset)    ((uint8_t*)argS)[argOffset] ^= (argData)
void Xoodoo_plain_AddBytes(Xoodoo_plain32_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_plain_OverwriteBytes(Xoodoo_plain32_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_plain_OverwriteWithZeroes(Xoodoo_plain32_state *state, unsigned int byteCount);
void Xoodoo_plain_Permute_Nrounds(Xoodoo_plain32_state *state, unsigned int nrounds);
void Xoodoo_plain_Permute_6rounds(Xoodoo_plain32_state *state);
void Xoodoo_plain_Permute_12rounds(Xoodoo_plain32_state *state);
void Xoodoo_plain_ExtractBytes(const Xoodoo_plain32_state *state, uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_plain_ExtractAndAddBytes(const Xoodoo_plain32_state *state, const uint8_t *input, uint8_t *output, unsigned int offset, unsigned int length);

size_t Xoodyak_plain_AbsorbKeyedFullBlocks(Xoodoo_plain32_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_plain_AbsorbHashFullBlocks(Xoodoo_plain32_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_plain_SqueezeHashFullBlocks(Xoodoo_plain32_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_plain_SqueezeKeyedFullBlocks(Xoodoo_plain32_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_plain_EncryptFullBlocks(Xoodoo_plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);
size_t Xoodyak_plain_DecryptFullBlocks(Xoodoo_plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);

#endif
