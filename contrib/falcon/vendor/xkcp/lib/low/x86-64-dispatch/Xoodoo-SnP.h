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

#ifndef _Xoodoo_SnP_h_
#define _Xoodoo_SnP_h_

#include "Xoodoo-plain.h"
#include "Xoodoo-SSSE3.h"
#include "Xoodoo-AVX512.h"

typedef union {
    Xoodoo_plain32_state plain32_state;
    Xoodoo_align128plain32_state align128plain32_state;
} Xoodoo_state;

const char * Xoodoo_GetImplementation();
int Xoodoo_GetFeatures();

void Xoodoo_StaticInitialize();
void Xoodoo_Initialize(Xoodoo_state *state);
void Xoodoo_AddByte(Xoodoo_state *state, uint8_t data, unsigned int offset);
void Xoodoo_AddBytes(Xoodoo_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_OverwriteBytes(Xoodoo_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_OverwriteWithZeroes(Xoodoo_state *state, unsigned int byteCount);
void Xoodoo_Permute_Nrounds(Xoodoo_state *state, unsigned int nrounds);
void Xoodoo_Permute_6rounds(Xoodoo_state *state);
void Xoodoo_Permute_12rounds(Xoodoo_state *state);
void Xoodoo_ExtractBytes(const Xoodoo_state *state, uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_ExtractAndAddBytes(const Xoodoo_state *state, const uint8_t *input, uint8_t *output, unsigned int offset, unsigned int length);

void Xoofff_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen);
size_t Xoofff_CompressFastLoop(unsigned char *kRoll, unsigned char *xAccu, const unsigned char *input, size_t length);
size_t Xoofff_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length);

size_t Xoodyak_AbsorbKeyedFullBlocks(Xoodoo_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_AbsorbHashFullBlocks(Xoodoo_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_SqueezeHashFullBlocks(Xoodoo_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_SqueezeKeyedFullBlocks(Xoodoo_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_EncryptFullBlocks(Xoodoo_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);
size_t Xoodyak_DecryptFullBlocks(Xoodoo_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);

#endif
