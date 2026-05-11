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

#ifndef _Xoodoo_AVX512_h_
#define _Xoodoo_AVX512_h_

#include <stddef.h>
#include <stdint.h>
#include "SnP-common.h"
#include "Xoodoo-SSSE3.h"

#define Xoodoo_AVX512_GetImplementation() \
    "AVX512 implementation"
#define Xoodoo_AVX512_GetFeatures() \
    (SnP_Feature_Main \
        | SnP_Feature_Cyclist \
        | SnP_Feature_Farfalle)

#define Xoodoo_AVX512_StaticInitialize()
void Xoodoo_AVX512_Initialize(Xoodoo_align128plain32_state *state);
#define Xoodoo_AVX512_AddByte(argS, argData, argOffset)    ((uint8_t*)argS)[argOffset] ^= (argData)
void Xoodoo_AVX512_AddBytes(Xoodoo_align128plain32_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_AVX512_OverwriteBytes(Xoodoo_align128plain32_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_AVX512_OverwriteWithZeroes(Xoodoo_align128plain32_state *state, unsigned int byteCount);
void Xoodoo_AVX512_Permute_Nrounds(Xoodoo_align128plain32_state *state, unsigned int nrounds);
void Xoodoo_AVX512_Permute_6rounds(Xoodoo_align128plain32_state *state);
void Xoodoo_AVX512_Permute_12rounds(Xoodoo_align128plain32_state *state);
void Xoodoo_AVX512_ExtractBytes(const Xoodoo_align128plain32_state *state, uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_AVX512_ExtractAndAddBytes(const Xoodoo_align128plain32_state *state, const uint8_t *input, uint8_t *output, unsigned int offset, unsigned int length);

void Xoofff_AVX512_AddIs(unsigned char *output, const unsigned char *input, size_t bitLen);
size_t Xoofff_AVX512_CompressFastLoop(unsigned char *kRoll, unsigned char *xAccu, const unsigned char *input, size_t length);
size_t Xoofff_AVX512_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length);

size_t Xoodyak_AVX512_AbsorbKeyedFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_AVX512_AbsorbHashFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_AVX512_SqueezeHashFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_AVX512_SqueezeKeyedFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_AVX512_EncryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);
size_t Xoodyak_AVX512_DecryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);

#endif
