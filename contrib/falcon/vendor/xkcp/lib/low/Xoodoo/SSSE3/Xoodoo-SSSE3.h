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

#ifndef _Xoodoo_SSSE3_h_
#define _Xoodoo_SSSE3_h_

#include <stddef.h>
#include <stdint.h>
#include "align.h"
#include "SnP-common.h"

typedef struct {
    ALIGN(16) uint32_t A[12];
} Xoodoo_align128plain32_state;

#define Xoodoo_stateAlignment      16

#define Xoodoo_SSSE3_GetImplementation() \
    "SSSE3 implementation"
#define Xoodoo_SSSE3_GetFeatures() \
    (SnP_Feature_Main \
        | SnP_Feature_Cyclist)

#define Xoodoo_SSSE3_StaticInitialize()
void Xoodoo_SSSE3_Initialize(Xoodoo_align128plain32_state *state);
#define Xoodoo_SSSE3_AddByte(argS, argData, argOffset)    ((uint8_t*)argS)[argOffset] ^= (argData)
void Xoodoo_SSSE3_AddBytes(Xoodoo_align128plain32_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_SSSE3_OverwriteBytes(Xoodoo_align128plain32_state *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_SSSE3_OverwriteWithZeroes(Xoodoo_align128plain32_state *state, unsigned int byteCount);
void Xoodoo_SSSE3_Permute_Nrounds(Xoodoo_align128plain32_state *state, unsigned int nrounds);
void Xoodoo_SSSE3_Permute_6rounds(Xoodoo_align128plain32_state *state);
void Xoodoo_SSSE3_Permute_12rounds(Xoodoo_align128plain32_state *state);
void Xoodoo_SSSE3_ExtractBytes(const Xoodoo_align128plain32_state *state, uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_SSSE3_ExtractAndAddBytes(const Xoodoo_align128plain32_state *state, const uint8_t *input, uint8_t *output, unsigned int offset, unsigned int length);

size_t Xoodyak_SSSE3_AbsorbKeyedFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_SSSE3_AbsorbHashFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_SSSE3_SqueezeHashFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_SSSE3_SqueezeKeyedFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_SSSE3_EncryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);
size_t Xoodyak_SSSE3_DecryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen);

#endif
