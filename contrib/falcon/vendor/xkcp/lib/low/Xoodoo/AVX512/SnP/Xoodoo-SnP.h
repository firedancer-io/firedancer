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

#include "Xoodoo-AVX512.h"

/** For the documentation, see SnP-documentation.h.
 */

typedef Xoodoo_align128plain32_state Xoodoo_state;

#define Xoodoo_GetImplementation                    Xoodoo_AVX512_GetImplementation
#define Xoodoo_GetFeatures                          Xoodoo_AVX512_GetFeatures
#define Xoodoo_StaticInitialize                     Xoodoo_AVX512_StaticInitialize
#define Xoodoo_Initialize                           Xoodoo_AVX512_Initialize
#define Xoodoo_AddByte                              Xoodoo_AVX512_AddByte
#define Xoodoo_AddBytes                             Xoodoo_AVX512_AddBytes
#define Xoodoo_OverwriteBytes                       Xoodoo_AVX512_OverwriteBytes
#define Xoodoo_OverwriteWithZeroes                  Xoodoo_AVX512_OverwriteWithZeroes
#define Xoodoo_Permute_Nrounds                      Xoodoo_AVX512_Permute_Nrounds
#define Xoodoo_Permute_6rounds                      Xoodoo_AVX512_Permute_6rounds
#define Xoodoo_Permute_12rounds                     Xoodoo_AVX512_Permute_12rounds
#define Xoodoo_ExtractBytes                         Xoodoo_AVX512_ExtractBytes
#define Xoodoo_ExtractAndAddBytes                   Xoodoo_AVX512_ExtractAndAddBytes

#define Xoofff_AddIs                                Xoofff_AVX512_AddIs
#define Xoofff_CompressFastLoop                     Xoofff_AVX512_CompressFastLoop
#define Xoofff_ExpandFastLoop                       Xoofff_AVX512_ExpandFastLoop

#define Xoodyak_AbsorbKeyedFullBlocks               Xoodyak_AVX512_AbsorbKeyedFullBlocks
#define Xoodyak_AbsorbHashFullBlocks                Xoodyak_AVX512_AbsorbHashFullBlocks
#define Xoodyak_SqueezeHashFullBlocks               Xoodyak_AVX512_SqueezeHashFullBlocks
#define Xoodyak_SqueezeKeyedFullBlocks              Xoodyak_AVX512_SqueezeKeyedFullBlocks
#define Xoodyak_EncryptFullBlocks                   Xoodyak_AVX512_EncryptFullBlocks
#define Xoodyak_DecryptFullBlocks                   Xoodyak_AVX512_DecryptFullBlocks

#endif
