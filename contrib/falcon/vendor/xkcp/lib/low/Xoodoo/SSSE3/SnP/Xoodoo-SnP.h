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

#include "Xoodoo-SSSE3.h"

/** For the documentation, see SnP-documentation.h.
 */

typedef Xoodoo_align128plain32_state Xoodoo_state;

#define Xoodoo_GetImplementation                    Xoodoo_SSSE3_GetImplementation
#define Xoodoo_GetFeatures                          Xoodoo_SSSE3_GetFeatures
#define Xoodoo_StaticInitialize                     Xoodoo_SSSE3_StaticInitialize
#define Xoodoo_Initialize                           Xoodoo_SSSE3_Initialize
#define Xoodoo_AddByte                              Xoodoo_SSSE3_AddByte
#define Xoodoo_AddBytes                             Xoodoo_SSSE3_AddBytes
#define Xoodoo_OverwriteBytes                       Xoodoo_SSSE3_OverwriteBytes
#define Xoodoo_OverwriteWithZeroes                  Xoodoo_SSSE3_OverwriteWithZeroes
#define Xoodoo_Permute_Nrounds                      Xoodoo_SSSE3_Permute_Nrounds
#define Xoodoo_Permute_6rounds                      Xoodoo_SSSE3_Permute_6rounds
#define Xoodoo_Permute_12rounds                     Xoodoo_SSSE3_Permute_12rounds
#define Xoodoo_ExtractBytes                         Xoodoo_SSSE3_ExtractBytes
#define Xoodoo_ExtractAndAddBytes                   Xoodoo_SSSE3_ExtractAndAddBytes

#define Xoofff_AddIs(...)
#define Xoofff_CompressFastLoop(...)                0
#define Xoofff_ExpandFastLoop(...)                  0

#define Xoodyak_AbsorbKeyedFullBlocks               Xoodyak_SSSE3_AbsorbKeyedFullBlocks
#define Xoodyak_AbsorbHashFullBlocks                Xoodyak_SSSE3_AbsorbHashFullBlocks
#define Xoodyak_SqueezeHashFullBlocks               Xoodyak_SSSE3_SqueezeHashFullBlocks
#define Xoodyak_SqueezeKeyedFullBlocks              Xoodyak_SSSE3_SqueezeKeyedFullBlocks
#define Xoodyak_EncryptFullBlocks                   Xoodyak_SSSE3_EncryptFullBlocks
#define Xoodyak_DecryptFullBlocks                   Xoodyak_SSSE3_DecryptFullBlocks

#endif
