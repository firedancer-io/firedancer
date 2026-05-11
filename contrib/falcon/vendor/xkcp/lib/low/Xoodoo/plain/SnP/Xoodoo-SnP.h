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

/** For the documentation, see SnP-documentation.h.
 */

typedef Xoodoo_plain32_state Xoodoo_state;

#define Xoodoo_GetImplementation                    Xoodoo_plain_GetImplementation
#define Xoodoo_GetFeatures                          Xoodoo_plain_GetFeatures
#define Xoodoo_StaticInitialize                     Xoodoo_plain_StaticInitialize
#define Xoodoo_Initialize                           Xoodoo_plain_Initialize
#define Xoodoo_AddByte                              Xoodoo_plain_AddByte
#define Xoodoo_AddBytes                             Xoodoo_plain_AddBytes
#define Xoodoo_OverwriteBytes                       Xoodoo_plain_OverwriteBytes
#define Xoodoo_OverwriteWithZeroes                  Xoodoo_plain_OverwriteWithZeroes
#define Xoodoo_Permute_Nrounds                      Xoodoo_plain_Permute_Nrounds
#define Xoodoo_Permute_6rounds                      Xoodoo_plain_Permute_6rounds
#define Xoodoo_Permute_12rounds                     Xoodoo_plain_Permute_12rounds
#define Xoodoo_ExtractBytes                         Xoodoo_plain_ExtractBytes
#define Xoodoo_ExtractAndAddBytes                   Xoodoo_plain_ExtractAndAddBytes

#define Xoofff_AddIs(...)
#define Xoofff_CompressFastLoop(...)                0
#define Xoofff_ExpandFastLoop(...)                  0

#define Xoodyak_AbsorbKeyedFullBlocks               Xoodyak_plain_AbsorbKeyedFullBlocks
#define Xoodyak_AbsorbHashFullBlocks                Xoodyak_plain_AbsorbHashFullBlocks
#define Xoodyak_SqueezeHashFullBlocks               Xoodyak_plain_SqueezeHashFullBlocks
#define Xoodyak_SqueezeKeyedFullBlocks              Xoodyak_plain_SqueezeKeyedFullBlocks
#define Xoodyak_EncryptFullBlocks                   Xoodyak_plain_EncryptFullBlocks
#define Xoodyak_DecryptFullBlocks                   Xoodyak_plain_DecryptFullBlocks

#endif
