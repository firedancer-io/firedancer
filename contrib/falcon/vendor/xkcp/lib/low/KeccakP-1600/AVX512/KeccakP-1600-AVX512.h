/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to SnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_AVX512_h_
#define _KeccakP_1600_AVX512_h_

#include <stddef.h>
#include <stdint.h>
#include "KeccakP-1600-plain64.h"
#include "SnP-common.h"

#ifdef __MINGW32__
#define FORCE_SYSV __attribute__((sysv_abi))
#else
#define FORCE_SYSV
#endif

#define KeccakP1600_AVX512_GetImplementation() \
    "AVX512 optimized implementation"
#define KeccakP1600_AVX512_GetFeatures() \
    (SnP_Feature_Main | SnP_Feature_SpongeAbsorb)

#define KeccakP1600_AVX512_StaticInitialize()
FORCE_SYSV void KeccakP1600_AVX512_Initialize(KeccakP1600_plain64_state *state);
#define KeccakP1600_AVX512_AddByte(state, byte, offset) ((unsigned char*)(state))[(offset)] ^= (byte)
FORCE_SYSV void KeccakP1600_AVX512_AddBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
FORCE_SYSV void KeccakP1600_AVX512_OverwriteBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
FORCE_SYSV void KeccakP1600_AVX512_OverwriteWithZeroes(KeccakP1600_plain64_state *state, unsigned int byteCount);
FORCE_SYSV void KeccakP1600_AVX512_Permute_Nrounds(KeccakP1600_plain64_state *state, unsigned int nrounds);
FORCE_SYSV void KeccakP1600_AVX512_Permute_12rounds(KeccakP1600_plain64_state *state);
FORCE_SYSV void KeccakP1600_AVX512_Permute_24rounds(KeccakP1600_plain64_state *state);
FORCE_SYSV void KeccakP1600_AVX512_ExtractBytes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int offset, unsigned int length);
FORCE_SYSV void KeccakP1600_AVX512_ExtractAndAddBytes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
FORCE_SYSV size_t KeccakF1600_AVX512_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);
FORCE_SYSV size_t KeccakP1600_12rounds_AVX512_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);

#endif
