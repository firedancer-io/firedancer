/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Kravatte, designed by Guido Bertoni, Joan Daemen, Seth Hoffert, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _Kravatte_h_
#define _Kravatte_h_

#include "config.h"
#ifdef XKCP_has_KeccakP1600

#include <stddef.h>
#include <stdint.h>
#include "align.h"
#include "KeccakP-1600-SnP.h"


#define SnP_widthInBytes            200
#define Kravatte_RollcSizeInBytes    (5*8)
#define Kravatte_RollcOffset         (SnP_widthInBytes-Kravatte_RollcSizeInBytes)
#define Kravatte_RolleSizeInBytes    (10*8)
#define Kravatte_RolleOffset         (SnP_widthInBytes-Kravatte_RolleSizeInBytes)

#define KRAVATTE_FLAG_NONE          0
#define KRAVATTE_FLAG_INIT          1 /* If set, initialize a new Kra session */
#define KRAVATTE_FLAG_LAST_PART     2 /* If set, indicates the last part of input/output */
#define KRAVATTE_FLAG_SHORT         4 /* If set, indicates Short-Kravatte will be performed */

typedef unsigned char BitSequence;
typedef size_t BitLength;

typedef enum
{
    NOT_INITIALIZED_YET,
    COMPRESSING,
    EXPANDING,
    EXPANDED,
} Kravatte_Phases;

#if defined(XKCP_has_KeccakP1600times8)
    #define KravatteMaxParallellism   8
    #define KravatteAlignment         64
#elif defined(XKCP_has_KeccakP1600times4)
    #define KravatteMaxParallellism   4
    #define KravatteAlignment         32
#elif defined(XKCP_has_KeccakP1600times2)
    #define KravatteMaxParallellism   2
    #define KravatteAlignment         16
#else
    #define KravatteMaxParallellism   1
    #define KravatteAlignment         8
#endif

typedef struct {
    ALIGN(KravatteAlignment) uint8_t k[200];
    ALIGN(KravatteAlignment) uint8_t kRoll[200];
    ALIGN(KravatteAlignment) uint8_t xAccu[200];
    ALIGN(KravatteAlignment) uint8_t yAccu[200];
    ALIGN(KravatteAlignment) uint8_t queue[200];    /* input/output queue buffer */
    BitLength queueOffset;          /* current offset in queue */
    Kravatte_Phases phase;
} Kravatte_Instance;

/**
  * Function to initialize a Kravatte instance with given key.
  * @param  kvInstance      Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_MaskDerivation(Kravatte_Instance *kvInstance, const BitSequence *Key, BitLength KeyBitLen);

/**
  * Function to give input data to be compressed.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_MaskDerivation().
  * @param  input           Pointer to the input message data (M).
  * @param  inputBitLen     The number of bits provided in the input message data.
  *                         This must be a multiple of 8 if KRAVATTE_FLAG_LAST_PART flag not set.
  * @param  flags           Bitwise or combination of KRAVATTE_FLAG_NONE, KRAVATTE_FLAG_INIT, KRAVATTE_FLAG_LAST_PART.
  * @return 0 if successful, 1 otherwise.
  */
int Kra(Kravatte_Instance *kvInstance, const BitSequence *input, BitLength inputBitLen, int flags);

/**
  * Function to expand output data.
  * @param  kvInstance      Pointer to the hash instance initialized by Kravatte_MaskDerivation().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         This must be a multiple of 8 if KRAVATTE_FLAG_LAST_PART flag not set.
  * @param  flags           Bitwise or combination of KRAVATTE_FLAG_NONE, KRAVATTE_FLAG_SHORT, KRAVATTE_FLAG_LAST_PART.
  * @return 0 if successful, 1 otherwise.
  */
int Vatte(Kravatte_Instance *kvInstance, BitSequence *output, BitLength outputBitLen, int flags);

/** Function to compress input data and expand output data.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_MaskDerivation().
  * @param  input           Pointer to the input message (M).
  * @param  inputBitLen     The number of bits provided in the input message data.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The number of output bits desired.
  * @param  flags           Bitwise or combination of KRAVATTE_FLAG_NONE, KRAVATTE_FLAG_INIT, KRAVATTE_FLAG_SHORT, KRAVATTE_FLAG_LAST_PART.
  *                         KRAVATTE_FLAG_LAST_PART is internally forced to true for input and output.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte(Kravatte_Instance *kvInstance, const BitSequence *input, BitLength inputBitLen, BitSequence *output, BitLength outputBitLen, int flags);

#else
#error This requires an implementation of Keccak-p[1600]
#endif

#endif
