/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Xoofff, designed by Joan Daemen, Seth Hoffert, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _Xoofff_h_
#define _Xoofff_h_

#include "config.h"
#ifdef XKCP_has_Xoodoo

#include <stddef.h>
#include <stdint.h>
#include "align.h"
#include "Xoodoo-SnP.h"


#define SnP_widthInBytes        (3*4*4)
#define Xoofff_RollSizeInBytes  SnP_widthInBytes
#define Xoofff_RollOffset       0

#define Xoofff_FlagNone         0
#define Xoofff_FlagInit         1 /* If set, initialize a new Xoofff_Compress session */
#define Xoofff_FlagLastPart     2 /* If set, indicates the last part of input/output */
#define Xoofff_FlagXoofffie     4 /* If set, indicates Xoofffie will be performed */

#ifndef _Keccak_BitTypes_
#define _Keccak_BitTypes_
typedef uint8_t BitSequence;
typedef size_t  BitLength;
#endif

typedef enum
{
    NOT_INITIALIZED_YET,
    COMPRESSING,
    EXPANDING,
    EXPANDED,
} Xoofff_Phases;

#if defined(XKCP_has_Xoodootimes16)
    #define XoodooMaxParallellism   16
    #define XoodooAlignment         64
    #if defined(Xoodootimes16_FastXoofff_supported)
        #define    Xoofff_AddIs    Xooffftimes16_AddIs
    #endif
#elif defined(XKCP_has_Xoodootimes8)
    #define XoodooMaxParallellism   8
    #define XoodooAlignment         64
    #if defined(Xoodootimes8_FastXoofff_supported)
        #define    Xoofff_AddIs    Xooffftimes8_AddIs
    #endif
#elif defined(XKCP_has_Xoodootimes4)
    #define XoodooMaxParallellism   4
    #define XoodooAlignment         64
    #if defined(Xoodootimes4_FastXoofff_supported)
        #define    Xoofff_AddIs    Xooffftimes4_AddIs
    #endif
#else
    #define XoodooMaxParallellism   1
    #define XoodooAlignment         4
#endif

typedef struct {
    ALIGN(XoodooAlignment) uint8_t k[48];
    ALIGN(XoodooAlignment) uint8_t kRoll[48];
    ALIGN(XoodooAlignment) uint8_t xAccu[48];
    ALIGN(XoodooAlignment) uint8_t yAccu[48];
    ALIGN(XoodooAlignment) uint8_t queue[48];     /* input/output queue buffer */
    BitLength queueOffset;          /* current offset in queue */
    Xoofff_Phases phase;
} Xoofff_Instance;

/**
  * Function to initialize a Xoofff instance with given key.
  * @param  xpInstance      Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
int Xoofff_MaskDerivation(Xoofff_Instance *xpInstance, const BitSequence *Key, BitLength KeyBitLen);

/**
  * Function to handle input data to be compressed.
  * @param  xpInstance      Pointer to the instance initialized by Xoofff_MaskDerivation().
  * @param  input           Pointer to the input message data (M).
  * @param  inputBitLen     The number of bits provided in the input message data.
  *                         This must be a multiple of 8 if Xoofff_FlagLastPart flag not set.
  * @param  flags           Bitwise or combination of Xoofff_FlagNone, Xoofff_FlagInit, Xoofff_FlagLastPart.
  * @return 0 if successful, 1 otherwise.
  */
int Xoofff_Compress(Xoofff_Instance *xpInstance, const BitSequence *input, BitLength inputBitLen, int flags);

/**
  * Function to expand output data.
  * @param  xpInstance      Pointer to the hash instance initialized by Xoofff_MaskDerivation().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         This must be a multiple of 8 if Xoofff_FlagLastPart flag not set.
  * @param  flags           Bitwise or combination of Xoofff_FlagNone, Xoofff_FlagXoofffie, Xoofff_FlagLastPart.
  * @return 0 if successful, 1 otherwise.
  */
int Xoofff_Expand(Xoofff_Instance *xpInstance, BitSequence *output, BitLength outputBitLen, int flags);

/** Function to compress input data and expand output data.
  * @param  xpInstance      Pointer to the instance initialized by Xoofff_MaskDerivation().
  * @param  input           Pointer to the input message (M).
  * @param  inputBitLen     The number of bits provided in the input message data.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The number of output bits desired.
  * @param  flags           Bitwise or combination of Xoofff_FlagNone, Xoofff_FlagInit, Xoofff_FlagXoofffie, Xoofff_FlagLastPart.
  *                         Xoofff_FlagLastPart is internally forced to true for input and output.
  * @return 0 if successful, 1 otherwise.
  */
int Xoofff(Xoofff_Instance *xpInstance, const BitSequence *input, BitLength inputBitLen, BitSequence *output, BitLength outputBitLen, int flags);

#else
#error This requires an implementation of Xoodoo
#endif

#endif
