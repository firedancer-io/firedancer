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

#ifndef _KravatteModes_h_
#define _KravatteModes_h_

#include "config.h"
#ifdef XKCP_has_KeccakP1600

#include <stddef.h>
#include <stdint.h>
#include "align.h"
#include "Kravatte.h"

/**
  * Kravatte-SANE Tag Length in bytes.
  */
#define Kravatte_SANE_TagLength      16

/**
  * Definition of the constant l.
  */
#define Kravatte_SANE_l              8

typedef struct {
    Kravatte_Instance   kravatte;
    unsigned int        e;
} Kravatte_SANE_Instance;


/**
  * Function to initialize a Kravatte SANE instance with given key and nonce.
  * @param  kvInstance      Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @param  Nonce           Pointer to the nonce (N).
  * @param  NonceBitLen     The length of the nonce in bits.
  * @param  tag             The buffer where to store the tag.
  *                         This buffer must be minimum Kravatte_SANE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_SANE_Initialize(Kravatte_SANE_Instance *kvInstance, const BitSequence *Key, BitLength KeyBitLen, 
                            const BitSequence *Nonce, BitLength NonceBitLen, unsigned char *tag);

/**
  * Function to wrap plaintext into ciphertext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_SANE_Initialize().
  * @param  plaintext       Pointer to plaintext data to wrap.
  * @param  ciphertext      Pointer to buffer where the full wrapped data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  * @param  dataBitLen      The size of the plaintext/ciphertext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to store the tag.
  *                         This buffer must be minimum Kravatte_SANE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_SANE_Wrap(Kravatte_SANE_Instance *kvInstance, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag);

/**
  * Function to unwrap ciphertext into plaintext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_SANE_Initialize().
  * @param  ciphertext      Pointer to ciphertext data to unwrap.
  * @param  plaintext       Pointer to buffer where the full unwrapped data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size of the ciphertext/plaintext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to read the tag to check (when lastFlag is set).
  *                         This buffer must be minimum Kravatte_SANE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_SANE_Unwrap(Kravatte_SANE_Instance *kvInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag);

/* ------------------------------------------------------------------------- */

/**
  * Kravatte-SANSE Tag Length in bytes.
  */
#define Kravatte_SANSE_TagLength      32

typedef struct {
    Kravatte_Instance   kravatte;
    unsigned int        e;
} Kravatte_SANSE_Instance;


/**
  * Function to initialize a Kravatte SANSE instance with given key and nonce.
  * @param  kvInstance      Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_SANSE_Initialize(Kravatte_SANSE_Instance *kvInstance, const BitSequence *Key, BitLength KeyBitLen);

/**
  * Function to wrap plaintext into ciphertext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_SANSE_Initialize().
  * @param  plaintext       Pointer to plaintext data to wrap.
  * @param  ciphertext      Pointer to buffer where the full wrapped data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  * @param  dataBitLen      The size of the plaintext/ciphertext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to store the tag.
  *                         This buffer must be minimum Kravatte_SANSE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_SANSE_Wrap(Kravatte_SANSE_Instance *kvInstance, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag);

/**
  * Function to unwrap ciphertext into plaintext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_SANSE_Initialize().
  * @param  ciphertext      Pointer to ciphertext data to unwrap.
  * @param  plaintext       Pointer to buffer where the full unwrapped data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size of the ciphertext/plaintext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to read the tag to check (when lastFlag is set).
  *                         This buffer must be minimum Kravatte_SANSE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_SANSE_Unwrap(Kravatte_SANSE_Instance *kvInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag);

/* ------------------------------------------------------------------------- */

/**
  * Definition of the constant l, used to split the input into two parts.
  * The left part of the input will be a multiple of l bits.
  */
#define Kravatte_WBC_l      8

/**
  * Definition of the constant b block length.
  */
#define Kravatte_WBC_b      (SnP_widthInBytes*8)

/**
  * Macro to initialize a Kravatte_WBC instance with given key.
  * @param  kvw             Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
#define Kravatte_WBC_Initialize(kvw, Key, KeyBitLen)        Kravatte_MaskDerivation(kvw, Key, KeyBitLen)

/**
  * Function to encipher plaintext into ciphertext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_WBC_Initialize().
  * @param  plaintext       Pointer to plaintext data to encipher.
  * @param  ciphertext      Pointer to buffer where the enciphered data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  * @param  dataBitLen      The size in bits of the plaintext/ciphertext data.
  * @param  W               Pointer to the tweak W.
  * @param  WBitLen         The number of bits provided in the tweak.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_WBC_Encipher(Kravatte_Instance *kvwInstance, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *W, BitLength WBitLen);

/**
  * Function to decipher ciphertext into plaintext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_WBC_Initialize().
  * @param  ciphertext      Pointer to ciphertext data to decipher.
  * @param  plaintext       Pointer to buffer where the deciphered data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size in bits of the plaintext/ciphertext data.
  * @param  W               Pointer to the tweak W.
  * @param  WBitLen         The number of bits provided in the tweak.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_WBC_Decipher(Kravatte_Instance *kvwInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                        const BitSequence *W, BitLength WBitLen);

/* ------------------------------------------------------------------------- */

/**
  * Definition of the constant t, expansion length (in bits).
  */
#define Kravatte_WBCAE_t      128

/**
  * Macro to initialize a Kravatte_WBC instance with given key.
  * @param  kvw             Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
#define Kravatte_WBCAE_Initialize(kvw, Key, KeyBitLen)      Kravatte_MaskDerivation(kvw, Key, KeyBitLen)

/**
  * Function to encipher plaintext into ciphertext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_WBC_Initialize().
  * @param  plaintext       Pointer to plaintext data to encipher.
  *                         The last ::Kravatte_WBCAE_t bits of the buffer will be overwritten with zeros.
  * @param  ciphertext      Pointer to buffer where the enciphered data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  *                         Ciphertext will be ::Kravatte_WBCAE_t bits longer than plaintext.
  * @param  dataBitLen      The size in bits of the plaintext data.
  *                         Plaintext and ciphertext buffers must be ::Kravatte_WBCAE_t bits longer than dataBitLen.
  * @param  AD              Pointer to the metadata AD.
  * @param  ADBitLen        The number of bits provided in the metadata.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_WBCAE_Encipher(Kravatte_Instance *kvwInstance, BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen);

/**
  * Function to decipher ciphertext into plaintext.
  * @param  kvInstance      Pointer to the instance initialized by Kravatte_WBC_Initialize().
  * @param  ciphertext      Pointer to ciphertext data to decipher.
  *                         Ciphertext is ::Kravatte_WBCAE_t bits longer than plaintext.
  * @param  plaintext       Pointer to buffer where the deciphered data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size in bits of the plaintext data.
  *                         Ciphertext and plaintext buffers must be ::Kravatte_WBCAE_t bits longer than dataBitLen.
  * @param  AD              Pointer to the metadata AD.
  * @param  ADBitLen        The number of bits provided in the metadata.
  * @return 0 if successful, 1 otherwise.
  */
int Kravatte_WBCAE_Decipher(Kravatte_Instance *kvwInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen);

#else
#error This requires an implementation of Keccak-p[1600]
#endif

#endif
