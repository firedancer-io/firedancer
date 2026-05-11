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

#ifndef _XoofffModes_h_
#define _XoofffModes_h_

#include "config.h"
#ifdef XKCP_has_Xoodoo

#include <stddef.h>
#include <stdint.h>
#include "align.h"
#include "Xoofff.h"

/**
  * XoofffSANE Tag Length in bytes.
  */
#define XoofffSANE_TagLength      16

typedef struct {
    Xoofff_Instance xoofff;
    unsigned int    e;
} XoofffSANE_Instance;

/**
  * Function to initialize a XoofffSANE instance with given key and nonce.
  * @param  xpInstance      Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @param  Nonce           Pointer to the nonce (N).
  * @param  NonceBitLen     The length of the nonce in bits.
  * @param  tag             The buffer where to store the tag.
  *                         This buffer must be minimum XoofffSANE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffSANE_Initialize(XoofffSANE_Instance *xpInstance, const BitSequence *Key, BitLength KeyBitLen, 
                            const BitSequence *Nonce, BitLength NonceBitLen, unsigned char *tag);

/**
  * Function to wrap plaintext into ciphertext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffSANE_Initialize().
  * @param  plaintext       Pointer to plaintext data to wrap.
  * @param  ciphertext      Pointer to buffer where the full wrapped data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  * @param  dataBitLen      The size of the plaintext/ciphertext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to store the tag.
  *                         This buffer must be minimum XoofffSANE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffSANE_Wrap(XoofffSANE_Instance *xpInstance, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag);

/**
  * Function to unwrap ciphertext into plaintext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffSANE_Initialize().
  * @param  ciphertext      Pointer to ciphertext data to unwrap.
  * @param  plaintext       Pointer to buffer where the full unwrapped data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size of the ciphertext/plaintext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to read the tag to check (when lastFlag is set).
  *                         This buffer must be minimum XoofffSANE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffSANE_Unwrap(XoofffSANE_Instance *xpInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag);

/* ------------------------------------------------------------------------- */

/**
  * XoofffSANSE Tag Length in bytes.
  */
#define XoofffSANSE_TagLength      32

typedef struct {
    Xoofff_Instance xoofff;
    unsigned int    e;
} XoofffSANSE_Instance;


/**
  * Function to initialize a XoofffSANSE instance with given key and nonce.
  * @param  xpInstance      Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffSANSE_Initialize(XoofffSANSE_Instance *xpInstance, const BitSequence *Key, BitLength KeyBitLen);

/**
  * Function to wrap plaintext into ciphertext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffSANSE_MaskDerivation().
  * @param  plaintext       Pointer to plaintext data to wrap.
  * @param  ciphertext      Pointer to buffer where the full wrapped data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  * @param  dataBitLen      The size of the plaintext/ciphertext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to store the tag.
  *                         This buffer must be minimum XoofffSANSE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffSANSE_Wrap(XoofffSANSE_Instance *xpInstance, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag);

/**
  * Function to unwrap ciphertext into plaintext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffSANSE_MaskDerivation().
  * @param  ciphertext      Pointer to ciphertext data to unwrap.
  * @param  plaintext       Pointer to buffer where the full unwrapped data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size of the ciphertext/plaintext data.
  * @param  AD              Pointer to the Associated Data.
  * @param  ADBitLen        The number of bytes provided in the Associated Data.
  * @param  tag             The buffer where to read the tag to check (when lastFlag is set).
  *                         This buffer must be minimum XoofffSANSE_TagLength bytes long.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffSANSE_Unwrap(XoofffSANSE_Instance *xpInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag);

/* ------------------------------------------------------------------------- */

/**
  * Definition of the constant l, used to split the input into two parts.
  * The left part of the input will be a multiple of l bits.
  */
#define XoofffWBC_l      8

/**
  * Definition of the constant b block length.
  */
#define XoofffWBC_b      (SnP_widthInBytes*8)

/**
  * Macro to initialize a XoofffWBC instance with given key.
  * @param  xp             Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
#define XoofffWBC_Initialize(xp, Key, KeyBitLen)        Xoofff_MaskDerivation(xp, Key, KeyBitLen)

/**
  * Function to encipher plaintext into ciphertext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffWBC_Initialize().
  * @param  plaintext       Pointer to plaintext data to encipher.
  * @param  ciphertext      Pointer to buffer where the enciphered data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  * @param  dataBitLen      The size in bits of the plaintext/ciphertext data.
  * @param  W               Pointer to the tweak W.
  * @param  WBitLen         The number of bits provided in the tweak.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffWBC_Encipher(Xoofff_Instance *xpInstance, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *W, BitLength WBitLen);

/**
  * Function to decipher ciphertext into plaintext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffWBC_Initialize().
  * @param  ciphertext      Pointer to ciphertext data to decipher.
  * @param  plaintext       Pointer to buffer where the deciphered data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size in bits of the plaintext/ciphertext data.
  * @param  W               Pointer to the tweak W.
  * @param  WBitLen         The number of bits provided in the tweak.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffWBC_Decipher(Xoofff_Instance *xpInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                        const BitSequence *W, BitLength WBitLen);

/* ------------------------------------------------------------------------- */

/**
  * Definition of the constant t, expansion length (in bits).
  */
#define XoofffWBCAE_t      128

/**
  * Macro to initialize a XoofffWBC instance with given key.
  * @param  xp             Pointer to the instance to be initialized.
  * @param  Key             Pointer to the key (K).
  * @param  KeyBitLen       The length of the key in bits.
  * @return 0 if successful, 1 otherwise.
  */
#define XoofffWBCAE_Initialize(xp, Key, KeyBitLen)      Xoofff_MaskDerivation(xp, Key, KeyBitLen)

/**
  * Function to encipher plaintext into ciphertext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffWBC_Initialize().
  * @param  plaintext       Pointer to plaintext data to encipher.
  *                         The last ::XoofffWBCAE_t bits of the buffer will be overwritten with zeros.
  * @param  ciphertext      Pointer to buffer where the enciphered data will be stored.
  *                         The ciphertext buffer must not overlap plaintext.
  *                         Ciphertext will be ::XoofffWBCAE_t bits longer than plaintext.
  * @param  dataBitLen      The size in bits of the plaintext data.
  *                         Plaintext and ciphertext buffers must be ::XoofffWBCAE_t bits longer than dataBitLen.
  * @param  AD              Pointer to the metadata AD.
  * @param  ADBitLen        The number of bits provided in the metadata.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffWBCAE_Encipher(Xoofff_Instance *xpInstance, BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen);

/**
  * Function to decipher ciphertext into plaintext.
  * @param  xpInstance      Pointer to the instance initialized by XoofffWBC_Initialize().
  * @param  ciphertext      Pointer to ciphertext data to decipher.
  *                         Ciphertext is ::XoofffWBCAE_t bits longer than plaintext.
  * @param  plaintext       Pointer to buffer where the deciphered data will be stored.
  *                         The plaintext buffer must not overlap ciphertext.
  * @param  dataBitLen      The size in bits of the plaintext data.
  *                         Ciphertext and plaintext buffers must be ::XoofffWBCAE_t bits longer than dataBitLen.
  * @param  AD              Pointer to the metadata AD.
  * @param  ADBitLen        The number of bits provided in the metadata.
  * @return 0 if successful, 1 otherwise.
  */
int XoofffWBCAE_Decipher(Xoofff_Instance *xpInstance, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen);

#else
#error This requires an implementation of Xoodoo
#endif

#endif
