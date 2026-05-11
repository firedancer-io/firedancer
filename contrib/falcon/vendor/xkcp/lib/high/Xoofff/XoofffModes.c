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

#include <string.h>
#include "brg_endian.h"
#include "Xoofff.h"
#include "XoofffModes.h"

/* #define    DEBUG_DUMP */

#define laneSize        4
#define width           (3*4*32)
#define widthInBytes    (width/8)
#define widthInLanes    (widthInBytes/laneSize)

#define MyMin(a, b)     (((a) < (b)) ? (a) : (b))

void Xoofff_AddIs_dispatch(unsigned char *output, const unsigned char *input, size_t bitLen);
#ifdef Xoofff_AddIs
#undef Xoofff_AddIs
#endif
#define Xoofff_AddIs Xoofff_AddIs_dispatch

#if defined(DEBUG_DUMP)
static void DUMP( const unsigned char * pText, const unsigned char * pData, unsigned int size )
{
    unsigned int i;
    printf("%s (%u bytes):", pText, size);
    for(i=0; i<size; i++)
        printf(" %02x", (int)pData[i]);
    printf("\n");
}
#else
#define DUMP(pText, pData, size )
#endif

/* ------------------------------------------------------------------------- */

static BitLength XoofffWBC_Split(BitLength n)
{
    BitLength   nL;
    BitLength   q, x;

    if (n <= (2 * XoofffWBC_b - (XoofffWBC_l + 2)))
        nL = XoofffWBC_l * ((n + XoofffWBC_l) / (2*XoofffWBC_l));
    else {
        q = (n + XoofffWBC_l + 2 + (XoofffWBC_b - 1)) / XoofffWBC_b;
        for (x = 1; (BitLength)(1 << x) < q; ++x)
            ; /* empty */
        --x;
        nL = (q - (BitLength)(1 << x)) * XoofffWBC_b - XoofffWBC_l;
    }
    return nL;
}

#define Lp  plaintext
#define Rp  (plaintext + nL / 8)
#define Lc  ciphertext
#define Rc  (ciphertext + nL / 8)

int XoofffWBC_Encipher(Xoofff_Instance *xp, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen,
                        const BitSequence *W, BitLength WBitLen)
{
    size_t nL = XoofffWBC_Split(dataBitLen);
    size_t nR = dataBitLen - nL;
    size_t nL0 = MyMin(width, nL);
    size_t nR0 = MyMin(width, nR);
    unsigned char R0[SnP_widthInBytes];
    unsigned char HkW[SnP_widthInBytes];
    unsigned char kRollAfterHkW[Xoofff_RollSizeInBytes];
    unsigned int numberOfBitsInLastByte;
    BitSequence lastByte[1];

    /* R0 = R0 + Hk(L || 0) */
    if (Xoofff_Compress(xp, Lp, nL, Xoofff_FlagInit) != 0) /* Do complete L, is always a multiple of 8 bits */
        return 1;
    lastByte[0] = 0;
    if (Xoofff(xp, lastByte, 1, R0, nR0, Xoofff_FlagXoofffie) != 0)
        return 1;
    Xoofff_AddIs(R0, Rp, nR0);

    /* L = L + Fk(R || 1 . W) */
    if (Xoofff_Compress(xp, W, WBitLen, Xoofff_FlagInit | Xoofff_FlagLastPart) != 0)
        return 1;
    memcpy(HkW, xp->xAccu, SnP_widthInBytes);
    memcpy(kRollAfterHkW, xp->kRoll+Xoofff_RollOffset, Xoofff_RollSizeInBytes);
    numberOfBitsInLastByte = nR & 7;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rp[nR/8] : 0;
    if (nR0 == nR) {
        if (Xoofff_Compress(xp, R0, nR0 - numberOfBitsInLastByte, Xoofff_FlagNone) != 0)  /* Compress R0 except last byte if incomplete */
            return 1;
        lastByte[0] = (numberOfBitsInLastByte != 0) ? R0[nR/8] : 0;
    }
    else {
        if (Xoofff_Compress(xp, R0, nR0, Xoofff_FlagNone) != 0) /* compress R0 */
            return 1;
        if (Xoofff_Compress(xp, Rp + nR0 / 8, nR - nR0 - numberOfBitsInLastByte, Xoofff_FlagNone) != 0)  /* rest of R except last byte if incomplete */
            return 1;
        lastByte[0] = (numberOfBitsInLastByte != 0) ? Rp[nR/8] : 0;
    }
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Xoofff(xp, lastByte, numberOfBitsInLastByte + 1, Lc, nL, Xoofff_FlagNone) != 0)
        return 1;
    Xoofff_AddIs(Lc, Lp, nL);

    /* R = R + Fk(L || 0 . W) */
    memcpy(xp->kRoll+Xoofff_RollOffset, kRollAfterHkW, Xoofff_RollSizeInBytes);
    memcpy(xp->xAccu, HkW, SnP_widthInBytes);
    if (Xoofff_Compress(xp, Lc, nL, Xoofff_FlagNone) != 0)
        return 1;
    lastByte[0] = 0;
    if (Xoofff(xp, lastByte, 1, Rc, nR, Xoofff_FlagNone) != 0)
        return 1;
    Xoofff_AddIs(Rc, R0, nR0);
    Xoofff_AddIs(Rc + nR0 / 8, Rp + nR0 / 8, nR - nR0);

    /* L0 = L0 + Hk(R || 1) */
    if (Xoofff_Compress(xp, Rc, nR - numberOfBitsInLastByte, Xoofff_FlagInit) != 0) /* Do all except last byte if incomplete */
        return 1;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rc[nR/8] : 0;
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Xoofff(xp, lastByte, numberOfBitsInLastByte + 1, R0, nL0, Xoofff_FlagXoofffie) != 0)
        return 1;
    Xoofff_AddIs(Lc, R0, nL0);

    return 0;
}

int XoofffWBC_Decipher(Xoofff_Instance *xp, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen,
                        const BitSequence *W, BitLength WBitLen)
{
    size_t nL = XoofffWBC_Split(dataBitLen);
    size_t nR = dataBitLen - nL;
    size_t nL0 = MyMin(width, nL);
    size_t nR0 = MyMin(width, nR);
    unsigned char L0[SnP_widthInBytes];
    unsigned char HkW[SnP_widthInBytes];
    unsigned char kRollAfterHkW[Xoofff_RollSizeInBytes];
    unsigned int numberOfBitsInLastByte;
    BitSequence lastByte[1];

    /* L0 = L0 + Hk(R || 1) */
    numberOfBitsInLastByte = nR & 7;
    if (Xoofff_Compress(xp, Rc, nR - numberOfBitsInLastByte, Xoofff_FlagInit) != 0) /* Do all except last byte if incomplete */
        return 1;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rc[nR/8] : 0;
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Xoofff(xp, lastByte, numberOfBitsInLastByte + 1, L0, nL0, Xoofff_FlagXoofffie) != 0)
        return 1;
    Xoofff_AddIs( L0, Lc, nL0);

    /* R = R + Fk(L || 0 . W) */
    if (Xoofff_Compress(xp, W, WBitLen, Xoofff_FlagInit | Xoofff_FlagLastPart) != 0)
        return 1;
    memcpy(HkW, xp->xAccu, SnP_widthInBytes);
    memcpy(kRollAfterHkW, xp->kRoll+Xoofff_RollOffset, Xoofff_RollSizeInBytes);
    if (Xoofff_Compress(xp, L0, nL0, Xoofff_FlagNone) != 0) /* compress L0 */
        return 1;
    if (Xoofff_Compress(xp, Lc + nL0 / 8, nL - nL0, Xoofff_FlagNone) != 0)  /* compress rest of L */
        return 1;
    lastByte[0] = 0;
    if (Xoofff(xp, lastByte, 1, Rp, nR, Xoofff_FlagNone) != 0)  /* last zero bit */
        return 1;
    Xoofff_AddIs(Rp, Rc, nR);

    /* L = L + Fk(R || 1 . W) */
    memcpy(xp->kRoll+Xoofff_RollOffset, kRollAfterHkW, Xoofff_RollSizeInBytes);
    memcpy(xp->xAccu, HkW, SnP_widthInBytes);
    if (Xoofff_Compress(xp, Rp, nR - numberOfBitsInLastByte, Xoofff_FlagNone) != 0)
        return 1;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rp[nR/8] : 0;
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Xoofff(xp, lastByte, numberOfBitsInLastByte + 1, Lp, nL, Xoofff_FlagNone) != 0)
        return 1;
    Xoofff_AddIs(Lp, L0, nL0);
    Xoofff_AddIs(Lp + nL0 / 8, Lc + nL0 / 8, nL - nL0);

    /* R0 = R0 + Hk(L || 0) */
    if (Xoofff_Compress(xp, Lp, nL, Xoofff_FlagInit) != 0) /* Do all, L is always a multiple of 8 bits */
        return 1;
    lastByte[0] = 0;
    if (Xoofff(xp, lastByte, 1, L0, nR0, Xoofff_FlagXoofffie) != 0)
        return 1;
    Xoofff_AddIs(Rp, L0, nR0);

    return 0;
}

int XoofffWBCAE_Encipher(Xoofff_Instance *xp, BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen,
                        const BitSequence *AD, BitLength ADBitLen)
{
    size_t          databytelen = dataBitLen / 8;
    unsigned int    nbitsInLastByte = dataBitLen & 7;
    int             result;

    if (nbitsInLastByte != 0) {
        plaintext[databytelen] &= ((1 << nbitsInLastByte) - 1);
        ++databytelen;
    }
    memset(plaintext + databytelen, 0, XoofffWBCAE_t/8);

    result = XoofffWBC_Encipher(xp, plaintext, ciphertext, dataBitLen + XoofffWBCAE_t, AD, ADBitLen);

    return(result);
}

const BitSequence XoofffWBCAE_Zero[XoofffWBCAE_t/8] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };

int XoofffWBCAE_Decipher(Xoofff_Instance *xp, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen,
                        const BitSequence *AD, BitLength ADBitLen)
{
    unsigned int nbitsInLastByte = dataBitLen & 7;

    if ( XoofffWBC_Decipher(xp, ciphertext, plaintext, dataBitLen + XoofffWBCAE_t, AD, ADBitLen) != 0)
        return 1;
    if (nbitsInLastByte != 0) { /* check first bits of checkValue sitting in last byte of plaintext */
        if ((plaintext[dataBitLen/8] & ~((1 << nbitsInLastByte) - 1)) != 0) {
            memset( plaintext, 0, (dataBitLen + XoofffWBCAE_t + 7) / 8 );
            return 1;
        }
    }
    if (memcmp(plaintext + (dataBitLen+7)/8, XoofffWBCAE_Zero, XoofffWBCAE_t/8) != 0) {
        memset( plaintext, 0, (dataBitLen + XoofffWBCAE_t + 7) / 8 );
        return 1;
    }
    return 0;
}


#undef  Lp
#undef  Rp
#undef  Lc
#undef  Rc

/* ------------------------------------------------------------------------- */

int XoofffSANE_Initialize(XoofffSANE_Instance *xp, const BitSequence *Key, BitLength KeyBitLen, 
                            const BitSequence *Nonce, BitLength NonceBitLen, unsigned char *tag)
{
    xp->e = 0;
    if (Xoofff_MaskDerivation(&xp->xoofff, Key, KeyBitLen) != 0)
        return 1;
    if (Xoofff_Compress(&xp->xoofff, Nonce, NonceBitLen, Xoofff_FlagInit | Xoofff_FlagLastPart) != 0)
        return 1;
    return Xoofff_Expand(&xp->xoofff, tag, XoofffSANE_TagLength * 8, Xoofff_FlagNone);
}

static int XoofffSANE_AddToHistory(XoofffSANE_Instance *xp, const BitSequence *data, BitLength dataBitLen, unsigned char appendix)
{
    BitSequence lastByte[1];

    if (Xoofff_Compress(&xp->xoofff, data, dataBitLen & ~7, Xoofff_FlagNone) != 0) /* Do all except last byte if incomplete */
        return 1;

    data += dataBitLen >> 3; /* move pointer to last incomplete byte (if no incomplete last byte, it will point beyond the buffer, but pointer won't be dereferenced) */
    dataBitLen &= 7; /* dataBitLen is now number of bits in last possible incomplete byte */
    if (dataBitLen == 0) {
        lastByte[0] = (BitSequence)(appendix | (xp->e << 1));
        dataBitLen = 2;
    }
    else if (dataBitLen <= 6) {
        lastByte[0] = (BitSequence)(*data | (appendix << dataBitLen) | (xp->e << (dataBitLen + 1)));
        dataBitLen += 2;
    }
    else { /* dataBitLen == 7 */
        lastByte[0] = (BitSequence)(*data | (appendix << 7));
        if ( Xoofff_Compress(&xp->xoofff, lastByte, 8, Xoofff_FlagNone) != 0) {
            return 1;
        }
        lastByte[0] = (BitSequence)xp->e;
        dataBitLen = 1;
    }
       return Xoofff_Compress(&xp->xoofff, lastByte, dataBitLen, Xoofff_FlagLastPart);
}

int XoofffSANE_Wrap(XoofffSANE_Instance *xp, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag)
{

    if (dataBitLen != 0) {
        /* C = P ^ Fk(history) << offset */
        if (Xoofff_Expand(&xp->xoofff, ciphertext, dataBitLen, Xoofff_FlagLastPart) != 0)
            return 1;
        Xoofff_AddIs(ciphertext, plaintext, dataBitLen);
    }
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history <- A || 0 || e ° history */
        if (XoofffSANE_AddToHistory(xp, AD, ADBitLen, 0 ) != 0)
            return 1;
    }
    if (dataBitLen != 0) {
        /* history <- C || 1 || e ° history */
        if (XoofffSANE_AddToHistory(xp, ciphertext, dataBitLen, 1 ) != 0)
            return 1;
    }
    xp->e ^= 1;

    /* T = Fk(history) */
    return Xoofff_Expand(&xp->xoofff, tag, XoofffSANE_TagLength * 8, Xoofff_FlagNone);
}

int XoofffSANE_Unwrap(XoofffSANE_Instance *xp, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag)
{
    unsigned char tagPrime[XoofffSANE_TagLength];

    if (dataBitLen != 0) {
        /*    P = C ^ Fk(history) << offset */
        if (Xoofff_Expand(&xp->xoofff, plaintext, dataBitLen, Xoofff_FlagLastPart) != 0)
            return 1;
        Xoofff_AddIs(plaintext, ciphertext, dataBitLen);
    }
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history <- A || 0 || e ° history */
        if (XoofffSANE_AddToHistory(xp, AD, ADBitLen, 0 ) != 0)
            return 1;
    }
    if (dataBitLen != 0) {
        /* history <- C || 1 || e  ° history */
        if (XoofffSANE_AddToHistory(xp, ciphertext, dataBitLen, 1 ) != 0)
            return 1;
    }
    /* Tprime = Fk(history) */
    if (Xoofff_Expand(&xp->xoofff, tagPrime, XoofffSANE_TagLength * 8, Xoofff_FlagNone) != 0)
        return 1;
    xp->e ^= 1;
     /* Wipe plaintext on tag difference */
    if ( memcmp( tagPrime, tag, XoofffSANE_TagLength) != 0) {
        memset(plaintext, 0, (dataBitLen + 7) / 8);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */

static int XoofffSANSE_AddToHistory(XoofffSANSE_Instance *xp, const BitSequence *data, BitLength dataBitLen, unsigned char appendix, unsigned int appendixLen)
{
    BitSequence lastByte[1];

    if (Xoofff_Compress(&xp->xoofff, data, dataBitLen & ~7, Xoofff_FlagNone) != 0) /* Do all except last byte if incomplete */
        return 1;
    data += dataBitLen >> 3; /* move pointer to last incomplete byte (if no incomplete last byte, it will point beyond the buffer, but pointer won't be dereferenced) */
    dataBitLen &= 7; /* dataBitLen is now number of bits in last possible incomplete byte */
    if (dataBitLen == 0) {
        lastByte[0] = (BitSequence)(appendix | (xp->e << appendixLen));
        dataBitLen = appendixLen + 1;
    }
    else if (dataBitLen <= (8 - (appendixLen + 1))) {
        lastByte[0] = (BitSequence)((*data & ((1 << dataBitLen) - 1)) | (appendix << dataBitLen) | (xp->e << (dataBitLen + appendixLen)));
        dataBitLen += appendixLen + 1;
    }
    else { /* dataBitLen too big to hold everything in last byte */
        unsigned int bitsLeft;

        bitsLeft = 8 - (unsigned int)dataBitLen;
        lastByte[0] = (BitSequence)((*data & ((1 << dataBitLen) - 1)) | ((appendix & ((1 << bitsLeft) - 1)) << dataBitLen));
        appendixLen -= bitsLeft;
        appendix >>= bitsLeft;
        if ( Xoofff_Compress(&xp->xoofff, lastByte, 8, Xoofff_FlagNone) != 0) {
            return 1;
        }
        lastByte[0] = (BitSequence)(appendix | (xp->e << appendixLen));
        dataBitLen = appendixLen + 1;
    }
    return Xoofff_Compress(&xp->xoofff, lastByte, dataBitLen, Xoofff_FlagLastPart);
}


int XoofffSANSE_Initialize(XoofffSANSE_Instance *xp, const BitSequence *Key, BitLength KeyBitLen)
{
    xp->e = 0;
    return Xoofff_MaskDerivation(&xp->xoofff, Key, KeyBitLen);
}

int XoofffSANSE_Wrap(XoofffSANSE_Instance *xp, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag)
{

    /* if |A| > 0 OR |P| = 0 then */
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history <- A || 0 || e . history */
        if (XoofffSANSE_AddToHistory(xp, AD, ADBitLen, 0, 1 ) != 0)
            return 1;
    }
    /* if |P| > 0 then */
    if (dataBitLen != 0) {
        Xoofff_Instance initialHistory = xp->xoofff;
        Xoofff_Instance newHistory;

        /* T = 0t + FK (P || 01 || e . history) */
        if (XoofffSANSE_AddToHistory(xp, plaintext, dataBitLen, 2, 2 ) != 0)
            return 1;
        newHistory = xp->xoofff;
        if ( Xoofff_Expand(&xp->xoofff, tag, XoofffSANSE_TagLength * 8, Xoofff_FlagNone) != 0)
            return 1;

        /* C = P + FK (T || 11 || e . history) */
        xp->xoofff = initialHistory;
        if (XoofffSANSE_AddToHistory(xp, tag, XoofffSANSE_TagLength * 8, 3, 2 ) != 0)
            return 1;
        if (Xoofff_Expand(&xp->xoofff, ciphertext, dataBitLen, Xoofff_FlagLastPart) != 0)
            return 1;
        Xoofff_AddIs(ciphertext, plaintext, dataBitLen);

        /* history = P || 01 || e . history */
        xp->xoofff = newHistory;
    }
    else {
        /* T = 0t + FK (history)  */
        if ( Xoofff_Expand(&xp->xoofff, tag, XoofffSANSE_TagLength * 8, Xoofff_FlagNone) != 0)
            return 1;
    }
    /* e = e + 1 */
    xp->e ^= 1;

    return 0;
}

int XoofffSANSE_Unwrap(XoofffSANSE_Instance *xp, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag)
{
    unsigned char tagPrime[XoofffSANSE_TagLength];

    /* if |A| > 0 OR |C| = 0 then */
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history = A || 0 || e . history */
        if (XoofffSANSE_AddToHistory(xp, AD, ADBitLen, 0, 1 ) != 0)
            return 1;
    }

    /* if |C| > 0 then */
    if (dataBitLen != 0) {
        Xoofff_Instance initialHistory = xp->xoofff;

        /* P = C + FK (T || 11 || e . history) */
        if (XoofffSANSE_AddToHistory(xp, tag, XoofffSANSE_TagLength * 8, 3, 2 ) != 0)
            return 1;
        if (Xoofff_Expand(&xp->xoofff, plaintext, dataBitLen, Xoofff_FlagLastPart) != 0)
            return 1;
        Xoofff_AddIs(plaintext, ciphertext, dataBitLen);

        /* history = P || 01 || e . history */
        xp->xoofff = initialHistory;
        if (XoofffSANSE_AddToHistory(xp, plaintext, dataBitLen, 2, 2 ) != 0)
            return 1;
    }

    /* T' = 0t + FK (history) */
    if ( Xoofff_Expand(&xp->xoofff, tagPrime, sizeof(tagPrime) * 8, Xoofff_FlagNone) != 0)
        return 1;

    /* e = e + 1 */
    xp->e ^= 1;

    /* if T' != T then */
    if ( memcmp( tagPrime, tag, sizeof(tagPrime)) != 0) {
        /* wipe P, return error! */
        memset(plaintext, 0, (dataBitLen + 7) / 8);
        return 1;
    }
    /* else return P */
    return 0;
}
