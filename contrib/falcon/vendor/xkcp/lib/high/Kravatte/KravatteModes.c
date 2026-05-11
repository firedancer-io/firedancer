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

#include <string.h>
#include "brg_endian.h"
#include "Kravatte.h"
#include "KravatteModes.h"

/* #define    DEBUG_DUMP */

/*
 * Uncomment this define if your CPU can not handle misaligned memory accesses.
#define NO_MISALIGNED_ACCESSES
 */

#define laneSize        8
#define width           1600
#define widthInBytes    (width/8)
#define widthInLanes    (widthInBytes/laneSize)
#define rate            (width-64)
#define rateInBytes     (rate/8)
#define rateInLanes     (rateInBytes/laneSize)

#define MyMin(a, b)     (((a) < (b)) ? (a) : (b))

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

static void memxoris(BitSequence *target, const BitSequence *source, BitLength bitLen)
{
    size_t  byteLen = bitLen / 8;

    #if !defined(NO_MISALIGNED_ACCESSES)
    while ( byteLen >= 32 ) {
        *((uint64_t*)(target+0)) ^= *((uint64_t*)(source+0));
        *((uint64_t*)(target+8)) ^= *((uint64_t*)(source+8));
        *((uint64_t*)(target+16)) ^= *((uint64_t*)(source+16));
        *((uint64_t*)(target+24)) ^= *((uint64_t*)(source+24));
        source += 32;
        target += 32;
        byteLen -= 32;
    }
    while ( byteLen >= 8 ) {
        *((uint64_t*)target) ^= *((uint64_t*)source);
        source += 8;
        target += 8;
        byteLen -= 8;
    }
    #endif

    while ( byteLen-- != 0 )
    {
        *target++ ^= *source++;
    }

    bitLen &= 7;
    if (bitLen != 0)
    {
        *target ^= *source;
        *target &= (1 << bitLen) - 1;
    }
}

#if 0 /* no longer used */
static void memxor(BitSequence *target, const BitSequence *source1, const BitSequence *source2, BitLength bitLen)
{
    size_t    byteLen = bitLen / 8;

    #if !defined(NO_MISALIGNED_ACCESSES)
    while ( byteLen >= 32 ) {
        *((uint64_t*)(target+0))  = *((uint64_t*)(source1+0))  ^ *((uint64_t*)(source2+0));
        *((uint64_t*)(target+8))  = *((uint64_t*)(source1+8))  ^ *((uint64_t*)(source2+8));
        *((uint64_t*)(target+16)) = *((uint64_t*)(source1+16)) ^ *((uint64_t*)(source2+16));
        *((uint64_t*)(target+24)) = *((uint64_t*)(source1+24)) ^ *((uint64_t*)(source2+24));
        source1 += 32;
        source2 += 32;
        target += 32;
        byteLen -= 32;
    }
    while ( byteLen >= 8 ) {
        *((uint64_t*)target)  = *((uint64_t*)source1) ^ *((uint64_t*)source2);
        source1 += 8;
        source2 += 8;
        target += 8;
        byteLen -= 8;
    }
    #endif

    while ( byteLen-- != 0 )
    {
        *target++ = *source1++ ^ *source2++;
    }

    bitLen &= 7;
    if (bitLen != 0)
    {
        *target = *source1 ^ *source2;
        *target &= (1 << bitLen) - 1;
    }

}
#endif

/* ------------------------------------------------------------------------- */

int Kravatte_SANE_Initialize(Kravatte_SANE_Instance *kp, const BitSequence *Key, BitLength KeyBitLen, 
                            const BitSequence *Nonce, BitLength NonceBitLen, unsigned char *tag)
{
    kp->e = 0;
    if (Kravatte_MaskDerivation(&kp->kravatte, Key, KeyBitLen) != 0)
        return 1;
    if (Kra(&kp->kravatte, Nonce, NonceBitLen, KRAVATTE_FLAG_INIT | KRAVATTE_FLAG_LAST_PART) != 0)
        return 1;
    return Vatte(&kp->kravatte, tag, Kravatte_SANE_TagLength * 8, KRAVATTE_FLAG_NONE);
}

static int Kravatte_SANE_AddToHistory(Kravatte_SANE_Instance *kp, const BitSequence *data, BitLength dataBitLen, unsigned char appendix)
{
    BitSequence lastByte[1];

    if (Kra(&kp->kravatte, data, dataBitLen & ~7, KRAVATTE_FLAG_NONE) != 0) /* Do all except last byte if incomplete */
        return 1;

    data += dataBitLen >> 3; /* move pointer to last incomplete byte (if no incomplete last byte, it will point beyond the buffer, but pointer won't be dereferenced) */
    dataBitLen &= 7; /* dataBitLen is now number of bits in last possible incomplete byte */
    if (dataBitLen == 0) {
        lastByte[0] = (BitSequence)(appendix | (kp->e << 1));
        dataBitLen = 2;
    }
    else if (dataBitLen <= 6) {
        lastByte[0] = (BitSequence)(*data | (appendix << dataBitLen) | (kp->e << (dataBitLen + 1)));
        dataBitLen += 2;
    }
    else { /* dataBitLen == 7 */
        lastByte[0] = (BitSequence)(*data | (appendix << 7));
        if ( Kra(&kp->kravatte, lastByte, 8, KRAVATTE_FLAG_NONE) != 0) {
            return 1;
        }
        lastByte[0] = (BitSequence)kp->e;
        dataBitLen = 1;
    }
    return Kra(&kp->kravatte, lastByte, dataBitLen, KRAVATTE_FLAG_LAST_PART);
}


int Kravatte_SANE_Wrap(Kravatte_SANE_Instance *kp, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag)
{

    if (dataBitLen != 0) {
        /* C = P ^ Fk(history) << offset */
        if (Vatte(&kp->kravatte, ciphertext, dataBitLen, KRAVATTE_FLAG_LAST_PART) != 0)
            return 1;
        memxoris(ciphertext, plaintext, dataBitLen);
    }
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history <- A || 0 || e ° history */
        if (Kravatte_SANE_AddToHistory(kp, AD, ADBitLen, 0 ) != 0)
            return 1;
    }
    if (dataBitLen != 0) {
        /* history <- C || 1 || e ° history */
        if (Kravatte_SANE_AddToHistory(kp, ciphertext, dataBitLen, 1 ) != 0)
            return 1;
    }
    kp->e ^= 1;

    /* T = Fk(history) */
    return Vatte(&kp->kravatte, tag, Kravatte_SANE_TagLength * 8, KRAVATTE_FLAG_NONE);
}

int Kravatte_SANE_Unwrap(Kravatte_SANE_Instance *kp, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag)
{
    unsigned char tagPrime[Kravatte_SANE_TagLength];

    if (dataBitLen != 0) {
        /*    P = C ^ Fk(history) << offset */
        if (Vatte(&kp->kravatte, plaintext, dataBitLen, KRAVATTE_FLAG_LAST_PART) != 0)
            return 1;
        memxoris(plaintext, ciphertext, dataBitLen);
    }
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history <- A || 0 || e ° history */
        if (Kravatte_SANE_AddToHistory(kp, AD, ADBitLen, 0 ) != 0)
            return 1;
    }
    if (dataBitLen != 0) {
        /* history <- C || 1 || e  ° history */
        if (Kravatte_SANE_AddToHistory(kp, ciphertext, dataBitLen, 1 ) != 0)
            return 1;
    }
    /* Tprime = Fk(history) */
    if (Vatte(&kp->kravatte, tagPrime, Kravatte_SANE_TagLength * 8, KRAVATTE_FLAG_NONE) != 0)
        return 1;
    kp->e ^= 1;
     /* Wipe plaintext on tag difference */
    if ( memcmp( tagPrime, tag, Kravatte_SANE_TagLength) != 0) {
        memset(plaintext, 0, (dataBitLen + 7) / 8);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */

int Kravatte_SANSE_Initialize(Kravatte_SANSE_Instance *kp, const BitSequence *Key, BitLength KeyBitLen)
{
    kp->e = 0;
    return Kravatte_MaskDerivation(&kp->kravatte, Key, KeyBitLen);
}

static int Kravatte_SANSE_AddToHistory(Kravatte_SANSE_Instance *kp, const BitSequence *data, BitLength dataBitLen, unsigned char appendix, unsigned int appendixLen)
{
    BitSequence lastByte[1];

    if (Kra(&kp->kravatte, data, dataBitLen & ~7, KRAVATTE_FLAG_NONE) != 0) /* Do all except last byte if incomplete */
        return 1;
    data += dataBitLen >> 3; /* move pointer to last incomplete byte (if no incomplete last byte, it will point beyond the buffer, but pointer won't be dereferenced) */
    dataBitLen &= 7; /* dataBitLen is now number of bits in last possible incomplete byte */
    if (dataBitLen == 0) {
        lastByte[0] = (BitSequence)(appendix | (kp->e << appendixLen));
        dataBitLen = appendixLen + 1;
    }
    else if (dataBitLen <= (8 - (appendixLen + 1))) {
        lastByte[0] = (BitSequence)((*data & ((1 << dataBitLen) - 1)) | (appendix << dataBitLen) | (kp->e << (dataBitLen + appendixLen)));
        dataBitLen += appendixLen + 1;
    }
    else { /* dataBitLen too big to hold everything in last byte */
        unsigned int bitsLeft;

        bitsLeft = 8 - (unsigned int)dataBitLen;
        lastByte[0] = (BitSequence)((*data & ((1 << dataBitLen) - 1)) | ((appendix & ((1 << bitsLeft) - 1)) << dataBitLen));
        appendixLen -= bitsLeft;
        appendix >>= bitsLeft;
        if ( Kra(&kp->kravatte, lastByte, 8, KRAVATTE_FLAG_NONE) != 0) {
            return 1;
        }
        lastByte[0] = (BitSequence)(appendix | (kp->e << appendixLen));
        dataBitLen = appendixLen + 1;
    }
    return Kra(&kp->kravatte, lastByte, dataBitLen, KRAVATTE_FLAG_LAST_PART);
}

int Kravatte_SANSE_Wrap(Kravatte_SANSE_Instance *kp, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen, 
                        const BitSequence *AD, BitLength ADBitLen, unsigned char *tag)
{

    /* if |A| > 0 OR |P| = 0 then */
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history <- A || 0 || e . history */
        if (Kravatte_SANSE_AddToHistory(kp, AD, ADBitLen, 0, 1 ) != 0)
            return 1;
    }
    /* if |P| > 0 then */
    if (dataBitLen != 0) {
        Kravatte_Instance initialHistory = kp->kravatte;
        Kravatte_Instance newHistory;

        /* T = 0t + FK (P || 01 || e . history) */
        if (Kravatte_SANSE_AddToHistory(kp, plaintext, dataBitLen, 2, 2 ) != 0)
            return 1;
        newHistory = kp->kravatte;
        if ( Vatte(&kp->kravatte, tag, Kravatte_SANSE_TagLength * 8, KRAVATTE_FLAG_NONE) != 0)
            return 1;

        /* C = P + FK (T || 11 || e . history) */
        kp->kravatte = initialHistory;
        if (Kravatte_SANSE_AddToHistory(kp, tag, Kravatte_SANSE_TagLength * 8, 3, 2 ) != 0)
            return 1;
        if (Vatte(&kp->kravatte, ciphertext, dataBitLen, KRAVATTE_FLAG_LAST_PART) != 0)
            return 1;
        memxoris(ciphertext, plaintext, dataBitLen);

        /* history = P || 01 || e . history */
        kp->kravatte = newHistory;
    }
    else {
        /* T = 0t + FK (history)  */
        if ( Vatte(&kp->kravatte, tag, Kravatte_SANSE_TagLength * 8, KRAVATTE_FLAG_NONE) != 0)
            return 1;
    }
    /* e = e + 1 */
    kp->e ^= 1;

    return 0;
}

int Kravatte_SANSE_Unwrap(Kravatte_SANSE_Instance *kp, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen, 
                            const BitSequence *AD, BitLength ADBitLen, const unsigned char *tag)
{
    unsigned char tagPrime[Kravatte_SANSE_TagLength];

    /* if |A| > 0 OR |C| = 0 then */
    if ((ADBitLen != 0) || (dataBitLen == 0)) {
        /* history = A || 0 || e . history */
        if (Kravatte_SANSE_AddToHistory(kp, AD, ADBitLen, 0, 1 ) != 0)
            return 1;
    }

    /* if |C| > 0 then */
    if (dataBitLen != 0) {
        Kravatte_Instance initialHistory = kp->kravatte;

        /* P = C + FK (T || 11 || e . history) */
        if (Kravatte_SANSE_AddToHistory(kp, tag, Kravatte_SANSE_TagLength * 8, 3, 2 ) != 0)
            return 1;
        if (Vatte(&kp->kravatte, plaintext, dataBitLen, KRAVATTE_FLAG_LAST_PART) != 0)
            return 1;
        memxoris(plaintext, ciphertext, dataBitLen);

        /* history = P || 01 || e . history */
        kp->kravatte = initialHistory;
        if (Kravatte_SANSE_AddToHistory(kp, plaintext, dataBitLen, 2, 2 ) != 0)
            return 1;
    }

    /* T' = 0t + FK (history) */
    if ( Vatte(&kp->kravatte, tagPrime, sizeof(tagPrime) * 8, KRAVATTE_FLAG_NONE) != 0)
        return 1;

    /* e = e + 1 */
    kp->e ^= 1;

    /* if T' != T then */
    if ( memcmp( tagPrime, tag, sizeof(tagPrime)) != 0) {
        /* wipe P, return error! */
        memset(plaintext, 0, (dataBitLen + 7) / 8);
        return 1;
    }
    /* else return P */
    return 0;
}

/* ------------------------------------------------------------------------- */

static BitLength Kravatte_WBC_Split(BitLength n)
{
    BitLength   nL;
    BitLength   q, x;

    if (n <= (2 * Kravatte_WBC_b - (Kravatte_WBC_l + 2)))
        nL = Kravatte_WBC_l * ((n + Kravatte_WBC_l) / (2*Kravatte_WBC_l));
    else {
        q = (n + Kravatte_WBC_l + 2 + (Kravatte_WBC_b - 1)) / Kravatte_WBC_b;
        for (x = 1; (BitLength)(1 << x) < q; ++x)
            ; /* empty */
        --x;
        nL = (q - (BitLength)(1 << x)) * Kravatte_WBC_b - Kravatte_WBC_l;
    }
    return nL;
}

#define Lp  plaintext
#define Rp  (plaintext + nL / 8)
#define Lc  ciphertext
#define Rc  (ciphertext + nL / 8)

int Kravatte_WBC_Encipher(Kravatte_Instance *kv, const BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen,
                        const BitSequence *W, BitLength WBitLen)
{
    size_t nL = Kravatte_WBC_Split(dataBitLen);
    size_t nR = dataBitLen - nL;
    size_t nL0 = MyMin(width, nL);
    size_t nR0 = MyMin(width, nR);
    unsigned char R0[SnP_widthInBytes];
    unsigned char HkW[SnP_widthInBytes];
    unsigned char kRollAfterHkW[Kravatte_RollcSizeInBytes];
    unsigned int numberOfBitsInLastByte;
    BitSequence lastByte[1];

    /* R0 = R0 + Hk(L || 0) */
    if (Kra(kv, Lp, nL, KRAVATTE_FLAG_INIT) != 0) /* Do complete L, is always a multiple of 8 bits */
        return 1;
    lastByte[0] = 0;
    if (Kravatte(kv, lastByte, 1, R0, nR0, KRAVATTE_FLAG_SHORT) != 0)
        return 1;
    memxoris(R0, Rp, nR0);

    /* L = L + Fk(R || 1 . W) */
    if (Kra(kv, W, WBitLen, KRAVATTE_FLAG_INIT | KRAVATTE_FLAG_LAST_PART) != 0)
        return 1;
    memcpy(HkW, kv->xAccu, SnP_widthInBytes);
    memcpy(kRollAfterHkW, kv->kRoll+Kravatte_RollcOffset, Kravatte_RollcSizeInBytes);
    numberOfBitsInLastByte = nR & 7;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rp[nR/8] : 0;
    if (nR0 == nR) {
        if (Kra(kv, R0, nR0 - numberOfBitsInLastByte, KRAVATTE_FLAG_NONE) != 0)  /* Compress R0 except last byte if incomplete */
            return 1;
        lastByte[0] = (numberOfBitsInLastByte != 0) ? R0[nR/8] : 0;
    }
    else {
        if (Kra(kv, R0, nR0, KRAVATTE_FLAG_NONE) != 0) /* compress R0 */
            return 1;
        if (Kra(kv, Rp + nR0 / 8, nR - nR0 - numberOfBitsInLastByte, KRAVATTE_FLAG_NONE) != 0)  /* rest of R except last byte if incomplete */
            return 1;
        lastByte[0] = (numberOfBitsInLastByte != 0) ? Rp[nR/8] : 0;
    }
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Kravatte(kv, lastByte, numberOfBitsInLastByte + 1, Lc, nL, KRAVATTE_FLAG_NONE) != 0)
        return 1;
    memxoris(Lc, Lp, nL);

    /* R = R + Fk(L || 0 . W) */
    memcpy(kv->kRoll+Kravatte_RollcOffset, kRollAfterHkW, Kravatte_RollcSizeInBytes);
    memcpy(kv->xAccu, HkW, SnP_widthInBytes);
    if (Kra(kv, Lc, nL, KRAVATTE_FLAG_NONE) != 0)
        return 1;
    lastByte[0] = 0;
    if (Kravatte(kv, lastByte, 1, Rc, nR, KRAVATTE_FLAG_NONE) != 0)
        return 1;
    memxoris(Rc, R0, nR0);
    memxoris(Rc + nR0 / 8, Rp + nR0 / 8, nR - nR0);

    /* L0 = L0 + Hk(R || 1) */
    if (Kra(kv, Rc, nR - numberOfBitsInLastByte, KRAVATTE_FLAG_INIT) != 0) /* Do all except last byte if incomplete */
        return 1;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rc[nR/8] : 0;
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Kravatte(kv, lastByte, numberOfBitsInLastByte + 1, R0, nL0, KRAVATTE_FLAG_SHORT) != 0)
        return 1;
    memxoris(Lc, R0, nL0);

    return 0;
}

int Kravatte_WBC_Decipher(Kravatte_Instance *kv, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen,
                        const BitSequence *W, BitLength WBitLen)
{
    size_t nL = Kravatte_WBC_Split(dataBitLen);
    size_t nR = dataBitLen - nL;
    size_t nL0 = MyMin(width, nL);
    size_t nR0 = MyMin(width, nR);
    unsigned char L0[SnP_widthInBytes];
    unsigned char HkW[SnP_widthInBytes];
    unsigned char kRollAfterHkW[Kravatte_RollcSizeInBytes];
    unsigned int numberOfBitsInLastByte;
    BitSequence lastByte[1];

    /* L0 = L0 + Hk(R || 1) */
    numberOfBitsInLastByte = nR & 7;
    if (Kra(kv, Rc, nR - numberOfBitsInLastByte, KRAVATTE_FLAG_INIT) != 0) /* Do all except last byte if incomplete */
        return 1;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rc[nR/8] : 0;
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Kravatte(kv, lastByte, numberOfBitsInLastByte + 1, L0, nL0, KRAVATTE_FLAG_SHORT) != 0)
        return 1;
    memxoris( L0, Lc, nL0);

    /* R = R + Fk(L || 0 . W) */
    if (Kra(kv, W, WBitLen, KRAVATTE_FLAG_INIT | KRAVATTE_FLAG_LAST_PART) != 0)
        return 1;
    memcpy(HkW, kv->xAccu, SnP_widthInBytes);
    memcpy(kRollAfterHkW, kv->kRoll+Kravatte_RollcOffset, Kravatte_RollcSizeInBytes);
    if (Kra(kv, L0, nL0, KRAVATTE_FLAG_NONE) != 0) /* compress L0 */
        return 1;
    if (Kra(kv, Lc + nL0 / 8, nL - nL0, KRAVATTE_FLAG_NONE) != 0)  /* compress rest of L */
        return 1;
    lastByte[0] = 0;
    if (Kravatte(kv, lastByte, 1, Rp, nR, KRAVATTE_FLAG_NONE) != 0)  /* last zero bit */
        return 1;
    memxoris(Rp, Rc, nR);

    /* L = L + Fk(R || 1 . W) */
    memcpy(kv->kRoll+Kravatte_RollcOffset, kRollAfterHkW, Kravatte_RollcSizeInBytes);
    memcpy(kv->xAccu, HkW, SnP_widthInBytes);
    if (Kra(kv, Rp, nR - numberOfBitsInLastByte, KRAVATTE_FLAG_NONE) != 0)
        return 1;
    lastByte[0] = (numberOfBitsInLastByte != 0) ? Rp[nR/8] : 0;
    lastByte[0] &= (1 << numberOfBitsInLastByte) - 1;
    lastByte[0] |= 1 << numberOfBitsInLastByte;
    if (Kravatte(kv, lastByte, numberOfBitsInLastByte + 1, Lp, nL, KRAVATTE_FLAG_NONE) != 0)
        return 1;
    memxoris(Lp, L0, nL0);
    memxoris(Lp + nL0 / 8, Lc + nL0 / 8, nL - nL0);

    /* R0 = R0 + Hk(L || 0) */
    if (Kra(kv, Lp, nL, KRAVATTE_FLAG_INIT) != 0) /* Do all, L is always a multiple of 8 bits */
        return 1;
    lastByte[0] = 0;
    if (Kravatte(kv, lastByte, 1, L0, nR0, KRAVATTE_FLAG_SHORT) != 0)
        return 1;
    memxoris(Rp, L0, nR0);

    return 0;
}

int Kravatte_WBCAE_Encipher(Kravatte_Instance *kv, BitSequence *plaintext, BitSequence *ciphertext, BitLength dataBitLen,
                        const BitSequence *AD, BitLength ADBitLen)
{
    size_t          databytelen = dataBitLen / 8;
    unsigned int    nbitsInLastByte = dataBitLen & 7;
    int             result;

    if (nbitsInLastByte != 0) {
        plaintext[databytelen] &= ((1 << nbitsInLastByte) - 1);
        ++databytelen;
    }
    memset(plaintext + databytelen, 0, Kravatte_WBCAE_t/8);

    result = Kravatte_WBC_Encipher(kv, plaintext, ciphertext, dataBitLen + Kravatte_WBCAE_t, AD, ADBitLen);

    return(result);
}

const BitSequence Kravatte_WBCAE_Zero[Kravatte_WBCAE_t/8] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };

int Kravatte_WBCAE_Decipher(Kravatte_Instance *kv, const BitSequence *ciphertext, BitSequence *plaintext, BitLength dataBitLen,
                        const BitSequence *AD, BitLength ADBitLen)
{
    unsigned int nbitsInLastByte = dataBitLen & 7;

    if ( Kravatte_WBC_Decipher(kv, ciphertext, plaintext, dataBitLen + Kravatte_WBCAE_t, AD, ADBitLen) != 0)
        return 1;
    if (nbitsInLastByte != 0) { /* check first bits of checkValue sitting in last byte of plaintext */
        if ((plaintext[dataBitLen/8] & ~((1 << nbitsInLastByte) - 1)) != 0) {
            memset( plaintext, 0, (dataBitLen + Kravatte_WBCAE_t + 7) / 8 );
            return 1;
        }
    }
    if (memcmp(plaintext + (dataBitLen+7)/8, Kravatte_WBCAE_Zero, Kravatte_WBCAE_t/8) != 0) {
        memset( plaintext, 0, (dataBitLen + Kravatte_WBCAE_t + 7) / 8 );
        return 1;
    }
    return 0;
}

#undef  Lp
#undef  Rp
#undef  Lc
#undef  Rc
