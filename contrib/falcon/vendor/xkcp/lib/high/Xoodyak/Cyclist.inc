/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Xoodyak, designed by Joan Daemen, Seth Hoffert, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#define JOIN0(a, b)                     a ## b
#define JOIN(a, b)                      JOIN0(a, b)

#define SnP_GetFeatures                 JOIN(SnP, _GetFeatures)
#define SnP_StaticInitialize            JOIN(SnP, _StaticInitialize)
#define SnP_Initialize                  JOIN(SnP, _Initialize)
#define SnP_AddBytes                    JOIN(SnP, _AddBytes)
#define SnP_AddByte                     JOIN(SnP, _AddByte)
#define SnP_OverwriteBytes              JOIN(SnP, _OverwriteBytes)
#define SnP_ExtractBytes                JOIN(SnP, _ExtractBytes)
#define SnP_ExtractAndAddBytes          JOIN(SnP, _ExtractAndAddBytes)

#define Cyclist_Instance                JOIN(prefix, _Instance)
#define Cyclist_Initialize              JOIN(prefix, _Initialize)
#define Cyclist_Absorb                  JOIN(prefix, _Absorb)
#define Cyclist_Encrypt                 JOIN(prefix, _Encrypt)
#define Cyclist_Decrypt                 JOIN(prefix, _Decrypt)
#define Cyclist_Squeeze                 JOIN(prefix, _Squeeze)
#define Cyclist_SqueezeKey              JOIN(prefix, _SqueezeKey)
#define Cyclist_Ratchet                 JOIN(prefix, _Ratchet)

#define Cyclist_AbsorbAny               JOIN(prefix, _AbsorbAny)
#define Cyclist_AbsorbKey               JOIN(prefix, _AbsorbKey)
#define Cyclist_SqueezeAny              JOIN(prefix, _SqueezeAny)
#define Cyclist_Down                    JOIN(prefix, _Down)
#define Cyclist_Up                      JOIN(prefix, _Up)
#define Cyclist_Crypt                   JOIN(prefix, _Crypt)

#define Cyclist_f_bPrime                JOIN(prefix, _f_bPrime)
#define Cyclist_Rhash                   JOIN(prefix, _Rhash)
#define Cyclist_Rkin                    JOIN(prefix, _Rkin)
#define Cyclist_Rkout                   JOIN(prefix, _Rkout)
#define Cyclist_lRatchet                JOIN(prefix, _lRatchet)

#define Cyclist_AbsorbKeyedFullBlocks   JOIN(prefix, _AbsorbKeyedFullBlocks)
#define Cyclist_AbsorbHashFullBlocks    JOIN(prefix, _AbsorbHashFullBlocks)
#define Cyclist_SqueezeKeyedFullBlocks  JOIN(prefix, _SqueezeKeyedFullBlocks)
#define Cyclist_SqueezeHashFullBlocks   JOIN(prefix, _SqueezeHashFullBlocks)
#define Cyclist_EncryptFullBlocks       JOIN(prefix, _EncryptFullBlocks)
#define Cyclist_DecryptFullBlocks       JOIN(prefix, _DecryptFullBlocks)

/* ------- Cyclist internal interfaces ------- */

static void Cyclist_Down(Cyclist_Instance *instance, const uint8_t *Xi, unsigned int XiLen, uint8_t Cd)
{
    SnP_AddBytes(&instance->state, Xi, 0, XiLen);
    SnP_AddByte(&instance->state, 0x01, XiLen);
    SnP_AddByte(&instance->state, (instance->mode == Cyclist_ModeHash) ? (Cd & 0x01) : Cd, Cyclist_f_bPrime - 1);
    instance->phase = Cyclist_PhaseDown;

}

static void Cyclist_Up(Cyclist_Instance *instance, uint8_t *Yi, unsigned int YiLen, uint8_t Cu)
{
    #if defined(OUTPUT)
    uint8_t   s[Cyclist_f_bPrime];
    #endif

    if (instance->mode != Cyclist_ModeHash) {
        SnP_AddByte(&instance->state, Cu, Cyclist_f_bPrime - 1);
    }
    #if defined(OUTPUT)
    if (instance->file != NULL) {
        SnP_ExtractBytes( &instance->stateShadow, s, 0, Cyclist_f_bPrime );
        SnP_ExtractAndAddBytes( &instance->state, s, s, 0, Cyclist_f_bPrime );
    }
    #endif
    SnP_Permute( &instance->state );
    #if defined(OUTPUT)
    if (instance->file != NULL) {
        memcpy( instance->stateShadow, instance->state, sizeof(instance->state) );
        fprintf( instance->file, "Data XORed" );
        displayByteString( instance->file, "", s, Cyclist_f_bPrime );
        SnP_ExtractBytes( &instance->stateShadow, s, 0, Cyclist_f_bPrime );
        fprintf( instance->file, "After f() ");
        displayByteString( instance->file, "", s, Cyclist_f_bPrime );
    }
    #endif
    instance->phase = Cyclist_PhaseUp;
    SnP_ExtractBytes( &instance->state, Yi, 0, YiLen );
}

static void Cyclist_AbsorbAny(Cyclist_Instance *instance, const uint8_t *X, size_t XLen, unsigned int r, uint8_t Cd)
{
    unsigned int    splitLen;

    do {
        if (instance->phase != Cyclist_PhaseUp) {
            Cyclist_Up(instance, NULL, 0, 0);
        }
        splitLen = (unsigned int)MyMin(XLen, r);
        Cyclist_Down(instance, X, splitLen, Cd);
        Cd = 0;
        X       += splitLen;
        XLen    -= splitLen;
        if (SnP_GetFeatures() & SnP_Feature_Cyclist) {
            if ((r == Cyclist_Rkin) && (XLen >= Cyclist_Rkin)) {
                size_t  lenProcessed = Cyclist_AbsorbKeyedFullBlocks(&instance->state, X, XLen);
                X       += lenProcessed;
                XLen    -= lenProcessed;
            }
            else if ((r == Cyclist_Rhash) && (XLen >= Cyclist_Rhash)) {
                size_t  lenProcessed = Cyclist_AbsorbHashFullBlocks(&instance->state, X, XLen);
                X       += lenProcessed;
                XLen    -= lenProcessed;
            }
        }
    } while ( XLen != 0 );
}

static void Cyclist_AbsorbKey(Cyclist_Instance *instance, const uint8_t *K, size_t KLen, const uint8_t *ID, size_t IDLen, const uint8_t *counter, size_t counterLen)
{
    uint8_t KID[Cyclist_Rkin];

    #if DEBUG
    assert(instance->mode == Cyclist_ModeHash);
    assert((KLen + IDLen) <= (Cyclist_Rkin - 1));
    #endif
    instance->mode      = Cyclist_ModeKeyed;
    instance->Rabsorb   = Cyclist_Rkin;
    instance->Rsqueeze  = Cyclist_Rkout;
    if (KLen != 0) {
        memcpy(KID, K, KLen);
        memcpy(KID + KLen, ID, IDLen);
        KID[KLen + IDLen] = (uint8_t)IDLen;
        Cyclist_AbsorbAny(instance, KID, KLen + IDLen + 1, instance->Rabsorb, 0x02);
        if (counterLen != 0) {
            Cyclist_AbsorbAny(instance, counter, counterLen, 1, 0x00);
        }
    }
}

static void Cyclist_SqueezeAny(Cyclist_Instance *instance, uint8_t *Y, size_t YLen, uint8_t Cu)
{
    unsigned int    len;

    len = (unsigned int)MyMin(YLen, instance->Rsqueeze );
    Cyclist_Up(instance, Y, len, Cu);
    Y += len;
    YLen -= len;
    while (YLen != 0) {
        if ((SnP_GetFeatures() & SnP_Feature_Cyclist) && (instance->mode == Cyclist_ModeKeyed) && (YLen >= Cyclist_Rkin)) {
            size_t  lenProcessed = Cyclist_SqueezeKeyedFullBlocks(&instance->state, Y, YLen);
            Y       += lenProcessed;
            YLen    -= lenProcessed;
        }
        else if ((SnP_GetFeatures() & SnP_Feature_Cyclist) && (instance->mode == Cyclist_ModeHash) && (YLen >= Cyclist_Rhash)) {
            size_t  lenProcessed = Cyclist_SqueezeHashFullBlocks(&instance->state, Y, YLen);
            Y       += lenProcessed;
            YLen    -= lenProcessed;
        }
        else
        {
            Cyclist_Down(instance, NULL, 0, 0);
            len = (unsigned int)MyMin(YLen, instance->Rsqueeze );
            Cyclist_Up(instance, Y, len, 0);
            Y += len;
            YLen -= len;
        }
    }
}

static void Cyclist_Crypt(Cyclist_Instance *instance, const uint8_t *I, uint8_t *O, size_t IOLen, int decrypt)
{
    unsigned int    splitLen;
    uint8_t         P[Cyclist_Rkout];
    uint8_t         Cu = 0x80;

    do {
        if (decrypt != 0) {
            if ((SnP_GetFeatures() & SnP_Feature_Cyclist) && (Cu == 0) && (IOLen >= Cyclist_Rkout)) {
                size_t  lenProcessed = Cyclist_DecryptFullBlocks(&instance->state, I, O, IOLen);
                I       += lenProcessed;
                O       += lenProcessed;
                IOLen   -= lenProcessed;
            }
            else
            {
                splitLen = (unsigned int)MyMin(IOLen, Cyclist_Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
                Cyclist_Up(instance, NULL, 0, Cu); /* Up without extract */
                SnP_ExtractAndAddBytes(&instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
                Cyclist_Down(instance, O, splitLen, 0x00);
                I       += splitLen;
                O       += splitLen;
                IOLen   -= splitLen;
            }
        }
        else {
            if ((SnP_GetFeatures() & SnP_Feature_Cyclist) && (Cu == 0) && (IOLen >= Cyclist_Rkout)) {
                size_t  lenProcessed = Cyclist_EncryptFullBlocks(&instance->state, I, O, IOLen);
                I       += lenProcessed;
                O       += lenProcessed;
                IOLen   -= lenProcessed;
            }
            else
            {
                splitLen = (unsigned int)MyMin(IOLen, Cyclist_Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
                memcpy(P, I, splitLen);
                Cyclist_Up(instance, NULL, 0, Cu); /* Up without extract */
                SnP_ExtractAndAddBytes(&instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
                Cyclist_Down(instance, P, splitLen, 0x00);
                I       += splitLen;
                O       += splitLen;
                IOLen   -= splitLen;
            }
        }
        Cu = 0x00;
    } while ( IOLen != 0 );
}

/* ------- Cyclist interfaces ------- */

void Cyclist_Initialize(Cyclist_Instance *instance, const uint8_t *K, size_t KLen, const uint8_t *ID, size_t IDLen, const uint8_t *counter, size_t counterLen)
{
    SnP_StaticInitialize();
    SnP_Initialize(&instance->state);
    instance->phase     = Cyclist_PhaseUp;
    instance->mode      = Cyclist_ModeHash;
    instance->Rabsorb   = Cyclist_Rhash;
    instance->Rsqueeze  = Cyclist_Rhash;
    #ifdef OUTPUT
    instance->file = 0;
    SnP_Initialize( &instance->stateShadow );
    #endif
    if (KLen != 0) {
        Cyclist_AbsorbKey(instance, K, KLen, ID, IDLen, counter, counterLen);
    }
}

void Cyclist_Absorb(Cyclist_Instance *instance, const uint8_t *X, size_t XLen)
{
    Cyclist_AbsorbAny(instance, X, XLen, instance->Rabsorb, 0x03);
}

void Cyclist_Encrypt(Cyclist_Instance *instance, const uint8_t *P, uint8_t *C, size_t PLen)
{
    #if DEBUG
    assert(instance->mode == Cyclist_ModeKeyed);
    #endif
    Cyclist_Crypt(instance, P, C, PLen, 0);
}

void Cyclist_Decrypt(Cyclist_Instance *instance, const uint8_t *C, uint8_t *P, size_t CLen)
{
    #if DEBUG
    assert(instance->mode == Cyclist_ModeKeyed);
    #endif
    Cyclist_Crypt(instance, C, P, CLen, 1);
}

void Cyclist_Squeeze(Cyclist_Instance *instance, uint8_t *Y, size_t YLen)
{
    Cyclist_SqueezeAny(instance, Y, YLen, 0x40);
}

void Cyclist_SqueezeKey(Cyclist_Instance *instance, uint8_t *K, size_t KLen)
{
    #if DEBUG
    assert(instance->mode == Cyclist_ModeKeyed);
    #endif
    Cyclist_SqueezeAny(instance, K, KLen, 0x20);
}

void Cyclist_Ratchet(Cyclist_Instance *instance)
{
    uint8_t buffer[Cyclist_lRatchet];

    #if DEBUG
    assert(instance->mode == Cyclist_ModeKeyed);
    #endif
    /* Squeeze then absorb is the same as overwriting with zeros */
    Cyclist_SqueezeAny(instance, buffer, sizeof(buffer), 0x10);
    Cyclist_AbsorbAny(instance, buffer, sizeof(buffer), instance->Rabsorb, 0x00);
}

#undef SnP_StaticInitialize
#undef SnP_Initialize
#undef SnP_AddBytes
#undef SnP_AddByte
#undef SnP_OverwriteBytes
#undef SnP_ExtractBytes
#undef SnP_ExtractAndAddBytes

#undef Cyclist_Instance
#undef Cyclist_Initialize
#undef Cyclist_Absorb
#undef Cyclist_Encrypt
#undef Cyclist_Decrypt
#undef Cyclist_Squeeze
#undef Cyclist_SqueezeKey
#undef Cyclist_Ratchet

#undef Cyclist_AbsorbAny
#undef Cyclist_AbsorbKey
#undef Cyclist_SqueezeAny
#undef Cyclist_Down
#undef Cyclist_Up
#undef Cyclist_Crypt

#undef Cyclist_f_bPrime
#undef Cyclist_Rhash
#undef Cyclist_Rkin
#undef Cyclist_Rkout
#undef Cyclist_lRatchet

#undef Cyclist_AbsorbKeyedFullBlocks
#undef Cyclist_AbsorbHashFullBlocks
#undef Cyclist_SqueezeKeyedFullBlocks
#undef Cyclist_SqueezeHashFullBlocks
#undef Cyclist_EncryptFullBlocks
#undef Cyclist_DecryptFullBlocks
