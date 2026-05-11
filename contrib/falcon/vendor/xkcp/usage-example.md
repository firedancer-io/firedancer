In this guide, we will provide examples of using the high-level API, with less emphasis on
the low-level implementation, since XKCP abstracts the low-level implementation from the user.

Before proceeding with the usage example, please make sure that you have built the XKCP library as described in the [README](./README.markdown)
and included it in your C/C++ project.

# Hashing and extendable output functions (XOFs)

## FIPS 202

Those are the NIST approved SHA-3 functions. They are based on the `Sponge construction`, and the `Keccak-p[1600, 24]` permutation.
The functions are:

### Hash functions

A hash function is a function of binary data (i.e., of a bit string) for which the length of the output is fixed.
The input to a hash function is called the _message_, and the output is called the _digest_ or _hash value_.

NIST standardized the following hash functions in FIPS 202:

- `SHA3-224`
- `SHA3-256`
- `SHA3-384`
- `SHA3-512`

The suffix `224`, `256`, `384`, and `512` indicate the fixed length of the `digest` in bits.

### Extendable output functions (XOFs)

A XOF is a function of a bit string, also called _message_, but for which the output can be extended to any desired length.

NIST standardized the following XOFs in FIPS 202, marking them as the first XOFs to be standardized by NIST.

- `SHAKE128`
- `SHAKE256`

The suffix `128` and `256` indicates the desired security level of the function.

### Usage

To use any of them in your C/C++ project, you have to first build the XKCP library, and include it in your project.
The following steps illustrate how to do that:

#### Example of using the `SHA3-256` hash function

<details open>
    <summary>Simple usage</summary>

```c
#include "SimpleFIPS202.h"

int main() {
   // your input message
   const unsigned char *input =
           (const unsigned char *) "The random message to hash";

   int outputByteLen = 32;
   unsigned char output[outputByteLen];

   int result = SHA3_256(output, input, strlen((const char *) input));

   // returning 0 means success
   assert(result == 0);

   // printing the hash in hexadecimal format
   for (int i = 0; i < outputByteLen; i++)
       printf("\\x%02x", output[i]);
   printf("\n");

   // ...
}
```

</details>

<details open>
    <summary>Advanced: Chunked input</summary>
    Sometimes, the input of your function is too long to be stored in memory and passed to the function at once, 
    think of a big file for example. In such cases, you can feed the input as chunks to the hash function, and at the end, 
    get the output at once or in chunks as well.
    (We'll show an example of that later, with the SHAKE128 XOF.)

```c
 #include "KeccakHash.h"

 int main() {
     const int inputChunksCount = 4;

     const unsigned char *input[inputChunksCount] = {
         (const unsigned char *) "Hello, ",
         (const unsigned char *) "this is ",
         (const unsigned char *) "my custom ",
         (const unsigned char *) "message!"
     };

     Keccak_HashInstance hi;
     HashReturn result;

     // initialize the hash instance
     result = Keccak_HashInitialize_SHA3_256(&hi);
     assert(result == KECCAK_SUCCESS);

     for (int i = 0; i < inputChunksCount; i++) {
         // feed the input in chunks
         result = Keccak_HashUpdate(&hi, input[i], strlen((const char *) input[i]) * 8);
         assert(result == KECCAK_SUCCESS);
     }

     int outputByteLen = 32;
     unsigned char output[outputByteLen];

     // get the output
     result = Keccak_HashFinal(&hi, output);
     assert(result == KECCAK_SUCCESS);

     // printing the hash in hexadecimal format
     for (int i = 0; i < outputByteLen; i++)
         printf("\\x%02x", output[i]);
     printf("\n");

     // ...
 }

```

</details>

#### Example of using the `SHAKE128` XOF

<details open>
<summary>Simple usage</summary>

```c
 #include "SimpleFIPS202.h"

 int main() {
     // your input message
     const unsigned char *input = (const unsigned char *) "The random message to hash";

     // you can choose any output length
     int outputByteLen = 64;
     unsigned char output[outputByteLen];

     int result = SHAKE128(output, outputByteLen, input, strlen((const char *) input));
     // returning 0 means success
     assert(result == 0);

     // printing the hash in hexadecimal format
     for (int i = 0; i < outputByteLen; i++)
        printf("\\x%02x", output[i]);
     printf("\n");

     // ...
 }
```

</details>

<details open>
    <summary>Advanced: Chunked output</summary>
    Since a XOF function has an arbitrary output length, you might want to read the output in chunks.
    
   ```c
    #include "KeccakHash.h"

    int main() {
        // your input message
        const unsigned char *input = (const unsigned char *) "The random message to hash";

        Keccak_HashInstance hi;
        HashReturn result;

        // initialize the hash instance
        result = Keccak_HashInitialize_SHAKE128(&hi);
        assert(result == KECCAK_SUCCESS);

        // feed the input
        result = Keccak_HashUpdate(&hi, input, strlen((const char *) input) * 8);
        assert(result == KECCAK_SUCCESS);

        // call `Keccak_HashFinal` to mark the end of the input
        result = Keccak_HashFinal(&hi, NULL);
        assert(result == KECCAK_SUCCESS);

        // choose the output chunk length
        const int outputChunkByteLen = 16;
        unsigned char chunk[outputChunkByteLen];

        // choose the number of output chunks
        const int outputChunksCount = 4;

        // initialize the full output
        const int fullOutputByteLen = outputChunkByteLen * outputChunksCount;
        unsigned char output[fullOutputByteLen];

        for (int i = 0; i < outputChunksCount; i++) {
            result = Keccak_HashSqueeze(&hi, chunk, outputChunkByteLen * 8);
            assert(result == KECCAK_SUCCESS);

            // incrementally build the output, like writing to a file.
            // for simplicity, we use `memcpy` in this example:
            memcpy(output + (i * outputChunkByteLen), chunk, outputChunkByteLen);
        }

        // printing the output chunk in hexadecimal format
        for (int i = 0; i < fullOutputByteLen; i++)
            printf("\\x%02x", output[i]);
        printf("\n");

        // ...
    }

````

</details>

For more information on how to use the FIPS 202 functions, see the `SimpleFIPS202.h` and `KeccakHash.h` headers.

## TurboSHAKE
`TurboSHAKE` is a family of fast and secure XOFs. These are just like the SHAKE functions of FIPS 202, but with the
Keccak-p permutation reduced to 12 rounds (instead of 24), so about twice faster.
They are based on the `Sponge construction`, and the `Keccak-p[1600, 12]` permutation.

There are 2 main functions in this family:
- `TurboSHAKE128`
- `TurboSHAKE256`

The suffix `128` and `256` indicates the desired security level of the function.

We will give usage examples of the `TurboSHAKE128` function, but the same applies to the `TurboSHAKE256` function.

<details open>
<summary>Simple usage</summary>

```c
 #include "TurboSHAKE.h"

 int main() {
     // your input message
     const unsigned char *input = (const unsigned char *) "The random message to hash";

     // you can choose any output length
     int outputByteLen = 512;
     unsigned char output[outputByteLen];

     // choose a domain separation in the range `[0x01, 0x02, .. , 0x7F]`
     unsigned char domain = 0x1F;

     int result = TurboSHAKE(256, input, strlen((const char *) input), domain, output, outputByteLen);
     assert(result == 0);  // returning 0 means success

     // printing the hash in hexadecimal format
     for (int i = 0; i < outputByteLen; i++)
        printf("\\x%02x", output[i]);
     printf("\n");

     // ...
 }
````

</details>

<details open>
    <summary>Advanced: Chunked output</summary>
    Since a XOF function has an arbitrary output length, you might want to read the output in chunks.
    
   ```c
    #include "TurboSHAKE.h"

    int main() {
        // your input message
        const unsigned char *input = (const unsigned char *) "The random message to hash";

        TurboSHAKE_Instance tsi;

        // initialize the turboSHAKE instance
        int result = TurboSHAKE128_Initialize(&tsi);
        assert(result == 0);

        // feed the input
        result = TurboSHAKE_Absorb(&tsi, input, strlen((const char *) input));
        assert(result == 0);

        // choose a domain separation in the range `[0x01, 0x02, .. , 0x7F]`
        unsigned char domain = 0x1F;
        result = TurboSHAKE_AbsorbDomainSeparationByte(&tsi, domain);
        assert(result == 0);

        // choose the output chunk length
        const int outputChunkByteLen = 16;
        unsigned char chunk[outputChunkByteLen];

        // choose the number of output chunks
        const int outputChunksCount = 4;

        // initialize the full output
        const int fullOutputByteLen = outputChunkByteLen * outputChunksCount;
        unsigned char output[fullOutputByteLen];

        for (int i = 0; i < outputChunksCount; i++) {
            result = TurboSHAKE_Squeeze(&tsi, output, outputChunkByteLen);
            assert(result == 0);

            // incrementally build the output, like writing to a file.
            // for simplicity, we use `memcpy` in this example:
            memcpy(output + (i * outputChunkByteLen), chunk, outputChunkByteLen);
        }

        // printing the output chunk in hexadecimal format
        for (int i = 0; i < fullOutputByteLen; i++)
            printf("\\x%02x", output[i]);
        printf("\n");

        // ...
    }

````
</details>

## KangarooTwelve
`KangarooTwelve` is a family of XOFs, `KT128` and `KT256`, based on `TurboSHAKE128` and `TurboSHAKE256`, respectively, hence using the `Keccak-p[1600, 12]` permutation.
On high-end platforms, it can exploit a high degree of parallelism, whether using multiple cores or the SIMD instruction set of modern processors.

We will give 2 examples of using the `KT128` function, one for the simple usage, with single input single output, then a more advanced example, with chunked input/output.

<details open>
<summary>Simple usage</summary>

```c
 #include "KangarooTwelve.h"

 int main() {
     const unsigned char *input = (const unsigned char *) "The random message to hash";

     const int outputByteLen = 64;
     unsigned char output[outputByteLen];

     int result = KT128(input, strlen((const char *) input), output, outputByteLen, NULL, 0);
     assert(result == 0);  // returning 0 means success

     // printing the hash in hexadecimal format
     for (int i = 0; i < outputByteLen; i++)
        printf("\\x%02x", output[i]);
     printf("\n");

     // ...
 }
````

</details>

<details open>
    <summary>Advanced: Chunked input/output</summary>
    We will feed the input in chunks, and get the output in chunks as well.
    
   ```c
    #include "KangarooTwelve.h"

    int main() {
        const int inputChunksCount = 4;

        const unsigned char *input[inputChunksCount] = {
            (const unsigned char *) "The ",
            (const unsigned char *) "random ",
            (const unsigned char *) "message ",
            (const unsigned char *) "to hash"
        };

        KangarooTwelve_Instance kti;

        int result = KangarooTwelve_Initialize(&kti, 128, 0);
        assert(result == 0);

        for (int i = 0; i < inputChunksCount; i++) {
            result = KangarooTwelve_Update(&kti, input[i], strlen((const char *) input[i]));
            assert(result == 0);
        }

        result = KangarooTwelve_Final(&kti, NULL, NULL, 0);
        assert(result == 0);

        const int outputChunkByteLen = 16;
        unsigned char chunk[outputChunkByteLen];

        const int outputChunksCount = 4;

        const int fullOutputByteLen = outputChunkByteLen * outputChunksCount;
        unsigned char output[fullOutputByteLen];

        for (int i = 0; i < outputChunksCount; i++) {
            result = KangarooTwelve_Squeeze(&kti, chunk, outputChunkByteLen);
            assert(result == 0);

            memcpy(output + (i * outputChunkByteLen), chunk, outputChunkByteLen);
        }

        // printing the output chunk in hexadecimal format
        for (int i = 0; i < fullOutputByteLen; i++)
            printf("\\x%02x", output[i]);
        printf("\n");

        // ...
    }

````
</details>

# General-purpose deck functions

A deck function allows us to feed arbitrary long input chunks and get arbitrary long output chunks interchangeably,
while offering incremental properties on the input and output, helping in speeding up the computation.

## Kravatte

Kravatte is a deck function, on top of which we define simple modes:

1. Kravatte-SANE: authenticated encryption supporting sessions
2. Kravatte-SANSE: nonce-misuse resistant authenticated encryption supporting sessions
3. Kravatte-WBC: wide block cipher
4. Kravatte-WBC-AE: authenticated encryption

Kravatte is built upon the Keccak-p permutation, and the Farfalle construction, providing inherent parallelism that can be exploited on platforms supporting SIMD instructions or multiple cores.

In the following, we will give example usages of these modes.


### Kravatte-SANE authenticated encryption

SANE is a nonce-based authenticated encryption scheme supporting sessions, the tag for the message _n_ authenticates
the full history of the session up to that point, i.e., the messages 1, 2, ..., _n_.

<details open>
   <summary>Authenticated Encryption: conversation example</summary>

```c
#include "KravatteModes.h"

struct Message
{
    unsigned char *data;
    unsigned char *metadata;
} Message;

struct Message messages[] = {
    {(unsigned char *)"Hello, how is it going?", (unsigned char *)"time: 2020-12-12 12:12:12"},
    {(unsigned char *)"Can we meet at 12:30?", (unsigned char *)"time: 2020-12-12 12:12:13"},
    {(unsigned char *)"I want to talk about the project", (unsigned char *)"time: 2020-12-12 12:12:14"}};


int main() {
    // ksiEnc is the sender, while ksiDec is the receiver
    Kravatte_SANE_Instance ksiEnc;
    Kravatte_SANE_Instance ksiDec;

    // choose any key
    const int keyBitLen = 256;
    BitSequence key[keyBitLen] = "alksjdfo2300a9sdflkjasdfdq343ag2";

    // choose the nonce. it must be the same for both ksiEnc and ksiDec
    const int nonceBitLen = 128;
    // important: the nonce must be a different value at every use!
    BitSequence nonce[nonceBitLen] = "alksjdfo2300a9sd";

    BitSequence tagEnc[Kravatte_SANE_TagLength];
    BitSequence tagDec[Kravatte_SANE_TagLength];

    int result;

    // initialize the instance for both sender and receiver
    // make sure to use the same key/nonce pair for both,
    // otherwise, `tagEnc` and `tagDec` won't match.

    result = Kravatte_SANE_Initialize(&ksiEnc, key, keyBitLen, nonce, nonceBitLen, tagEnc);
    assert(result == 0);

    result = Kravatte_SANE_Initialize(&ksiDec, key, keyBitLen, nonce, nonceBitLen, tagDec);
    assert(result == 0);

    assert(memcmp(tagEnc, tagDec, Kravatte_SANE_TagLength) == 0);

    BitSequence *ciphertexts[3];
    BitSequence *tags[3];

    // Encrypt the messages by the sender
    for (int i = 0; i < 3; i++)
    {
        struct Message message = messages[i];

        int messageBitLen = strlen((const char *)message.data) * 8;
        ciphertexts[i] = malloc(sizeof(BitSequence) * (messageBitLen / 8));

        tags[i] = malloc(sizeof(BitSequence) * Kravatte_SANE_TagLength);

        int metadataBitLen = strlen((const char *)message.metadata) * 8;

        // encrypt the message and store the ciphertext and the tag in `ciphertexts[i]`
        // and `tag[i]` for later use by the decryptor. In real application, we will
        // be sending ciphertext and the tag over the wire towards the decryptor.

        result = Kravatte_SANE_Wrap(
            &ksiEnc,
            message.data, ciphertexts[i], messageBitLen,
            message.metadata, metadataBitLen,
            tags[i]);

        assert(result == 0);
    }

    // CAUTION: uncomment the line below (tempering with the ciphertexts)
    // for the decryption to fail (i.e. for Kravatte_SANE_Unwrap to return 1)
    // ciphertexts[0][0] ^= 1;

    // Decrypt the messages by the receiver
    for (int i = 0; i < 3; i++)
    {
        struct Message message = messages[i];

        int messageBitLen = strlen((const char *)message.data) * 8;
        BitSequence *plaintext = malloc(sizeof(BitSequence) * (messageBitLen / 8));

        int metadataBitLen = strlen((const char *)message.metadata) * 8;

        result = Kravatte_SANE_Unwrap(
            &ksiDec,
            ciphertexts[i], plaintext, messageBitLen,
            message.metadata, metadataBitLen,
            tags[i]);

        assert(result == 0); // no corruption detected, tag is valid

        assert(memcmp(plaintext, message.data, messageBitLen / 8) == 0);
    }

    // don't forget to free the memory :)
    for (int i = 0; i < 3; i++)
    {
        free(ciphertexts[i]);
        free(tags[i]);
    }
    // ...
}
```

</details>

### Kravatte-SANSE authenticated encryption

Like SANE, SANSE is an authenticated encryption scheme supporting sessions, the tag for the message _n_ authenticates
the full history of the session up to that point, i.e. the messages 1, 2, ..., _n_.

However, SANSE is a nonce-misuse resistant version of SANE.
Instead, it uses a nonce internally, and the user only needs to provide a key.

Equal plaintext-associated data pairs can still be detected from equal ciphertexts, so it is best to make sure the associated data is unique per session.
For instance, a user can include a nonce in the associated data of the first message of the session.

<!-- TODO: clarify more about nonce misuse resistant of SANSE? -->

<details open>
   <summary>Authenticated Encryption: conversation example</summary>

```c
#include "KravatteModes.h"

struct Message
{
    unsigned char *data;
    unsigned char *metadata;
} Message;

struct Message messages[] = {
    {(unsigned char *)"Hello, how is it going?", (unsigned char *)"time: 2020-12-12 12:12:12"},
    {(unsigned char *)"Can we meet at 12:30?", (unsigned char *)"time: 2020-12-12 12:12:13"},
    {(unsigned char *)"I want to talk about the project", (unsigned char *)"time: 2020-12-12 12:12:14"}};


int main() {
    // ksiEnc is the sender, while ksiDec is the receiver
    Kravatte_SANSE_Instance ksiEnc;
    Kravatte_SANSE_Instance ksiDec;

    // choose any key
    const int keyBitLen = 256;
    BitSequence key[keyBitLen] = "alksjdfo2300a9sdflkjasdfdq343ag2";

    BitSequence tagEnc[Kravatte_SANSE_TagLength];
    BitSequence tagDec[Kravatte_SANSE_TagLength];

    int result;

    // initialize the instance for both sender and receiver with the same key

    result = Kravatte_SANSE_Initialize(&ksiEnc, key, keyBitLen);
    assert(result == 0);

    result = Kravatte_SANSE_Initialize(&ksiDec, key, keyBitLen);
    assert(result == 0);

    BitSequence *ciphertexts[3];
    BitSequence *tags[3];

    // Encrypt the messages by the sender
    for (int i = 0; i < 3; i++)
    {
        struct Message message = messages[i];

        int messageBitLen = strlen((const char *)message.data) * 8;
        ciphertexts[i] = malloc(sizeof(BitSequence) * (messageBitLen / 8));

        tags[i] = malloc(sizeof(BitSequence) * Kravatte_SANSE_TagLength);

        int metadataBitLen = strlen((const char *)message.metadata) * 8;

        // encrypt the message and store the ciphertext and the tag in `ciphertexts[i]`
        // and `tag[i]` for later use by the decryptor. In real application, we will
        // be sending ciphertext and the tag over the wire towards the decryptor.

        result = Kravatte_SANSE_Wrap(
            &ksiEnc,
            message.data, ciphertexts[i], messageBitLen,
            message.metadata, metadataBitLen,
            tags[i]);

        assert(result == 0);
    }

    // CAUTION: uncomment the line below (tempering with the ciphertexts)
    // for the decryption to fail (i.e. for Kravatte_SANSE_Unwrap to return 1)
    // ciphertexts[0][0] ^= 1;

    // Decrypt the messages by the receiver
    for (int i = 0; i < 3; i++)
    {
        struct Message message = messages[i];

        int messageBitLen = strlen((const char *)message.data) * 8;
        BitSequence *plaintext = malloc(sizeof(BitSequence) * (messageBitLen / 8));

        int metadataBitLen = strlen((const char *)message.metadata) * 8;

        result = Kravatte_SANSE_Unwrap(
            &ksiDec,
            ciphertexts[i], plaintext, messageBitLen,
            message.metadata, metadataBitLen,
            tags[i]);

        assert(result == 0); // no corruption detected, tag is valid

        assert(memcmp(plaintext, message.data, messageBitLen / 8) == 0);
    }

    // don't forget to free the memory :)
    for (int i = 0; i < 3; i++)
    {
        free(ciphertexts[i]);
        free(tags[i]);
    }

    // ...
}
```

</details>

### Kravatte-WBC wide block cipher

WBC is a wide block cipher mode, built as a Feistel network.
It can be used to encrypt a message of any length, and produce a ciphertext of the same length.

<details open>
   <summary>Simple encryption/decryption example</summary>

```c
#include "KravatteModes.h"

int main() {
    Kravatte_Instance kwiEnc;

    // choose any key
    const int keyBitLen = 256;
    BitSequence key[keyBitLen] = "alksjdfo2300a9sdflkjasdfdq343ag2";

    int result;

    // initialize the WBC instance
    result = Kravatte_WBC_Initialize(&kwiEnc, key, keyBitLen);
    assert(result == 0);

    const BitSequence *plaintext = (const BitSequence *)"The random message to encrypt";
    int messageBitLen = strlen((const char *)plaintext) * 8;

    BitSequence *ciphertext = malloc(sizeof(BitSequence) * (messageBitLen / 8));

    // choose a unique tweak - it must be the same for the encryption and decryption
    const int tweakBitLen = 128;
    BitSequence tweak[tweakBitLen] = "alksjdfo2300a9sd";

    result = Kravatte_WBC_Encipher(&kwiEnc, plaintext, ciphertext, messageBitLen, tweak, tweakBitLen);
    assert(result == 0);

    BitSequence *decrypted = malloc(sizeof(BitSequence) * (messageBitLen / 8));

    // if the tweak is not the same as the one used for encryption, the decryption will fail
    result = Kravatte_WBC_Decipher(&kwiEnc, ciphertext, decrypted, messageBitLen, tweak, tweakBitLen);
    assert(result == 0);

    assert(memcmp(plaintext, decrypted, messageBitLen / 8) == 0);

    // ...
}
```

</details>

### Kravatte-WBC-AE authenticated encryption

WBC-AE is an authenticated encryption mode, built on top of the WBC mode.

<details open>
   <summary>Simple encryption/decryption example with authentication</summary>

```c
#include "KravatteModes.h"

int main() {
    Kravatte_Instance kwiInstance;

    // choose any key
    const int keyBitLen = 256;
    BitSequence key[keyBitLen] = "alksjdfo2300a9sdflkjasdfdq343ag2";

    int result;

    // initialize the WBC-AE instance
    result = Kravatte_WBCAE_Initialize(&kwiInstance, key, keyBitLen);
    assert(result == 0);

    char plaintext[] = "The random message to encrypt";
    int messageBitLen = strlen((const char *)plaintext) * 8;

    // WBC_AE adds additional `Kravatte_WBCAE_t` bits to the message as tag
    // so we need to allocate buffers with size `messageBitLen + Kravatte_WBCAE_t`
    int extendedBitLen = messageBitLen + Kravatte_WBCAE_t;

    BitSequence *plaintext_buffer = malloc((extendedBitLen) / 8);
    memcpy(plaintext_buffer, plaintext, messageBitLen / 8);

    BitSequence *ciphertext = malloc((extendedBitLen) / 8);

    const int metadataBitLen = 200;
    BitSequence metadata[metadataBitLen] = "time: 2020-12-12 12:12:12";

    // encrypt the message
    result = Kravatte_WBCAE_Encipher(&kwiInstance, plaintext_buffer, ciphertext, messageBitLen, metadata, metadataBitLen);
    assert(result == 0);

    // CAUTION: uncomment the line below (tempering with the ciphertexts)
    // for the decryption to fail (i.e. for Kravatte_WBCAE_Decipher to return 1)
    // ciphertext_extended[0] ^= 1;

    unsigned char *decrypted = malloc((extendedBitLen) / 8);

    result = Kravatte_WBCAE_Decipher(&kwiInstance, ciphertext, decrypted, messageBitLen, metadata, metadataBitLen);
    assert(result == 0);

    assert(memcmp(plaintext, decrypted, messageBitLen / 8) == 0);

    // don't forget to free the memory :)
    free(ciphertext);
    free(decrypted);

    // ...
}
```

</details>

## Xoofff

Xoofff is similar to Kravatte, it's also built on top of the Farfalle construction.
However, it uses the Xoodoo permutation as primitive instead of the Keccak-p used in Kravatte, which makes it more suitable for constrained environments.

Xoofff has an API similar to Kravatte, so the examples of Kravatte can be adapted to use Xoofff.
In the following, we will give the differences between the APIs of Kravatte and Xoofff.

One can use the below conversion tables to adapt the examples of Kravatte to use Xoofff.

### Xoofff-SANE authenticated encryption

| Feature             | Kravatte SANE            | Xoofff SANE           |
| ------------------- | ------------------------ | --------------------- |
| Header              | "KravatteModes.h"        | "XoofffModes.h"       |
| Instance Type       | Kravatte_SANE_Instance   | XoofffSANE_Instance   |
| Initialization      | Kravatte_SANE_Initialize | XoofffSANE_Initialize |
| Wrapping Function   | Kravatte_SANE_Wrap       | XoofffSANE_Wrap       |
| Unwrapping Function | Kravatte_SANE_Unwrap     | XoofffSANE_Unwrap     |
| Tag Length          | Kravatte_SANE_TagLength  | XoofffSANE_TagLength  |

### Xoofff-SANSE authenticated encryption

| Feature             | Kravatte SANSE            | Xoofff SANSE           |
| ------------------- | ------------------------- | ---------------------- |
| Header              | "KravatteModes.h"         | "XoofffModes.h"        |
| Instance Type       | Kravatte_SANSE_Instance   | XoofffSANSE_Instance   |
| Initialization      | Kravatte_SANSE_Initialize | XoofffSANSE_Initialize |
| Wrapping Function   | Kravatte_SANSE_Wrap       | XoofffSANSE_Wrap       |
| Unwrapping Function | Kravatte_SANSE_Unwrap     | XoofffSANSE_Unwrap     |
| Tag Length          | Kravatte_SANSE_TagLength  | XoofffSANSE_TagLength  |

### Xoofff-WBC wide block cipher

| Feature           | Kravatte WBC            | Xoofff WBC           |
| ----------------- | ----------------------- | -------------------- |
| Header            | "KravatteModes.h"       | "XoofffModes.h"      |
| Instance Type     | Kravatte_Instance       | Xoofff_Instance      |
| Initialization    | Kravatte_WBC_Initialize | XoofffWBC_Initialize |
| Encipher Function | Kravatte_WBC_Encipher   | XoofffWBC_Encipher   |
| Decipher Function | Kravatte_WBC_Decipher   | XoofffWBC_Decipher   |

### Xoofff-WBC-AE authenticated encryption

| Feature           | Kravatte WBC-AE           | Xoofff WBC-AE          |
| ----------------- | ------------------------- | ---------------------- |
| Header            | "KravatteModes.h"         | "XoofffModes.h"        |
| Instance Type     | Kravatte_Instance         | Xoofff_Instance        |
| Initialization    | Kravatte_WBCAE_Initialize | XoofffWBCAE_Initialize |
| Encipher Function | Kravatte_WBCAE_Encipher   | XoofffWBCAE_Encipher   |
| Decipher Function | Kravatte_WBCAE_Decipher   | XoofffWBCAE_Decipher   |

## Xoodyak

Xoodyak is a versatile cryptographic primitive suitable for hashing, encryption, MAC computation, and authenticated encryption. Xoodyak is a duplex object that absorbs strings of varying lengths, encrypts them, and produces output of arbitrary length.

It inherently maintains a history of operations in its state, deriving resistance against generic attacks from the full-state keyed duplex.

Internally, it uses the Xoodoo permutation that, with its width of 48 bytes, allows for very compact implementations. The choice of 12 rounds justifies a security claim in the hermetic philosophy: It implies that there are no shortcut attacks with higher success probability than generic attacks.

The mode of operation on top of Xoodoo is called Cyclist.

Xoodoo can be used in 2 modes, Hashed mode and Keyed mode. We will provide examples for both modes separately, as well as an example for using them together.

### Hash mode

In hash mode, Xoodoo can absorb an arbitrary length input, and produce an arbitrary length output.

<details open>
   <summary>Simple usage: single input single output</summary>

```c
#include "Xoodyak.h"

void singleInputSingleOuput()
{
    Xoodyak_Instance instance;

    // intialize the instance, with no key, no id, and no counter
    Xoodyak_Initialize(&instance, NULL, 0, NULL, 0, NULL, 0);

    // absorb the message in one call
    Xoodyak_Absorb(&instance, messages[0].data, strlen((char *)messages[0].data));

    const int outputByteLen = 32;
    unsigned char output[outputByteLen];

    // get the hash in one call
    Xoodyak_Squeeze(&instance, output, outputByteLen);

    // print the hash in hexadecimal format
    for (int i = 0; i < outputByteLen; i++)
        printf("\\x%02x", output[i]);
    printf("\n");

    // ...
}

```

</details>

<details open>
   <summary>Advanced usages: Multiple input and/or output</summary>

```c
#include "Xoodyak.h"


// custom struct to be used in the below examples
struct Message { unsigned char *data; unsigned char *metadata; } Message;

// example messages to be used by the hashing functions below
struct Message messages[] = {
    {(unsigned char *)"Hello, how is it going?", (unsigned char *)"time: 2020-12-12 12:12:12"},
    {(unsigned char *)"Can we meet at 12:30?", (unsigned char *)"time: 2020-12-12 12:12:13"},
    {(unsigned char *)"I want to talk about the project", (unsigned char *)"time: 2020-12-12 12:12:14"},
    {(unsigned char *)"", (unsigned char *)"time: 2020-12-12 12-12:16"},
    {(unsigned char*)"I am going to be late", (unsigned char *)""},
    {(unsigned char *)"", (unsigned char *)""}
    };


void multipleInputSingleOutput()
{
    Xoodyak_Instance instance;

    // intialize the instance, with no key, no id, and no counter
    Xoodyak_Initialize(&instance, NULL, 0, NULL, 0, NULL, 0);

    // absorb multiple messages
    Xoodyak_Absorb(&instance, messages[0].data, strlen((char *)messages[0].data));
    Xoodyak_Absorb(&instance, messages[1].data, strlen((char *)messages[1].data));
    Xoodyak_Absorb(&instance, messages[2].data, strlen((char *)messages[2].data));

    const int outputByteLen = 32;
    unsigned char output[outputByteLen];

    // get the hash in one call
    Xoodyak_Squeeze(&instance, output, outputByteLen);

    // print the hash in hexadecimal format
    for (int i = 0; i < outputByteLen; i++)
        printf("\\x%02x", output[i]);
    printf("\n");

    // ...
}

void singleInputMultipleOutput()
{
    Xoodyak_Instance instance;

    // intialize the instance, with no key, no id, and no counter
    Xoodyak_Initialize(&instance, NULL, 0, NULL, 0, NULL, 0);

    // absorb the message in one call
    Xoodyak_Absorb(&instance, messages[0].data, strlen((char *)messages[0].data));

    const int outputByteLen = 16;
    unsigned char output[outputByteLen];

    // squeeze multiple outputs
    for (int i = 0; i < 2; i++)
    {
        Xoodyak_Squeeze(&instance, output, outputByteLen);

        // print the output in hexadecimal format
        for (int i = 0; i < outputByteLen; i++)
            printf("\\x%02x", output[i]);
        printf("\n");

        // NOTE: the first output should be the same as the first 16 bytes of the output of
        // the `singleInputSingleOuput` example above - this is due to the Cyclist properties.
        // However, the second output onwards will be different.
    }

    // ...
}

void multipleInputMultipleOutput()
{
    Xoodyak_Instance instance;

    // intialize the instance, with no key, no id, and no counter
    Xoodyak_Initialize(&instance, NULL, 0, NULL, 0, NULL, 0);

    // absorb multiple messages
    Xoodyak_Absorb(&instance, messages[0].data, strlen((char *)messages[0].data));
    Xoodyak_Absorb(&instance, messages[1].data, strlen((char *)messages[1].data));
    Xoodyak_Absorb(&instance, messages[2].data, strlen((char *)messages[2].data));

    const int outputByteLen = 16;
    unsigned char output[outputByteLen];

    // squeeze multiple outputs
    for (int i = 0; i < 2; i++)
    {

        Xoodyak_Squeeze(&instance, output, outputByteLen);

        // print the output in hexadecimal format
        for (int i = 0; i < outputByteLen; i++)
            printf("\\x%02x", output[i]);
        printf("\n");

        // NOTE: the first output should be the same as the first 16 bytes of the output of
        // the `multipleInputSingleOutput` example above - this is due to the Cyclist properties.
        // However, the second output onwards will be different.
    }

    // ...
}

```

</details>

### Keyed mode

In keyed mode, Xoodyak can do stream encryption, message authentication code (MAC)
computation and authenticated encryption.

Note that in the following examples, we will use the same `messages` array used in the above "Hash mode" examples.

<details open>
    <summary>Simple encryption/decryption</summary>

```c
#include "Xoodyak.h"

void simpleEncryptDecrypt() {
Xoodyak_Instance encInstance;
Xoodyak_Instance decInstance;

    // choose a key
    unsigned char key[16] = "o2jso2j!~l;aksj-";

    // initialize the encryption and decryption instances with the same key
    Xoodyak_Initialize(&encInstance, key, 16, NULL, 0, NULL, 0);
    Xoodyak_Initialize(&decInstance, key, 16, NULL, 0, NULL, 0);

    // choose any nonce
    // important: the nonce must be a different value at every use!
    unsigned char nonce[16] = "#dojd983&72-21!@";

    // encryption and decryption instances must absorb the same nonce
    Xoodyak_Absorb(&encInstance, nonce, 16);
    Xoodyak_Absorb(&decInstance, nonce, 16);

    const int messageByteLen = strlen((char *)messages[0].data);

    // encryption instance encrypts the message
    unsigned char encrypted[messageByteLen];
    Xoodyak_Encrypt(&encInstance, messages[0].data, encrypted, messageByteLen);

    // sends it over the wire

    // decryption instance decrypts the message
    unsigned char decrypted[messageByteLen];
    Xoodyak_Decrypt(&decInstance, encrypted, decrypted, messageByteLen);

    // ...

}

````

</details>

<details open>
    <summary>Authenticated Encryption: simple example</summary>

```c
#include "Xoodyak.h"

void authenticatedEncryption() {
    Xoodyak_Instance encInstance;
    Xoodyak_Instance decInstance;

    // choose a key
    unsigned char key[16] = "o2jso2j!~l;aksj-";

    // initialize the encryption and decryption instances with the same key
    Xoodyak_Initialize(&encInstance, key, 16, NULL, 0, NULL, 0);
    Xoodyak_Initialize(&decInstance, key, 16, NULL, 0, NULL, 0);

    // choose any nonce
    // important: the nonce must be a different value at every use (or the metadata of the first message must be unique).
    unsigned char nonce[16] = "#dojd983&72-21!@";

    // encryption and decryption instances must absorb the same nonce
    Xoodyak_Absorb(&encInstance, nonce, 16);
    Xoodyak_Absorb(&decInstance, nonce, 16);

    const int messageByteLen = strlen((char *)messages[0].data);

    // agree on a tag length
    const int tagByteLen = 16;

    // the AE mode we will use is: encrypt-then-MAC

    // sender side:

    // 1. absorb the metadata for it to also be authenticated
    Xoodyak_Absorb(&encInstance, messages[0].metadata, messageByteLen);

    // 2. encrypt the message
    unsigned char encrypted[messageByteLen];
    Xoodyak_Encrypt(&encInstance, messages[0].data, encrypted, messageByteLen);

    // 3. compute the tag
    unsigned char tag[tagByteLen];
    Xoodyak_Squeeze(&encInstance, tag, tagByteLen);

    // 4. send the encrypted message and the tag over the wire:

    // on the wire:
    // CAUTION: tamper with the encrypted message (flip a bit) by uncommenting
    // the following line and the tags will not match -> Authentication insured.
    // encrypted[0] ^= 1;

    // receiver side:

    // 1. absorb the metadata for it to be part of the history and thus authenticated
    Xoodyak_Absorb(&decInstance, messages[0].metadata, messageByteLen);

    // 2. decrypt the message
    unsigned char decrypted[messageByteLen];
    Xoodyak_Decrypt(&decInstance, encrypted, decrypted, messageByteLen);

    // 3. compute the tag
    unsigned char expectedTag[tagByteLen];
    Xoodyak_Squeeze(&decInstance, expectedTag, tagByteLen);

    // 4. ensure that the tag matches
    assert(memcmp(tag, expectedTag, tagByteLen) == 0);

    // 5. use the decrypted message
    // ...
}


```

</details>

<details open>
    <summary>Authenticated Encryption: Session (aka conversation) example</summary>

```c
#include "Xoodyak.h"

void sessionAuthenticatedEncryption() {
    // we call them alice and bob, as both will play the role of sender and receiver
    Xoodyak_Instance aliceInstance;
    Xoodyak_Instance bobInstance;

    // choose a key
    unsigned char key[16] = "o2jso2j!~l;aksj-";

    // initialize the encryption and decryption instances with the same key
    Xoodyak_Initialize(&aliceInstance, key, 16, NULL, 0, NULL, 0);
    Xoodyak_Initialize(&bobInstance, key, 16, NULL, 0, NULL, 0);

    // choose any nonce
    // important: the nonce must be a different value at every use (or the metadata of the first message must be unique).
    unsigned char nonce[16] = "#dojd983&72-21!@";

    // alice and bob instances must absorb the same nonce
    Xoodyak_Absorb(&aliceInstance, nonce, 16);
    Xoodyak_Absorb(&bobInstance, nonce, 16);

    // choose any tag length
    const int tagByteLen = 16;

    const int messageCount = 6;

    unsigned char *encrypted_messages[messageCount];
    unsigned char *tags[messageCount];

    // Alice sends all the messages to Bob:

    for (int i = 0; i < messageCount; i++) {
        const int messageByteLen = strlen((char *)messages[i].data);

        tags[i] = malloc(tagByteLen);

        // only absorb the metadata if it's not empty
        if (messages[i].metadata != NULL) {
            Xoodyak_Absorb(&aliceInstance, messages[i].metadata, strlen((char *)messages[i].metadata));
        }

        // only encrypt the message if it's not empty
        if (messageByteLen) {
            encrypted_messages[i] = malloc(messageByteLen);
            Xoodyak_Encrypt(&aliceInstance, messages[i].data, encrypted_messages[i], messageByteLen);
        } else {
            encrypted_messages[i] = NULL;
        }

        // finally squeeze a tag
        Xoodyak_Squeeze(&aliceInstance, tags[i], tagByteLen);
    }

    // send all the encrypted messages and the tags over the wire:

    // CAUTION: temper with the encrypted message (flip a bit) by uncommenting
    // the following line and the tags will not match -> Authentication insured.
    // encrypted_messages[0][0] ^= 1;

    // Bob receives the messages and ensure that they're authenticated:

    for (int i = 0; i < messageCount; i++) {
        const int messageByteLen = strlen((char *)messages[i].data);

        // should be the same rules as Alice, only absorb the metadata if it's not empty
        if (messages[i].metadata != NULL) {
            Xoodyak_Absorb(&bobInstance, messages[i].metadata, strlen((char *)messages[i].metadata));
        }

        // should be the same rules as Alice, only decrypt the message if it's not empty
        if (messageByteLen) {
            unsigned char decrypted[messageByteLen];
            Xoodyak_Decrypt(&bobInstance, encrypted_messages[i], decrypted, messageByteLen);
            assert(memcmp(messages[i].data, decrypted, messageByteLen) == 0);
        } else {
            assert(encrypted_messages[i] == NULL);
        }

        // squeeze the tag and ensure that it matches the one received from Alice
        unsigned char expectedTag[tagByteLen];
        Xoodyak_Squeeze(&bobInstance, expectedTag, tagByteLen);
        assert(memcmp(tags[i], expectedTag, tagByteLen) == 0);

        // if the tags match, authentication guaranteed
    }


    // Finally, Bob sends a confirmation message to Alice:

    unsigned char confirmationMessage[32] = "I have received all the messages";

    unsigned char confirmationEncrypted[32];
    Xoodyak_Encrypt(&bobInstance, confirmationMessage, confirmationEncrypted, 32);

    unsigned char confirmationTag[tagByteLen];
    Xoodyak_Squeeze(&bobInstance, confirmationTag, tagByteLen);

    // CAUTION: temper with the encrypted message (flip a bit) by uncommenting
    // the following line and the tags will not match -> Authentication insured.
    // confirmationEncrypted[0] ^= 1;

    // Alice receives the confirmation message and ensures that it's authenticated:

    unsigned char confirmationDecrypted[32];
    Xoodyak_Decrypt(&aliceInstance, confirmationEncrypted, confirmationDecrypted, 32);

    unsigned char expectedConfirmationTag[tagByteLen];
    Xoodyak_Squeeze(&aliceInstance, expectedConfirmationTag, tagByteLen);

    assert(memcmp(confirmationTag, expectedConfirmationTag, tagByteLen) == 0);

    // if the tags match, authentication guaranteed

    // don't forget to free the memory :)
    for (int i = 0; i < messageCount; i++) {
        free(encrypted_messages[i]);
        free(tags[i]);
    }

    // ...
}


```

</details>

<details open>
    <summary>Authenticated Encryption: Session with rolling subkeys example</summary>

As an alternative to using a long-term secret key together with its associated nonce that is incremented at each use, Cyclist offers a mechanism to derive a subkey via the `SqueezeKey()` call. On an encrypting device, one can therefore replace the process of incrementing and storing the updated nonce at each use of the long-term secret key with the process of updating a rolling subkey

In the following example, Alice and Bob will have 2 sessions of conversation, in the first session, they use the same key, and in the second session, they use a new key derived from the first key.

```c
#include "Xoodyak.h"

void sessionAuthenticatedEncryptionWithRollingSubKeys() {
    Xoodyak_Instance aliceInstanceSession1;
    Xoodyak_Instance bobInstanceSession1;

    // choose the same initial key for both instances
    unsigned char aliceKeySession1[16] = "o2jso2j!~l;aksj-";
    unsigned char bobKeySession1[16] = "o2jso2j!~l;aksj-";

    // just to be sure they're the same :)
    assert(memcmp(aliceKeySession1, bobKeySession1, 16) == 0);

    // initialize the instances
    Xoodyak_Initialize(&aliceInstanceSession1, aliceKeySession1, 16, NULL, 0, NULL, 0);
    Xoodyak_Initialize(&bobInstanceSession1, bobKeySession1, 16, NULL, 0, NULL, 0);

    // Note that a nonce is not needed here, as we use a different key for each session.

    // now after we have initialized the instances of session 1,
    // we can derive the subkeys for session 2 and stored it for later.
    unsigned char aliceKeySession2[16];
    Xoodyak_SqueezeKey(&aliceInstanceSession1, aliceKeySession2, 16);
    unsigned char bobKeySession2[16];
    Xoodyak_SqueezeKey(&bobInstanceSession1, bobKeySession2, 16);

    // the new derived keys will be the same, and just to be sure :)
    assert(memcmp(aliceKeySession2, bobKeySession2, 16) == 0);

    // start of session 1 (note that we will not detail the usage of Xoodyak here,
    // for a detailed example, see `sessionAuthenticatedEncryption` above)

    // agree on a tag length
    const int tagByteLen = 16;

    // Alice sends a message to Bob
    unsigned char aliceToBobMessage[24] = "Hello Bob, this is Alice";
    unsigned char encryptedAliceToBobMessage[24];
    Xoodyak_Encrypt(&aliceInstanceSession1, aliceToBobMessage, encryptedAliceToBobMessage, 24);
    unsigned char aliceToBobMessageTag[tagByteLen];
    Xoodyak_Squeeze(&aliceInstanceSession1, aliceToBobMessageTag, tagByteLen);

    // Bob receives the message, decrypts and authenticates it
    unsigned char decryptedAliceToBobMessage[24];
    Xoodyak_Decrypt(&bobInstanceSession1, encryptedAliceToBobMessage, decryptedAliceToBobMessage, 24);
    unsigned char expectedAliceToBobMessageTag[tagByteLen];
    Xoodyak_Squeeze(&bobInstanceSession1, expectedAliceToBobMessageTag, tagByteLen);
    // authenticate the message
    assert(memcmp(aliceToBobMessageTag, expectedAliceToBobMessageTag, tagByteLen) == 0);

    // end of session 1

    // start of session 2

    // we need to use new instances for session 2
    Xoodyak_Instance aliceInstanceSession2;
    Xoodyak_Instance bobInstanceSession2;

    // initialize the instances with the new key direvied from the initial key above
    Xoodyak_Initialize(&aliceInstanceSession2, aliceKeySession2, 16, NULL, 0, NULL, 0);
    Xoodyak_Initialize(&bobInstanceSession2, bobKeySession2, 16, NULL, 0, NULL, 0);

    // same as above, derive the subkeys for session 3 and stored it for later.
    unsigned char aliceKeySession3[16];
    Xoodyak_SqueezeKey(&aliceInstanceSession2, aliceKeySession3, 16);
    unsigned char bobKeySession3[16];
    Xoodyak_SqueezeKey(&bobInstanceSession2, bobKeySession3, 16);

    // Bob sends a message to Alice
    unsigned char bobToAliceMessage[24] = "Hello Alice, this is Bob";
    unsigned char encryptedBobToAliceMessage[24];
    Xoodyak_Encrypt(&bobInstanceSession2, bobToAliceMessage, encryptedBobToAliceMessage, 24);
    unsigned char bobToAliceMessage1Tag[tagByteLen];
    Xoodyak_Squeeze(&bobInstanceSession2, bobToAliceMessage1Tag, tagByteLen);

    // Alice receives the message, decrypts and authenticates it
    unsigned char decryptedBobToAliceMessage[24];
    Xoodyak_Decrypt(&aliceInstanceSession2, encryptedBobToAliceMessage, decryptedBobToAliceMessage, 24);
    unsigned char expectedBobToAliceMessageTag[tagByteLen];
    Xoodyak_Squeeze(&aliceInstanceSession2, expectedBobToAliceMessageTag, tagByteLen);
    // authenticate the message
    assert(memcmp(bobToAliceMessage1Tag, expectedBobToAliceMessageTag, tagByteLen) == 0);

    // end of session 2

    // repeat the same for session 3
    // ...
}

```

</details>

<details open>
    <summary>Authenticated Encryption: Ratchet example</summary>

At any time in keyed mode, the user can call Ratchet(). This causes part of the state to be overwritten with zeroes, thereby making it computationally infeasible to compute the state value before the call to Ratchet() to mitigate the impact of recovering the internal state, e.g., after a side channel attack.

```c

#include "Xoodyak.h"

void authenticatedEncryptionWithRatchet() {
    Xoodyak_Instance encInstance;
    Xoodyak_Instance decInstance;

    unsigned char key[16] = "o2jso2j!~l;aksj-";

    Xoodyak_Initialize(&encInstance, key, 16, NULL, 0, NULL, 0);
    Xoodyak_Initialize(&decInstance, key, 16, NULL, 0, NULL, 0);

    unsigned char nonce[16] = "#dojd983&72-21!@";

    // they must absorb the same nonce
    Xoodyak_Absorb(&encInstance, nonce, 16);
    Xoodyak_Absorb(&decInstance, nonce, 16);

    const int messageByteLen = strlen((char *)messages[0].data);
    const int tagByteLen = 16;

    // sender side:

    unsigned char encrypted[messageByteLen];
    Xoodyak_Absorb(&encInstance, messages[0].metadata, messageByteLen);
    Xoodyak_Encrypt(&encInstance, messages[0].data, encrypted, messageByteLen);

    // Ratchet can be called here (before squeezing the tag) and in
    //  that case, it only requires on extra call to the permutation f.
    //  In this example, it's called before squeezing the tag.
    Xoodyak_Ratchet(&encInstance);

    unsigned char tag[tagByteLen];
    Xoodyak_Squeeze(&encInstance, tag, tagByteLen);

    // Ratchet can be called here (after squeezing the tag) and in
    //  that case, its processing can be done asynchronously, while
    //  the message is transmitted, and waits for the next message.

    // on the wire:
    // CAUTION: temper with the encrypted message (flip a bit) by uncommenting
    // the following line and the tags will not match -> Authentication insured.
    // encrypted[0] ^= 1;

    // receiver side:

    unsigned char decrypted[messageByteLen];
    Xoodyak_Absorb(&decInstance, messages[0].metadata, messageByteLen);
    Xoodyak_Decrypt(&decInstance, encrypted, decrypted, messageByteLen);

    // the receiver has to call Ratchet in the same position as the sender
    // (in this example, before squeezing the tag)
    Xoodyak_Ratchet(&decInstance);

    unsigned char expectedTag[tagByteLen];
    Xoodyak_Squeeze(&decInstance, expectedTag, tagByteLen);

    assert(memcmp(tag, expectedTag, tagByteLen) == 0);
}

```

</details>

### Combining hash and keyed modes

A key exchange protocol, such as Diffie-Hellman or variant, results in a common secret that usually requires further derivation before being used as a symmetric secret key. To do this with a Xoodyak, we can first use it in hash mode to process the common secret, and then use the derived key with Xoodyak in keyed mode.

An example of such usage is given below. Note that we're not focusing on the details on the Diffie-Hellman key exchange, but rather on how to use Xoodyak in Hashed and Keyed modes together.

<details open>
    <summary>Asymetric encryption example with Deffie-Hellman</summary>

```c

void xoodyakCombinedMode() {
    // Alice and Bob have their own public keys
    unsigned char alicePublicKey[32] = "alice's public key";
    unsigned char bobPublicKey[32] = "bob's public key";

    // Alice and Bob have done the Diffie-Hellman key exchange to obtain a shared secret key
    unsigned char sharedSecretKey[32] = "shared secret key";

    // Alice and Bob have agreed on a nonce
    unsigned char nonce[16] = "nonce";

    // Now we get the session key by hashing the public keys, the shared secret key and the nonce:

    Xoodyak_Instance sessionKeyInstance;
    Xoodyak_Initialize(&sessionKeyInstance, NULL, 0, NULL, 0, NULL, 0);

    // absorb the protocol id - could be anything.
    Xoodyak_Absorb(&sessionKeyInstance, "Xoodyak_Combined_Mode", 21);

    // absorb the keys
    Xoodyak_Absorb(&sessionKeyInstance, alicePublicKey, 32);
    Xoodyak_Absorb(&sessionKeyInstance, bobPublicKey, 32);
    Xoodyak_Absorb(&sessionKeyInstance, sharedSecretKey, 32);

    // absorb a nonce - note that if the keys are ephemeral, no need for a nonce
    Xoodyak_Absorb(&sessionKeyInstance, nonce, 16);

    // squeeze the session key
    unsigned char sessionKey[32];
    Xoodyak_Squeeze(&sessionKeyInstance, sessionKey, 32);

    // Now we can use the session key to encrypt and decrypt messages
    //  (note that in this example, for simplicity, we will not authenticate
    // the messages - look into the above examples for authenticated encryption)
    Xoodyak_Instance encInstance;
    Xoodyak_Instance decInstance;

    Xoodyak_Initialize(&encInstance, sessionKey, 32, NULL, 0, NULL, 0);
    Xoodyak_Initialize(&decInstance, sessionKey, 32, NULL, 0, NULL, 0);

    // Alice sends a message to Bob
    unsigned char message[32] = "Hello Bob, this is Alice";
    unsigned char encrypted[32];
    Xoodyak_Encrypt(&encInstance, message, encrypted, 32);
    // Bob decrypts the message
    unsigned char decrypted[32];
    Xoodyak_Decrypt(&decInstance, encrypted, decrypted, 32);

    // Bob sends a message to Alice
    unsigned char message2[32] = "Hello Alice, this is Bob";
    // Bob encrypts the message
    unsigned char encrypted2[32];
    Xoodyak_Encrypt(&decInstance, message2, encrypted2, 32);
    // Alice decrypts the message
    unsigned char decrypted2[32];
    Xoodyak_Decrypt(&encInstance, encrypted2, decrypted2, 32);

    // ...
}

```

</details>
