# NIST Cryptographic Algorithm Validation Program (CAVP)

CAVP by NIST includes a number of test vectors for validating implementations of NIST-recommended cryptographic algorithms.
For more information, see [csrc.nist.gov](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program).

This module contains unmodified copies of individual test vectors (as of 2022-06-12).
The SHA-256 checksums listed below can be used to verify that the content of these test vectors was not changed.

## SHA Test Vectors for Hashing Byte-Oriented Messages

Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip

Refer to [The Secure Hash Algorithm Validation System (SHAVS)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf) for usage.

Contains test vectors for SHA-2 family hash functions (SHA-256, SHA-512, ...) as specified in FIPS 180-4.

| File Name                | Location        | SHA-256 sum                                                        |
|--------------------------|-----------------|--------------------------------------------------------------------|
| `shabytetestvectors.zip` | -               | `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8` |
| `SHA256ShortMsg.rsp`     | `./sha256/cavp` | `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c` |
| `SHA256LongMsg.rsp`      | `./sha256/cavp` | `6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974` |
| `SHA256Monte.rsp`        | `./sha256/cavp` | `29ea30c6bb4b84e425fb8c1d731c6bb852dac935825f2bd1143e5d3c4f10bfb9` |
| `SHA512LongMsg.rsp`      | `./sha512/cavp` | `b1f3f05d5c209777954d49521d7ea1349447c36a0c52849e044bc397a27dd410` |
| `SHA512ShortMsg.rsp`     | `./sha512/cavp` | `e53a36c03609e5a3e3cc4b6e117a499db7864c23ec825c6cec99503a45f40764` |
| `SHA512Monte.rsp`        | `./sha512/cavp` | `8ca78659286c2f01667a98fc7accd32fc171ae7b24ac00f1a8ce6b77770247fa` |
