#ifndef HEADER_fd_src_waltz_mbedtls_fd_mbedtls_config_h
#define HEADER_fd_src_waltz_mbedtls_fd_mbedtls_config_h

/* fd_mbedtls_config.h should not be included directly.
   The MbedTLS dependency includes this file itself to do various
   build configuration.

   See mbedtls_config.h for a list of available config options. */

/* Modules */
#define MBEDTLS_ERROR_C
#define MBEDTLS_NET_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_VERSION_C

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_STD_CALLOC fd_mbedtls_calloc
#define MBEDTLS_PLATFORM_STD_FREE   fd_mbedtls_free
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C
#define MBEDTLS_FS_IO
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_SSL_ALL_ALERT_MESSAGES
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_ALPN
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_DEBUG_C
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* X.509 */
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

/* RSA */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS

/* ECC */
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_PK_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#define MBEDTLS_PK_PARSE_EC_EXTENDED
#define MBEDTLS_PK_PARSE_EC_COMPRESSED

/* Hash functions */
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_HKDF_C

/* Ciphers */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_AESNI_C
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC

/* fd_mbedtls_{calloc,free} redirect MbedTLS allocations to fd_alloc_t.

   fd_mbedtls_calloc matches the behavior of calloc(3p).  On alloc fail,
   returns NULL and sets errno to ENOMEM.  Reasons for alloc fail are
   (nelem*elsize) overflows, no fd_alloc_t instance available, or no
   free bytes in workspace. */

void *
fd_mbedtls_calloc( unsigned long nelem,
                   unsigned long elsize );

void
fd_mbedtls_free( void * ptr );

#endif /* HEADER_fd_src_waltz_mbedtls_fd_mbedtls_config_h */
