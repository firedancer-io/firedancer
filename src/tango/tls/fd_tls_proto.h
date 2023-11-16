#ifndef HEADER_src_ballet_tls_fd_tls_proto_h
#define HEADER_src_ballet_tls_fd_tls_proto_h

/* fd_tls_proto.h declares various TLS v1.3 data structures and provides
   internal APIs to decode and encode them from/to wire format.

   Most encodings in TLS v1.3 are laid out dynamically and cannot be
   represented with packed C structs, such as variable-length lists and
   "unions" (fields that may hold one of multiple data types).  For this
   dynamic kind of data, fd_tls_proto declares custom structs and
   provides an encode/decode API.

   A small number of type encodings are laid out statically.  For these,
   a packed C struct and a "bswap" (endianness conversion) function is
   provided. */

#include "fd_tls_base.h"

/* TLS Extensions *****************************************************/

struct __attribute__((packed)) fd_tls_ext_hdr {
  ushort type;
  ushort sz;
};

typedef struct fd_tls_ext_hdr fd_tls_ext_hdr_t;

/* Supported TLS versions (RFC 8446)
   Type: FD_TLS_EXT_TYPE_SUPPORTED_VERSIONS */

struct fd_tls_ext_supported_versions {
  uchar tls13 : 1;
};

typedef struct fd_tls_ext_supported_versions fd_tls_ext_supported_versions_t;

/* Server name indication (RFC 6066)
   Type: FD_TLS_EXT_TYPE_SERVER_NAME (0) */

struct fd_tls_ext_server_name {
  ushort host_name_len;    /* Length of name cstr (excluding NUL) */
  char   host_name[ 254 ]; /* Name cstr */
};

typedef struct fd_tls_ext_server_name fd_tls_ext_server_name_t;

/* Supported ECDHE groups (RFC 8422, 7919)
   Type: FD_TLS_EXT_TYPE_SUPPORTED_GROUPS */

struct fd_tls_ext_supported_groups {
  uchar x25519 : 1;
};

typedef struct fd_tls_ext_supported_groups fd_tls_ext_supported_groups_t;

/* Supported signature schemes (RFC 8446)
   Type: FD_TLS_EXT_TYPE_SIGNATURE_ALGORITHMS */

struct fd_tls_ext_signature_algorithms {
  uchar ed25519 : 1;
};

typedef struct fd_tls_ext_signature_algorithms fd_tls_ext_signature_algorithms_t;

struct fd_tls_key_share {
  uchar has_x25519 : 1;
  uchar x25519[ 32 ];
};

typedef struct fd_tls_key_share fd_tls_key_share_t;

union fd_tls_ext_cert_type_list {
  struct {
    uchar present    : 1;  /* if 0, indicates that this extension is missing */
    uchar x509       : 1;
    uchar raw_pubkey : 1;
  };
  uchar uc;
};

typedef union fd_tls_ext_cert_type_list fd_tls_ext_cert_type_list_t;

struct fd_tls_ext_cert_type {
  uchar cert_type;
};

typedef struct fd_tls_ext_cert_type fd_tls_ext_cert_type_t;

/* fd_tls_ext_opaque_t holds a pointer to opaque serialized extension
   data.  Lifetime of buf depends on context -- Look for documentation
   in usages of this structure.

   This structure can have 3 subtly different meanings:
     (!!buf) & (!!bufsz)   Extension present, non-zero sz
     (!!buf) & ( !bufsz)   Extension present, zero sz
     ( !buf) & ( !bufsz)   Extension absent

   Notably,
     (!buf  )  ... implies extension is absent
     (!bufsz)  ... implies extension is absent or zero sz */

struct fd_tls_ext_opaque {
  uchar const * buf;
  ulong         bufsz;
};

typedef struct fd_tls_ext_opaque fd_tls_ext_opaque_t;
typedef struct fd_tls_ext_opaque fd_tls_ext_quic_tp_t;
typedef struct fd_tls_ext_opaque fd_tls_ext_alpn_t;

/* TLS Messages *******************************************************/

/* fd_tls_u24_t is a 24-bit / 3 byte big-endian integer.
   Matches wire representation. */

struct fd_tls_u24 { uchar v[3]; };
typedef struct fd_tls_u24 fd_tls_u24_t;

/* TODO is record header the correct term for this? */

struct __attribute__((packed)) fd_tls_record_hdr {
  uchar        type;   /* FD_TLS_RECORD_{...} */
  fd_tls_u24_t sz;     /* Byte size of fields following this header */
};

typedef struct fd_tls_record_hdr fd_tls_record_hdr_t;

/* fd_tls_client_hello_t describes a TLS v1.3 ClientHello (RFC 8446,
   Section 4.1.2). */

struct fd_tls_client_hello {
  uchar random[ 32 ];

  struct {
    uchar aes_128_gcm_sha256 : 1;
    /* Add more cipher suites here */
  } cipher_suites;

  fd_tls_ext_supported_versions_t   supported_versions;
  fd_tls_ext_server_name_t          server_name;
  fd_tls_ext_supported_groups_t     supported_groups;
  fd_tls_ext_signature_algorithms_t signature_algorithms;
  fd_tls_key_share_t                key_share;
  fd_tls_ext_cert_type_list_t       server_cert_types;
  fd_tls_ext_cert_type_list_t       client_cert_types;
  fd_tls_ext_quic_tp_t              quic_tp;
};

typedef struct fd_tls_client_hello fd_tls_client_hello_t;

/* fd_tls_server_hello_t describes a TLS v1.3 ServerHello (RFC 8446,
   Section 4.1.3). */

struct fd_tls_server_hello {
  uchar  random[ 32 ];
  ushort cipher_suite;

  fd_tls_key_share_t key_share;
};

typedef struct fd_tls_server_hello fd_tls_server_hello_t;

/* fd_tls_enc_ext_t describes a TLS v1.3 EncryptedExtensions message
   (RFC 8446, Section 4.3.1). */

struct fd_tls_enc_ext_t {
  fd_tls_ext_cert_type_t server_cert;
  fd_tls_ext_cert_type_t client_cert;
  fd_tls_ext_quic_tp_t   quic_tp;

  uchar alpn_sz;
  uchar alpn[ FD_TLS_EXT_ALPN_SZ_MAX ];
};

typedef struct fd_tls_enc_ext_t fd_tls_enc_ext_t;

/* fd_tls_cert_verify_t matches the wire representation of
   CertificateVerify (RFC 8446, Section 4.4.3).  Only supports TLS
   signature algorithms with 64 byte signature size (e.g. Ed25519). */

struct __attribute__((packed)) fd_tls_cert_verify {
  ushort sig_alg;  /* FD_TLS_SIGNATURE_{...} */
  uchar  sig[ 64 ];
};

typedef struct fd_tls_cert_verify fd_tls_cert_verify_t;

/* fd_tls_finished_t matches the wire representation of Finished (RFC
   8446, Section 4.4.4).  Only supports TLS cipher suites with 32 byte
   hash output size. */

struct __attribute__((packed)) fd_tls_finished {
  uchar verify[ 32 ];
};

typedef struct fd_tls_finished fd_tls_finished_t;

/* Enums **************************************************************/

/* TLS Legacy Version field */

#define FD_TLS_VERSION_TLS12 ((ushort)0x0303)
#define FD_TLS_VERSION_TLS13 ((ushort)0x0304)

/* TLS cipher suite IDs */

#define FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 ((ushort)0x1301)

/* TLS extension IDs */

#define FD_TLS_EXT_SERVER_NAME           ((ushort) 0)
#define FD_TLS_EXT_SUPPORTED_GROUPS      ((ushort)10)
#define FD_TLS_EXT_SIGNATURE_ALGORITHMS  ((ushort)13)
#define FD_TLS_EXT_ALPN                  ((ushort)16)
#define FD_TLS_EXT_CLIENT_CERT_TYPE      ((ushort)19)
#define FD_TLS_EXT_SERVER_CERT_TYPE      ((ushort)20)
#define FD_TLS_EXT_SUPPORTED_VERSIONS    ((ushort)43)
#define FD_TLS_EXT_KEY_SHARE             ((ushort)51)
#define FD_TLS_EXT_KEY_SHARE             ((ushort)51)
#define FD_TLS_EXT_QUIC_TRANSPORT_PARAMS ((ushort)57)

/* TLS Alert Protocol */

#define FD_TLS_ALERT_UNEXPECTED_MESSAGE              ((uchar) 10)
#define FD_TLS_ALERT_BAD_RECORD_MAC                  ((uchar) 20)
#define FD_TLS_ALERT_RECORD_OVERFLOW                 ((uchar) 22)
#define FD_TLS_ALERT_HANDSHAKE_FAILURE               ((uchar) 40)
#define FD_TLS_ALERT_BAD_CERTIFICATE                 ((uchar) 42)
#define FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE         ((uchar) 43)
#define FD_TLS_ALERT_CERTIFICATE_REVOKED             ((uchar) 44)
#define FD_TLS_ALERT_CERTIFICATE_EXPIRED             ((uchar) 45)
#define FD_TLS_ALERT_CERTIFICATE_UNKNOWN             ((uchar) 46)
#define FD_TLS_ALERT_ILLEGAL_PARAMETER               ((uchar) 47)
#define FD_TLS_ALERT_UNKNOWN_CA                      ((uchar) 48)
#define FD_TLS_ALERT_ACCESS_DENIED                   ((uchar) 49)
#define FD_TLS_ALERT_DECODE_ERROR                    ((uchar) 50)
#define FD_TLS_ALERT_DECRYPT_ERROR                   ((uchar) 51)
#define FD_TLS_ALERT_PROTOCOL_VERSION                ((uchar) 70)
#define FD_TLS_ALERT_INSUFFICIENT_SECURITY           ((uchar) 71)
#define FD_TLS_ALERT_INTERNAL_ERROR                  ((uchar) 80)
#define FD_TLS_ALERT_INAPPROPRIATE_FALLBACK          ((uchar) 86)
#define FD_TLS_ALERT_USER_CANCELED                   ((uchar) 90)
#define FD_TLS_ALERT_MISSING_EXTENSION               ((uchar)109)
#define FD_TLS_ALERT_UNSUPPORTED_EXTENSION           ((uchar)110)
#define FD_TLS_ALERT_UNRECOGNIZED_NAME               ((uchar)112)
#define FD_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE ((uchar)113)
#define FD_TLS_ALERT_UNKNOWN_PSK_IDENTITY            ((uchar)115)
#define FD_TLS_ALERT_CERTIFICATE_REQUIRED            ((uchar)116)
#define FD_TLS_ALERT_NO_APPLICATION_PROTOCOL         ((uchar)120)

/* TLS server_name extension */

#define FD_TLS_SERVER_NAME_TYPE_DNS ((uchar)0)  /* RFC 6066 */

/* TLS signature scheme IDs */

#define FD_TLS_SIGNATURE_ED25519 ((ushort)0x0807)

/* TLS supported_groups extension */

#define FD_TLS_GROUP_SECP256R1 ((ushort)23)
#define FD_TLS_GROUP_X25519    ((ushort)29)

/* TLS supported_versions extension */

#define FD_TLS_VERSION_TLS13 ((ushort)0x0304)

/* TLS key_share extension */

#define FD_TLS_KEY_SHARE_TYPE_X25519 ((ushort)29)

/* TLS v1.3 record types */

#define FD_TLS_RECORD_CLIENT_HELLO       ((uchar)  1)
#define FD_TLS_RECORD_SERVER_HELLO       ((uchar)  2)
#define FD_TLS_RECORD_NEW_SESSION_TICKET ((uchar)  4)
#define FD_TLS_RECORD_ENCRYPTED_EXT      ((uchar)  8)
#define FD_TLS_RECORD_CERT               ((uchar) 11)
#define FD_TLS_RECORD_CERT_REQ           ((uchar) 13)
#define FD_TLS_RECORD_CERT_VERIFY        ((uchar) 15)
#define FD_TLS_RECORD_FINISHED           ((uchar) 20)

/* TLS certificate_type extension (RFC 7250) */

#define FD_TLS_CERTTYPE_X509       ((uchar) 0)
#define FD_TLS_CERTTYPE_RAW_PUBKEY ((uchar) 2)

/* Serialization related **********************************************/

/* ### Decode functions

   Most deserializers follow the same prototype:

     long
     fd_tls_decode_TYPE( TYPE_t * out,
                         void *   wire,
                         ulong    wire_sz );

   Consumes bytes of the provided and populates the data structure
   pointed to by out.  out must be zero-initialized, as the decoder does
   promise to fill in all fields.  wire points to the first byte of the
   encoded payload that may span up to wire_sz bytes.  Returns number of
   bytes read from wire on success.  On failure, returns a negated TLS
   error code.  (Typically DECODE_ERROR alert)

   wire (input) may get mangled for endianness conversion.  Thus, decode
   may not be called twice on the same input buffer.

   ### Encode functions

   Most serializers follow the same prototype:

     long
     fd_tls_encode_TYPE( TYPE_t const * in,
                         void *         wire,
                         ulong          wire_sz );

   Writes bytes containing serialized version of data structure pointed
   to by in.  wire points to the first byte of the buffer to fill.
   wire_sz is the size of that buffer.  Returns number of bytes written
   on success (can be 0).  On failure, returns a negated TLS error code. */

FD_PROTOTYPES_BEGIN

/* Methods for static layout types */

/* Macro STATIC_SERDE defines decode/encode implementations for structs
   that match their wire encoding */

#define STATIC_SERDE( NAME, TYPE_T )                                   \
  static inline long                                                   \
  fd_tls_decode_##NAME ( TYPE_T *     out,                             \
                         void const * wire,                            \
                         ulong        wire_sz ) {                      \
    if( FD_UNLIKELY( wire_sz < sizeof(TYPE_T) ) )                      \
      return -(long)FD_TLS_ALERT_DECODE_ERROR;                         \
    memcpy( out, wire, sizeof(TYPE_T) );                               \
    fd_tls_##NAME##_bswap( out );                                      \
    return (long)sizeof(TYPE_T);                                       \
  }                                                                    \
  static inline long                                                   \
  fd_tls_encode_##NAME ( TYPE_T const * in,                            \
                         void *         wire,                          \
                         ulong          wire_sz ) {                    \
    if( FD_UNLIKELY( wire_sz < sizeof(TYPE_T) ) )                      \
      return -(long)FD_TLS_ALERT_DECODE_ERROR;                         \
    TYPE_T * out = (TYPE_T *)wire;                                     \
    memcpy( out, in, sizeof(TYPE_T) );                                 \
    fd_tls_##NAME##_bswap( out );                                      \
    return (long)sizeof(TYPE_T);                                       \
  }

/* End of STATIC_SERDE macro */

/* Static serialization methods for fd_tls_u24_t */

static inline fd_tls_u24_t
fd_tls_u24_bswap( fd_tls_u24_t x ) {
  fd_tls_u24_t ret = {{ x.v[2], x.v[1], x.v[0] }};
  return ret;
}

static inline uint
fd_tls_u24_to_uint( fd_tls_u24_t x ) {
  return fd_uint_load_3( x.v );
}

static inline fd_tls_u24_t
fd_uint_to_tls_u24( uint x ) {
  fd_tls_u24_t ret = {{ (uchar)( x     &0xffU),
                        (uchar)((x>> 8)&0xffU),
                        (uchar)((x>>16)&0xffU) }};
  return ret;
}

/* Static serde methods for fd_tls_ext_hdr_t */

static inline void
fd_tls_ext_hdr_bswap( fd_tls_ext_hdr_t * x ) {
  x->type = fd_ushort_bswap( x->type );
  x->sz   = fd_ushort_bswap( x->sz );
}

STATIC_SERDE( ext_hdr, fd_tls_ext_hdr_t )

/* Static serde methods for fd_tls_record_hdr_t */

static inline void
fd_tls_record_hdr_bswap( fd_tls_record_hdr_t * x ) {
  x->sz = fd_tls_u24_bswap( x->sz );
}

STATIC_SERDE( record_hdr, fd_tls_record_hdr_t )

/* Static serde methods for fd_tls_finished_t */

static inline void fd_tls_finished_bswap( fd_tls_finished_t * x FD_FN_UNUSED ) {}

STATIC_SERDE( finished, fd_tls_finished_t )

/* Methods for dynamic layout types */

long
fd_tls_decode_client_hello( fd_tls_client_hello_t * out,
                            void const *            wire,
                            ulong                   wire_sz );

long
fd_tls_encode_client_hello( fd_tls_client_hello_t const * in,
                            void *                        wire,
                            ulong                         wire_sz );

long
fd_tls_decode_server_hello( fd_tls_server_hello_t * out,
                            void const *            wire,
                            ulong                   wire_sz );

long
fd_tls_encode_server_hello( fd_tls_server_hello_t const * in,
                            void *                        wire,
                            ulong                         wire_sz );

long
fd_tls_decode_enc_ext( fd_tls_enc_ext_t * out,
                       void const *       wire,
                       ulong              wire_sz );

long
fd_tls_encode_enc_ext( fd_tls_enc_ext_t const * in,
                       void *                   wire,
                       ulong                    wire_sz );

long
fd_tls_encode_server_cert_x509( void const * x509,
                                ulong        x509_sz,
                                void *       wire,
                                ulong        wire_sz );


long
fd_tls_encode_raw_public_key( void const * ed25519_pubkey,
                              void *       wire,
                              ulong        wire_sz );

long
fd_tls_decode_cert_verify( fd_tls_cert_verify_t * out,
                           void const *           wire,
                           ulong                  wire_sz );

static inline void
fd_tls_cert_verify_bswap( fd_tls_cert_verify_t * x ) {
  x->sig_alg = fd_ushort_bswap( x->sig_alg );
}

long
fd_tls_decode_ext_server_name( fd_tls_ext_server_name_t * out,
                               void const *               wire,
                               ulong                      wire_sz );

long
fd_tls_decode_ext_supported_groups( fd_tls_ext_supported_groups_t * out,
                                    void const *                    wire,
                                    ulong                           wire_sz );

long
fd_tls_decode_ext_supported_versions( fd_tls_ext_supported_versions_t * out,
                                      void const *                      wire,
                                      ulong                             wire_sz );

long
fd_tls_decode_ext_signature_algorithms( fd_tls_ext_signature_algorithms_t * out,
                                        void const *                        wire,
                                        ulong                               wire_sz );

long
fd_tls_decode_key_share( fd_tls_key_share_t * out,
                         void const *         wire,
                         ulong                wire_sz );

long
fd_tls_decode_key_share_list( fd_tls_key_share_t * out,
                              void const *         wire,
                              ulong                wire_sz );

long
fd_tls_decode_ext_cert_type_list( fd_tls_ext_cert_type_list_t * out,
                                  void const *                  wire,
                                  ulong                         wire_sz );

long
fd_tls_encode_ext_cert_type_list( fd_tls_ext_cert_type_list_t in,
                                  void const *                wire,
                                  ulong                       wire_sz );


long
fd_tls_decode_ext_cert_type( fd_tls_ext_cert_type_t * out,
                              void const *            wire,
                              ulong                   wire_sz );

long
fd_tls_encode_ext_cert_type( fd_tls_ext_cert_type_t in,
                             void const *           wire,
                             ulong                  wire_sz );

/* fd_tls_decode_ext_opaque is special:
   out->{buf,buf_sz} will be set to {wire,wire_sz}.
   i.e. lifetime of out->quic_tp is that of wire. */

long
fd_tls_decode_ext_opaque( fd_tls_ext_opaque_t * const out,
                          void const *          const wire,
                          ulong                       wire_sz );

static inline long
fd_tls_decode_ext_quic_tp( fd_tls_ext_quic_tp_t * const out,
                           void const *           const wire,
                           ulong                        wire_sz ) {
  return fd_tls_decode_ext_opaque( out, wire, wire_sz );
}

long
fd_tls_decode_ext_alpn( fd_tls_ext_alpn_t * const out,
                        void const *        const wire,
                        ulong                     wire_sz );

/* fd_tls_extract_cert_pubkey extracts the public key of a TLS cert
   message. */

struct fd_tls_extract_cert_pubkey_res {
  uchar const * pubkey;
  uint          alert;
  ushort        reason;
};

typedef struct fd_tls_extract_cert_pubkey_res fd_tls_extract_cert_pubkey_res_t;

fd_tls_extract_cert_pubkey_res_t
fd_tls_extract_cert_pubkey( uchar const * cert,
                            ulong         cert_sz,
                            uint          cert_type );

FD_PROTOTYPES_END

#undef STATIC_SERDE
#endif /* HEADER_src_ballet_tls_fd_tls_proto_h */
