#ifndef HEADER_src_ballet_tls_fd_tls_proto_h
#define HEADER_src_ballet_tls_fd_tls_proto_h

/* fd_tls_proto.h declares various TLS v1.3 data structures. */

#include "../fd_tango_base.h"

struct __attribute__((packed)) fd_tls_record_hdr {
  uchar type;
  uint  sz : 24;
};

typedef struct fd_tls_record_hdr fd_tls_record_hdr_t;

/* TLS Extensions *****************************************************/

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

struct fd_tls_ext_key_share {
  uchar has_x25519 : 1;
  uchar x25519[ 32 ];
};

typedef struct fd_tls_ext_key_share fd_tls_ext_key_share_t;

union fd_tls_ext_cert_type_list {
  struct {
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

/* TLS v1.3 Client and Server Hello ************************************

   - legacy_version is always set to FD_TLS_VERSION_TLS12.
     Other values raise FD_TLS_ALERT_PROTOCOL_VERSION.

   - random contains 32 cryptographically secure random bytes.
     The client and server independently generate them for their
     respective hello messages.

   - legacy_session_{id,id_echo}_sz is always zero.
     Other values raise FD_TLS_ALERT_PROTOCOL_VERSION.

   - The client presents a list of supported cipher suites in the
     cipher_suites array.  cipher_suite_cnt sets the array count.
     This array must contain at least one element and must contain
     FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256.  Violations result in
     FD_TLS_ALERT_HANDSHAKE_FAILURE.

   - The server picks one of the client's advertised cipher suites and
     signals it via cipher_suite (singular).

   - legacy_compression_method_cnt is always 1.
     legacy_compression_methods[0] is always 0.
     Violations result in FD_TLS_ALERT_ILLEGAL_PARAMETER. */

struct fd_tls_client_hello {
  uchar  random[ 32 ];

  struct {
    uchar aes_128_gcm_sha256 : 1;
    /* Add more cipher suites here */
  } cipher_suites;

  fd_tls_ext_supported_versions_t   supported_versions;
  fd_tls_ext_server_name_t          server_name;
  fd_tls_ext_supported_groups_t     supported_groups;
  fd_tls_ext_signature_algorithms_t signature_algorithms;
  fd_tls_ext_key_share_t            key_share;
};

struct fd_tls_server_hello {
  uchar  random[ 32 ];
  ushort cipher_suite;

  fd_tls_ext_key_share_t key_share;
};

typedef struct fd_tls_client_hello fd_tls_client_hello_t;
typedef struct fd_tls_server_hello fd_tls_server_hello_t;

struct fd_tls_server_ee {};

typedef struct fd_tls_server_ee fd_tls_server_ee_t;

/* TLS Legacy Version field */

#define FD_TLS_VERSION_TLS12 ((ushort)0x0303)
#define FD_TLS_VERSION_TLS13 ((ushort)0x0304)

/* TLS cipher suite IDs */

#define FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256 ((ushort)0x1301)

/* TLS extension IDs */

#define FD_TLS_EXT_SERVER_NAME          ((ushort) 0)
#define FD_TLS_EXT_SUPPORTED_GROUPS     ((ushort)10)
#define FD_TLS_EXT_SIGNATURE_ALGORITHMS ((ushort)13)
#define FD_TLS_EXT_SUPPORTED_VERSIONS   ((ushort)43)
#define FD_TLS_EXT_KEY_SHARE            ((ushort)51)

/* TLS Alert Protocol */

#define FD_TLS_ALERT_CLOSE_NOTIFY                    ((uchar)  0)
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

/* TLS extension types */

#define FD_TLS_EXT_TYPE_SERVER_NAME          ((ushort) 0)
#define FD_TLS_EXT_TYPE_SUPPORTED_GROUPS     ((ushort)10)
#define FD_TLS_EXT_TYPE_SIGNATURE_ALGORITHMS ((ushort)13)
#define FD_TLS_EXT_TYPE_SUPPORTED_VERSIONS   ((ushort)43)
#define FD_TLS_EXT_TYPE_KEY_SHARE            ((ushort)51)

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

FD_PROTOTYPES_BEGIN

long
fd_tls_decode_record_hdr( fd_tls_record_hdr_t * out,
                          void const *          wire,
                          ulong                 wire_sz );

long
fd_tls_encode_record_hdr( fd_tls_record_hdr_t const * in,
                          void *                      wire,
                          ulong                       wire_sz );

/* Deserialization functions

   All type deserializers follow the same prototype:

     long
     fd_tls_decode_TYPE( TYPE_t *     out,
                         void const * wire,
                         ulong        wire_sz );

   They consume bytes of the provided and populate the data structure
   pointed to by out.  out points to the structure to be filled in
   initialized state.  wire points to the first byte of the encoded
   payload that may span up to wire_sz bytes.  Returns number of bytes
   read from wire on success. On failure, returns a negated TLS error
   code.

   Common reasons for failure include:  FD_TLS_ALERT_DECODE_ERROR
   if input violates encoding rules.  ... TODO */

long
fd_tls_decode_client_hello( fd_tls_client_hello_t * out,
                            void const *            wire,
                            ulong                   wire_sz );

long
fd_tls_decode_server_hello( fd_tls_server_hello_t * out,
                            void const *            wire,
                            ulong                   wire_sz );

long
fd_tls_encode_server_hello( fd_tls_server_hello_t * in,
                            void *                  wire,
                            ulong                   wire_sz );

long
fd_tls_encode_server_ee( fd_tls_server_ee_t * in,
                         void *               wire,
                         ulong                wire_sz );

long
fd_tls_encode_server_cert_x509( void const * x509,
                                ulong        x509_sz,
                                void *       wire,
                                ulong        wire_sz );

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
fd_tls_decode_ext_key_share_client( fd_tls_ext_key_share_t * out,
                                    void const *             wire,
                                    ulong                    wire_sz );

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

FD_PROTOTYPES_END

#endif /* HEADER_src_ballet_tls_fd_tls_proto_h */
