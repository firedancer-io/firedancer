#ifndef HEADER_src_ballet_tls_fd_tls_proto_h
#define HEADER_src_ballet_tls_fd_tls_proto_h

/* fd_tls_proto.h declares various TLS v1.3 data structures. */

#include "../fd_tango_base.h"

/* TLS Extensions *****************************************************/

/* Server name indication (RFC 6066)

   Type: FD_TLS_EXT_TYPE_SERVER_NAME (0) */

struct fd_tls_ext_server_name {
  ushort host_name_len;    /* Length of name cstr (excluding NUL) */
  char   host_name[ 254 ]; /* Name cstr */
};

typedef struct fd_tls_ext_server_name fd_tls_ext_server_name_t;

/* TLS v1.3 Client and Server Hello ************************************

   - legacy_version is always set to FD_TLS_LEGACY_VERSION_TLS12.
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
     Violations result in FD_TLS_ALERT_ILLEGAL_PARAMETER.

   - extension_cnt indicates the number of extensions that were
     originally presented over the wire.  As unsupported extensions are
     ignored, this number may be larger than the number of extensions
     structs stored in the client/server hellos. */

struct fd_tls_client_hello {
  ushort legacy_version;  /* ==FD_TLS_LEGACY_VERSION_TLS12 */
  uchar  random[ 32 ];
  uchar  legacy_session_id_sz; /* ==0 */
  uchar  cipher_suite_cnt;
  ushort cipher_suites[ 8 ];
  uchar  legacy_compression_method_cnt;    /* == 1  */
  uchar  legacy_compression_methods[ 1 ];  /* =={0} */
  ushort extension_cnt;

  fd_tls_ext_server_name_t server_name;
};

struct fd_tls_server_hello {
  ushort legacy_version;  /* ==FD_TLS_LEGACY_VERSION_TLS12 */
  uchar  random[ 32 ];
  uchar  legacy_session_id_echo_sz;  /* ==0 */
  ushort cipher_suite;
  uchar  legacy_compression_method;  /* ==0 */
  ushort extension_cnt;
};

typedef struct fd_tls_client_hello fd_tls_client_hello_t;
typedef struct fd_tls_server_hello fd_tls_server_hello_t;

/* TLS Legacy Version field */

#define FD_TLS_LEGACY_VERSION_TLS12 ((ushort)0x0303)

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

/* TLS v1.3 handshake message types */

#define FD_TLS_HANDSHAKE_TYPE_CLIENT_HELLO ((uchar) 1)
#define FD_TLS_HANDSHAKE_TYPE_SERVER_HELLO ((uchar) 2)
#define FD_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET ((uchar) 4)
#define FD_TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA ((uchar) 5)

/* Serialization related **********************************************/

FD_PROTOTYPES_BEGIN

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

FD_PROTOTYPES_END

#endif /* HEADER_src_ballet_tls_fd_tls_proto_h */
