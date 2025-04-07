#ifndef HEADER_snp_proto_h
#define HEADER_snp_proto_h

/* snp_proto.h defines SNP protocol data structures. */

#include "fd_snp_base.h"
#include <stdint.h>

/* SNP_MTU controls the maximum supported UDP payload size. */

#define SNP_MTU     (2048UL)
#define SNP_MTU_MIN (1200UL)

/* SNP_V{...} identify SNP versions. */

#define SNP_V0  ((uchar)0x00)

/* SNP_TYPE_{...} identify SNP packet types. */

#define SNP_TYPE_NULL               ((uchar)0x00)  /* invalid */
#define SNP_TYPE_APP_SIMPLE         ((uchar)0x01)
#define SNP_TYPE_APP_AUTH           ((uchar)0x02)
#define SNP_TYPE_APP_ENCRYPTED      ((uchar)0x03)
#define SNP_TYPE_APP_TLV            ((uchar)0x04)

#define SNP_TYPE_HS_CLIENT_INITIAL  ((uchar)0x08)
#define SNP_TYPE_HS_SERVER_CONTINUE ((uchar)0x09)
#define SNP_TYPE_HS_CLIENT_ACCEPT   ((uchar)0x0A)
#define SNP_TYPE_HS_SERVER_ACCEPT   ((uchar)0x0B)

#define SNP_TYPE_HS_DONE            ((uchar)0xFF) /* invalid on wire */

/* SNP_SUITE_{...} defines cipher suite IDs.

   Each suite consists of:
   - A signature scheme for authentication
   - A key exchange mechanism
   - An authenticated encrypted scheme
   - A hash function for key expansion */

#define SNP_SUITE_S0  ((ushort)0x0000)  /* Ed25519 auth, unencrypted */
#define SNP_SUITE_S1  ((ushort)0x0001)  /* Ed25519 auth, X25519 KEX, AES-128-GCM AEAD, HMAC-SHA256 hash */

/* SNP_SESSION_ID_SZ is the byte size of the session ID. */

#define SNP_SESSION_ID_SZ (7UL)

/* SNP_COOKIE_SZ is the cookie byte size used in the handshake
   mechanism.  (Handshake cookies are analogous to TCP SYN cookies). */

#define SNP_COOKIE_SZ (8UL)

#define SNP_COOKIE_KEY_SZ (16UL)

#define SNP_ED25519_KEY_SZ (32UL)
#define SNP_STATE_KEY_SZ   (16UL)

/* SNP_TOKEN_SZ is the byte size of the "random token" value.  Both
   client and server mix in their token value into the handshake
   commitment to prevent replay attacks. */

#define SNP_TOKEN_SZ (16UL)

/* SNP_MAC_SZ is the byte size of the MAC tag in authenticated packets */

#define SNP_MAC_SZ (16UL)

/* SNP_BASIC_PAYLOAD_MTU is the MTU of the payload carried by the
   0x1 frame type */

#define SNP_BASIC_PAYLOAD_MTU (SNP_MTU - SNP_SESSION_ID_SZ - SNP_MAC_SZ - 1)

#define FD_SNP_MAX_BUF (2UL)

#define FD_SNP_MAX_SESSION_TMP (3)

#define FD_SNP_MAGIC (0xdeadbeeffeebdaedUL)


struct fd_snp_payload {
   ushort sz;
   uchar data[SNP_BASIC_PAYLOAD_MTU];
};

typedef struct fd_snp_payload fd_snp_payload_t;

/* snp_hdr_t is the common SNP header shared by all packets. */

struct __attribute__((packed)) snp_hdr {
  uchar version_type;
  uchar session_id[ SNP_SESSION_ID_SZ ];
};

typedef struct snp_hdr snp_hdr_t;

/* snp_hs_hdr_t is the SNP header shared by all handshake packets. */

struct __attribute__((packed)) snp_hs_hdr {
  snp_hdr_t base;
  uchar   cookie[ SNP_COOKIE_SZ ];
};

typedef struct snp_hs_hdr snp_hdr_hs_t;


FD_PROTOTYPES_BEGIN

/* snp_hdr_{version,type} extract the version and type fields from
   an snp_hdr_t. */

__attribute__((pure))
static inline uchar
snp_hdr_version( snp_hdr_t const * hdr ) {
  return (uchar)( hdr->version_type >> 4 );
}

__attribute__((pure))
static inline uchar
snp_hdr_type( snp_hdr_t const * hdr ) {
  return (uchar)( hdr->version_type & 0x0F );
}

/* snp_hdr_version_type assembles the version_type compound field. */

__attribute__((const))
static inline uchar
snp_hdr_version_type( unsigned int version,
                      unsigned int type ) {
  return (uchar)( ( version << 4 ) | ( type & 0x0F ) );
}

/* seq_{compress,expand} compress 64-bit sequence numbers to 32-bit
   compact versions and vice versa.

   seq_compress implements lossy compression by masking off the high
   half of the sequence number.

   seq_expand attempts to recover a 64-bit sequence given the
   compressed form (seq_compact), and the largest previously
   recovered sequence number (last_seq; does not necessarily have
   to be the previous packet).  For a given unreliable packet stream,
   seq_expand returns the correct result assuming conditions:

   1. The sequence number increments by one for each packet in the
      original order that the packets were sent in.
   2. Less than 2^31 packets were lost between the packet that
      yielded last_seq and the packet carrying seq_compact.
      (Otherwise, the returned sequence number is too small)
   3. The packet carrying seq_compact was reordered less than 2^31
      packets ahead.  (Otherwise, the returned sequence number is
      too large)

   The re-expanded packet number must be authenticated.  E.g.
   in SNP_SUITE_S1, it is part of the IV.  Thus, if an incorrect
   packet number is recovered, decryption fails.  Only sequence
   numbers that passed authentication sholud be considered for
   last_seq. */

static inline uint
seq_compress( ulong seq ) {
  return (uint)seq;
}

static inline ulong
seq_expand( uint seq_compact,
            ulong last_seq ) {
  /* O(3): 32-bit subtract, sign extend, 64-bit add */
  return last_seq + (ulong)(int)(seq_compact - (uint)last_seq);
}

FD_PROTOTYPES_END


/* Suite S0 structures ************************************************/

/* snp_s0_app_hdr_t is the SNP header of application unencrypted packets
   using SNP_SUITE_S0. */

typedef struct snp_hdr snp_s0_app_hdr_t;

/* snp_s0_hs_pkt_t is the SNP header of handshake packets using
   SNP_SUITE_S0. */

union __attribute__((packed)) snp_s0_hs_pkt {

  struct {
    snp_hdr_hs_t hs;

    uchar  identity[32];
    uchar  key_share[32];
    uchar  verify[64]; /* signature */
    uchar  client_token[ SNP_TOKEN_SZ ];
    uchar  server_token[ SNP_TOKEN_SZ ];
  };

  uchar raw[186];

};

typedef union snp_s0_hs_pkt snp_s0_hs_pkt_t;

struct snp_s0_hs_pkt_server_continue {
   snp_hdr_hs_t hs;

   uchar client_token[SNP_TOKEN_SZ];
   uchar key_share[32];     // e
   uchar key_share_enc[48]; // h
};
typedef struct snp_s0_hs_pkt_server_continue snp_s0_hs_pkt_server_continue_t;

struct snp_s0_hs_pkt_client_accept {
   snp_hdr_hs_t hs;

   uchar server_key_share[32];     // e
   uchar server_key_share_enc[48]; // h
   uchar key_share[32];  // e
   /* TODO: if this data is encrypted, it'll be bigger */
   uchar identity[32];   // s
   uchar signature[64];  // sig
};
typedef struct snp_s0_hs_pkt_client_accept snp_s0_hs_pkt_client_accept_t;

struct snp_s0_hs_pkt_server_accept {
   snp_hdr_hs_t hs;

   /* TODO: if this data is encrypted, it'll be bigger */
   uchar identity[32];  // s
   uchar signature[32]; // sig
};
typedef struct snp_s0_hs_pkt_server_accept snp_s0_hs_pkt_server_accept_t;

#endif /* HEADER_snp_proto_h */
