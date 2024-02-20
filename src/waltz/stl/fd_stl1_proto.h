#ifndef HEADER_fd_src_waltz_stl_fd_stl1_proto_h
#define HEADER_fd_src_waltz_stl_fd_stl1_proto_h

/* fd_stl1_proto.h defined STLv1 protocol data structures. */

#include "../../util/fd_util_base.h"

/* FD_STL_MTU controls the maximum supported UDP payload size.
   This is an implementation specific constant. */

#define FD_STL_MTU (4096UL)

/* FD_STL1_PKT_{...} identify STLv1 packet types. */

#define FD_STL1_PKT_APP_DATA           (0x11)
#define FD_STL1_PKT_HS_SERVER_RETRY    (0x19)
#define FD_STL1_PKT_HS_CLIENT_INITIAL  (0x1a)
#define FD_STL1_PKT_HS_SERVER_CONTINUE (0x1b)
#define FD_STL1_PKT_HS_CLIENT_ACCEPT   (0x1c)
#define FD_STL1_PKT_HS_SERVER_ACCEPT   (0x1d)

/* FD_STL1_SESSION_ID_SZ is the byte size of the session ID. */

#define FD_STL1_SESSION_ID_SZ (7UL)

/* FD_STL1_SUITE_{...} identify STLv1 encryption suites. */

#define FD_STL1_SUITE_A  (0x0001)  /* authenticated (Poly1305) */
#define FD_STL1_SUITE_AE (0x0002)  /* authenticated and encrypted (ChaCha20-Poly1305) */

/* FD_STL1_COOKIE_SZ is the cookie byte size used in the handshake
   mechanism.  (Handshake cookies are analogous to TCP SYN cookies). */

#define FD_STL1_COOKIE_SZ (8UL)

/* FD_STL1_MAC_SZ is the byte size of the message auth code. */

#define FD_STL1_MAC_SZ (16UL)

/* FD_STL1_PUBKEY_SZ is the size of an X25519 key share. */

#define FD_STL1_PUBKEY_SZ (32UL)

/* fd_stl1_hdr_t is the common STLv1 header shared by all packets. */

struct __attribute__((packed)) fd_stl1_hdr {
  /* 0x00 */ uchar version_type;
  /* 0x01 */ uchar session_id[ FD_STL1_SESSION_ID_SZ ];
  /* 0x08 */
};

typedef struct fd_stl1_hdr fd_stl1_hdr_t;

/* fd_stl1_hs_t is an STLv1 handshake packet. */

struct __attribute__((packed)) fd_stl1_hs {
  /* 0x00 */ fd_stl1_hdr_t base;
  /* 0x08 */ uchar         cookie_client   [ FD_STL1_COOKIE_SZ ];
  /* 0x10 */ uchar         cookie_server   [ FD_STL1_COOKIE_SZ ];
  /* 0x18 */ uchar         cookie_gateway  [ FD_STL1_COOKIE_SZ ];
  /* 0x20 */ uchar         static_pubkey   [ FD_STL1_PUBKEY_SZ ];
  /* 0x40 */ uchar         ephemeral_pubkey[ FD_STL1_PUBKEY_SZ ];
  /* 0x60 */ uchar         mac_tag         [ FD_STL1_MAC_SZ    ];
  /* 0x70 */ ushort        version_max;
  /* 0x72 */ ushort        suite;
  /* 0x74 */
};

typedef struct fd_stl1_hs fd_stl1_hs_t;

/* fd_stl1_app_t is an STLv1 application packet. */

struct __attribute__((packed)) fd_stl1_app {
  /* 0x00 */ fd_stl1_hdr_t base;
  /* 0x08 */ uchar         mac_tag[ FD_STL1_MAC_SZ ];
  /* 0x18 */ uint          seq;
  /* 0x1c */
};

typedef struct fd_stl1_app fd_stl1_app_t;

#endif /* HEADER_fd_src_waltz_stl_fd_stl1_proto_h */
