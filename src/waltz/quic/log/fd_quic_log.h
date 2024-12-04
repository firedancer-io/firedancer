#ifndef HEADER_fd_src_waltz_quic_log_fd_quic_log_event_h
#define HEADER_fd_src_waltz_quic_log_fd_quic_log_event_h

/* fd_quic_log.h contains ABI definitions for quic shm logging. */

#include "../../../util/fd_util_base.h"

/* fd_quic_log_abi_t contains all parameters required to consume log
   messages out from a quic_log interface. */

struct fd_quic_log_abi {
  ulong magic; /* ==FD_QUIC_LOG_MAGIC */
  ulong mcache_off;
  uint  chunk0;
  uint  chunk1;
};

typedef struct fd_quic_log_abi fd_quic_log_abi_t;

/* FIXME document */

struct fd_quic_log_hdr {
  /* 0x00 */ ulong  conn_id;
  /* 0x08 */ ulong  pkt_num;
  /* 0x10 */ uchar  ip4_saddr[4]; /* big endian */
  /* 0x14 */ ushort udp_sport;    /* little endian */
  /* 0x16 */ uchar  enc_level;
  /* 0x17 */ uchar  flags;
  /* 0x18 */
};

typedef struct fd_quic_log_hdr fd_quic_log_hdr_t;

/* Event IDs **********************************************************/

/* Event group: Connection events */

#define FD_QUIC_EVENT_CONN_NEW         (0x01) /* connection opened */
#define FD_QUIC_EVENT_CONN_ESTABLISHED (0x02) /* connection established (handshake done) */
#define FD_QUIC_EVENT_CONN_QUIC_CLOSE  (0x03) /* connection closed (due to QUIC) */
#define FD_QUIC_EVENT_CONN_APP_CLOSE   (0x04) /* connection closed (due to app request) */

/* Event group: Object pool alloc failures */

#define FD_QUIC_EVENT_ALLOC_FAIL_PKT_META (0x101) /* fd_quic_pkt_meta_t */
#define FD_QUIC_EVENT_ALLOC_FAIL_CONN     (0x102) /* fd_quic_conn_t */
#define FD_QUIC_EVENT_ALLOC_FAIL_STREAM   (0x103) /* fd_quic_stream_t */

/* Event structs ******************************************************/

/* fd_quic_log_error_t is a generic error code container.
   src_file:src_line point to the source line of code that threw this
   error.  flags&1==0 if the error originated locally.  flags&1==1 if
   the error originated on the peer's side and was sent to us.

   code is defined depending on the FD_QUIC_EVENT_{...} error:

     CONN_QUIC_CLOSE: code[0] is a QUIC Transport Error Code
                        (https://www.iana.org/assignments/quic/quic.xhtml#quic-transport-error-codes)
                      code[1] is an fd_tls specific error code, if code[0] in [0x0100,0x01ff]
     CONN_APP_CLOSE:  code[0] is the error code set by the application */

struct fd_quic_log_error {
  /* 0x00 */ fd_quic_log_hdr_t hdr;
  /* 0x18 */ ulong code[2];       /* protocol-specific error codes */
  /* 0x28 */ char  src_file[16];  /* e.g. "fd_quic.c" */
  /* 0x38 */ uint  src_line;
  /* 0x3c */ uchar flags;
};

typedef struct fd_quic_log_error fd_quic_log_error_t;

#endif /* HEADER_fd_src_waltz_quic_log_fd_quic_log_event_h */
