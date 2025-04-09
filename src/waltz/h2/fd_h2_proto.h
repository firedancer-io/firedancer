#ifndef HEADER_fd_src_waltz_h2_fd_h2_proto
#define HEADER_fd_src_waltz_h2_fd_h2_proto

/* fd_h2_proto.h contains constants and data structures taken from
   HTTP/2 specs. */

#include "fd_h2_base.h"

/* FD_H2_FRAME_TYPE_* give HTTP/2 frame IDs.
   https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#frame-type */

#define FD_H2_FRAME_TYPE_DATA            ((uchar)0x00)
#define FD_H2_FRAME_TYPE_HEADERS         ((uchar)0x01)
#define FD_H2_FRAME_TYPE_PRIORITY        ((uchar)0x02)
#define FD_H2_FRAME_TYPE_RST_STREAM      ((uchar)0x03)
#define FD_H2_FRAME_TYPE_SETTINGS        ((uchar)0x04)
#define FD_H2_FRAME_TYPE_PUSH_PROMISE    ((uchar)0x05)
#define FD_H2_FRAME_TYPE_PING            ((uchar)0x06)
#define FD_H2_FRAME_TYPE_GOAWAY          ((uchar)0x07)
#define FD_H2_FRAME_TYPE_WINDOW_UPDATE   ((uchar)0x08)
#define FD_H2_FRAME_TYPE_CONTINUATION    ((uchar)0x09)
#define FD_H2_FRAME_TYPE_ALTSVC          ((uchar)0x0a)
#define FD_H2_FRAME_TYPE_ORIGIN          ((uchar)0x0c)
#define FD_H2_FRAME_TYPE_PRIORITY_UPDATE ((uchar)0x10)

/* fd_h2_frame_{length,type} pack/unpack the typlen field as found in a
   frame header. */

FD_FN_CONST static inline uchar
fd_h2_frame_type( uint typlen ) {
  return (uchar)( typlen>>24 ); /* in [0,2^8) */
}

FD_FN_CONST static inline uint
fd_h2_frame_length( uint typlen ) {
  return fd_uint_bswap( typlen<<8 ) & 0xFFFFFF; /* in [0,2^24) */
}

/* fd_h2_frame_typlen packs the typlen field for use in a frame header. */

FD_FN_CONST static inline uint
fd_h2_frame_typlen( ulong type,      /* in [0,2^8) */
                    ulong length ) { /* in [0,2^24) */
  return (fd_uint_bswap( (uint)length )>>8) | ((uint)type<<24);
}

FD_FN_CONST static inline uint
fd_h2_frame_stream_id( uint r_stream_id ) {
  return fd_uint_bswap( r_stream_id ) & 0x7fffffffu;
}

/* fd_h2_frame_hdr_t matches the encoding of a HTTP/2 frame header.
   https://www.rfc-editor.org/rfc/rfc9113.html#section-4.1 */

struct __attribute__((packed)) fd_h2_frame_hdr {
  uint  typlen;
  uchar flags;
  uint  r_stream_id;
};

typedef struct fd_h2_frame_hdr fd_h2_frame_hdr_t;

#define FD_H2_FLAG_ACK         ((uchar)0x01)
#define FD_H2_FLAG_END_STREAM  ((uchar)0x01)
#define FD_H2_FLAG_END_HEADERS ((uchar)0x04)
#define FD_H2_FLAG_PADDED      ((uchar)0x08)
#define FD_H2_FLAG_PRIORITY    ((uchar)0x20)


/* fd_h2_priority_t matches the encoding of a PRIORITY frame. */

struct __attribute__((packed)) fd_h2_priority {
  fd_h2_frame_hdr_t hdr;
  uint r_stream_dep;
  uchar weight;
};

typedef struct fd_h2_priority fd_h2_priority_t;


/* A SETTINGS frame contains a series of fd_h2_setting_t. */

struct __attribute__((packed)) fd_h2_setting {
  ushort id;
  uint   value;
};

typedef struct fd_h2_setting fd_h2_setting_t;

/* FD_H2_SETTINGS_* give HTTP/2 setting IDs.
   https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings
   https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2 */

#define FD_H2_SETTINGS_HEADER_TABLE_SIZE      ((ushort)0x01)
#define FD_H2_SETTINGS_ENABLE_PUSH            ((ushort)0x02)
#define FD_H2_SETTINGS_MAX_CONCURRENT_STREAMS ((ushort)0x03)
#define FD_H2_SETTINGS_INITIAL_WINDOW_SIZE    ((ushort)0x04)
#define FD_H2_SETTINGS_MAX_FRAME_SIZE         ((ushort)0x05)
#define FD_H2_SETTINGS_MAX_HEADER_LIST_SIZE   ((ushort)0x06)


/* fd_h2_ping_t matches the encoding of a PING frame.
   https://www.rfc-editor.org/rfc/rfc9113.html#name-ping
   Valid flags: ACK */

struct __attribute__((packed)) fd_h2_ping {
  fd_h2_frame_hdr_t hdr;

  ulong payload;
};

typedef struct fd_h2_ping fd_h2_ping_t;


/* fd_h2_goaway_t matches the encoding of a GOAWAY frame.
   https://www.rfc-editor.org/rfc/rfc9113.html#name-goaway */

struct __attribute__((packed)) fd_h2_goaway {
  fd_h2_frame_hdr_t hdr;

  uint last_stream_id;
  uint error_code;
  /* variable length debug data follows ... */
};

typedef struct fd_h2_goaway fd_h2_goaway_t;


/* fd_h2_window_update_t matches the encoding of a WINDOW_UPDATE frame.
   https://www.rfc-editor.org/rfc/rfc9113.html#name-window_update */

struct __attribute__((packed)) fd_h2_window_update {
  fd_h2_frame_hdr_t hdr;

  uint increment;
};

typedef struct fd_h2_window_update fd_h2_window_update_t;


/* fd_h2_rst_stream_t matches the encoding of a RST_STREAM frame.
   https://www.rfc-editor.org/rfc/rfc9113.html#name-rst_stream */

struct __attribute__((packed)) fd_h2_rst_stream {
  fd_h2_frame_hdr_t hdr;

  uint error_code;
};

typedef struct fd_h2_rst_stream fd_h2_rst_stream_t;


FD_PROTOTYPES_BEGIN

/* fd_h2_frame_name returns a static-lifetime uppercase cstr with the
   name of a HTTP/2 frame. */

FD_FN_CONST char const *
fd_h2_frame_name( uint frame_id );

/* fd_h2_setting_name returns a static-lifetime uppercase cstr with the
   name of a HTTP/2 setting. */

FD_FN_CONST char const *
fd_h2_setting_name( uint setting_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_proto */
