#ifndef HEADER_fd_src_waltz_h2_fd_h2_base_h
#define HEADER_fd_src_waltz_h2_fd_h2_base_h

#include "../../util/bits/fd_bits.h"

/* Enable sockets support? */

#ifndef FD_H2_HAS_SOCKETS
#if FD_HAS_HOSTED
#define FD_H2_HAS_SOCKETS 1
#endif
#endif

#ifndef FD_H2_HAS_SOCKETS
#define FD_H2_HAS_SOCKETS 0
#endif

/* Forward declarations for all objects */

struct fd_h2_callbacks;
typedef struct fd_h2_callbacks fd_h2_callbacks_t;

struct fd_h2_rbuf;
typedef struct fd_h2_rbuf fd_h2_rbuf_t;

struct fd_h2_conn;
typedef struct fd_h2_conn fd_h2_conn_t;

struct fd_h2_stream;
typedef struct fd_h2_stream fd_h2_stream_t;

/* HTTP/2 error codes
   https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#error-code */

#define FD_H2_SUCCESS                   0x00
#define FD_H2_ERR_PROTOCOL              0x01
#define FD_H2_ERR_INTERNAL              0x02
#define FD_H2_ERR_FLOW_CONTROL          0x03
#define FD_H2_ERR_SETTINGS_TIMEOUT      0x04
#define FD_H2_ERR_STREAM_CLOSED         0x05
#define FD_H2_ERR_FRAME_SIZE            0x06
#define FD_H2_ERR_REFUSED_STREAM        0x07
#define FD_H2_ERR_CANCEL                0x08
#define FD_H2_ERR_COMPRESSION           0x09
#define FD_H2_ERR_CONNECT               0x0a
#define FD_H2_ERR_ENHANCE_YOUR_CALM     0x0b
#define FD_H2_ERR_INADEQUATE_SECURITY   0x0c
#define FD_H2_ERR_HTTP_1_1_REQUIRED     0x0d

FD_PROTOTYPES_BEGIN

/* fd_h2_strerror returns a static-lifetime cstr briefly describing the
   given FD_H2_ERR_* code. */

FD_FN_CONST char const *
fd_h2_strerror( uint err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_base_h */
