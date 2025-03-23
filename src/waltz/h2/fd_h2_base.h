#ifndef HEADER_fd_src_waltz_h2_fd_h2_base
#define HEADER_fd_src_waltz_h2_fd_h2_base

#include "../../util/bits/fd_bits.h"

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

#endif /* HEADER_fd_src_waltz_h2_fd_h2_base */
