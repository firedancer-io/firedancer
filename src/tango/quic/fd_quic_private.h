#ifndef HEADER_fd_quic_private_h
#define HEADER_fd_quic_private_h

#include "fd_quic_conn.h"

FD_PROTOTYPES_BEGIN

/* used by quic to receive data from network */
size_t
fd_quic_aio_cb_receive( void *            context,
                        fd_aio_buffer_t * batch,
                        size_t            batch_sz );

FD_PROTOTYPES_END

#endif

