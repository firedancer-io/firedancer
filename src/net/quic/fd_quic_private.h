#ifndef HEADER_fd_quic_private_h
#define HEADER_fd_quic_private_h

#include "fd_quic_conn.h"

FD_PROTOTYPES_BEGIN

/* used by quic to receive data from network */
ulong
fd_quic_aio_cb_receive( void *            context,
                        fd_aio_buffer_t * batch,
                        ulong            batch_sz );

FD_PROTOTYPES_END

#endif

