#ifndef HEADER_fd_quic_private_h
#define HEADER_fd_quic_private_h

#include "fd_quic_conn.h"

#define FD_QUIC_MAGIC (0xdadf8cfa01cc5460UL)

FD_PROTOTYPES_BEGIN

/* used by quic to receive data from network */
int
fd_quic_aio_cb_receive( void *                    context,
                        fd_aio_pkt_info_t const * batch,
                        ulong                     batch_sz,
                        ulong *                   opt_batch_idx );

FD_PROTOTYPES_END

#endif

