#include "fd_aio.h"

/* generate one non-inline compiled copy of fd_aio_send */
extern
ulong
fd_aio_send( fd_aio_t *        aio,
             fd_aio_buffer_t * batch,
             ulong             batch_sz );
