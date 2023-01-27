#include "fd_aio.h"

/* generate one non-inline compiled copy of fd_aio_send */
extern
size_t
fd_aio_send( fd_aio_t *        aio, 
             fd_aio_buffer_t * batch,
             size_t            batch_sz );

