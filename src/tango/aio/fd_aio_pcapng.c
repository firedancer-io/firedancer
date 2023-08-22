#include "fd_aio_pcapng.h"
#include "../../util/net/fd_pcapng_private.h"

#include <errno.h>

/* fd_aio_pcapng_send implements fd_aio_send_t */

static int
fd_aio_pcapng_send( void *                    ctx,
                    fd_aio_pkt_info_t const * batch,
                    ulong                     batch_cnt,
                    ulong *                   opt_batch_idx,
                    int                       flush ) {

  long ts = fd_log_wallclock(); /* TODO allow custom clock */

  fd_aio_pcapng_t * mitm = (fd_aio_pcapng_t *)ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( 1UL!=fd_pcapng_fwrite_pkt( ts, batch[ i ].buf, batch[ i ].buf_sz, mitm->pcapng ) ) ) {
      FD_LOG_WARNING(( "fd_pcapng_fwrite_pkt failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      break;
    }
  }

  /* pcaping doesn't require any additional destination */
  if( mitm->dst ) {
    return fd_aio_send( mitm->dst, batch, batch_cnt, opt_batch_idx, flush );
  }

  return FD_AIO_SUCCESS;
}

FD_FN_CONST fd_aio_t const *
fd_aio_pcapng_get_aio( fd_aio_pcapng_t const * mitm ) {
  return &mitm->local;
}

ulong
fd_aio_pcapng_start( void * pcapng ) {
  fd_pcapng_shb_opts_t shb_opts = {0};
  fd_pcapng_shb_defaults( &shb_opts );

  if( FD_UNLIKELY( 1UL!=fd_pcapng_fwrite_shb( &shb_opts, pcapng ) ) )
    return 0UL;

  if( FD_UNLIKELY( 1UL!=fd_pcapng_fwrite_idb(
        FD_PCAPNG_LINKTYPE_ETHERNET, NULL, pcapng ) ) )
    return 0UL;

  return 1UL;
}

fd_aio_pcapng_t *
fd_aio_pcapng_join( void *           _mitm,
                    fd_aio_t const * dst,
                    void *           pcapng ) {

  fd_aio_pcapng_t * mitm = (fd_aio_pcapng_t *)_mitm;
  mitm->dst    = dst;
  mitm->pcapng = pcapng;

  FD_TEST( fd_aio_join( fd_aio_new( &mitm->local, mitm, fd_aio_pcapng_send ) ) );

  return mitm;
}

void *
fd_aio_pcapng_leave( fd_aio_pcapng_t * mitm ) {
  fd_aio_delete( fd_aio_leave( &mitm->local ) );

  mitm->dst    = NULL;
  mitm->pcapng = NULL; /* FIXME flush? */

  return (void *)mitm;
}
