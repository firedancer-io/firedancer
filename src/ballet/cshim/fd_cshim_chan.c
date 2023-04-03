#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "fd_cshim_chan.h"

int
fd_cshim_chan_open_fd( fd_cshim_chan_t * chan,
                       int               fd_ctl,
                       int               fd_msg ) {
  chan->shm_ctl = mmap( NULL, 8UL,            PROT_READ|PROT_WRITE, MAP_SHARED, fd_ctl, 0 );
  if( FD_UNLIKELY( chan->shm_ctl==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "Failed to mmap shim ctl: %s", strerror( errno ) ));
    return 0;
  }

  chan->shm_msg = mmap( NULL, FD_SHIM_MSG_SZ, PROT_READ|PROT_WRITE, MAP_SHARED, fd_msg, 0 );
  if( FD_UNLIKELY( chan->shm_msg==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "Failed to mmap shim msg: %s", strerror( errno ) ));
    return 0;
  }

  chan->wseq = 0UL;
  chan->rseq = 0UL;

  return 1;
}

void
fd_cshim_chan_recvmsg( fd_cshim_chan_t  *    rx,
                       fd_cshim_chan_msg_t * msg ) {
  fd_cshim_chan_msg_t const * shm_msg = rx->shm_msg;

  ulong cseq;
  for(;;) {
    // Poll sequence number for change
    ulong rseq = rx->rseq;
    do {
      cseq = FD_VOLATILE_CONST( shm_msg->cseq );
      FD_SPIN_PAUSE();
    } while( cseq <= rseq );
    msg->cseq = cseq;

    // Check for commit
    ulong nseq = FD_VOLATILE_CONST( shm_msg->nseq );
    if( FD_UNLIKELY( cseq+1UL != nseq ) ) {
      // Torn read
      continue;
    }

    // Read message
    msg->payload_sz = FD_VOLATILE_CONST( shm_msg->payload_sz );
    fd_memcpy( msg->payload, shm_msg->payload, FD_SHIM_PAYLOAD_SZ );

    FD_COMPILER_MFENCE();

    // Double check for commit
    nseq = FD_VOLATILE_CONST( shm_msg->nseq );
    if( FD_UNLIKELY( cseq+1UL != nseq ) ) {
      // Torn read
      continue;
    }
    msg->nseq = nseq;

    break;
  }

  // Write ack
  rx->rseq = cseq;
  FD_VOLATILE( *rx->shm_ctl ) = cseq;
}

void
fd_cshim_chan_sendmsg( fd_cshim_chan_t *  tx,
                       uchar const *      payload,
                       ulong              sz ) {
  fd_cshim_chan_msg_t * shm_msg = tx->shm_msg;

  /* Wait until reader catches up */
  ulong last_wseq = tx->wseq;
  ulong last_rseq;
  do {
    last_rseq = FD_VOLATILE_CONST( *(tx->shm_ctl) );
    FD_SPIN_PAUSE();
  } while( FD_UNLIKELY( last_rseq<last_wseq ) );

  /* Write sequence number, payload size */
  ulong wseq = last_wseq+1UL;
  FD_VOLATILE( shm_msg->cseq       ) = wseq;
  FD_VOLATILE( shm_msg->payload_sz ) = sz;

  /* Write payload */
  if( FD_UNLIKELY( sz>FD_SHIM_PAYLOAD_SZ ) ) sz=FD_SHIM_PAYLOAD_SZ;
  fd_memcpy( shm_msg->payload, payload, sz );

  FD_COMPILER_MFENCE();

  /* Commit sequence number
     Once `cseq+1UL == nseq`, notifies reader that the message is complete */
  FD_VOLATILE( shm_msg->nseq ) = wseq+1UL;

  tx->wseq = wseq;
}
