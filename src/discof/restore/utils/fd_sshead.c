#include "fd_sshead.h"

#include "../../../util/fd_util.h"

#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define FD_SSHEAD_MAGIC (0xF17EDA2CE55DEAD0UL) /* FIREDANCER SSHEAD V0 */

struct fd_sshead_private {
  fd_ssresolve_t * ssresolve;
  int              active;
  long             deadline;
  struct pollfd    pfd;
  ulong            magic;
};

FD_FN_CONST ulong
fd_sshead_align( void ) {
  return fd_ulong_max( alignof(fd_sshead_t), fd_ssresolve_align() );
}

FD_FN_CONST ulong
fd_sshead_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sshead_t), sizeof(fd_sshead_t) );
  l = FD_LAYOUT_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );
  return FD_LAYOUT_FINI( l, fd_sshead_align() );
}

void *
fd_sshead_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sshead_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_sshead_t * head       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sshead_t), sizeof(fd_sshead_t) );
  void *        _ssresolve = FD_SCRATCH_ALLOC_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );

  head->ssresolve = fd_ssresolve_join( fd_ssresolve_new( _ssresolve ) );
  if( FD_UNLIKELY( !head->ssresolve ) ) {
    FD_LOG_WARNING(( "fd_ssresolve_new/join failed" ));
    return NULL;
  }
  head->active    = 0;
  head->deadline  = 0L;
  head->pfd       = (struct pollfd){ .fd = -1, .events = 0, .revents = 0 };

  FD_COMPILER_MFENCE();
  FD_VOLATILE( head->magic ) = FD_SSHEAD_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)head;
}

fd_sshead_t *
fd_sshead_join( void * shhead ) {
  if( FD_UNLIKELY( !shhead ) ) {
    FD_LOG_WARNING(( "NULL shhead" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhead, fd_sshead_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhead" ));
    return NULL;
  }

  fd_sshead_t * head = (fd_sshead_t *)shhead;

  if( FD_UNLIKELY( head->magic!=FD_SSHEAD_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return head;
}

void *
fd_sshead_leave( fd_sshead_t * head ) {
  if( FD_UNLIKELY( !head ) ) {
    FD_LOG_WARNING(( "NULL head" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)head, fd_sshead_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned head" ));
    return NULL;
  }

  if( FD_UNLIKELY( head->magic!=FD_SSHEAD_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *)head;
}

void *
fd_sshead_delete( void * shhead ) {
  if( FD_UNLIKELY( !shhead ) ) {
    FD_LOG_WARNING(( "NULL shhead" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhead, fd_sshead_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhead" ));
    return NULL;
  }

  fd_sshead_t * head = (fd_sshead_t *)shhead;

  if( FD_UNLIKELY( head->magic!=FD_SSHEAD_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_sshead_cancel( head );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( head->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)head;
}

int
fd_sshead_start( fd_sshead_t * head,
                 fd_ip4_port_t addr,
                 int           full,
                 long          now,
                 long          timeout_nanos ) {
  if( FD_UNLIKELY( head->active ) ) {
    FD_LOG_WARNING(( "unable to start sshead with an active session" ));
    return FD_SSHEAD_START_ERR_ACTIVE;
  }

  int sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sockfd ) ) {
    FD_LOG_WARNING(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return FD_SSHEAD_START_ERR_CONN;
  }

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sockfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(int) ) ) ) {
    FD_LOG_WARNING(( "setsockopt() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( sockfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return FD_SSHEAD_START_ERR_CONN;
  }

  struct sockaddr_in sin = {
    .sin_family = AF_INET,
    .sin_port   = addr.port,
    .sin_addr   = { .s_addr = addr.addr },
  };

  if( FD_UNLIKELY( -1==connect( sockfd, fd_type_pun( &sin ), sizeof(sin) ) && errno!=EINPROGRESS ) ) {
    FD_LOG_WARNING(( "connect() to " FD_IP4_ADDR_FMT ":%hu failed for HEAD pre-resolve (%i-%s)",
                     FD_IP4_ADDR_FMT_ARGS( addr.addr ), fd_ushort_bswap( addr.port ),
                     errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( sockfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return FD_SSHEAD_START_ERR_CONN;
  }

  fd_ssresolve_init( head->ssresolve, addr, sockfd, full, NULL );

  head->active   = 1;
  head->deadline = now + timeout_nanos;
  head->pfd      = (struct pollfd){ .fd = sockfd, .events = POLLIN|POLLOUT, .revents = 0 };

  FD_LOG_INFO(( "starting HEAD pre-resolve to " FD_IP4_ADDR_FMT ":%hu",
                FD_IP4_ADDR_FMT_ARGS( addr.addr ), fd_ushort_bswap( addr.port ) ));
  return FD_SSHEAD_START_OK;
}

int
fd_sshead_advance( fd_sshead_t *           head,
                   fd_ssresolve_result_t * result,
                   long                    now ) {
  if( FD_UNLIKELY( !head ) ) {
    FD_LOG_WARNING(( "NULL head" ));
    return FD_SSHEAD_ADVANCE_ERROR;
  }
  if( FD_UNLIKELY( !result ) ) {
    FD_LOG_WARNING(( "NULL result" ));
    return FD_SSHEAD_ADVANCE_ERROR;
  }
  if( FD_UNLIKELY( !head->active ) ) return FD_SSHEAD_ADVANCE_IDLE;

  /* Check timeout (strictly past deadline). */
  if( FD_UNLIKELY( now>head->deadline ) ) {
    fd_ssresolve_cancel( head->ssresolve ); /* closes socket */
    head->active = 0;
    head->pfd.fd = -1;
    return FD_SSHEAD_ADVANCE_TIMEOUT;
  }

  /* Poll the socket */
  int nfds = fd_syscall_poll( &head->pfd, 1U, 0 );
  if( FD_LIKELY( !nfds ) ) return FD_SSHEAD_ADVANCE_AGAIN;
  if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return FD_SSHEAD_ADVANCE_AGAIN;
  if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Drive the ssresolve state machine.  Process POLLOUT then POLLIN
     before checking POLLERR/POLLHUP, as the server may have already
     sent the redirect response before closing the connection. */
  int resolve_error = 0;

  if( FD_LIKELY( !fd_ssresolve_is_done( head->ssresolve ) ) ) {
    if( FD_LIKELY( head->pfd.revents & POLLOUT ) ) {
      int res = fd_ssresolve_advance_poll_out( head->ssresolve );
      if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_ERROR ) ) resolve_error = 1;
    }

    if( !resolve_error && (head->pfd.revents & POLLIN) ) {
      int res = fd_ssresolve_advance_poll_in( head->ssresolve, result );

      if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_ERROR ) ) {
        resolve_error = 1;
      } else if( FD_LIKELY( res==FD_SSRESOLVE_ADVANCE_RESULT ) ) {
        /* Got a valid result from the redirect. */
        fd_ssresolve_cancel( head->ssresolve ); /* closes socket */
        head->active = 0;
        head->pfd.fd = -1;
        return FD_SSHEAD_ADVANCE_DONE;
      }
    }

    /* Check POLLERR/POLLHUP only if the resolve hasn't completed */
    if( !resolve_error && (head->pfd.revents & (POLLERR|POLLHUP)) && !fd_ssresolve_is_done( head->ssresolve ) ) {
      resolve_error = 1;
    }
  }

  if( FD_UNLIKELY( resolve_error ) ) {
    fd_ssresolve_cancel( head->ssresolve ); /* closes socket */
    head->active = 0;
    head->pfd.fd = -1;
    return FD_SSHEAD_ADVANCE_ERROR;
  }

  return FD_SSHEAD_ADVANCE_AGAIN;
}

void
fd_sshead_cancel( fd_sshead_t * head ) {
  if( FD_UNLIKELY( head->active ) ) {
    fd_ssresolve_cancel( head->ssresolve );
    head->active = 0;
    head->pfd.fd = -1;
  }
}

int
fd_sshead_active( fd_sshead_t const * head ) {
  return head->active;
}
