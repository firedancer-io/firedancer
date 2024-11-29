#ifndef HEADER_fd_src_waltz_quic_fd_quic_log_private_h
#define HEADER_fd_src_waltz_quic_fd_quic_log_private_h

/* fd_quic_log_private.h provides internal APIs for high performance
   logging of events.  Programs that wish to read logs should use
   fd_quic_log_user.h instead.

   These are designed to handle millions of events per second in a
   production environment without significantly impacting application
   performance.  That said, the below inlines still contribute to code
   bloat so they should be used sparingly in the hot path.

   Currently uses an unstable custom binary log format, could be made
   compatible with qlog in the future.

   FIXME periodically post mcache heartbeat */

#include "fd_quic_log_event.h"
#include "fd_quic_log_user.h"
#include "../../../tango/fd_tango.h"

#define FD_QUIC_LOG_MTU FD_CHUNK_SZ

struct __attribute__((aligned(64))) fd_quic_logger {
  fd_quic_log_t abi; /* Public ABI */

  ulong seq;
  uint  chunk;
  uint  chunk0;
  uint  wmark;
};

typedef struct fd_quic_logger fd_quic_logger_t;

#define FD_QUIC_LOGGER_ALIGN (64)
#define FD_QUIC_LOGGER_FOOTPRINT(depth)                                                                      \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,                      \
    FD_QUIC_LOGGER_ALIGN, sizeof(fd_quic_logger_t) ),                                                        \
    FD_MCACHE_ALIGN,      FD_MCACHE_FOOTPRINT( depth, 0 ) ),                                                 \
    FD_DCACHE_ALIGN,      FD_DCACHE_FOOTPRINT( FD_DCACHE_REQ_DATA_SZ( FD_QUIC_LOG_MTU, depth, 1, 1 ), 0 ) ), \
    FD_QUIC_LOGGER_ALIGN )

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_quic_logger_align( void );

FD_FN_CONST ulong
fd_quic_logger_footprint( ulong depth );

void *
fd_quic_logger_new( void * shmlog,
                    ulong  depth );

FD_FN_CONST static inline fd_frag_meta_t *
fd_quic_logger_mcache( fd_quic_logger_t * log ) {
  return (void *)( (ulong)log + sizeof(fd_quic_logger_t) + 320UL /* ugly */ );
}

void
fd_quic_logger_sync( fd_quic_logger_t * log );

static inline ulong
fd_quic_log_sig( uint event ) {
  return (ulong)event;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_log_private_h */
