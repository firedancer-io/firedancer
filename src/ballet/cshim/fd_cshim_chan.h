#ifndef HEADER_fd_src_ballet_cshim_fd_cshim_chan_h
#define HEADER_fd_src_ballet_cshim_fd_cshim_chan_h
#include "../../util/fd_util_base.h"
#include "../../util/log/fd_log.h"

#define FD_SHIM_MSG_SZ      (2048UL)
#define FD_SHIM_PAYLOAD_SZ  (FD_SHIM_MSG_SZ - 24UL)
#define FD_SHIM_MSG_ALIGN   ( 128UL)

struct __attribute((aligned(FD_SHIM_MSG_ALIGN))) fd_cshim_chan_msg {
  ulong cseq;
  ulong payload_sz;
  uchar payload[FD_SHIM_PAYLOAD_SZ];
  ulong nseq;
};
typedef struct fd_cshim_chan_msg fd_cshim_chan_msg_t;

struct __attribute((aligned(FD_SHIM_MSG_ALIGN))) fd_cshim_chan {
  void *  shm_msg;
  ulong * shm_ctl;
  ulong   wseq;
  ulong   rseq;
};
typedef struct fd_cshim_chan fd_cshim_chan_t;

FD_PROTOTYPES_BEGIN

int
fd_cshim_chan_open_fd( fd_cshim_chan_t * chan,
                       int               fd_ctl,
                       int               fd_msg );

void
fd_cshim_chan_recvmsg( fd_cshim_chan_t *     rx,
                       fd_cshim_chan_msg_t * msg );

void
fd_cshim_chan_sendmsg( fd_cshim_chan_t * tx,
                       uchar const *     payload,
                       ulong             sz );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_ballet_cshim_fd_cshim_chan_h */

