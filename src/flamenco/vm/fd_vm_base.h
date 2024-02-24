#ifndef HEADER_fd_src_flamenco_vm_fd_vm_base_h
#define HEADER_fd_src_flamenco_vm_fd_vm_base_h

/* TODO: Headers included from other modules need cleanup.  At it
   stands, this also brings in util, flamenco_base, ballet/base58,
   ballet/sha256, and a bunch of other stuff (that may or may not be
   necessary) in a somewhat haphazard fashion (include no-no things that
   are only available in hosted environments like stdio and stdlib) */

/* TODO: Separate into public-use / private-implementation APIs */

#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../runtime/fd_runtime.h"

/* fd_vm_log_collector API ********************************************/
/* TODO: ADD SPECIFIC UNIT TEST COVERAGE OF THIS API */

/* A fd_vm_log_collector_t is used by the vm for storing text/bytes
   logged by programs running in the vm.  The collector can collect up
   to FD_VM_LOG_COLLECTOR_BUF_MAX bytes of log data, beyond which the
   log is truncated. */

#define FD_VM_LOG_COLLECTOR_BUF_MAX (10000UL) /* FIXME: IS THIS NUMBER A PROTOCOL REQUIREMENT OR IS 10K JUST LUCKY? */

struct fd_vm_log_collector_private {
  uchar buf[ FD_VM_LOG_COLLECTOR_BUF_MAX ];
  ulong buf_used;
};

typedef struct fd_vm_log_collector_private fd_vm_log_collector_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_log_collector_flush flushes all bytes from a log collector.
   Assumes collector is valid and returns collector.  Use this to
   initial a log collector.  fd_vm_log_collector_wipe is the same as the
   above but also zeros out all memory. */

static inline fd_vm_log_collector_t *
fd_vm_log_collector_flush( fd_vm_log_collector_t * collector ) {
  collector->buf_used = 0UL;
  return collector;
}

static inline fd_vm_log_collector_t *
fd_vm_log_collector_wipe( fd_vm_log_collector_t * collector ) {
  collector->buf_used = 0UL;
  fd_memset( collector->buf, 0, FD_VM_LOG_COLLECTOR_BUF_MAX );
  return collector;
}

/* fd_vm_log_collector_log appends a message of sz bytes to the log,
   truncating it if the collector is already full.  Assumes collector is
   valid and returns collector and msg / sz are valid.  sz 0 is fine. */

static inline fd_vm_log_collector_t *
fd_vm_log_collector_append( fd_vm_log_collector_t * collector,
                            void const *            msg,
                            ulong                   sz ) {
  ulong buf_used = collector->buf_used;
  ulong cpy_sz   = fd_ulong_min( sz, FD_VM_LOG_COLLECTOR_BUF_MAX - buf_used );
  if( FD_LIKELY( cpy_sz ) ) fd_memcpy( collector->buf + buf_used, msg, cpy_sz ); /* Sigh ... branchless if sz==0 wasn't UB */
  collector->buf_used = buf_used + cpy_sz;
  return collector;
}

/* fd_vm_log_collector_{buf,max,used,avail} access the state of the log
   collector.  Assumes collector is valid.  buf returns the location of
   the first buffer buf, the lifetime of the returned pointer is the
   collector lifetime.  max gives the size of buf (positive), used gives
   the number currently in use, in [0,max], avail gives the number of
   bytes free for additional logging (max-used).  Used bytes are at
   offsets [0,used) and available bytes are at offset [used,max). */

FD_FN_CONST static inline uchar const *
fd_vm_log_collector_buf( fd_vm_log_collector_t const * collector ) {
  return collector->buf;
}

FD_FN_CONST static inline ulong
fd_vm_log_collector_buf_max( fd_vm_log_collector_t const * collector ) {
  (void)collector;
  return FD_VM_LOG_COLLECTOR_BUF_MAX;
}

FD_FN_PURE static inline ulong
fd_vm_log_collector_buf_used( fd_vm_log_collector_t const * collector ) {
  return collector->buf_used;
}

FD_FN_PURE static inline ulong
fd_vm_log_collector_buf_avail( fd_vm_log_collector_t const * collector ) {
  return FD_VM_LOG_COLLECTOR_BUF_MAX - collector->buf_used;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_base_h */
