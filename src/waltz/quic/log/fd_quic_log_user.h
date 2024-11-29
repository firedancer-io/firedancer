#ifndef HEADER_fd_src_waltz_quic_fd_quic_log_user_h
#define HEADER_fd_src_waltz_quic_fd_quic_log_user_h

/* fd_quic_log_user.h defines an ABI for extracting high frequency logs
   from an fd_quic instance.

   This header does not provide APIs to write logs.  For those, look in
   fd_quic_log_private.h (as the name implies, currently not stable). */

/* FIXME: Consider custom ring buffer layout instead of using mainline
          fd_frag_meta_t?  Would allow moving most log information into
          the metadata ring, obsoleting the need for a separate data
          cache ring. */

/* FIXME: Consider providing higher level API? */

#include "../../../tango/mcache/fd_mcache.h"

/* fd_quic_log_t describes the memory layout of a log cache. */

struct fd_quic_log {
  ulong magic; /* ==FD_QUIC_LOG_MAGIC */
  uint  mcache_off;
  uint  depth;
};

typedef struct fd_quic_log fd_quic_log_t;

/* FIXME document */

struct fd_quic_log_hdr {
  /* 0x00 */ ulong  conn_id;
  /* 0x08 */ ulong  pkt_num;
  /* 0x10 */ uchar  ip4_saddr[4]; /* big endian */
  /* 0x14 */ ushort udp_sport;    /* little endian */
  /* 0x16 */ uchar  enc_level;
  /* 0x17 */ uchar  flags;
  /* 0x18 */
};

typedef struct fd_quic_log_hdr fd_quic_log_hdr_t;

/* FD_QUIC_LOG_ALIGN describes the expected alignment of a quic_log. */

#define FD_QUIC_LOG_ALIGN (64UL)

/* FD_QUIC_LOG_MAGIC is used to signal the layout of shared memory
   region of a quic_log. */

#define FD_QUIC_LOG_MAGIC (0x9002c4662f7e58b5UL)

FD_PROTOTYPES_BEGIN

/* FIXME document these */

fd_quic_log_t *
fd_quic_log_join( void * shmlog );

void *
fd_quic_log_leave( fd_quic_log_t * log );

/* fd_quic_log_mcache returns a pointer to the metadata ring.  Each log
   message corresponds to an frag_meta entry.  Log message contents are
   extracted using fd_chunk_to_laddr( log, frag->chunk ) where log is
   the pointer to the fd_quic_log_t. */

static inline fd_frag_meta_t *
fd_quic_log_mcache( fd_quic_log_t * log ) {
  return (fd_frag_meta_t *)( (ulong)log + log->mcache_off );
}

/* fd_quic_log_data{,_const} return a pointer to the data record.  log
   is a local join to a quic_log object.  The chunk value is taken from
   a frag_meta received via the mcache of this quic_log object/ */

FD_FN_CONST static inline void *
fd_quic_log_data( fd_quic_log_t * log,
                  uint            chunk ) {
  return fd_chunk_to_laddr( log, chunk );
}

FD_FN_CONST static inline void const *
fd_quic_log_data_const( fd_quic_log_t const * log,
                        uint                  chunk ) {
  return fd_chunk_to_laddr_const( log, chunk );
}

/* fd_quic_log_sig_event extracts the event ID from the 'sig' field of
   a frag_meta record.  (bits 0..16) */

static inline uint
fd_quic_log_sig_event( ulong sig ) {
  return (uint)( sig & USHORT_MAX );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_log_user_h */
