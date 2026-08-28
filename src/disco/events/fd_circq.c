#include "fd_circq.h"

#include "../../util/log/fd_log.h"
#include "../../util/io/fd_io.h"

#include <errno.h>
#include <unistd.h>

struct __attribute__((aligned(8UL))) fd_circq_message_private {
  ulong align;
  ulong footprint;

  /* Offset withn the circular buffer data region of where the next
     message starts, if there is one.  This is not always the same as
     aligning up this message + footprint, because the next message may
     have wrapped around to the start of the buffer. */
  ulong next;
};

typedef struct fd_circq_message_private fd_circq_message_t;

FD_FN_CONST ulong
fd_circq_align( void ) {
  return FD_CIRCQ_ALIGN;
}

FD_FN_CONST ulong
fd_circq_footprint( ulong sz ) {
  return sizeof( fd_circq_t ) + sz;
}

FD_FN_CONST ulong
fd_circq_spool_footprint( ulong sz,
                          ulong max_msg ) {
  return sizeof( fd_circq_t ) + sz + max_msg;
}

void *
fd_circq_new( void * shmem,
              ulong  sz ) {
  fd_circq_t * circq = (fd_circq_t *)shmem;
  circq->cnt  = 0UL;
  circq->head = 0UL;
  circq->tail = 0UL;
  circq->size = sz;
  circq->cursor = ULONG_MAX;
  circq->cursor_seq = 0UL;
  circq->cursor_push_seq = 0UL;

  circq->spool_fd         = -1;
  circq->spool_cap        = 0UL;
  circq->spool_max_msg    = 0UL;
  circq->spool_head       = 0UL;
  circq->spool_tail       = 0UL;
  circq->spool_cnt        = 0UL;
  circq->spool_bytes      = 0UL;
  circq->cursor_spool     = 0;
  circq->cursor_ram_entry = 0;
  circq->spool_cursor     = 0UL;

  memset( &circq->metrics, 0, sizeof( circq->metrics ) );

  return shmem;
}

#define SPOOL_HDR_SZ (16UL)

static inline ulong
spool_rec_sz( ulong sz ) {
  return SPOOL_HDR_SZ+fd_ulong_align_up( sz, 8UL );
}

void
fd_circq_spool_init( fd_circq_t * circq,
                     int          fd,
                     ulong        cap,
                     ulong        max_msg ) {
  FD_TEST( fd>=0 );
  FD_TEST( !circq->cnt && !circq->cursor_push_seq );
  FD_TEST( fd_ulong_is_aligned( circq->size, FD_CIRCQ_ALIGN ) ); /* keeps the bounce buffer at buf+size well aligned */
  FD_TEST( cap>=2UL*spool_rec_sz( max_msg ) );
  circq->spool_fd      = fd;
  circq->spool_cap     = cap;
  circq->spool_max_msg = max_msg;
}

fd_circq_t *
fd_circq_join( void * shbuf ) {
  return (fd_circq_t *)shbuf;
}

void *
fd_circq_leave( fd_circq_t * buf ) {
  return (void *)buf;
}

void *
fd_circq_delete( void * shbuf ) {
  return shbuf;
}

static inline void FD_FN_UNUSED
verify( fd_circq_t * circq ) {
  FD_TEST( circq->head<circq->size );
  FD_TEST( circq->tail<circq->size );
  FD_TEST( circq->tail!=circq->head || circq->cnt<=1 );
  if( !circq->cnt ) {
    FD_TEST( circq->head==0UL );
    FD_TEST( circq->tail==0UL );
  } else if( circq->cnt==1UL ) {
    FD_TEST( circq->head==circq->tail );
  }

  uchar * buf = (uchar *)(circq+1);

  ulong current = circq->head;
  int wrapped = 0;
  for( ulong i=0UL; i<circq->cnt; i++ ) {
    fd_circq_message_t * message = (fd_circq_message_t *)(buf+current);
    ulong start = current;
    ulong end = fd_ulong_align_up( start+sizeof( fd_circq_message_t ), message->align ) + message->footprint;
    if( wrapped ) FD_TEST( end<=circq->head );
    FD_TEST( start<end );
    FD_TEST( end<=circq->size );
    current = message->next;
    if( current<start ) wrapped = 1;
  }
}

static inline void
cursor_reset( fd_circq_t * circq ) {
  circq->cursor           = ULONG_MAX;
  circq->cursor_spool     = 0;
  circq->cursor_ram_entry = 0;
}

static inline int
cursor_active( fd_circq_t const * circq ) {
  return circq->cursor!=ULONG_MAX || circq->cursor_spool || circq->cursor_ram_entry;
}

/* Recover from eviction logic removing elements at the cursor */

static inline void
overrun_recover( fd_circq_t * circq ) {
  if( FD_UNLIKELY( !cursor_active( circq ) ) ) return;

  ulong oldest_seq = circq->cursor_push_seq - circq->cnt - circq->spool_cnt;
  if( FD_UNLIKELY( circq->cursor_seq<=oldest_seq ) ) cursor_reset( circq );
}

/* spool_resolve reads the record header at off, following the
   end-of-ring wrap and any wrap marker.  Returns the resolved record
   offset and fills sz/seq. */

static ulong
spool_resolve( fd_circq_t const * circq,
               ulong              off,
               ulong *            sz,
               ulong *            seq ) {
  int wrapped = 0;
  for(;;) {
    if( FD_UNLIKELY( off+SPOOL_HDR_SZ>circq->spool_cap ) ) {
      FD_TEST( !wrapped );
      wrapped = 1;
      off = 0UL;
      continue;
    }
    ulong hdr[ 2 ];
    if( FD_UNLIKELY( (long)SPOOL_HDR_SZ!=pread( circq->spool_fd, hdr, SPOOL_HDR_SZ, (off_t)off ) ) )
      FD_LOG_ERR(( "pread(circq spool) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( hdr[ 0 ]==ULONG_MAX ) ) { /* wrap marker */
      FD_TEST( !wrapped );
      wrapped = 1;
      off = 0UL;
      continue;
    }
    FD_TEST( hdr[ 0 ]<=circq->spool_max_msg );
    *sz  = hdr[ 0 ];
    *seq = hdr[ 1 ];
    return off;
  }
}

static void
spool_pop_head( fd_circq_t * circq,
                int          dropped ) {
  ulong sz, seq;
  ulong off = spool_resolve( circq, circq->spool_head, &sz, &seq );
  FD_TEST( seq==circq->cursor_push_seq-circq->cnt-circq->spool_cnt );
  circq->spool_cnt--;
  circq->spool_bytes -= spool_rec_sz( sz );
  if( FD_UNLIKELY( !circq->spool_cnt ) ) { circq->spool_head = 0UL; circq->spool_tail = 0UL; }
  else                                     circq->spool_head = off+spool_rec_sz( sz );
  if( FD_UNLIKELY( dropped ) ) {
    circq->metrics.drop_cnt++;
    overrun_recover( circq );
  }
}

static void
spool_evict( fd_circq_t * circq,
             ulong        from,
             ulong        to ) {
  while( circq->spool_cnt ) {
    ulong sz, seq;
    ulong start = spool_resolve( circq, circq->spool_head, &sz, &seq );
    ulong end   = start+spool_rec_sz( sz );
    if( FD_UNLIKELY( start<to && end>from ) ) spool_pop_head( circq, 1 );
    else break;
  }
}

/* spool_migrate_front moves the front in-memory message into the spool
   file, evicting the spool's own oldest records if the file ring is
   full (those are true drops).  Called by evict() when the memory
   window needs space and a spool is attached. */

static void
spool_migrate_front( fd_circq_t * circq ) {
  uchar * buf = (uchar *)(circq+1);
  fd_circq_message_t * head = (fd_circq_message_t *)(buf+circq->head);
  ulong sz  = head->footprint;
  ulong seq = circq->cursor_push_seq-circq->cnt; /* seq of the front in-memory message */
  FD_TEST( sz<=circq->spool_max_msg );

  ulong rec = spool_rec_sz( sz );
  ulong pos = circq->spool_tail;
  if( FD_UNLIKELY( pos+rec>circq->spool_cap ) ) {
    spool_evict( circq, pos, circq->spool_cap );
    spool_evict( circq, 0UL, rec );
    if( FD_LIKELY( pos+SPOOL_HDR_SZ<=circq->spool_cap ) ) {
      ulong marker[ 2 ] = { ULONG_MAX, 0UL };
      if( FD_UNLIKELY( (long)SPOOL_HDR_SZ!=pwrite( circq->spool_fd, marker, SPOOL_HDR_SZ, (off_t)pos ) ) )
        FD_LOG_ERR(( "pwrite(circq spool) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    pos = 0UL;
  } else {
    spool_evict( circq, pos, pos+rec );
  }

  ulong hdr[ 2 ] = { sz, seq };
  if( FD_UNLIKELY( (long)SPOOL_HDR_SZ!=pwrite( circq->spool_fd, hdr, SPOOL_HDR_SZ, (off_t)pos ) ) )
    FD_LOG_ERR(( "pwrite(circq spool) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (long)sz!=pwrite( circq->spool_fd, (uchar const *)(head+1), sz, (off_t)(pos+SPOOL_HDR_SZ) ) ) )
    FD_LOG_ERR(( "pwrite(circq spool) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  circq->spool_tail   = pos+rec;
  circq->spool_cnt++;
  circq->spool_bytes += rec;

  /* Remove from memory (not a drop; the message lives on in the
     spool). */
  circq->cnt--;
  if( FD_UNLIKELY( !circq->cnt ) ) { circq->head = 0UL; circq->tail = 0UL; }
  else                              circq->head = head->next;

  /* An offset-based memory cursor at or before the migrated message is
     no longer valid; restart iteration from the queue front (harmless
     resend of unacked messages).  A pending ram-entry cursor only
     breaks if the pending message itself migrated.  A spool cursor is
     unaffected: appends never move live spool records. */
  if(      FD_UNLIKELY( circq->cursor!=ULONG_MAX    && circq->cursor_seq<=seq+1UL ) ) cursor_reset( circq );
  else if( FD_UNLIKELY( circq->cursor_ram_entry     && circq->cursor_seq<=seq     ) ) cursor_reset( circq );
}

static void
evict( fd_circq_t * circq,
       ulong        from,
       ulong        to ) {
  uchar * buf = (uchar *)(circq+1);

  for(;;) {
    if( FD_UNLIKELY( !circq->cnt ) ) return;

    fd_circq_message_t * head = (fd_circq_message_t *)(buf+circq->head);

    ulong start = circq->head;
    ulong end = fd_ulong_align_up( start + sizeof( fd_circq_message_t ), head->align ) + head->footprint;

    if( FD_UNLIKELY( (start<to && end>from) ) ) {
      if( FD_LIKELY( circq->spool_fd>=0 ) ) {
        spool_migrate_front( circq );
      } else {
        circq->cnt--;
        circq->metrics.drop_cnt++;
        if( FD_LIKELY( !circq->cnt ) ) circq->head = circq->tail = 0UL;
        else                           circq->head = head->next;
        overrun_recover( circq );
      }
    } else {
      break;
    }
  }
}

uchar *
fd_circq_push_back( fd_circq_t * circq,
                    ulong        align,
                    ulong        footprint ) {
  if( FD_UNLIKELY( !fd_ulong_is_pow2( align ) ) ) {
    FD_LOG_WARNING(( "align must be a power of 2" ));
    return NULL;
  }
  if( FD_UNLIKELY( align>FD_CIRCQ_ALIGN ) ) {
    FD_LOG_WARNING(( "align must be at most %lu", FD_CIRCQ_ALIGN ));
    return NULL;
  }

  ulong required = fd_ulong_align_up( sizeof( fd_circq_message_t ), align ) + footprint;
  if( FD_UNLIKELY( required>circq->size ) ) {
    FD_LOG_WARNING(( "tried to push message which was too large %lu>%lu", required, circq->size ));
    return NULL;
  }

  uchar * buf = (uchar *)(circq+1);

  ulong current = 0UL;
  fd_circq_message_t * message = NULL;
  if( FD_LIKELY( circq->cnt ) ) {
    message = (fd_circq_message_t *)(buf+circq->tail);
    current = fd_ulong_align_up( fd_ulong_align_up( circq->tail+sizeof( fd_circq_message_t ), message->align )+message->footprint, alignof( fd_circq_message_t ) );
  }

  if( FD_UNLIKELY( current+required>circq->size ) ) {
    evict( circq, current, circq->size );
    evict( circq, 0UL, required );

    circq->tail = 0UL;
    if( FD_LIKELY( circq->cnt && message ) ) message->next = 0UL;
  } else {
    evict( circq, current, current+required );

    circq->tail = current;
    if( FD_LIKELY( circq->cnt && message ) ) message->next = current;
  }

  circq->cnt++;
  fd_circq_message_t * next_message = (fd_circq_message_t *)(buf+circq->tail);
  next_message->align = align;
  next_message->footprint = footprint;
  next_message->next = ULONG_MAX;
  circq->cursor_push_seq++;
  return (uchar *)(next_message+1);
}

void
fd_circq_resize_back( fd_circq_t * circq,
                      ulong        new_footprint ) {
  FD_TEST( circq->cnt );

  uchar * buf = (uchar *)(circq+1);
  fd_circq_message_t * message = (fd_circq_message_t *)(buf+circq->tail);
  FD_TEST( new_footprint<=message->footprint );

  message->footprint = new_footprint;
}

uchar const *
fd_circq_cursor_advance( fd_circq_t * circq,
                         ulong *      msg_sz ) {
  uchar * buf = (uchar *)(circq+1);

start:
  if( FD_UNLIKELY( circq->cursor_spool ) ) {
    if( FD_LIKELY( circq->cursor_seq<circq->cursor_push_seq-circq->cnt ) ) {
      ulong sz, seq;
      ulong off = spool_resolve( circq, circq->spool_cursor, &sz, &seq );
      FD_TEST( seq==circq->cursor_seq );
      uchar * bounce = buf+circq->size;
      if( FD_UNLIKELY( (long)sz!=pread( circq->spool_fd, bounce, sz, (off_t)(off+SPOOL_HDR_SZ) ) ) )
        FD_LOG_ERR(( "pread(circq spool) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      circq->spool_cursor = off+spool_rec_sz( sz );
      circq->cursor_seq++;
      if( FD_LIKELY( msg_sz ) ) *msg_sz = sz;
      return bounce;
    }
    /* Crossed from the spool tier into the memory tier */
    circq->cursor_spool     = 0;
    circq->cursor_ram_entry = 1;
  }

  if( FD_UNLIKELY( circq->cursor_ram_entry ) ) {
    if( FD_UNLIKELY( circq->cursor_seq>=circq->cursor_push_seq ) ) return NULL;
    circq->cursor_ram_entry = 0;
    circq->cursor           = circq->head;
  } else if( FD_UNLIKELY( circq->cursor==ULONG_MAX ) ) {
    /* First call or after reset - start from the queue front */
    ulong total_cnt = circq->cnt+circq->spool_cnt;
    if( FD_UNLIKELY( !total_cnt ) ) return NULL;
    circq->cursor_seq = circq->cursor_push_seq - total_cnt;
    if( FD_UNLIKELY( circq->spool_cnt ) ) {
      circq->cursor_spool = 1;
      circq->spool_cursor = circq->spool_head;
      goto start;
    }
    circq->cursor = circq->head;
  } else {
    /* Already iterating - move to next */
    if( FD_UNLIKELY( circq->cursor_seq >= circq->cursor_push_seq ) ) return NULL;

    fd_circq_message_t * message = (fd_circq_message_t *)(buf+circq->cursor);
    circq->cursor = message->next;
  }

  fd_circq_message_t * current_msg = (fd_circq_message_t *)(buf+circq->cursor);
  circq->cursor_seq++;
  if( FD_LIKELY( msg_sz ) ) *msg_sz = current_msg->footprint;
  return (uchar *)(current_msg+1);
}

int
fd_circq_pop_until( fd_circq_t * circq,
                    ulong        cursor ) {
  if( FD_UNLIKELY( cursor>=circq->cursor_seq ) ) return -1;

  ulong oldest_seq = circq->cursor_push_seq-circq->cnt-circq->spool_cnt;
  if( FD_UNLIKELY( cursor<oldest_seq ) ) return 0;

  ulong to_pop = fd_ulong_min( cursor-oldest_seq+1UL, circq->cnt+circq->spool_cnt );

  while( to_pop && circq->spool_cnt ) {
    spool_pop_head( circq, 0 );
    to_pop--;
  }

  uchar * buf = (uchar *)(circq+1);
  for( ulong i=0UL; i<to_pop; i++ ) {
    fd_circq_message_t * message = (fd_circq_message_t *)(buf+circq->head);
    circq->cnt--;

    if( FD_UNLIKELY( !circq->cnt ) ) {
      circq->head = circq->tail = 0UL;
    } else {
      circq->head = message->next;
      FD_TEST( circq->head<circq->size );
    }
  }

  if( FD_UNLIKELY( !circq->cnt && !circq->spool_cnt ) ) cursor_reset( circq );
  overrun_recover( circq );
  return 0;
}

void
fd_circq_reset_cursor( fd_circq_t * circq ) {
  cursor_reset( circq );
}

ulong
fd_circq_bytes_used( fd_circq_t const * circq ) {
  if( FD_UNLIKELY( !circq->cnt ) ) return circq->spool_bytes;

  uchar const * buf = (uchar const *)(circq+1);

  fd_circq_message_t const * tail_msg = (fd_circq_message_t const *)(buf+circq->tail);
  ulong tail_end = fd_ulong_align_up( circq->tail + sizeof(fd_circq_message_t), tail_msg->align ) + tail_msg->footprint;

  if( FD_LIKELY( circq->tail>=circq->head ) ) return tail_end - circq->head + circq->spool_bytes;
  else return (circq->size - circq->head) + tail_end + circq->spool_bytes;
}

ulong
fd_circq_unsent_cnt( fd_circq_t const * circq ) {
  ulong total_cnt = circq->cnt+circq->spool_cnt;
  if( FD_UNLIKELY( !cursor_active( circq ) ) ) return total_cnt;
  return fd_ulong_min( circq->cursor_push_seq - circq->cursor_seq, total_cnt );
}
