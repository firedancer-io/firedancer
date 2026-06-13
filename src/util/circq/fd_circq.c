#include "fd_circq.h"

#include "../log/fd_log.h"

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

/* msg_payload returns a message->align-aligned pointer to the payload
   bytes of message. */

static inline uchar *
msg_payload( fd_circq_t *         circq,
             ulong                off,
             fd_circq_message_t * message ) {
  uchar * buf = (uchar *)(circq+1);
  return buf + fd_ulong_align_up( off+sizeof( fd_circq_message_t ), message->align );
}

FD_FN_CONST ulong
fd_circq_align( void ) {
  return FD_CIRCQ_ALIGN;
}

FD_FN_CONST ulong
fd_circq_footprint( ulong sz ) {
  return sizeof( fd_circq_t ) + sz;
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
  circq->batch_evict_cb = NULL;
  circq->batch_evict_ctx = NULL;

  memset( &circq->metrics, 0, sizeof( circq->metrics ) );

  return shmem;
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

/* Recover from eviction logic removing elements at the cursor */

static inline void
overrun_recover( fd_circq_t * circq ) {
  if( FD_UNLIKELY( circq->cursor==ULONG_MAX ) ) return;

  ulong oldest_seq = circq->cursor_push_seq - circq->cnt;
  if( FD_UNLIKELY( circq->cursor_seq<=oldest_seq ) ) circq->cursor = ULONG_MAX;
}

/* evict_one_unrecorded drops the current head message, performing all the
   per-message bookkeeping. */

static void
evict_one_unrecorded( fd_circq_t * circq ) {
  uchar * buf = (uchar *)(circq+1);

  fd_circq_message_t * head = (fd_circq_message_t *)(buf+circq->head);

  circq->cnt--;
  circq->metrics.drop_cnt++;
  if( FD_LIKELY( !circq->cnt ) ) circq->head = circq->tail = 0UL;
  else                           circq->head = head->next;
  overrun_recover( circq );
}

static void
evict( fd_circq_t * circq,
       ulong        from,
       ulong        to ) {
  uchar * buf = (uchar *)(circq+1);

  fd_circq_evict_entry_t pending[ FD_CIRCQ_EVICT_BATCH_MAX ];
  ulong                  pending_cnt = 0UL;
  int                    have_cb     = !!circq->batch_evict_cb;

  for(;;) {
    if( FD_UNLIKELY( !circq->cnt ) ) break;

    fd_circq_message_t * head = (fd_circq_message_t *)(buf+circq->head);

    ulong start = circq->head;
    ulong end = fd_ulong_align_up( start + sizeof( fd_circq_message_t ), head->align ) + head->footprint;

    if( FD_LIKELY( !(start<to && end>from) ) ) break;

    /* Flush a full batch before overflow. */
    if( FD_UNLIKELY( have_cb ) ) {
      if( FD_UNLIKELY( pending_cnt==FD_CIRCQ_EVICT_BATCH_MAX ) ) {
        circq->batch_evict_cb( circq->batch_evict_ctx, pending, pending_cnt );
        pending_cnt = 0UL;
      }
      pending[ pending_cnt ].payload = msg_payload( circq, circq->head, head );
      pending[ pending_cnt ].sz      = head->footprint;
      pending_cnt++;
    }

    evict_one_unrecorded( circq );
  }

  if( FD_UNLIKELY( have_cb && pending_cnt ) ) {
    circq->batch_evict_cb( circq->batch_evict_ctx, pending, pending_cnt );
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

  /* The end offset of a message placed at current */
  ulong current_end = fd_ulong_align_up( current + sizeof( fd_circq_message_t ), align ) + footprint;

  if( FD_UNLIKELY( current_end>circq->size ) ) {
    evict( circq, current, circq->size );
    evict( circq, 0UL, required );

    circq->tail = 0UL;
    if( FD_LIKELY( circq->cnt && message ) ) message->next = 0UL;
  } else {
    evict( circq, current, current_end );

    circq->tail = current;
    if( FD_LIKELY( circq->cnt && message ) ) message->next = current;
  }

  circq->cnt++;
  fd_circq_message_t * next_message = (fd_circq_message_t *)(buf+circq->tail);
  next_message->align = align;
  next_message->footprint = footprint;
  next_message->next = ULONG_MAX;
  circq->cursor_push_seq++;
  return msg_payload( circq, circq->tail, next_message );
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
  /* First call or after reset - start from head */
  if( FD_UNLIKELY( circq->cursor==ULONG_MAX ) ) {
    if( FD_UNLIKELY( !circq->cnt ) ) return NULL;
    circq->cursor = circq->head;
    circq->cursor_seq = circq->cursor_push_seq - circq->cnt;
  } else {
    /* Already iterating - move to next */
    if( FD_UNLIKELY( circq->cursor_seq >= circq->cursor_push_seq ) ) return NULL;

    uchar * buf = (uchar *)(circq+1);
    fd_circq_message_t * message = (fd_circq_message_t *)(buf+circq->cursor);
    circq->cursor = message->next;
  }

  uchar * buf = (uchar *)(circq+1);
  fd_circq_message_t * current_msg = (fd_circq_message_t *)(buf+circq->cursor);
  circq->cursor_seq++;
  if( FD_LIKELY( msg_sz ) ) *msg_sz = current_msg->footprint;
  return msg_payload( circq, circq->cursor, current_msg );
}

int
fd_circq_pop_until( fd_circq_t * circq,
                    ulong        cursor ) {
  if( FD_UNLIKELY( cursor>=circq->cursor_seq ) ) return -1;

  ulong oldest_seq = circq->cursor_push_seq-circq->cnt;
  if( FD_UNLIKELY( cursor<oldest_seq ) ) return 0;

  ulong to_pop = fd_ulong_min( cursor-oldest_seq+1UL, circq->cnt );

  /* Pop oldest-first, gathering the dropped payloads into batches
     delivered to the eviction callback (if registered).  As in evict(),
     a batch is flushed when it fills (FD_CIRCQ_EVICT_BATCH_MAX) and at
     each buffer wrap, so a batch never straddles the wrap. */

  uchar * buf = (uchar *)(circq+1);

  fd_circq_evict_entry_t pending[ FD_CIRCQ_EVICT_BATCH_MAX ];
  ulong                  pending_cnt = 0UL;
  int                    have_cb     = !!circq->batch_evict_cb;

  for( ulong i=0UL; i<to_pop; i++ ) {
    fd_circq_message_t * message = (fd_circq_message_t *)(buf+circq->head);
    ulong next  = message->next;
    int   wraps = next<circq->head; /* head about to wrap to a lower offset */

    if( FD_UNLIKELY( have_cb ) ) {
      if( FD_UNLIKELY( pending_cnt==FD_CIRCQ_EVICT_BATCH_MAX ) ) {
        circq->batch_evict_cb( circq->batch_evict_ctx, pending, pending_cnt );
        pending_cnt = 0UL;
      }
      pending[ pending_cnt ].payload = msg_payload( circq, circq->head, message );
      pending[ pending_cnt ].sz      = message->footprint;
      pending_cnt++;
    }

    circq->cnt--;

    if( FD_UNLIKELY( !circq->cnt ) ) {
      circq->head = circq->tail = 0UL;
    } else {
      circq->head = next;
      FD_TEST( circq->head<circq->size );
    }

    /* Flush before crossing the wrap so a batch stays contiguous. */
    if( FD_UNLIKELY( have_cb && wraps && pending_cnt ) ) {
      circq->batch_evict_cb( circq->batch_evict_ctx, pending, pending_cnt );
      pending_cnt = 0UL;
    }
  }

  if( FD_UNLIKELY( have_cb && pending_cnt ) ) {
    circq->batch_evict_cb( circq->batch_evict_ctx, pending, pending_cnt );
  }

  if( FD_UNLIKELY( !circq->cnt ) ) circq->cursor = ULONG_MAX;
  overrun_recover( circq );
  return 0;
}

void
fd_circq_reset_cursor( fd_circq_t * circq ) {
  circq->cursor = ULONG_MAX;
}

ulong
fd_circq_cursor( fd_circq_t const * circq ) {
  return circq->cursor_seq;
}

ulong
fd_circq_bytes_used( fd_circq_t const * circq ) {
  if( FD_UNLIKELY( !circq->cnt ) ) return 0UL;

  uchar const * buf = (uchar const *)(circq+1);

  fd_circq_message_t const * tail_msg = (fd_circq_message_t const *)(buf+circq->tail);
  ulong tail_end = fd_ulong_align_up( circq->tail + sizeof(fd_circq_message_t), tail_msg->align ) + tail_msg->footprint;

  if( FD_LIKELY( circq->tail>=circq->head ) ) return tail_end - circq->head;
  else return (circq->size - circq->head) + tail_end;
}

ulong
fd_circq_unsent_cnt( fd_circq_t const * circq ) {
  if( FD_UNLIKELY( circq->cursor==ULONG_MAX ) ) return circq->cnt;
  return fd_ulong_min( circq->cursor_push_seq - circq->cursor_seq, circq->cnt );
}

void
fd_circq_set_batch_evict_cb( fd_circq_t *              circq,
                             fd_circq_batch_evict_cb_t cb,
                             void *                    ctx ) {
  circq->batch_evict_cb  = cb;
  circq->batch_evict_ctx = ctx;
}
