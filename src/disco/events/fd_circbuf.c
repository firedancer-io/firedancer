#include "fd_circbuf.h"

struct __attribute__((aligned(8UL))) fd_circbuf_message_private {
  ulong align;
  ulong footprint;
  ulong next;
};

typedef struct fd_circbuf_message_private fd_circbuf_message_t;

FD_FN_CONST ulong
fd_circbuf_align( void ) {
  return FD_CIRCBUF_ALIGN;
}

FD_FN_CONST ulong
fd_circbuf_footprint( ulong sz ) {
  return sizeof( fd_circbuf_t ) + sz;
}

void *
fd_circbuf_new( void * shmem,
                ulong  sz ) {
  fd_circbuf_t * circbuf = (fd_circbuf_t *)shmem;
  circbuf->cnt  = 0UL;
  circbuf->head = 0UL;
  circbuf->tail = 0UL;
  circbuf->size = sz;
  return shmem;
}

fd_circbuf_t *
fd_circbuf_join( void * shbuf ) {
  return (fd_circbuf_t *)shbuf;
}

void *
fd_circbuf_leave( fd_circbuf_t * buf ) {
  return (void *)buf;
}

void *
fd_circbuf_delete( void * shbuf ) {
  return shbuf;
}

static inline void
verify( fd_circbuf_t * circbuf ) {
  FD_TEST( circbuf->head<circbuf->size );
  FD_TEST( circbuf->tail<circbuf->size );
  FD_TEST( circbuf->head!=circbuf->tail || circbuf->cnt<=1 );
  if( !circbuf->cnt ) {
    FD_TEST( circbuf->head==0UL );
    FD_TEST( circbuf->tail==0UL );
  } else if( circbuf->cnt==1UL ) {
    FD_TEST( circbuf->head==circbuf->tail );
  }

  uchar * buf = (uchar *)(circbuf+1);

  ulong tail = circbuf->tail;
  int wrapped = 0;
  for( ulong i=0UL; i<circbuf->cnt; i++ ) {
    fd_circbuf_message_t * message = (fd_circbuf_message_t *)(buf+tail);
    ulong start = tail;
    ulong end = fd_ulong_align_up( start+sizeof( fd_circbuf_message_t ), message->align ) + message->footprint;
    if( wrapped ) FD_TEST( end<=circbuf->tail );
    FD_TEST( start<end );
    FD_TEST( end<=circbuf->size );
    tail = message->next;
    if( tail<start ) wrapped = 1;
  }
}

static void
evict( fd_circbuf_t * circbuf,
       ulong          from,
       ulong          to ) {
  uchar * buf = (uchar *)(circbuf+1);

  for(;;) {
    if( FD_UNLIKELY( !circbuf->cnt ) ) return;

    fd_circbuf_message_t * tail = (fd_circbuf_message_t *)(buf+circbuf->tail);

    ulong start = circbuf->tail;
    ulong end = fd_ulong_align_up( start + sizeof( fd_circbuf_message_t ), tail->align ) + tail->footprint;

    if( FD_UNLIKELY( (start<to && end>from) ) ) {
      circbuf->cnt--;
      circbuf->metrics.drop_cnt++;
      if( FD_LIKELY( !circbuf->cnt ) ) circbuf->head = circbuf->tail = 0UL;
      else                             circbuf->tail = tail->next;

      continue;
    }

    break;
  }
}

uchar *
fd_circbuf_push_back( fd_circbuf_t * circbuf,
                      ulong          align,
                      ulong          footprint ) {
  if( FD_UNLIKELY( !fd_ulong_is_pow2( align ) ) ) {
    FD_LOG_WARNING(( "align must be a power of 2" ));
    return NULL;
  }
  if( FD_UNLIKELY( align>FD_CIRCBUF_ALIGN ) ) {
    FD_LOG_WARNING(( "align must be at most %lu", FD_CIRCBUF_ALIGN ));
    return NULL;
  }

  ulong required = fd_ulong_align_up( sizeof( fd_circbuf_message_t ), align ) + footprint;
  if( FD_UNLIKELY( required>circbuf->size ) ) {
    FD_LOG_WARNING(( "tried to push message which was too large %lu>%lu", required, circbuf->size ));
    return NULL;
  }

  uchar * buf = (uchar *)(circbuf+1);

  ulong next = 0UL;
  fd_circbuf_message_t * message = NULL;
  if( FD_LIKELY( circbuf->cnt ) ) {
    message = (fd_circbuf_message_t *)(buf+circbuf->head);
    next = fd_ulong_align_up( fd_ulong_align_up( circbuf->head+sizeof( fd_circbuf_message_t ), message->align )+message->footprint, alignof( fd_circbuf_message_t ) );
  }

  if( FD_UNLIKELY( next+required>circbuf->size ) ) {
    evict( circbuf, next, circbuf->size );
    evict( circbuf, 0UL, required );

    circbuf->head = 0UL;
    if( FD_LIKELY( circbuf->cnt && message ) ) message->next = 0UL;
  } else {
    evict( circbuf, next, next+required );

    circbuf->head = next;
    if( FD_LIKELY( circbuf->cnt && message ) ) message->next = next;
  }

  circbuf->cnt++;
  fd_circbuf_message_t * next_message = (fd_circbuf_message_t *)(buf+circbuf->head);
  next_message->align = align;
  next_message->footprint = footprint;
  return (uchar *)(next_message+1);
}

uchar const *
fd_circbuf_pop_front( fd_circbuf_t * circbuf ) {
  if( FD_UNLIKELY( !circbuf->cnt ) ) return NULL;

  circbuf->cnt--;
  fd_circbuf_message_t * message = (fd_circbuf_message_t *)((uchar *)(circbuf+1)+circbuf->tail);
  if( FD_UNLIKELY( !circbuf->cnt ) ) circbuf->head = circbuf->tail = 0UL;
  else                               circbuf->tail = message->next;
  FD_TEST( circbuf->tail<circbuf->size );
  return (uchar *)(message+1);
}
