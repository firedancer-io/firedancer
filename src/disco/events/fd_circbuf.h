#ifndef HEADER_fd_src_disco_events_fd_circbuf_h
#define HEADER_fd_src_disco_events_fd_circbuf_h

#include "../fd_disco_base.h"

#define FD_CIRCBUF_ALIGN (4096UL)

struct __attribute__((aligned(FD_CIRCBUF_ALIGN))) fd_circbuf_private {
  ulong cnt;
  ulong head;
  ulong tail;
  ulong size;

  struct {
    ulong drop_cnt;
  } metrics;
};

typedef struct fd_circbuf_private fd_circbuf_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_circbuf_align( void );

FD_FN_CONST ulong
fd_circbuf_footprint( ulong sz );

void *
fd_circbuf_new( void * shmem,
                ulong  sz );

fd_circbuf_t *
fd_circbuf_join( void * shbuf );

void *
fd_circbuf_leave( fd_circbuf_t * buf );

void *
fd_circbuf_delete( void * shbuf );

/* fd_circbuf_push_back appends a message of size sz into the circular
   buffer, evicting any old messages if they would be overwritten when
   the buffer wraps around.  Returns the address of the memory contents
   in the buffer on success, or NULL on failure.  The only reason for
   failure is if the requested sz (along with the message metadata)
   exceeds the size of the entire buffer and can't fit. */

uchar *
fd_circbuf_push_back( fd_circbuf_t * circbuf,
                      ulong          align,
                      ulong          footprint );

/* fd_circbuf_pop_front pops the oldest message from the circular buffer
   and returns the address of the memory contents in the buffer.  The
   memory contents are guaranteed to be valid until the next call to
   fd_circbuf_push_back.  Returns NULL if there are no messages in the
   circular buffer. */

uchar const *
fd_circbuf_pop_front( fd_circbuf_t * circbuf );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_circbuf_h */
