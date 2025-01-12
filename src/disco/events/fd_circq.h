#ifndef HEADER_fd_src_disco_events_fd_circq_h
#define HEADER_fd_src_disco_events_fd_circq_h

/* The circular buffer is a structure, which stores a queue of messages,
   supporting two operations: push_back and pop_front.  Unlike a regular
   queue, the circular buffer is fixed size and push_back must always
   succeed.

   To ensure push_back always succeeds, the circular buffer will evict
   old messages if necessary to make room for the new one.

   One more complication is that the circular buffer must store
   metadata about the messages in the data buffer itself, as it does not
   have a separate metadata region.  The structure of the buffer then
   looks as follows:

    +-------+-----+------+-----+-------+-----+------+-----+-------+-----+------+
    + meta0 | pad | msg0 | pad | meta1 | pad | msg1 | pad | meta2 | pad | msg2 |
    +-------+-----+------+-----+-------+-----+------+-----+-------+-----+------+
     ^  |                        ^  |                        ^  |
     |  +-----next---------next--+  +------------------------+  |
     |                                                          |
   head                                                        tail

   Here, the meta elements are fd_circq_message_t, which each point to
   the next message in the queue, and head, tail are the head and tail
   of the queue respectively. */

#include "../fd_disco_base.h"

#define FD_CIRCQ_ALIGN (4096UL)

struct __attribute__((aligned(FD_CIRCQ_ALIGN))) fd_circq_private {
  /* Current count of elements in the queue. */
  ulong cnt;

  /* These are offsets relative to the end of this struct of the
     metadata for the first, and last message in the queue,
     respectively. */
  ulong head;
  ulong tail;

  ulong size;

  struct {
    ulong drop_cnt;
  } metrics;

  /* padding out to 4k here ... */
};

typedef struct fd_circq_private fd_circq_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_circq_align( void );

FD_FN_CONST ulong
fd_circq_footprint( ulong sz );

void *
fd_circq_new( void * shmem,
                ulong  sz );

fd_circq_t *
fd_circq_join( void * shbuf );

void *
fd_circq_leave( fd_circq_t * buf );

void *
fd_circq_delete( void * shbuf );

/* fd_circq_push_back appends a message of size sz into the circular
   buffer, evicting any old messages if they would be overwritten when
   the buffer wraps around.  Returns the address of the memory contents
   in the buffer on success, or NULL on failure.  The only two reasons
   for failure are if the requested sz (along with the message metadata)
   exceeds the size of the entire buffer and can't fit, or if the
   requested alignment is not a power of 2, or is larger than 4096. */

uchar *
fd_circq_push_back( fd_circq_t * circq,
                    ulong        align,
                    ulong        footprint );

/* fd_circq_pop_front pops the oldest message from the circular buffer
   and returns the address of the memory contents in the buffer.  The
   memory contents are guaranteed to be valid until the next call to
   fd_circq_push_back.  Returns NULL if there are no messages in the
   circular buffer. */

uchar const *
fd_circq_pop_front( fd_circq_t * circq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_circq_h */
