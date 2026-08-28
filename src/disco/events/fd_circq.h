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
   of the queue respectively.

   Optionally, a spool file can be attached with fd_circq_spool_init.
   The buffer then becomes a two-tier queue: instead of dropping the
   oldest messages when the in-memory window overflows, they migrate
   (in order) to a file ring accessed only with explicit pread/pwrite,
   and messages are dropped oldest-first only once the file ring is
   also full.  The logical queue order is [spool: oldest][memory:
   newest], and cursor iteration, pop_until, and reset_cursor operate
   transparently across both tiers (spool messages are read back
   through a bounce buffer placed after the data region, so the caller
   must size the backing memory with fd_circq_spool_footprint).  The
   file is only touched when the queue depth exceeds the memory
   window. */

#include "../../util/fd_util_base.h"

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

  ulong cursor;          /* Current offset in buffer for iteration, or ULONG_MAX if at end */
  ulong cursor_seq;      /* Monotonic counter - cursor value for current position */
  ulong cursor_push_seq; /* Monotonic counter - incremented on each push */

  /* Optional explicit-I/O spool tier holding the oldest messages, see
     fd_circq_spool_init.  Records are { ulong sz; ulong seq; } headers
     followed by the message bytes, appended into a file ring; a header
     sz of ULONG_MAX marks an end-of-ring wrap. */
  int   spool_fd;         /* -1 if no spool attached */
  ulong spool_cap;        /* file ring capacity in bytes */
  ulong spool_max_msg;    /* larger messages cannot migrate; also the bounce buffer size */
  ulong spool_head;       /* file offset of the oldest record */
  ulong spool_tail;       /* file offset where the next record is appended */
  ulong spool_cnt;        /* messages in the spool tier */
  ulong spool_bytes;      /* bytes of live records in the spool tier */
  int   cursor_spool;     /* cursor is iterating spool records (cursor==ULONG_MAX) */
  int   cursor_ram_entry; /* next advance starts at the memory head, cursor_seq already seeded (cursor==ULONG_MAX) */
  ulong spool_cursor;     /* file offset of the next spool record to return */

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

/* fd_circq_spool_footprint gives the required backing memory for a
   circq of in-memory window sz that will have a spool attached with
   max message size max_msg (the extra max_msg bytes are the bounce
   buffer spool reads return through). */

FD_FN_CONST ulong
fd_circq_spool_footprint( ulong sz,
                          ulong max_msg );

void *
fd_circq_new( void * shmem,
              ulong  sz );

/* fd_circq_spool_init attaches a spool file to the circq.  fd is an
   open file descriptor to a (typically unlinked) file of at least cap
   bytes, owned by the caller; cap is the file ring capacity; max_msg
   must be at least the largest footprint ever passed to push_back.
   The backing memory must have been sized with
   fd_circq_spool_footprint, and sz must be a multiple of
   FD_CIRCQ_ALIGN.  Must be called before any messages are pushed. */

void
fd_circq_spool_init( fd_circq_t * circq,
                     int          fd,
                     ulong        cap,
                     ulong        max_msg );

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

void
fd_circq_resize_back( fd_circq_t * circq,
                      ulong        new_footprint );

/* fd_circq_cursor_advance moves an internal cursor forward to the next
   message in the circular buffer, returning the message at the previous
   cursor position, or NULL if there are no more messages.

   Moving the cursor does not remove the message from the circular
   buffer, which only happens when fd_circq_pop_until is called. */

uchar const *
fd_circq_cursor_advance( fd_circq_t * circq,
                         ulong *      msg_sz );

/* fd_circq_pop_until removes messages from the front of the circular
   buffer up to and including the message with the given cursor value.
   Returns 0 on success, or -1 if the given cursor value is invalid
   (i.e., larger than highest cursor value returned by cursor_advance). */

int
fd_circq_pop_until( fd_circq_t * circq,
                    ulong        cursor );

/* fd_circq_reset_cursor resets the internal cursor to the front of the
   circular buffer.  This is useful if you want to re-process all
   messages in the buffer from the start. */

void
fd_circq_reset_cursor( fd_circq_t * circq );

/* fd_circq_bytes_used returns the total number of bytes currently used
   in the circular buffer, including message metadata and padding. */

ulong
fd_circq_bytes_used( fd_circq_t const * circq );

/* fd_circq_unsent_cnt returns the number of messages in the queue that
   the cursor has not yet advanced past, i.e. messages still waiting to
   be sent.  The remaining messages (cnt - unsent) have been sent and are
   awaiting acknowledgement before they are popped. */

ulong
fd_circq_unsent_cnt( fd_circq_t const * circq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_circq_h */
