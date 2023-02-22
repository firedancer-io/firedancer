#ifndef HEADER_fd_src_util_alloc_fd_alloc_h
#define HEADER_fd_src_util_alloc_fd_alloc_h

/* fd_alloc is a high performance lockfree fast O(1) (typically)
   allocator.

   It is optimized for high concurrency use and small-ish clustered /
   multi-modal distributed allocation sizes.  It is further optimized
   for single-threaded use cases and/or when malloc-free pairs have have
   good thread affinity (i.e. frees done by the same thread that did the
   corresponding malloc).  It behaves well with irregular sizes and
   exploits ultra fine grained alignment for good packing (e.g.
   reasonable low memory overhead packing of byte strings with irregular
   small-ish sizes).

   It is less optimized for pipelined (e.g. malloc in one thread, free
   in another) and more aggressive threading use cases but it could be
   tuned to be so.

   A fd_alloc stores its state in a wksp in a persistent way and backs
   its allocations by that same wksp.  This avoids many of the severe
   performance and reliability issues of malloc

   Critically, it _doesn't_ _lie_ and it _doesn't_ _blow_ _up_.

   fd_alloc_malloc will not stall your program behind your back, calling
   the OS to grow or shrink the program's memory footprint during the
   call; it will never use more memory than has already be procured for
   the underlying wksp.  And, if fd_alloc_malloc succeeds, the returned
   memory is real and is ready for use.

   Obligatory dynamic allocation rant *********************************

   That is, fd_alloc is not the absolute unforgivable garbage of
   Linux/libc malloc.  malloc often just reserves page table entries and
   returns, irrespective of whether or not the request can be satisfied
   (on the apparent belief that the malloc call was a bluff and the user
   is probably a bad dev who doesn't bother with error trapping anyway),
   in hopes that that a later glacially slow page fault to the OS will
   actually reserve the memory.

   Which, even when it does work, it will by its very nature will be at
   the worst possible times (e.g. in the middle of incoming line rate
   network traffic bursts ... data structures try to grow to accommodate
   but slowing down throughput faster than they are growing at a time
   when keeping up is critical to surviving ... and then on a
   ridiculously awful normal page by normal page basis), exposing the
   caller to non-deterministic performance and reduced throughput.

   Unfortunately, getting overrun by DoS-like traffic patterns is the
   least of the worries.  When Linux can't back one of the page by DRAM
   on a page fault (skipping over some additional TLB and NUMA
   dubiousness that goes on under the hood), it goes from glacial
   performance to continental drift levels of performance.  It will try
   to honor the request by shuffling things to swap, exacerbating the
   above.  Suddenly it is a feat to even keep up with a 1980s modem.

   But that's not the end of the horror.  Because Linux thinks it cool
   to overcommit beyond physical limits for no discernable reason and
   gets flaky if you try to disable swap and/or overcommit, the page
   fault might not be able honor the committment.  Finding itself caught
   in a lie (it can't go back in time and rescind the success that
   malloc already returned to the unsuspecting developer), the Linux
   kernel goes full HAL-9000 and starts randomly killing things.  A dead
   process can't complain about malloc lying to it after all.  And,
   cherry on top, the victims of the oom killer are frequently not even
   the culprits.

   Sigh ... all completely unacceptable behaviors in any situation, much
   less mission critical ones.

   TL;DR Friends don't let friends malloc.

   If you truly need malloc-free semantics, use fd_alloc.  This at least
   eliminates the most egregious horrors above.  It can't help the
   intrinsic horrors though.

   (Though it is ingrained in CS teaching and languages to the extent
   there's rarely even recognition of the faintest possibility of the
   existence of alternatives, people rarely truly need malloc/free
   semantics.  But, after they convince themselves they still do because
   of the brainwashing, they need to remind themselves that computers
   don't work remotely like malloc/free suggest and then should try to
   think about resource acquisition more fundamentally.  And, after they
   still manage to talk themselves back into needing it because of the
   teaching and linguistic traps, repeat ... at least if they want to
   make something fast and robust.  Even if they can prove dynamic
   allocation requests have an attainable worst level at all points in
   time, they still have to prove that heap fragmentation over time will
   never cause malloc to fail.  Good luck with that.)

   The above rant applies to any paired dynamic memory strategies,
   including non-placement new, implicit copy constructors, dynamic
   resizing containers, etc.  Real world computers aren't just funky
   implementations of infinite tape Turing machines.  This make-believe
   that they are in code that interacts with the real world is a recipe
   for real world disaster.

   End of obligatory dynamic allocation rant **************************

   Since it is backed by a wksp, allocations have the same NUMA, TLB,
   IPC and persistence properties of the underlying wksp.  This allows
   fd_alloc to go far beyond the capabilities of a typical allocator
   Allocations done by fd_alloc can be shared between processes (can
   even malloc in one process, translate the pointer into the address
   space of another process, and free it there, even after the first
   process has terminated), a process can be stopped and then other
   processes can still find the stopped processes's allocations and use
   them / free them / etc.

   Regarding time efficiency and concurrency, large allocations are
   passed through to the underlying wksp allocator (which is neither
   O(1) and only "quasi"-lockfree in the sense described in fd_wksp.h).
   But the allocation strategies used under the hood (loosely inspired
   by Hoard-style lockfree allocators but with a lot of optimizations
   and tweaks for the above) are such that, in the common case of not
   needing to fall back to the underlying wksp allocator, the allocator
   is lockfree O(1).

   Regarding spatial efficiency, it is reasonbly space efficient
   (overhead for a cstr-style allocation is ~4 bytes) and adapts over
   time to try to bound the amount of pre-allocation for small requests. */

#include "../wksp/fd_wksp.h"

#if FD_HAS_HOSTED && FD_HAS_X86 /* This limitation is inherited from wksp */

/* FD_ALLOC_{ALIGN,FOOTPRINT} give the required alignment and footprint
   needed for a wksp allocation to be suitable as a fd_alloc.  ALIGN is
   an integer pointer of 2 and FOOTPRINT is an integer multiple of
   ALIGN.  These are provided to facilitate compile time declarations.
   4096 for ALIGN has been is picked to be normal-page like and match
   the minimum alignment of a fd_wksp_alloc. */

#define FD_ALLOC_ALIGN     (4096UL)
#define FD_ALLOC_FOOTPRINT (20480UL)

/* FD_ALLOC_MALLOC_ALIGN_DEFAULT gives the alignment that will be used
   when the user does not specify an alignment.  This will be an integer
   power of 2 of at least 16 for C/C++ allocator alignment conformance.
   (16 instead of 8 on the grounds that 128-bit is a primitive type on
   platforms with FD_HAS_INT128.) */

#define FD_ALLOC_MALLOC_ALIGN_DEFAULT (16UL)

/* FD_ALLOC_JOIN_CGROUP_CNT is the number of concurrency groups
   supported by the allocator.  This is an integer power of 2 of at most
   FD_ALLOC_ALIGN. */

#define FD_ALLOC_JOIN_CGROUP_CNT (16UL)

/* A "fd_alloc_t *" is an opaque handle of an fd_alloc. */

struct fd_alloc;
typedef struct fd_alloc fd_alloc_t;

FD_PROTOTYPES_BEGIN

/* fd_alloc_{align,footprint} return FD_ALLOC_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong
fd_alloc_align( void );

FD_FN_CONST ulong
fd_alloc_footprint( void );

/* fd_alloc_new formats an unused wksp allocation with the appropriate
   alignment and footprint as a fd_alloc.  Caller is not joined on
   return.  Returns shmem on success and NULL on failure (shmem NULL,
   shmem misaligned, shmem is not backed by a wksp ... logs details).  A
   workspace can have multiple fd_alloc created for it.  They will
   dynamically share the underlying workspace along with any other
   non-fd_alloc usage but will otherwise act as completely separate
   non-conflicting arenas (useful for logical grouping and improved
   concurrency). */

void *
fd_alloc_new( void * shmem );

/* fd_alloc_join joins the caller to a fd_alloc.  shalloc points to the
   first byte of the memory region backing the alloc in the caller's
   address space.  Returns an opaque handle of the join on success
   (IMPORTANT! THIS IS NOT JUST A CAST OF SHALLOC) and NULL on failure
   (NULL shalloc, misaligned shalloc, bad magic, cgroup_idx not in
   [0,FD_ALLOC_JOIN_CGROUP_CNT) ... logs details).  Every successful
   join should have a matching leave.  The lifetime of the join is until
   the matching leave or the thread group is terminated (joins are local
   to a thread group).

   cgroup_idx is a concurrency hint used to optimize parallel and
   persistent use cases. Ideally each thread (regardless of thread
   group) should join the allocator with a different cgroup_idx system
   wide (note that joins are practically free).  And if using a fd_alloc
   in a persistent way, logical streams of execution would ideally
   preserve the cgroup_idx address starts and stops of that stream for
   the most optimal affinity behaviors.  0 is fine in single threaded
   use cases and 0 and/or collisions are fine in more general cases
   though concurrent performance might be reduced due to additional
   contention between threads that share the same cgroup_idx.

   TL;DR A cgroup_idx of 0 is often a practical choice single threaded.
   A cgroup_idx of fd_tile_idx()%FD_ALLOC_JOIN_CGROUP_CNT or a uniform
   random value in [0,FD_ALLOC_JOIN_CGROUP_CNT) is often a practical
   choice in more general situations. */

fd_alloc_t *
fd_alloc_join( void * shalloc,
               ulong  cgroup_idx );

/* fd_alloc_leave leaves an existing join.  Returns the underlying
   shalloc (IMPORTANT! THIS IS NOT A SIMPLE CAST OF JOIN) on success and
   NULL on failure.  Reasons for failure include join is NULL (logs
   details). */

void *
fd_alloc_leave( fd_alloc_t * join );

/* fd_alloc_delete unformats a wksp allocation used as a fd_alloc.
   Assumes nobody is or will be joined to the fd_alloc.  The caller
   further promises there are no allocations outstanding.  If there are
   still some outstanding allocations, it will try to clean up as many
   as it can find but it is not guaranteed to find all of them (those
   will continue to consume wksp space but could be theoretically be
   cleaned up in an application specific way by operating directly on
   the underlying workspace ... of course, if the application could do
   that, it probably such just clean up after itself before calling
   delete).  Returns shmem on success and NULL on failure (logs
   details).  Reasons for failure include shalloc is NULL, misaligned
   fd_alloc, bad magic, etc. */

void *
fd_alloc_delete( void * shalloc );

/* FIXME: CONSIDER API FOR GETTING WKSP BACKING FD_ALLOC? */

/* fd_alloc_malloc allocates sz bytes with alignment align from the wksp
   backing the fd_alloc.  join is a current local join to the fd_alloc.
   align should be an integer power of 2 or 0.

   An align of 0 indicates to use FD_ALLOC_MALLOC_DEFAULT_ALIGN for the
   request alignment.  This will be large enough such that
   fd_alloc_malloc is conformant with C/C++ alignment specifications
   (i.e. can trivally wrap fd_alloc_malloc to use as a drop in
   replacement for malloc).

   Small values of align will NOT be rounded up to some minimum (e.g.
   allocating lots of 1 byte aligned short strings is fine and
   relatively space and time efficient ... the overhead is ~4 bytes per
   allocation).  fd_alloc is not particularly optimized when align>~sz
   and/or large aligments (>~4096B).  While large values for align are
   supported by fd_alloc_malloc, directly using fd_wksp_alloc is
   recommended in such cases.

   If an allocation is "large" (align + sz >~ 64KiB for the current
   implementation), it will be handled by fd_wksp_alloc under the hood.
   Otherwise, it will be handled by fd_alloc_malloc algorithms (which
   are ultimately backed by fd_wksp_alloc).  As such, if a small
   allocation is "new" (e.g. first allocation of a size around sz, an
   allocation that can't be packed near other existing allocations
   around that sz, etc), this might also fallback on fd_wksp_alloc.
   Typically though, after initial allocation and/or program warmup,
   fd_alloc_malloc calls will be a reasonably fast O(1) lockfree.

   Returns a pointer to the allocation in the local address space on
   success.  Note that this pointer will a wksp laddr.  As such, it can
   be converted to a gaddr, passed to other threads in other thread
   groups, and converted to a wksp laddr in their address spaces, freed
   via a join to the fd_alloc in that thread group, persisted beyond the
   lifetime of the calling thread, etc.

   Returns NULL on failure (silent to support HPC usage) or when sz is
   0.  Reasons for failure include NULL join, invalid align, sz overflow
   (sz+align>~2^64), no memory available for request (e.g. workspace has
   insufficient room or is too fragmented). */

void *
fd_alloc_malloc( fd_alloc_t * join,
                 ulong        align,
                 ulong        sz );

/* fd_alloc_free frees the outstanding allocation whose first byte is
   pointed to by laddr in the caller's local address space.  join is a
   current local join to the fd_alloc.  The caller promises laddr was
   allocated by the underlying fd_alloc (but not necessarily on the
   calling thread or even in this calling process or even by a thread /
   process that is still running).  Silent for HPC usage (NULL join and
   NULL laddr are a no-op).

   Like fd_alloc_malloc, if the allocation was large, this will be
   handled by fd_wksp_free under the hood, which is neither lockfree nor
   O(1).  If the allocation was small, this will typically be lockfree
   O(1).  It is possible that, if the amount of outstanding small
   allocations has reduced signficantly, fd_alloc_free on a small
   allocation might trigger a fd_wksp_free to free up wksp space for
   other usage (including uses not through this fd_alloc).

   (It would be possible to implement this less efficiently in space and
   time such that join didn't need to be passed.  The current design has
   picked efficiency and consistency with other APIs though.) */

void
fd_alloc_free( fd_alloc_t * join,
               void *       laddr );

/* FIXME: Consider an advanced free api with a concurrency hint to allow
   users to optimize usages with malloc in one thread and free in a
   different thread. */

FD_PROTOTYPES_END

#endif

#endif /* HEADER_fd_src_util_alloc_fd_alloc_h */

