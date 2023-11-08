#ifndef HEADER_fd_src_util_alloc_fd_alloc_h
#define HEADER_fd_src_util_alloc_fd_alloc_h

/* fd_alloc is a high performance lockfree fast O(1) (typically)
   allocator.

   It is optimized for high concurrency use and small-ish clustered /
   multi-modal distributed allocation sizes.  It is further optimized
   for single-threaded use cases and/or when malloc-free pairs have have
   good thread affinity (i.e. frees done by the same thread that did the
   corresponding malloc).  It can also be used optimally in more complex
   threading use cases (e.g. malloc in one or more producer threads,
   free in one or more consumer threads).  It behaves well with
   irregular sizes and exploits ultra fine grained alignment for good
   packing (e.g. reasonable low memory overhead packing of byte strings
   with irregular small-ish sizes).

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
#include "../valloc/fd_valloc.h"

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

/* FD_ALLOC_JOIN_CGROUP_HINT_MAX is maximum value for a cgroup hint.
   This is an integer power of 2 minus 1 of at most FD_ALLOC_ALIGN. */

#define FD_ALLOC_JOIN_CGROUP_HINT_MAX (15UL)

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
   concurrency).  To help with various diagnostics, garbage collection
   and what not, all allocations to the underlying wksp are tagged with
   the given tag, positive.  Ideally, the tag used here should be
   distinct from all other tags used by this workspace. */

void *
fd_alloc_new( void * shmem,
              ulong  tag );

/* fd_alloc_join joins the caller to a fd_alloc.  shalloc points to the
   first byte of the memory region backing the alloc in the caller's
   address space.  Returns an opaque handle of the join on success
   (IMPORTANT! THIS IS NOT JUST A CAST OF SHALLOC) and NULL on failure
   (NULL shalloc, misaligned shalloc, bad magic, ... logs details).
   Every successful join should have a matching leave.  The lifetime of
   the join is until the matching leave or the thread group is
   terminated (joins are local to a thread group).

   cgroup_hint is a concurrency hint used to optimize parallel and
   persistent use cases. Ideally each thread (regardless of thread
   group) should join the allocator with a different cgroup_hint system
   wide (note that joins are practically free).  And if using a fd_alloc
   in a persistent way, logical streams of execution would ideally
   preserve the cgroup_hint address starts and stops of that stream for
   the most optimal affinity behaviors.  0 is fine in single threaded
   use cases and 0 and/or collisions are fine in more general cases
   though concurrent performance might be reduced due to additional
   contention between threads that share the same cgroup_hint.  If
   cgroup_hint is not in [0,FD_ALLOC_JOIN_CGROUP_HINT_MAX], it will be
   wrapped to be in that range.

   TL;DR A cgroup_hint of 0 is often a practical choice single threaded.
   A cgroup_hint of fd_tile_idx() or just uniform random 64-bit value
   choice in more general situations. */

fd_alloc_t *
fd_alloc_join( void * shalloc,
               ulong  cgroup_hint );

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

/* fd_alloc_join_cgroup_hint returns the cgroup_hint of the current
   join.  Assumes join is a current local join.  The return will be in
   [0,FD_ALLOC_JOIN_CGROUP_HINT_MAX].

   fd_alloc_join_cgroup_hint_set returns join with the cgroup_hint
   updated to provided cgroup_hint.  If cgroup hint is not in
   [0,FD_ALLOC_JOIN_CGROUP_HINT_MAX], it will be wrapped into this
   range.  Assumes join is a current local join.  The return value is
   not a new join. */

FD_FN_CONST static inline ulong
fd_alloc_join_cgroup_hint( fd_alloc_t * join ) {
  return ((ulong)join) & FD_ALLOC_JOIN_CGROUP_HINT_MAX;
}

FD_FN_CONST static inline fd_alloc_t *
fd_alloc_join_cgroup_hint_set( fd_alloc_t * join,
                               ulong        cgroup_hint ) {
  return (fd_alloc_t *)((((ulong)join) & (~FD_ALLOC_JOIN_CGROUP_HINT_MAX)) | (cgroup_hint & FD_ALLOC_JOIN_CGROUP_HINT_MAX));
}

/* fd_alloc_wksp returns a pointer to a local wksp join of the wksp
   backing the fd_alloc with the current local join.  Caller should not
   call fd_alloc_leave on the returned value.  Lifetime of the returned
   wksp handle is as long as the shalloc used on the fd_alloc_join is
   still mapped into the caller's address space.

   fd_alloc_tag returns the tag that will be used for allocations from
   this workspace. */

FD_FN_PURE fd_wksp_t * fd_alloc_wksp( fd_alloc_t * join ); // NULL indicates NULL join
FD_FN_PURE ulong       fd_alloc_tag ( fd_alloc_t * join ); // Positive, 0 indicates NULL join

/* fd_alloc_malloc_at_least allocates at least sz bytes with alignment
   of at least align from the wksp backing the fd_alloc.  join is a
   current local join to the fd_alloc.  align should be an integer power
   of 2 or 0.

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
   insufficient room or is too fragmented).

   On return, *max will contain the number actual number of bytes
   available at the returned gaddr.  On success, this will be at least
   sz and it is not guaranteed to be a multiple of align.  On failure,
   *max will be zero.

   fd_alloc_malloc is a simple wrapper around fd_alloc_malloc_at_least
   for use when applications do not care about the actual size of their
   allocation. */

void *
fd_alloc_malloc_at_least( fd_alloc_t * join,
                          ulong        align,
                          ulong        sz,
                          ulong *      max );

static inline void *
fd_alloc_malloc( fd_alloc_t * join,
                 ulong        align,
                 ulong        sz ) {
  ulong max[1];
  return fd_alloc_malloc_at_least( join, align, sz, max );
}

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
   picked efficiency and consistency with other APIs though.)

   Note that this will implicitly optimize the freed memory to be
   preferentially reused by the join's concurrency group.  Thus the
   caller should have at least one join for each concurrency group to
   which it might want to return memory for reuse and then call free
   with the appropriate join. */

void
fd_alloc_free( fd_alloc_t * join,
               void *       laddr );

/* fd_alloc_compact frees all wksp allocations that are not required
   for any outstanding user mallocs (note that fd_alloc_free lazily
   returns unused memory from the underlying wksp to accelerate
   potential future allocations).  join is a current local join to the
   alloc.  This cannot fail from a user's POV but logs any wonkiness
   detected.

   fd_alloc_compact has the property that it minimizes the amount of
   wksp utilization for the set of outstanding user mallocs when there
   is no other concurrent alloc usage.  As such, if there is no
   concurrent alloc usage _and_ there are no outstanding mallocs, on
   return, all wksp allocations (except the user provided memory region
   that holds the state of the allocator) will be returned to the wksp.
   This can be then be used to reset the alloc and/or implement robust
   leak detection at program teardown.

   This function is safe to use even when there is other concurrent
   alloc usage.  It t is best effort in that case; it is not guaranteed
   that there was some point in time between call and return when the
   wksp utilization was minimized for the contemporaneous set of
   outstanding user mallocs.

   Also note that this function is not O(1) and the fd_alloc_free lazy
   return mechanism does not permit unbounded growth of unreturned free
   memory.  So this should be used sparingly at best (e.g. in teardown
   leak detection or rare non-critical path housekeeping). */

void
fd_alloc_compact( fd_alloc_t * join );

/* fd_alloc_is_empty returns 1 if the alloc has no outstanding mallocs
   and 0 otherwise.  join is a current local join to the alloc.  NULL
   join silently returns 0.

   Important safety tip!  This should only be run when there is no
   concurrent alloc usage.  It is not algorithmically fast.  This might
   temporarily lock the underlying wksp while running and might call
   fd_alloc_compact under the hood.  It assumes the user provided memory
   region holding the alloc state is contained within a region returned
   by a single fd_wksp_alloc call (it would be hard to create an alloc
   where that isn't the case).  It assumes alloc is the only user of the
   alloc's tag in the wksp.  As such this should be used carefully and
   sparingly (e.g. at program teardown for leak detection).

   It will "work" with concurrent alloc usage in that the return value
   will be in 0 or 1 and it will not corrupt the alloc or underlying
   wksp.  But the return value will not be well-defined (e.g. it is not
   guaranteed to correspond the state of the alloc at some point in time
   between when this was called and it when it returned). */

int
fd_alloc_is_empty( fd_alloc_t * join );

/* fd_alloc_max_expand computes a recommended value to use for max when
   needing to dynamically resize structures.  The below is very subtle
   and fixes a lot of pervasive errors with dynamic resizing
   implementations (either explicit or implicitly done under the hood).
   It doesn't fix the main error with dynamic resizing though.  The main
   error being deciding to use anything with dynamic resizing (outside
   of, maybe, initialization at program start).

   Consider an all too common case of an initially too small dynamically
   sized array that is getting elements appended to it one at a time.
   E.g. without proper error trapping, overflow handling and the like:

     foo_t * foo       = NULL;
     ulong   foo_max   = 0UL;
     ulong   foo_cnt   = 0UL;
     ulong   foo_delta = ... some reasonable increment ...;

     while( ... still appending ... ) {

       if( foo_cnt==foo_max ) { // Need to resize
         foo_max += foo_delta;
         foo = (foo_t *)realloc( foo, foo_max*sizeof(foo_t) );
       }

       foo[ foo_cnt++ ] = ... next val to append ...;
     }

   This is terrible theoretically and practically and yet it looks like
   it does everything right.

   The theoretical issue is that, if the realloc can't be done in-place
   (which is more common than most realize ... depends on how the
   underlying realloc implementation details), the memory will have to
   be copied from the original location to the resized location with a
   typical cost of final_foo_max/2 -> O(final_foo_cnt).  Because max is
   increased by fixed absolute amount each resizing, there will be
   final_foo_cnt/foo_delta -> O(final_foo_cnt) such resizes.

   That is, we've accidentially written a method that has a slow
   O(final_foo_cnt^2) worst case even though it superficially looks like
   a fast O(final_foo_cnt) method.  Worse still, this behavior might
   appear suddenly in previously fine code if realloc implementation
   changes or, yet again worse, because a larger problem size was used
   in the wild than used in testing.

   The practical issue is realloc is painfully slow and it gets worse
   for large sizes because large sizes are usually handled by operating
   system calls (e.g. mmap or sbrk under the hood).  We've also now done
   O(final_foo_cnt) slow operating system calls in our already
   algorithmically slow O(final_foo_cnt^2) worst case algorithm that
   still superficially looks like a fast O(final_foo_cnt).  (And throw
   in the other issues with malloc described above about TLB and NUMA
   inefficiency, the gaslighting the kernel does "clearly the crash had
   nothing to do with the OOM killer shooting processes randomly in the
   head, your program probably just had a bug ... yeah ... that's the
   ticket" ... for good measure).

   We can get an algorithmic improvement if we change the above to
   increase max by a fixed relative amount each resize.  Since we are
   dealing with integers though, we should make sure that we always
   increase max by some minimal amount.  Instead of:

     foo_max += foo_delta;

   we can use something like:

     foo_max = fd_ulong_max( foo_max*gamma, foo_max + foo_delta );

   If gamma>1, asymptotically, we will only do O(lg cnt) resizes.
   Theoretically, we've gone from an O(final_foo_cnt^2) worst case
   method to an O(final_foo_cnt lg final_foo_cnt) worst case method.  It
   is still irritating that it looks superficially like a fast
   O(final_foo_cnt) method but this is amongst the many reasons why
   dynamic resizing is gross and wrong and to be avoided when possible.

   The larger gamma is, the smaller the leading coefficient is in the
   O(final_foo_cnt lg final_foo_cnt) and thus the better this
   approximates the fast O(final_foo_cnt) method that it superficially
   seems to be.  But using a very large gamma is clearly absurd.  There
   are obvious memory footprint limitations for large sizes and each
   resize would trigger an ever larger amount of OS work.  This raises
   the question:

   What is the optimal gamma?

   Suppose we have worst case realloc implementation (alloc new memory,
   copy, free old memory and, when no free fragment large enough is
   available, use sbrk like semantics to get memory from the O/S ...
   not uncommon as it is trivial to implement and often works "good
   enough" in lab settings).  It always works out-of-place and it always
   just appends new memory at the end of the heap when the heap runs out
   of space.  Then, while doing the above, asymptotically, we expect the
   heap to look something like:

     other allocs | M foo_t alloc | padding free | unmapped

   On the next resize, we'd request space for M gamma foo_t.  Since
   there are no free fragments large enough for this, realloc is going
   to have to map some space from the operating system, copy our memory
   into it and free up the original space for reuse.  Post resize, we
   expect the heap to look like:

     other allocs | M foo_t free | M gamma foo_t alloc | padding free | unmapped

   On the next resize, we'd request space for M gamma^2 foo_t.  This
   also can't fit within any free fragment above for gamma>1 (noting
   that, in this worst case realloc, we have to allocate the memory
   first and then copy and then free the old).  So we end up with:

     other allocs | M (1+gamma) foo_t free | M gamma^2 foo_t alloc | padding free | unmapped

   On the next resize, we'd request space for M gamma^3 foo_t.  If we
   have:

     gamma^3 < 1 + gamma

   we can fit this request in the hole left by the two previous resizes.
   This implies we need gamma<1.32471... where the magic number is the
   positive real root of:

     x^3 - x - 1  = 0

   This is the "silver ratio" in the sense that the positive real root
   of x^2 - x - 1 is the "golden ratio" of 1.61803...  (Note that the
   golden ratio would apply if we had a more sophisticated realloc under
   the hood that aliased the resized allocation over top the M foo_t
   free and the existing M gamma foo_t alloc and then moved the aliased
   memory.  Presumably such a sophisticated realloc would also just
   append to the end of the heap without any move or copy at all but
   that eventually leads to a question about how much overallocation and
   operating system overhead is acceptable on resize discussed further
   below).

   After a resize with something near but smaller than the silver ratio,
   we expect the heap to look like:

     other allocs | M gamma^3 foo_t alloc | padding free | unmapped

   which is back to where we started, except with a larger allocation.

   We don't want to be doing floating point math in methods like this.
   Noting that gamma = 1 + 1/4 + 1/16 = 1.3125 is very close to the
   silver yields the very practical:

     new_max = fd_ulong_max( max + (max>>2) + (max>>4), max + delta );

   This is friendly with even the worst case realloc behaviors under the
   hood.  It also works will in similar situations with linear storage
   media (e.g. disk storage).  The limit also means that the worst case
   overallocation for cases like the above at most ~32% and on average
   ~16%.  This is a comparable level of overallocation that already
   happens under the hood (e.g. on par with the level of waste that
   naturally happens in allocators for metadata and padding and much
   less waste than the golden ratio or larger growth rates if we
   dubiously trust that the realloc method under the hood).

   In cases where we might need to resize to even larger than this, we
   just resize to the caller's requested amount and keep our fingers
   crossed that the caller realized by this time dynamic resizing was a
   mistake and is allocating the correct size this time.

   Adding arithmetic overflow handling then yields the below.

   TL;DR  Example usage (ignoring size calculation overflow handling and
   allocation error trapping):

     ulong   foo_cnt   = 0UL;
     ulong   foo_max   = ... good estimate the actual amount needed;
     ulong   foo_delta = ... reasonable minimum resizing increment;
     foo_t * foo       = (foo_t *)malloc( foo_max*sizeof(foo_t) );

     while( ... still appending ... ) {

       if( FD_UNLIKELY( foo_cnt==foo_max ) ) {
         foo_max = fd_alloc_max_expand( foo_max, foo_delta, foo_cnt + foo_delta );
         foo     = (foo_t *)realloc( foo, foo_max*sizeof(foo_t) );
       }

       foo[ foo_cnt++ ] = ... next val to append ...;

     }

     ... at this point
     ... - foo has foo_cnt elements initialized
     ... - foo has room for foo_max elements total
     ... - when the initial foo_max estimate was correct or oversized,
     ...   no resizing was done
     ... - when the initial foo_max was undersized, asymptotically,
     ...   foo_max is at most ~32% larger worst case (~16% larger
     ...   average case) than foo_cnt with at most O(lg foo_cnt)
     ...   reallocs needed to initialize foo.
     ... - the resizing test branch is highly predictable
     ... - the underlying heap shouldn't be too fragmented or
     ...   overallocated regardless of the allocator implementation
     ...   details. */

FD_FN_CONST static inline ulong       /* new_max, new_max>=max(needed,max), if max<ULONG_MAX, will be new_max>max */
fd_alloc_max_expand( ulong max,
                     ulong delta,     /* Assumed > 0 */
                     ulong needed ) {
  ulong t0 = max + delta;               t0 = fd_ulong_if( t0<max, ULONG_MAX, t0 ); /* Handle overflow */
  ulong t1 = max + (max>>2) + (max>>4); t1 = fd_ulong_if( t1<max, ULONG_MAX, t1 ); /* Handle overflow */
  return fd_ulong_max( fd_ulong_max( t0, t1 ), needed );
}

/* fd_alloc_vtable is the virtual function table implementing fd_valloc
   for fd_alloc. */

extern const fd_valloc_vtable_t fd_alloc_vtable;

/* fd_alloc_virtual returns an abstract handle to the fd_alloc join.
   Valid for lifetime of join. */

FD_FN_CONST static inline fd_valloc_t
fd_alloc_virtual( fd_alloc_t * alloc ) {
  fd_valloc_t valloc = { alloc, &fd_alloc_vtable };
  return valloc;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_alloc_fd_alloc_h */

