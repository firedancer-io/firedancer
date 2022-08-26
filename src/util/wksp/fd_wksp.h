#ifndef HEADER_fd_src_util_wksp_fd_wksp_h
#define HEADER_fd_src_util_wksp_fd_wksp_h

#include "../shmem/fd_shmem.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* API for creating NUMA-aware and TLB-efficient workspaces used for
   complex inter-thread and inter-process shared memory communication
   patterns.  fd must be booted to use the APIs in this module.

   For example, startup scripts could reserve some memory on each NUMA
   node backed by huge and gigantic pages:

     sudo bin/fd_shmem_cfg alloc   8 gigantic 0 \
                           alloc   8 gigantic 1 \
                           alloc 256     huge 0 \
                           alloc 256     huge 1

   and then some of these memory could be formatted into fd_wksp for
   each NUMA node:

     bin/fd_shmem_ctl new my-wksp-numa-0 1 gigantic 0 \
                      new my-wksp-numa-1 1 gigantic 1

   Then, at application startup, processes can join these fd_wksp and
   concurrently allocate memory from the desired NUMA nodes as
   necessary.  E.g.

     fd_wksp_t * wksp = fd_wksp_attach( "my-wksp-numa-0" ); // logs details on failure
     if( !fd_wksp ) ... handle attach failure ...;

     ulong gaddr = fd_wksp_alloc( wksp, align, sz ); // logs details on failure
     if( !gaddr ) ... handle alloc failure ...;

   The local address of a workspace global address can be found via:

     void * laddr = fd_wksp_laddr( wksp, gaddr ); // logs details on failure
     if( !laddr ) ... handle bad (wksp,gaddr) ...;

   and the global address of a workspace local address can be found via:

     ulong gaddr = fd_wksp_gaddr( wksp, laddr ); // logs details on failure
     if( !gaddr ) ... handle bad (wksp,laddr) ...;

   Allocations can be freed via:

     fd_wksp_free( wksp, gaddr );

   Any join can free any allocation regardless of who made it.
   
   When the application is done using a wksp, it should leave it.  The
   workspace will continue to exist (it just is no longer safe to access
   in the caller's address space).  E.g.

     fd_wksp_detach( wksp ); // logs details on failure

   Likewise, if the workspaces are no longer in use, they can be deleted
   via something like:

     bin/fd_wksp_ctl delete my-wksp-numa-0 \
                     delete my-wksp-numa-1

   All allocations can be freed via something like:

     bin/fd_wksp_ctl reset my-wksp-numa-0 \
                     reset my-wksp-numa-1

   or in code:

     fd_wksp_reset( wksp ); // logs details on failure

   It is the caller's responsibility to ensure that previous allocations
   to the wksp are not in use.

   Note: while this presents an "aligned_alloc" style API semantics,
   this is not designed to be algorithmically optimal, HPC
   implementation or efficient at doing lots of tiny allocations.
   Rather it is designed to be akin to an "mmap" / "sbrk" style
   allocator of last resort, done rarely and then ideally at application
   startup (e.g. setting up datastructures at box startup or used in an
   interprocess lockfree allocator as a mmap replacement).

   Instead, this tries to keep wksp fragmentation low with low overhead
   and tight packing of larger size allocations (normal page size and
   up).  It further tries to proactively limit the risk of heap
   _metadata_ corruption (proactive intraworkspace heap application
   _data_ corruption prevention is not a goal though typical mechanisms
   for such are in _direct_ opposition to efficient use of TLB, low
   fragmentation and tight allocation packing).  It is quasi-lockfree
   such that a process _killed_ in the middle of a workspace operation
   will not prevent other processes from using the workspace but a
   process _stalled_ in the middle of a workspace operations can stall
   other applications waiting to use the workspace indefinitely.
   Operators can track down an errant process stalled in the middle of
   workspace operations and blocking other processors via fd_wksp_ctl
   check / fd_wksp_check).  Likewise detailed usage and metadata
   integrity checking can be done via something like fd_wksp_ctl usage /
   fprintf_wksp.  Practically speaking, none of this really matters if
   usage occurs predominantly during application startup / shutdown.

   See below for more details. */

/* FD_WKSP_CSTR_MAX is the number of bytes maximum that can be in a wksp
   global address cstr. */

#define FD_WKSP_CSTR_MAX (FD_SHMEM_NAME_MAX + 21UL)

/* FD_WKSP_ALLOC_ALIGN_{MIN,DEFAULT} give the minimal and default
   alignments of a wksp allocation.  MIN and DEFAULT must a positive
   power of two.  DEFAULT must be >= MIN.  Additional details described
   in FD_WKSP_ALLOC. */

#define FD_WKSP_ALLOC_ALIGN_MIN     FD_SHMEM_NORMAL_PAGE_SZ
#define FD_WKSP_ALLOC_ALIGN_DEFAULT FD_SHMEM_NORMAL_PAGE_SZ

/* A fd_wksp_t * is an opaque handle of a workspace */

struct fd_wksp_private;
typedef struct fd_wksp_private fd_wksp_t;

FD_PROTOTYPES_BEGIN

/* Simplified high-level end-user API *********************************/

/* Overall, these are meant for use at application startup / shutdown
   and not in critical loops. */

/* fd_wksp_cstr prints the wksp global address gaddr into cstr as a
   [fd_wksp_name(wksp)]:[gaddr].  Caller promises that cstr has room for
   FD_WKSP_CSTR_MAX bytes.  Returns cstr on success and NULL on failure
   (logs details).  Reasons for failure include NULL wksp, gaddr bad
   (i.e. a good gaddr is either 0 or a pointer to byte strictly inside
   the workspace global address space such fd_wksp_map( cstr ) can work)
   and NULL cstr. */

char *
fd_wksp_cstr( fd_wksp_t const * wksp,
              ulong             gaddr,
              char *            cstr );

/* fd_wksp_cstr_alloc allocates sz bytes with alignment align from wksp
   with name.  align and sz have the exact same semantics as
   fd_wksp_alloc.  cstr must be non-NULL with space for up to
   FD_WKSP_CSTR_MAX bytes.

   Returns cstr on success and NULL on failure (logs details).  On
   success, cstr will contain a [name]:[gaddr] string suitable for use
   by fd_wksp_map and fd_wksp_cstr_free.  cstr will be untouched
   otherwise.  Ignoring error trapping and such, equivalent to:

     fd_wksp_t * wksp  = fd_wksp_attach( name );
     ulong       gaddr = fd_wksp_alloc( wksp, align, sz );
     fd_wksp_detach( wksp );
     sprintf( cstr, "%s:%lu", name, gaddr );
     return cstr;

   As such, if doing many allocations from the same wksp, it is faster
   to do a fd_wksp_attach upfront, followed by the allocations and then
   a wksp detach (and faster still to use the advanced APIs to further
   amortize the fd_wksp_attach / fd_wksp_detach calls). */

char *
fd_wksp_cstr_alloc( char const * name,
                    ulong        align,
                    ulong        sz,
                    char *       cstr );

/* fd_wksp_cstr_free a wksp allocation specified by a cstr containing
   [name]:[gaddr].  Ignoring parsing and error trapping, equivalent to:

      fd_wksp_t * wksp = fd_wksp_attach( name );
      fd_wksp_free( wksp, gaddr );
      fd_wksp_detach( wksp );

   As such, if doing many deallocations from the same wksp, it is faster
   to do a fd_wksp_attach upfront, followed by the deallocations and
   then a fd_wksp_detach (and faster still to use the advanced APIs to
   further amortize the fd_wksp_attach / fd_wksp_detach calls.) */

void
fd_wksp_cstr_free( char const * cstr );

/* fd_wksp_cstr_memset memsets a wksp allocation specified by a cstr
   containing [name]:[gaddr] to c.  Ignoring parsing and error trapping,
   equivalent to:

      fd_wksp_t * wksp = fd_wksp_attach( name );
      fd_wksp_memset( wksp, gaddr, c );
      fd_wksp_detach( wksp );

   As such, if doing many memset from the same wksp, it is faster to do
   a fd_wksp_attach upfront, followed by the deallocations and then a
   fd_wksp_detach (and faster still to use the advanced APIs to further
   amortize the fd_wksp_attach / fd_wksp_detach calls.) */

void
fd_wksp_cstr_memset( char const * cstr,
                     int          c );

/* fd_wksp_map returns a pointer in the caller's address space to the
   wksp allocation specified by a cstr containing [name]:[gaddr].
   [name] is the name of the shared memory region holding the wksp.
   [gaddr] is converted to a number via fd_cstr_to_ulong that should
   correspond to a valid non-NULL global address in that wksp.
   Notwithstanding parsing and edge cases, does:

     fd_wksp_laddr( fd_wksp_attach( name ), gaddr )

   Returns non-NULL on successful (the lifetime of the returned pointer
   will be until fd_wksp_unmap is called on it).  Returns NULL and logs
   details on failure.

   fd_wksp_map should not be used to map open or half open intervals.
   E.g. in ["wksp:lo","wksp:hi"), "wksp:hi" might refer to a location
   just outside the wksp (that fd_wksp_unmap might not be able to deal
   with).  Such cases should instead be handled by using lo / sz
   representation (e.g. ["wksp:lo","wksp:lo"+sz) or via the advanced
   APIs.

   fd_wksp_map is algorithmically efficient and reasonably low overhead
   (especially if is this not the first attachment to the wksp).

   FIXME: READ-ONLY VARIANT? */

void *
fd_wksp_map( char const * cstr );

/* fd_wksp_unmap unmaps a pointer returned by fd_wksp_map, logs details
   if anything weird is detected.  Essentially:

     fd_wksp_detach( fd_wksp_containing( laddr ) )

   Undefined behavior if laddr is not currently mapped by fd_wksp_map.
   fd_wksp_unmap is not algorithmically efficient but practically still
   quite fast (especially if this is not the last attachment to wksp). */

void
fd_wksp_unmap( void const * laddr );

/**********************************************************************/

/* fd_wksp_attach attach to the workspace with the given name.  If there
   are regions with the same name backed by different page sizes,
   defaults to the region backed by the largest page size.  Returns wksp
   on success and NULL on failure (details are logged).  Multiple
   attachments within are fine (all but the first attachment will be a
   reasonably fast O(1) call); all attachments in a process will use the
   same local fd_wksp_t handle.  Every attachment should be paired with
   a detach.  FIXME: CONST-VARIANTS? */

fd_wksp_t *
fd_wksp_attach( char const * name );

/* fd_wksp_detach detaches from the given workspace.  All but the last
   detach should be a reasonably fast O(1) call. */

void
fd_wksp_detach( fd_wksp_t * wksp );

/* fd_wksp_name a cstr pointer to the wksp name (will point to a valid
   region name, e.g. strlen( name ) in [1,FD_SHMEM_NAME_MAX)).  Assumes
   wksp is a valid current join.  Lifetime of the returned string is
   until the last detachment. */

FD_FN_CONST char const *
fd_wksp_name( fd_wksp_t const * wksp );

/* fd_wksp_{align,footprint} give the required alignment and footprint
   for a workspace with a size of sz bytes (including metadata ... the
   largest possible allocation from a wksp of sz will be ~0.2% smaller
   than sz asymptotically for minimum alignment parameters below).  The
   returned align is guaranteed fd_shmem friendly (a power of two of at
   most FD_SHMEM_NORMAL_PAGE_SZ).  The footprint is guaranteed to be a
   multiple of align.  If sz is bad (e.g. too small), footprint returns
   0 (logs details).  Further, if sz is an adequately large multiple
   FD_SHMEM_NORMAL_PAGE_SZ, footprint should be equal to sz.  This is to
   facilitate applications that prefer to specify workspace in terms of
   total number of pages to use. */
   
FD_FN_CONST ulong
fd_wksp_align( void );

FD_FN_CONST ulong
fd_wksp_footprint( ulong sz );

/* fd_wksp_new formats an unused shared memory region with the
   appropriate footprint and alignment mapped into the caller's address
   space at shmem into a wksp with given name (should be a valid
   fd_shmem region name and match the underlying shared memory region
   name).  Returns NULL on failure (logs details) or shmem on success.
   The caller is _not_ joined on return.  If opt_part_max is zero, this
   will default the metadata storage size such that fd_wksp_alloc will
   never fail due to running out of metadata storage.  If non-zero, it
   will use this amount of opt_part_max (the theoretical maximum number
   of outstanding wksp allocations for such would be opt_part_max).
   There are no practical limitations on sz outside the caller's ability
   to actually procure that much memory. */

void *
fd_wksp_new( void *       shmem,
             char const * name,
             ulong        sz,
             ulong        opt_part_max );

/* fd_wksp_join joins a workspace.  shwksp is the location of the where
   the wksp has been mapped into the caller's address space.  Returns
   the local handle of the join on success or NULL on failure (logs
   details).  The caller can read / write memory in the joined workspace
   on return (a caller can do a read only join by mapping the shwksp
   into the local address as read only).  There is no practical
   limitation on the number of concurrent joins in a thread, process or
   system wide.*/

fd_wksp_t *
fd_wksp_join( void * shwksp );

/* fd_wksp_leave leaves a workspace.  Returns shwksp on success and NULL
   on failure (logs details).  The caller should not continue to read or
   write any memory for the join on return but the workspace will
   continue to exist. */

void *
fd_wksp_leave( fd_wksp_t * wksp );

/* fd_wksp_delete unformats a shared memory used as a workspace.
   Returns the shmem on pointer on success and NULL on failure (logs
   details).  There should not be anybody joined to the workspace when
   it is deleted. */

void *
fd_wksp_delete( void * shwksp );

/* fd_wksp_laddr map a fd_wksp global address (an address all joiners
   agree upon) to the caller's local address space.  Invalid global
   addresses and/or 0UL will map to NULL (logs details if invalid). */

void *
fd_wksp_laddr( fd_wksp_t * wksp,
               ulong       gaddr );

/* fd_wksp_containing maps a fd_wksp local addr to the corresponding
   fd_wksp local join.  Returns NULL if laddr does not appear to be from
   a locally joined fd_wksp.  Always silent such that this can be used
   to detect if a pointer is from a fd_wksp or not.  This is not a
   terribly fast call. */

fd_wksp_t *
fd_wksp_containing( void const * laddr );

/* fd_wksp_gaddr maps a fd_wksp local address to the corresponding wksp
   global address (an address all joiners agree upon).  Invalid local
   addresses and/or NULL will map to 0UL (logs details if invalid). */

ulong
fd_wksp_gaddr( fd_wksp_t * wksp,
               void *      laddr );

/* fd_wksp_alloc allocates sz bytes from wksp with alignment of at least
   align (align must be a non-negative integer power-of-two or 0, which
   indicates to use the default alignment FD_WKSP_ALLOC_ALIGN_DEFAULT
   ... allocations smaller than FD_WKSP_ALLOC_ALIGN_MIN will be rounded
   up to FD_WKSP_ALLOC_ALIGN_MIN).  Returns the fd_wksp global address
   of the join on success and "NULL" (0UL) on failure (logs details).  A
   zero sz returns "NULL" (silent).
   
   Note that fd_wksp_alloc / fd_wksp_free are neither algorithmically
   optimal nor HPC implementations.  Instead, they are designed to be
   akin to mmap / sbrk used as "last resort" allocators under the hood
   in other allocators like libc malloc, ptmalloc, dmalloc, Hoard, etc.
   As such they use large minimum alignments (akin to a block size /
   page size), prioritize efficiency of packing allocations tightly
   (best effort based on the first-fit address-ordered block empirically
   found quite robust in practice by Johnstone and Wilson "The Memory
   Fragmentation Problem: Solved?" ACM 1998) and prioritize robustness
   against heap corruption (e.g. overrunning an allocation might corrupt
   the data in other allocations but will not corrupt the heap structure
   ... as the goal of this data structure is to encourage minimization
   of TLB usage, there is very little that can be done to proactively
   prevent intraworkspace interallocation data corruption).

   These operations are "quasi-lock-free".  Specifically, while they can
   suffer priority inversion due to a slow thread stalling other threads
   from using these operations, a process that is terminated in the
   middle of these operations implicitly rolls back the state of wksp to
   what it was just before the operation.  The only risk is the same
   risk generally from any application that uses persistent resources:
   applications that are terminated abruptly might leave allocations in
   the wksp that would have been freed had the application terminated
   normally.  As the allocator has no way to tell the difference between
   such allocations and allocations that are intended to outlive the
   application, it is the callers responsibility to clean up such.
   
   Priority inversion is not expected to be an issue practical as the
   expected use case is once at box startup, some non-latency critical
   processes will do a handful of operations to setup workspaces for
   applications on that box going forward and then the allocations will
   not be used again until the wksp is tore down / reset / etc.  It
   would be possible to widen this API for the application to explicitly
   signal this intent and automatically clean up allocations not meant
   to outlive their creator but the general use here is expected to be
   allocations that are meant to outlive their creator.

   Note further that very fast interprocess allocations could be
   implemented on top of this by using a conventional allocator with
   this as the last resort allocator (in such, all allocations would be
   strictly lock free unless they needed to invoke the last resort, as
   is typically in other lock free allocators).

   IMPORTANT!  align technically refers to the alignment in the wksp's
   global address space.  As such, wksp must be mmaped into each local
   address space with an alignment of at least the largest alignment the
   overall application intends to use.  Common practices automatically
   satisfy this (e.g. if wksp is backed by normal/huge/gigantic pages
   and only asks for alignments of at most a normal/huge/gigantic page
   sz, this constraint is automatically satisfied as fd_shmem_join needs
   to mmap wksp into the local address space with normal/huge/gigantic
   alignment anyway).  If doing more exotic things (e.g. backing wksp by
   normal pages but requiring much larger alignments), things like
   explicitly specifying the wksp virtual address location in the
   fd_shmem_join calls might be necessary to satisfy this constraint.
   
   Theoretically, this implementation could accommodate
   FD_WKSP_ALLOC_ALIGN_MIN as low as 2 (it would be very silly though as
   the default metadata allocations would be insanely large).  For C/C++
   allocator conformance, FD_WKSP_ALLOC_ALIGN_MIN should be at least 8
   (still quite a lot of space burned for default metadata usage).  For
   modern architectures though, 16 (SSE), 32 (AVX), 64 (cache line /
   AVX-512), 128 (double cache line / adjacent cache line prefetch), 256
   (DRAM/NVME channel granularity) are more sensible bare minimums.
   Given the "mmap"-like allocator of last resort use case, we use a
   normal page size (4KiB) here.  In any case, fd_wksp_footprint and
   other parts of the implementation might need tweaked if adjusting if
   FD_WKSP_ALLOC_ALIGN_MIN. */

ulong
fd_wksp_alloc( fd_wksp_t * wksp,
               ulong       align,
               ulong       sz );

/* fd_wksp_free frees a wksp allocation.  gaddr is a global address that
   points to any byte in the allocation to free (i.e. can point to
   anything in [gbase,gbase+sz) where sz is value provided to the
   original fd_wksp_alloc and gbase is where it was allocated in the
   workspace).  Logs details of any weirdness detected.  Free of "NULL"
   (0UL) silently returns.  There are no restrictions on which join
   might free an allocation.  See note above other details. */

void
fd_wksp_free( fd_wksp_t * wksp,
              ulong       gaddr );

/* fd_wksp_memset sets a wksp allocation to character c.  gaddr is a
   global address that points to any byte in the allocation (i.e. can
   point to anything in [gbase,gbase+sz) where sz is value provided to
   the original fd_wksp_alloc and gbase is where it was allocated in the
   workspace).  Logs details of any weirdness detected.  Clear of "NULL"
   (0UL) silently returns.  Atomic with respect to other operations on
   this workspace. */

void
fd_wksp_memset( fd_wksp_t * wksp,
                ulong       gaddr,
                int         c );

/* fd_wksp_check cleans up after processes were abruptly terminated in
   the middle of workspace oeprations.  This is _not_ required for
   correctness in the presence of errant processes.  This is to allow
   applications to limit the risk of such cleanups occurring at
   inopportune times and to help operators trying to track down a
   process that has been paused in the middle of a workspace application
   (and is blocking other applications from using the workspace). */

void
fd_wksp_check( fd_wksp_t * wksp );

/* fd_wksp_reset frees all allocations from the wksp.  Logs details on
   failure.  This happens atomically. */

void
fd_wksp_reset( fd_wksp_t * wksp );

FD_PROTOTYPES_END

#endif

#endif /* HEADER_fd_src_util_wksp_fd_wksp_h */
