#ifndef HEADER_fd_src_util_shmem_fd_shmem_h
#define HEADER_fd_src_util_shmem_fd_shmem_h

/* APIs for NUMA aware and page size aware manipulation of complex
   interprocess shared memory topologies.  This API is designed to
   interoperate with the fd_shmem_cfg command and control script for
   host configuration.  fd must be booted to use the APIs in this
   module. */

#include "../log/fd_log.h"

/* FD_SHMEM_JOIN_MAX gives the maximum number of unique fd shmem regions
   that can be in mapped concurrently into the thread group's local
   address space.  Should be positive.  Powers of two minus 1 have good
   Feng Shui but this is not strictly required. */

#define FD_SHMEM_JOIN_MAX (255UL)

/* FD_SHMEM_JOIN_MODE_* are used to specify how a memory region should
   be initialy mapped into the thread group's local address space by
   fd_shmem_join. */

#define FD_SHMEM_JOIN_MODE_READ_ONLY   (0)
#define FD_SHMEM_JOIN_MODE_READ_WRITE  (1)

/* FD_SHMEM_{NUMA,CPU}_MAX give the maximum number of numa nodes and
   logical cpus supported by fd_shmem.
   FD_SHMEM_CPU_MAX>=FD_SHMEM_NUMA_MAX>0. */

#define FD_SHMEM_NUMA_MAX (1024UL)
#define FD_SHMEM_CPU_MAX  (1024UL)

/* FD_SHMEM_{UNKNOWN,NORMAL,HUGE,GIGANTIC}_{PAGE_LG_SZ,PAGE_SZ} give the
   log2 page size / page size on a hosted x86 target.  These are
   explicit to workaround various compiler limitations in common use
   cases. */

#define FD_SHMEM_UNKNOWN_LG_PAGE_SZ  (-1)
#define FD_SHMEM_NORMAL_LG_PAGE_SZ   (12)
#define FD_SHMEM_HUGE_LG_PAGE_SZ     (21)
#define FD_SHMEM_GIGANTIC_LG_PAGE_SZ (30)

#define FD_SHMEM_UNKNOWN_PAGE_SZ           (0UL)
#define FD_SHMEM_NORMAL_PAGE_SZ         (4096UL)
#define FD_SHMEM_HUGE_PAGE_SZ        (2097152UL)
#define FD_SHMEM_GIGANTIC_PAGE_SZ (1073741824UL)

/* FD_SHMEM_NAME_MAX gives the maximum number of bytes needed to hold
   the cstr with the name fd_shmem region.  That is, a valid fd_shmem
   region name will have a strlen in [1,FD_SHMEM_NAME_MAX).  (Harmonized
   with FD_LOG_NAME_MAX but this is not strictly required.) */

#define FD_SHMEM_NAME_MAX FD_LOG_NAME_MAX

/* FD_SHMEM_PAGE_SZ_CSTR_MAX is the size of a buffer large enough to
   hold an shmem page sz cstr (==strlen("gigantic")+1). */

#define FD_SHMEM_PAGE_SZ_CSTR_MAX (9UL)

/* fd_shmem_private_key_t is for internal use (tmpl/fd_map
   interoperability). */

struct fd_shmem_private_key {
  char cstr[ FD_SHMEM_NAME_MAX ];
};

typedef struct fd_shmem_private_key fd_shmem_private_key_t;

/* A fd_shmem_join_info_t used by various APIs to provide low level
   details about a join. */

struct fd_shmem_join_info {
  long   ref_cnt;  /* Number of joins, -1L indicates a join/leave is in progress.
                      Will be -1 the join is in join/leave func and positive otherwise. */
  void * join;     /* Local join handle (i.e. what join_func returned).  Will be NULL in a call join func. */
  void * shmem;    /* Location in the thread group local address space of name.  Will be non-NULL and page_sz aligned. */
  ulong  page_sz;  /* Page size unsed for the region.  Will be a supported page size (e.g. non-zero integer power-of-two) */
  ulong  page_cnt; /* Number of pages in the region.  Will be non-zero, page_sz*page_cnt will not overflow */
  int    mode;     /* Will be in FD_SHMEM_JOIN_MODE_{READ_ONLY,READ_WRITE}.  Attemping to execute and (if read-only) write in the
                      shmem region will fault the thread group. */
  uint   hash;     /* Will be (uint)fd_hash( 0UL, name, FD_SHMEM_NAME_MAX ) */
  union {
    char                   name[ FD_SHMEM_NAME_MAX ]; /* cstr with the region name at join time (guaranteed '\0' terminated) */
    fd_shmem_private_key_t key;                       /* For easy interoperability tmpl/fd_map.h */
  };
};

typedef struct fd_shmem_join_info fd_shmem_join_info_t;

/* A fd_shmem_joinleave_func_t is optionally used by fd_shmem_join /
   fd_shmem_leave to wrap / unwrap a shared memory region with
   additional thread group local context when it is mapped / unmapped. */

typedef void *
(*fd_shmem_joinleave_func_t)( void *                       context,
                              fd_shmem_join_info_t const * join_info );

/* A fd_shmem_info_t used by various APIs to provide low level details
   of a shared memory region. */

struct fd_shmem_info {
  ulong page_sz;  /* page size of the region, will be a suported page size (e.g. non-zero, integer power of two) */
  ulong page_cnt; /* number of pages in the region, will be positive, page_sz*page_cnt will not overflow */
};

typedef struct fd_shmem_info fd_shmem_info_t;

FD_PROTOTYPES_BEGIN

/* User APIs **********************************************************/

/* fd_shmem_{join,leave} joins/leaves the caller to/from a named fd
   shared memory region.

   It is very convenient to be able to join the same region multiple
   times within a thread group.  And it is safe and reasonably efficient
   to do so (O(1) but neither lockfree nor ultra HPC).  To facilitate
   this, when a join requires mapping the region into the thread group's
   local address space (e.g. the first join to the region in the thread
   group), this will try to discover the page size that is backing the
   region (if there multiple regions with same name, this will try to
   join the one backed by the largest page size).  Then the region is
   mapped into the address appropriately for the given access mode
   (FD_SHMEM_JOIN_MODE_{READ_ONLY,READ_WRITE}).  Lastly, any user
   provided fd_shmem_join_func_t is called on the mapping.

   A fd_shmem_join_func_t is meant to do any additional local address
   translations and what not as a one-time upfront cost on behalf of all
   subsequent joins.  It is called if the underlying shared memory needs
   to be mapped into the thread group's address space and ignored
   otherwise.  The input to a join_func is a pointer to any user context
   (i.e. the context passed to fd_shmem_join) and a pointer to
   information about the region (lifetime is the duration of the call
   and should not be assumed to be longer).

   On success, a join_func returns the join that wraps the shmem (often
   just a shmem); it should be one-to-one with shmem (i.e. while a
   thread group is joined, name cstr / shmem / join uniquely identify
   the name cstr / shmem / join).  On failure, a join_func returns NULL
   (ideally without impacting thread group state while logging details
   about the failure).

   Pass NULL for join_func if no special handling is needed.  The join
   handle will be just a pointer to the first byte of the region's local
   mapping.

   All joins should be paired with a leave.

   On success, if opt_info is non-NULL, *opt_info will also provide
   additional details about the join (i.e. the same details one would
   get if querying the join atomically with respect to join operations
   immediately afterward).  On failure, *opt_info is ignored.

   fd_shmem_leave is just the inverse of this.  It can fail for a few
   reasons, including if the mmap cannot be close()'d for any reason.
   IT will log extensive details if there is any wokiness udner the
   hood.  The caller may wish to proceed even if it fails.

   IMPORTANT!  It is safe to have join/leave functions themselves call
   fd_shmem_join/fd_shmem_leave to join additional regions as necessary.
   This allows very complex interdependent shared memory topologies to
   be constructed in a natural way.  The only restriction (beyond the
   total number of regions that can be joined) is that there can't be
   join/leave cycles (e.g. fd_shmem_join("region1") calls join_func
   region1_join("region1") which calls fd_shmem_join("region2") which
   calls join_func region2_join("region2") which calls
   shmem_join("region1")).  Such cycles will be detected, logged and
   failed. */

void *
fd_shmem_join( char const *               name,
               int                        mode,
               fd_shmem_joinleave_func_t  join_func,
               void *                     context,
               fd_shmem_join_info_t *     opt_info );

int
fd_shmem_leave( void *                    join,
                fd_shmem_joinleave_func_t leave_func,
                void *                    context );

/* FIXME: CONSIDER OPTION FOR SLIGHTLY MORE ALGO EFFICIENT LEAVE BY NAME
   VARIANT? */

/* fd_shmem_join_query_by_{name,join,addr} queries if the cstr pointed
   by name is already joined by the caller's thread group / the join
   handle is a valid current join handle / [addr,addr+sz-1] overlaps (at
   least partially) with a shared memory region of a current join.

   On success, returns 0 and, if opt_info non-NULL, *opt_info will hold
   details about the join (as observed at a point between when the call
   was made and when it returned).  On failure, returns a non-zero
   strerror friendly error code (these do not log anything so they can
   be use in situations where the query might fail in normal operation
   without being excessively chatty in the log).  Reasons for failure
   include name is not valid (EINVAL) and there is no join currently
   (ENOENT).

   For query_by_addr, returns ENOENT if sz is 0 (no overlap with an
   empty set) and EINVAL if the address range wrapps around the end of
   address space.  If there are multiple joins overlapped by the range,
   returns 0 and, if opt_info is non-NULL, *opt_info will have details
   about one of the joins (it is undefined which join).  Note it is
   impossible for a range to overlap multiple joins when sz==1.

   query by name is a reasonably fast O(1).  query by join and by addr
   are theoretically O(FD_SHMEM_JOIN_MAX) but still quite fast
   practically. */

int
fd_shmem_join_query_by_name( char const *           name,
                             fd_shmem_join_info_t * opt_info );

int
fd_shmem_join_query_by_join( void const *           join,
                             fd_shmem_join_info_t * opt_info );

int
fd_shmem_join_query_by_addr( void const *           addr,
                             ulong                  sz,
                             fd_shmem_join_info_t * opt_info );

/* fd_shmem_join_anonymous treats with region pointed to by mem (which
   must be non-NULL with page_sz alignment and page_sz*page_cnt
   footprint) as a shmem join with the local join handle join, cstr name
   and mode.

   Other code in the thread group can fd_shmem_join( name, ... ) as
   though the fd_shmem_join_anonymous was done for the mapping join for
   name in the thread group.  This is useful to allow memory regions
   procured out-of-band (e.g. a private anonymous mmap, interfacing with
   custom hardware that provides its own functions for getting access to
   its memory, etc) as a normal join.

   Returns 0 on failure and a strerror friendly error code on failure
   (logs details).  Reasons for failure include EINVAL: bad name (NULL /
   too short / too long / bad characters / already joined), bad join
   (NULL join / already joined), bad mem (NULL mem / unaligned mem /
   already joined), unsupported page_sz, zero page cnt, unsupported mode
   (not FD_SHMEM_JOIN_MODE_{READ_ONLY,READ_WRITE}.

   This will shadow any named shared memory region in the calling thread
   group (but not other thread groups).

   fd_shmem_leave_anonymous is just the inverse of this.  Returns 0 on
   success and a non-zero strerror friendly error code on failure (logs
   details on failure).  On success, if opt_info is non-NULL, *opt_info
   will contain details about the former join (e.g. determine details
   like the original name, mode, mem, page_sz and page_cnt of the join,
   ... opt_info->ref_cnt will be zero).  It is untouched otherwise.
   Reasons for failure include EINVAL: join is obviously not an
   anonymous join with a reference count of 1.

   IMPORTANT!  The join will have a ref cnt of 1 on return from
   join_anonymous.  The final leave of something joined by
   fd_shmem_join_anonymous should done only by fd_shmem_leave_anonymous.
   Conversely, fd_shmem_leave_anonymous should only be used for the
   final leave of any anonymous join. */

int
fd_shmem_join_anonymous( char const * name,
                         int          mode,
                         void *       join,
                         void *       mem,
                         ulong        page_sz,
                         ulong        page_cnt );

int
fd_shmem_leave_anonymous( void *                 join,
                          fd_shmem_join_info_t * opt_info );

/* Administrative APIs ************************************************/

/* Numa topology API */

/* fd_shmem_{numa,cpu}_cnt returns the number of numa nodes / logical
   cpus configured in system.  numa nodes are indexed in
   [0,fd_shmem_numa_cnt()) where fd_shmem_numa_cnt() is in
   [1,FD_SHMEM_NUMA_MAX] and simiarly for logical cpus.  This value is
   determined at thread group boot.  cpu_cnt>=numa_cnt. */

FD_FN_PURE ulong fd_shmem_numa_cnt( void );
FD_FN_PURE ulong fd_shmem_cpu_cnt ( void );

/* fd_shmem_numa_idx returns the closest numa node to the given logical
   cpu_idx.  Given a cpu_idx in [0,fd_shmem_cpu_cnt()), returns a value
   in [0,fd_shmem_numa_cnt()).  Returns ULONG_MAX otherwise.  The cpu ->
   numa mapping is determined at thread group boot. */

FD_FN_PURE ulong fd_shmem_numa_idx( ulong cpu_idx );

/* fd_shmem_cpu_idx returns the smallest cpu_idx of a cpu close to
   numa_idx.  Given a numa_idx in [0,fd_shmem_numa_cnt()), returns a
   value in [0,fd_shmem_cpu_cnt()).  Returns ULONG_MAX otherwise.  The
   numa -> cpu mapping is determined at thread group boot. */

FD_FN_PURE ulong fd_shmem_cpu_idx( ulong numa_idx );

/* fd_shmem_numa_validate returns 0 if all the pages in the page_cnt
   page_sz pages pointed to by mem are on a numa node near cpu_idx and a
   strerror friendly non-zero error code otherwise (logs details).
   Pages in mem will be queried (potentially non-atomically) over some
   point in time between when the call was made and when the call
   returns. */

int
fd_shmem_numa_validate( void const * mem,
                        ulong        page_sz,
                        ulong        page_cnt,
                        ulong        cpu_idx );

/* Creation/destruction APIs */

/* fd_shmem_create_multi creates a shared memory region whose name is
   given by the cstr pointed to by name backed by page_sz pages.  The
   region will consist of sub_cnt subregions, indexed [0,sub_cnt).  Each
   subregion will have page_cnt pages near cpu_idx and the region will
   be the concatentation of these subregions in the order specified.
   mode specifies the permissions for this region (the usual POSIX open
   umask caveats apply).

   Returns 0 on success and an strerror friendly error code on failure
   (also logs extensive details on error).  Reasons for failure include
   name is invalid (EINVAL), page_sz is invalid (EINVAL), page_cnt is
   zero (EINVAL), cnt*page_sz overflows an off_t (EINVAL), open fails
   (errno of the open, e.g. region with the same name and page_sz in the
   thread domain already exists), ftruncate fails (errno of ftruncate,
   e.g. no suitable memory available near cpu_idx), etc.

   Note that each page_sz has its own namespace.  As such, names are
   unique over caller's shared memory domain for a given page_sz.  Names
   can be reused between two different page_sz (and such will correspond
   to two unrelated mappings).  Generally, it is a good idea to have
   unique names over all page_sz but this is not strcitly required (the
   APIs may not work particularly well in this case though).

   fd_shmem_create is a simple wrapper around fd_shmem_create_multi for
   applications that just want to a create a shared memory region that
   contains only 1 subregion. */

int                                                /* 0 on success, strerror compatible error code on failure */
fd_shmem_create_multi( char const *  name,         /* Should point to cstr with a valid name for a shared memory region */
                       ulong         page_sz,      /* Should be a FD_SHMEM_{NORMAL,HUGE,GIGANTIC}_PAGE_SZ */
                       ulong         sub_cnt,      /* Should be positive */
                       ulong const * sub_page_cnt, /* Indexed [0,sub_cnt), 0 < sum(page_cnt)*page_sz <= ULONG_MAX */
                       ulong const * sub_cpu_idx,  /* Indexed [0,sub_cnt), each should be in [0,fd_shmem_cpu_cnt()) */
                       ulong         mode );       /* E.g. 0660 for user rw, group rw, world none */

static inline int
fd_shmem_create( char const * name,
                 ulong        page_sz,
                 ulong        page_cnt,
                 ulong        cpu_idx,
                 ulong        mode ) {
  return fd_shmem_create_multi( name, page_sz, 1UL, &page_cnt, &cpu_idx, mode );
}

/* fd_shmem_unlink removes the name of the page_sz backed shared memory
   region in the thread group's shared memory domain such that it can no
   longer be mapped into a thread group's address space.  The pages used
   for that region will be freed once there are no longer in use by any
   existing thread group.

   Return 0 on success and strerror friendly error code on failure (also
   logs extensive details on error).  Reasons for failure include name
   is invalid (EINVAL), page_sz is invalid (EINVAL), unlink failed
   (error of the unlink, e.g. there is no region backed by page_sz pages
   in the thread group's shared memory domain currently with that name),
   etc. */

int
fd_shmem_unlink( char const * name,
                 ulong        page_sz );

/* fd_shmem_info returns info about the given page_sz backed shared
   memory region in the thread groups' shared memory domain.  If the
   page_sz is zero, the page size will be discovered.  If there are
   multiple regions with different page sizes but the same name, the
   region backed by the largest (non-atomic) page size will be queried.

   Returns 0 on success and a strerror friendly error code on failure
   (logs extensive details on error with the exception of ENOENT / there
   is no region with that name so that existence checks can be done
   without generating excessive log chatter).  Reasons for failure
   include name is invalid (EINVAL), page_sz is invalid (EINVAL), open
   failed (error of the open, e.g. there is no region), stat failed
   (error of the stat) or the mounts have been corrupted (EFAULT).

   On success, if opt_buf is non-NULL, *opt_buf will contain additional
   metadata about the region as observed at some point between when the
   call was made and when it returned.  On failure, *opt_buf not be
   touched. */

int
fd_shmem_info( char const *      name,
               ulong             page_sz,
               fd_shmem_info_t * opt_info );

/* Raw page allocation */

/* fd_shmem_acquire_multi acquires the page_sz pages to create a memory
   region for the private use of the caller's thread group.  The region
   will consist of sub_cnt subregions, indexed [0,sub_cnt).  Each
   subregion will have page_cnt pages near cpu_idx and the region will
   be the concatentation of these subregions in the order specified.
   The lifetime of a page in the allocation is until the thread group
   terminates or the page is explicitly released.  Returns a pointer to
   the location in the local address space of the mapped pages on
   success and NULL on failure (logs details).  Reasons for failure
   include page_sz is invalid, page_cnt is zero, cnt*page_sz overflows
   an off_t, etc.

   fd_shmem_acquire is a simple wrapper around fd_shmem_acquire_multi
   for applications that just want to a create a shared memory region
   that contains only 1 subregion. */

void *
fd_shmem_acquire_multi( ulong         page_sz,       /* Should be a FD_SHMEM_{NORMAL,HUGE,GIGANTIC}_PAGE_SZ */
                        ulong         sub_cnt,       /* Should be positive */
                        ulong const * sub_page_cnt,  /* Indexed [0,sub_cnt), 0 < sum(page_cnt)*page_sz <= ULONG_MAX */
                        ulong const * sub_cpu_idx ); /* Indexed [0,sub_cnt), each should be in [0,fd_shmem_cpu_cnt()) */

static inline void *
fd_shmem_acquire( ulong page_sz,
                  ulong page_cnt,
                  ulong cpu_idx ) {
  return fd_shmem_acquire_multi( page_sz, 1UL, &page_cnt, &cpu_idx );
}

/* fd_shmem_release releases page_cnt page_sz pages of memory allocated
   by fd_shmem_acquire.  This always succeeds from the caller's POV but
   logs details if there is any wonkiness under the hood.  It is fine to
   release subregions of individual previous acquisitions. */

void
fd_shmem_release( void * mem,
                  ulong  page_sz,
                  ulong  page_cnt );

/* Parsing APIs */

/* fd_shmem_name_len:  If name points at a cstr holding a valid name,
   returns strlen( name ) (which is guaranteed to be in
   [1,FD_SHMEM_NAME_MAX)).  Returns 0 otherwise (e.g. name is NULL, name
   is too short, name is too long, name contains characters other than
   [0-9,A-Z,a-z,'_','-','.'], name doesn't start with a [0-9,A-Z,a-z],
   etc). */

FD_FN_PURE ulong fd_shmem_name_len( char const * name );

/* fd_shmem_page_sz_valid:  Returns 1 if page_sz is a valid page size
   or 0 otherwise. */

FD_FN_CONST static inline int
fd_shmem_is_page_sz( ulong page_sz ) {
  return (page_sz==FD_SHMEM_NORMAL_PAGE_SZ) | (page_sz==FD_SHMEM_HUGE_PAGE_SZ) | (page_sz==FD_SHMEM_GIGANTIC_PAGE_SZ);
}

/* fd_cstr_to_shmem_lg_page_sz:  Convert a cstr pointed to by cstr to
   a shmem log2 page size (guaranteed to be one of
   FD_SHMEM_*_LG_PAGE_SZ) via case insensitive comparison with various
   tokens and (if none match) fd_cstr_to_int.  Returns
   FD_SHMEM_UNKNOWN_LG_PAGE_SZ (-1 ... the only negative return
   possible) if it can't figure this out. */

FD_FN_PURE int
fd_cstr_to_shmem_lg_page_sz( char const * cstr );

/* fd_shmem_lg_page_sz_to_cstr:  Return a pointer to a cstr
   corresponding to a shmem log2 page sz.  The pointer is guaranteed to
   be non-NULL with an infinite lifetime.  If lg_page_sz is not a valid
   shmem log2 page size, the cstr will be "unknown".  Otherwise, the
   returned cstr is guaranteed to be compatible with
   fd_cstr_to_shmem_lg_page_sz / fd_cstr_to_shmem_page_sz.  strlen of
   the returned result will be in in [1,FD_SHMEM_PAGE_SZ_CSTR_MAX]. */

FD_FN_CONST char const *
fd_shmem_lg_page_sz_to_cstr( int lg_page_sz );

/* fd_cstr_to_shmem_page_sz:  Convert a cstr pointed to by cstr to a
   shmem page size (guaranteed to be one of the FD_SHMEM_*_PAGE_SZ
   values) via case insensitive comparison with various token and (if
   non match) via fd_cstr_to_ulong.  Returns FD_SHMEM_UNKNOWN_PAGE_SZ
   (0UL, the only non-integral power of 2 return possible) if it can't
   figure this out. */

FD_FN_PURE ulong
fd_cstr_to_shmem_page_sz( char const * cstr );

/* fd_shmem_page_sz_to_cstr:  Return a pointer to a cstr corresponding
   to a shmem page sz.  The pointer is guaranteed to be non-NULL with an
   infinite lifetime.  If page_sz is not a valid shmem page size, the
   cstr will be "unknown".  Otherwise, the returned cstr is guaranteed
   to be compatible with fd_cstr_to_shmem_lg_page_sz /
   fd_cstr_to_shmem_page_sz.  strlen of the returned result in
   [1,FD_SHMEM_PAGE_SZ_CSTR_MAX].  */

FD_FN_CONST char const *
fd_shmem_page_sz_to_cstr( ulong page_sz );

/* These functions are for fd_shmem internal use only. */

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv );

void
fd_shmem_private_halt( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_shmem_fd_shmem_h */

