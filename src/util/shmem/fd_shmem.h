#ifndef HEADER_fd_src_util_shmem_fd_shmem_h
#define HEADER_fd_src_util_shmem_fd_shmem_h

/* APIs for NUMA aware, huge and gigantic page aware manipulating shared
   memory regions.  This API is designed to interoperate with the
   fd_shmem_cfg command and control script for host configuration.  fd
   must be booted to use the APIs in this module. */

#include "../log/fd_log.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* FD_SHMEM_{NUMA,CPU}_MAX give the maximum number of numa nodes and
   logical cpus supported by fd_shmem.
   FD_SHMEM_CPU_MAX>=FD_SHMEM_NUMA_MAX>0. */

#define FD_SHMEM_NUMA_MAX (64UL)
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

FD_PROTOTYPES_BEGIN

/* NUMA topology APIs *************************************************/

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

/* fd_shmem_create creates a shared memory region whose name is given
   by the cstr pointed to by name backed by page_sz pages.  The region
   consistent of page_cnt pages near cpu_idx.  mode specifies the
   permissions for this region (the usual POSIX open umask caveats
   apply).  Returns 0 on success and an strerror friendly error code on
   failure (also logs extensive details on error).  Reasons for failure
   include name is invalid (EINVAL), page_sz is invalid (EINVAL),
   page_cnt is zero (EINVAL), cnt*page_sz overflows an off_t (EINVAL),
   open fails (errno of the open, e.g. region with the same name and
   page_sz in the thread domain already exists), ftruncate fails (errno
   of ftruncate, e.g. no suitable memory available near cpu_idx), etc.
   */

int                                     /* 0 on success, strerror compatible error code on failure */
fd_shmem_create( char const * name,     /* Should point to cstr with a valid name for a shared memory region */
                 ulong        page_sz,  /* Should be a FD_SHMEM_{NORMAL,HUGE,GIGANTIC}_PAGE_SZ */
                 ulong        page_cnt, /* Should be positive, page_cnt*page_sz <= ULONG_MAX */
                 ulong        cpu_idx,  /* Should be in [0,fd_shmem_cpu_cnt()) */
                 uint         mode );   /* E.g. 0660 for user rw, group rw, world none */

/* fd_shmem_unlink removes the name of the page_sz backed shared memory
   in the thread groups shared memory domain such that it can no longer
   be mapped into any thread group's address space.  The pages used for
   that region will be freed once there are no longer in use by any
   existing thread group.  Return 0 on success and strerror friendly
   error code on failure (also logs extensive details on error).
   Reasons for failure include name is invalid (EINVAL), page_sz is
   invalid (EINVAL), unlink failed (error of the unlink, e.g. there
   is no region backed by page_sz pages in the thread group's shared
   memory domain currently with that name), etc. */

int
fd_shmem_unlink( char const * name,
                 ulong        page_sz );

/* FIXME: FD_SHMEM INFO */

/* Parsing APIs *******************************************************/

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

FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */

/* These functions are for fd_shmem internal use only. */

FD_PROTOTYPES_BEGIN

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv );

void
fd_shmem_private_halt( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_shmem_fd_shmem_h */

