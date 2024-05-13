#if FD_HAS_HOSTED
#define _GNU_SOURCE
#endif

#include "fd_shmem_private.h"

#if FD_HAS_HOSTED

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/random.h>

/* fd_shmem_private_key converts the cstr pointed to by name into a
   valid key and stores it at the location pointed to by key assumed
   valid).  Returns key on success and NULL on failure (i.e. name does
   not point to a valid shmem region name).  All bytes of key will be
   unambiguously initialized so there is no issue with using things like
   memcmp to compare keys, etc. */

static inline fd_shmem_private_key_t *
fd_shmem_private_key( fd_shmem_private_key_t * key,
                      char const *             name ) {
  ulong len = fd_shmem_name_len( name );
  if( FD_UNLIKELY( !len ) ) return NULL;
  fd_memset( key->cstr, 0, FD_SHMEM_NAME_MAX );
  fd_memcpy( key->cstr, name, len );
  return key;
}

static fd_shmem_private_key_t const fd_shmem_private_key_null; /* Will be zeros at thread group start */

#define FD_SHMEM_PRIVATE_MAP_LG_SLOT_CNT (8)
#define FD_SHMEM_PRIVATE_MAP_SLOT_CNT    (1UL<<FD_SHMEM_PRIVATE_MAP_LG_SLOT_CNT)
FD_STATIC_ASSERT( FD_SHMEM_JOIN_MAX < FD_SHMEM_PRIVATE_MAP_SLOT_CNT, increase_lg_slot_count );

#define MAP_NAME              fd_shmem_private_map
#define MAP_T                 fd_shmem_join_info_t
#define MAP_LG_SLOT_CNT       FD_SHMEM_PRIVATE_MAP_LG_SLOT_CNT
#define MAP_KEY_T             fd_shmem_private_key_t
#define MAP_KEY_NULL          fd_shmem_private_key_null
#define MAP_KEY_INVAL(k)      (!((k).cstr[0]))
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).cstr, (k1).cstr, FD_SHMEM_NAME_MAX ))
#define MAP_KEY_EQUAL_IS_SLOW (1)
#define MAP_KEY_HASH(k)       ((uint)fd_hash( 0UL, (k).cstr, FD_SHMEM_NAME_MAX ))
#include "../tmpl/fd_map.c"

/* fd_shmem_private_map_query_by_{join,addr} are some extra
   fd_shmem_private_map APIs allow looking up the join info for a region
   by its join handle and/or by a pointer at a byte in the region int
   the thread group's local address space.  These aren't algorithmically
   efficient but aren't expected to be and are plenty fast in normal use
   anyway. */

static inline fd_shmem_join_info_t *
fd_shmem_private_map_query_by_join( fd_shmem_join_info_t * map,
                                    void const *           join,
                                    fd_shmem_join_info_t * def ) {
  for( ulong slot_idx=0UL; slot_idx<FD_SHMEM_PRIVATE_MAP_SLOT_CNT; slot_idx++ )
    if( ((!fd_shmem_private_map_key_inval( map[slot_idx].key )) & (map[slot_idx].join==join)) ) return &map[slot_idx];
  return def;
}

static inline fd_shmem_join_info_t *
fd_shmem_private_map_query_by_addr( fd_shmem_join_info_t * map,
                                    ulong                  a0,
                                    ulong                  a1,      /* Assumes a1>=a0 */
                                    fd_shmem_join_info_t * def ) __attribute__((no_sanitize("unsigned-integer-overflow"))) {
  for( ulong slot_idx=0UL; slot_idx<FD_SHMEM_PRIVATE_MAP_SLOT_CNT; slot_idx++ ) {
    ulong j0 = (ulong)map[slot_idx].shmem;
    ulong j1 = j0 + map[slot_idx].page_sz*map[slot_idx].page_cnt - 1UL;
    if( ((!fd_shmem_private_map_key_inval( map[slot_idx].key )) & (a1>=j0) & (a0<=j1)) ) return &map[slot_idx];
  }
  return def;
}

/*
 * fd_shmem_private_grab_region will attempt to map a region at the passed 
 * address with the passed size. If the return value of `mmap` equals the 
 * passed address this means the area of memory was unmapped previously and
 * we have succesfully "grabbed" the region. We can then call `mmap` with 
 * MAP_FIXED over the region and be certain no corruption occurs. If the 
 * return value of `mmap` does not return the passed address this means that 
 * the passed region is already atleast partially mapped and we cannot grab it.
 */
static int
fd_shmem_private_grab_region( ulong addr,
                              ulong size ) {
  void *mmap_ret;
  int err;

  mmap_ret = mmap( (void*)addr, size, PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0 );

  if( mmap_ret == MAP_FAILED )
    return 0;

  /* Only call munmap on failure case. On success we want to keep the mapping */
  if( (ulong)mmap_ret != addr ) {
    err = munmap( mmap_ret, size );
    if ( err == -1 ) {
      FD_LOG_ERR(( "failed to unmap temporary mapping, munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    return 0;
  }

  return 1;
}

static ulong
fd_shmem_private_get_random_mappable_addr( ulong size, 
                                           ulong page_size ) {
  ulong ret_addr = 0;

  /* Failure is unlikely, 1000 iterations should guarantee success */
  for( ulong i = 0; i < 1000; i++ ) {
    long n = getrandom( &ret_addr, sizeof(ret_addr), 0 );
    if( FD_UNLIKELY( n!=sizeof(ret_addr) ) ) FD_LOG_ERR(( "could not generate random address, getrandom() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    /* The type of region determines the alignment we need for the region */
    if( page_size == FD_SHMEM_GIGANTIC_PAGE_SZ ) 
      ret_addr &= FD_SHMEM_PRIVATE_MMAP_GIGANTIC_MASK;
    else if( page_size == FD_SHMEM_HUGE_PAGE_SZ )
      ret_addr &= FD_SHMEM_PRIVATE_MMAP_HUGE_MASK;
    else
      ret_addr &= FD_SHMEM_PRIVATE_MMAP_NORMAL_MASK;

    if( fd_shmem_private_grab_region( ret_addr, size ) ) {
      return ret_addr;
    }
  }
  
  FD_LOG_ERR(( "unable to find random address for memory map after 1000 attempts" ));
  return (ulong)MAP_FAILED;
}

static fd_shmem_join_info_t fd_shmem_private_map[ FD_SHMEM_PRIVATE_MAP_SLOT_CNT ]; /* Empty on thread group start */
static ulong                fd_shmem_private_map_cnt;                              /* 0 on thread group start */

void *
fd_shmem_join( char const *               name,
               int                        mode,
               fd_shmem_joinleave_func_t  join_func,
               void *                     context,
               fd_shmem_join_info_t *     opt_info ) {

  /* Check input args */

  fd_shmem_private_key_t key;
  if( FD_UNLIKELY( !fd_shmem_private_key( &key, name ) ) ) {
    FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" ));
    return NULL;
  }

  if( FD_UNLIKELY( !( (mode==FD_SHMEM_JOIN_MODE_READ_ONLY) | (mode==FD_SHMEM_JOIN_MODE_READ_WRITE) ) ) ) {
    FD_LOG_WARNING(( "unsupported join mode (%i) for %s", mode, name ));
    return NULL;
  }

  FD_SHMEM_LOCK;

  /* Query for an existing mapping */

  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query( fd_shmem_private_map, key, NULL );
  if( join_info ) {
    if( FD_UNLIKELY( join_info->ref_cnt<0L ) ) {
      FD_LOG_WARNING(( "join/leave circular dependency detected for %s", name ));
      FD_SHMEM_UNLOCK;
      return NULL;
    }
    join_info->ref_cnt++;

    if( opt_info ) *opt_info = *join_info;
    FD_SHMEM_UNLOCK;
    return join_info->join;
  }

  /* Not currently mapped.  See if we have enough room.  */

  if( FD_UNLIKELY( fd_shmem_private_map_cnt>=FD_SHMEM_JOIN_MAX ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "too many concurrent joins for %s", name ));
    return NULL;
  }

  /* We have enough room for it.  Try to map the memory. */

  fd_shmem_info_t shmem_info[1];
  if( FD_UNLIKELY( fd_shmem_info( name, 0UL, shmem_info ) ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", name ));
    return NULL;
  }
  ulong page_sz  = shmem_info->page_sz;
  ulong page_cnt = shmem_info->page_cnt;
  ulong sz       = page_sz*page_cnt;
  int   rw       = (mode==FD_SHMEM_JOIN_MODE_READ_WRITE);

  /* Map the region into our address space. */

  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int fd = open( fd_shmem_private_path( name, page_sz, path ), rw ? O_RDWR : O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "open(\"%s\",%s,0) failed (%i-%s)", path, rw ? "O_RDWR" : "O_RDONLY", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  /* Generate a random address that we are guaranteed to be able to map */
  ulong rand_addr = fd_shmem_private_get_random_mappable_addr( sz, page_sz );

  /* Note that MAP_HUGETLB and MAP_HUGE_* are implied by the mount point */
  void * shmem = mmap( (void*)rand_addr, sz, rw ? (PROT_READ|PROT_WRITE) : PROT_READ, MAP_SHARED | MAP_FIXED, fd, (off_t)0 );
  
  int mmap_errno = errno;
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  /* Validate the mapping */

  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,%s,MAP_SHARED,\"%s\",0) failed (%i-%s)",
                     sz>>10, rw ? "PROT_READ|PROT_WRITE" : "PROT_READ", path, mmap_errno, fd_io_strerror( mmap_errno ) ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, page_sz ) ) ) {
    if( FD_UNLIKELY( munmap( shmem, sz ) ) )
      FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                       path, sz>>10, errno, fd_io_strerror( errno ) ));
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "misaligned memory mapping for \"%s\"\n\t"
                     "This thread group's hugetlbfs mount path (--shmem-path / FD_SHMEM_PATH):\n\t"
                     "\t%s\n\t"
                     "has probably been corrupted and needs to be redone.\n\t"
                     "See 'bin/fd_shmem_cfg help' for more information.",
                     path, fd_shmem_private_base ));
    return NULL;
  }

  /* Lock this region in DRAM to prevent it going to swap and (try) to
     keep the virtual to physical DRAM mapping fixed for the join
     duration.  Also advise the kernel to not dump this region to avoid
     large shared mappings in concurrent use by multiple processes
     destroying the system with core files if a bunch of thread using
     this mapping seg fault concurrently. */

  if( FD_UNLIKELY( fd_numa_mlock( shmem, sz ) ) )
    FD_LOG_WARNING(( "fd_numa_mlock(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                     path, sz>>10, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( madvise( shmem, sz, MADV_DONTDUMP ) ) )
    FD_LOG_WARNING(( "madvise(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                     path, sz>>10, errno, fd_io_strerror( errno ) ));

  /* We have mapped the region.  Try to complete the join.  Note:
     map_query above and map_insert could be combined to improve
     efficiency further here (and eliminate the paranoid if check in the
     process). */

  join_info = fd_shmem_private_map_insert( fd_shmem_private_map, key );
  if( FD_UNLIKELY( !join_info ) ) /* should be impossible */
    FD_LOG_ERR(( "unable to insert region \"%s\" (internal error)", name ));
  fd_shmem_private_map_cnt++;

  join_info->ref_cnt  = -1L;  /* Mark join/leave in progress so we can detect circular join/leave dependencies */
  join_info->join     = NULL; /* Overridden below */
  join_info->shmem    = shmem;
  join_info->page_sz  = page_sz;
  join_info->page_cnt = page_cnt;
  join_info->mode     = mode;
  /* join_info->hash handled by insert */
  /* join_info->name "                 */
  /* join_info->key  "                 */

  void * join = join_func ? join_func( context, join_info ): shmem; /* Reset by the join func if provided */
  if( FD_UNLIKELY( !join ) ) {
    fd_shmem_private_map_remove( fd_shmem_private_map, join_info );
    fd_shmem_private_map_cnt--;
    if( FD_UNLIKELY( munmap( shmem, sz ) ) )
      FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                       name, sz>>10, errno, fd_io_strerror( errno ) ));
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "unable to join region \"%s\"", name ));
    return NULL;
  }
  join_info->ref_cnt = 1UL;
  join_info->join    = join;

  if( opt_info ) *opt_info = *join_info;
  FD_SHMEM_UNLOCK;
  return join;
}

int
fd_shmem_leave( void *                    join,
                fd_shmem_joinleave_func_t leave_func,
                void *                    context ) {
  if( FD_UNLIKELY( !join ) ) { FD_LOG_WARNING(( "NULL join" )); return 1; }

  FD_SHMEM_LOCK;

  if( FD_UNLIKELY( !fd_shmem_private_map_cnt ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join is not a current join" ));
    return 1;
  }
  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query_by_join( fd_shmem_private_map, join, NULL );
  if( FD_UNLIKELY( !join_info ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join is not a current join" ));
    return 1;
  }

  long ref_cnt = join_info->ref_cnt;
  if( join_info->ref_cnt>1L ) {
    join_info->ref_cnt = ref_cnt-1L;
    FD_SHMEM_UNLOCK;
    return 0;
  }

  if( join_info->ref_cnt==-1L ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join/leave circular dependency detected for %s", join_info->name ));
    return 1;
  }

  if( FD_UNLIKELY( join_info->ref_cnt!=1L ) ) /* Should be impossible */
    FD_LOG_WARNING(( "unexpected ref count for %s; attempting to continue", join_info->name ));

  char const * name     = join_info->name;     /* Just in case leave_func clobbers */
  void *       shmem    = join_info->shmem;    /* " */
  ulong        page_sz  = join_info->page_sz;  /* " */
  ulong        page_cnt = join_info->page_cnt; /* " */

  if( leave_func ) {
    join_info->ref_cnt = -1L; /* Mark join/leave is in progress so we can detect join/leave circular dependencies */
    leave_func( context, join_info );
  }

  int error = 0;
  ulong sz = page_sz*page_cnt;
  if( FD_UNLIKELY( munmap( shmem, sz ) ) ) {
    FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                     name, sz>>10, errno, fd_io_strerror( errno ) ));
    error = 1;
  }

  fd_shmem_private_map_remove( fd_shmem_private_map, join_info );
  fd_shmem_private_map_cnt--;
  FD_SHMEM_UNLOCK;
  return error;
}

int
fd_shmem_join_query_by_name( char const *           name,
                             fd_shmem_join_info_t * opt_info ) {
  fd_shmem_private_key_t key;
  if( FD_UNLIKELY( !fd_shmem_private_key( &key, name ) ) ) return EINVAL;

  FD_SHMEM_LOCK;

  if( !fd_shmem_private_map_cnt ) { FD_SHMEM_UNLOCK; return ENOENT; }
  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query( fd_shmem_private_map, key, NULL );
  if( !join_info ) { FD_SHMEM_UNLOCK; return ENOENT; }
  if( opt_info ) *opt_info = *join_info;

  FD_SHMEM_UNLOCK;
  return 0;
}

int
fd_shmem_join_query_by_join( void const *           join,
                             fd_shmem_join_info_t * opt_info ) {
  if( FD_UNLIKELY( !join ) ) return EINVAL;

  FD_SHMEM_LOCK;

  if( !fd_shmem_private_map_cnt ) { FD_SHMEM_UNLOCK; return ENOENT; }
  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query_by_join( fd_shmem_private_map, join, NULL );
  if( FD_UNLIKELY( !join_info ) ) { FD_SHMEM_UNLOCK; return ENOENT; }
  if( opt_info ) *opt_info = *join_info;

  FD_SHMEM_UNLOCK;
  return 0;
}

int
fd_shmem_join_query_by_addr( void const *           addr,
                             ulong                  sz,
                             fd_shmem_join_info_t * opt_info ) {
  if( FD_UNLIKELY( !sz ) ) return ENOENT; /* empty range */
  ulong a0 = (ulong)addr;
  ulong a1 = a0+sz-1UL;
  if( FD_UNLIKELY( a1<a0 ) ) return EINVAL; /* cyclic wrap range */

  FD_SHMEM_LOCK;

  if( !fd_shmem_private_map_cnt ) { FD_SHMEM_UNLOCK; return ENOENT; }
  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query_by_addr( fd_shmem_private_map, a0, a1, NULL );
  if( FD_UNLIKELY( !join_info ) ) { FD_SHMEM_UNLOCK; return ENOENT; }
  if( opt_info ) *opt_info = *join_info;

  FD_SHMEM_UNLOCK;
  return 0;
}

int
fd_shmem_join_anonymous( char const * name,
                         int          mode,
                         void *       join,
                         void *       mem,
                         ulong        page_sz,
                         ulong        page_cnt ) {

  /* Check input args */

  fd_shmem_private_key_t key;
  if( FD_UNLIKELY( !fd_shmem_private_key( &key, name ) ) ) {
    FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !( (mode==FD_SHMEM_JOIN_MODE_READ_ONLY) | (mode==FD_SHMEM_JOIN_MODE_READ_WRITE) ) ) ) {
    FD_LOG_WARNING(( "unsupported join mode (%i) for %s", mode, name ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) {
    FD_LOG_WARNING(( "unsupported page_sz (%lu)", page_sz ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !page_cnt ) ) {
    FD_LOG_WARNING(( "unsupported page_sz (%lu)", page_sz ));
    return EINVAL;
  }

  if( FD_UNLIKELY( page_cnt > (ULONG_MAX/page_sz) ) ) {
    FD_LOG_WARNING(( "too large page cnt (%lu)", page_cnt ));
    return EINVAL;
  }

  ulong sz = page_cnt*page_sz;
  ulong a0 = (ulong)mem;
  ulong a1 = a0 + sz-1UL;
  if( FD_UNLIKELY( a1<a0 ) ) {
    FD_LOG_WARNING(( "bad mem range" ));
    return EINVAL;
  }

  FD_SHMEM_LOCK;

  /* Query for an existing mapping */

  fd_shmem_join_info_t * join_info;

  join_info = fd_shmem_private_map_query( fd_shmem_private_map, key, NULL );
  if( FD_UNLIKELY( join_info ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "%s already joined", name ));
    return EINVAL;
  }

  join_info = fd_shmem_private_map_query_by_join( fd_shmem_private_map, join, NULL );
  if( FD_UNLIKELY( join_info ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "%s join handle already in use", name ));
    return EINVAL;
  }

  join_info = fd_shmem_private_map_query_by_addr( fd_shmem_private_map, a0, a1, NULL );
  if( FD_UNLIKELY( join_info ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "%s join memory already mapped", name ));
    return EINVAL;
  }

  /* Not currently mapped.  See if we have enough room.  */

  if( FD_UNLIKELY( fd_shmem_private_map_cnt>=FD_SHMEM_JOIN_MAX ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "too many concurrent joins for %s", name ));
    return EINVAL;
  }

  /* We have enough room for it.  Try to "map" the memory. */

  fd_shmem_info_t shmem_info[1];
  if( FD_UNLIKELY( !fd_shmem_info( name, 0UL, shmem_info ) ) )
    FD_LOG_WARNING(( "anonymous join to %s will shadow an existing shared memory region in this thread group; "
                     "attempting to continue", name ));

  join_info = fd_shmem_private_map_insert( fd_shmem_private_map, key );
  if( FD_UNLIKELY( !join_info ) ) /* should be impossible */
    FD_LOG_ERR(( "unable to insert region \"%s\" (internal error)", name ));
  fd_shmem_private_map_cnt++;

  join_info->ref_cnt  = 1L;
  join_info->join     = join;
  join_info->shmem    = mem;
  join_info->page_sz  = page_sz;
  join_info->page_cnt = page_cnt;
  join_info->mode     = mode;
  /* join_info->hash handled by insert */
  /* join_info->name "                 */
  /* join_info->key  "                 */

  FD_SHMEM_UNLOCK;
  return 0;
}

int
fd_shmem_leave_anonymous( void *                 join,
                          fd_shmem_join_info_t * opt_info ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return EINVAL;
  }

  FD_SHMEM_LOCK;

  if( FD_UNLIKELY( !fd_shmem_private_map_cnt ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join is not a current join" ));
    return EINVAL;
  }

  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query_by_join( fd_shmem_private_map, join, NULL );
  if( FD_UNLIKELY( !join_info ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join is not a current join" ));
    return EINVAL;
  }

  if( FD_UNLIKELY( join_info->ref_cnt!=1L ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join ref_cnt is not 1" ));
    return EINVAL;
  }

  if( opt_info ) {
    *opt_info = *join_info;
    opt_info->ref_cnt = 0L;
  }

  fd_shmem_private_map_remove( fd_shmem_private_map, join_info );
  fd_shmem_private_map_cnt--;
  FD_SHMEM_UNLOCK;
  return 0;
}

#endif
