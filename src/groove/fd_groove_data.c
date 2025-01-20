#include "fd_groove_data.h"

/* fd_groove_data_private_active_displace lockfree atomically sets the
   active superblock for (szc,cgroup) to the superblock at offset
   superblock_off and returns the offset of the previously active
   superblock.  Offsets are relative to volume0.

   Assumes active_slot points in the caller's address space to the
   active superblock offset for (szc,cgroup).  If superblock_off is
   non-zero, further assumes the input superblock is for sizeclass szc,
   has at least one free block and is not in circulation (i.e. neither
   in any active slot nor on any inactive stack such that nobody can
   concurrently allocate from it).

   If this returns zero, there was no active superblock for (szc,cgroup)
   just before it was set to the input superblock.

   If this returns non-zero, the output superblock was the previously
   active superblock.  The output superblock will have at least one free
   block (and possibly growing over time to all blocks free due to
   concurrent frees) and will not be in circulation.

   If superblock_off is non-zero, the input superblock will be in
   circulation as the active superblock for (szc,cgroup) on return.

   If superblock_off is zero, there will be no active superblock for
   (szc,cgroup) on return.

   This is a compiler fence. */

static inline ulong
fd_groove_data_private_active_displace( ulong volatile *     _active_slot,
                                        fd_groove_volume_t * volume0,
                                        ulong                superblock_off ) {
  (void)volume0;
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  superblock_off = FD_ATOMIC_XCHG( _active_slot, superblock_off );
# else
  ulong old      = *_active_slot;
  *_active_slot  = superblock_off;
  superblock_off = old;
# endif
  FD_COMPILER_MFENCE();
  return superblock_off;
}

/* fd_groove_data_private_inactive_push does a lockfree atomic push of
   the superblock at superblock_off relative to volume0 onto the given
   inactive stack.  Assumes all inputs are valid, the inactive stack and
   superblock have the same sizeclass, the superblock is not in
   circulation, and superblock contains at least one free block.  On
   return, superblock will be the top of the inactive stack.  This is a
   compiler fence. */

static inline void
fd_groove_data_private_inactive_push( ulong volatile *     _inactive_stack,
                                      fd_groove_volume_t * volume0,
                                      ulong                superblock_off ) {
  FD_COMPILER_MFENCE();

  fd_groove_data_hdr_t * superblock = (fd_groove_data_hdr_t *)(((ulong)volume0) + superblock_off);

  for(;;) {
    ulong ver_off = *_inactive_stack;

    ulong      ver = ver_off &  (FD_GROOVE_BLOCK_FOOTPRINT-1UL);
    ulong next_off = ver_off & ~(FD_GROOVE_BLOCK_FOOTPRINT-1UL);

    superblock->info = next_off;

    ulong next_ver = (ver+1UL) &  (FD_GROOVE_BLOCK_FOOTPRINT-1UL);

#   if FD_HAS_ATOMIC
    ulong old = FD_ATOMIC_CAS( _inactive_stack, ver_off, next_ver | superblock_off );
#   else
    ulong old = *_inactive_stack;
    *_inactive_stack = fd_ulong_if( old==ver_off, next_ver | superblock_off, old );
#   endif

    if( FD_LIKELY( old==ver_off ) ) break;

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();
}

/* fd_groove_data_private_inactive_pop does a lockfree atomic pop of the
   given inactive stack.  Assumes all inputs are valid.  Returns the
   offset relative to volume0 of the superblock.  The superblock will be
   for the same sizeclass as the inactive stack, will not be in
   circulation and will have at least 1 block free.  If the stack was
   empty when observed, returns 0.  This is a compiler fence. */

static inline ulong
fd_groove_data_private_inactive_pop( ulong volatile *     _inactive_stack,
                                     fd_groove_volume_t * volume0 ) {

  ulong off;

  FD_COMPILER_MFENCE();

  for(;;) {
    ulong ver_off = *_inactive_stack;

    ulong ver = ver_off &  (FD_GROOVE_BLOCK_FOOTPRINT-1UL);
    /**/  off = ver_off & ~(FD_GROOVE_BLOCK_FOOTPRINT-1UL);

    if( FD_UNLIKELY( !off ) ) break;

    fd_groove_data_hdr_t * superblock = (fd_groove_data_hdr_t *)(((ulong)volume0) + off);

    ulong next_ver = (ver+1UL) & (FD_GROOVE_BLOCK_FOOTPRINT-1UL);
    ulong next_off = superblock->info;

#   if FD_HAS_ATOMIC
    ulong old = FD_ATOMIC_CAS( _inactive_stack, ver_off, next_ver | next_off );
#   else
    ulong old = *_inactive_stack;
    *_inactive_stack = fd_ulong_if( old==ver_off, next_ver | next_off, old );
#   endif

    if( FD_LIKELY( old==ver_off ) ) break;

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

  return off;
}

void *
fd_groove_data_new( void * shmem ) {
  fd_groove_data_shmem_t * shdata = (fd_groove_data_shmem_t *)shmem;

  if( FD_UNLIKELY( !shdata ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shdata, fd_groove_data_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_groove_data_footprint();

  if( FD_UNLIKELY( !footprint ) ) { /* currently not possible */
    FD_LOG_WARNING(( "bad configuration" ));
    return NULL;
  }

  memset( shdata, 0, footprint );

  if( FD_UNLIKELY( !fd_groove_volume_pool_new( shdata->volume_pool ) ) ) return NULL; /* logs details (currently not possible) */

  FD_COMPILER_MFENCE();
  shdata->magic = FD_GROOVE_DATA_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_groove_data_t *
fd_groove_data_join( void * ljoin,
                     void * shdata,
                     void * volume0,
                     ulong  volume_max,
                     ulong  cgroup_hint ) {
  volume_max = fd_ulong_if( !!volume_max, volume_max, fd_groove_volume_pool_ele_max_max() );

  fd_groove_data_t *       join = (fd_groove_data_t       *)ljoin;
  fd_groove_data_shmem_t * data = (fd_groove_data_shmem_t *)shdata;

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)join, alignof(fd_groove_data_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_WARNING(( "NULL shdata" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)data, fd_groove_data_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shdata" ));
    return NULL;
  }

  if( FD_UNLIKELY( data->magic!=FD_GROOVE_DATA_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !volume0 ) ) {
    FD_LOG_WARNING(( "NULL volume0" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)volume0, alignof(fd_groove_volume_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned volume0" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_groove_volume_pool_join( join->volume_pool, data->volume_pool, volume0, volume_max ) ) ) /* logs details */
    return NULL;

  join->active_slot    = data->active_slot;
  join->inactive_stack = data->inactive_stack;
  join->cgroup_hint    = cgroup_hint;

  return join;
}

void *
fd_groove_data_leave( fd_groove_data_t * join ) {
  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_groove_volume_pool_leave( join->volume_pool ) ) ) { /* currently not possible */
    FD_LOG_WARNING(( "fd_groove_volume_pool_leave failed" ));
    return NULL;
  }

  return join;
}

void *
fd_groove_data_delete( void * shdata ) {
  fd_groove_data_shmem_t * data = (fd_groove_data_shmem_t *)shdata;

  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_WARNING(( "NULL shdata" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)data, fd_groove_data_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shdata" ));
    return NULL;
  }

  if( FD_UNLIKELY( data->magic!=FD_GROOVE_DATA_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  data->magic = 0UL;
  FD_COMPILER_MFENCE();

  return shdata;
}

/* FIXME: ideally would update the free_objs bit field after writing
   an alloc / superblock data hdr to give non-invasive concurrent
   real-time inspection / diagnostics a strong guarantee all objects
   marked as allocated have valid data hdrs. */

static int
fd_groove_data_private_alloc_obj( fd_groove_data_t * data,
                                  ulong              obj_szc,
                                  ulong *            _obj_off,
                                  ulong *            _obj_idx ) {

  fd_groove_volume_t * _volume0 = (fd_groove_volume_t *)fd_groove_data_volume0( data );

# if FD_GROOVE_PARANOID
  fd_groove_volume_t * _volume1 = (fd_groove_volume_t *)fd_groove_data_volume1( data );
# endif

  ulong obj_cnt       = (ulong)fd_groove_data_szc_cfg[ obj_szc ].obj_cnt;
  ulong obj_footprint = (ulong)fd_groove_data_szc_cfg[ obj_szc ].obj_footprint;
  ulong cgroup_mask   = (ulong)fd_groove_data_szc_cfg[ obj_szc ].cgroup_mask;
  ulong parent_szc    = (ulong)fd_groove_data_szc_cfg[ obj_szc ].parent_szc;

  /* At this point, we are allocating an object from a sizeclass obj_szc
     superblock.  Get the locations of the active slot and inactive
     stack for this sizeclass and our concurrency group. */

  ulong cgroup = data->cgroup_hint & cgroup_mask;

  ulong volatile * _active_slot    = data->active_slot    + obj_szc + FD_GROOVE_DATA_SZC_CNT*cgroup;
  ulong volatile * _inactive_stack = data->inactive_stack + obj_szc;

  ulong superblock_off;

  /* Try to get exclusive access to the active superblock.  Note that
     active superblocks have at least one free obj.  We do this
     test-and-test-and-set style to avoid atomic operations if there is
     no current active_superblock for this cgroup. */

  FD_COMPILER_MFENCE();
  superblock_off = *_active_slot;
  FD_COMPILER_MFENCE();

  if( FD_LIKELY( superblock_off ) ) superblock_off = fd_groove_data_private_active_displace( _active_slot, _volume0, 0UL );

  if( FD_UNLIKELY( !superblock_off ) ) {

    /* At this point, there was no active superblock for our cgroup when
       we observed it.  Try to pop the inactive superblock stack for
       this sizeclass instead.  Note that inactive superblocks also have
       at least one free obj. */

    superblock_off = fd_groove_data_private_inactive_pop( _inactive_stack, _volume0 );

    if( FD_UNLIKELY( !superblock_off ) ) {

      /* At this point, there were no inactive superblocks for this
         sizeclass when we observed the inactive stack.  Try to create a
         new superblock for this sizeclass */

      ulong parent_idx = 0UL; /* reduce risk of uninitialized variable false positives from code analysis tools */

      if( FD_UNLIKELY( parent_szc==FD_GROOVE_DATA_SZC_CNT ) ) { /* Acquire a volume to use for the new superblock */

        int err;
        fd_groove_volume_t * _volume = fd_groove_volume_pool_acquire( data->volume_pool, NULL, 1 /* blocking */, &err );

        if( FD_UNLIKELY( !_volume ) ) {
          if( FD_UNLIKELY( err!=FD_POOL_ERR_EMPTY ) ) {
            FD_LOG_WARNING(( "fd_groove_volume_pool_acquire failed (%i-%s)", err, fd_groove_volume_pool_strerror( err ) ));
            return FD_GROOVE_ERR_CORRUPT;
          }
          return FD_GROOVE_ERR_FULL;
        }

#       if FD_GROOVE_PARANOID
        ulong volume_off = (ulong)_volume - (ulong)_volume0;

        if( FD_UNLIKELY( !( (_volume0<=_volume) & (_volume<_volume1) &
                            fd_ulong_is_aligned( volume_off, FD_GROOVE_VOLUME_FOOTPRINT ) ) ) ) {
          FD_LOG_WARNING(( "volume not at a valid groove data local address" ));
          return FD_GROOVE_ERR_CORRUPT;
        }

        if( FD_UNLIKELY( !( (_volume->magic                         ==~FD_GROOVE_VOLUME_MAGIC  ) &
                            (_volume->idx*FD_GROOVE_VOLUME_FOOTPRINT==volume_off               ) &
                            (_volume->info_sz                       <=FD_GROOVE_VOLUME_INFO_MAX) ) ) ) {
          FD_LOG_WARNING(( "unexpected volume header" ));
          return FD_GROOVE_ERR_CORRUPT;
        }
#       endif

        FD_COMPILER_MFENCE();
        _volume->magic = FD_GROOVE_VOLUME_MAGIC; /* mark volume as potentially containing groove data allocations */
        FD_COMPILER_MFENCE();

      //parent_idx     = 0UL; /* See note above about initialization */
        superblock_off = (ulong)_volume->data - (ulong)_volume0;

      } else { /* Acquire a parent_szc object to use for the new superblock */

        int err = fd_groove_data_private_alloc_obj( data, parent_szc, &superblock_off, &parent_idx ); /* logs details */
        if( FD_UNLIKELY( err ) ) return err;

      }

      ulong superblock_align = FD_GROOVE_DATA_HDR_ALIGN;
      ulong superblock_sz    = FD_GROOVE_BLOCK_FOOTPRINT - FD_GROOVE_DATA_HDR_FOOTPRINT + obj_footprint*obj_cnt;

      fd_groove_data_hdr_t * _superblock_hdr = (fd_groove_data_hdr_t *)(((ulong)_volume0) + superblock_off);

#     if FD_GROOVE_PARANOID
      if( FD_UNLIKELY( !( ((ulong)_volume0<(ulong)_superblock_hdr) & ((ulong)_superblock_hdr<(ulong)_volume1) &
                          fd_ulong_is_aligned( (ulong)_superblock_hdr, FD_GROOVE_BLOCK_ALIGN ) ) ) ) {
        FD_LOG_WARNING(( "superblock not at a valid groove data local address" ));
        return FD_GROOVE_ERR_CORRUPT;
      }
#     endif

      *_superblock_hdr = fd_groove_data_hdr( FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK, parent_idx, obj_szc,
                                             superblock_align, fd_ulong_min( superblock_sz, (1UL<<25)-1UL ), 0UL /* no next */ );
      *(ulong *)(_superblock_hdr+1) = (1UL<<obj_cnt)-1UL; /* mark all objects in superblock as free */
    }
  }

  /* At this point, we have exclusive access to the superblock, there is
     at least one free block in it and only we can allocate blocks from
     it.  (Other threads could free blocks to it concurrently though.)
     Allocate a free block.  If there were more free blocks, put the
     superblock back into circulation as the active superblock for our
     cgroup.  Otherwise, free will put in back into circulation when the
     application frees a block in it.  See fd_alloc.c for details. */

  fd_groove_data_hdr_t * _superblock_hdr = (fd_groove_data_hdr_t *)(((ulong)_volume0) + superblock_off);

  ulong volatile * _free_objs = (ulong volatile *)(_superblock_hdr+1);

# if FD_GROOVE_PARANOID
  if( FD_UNLIKELY( !( ((ulong)_volume0<(ulong)_superblock_hdr) & ((ulong)_superblock_hdr<(ulong)_volume1) &
                      fd_ulong_is_aligned( (ulong)_superblock_hdr, FD_GROOVE_BLOCK_ALIGN ) ) ) ) {
    FD_LOG_WARNING(( "superblock not at a valid groove data local address" ));
    return FD_GROOVE_ERR_CORRUPT;
  }

  fd_groove_data_hdr_t superblock_hdr = *_superblock_hdr;

  ulong superblock_type = fd_groove_data_hdr_type( superblock_hdr );
  ulong superblock_szc  = fd_groove_data_hdr_szc ( superblock_hdr );

  if( FD_UNLIKELY( !((superblock_type==FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK) & (superblock_szc==obj_szc)) ) ) {
    FD_LOG_WARNING(( "unexpected superblock header" ));
    return FD_GROOVE_ERR_CORRUPT;
  }
# endif

  FD_COMPILER_MFENCE();
  ulong free_objs = *_free_objs;
  FD_COMPILER_MFENCE();

# if FD_GROOVE_PARANOID
  if( FD_UNLIKELY( (!free_objs) | (!!fd_ulong_shift_right( free_objs, (int)obj_cnt )) ) ) {
    FD_LOG_WARNING(( "%s", (!free_objs) ? "full superblock in circulation" : "invalid free_objs bit field" ));
    return FD_GROOVE_ERR_CORRUPT;
  }
# endif

  ulong obj = fd_ulong_lsb( free_objs );

  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  free_objs = FD_ATOMIC_FETCH_AND_SUB( _free_objs, obj ); /* Marginally better asm than FETCH_AND_AND */
# else
  free_objs   = *_free_objs;
  *_free_objs = free_objs & ~obj;
# endif
  FD_COMPILER_MFENCE();

# if FD_GROOVE_PARANOID
  if( FD_UNLIKELY( (!free_objs) | (!!fd_ulong_shift_right( free_objs, (int)obj_cnt )) ) ) {
    FD_LOG_WARNING(( "%s", (!free_objs) ? "full superblock in circulation" : "invalid free_objs bit field" ));
    return FD_GROOVE_ERR_CORRUPT;
  }
# endif

  if( FD_LIKELY( free_objs!=obj ) ) {
    ulong displaced_superblock_off = fd_groove_data_private_active_displace( _active_slot, _volume0, superblock_off );
    if( FD_UNLIKELY( displaced_superblock_off ) )
      fd_groove_data_private_inactive_push( _inactive_stack, _volume0, displaced_superblock_off );
  }

  /* At this point, we've allocated the object */

  ulong obj_idx = (ulong)fd_ulong_find_lsb( obj );

  *_obj_off = superblock_off + FD_GROOVE_BLOCK_FOOTPRINT + obj_idx*obj_footprint;
  *_obj_idx = obj_idx;
  return FD_GROOVE_SUCCESS;
}

void *
fd_groove_data_alloc( fd_groove_data_t * data,
                      ulong              align,
                      ulong              sz,
                      ulong              tag,
                      int *              _err ) {

  int stack_err[1];
  if( !_err ) _err = stack_err;

  /* Check input args */

  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_WARNING(( "NULL data" ));
    *_err = FD_GROOVE_ERR_INVAL;
    return NULL;
  }

  align = fd_ulong_if( !!align, align, FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT );
  if( FD_UNLIKELY( !(fd_ulong_is_pow2( align ) & (align<=FD_GROOVE_DATA_ALLOC_ALIGN_MAX)) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    *_err = FD_GROOVE_ERR_INVAL;
    return NULL;
  }

  ulong off_obj   = fd_ulong_align_up( FD_GROOVE_DATA_HDR_FOOTPRINT, align );
  ulong footprint = fd_ulong_align_up( off_obj+sz, FD_GROOVE_BLOCK_ALIGN );

  if( FD_UNLIKELY( !((sz<footprint) & (footprint<=FD_GROOVE_DATA_ALLOC_FOOTPRINT_MAX)) ) ) {
    FD_LOG_WARNING(( "bad sz/align" ));
    *_err = FD_GROOVE_ERR_INVAL;
    return NULL;
  }

  /* Acquire an object from the tightest suitable sizeclass */

  ulong obj_szc = fd_groove_data_szc( footprint );

  ulong obj_off;
  ulong obj_idx;
  int   err = fd_groove_data_private_alloc_obj( data, obj_szc, &obj_off, &obj_idx ); /* logs details */
  if( FD_UNLIKELY( err ) ) {
    *_err = err;
    return NULL;
  }

  /* Carve an allocation into it. */

  fd_groove_data_hdr_t * obj_hdr = (fd_groove_data_hdr_t *)((ulong)fd_groove_volume_pool_shele( data->volume_pool ) + obj_off);

  *obj_hdr = fd_groove_data_hdr( FD_GROOVE_DATA_HDR_TYPE_ALLOC, obj_idx, obj_szc, align, sz, tag );

  *_err = FD_GROOVE_SUCCESS;
  return (void *)((ulong)obj_hdr + off_obj);
}

int
fd_groove_data_private_free( fd_groove_data_t * data,
                             void *             _obj,
                             ulong              exp_type ) {

# if !FD_GROOVE_PARANOID
  (void)exp_type; /* Suppress unused warning if running without paranoia */
# endif

  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_WARNING(( "NULL data" ));
    return FD_GROOVE_ERR_INVAL;
  }

  if( FD_UNLIKELY( !_obj ) ) return FD_GROOVE_ERR_INVAL;

  fd_groove_data_hdr_t * _obj_hdr = fd_groove_data_object_hdr( _obj );

  fd_groove_volume_t * _volume0 = (fd_groove_volume_t *)fd_groove_data_volume0( data );

# if FD_GROOVE_PARANOID
  fd_groove_volume_t * _volume1 = (fd_groove_volume_t *)fd_groove_data_volume1( data );
  if( FD_UNLIKELY( !( ((ulong)_volume0<=(ulong)_obj_hdr                             ) &
                      ((ulong)_obj_hdr< (ulong)_volume1                             ) &
                      (fd_ulong_is_aligned( (ulong)_obj_hdr, FD_GROOVE_BLOCK_ALIGN )) ) ) ) {
    FD_LOG_WARNING(( "object not at a valid groove data local address" ));
    return FD_GROOVE_ERR_INVAL;
  }
# endif

  fd_groove_data_hdr_t obj_hdr = *_obj_hdr;

  ulong obj_type = fd_groove_data_hdr_type( obj_hdr );
  ulong obj_idx  = fd_groove_data_hdr_idx ( obj_hdr );
  ulong obj_szc  = fd_groove_data_hdr_szc ( obj_hdr );

#if FD_GROOVE_PARANOID
  if( FD_UNLIKELY( !((obj_type==exp_type) & (obj_szc<FD_GROOVE_DATA_SZC_CNT)) ) ) {
    FD_LOG_WARNING(( "object does not appear to be a groove data %s",
                     exp_type==FD_GROOVE_DATA_HDR_TYPE_ALLOC ? "alloc" : "superblock" ));
    return FD_GROOVE_ERR_INVAL;
  }
# endif

  obj_szc = fd_ulong_if( obj_type==FD_GROOVE_DATA_HDR_TYPE_ALLOC, obj_szc,
                        (ulong)fd_groove_data_szc_cfg[ obj_szc ].parent_szc );
  ulong obj_cnt       = (ulong)fd_groove_data_szc_cfg[ obj_szc ].obj_cnt;
# if FD_GROOVE_PARANOID
  ulong obj_footprint = (ulong)fd_groove_data_szc_cfg[ obj_szc ].obj_footprint;

  ulong req_align    = fd_groove_data_hdr_align( obj_hdr );
  ulong req_sz       = fd_groove_data_hdr_sz   ( obj_hdr );
  ulong req_footprint =
    fd_ulong_align_up( fd_ulong_align_up( FD_GROOVE_DATA_HDR_FOOTPRINT, req_align ) + req_sz, FD_GROOVE_BLOCK_ALIGN );

  if( FD_UNLIKELY( !( (obj_idx<obj_cnt                 ) &
                      (fd_ulong_is_pow2( req_align )   ) &
                      (req_align<=FD_GROOVE_BLOCK_ALIGN) &
                      (req_footprint<=obj_footprint    ) ) ) ) {
    FD_LOG_WARNING(( "object does not appear to be a groove data %s",
                     exp_type==FD_GROOVE_DATA_HDR_TYPE_ALLOC ? "alloc" : "superblock" ));
    return FD_GROOVE_ERR_INVAL;
  }
# endif

  /* At this point, we appear to have a valid allocated object.  Mark
     the object as not valid and then free it.

     Note: marking the object as dead is optional.  It is mostly a hint
     for diagnostics and for handholding as groove data users shouldn't
     be calling free on it again and alloc doesn't care about the state
     unallocated object memory.  Most useful, marking the object as dead
     can detect double free scenarios.

     The below implementation is not robust against _concurrent_ double
     frees.  Would probably have to use something like ATOMIC_CAS
     semantics on the object header bits to insure nobody freed the
     object behind our back.  And since the free bit field update isn't
     atomic with marking the object as dead, would probably need further
     to do something like mark the object as freeing then update bit
     field and then mark object as dead, etc. */

  fd_groove_data_hdr_t * _superblock_hdr = fd_groove_data_superblock_hdr( _obj, obj_szc, obj_idx );

  ulong volatile * _free_objs = (ulong volatile *)(_superblock_hdr+1);

  ulong free_objs;

  ulong obj = 1UL << obj_idx;

# if FD_GROOVE_PARANOID
  if( FD_UNLIKELY( !( ((ulong)_volume0<(ulong)_superblock_hdr) & ((ulong)_superblock_hdr<(ulong)_obj_hdr) &
                      fd_ulong_is_aligned( (ulong)_superblock_hdr, FD_GROOVE_BLOCK_ALIGN ) ) ) ) {
    FD_LOG_WARNING(( "superblock not at a valid groove data local address" ));
    return FD_GROOVE_ERR_INVAL;
  }

  fd_groove_data_hdr_t superblock_hdr = *_superblock_hdr;

  ulong superblock_type = fd_groove_data_hdr_type( superblock_hdr );
  ulong superblock_szc  = fd_groove_data_hdr_szc ( superblock_hdr );

  if( FD_UNLIKELY( !((superblock_type==FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK) & (superblock_szc==obj_szc)) ) ) {
    FD_LOG_WARNING(( "unexpected superblock header" ));
    return FD_GROOVE_ERR_INVAL;
  }

  FD_COMPILER_MFENCE();
  free_objs = *_free_objs;
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( (free_objs & obj) | fd_ulong_shift_right( free_objs, (int)obj_cnt ) ) ) {
    FD_LOG_WARNING(( "%s", (free_objs & obj) ? "possible concurrent double free" : "invalid free_objs bit field" ));
    return FD_GROOVE_ERR_INVAL;
  }

  FD_COMPILER_MFENCE();
  _obj_hdr->bits = 0UL; /* sets object type to an invalid value */
  FD_COMPILER_MFENCE();
# endif

  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  free_objs = FD_ATOMIC_FETCH_AND_ADD( _free_objs, obj ); /* Marginally better asm than FETCH_AND_OR */
# else
  free_objs   = *_free_objs;
  *_free_objs = free_objs | obj;
# endif
  FD_COMPILER_MFENCE();

# if FD_GROOVE_PARANOID
  if( FD_UNLIKELY( (free_objs & obj) | fd_ulong_shift_right( free_objs, (int)obj_cnt ) ) ) {
    FD_LOG_WARNING(( "%s", (free_objs & obj) ? "possible concurrent double free" : "invalid free_objs bit field" ));
    return FD_GROOVE_ERR_CORRUPT;
  }
# endif

  /* At this point, we've freed the object.  We might need to get the
     object's superblock back into circulation and/or free up excess
     empty superblocks for this sizeclass. */

  ulong free_cnt = (ulong)fd_ulong_popcnt( free_objs );

  if( FD_UNLIKELY( !free_cnt ) ) {

    /* At this point, the superblock was full before we freed it and
       thus not in circulation for use by fd_alloc.  We need to get the
       superblock back into circulation.  There are options for this
       with various subtle tradeoffs.  See fd_alloc.c for details.
       (FIXME: amongst then, consider using allocation cgroup instead of
       the groove data instance's cgroup?) */

    ulong cgroup = fd_groove_data_cgroup_hint( data ) & (ulong)fd_groove_data_szc_cfg[ obj_szc ].cgroup_mask;

    ulong displaced_superblock_off =
      fd_groove_data_private_active_displace( data->active_slot + obj_szc + FD_GROOVE_DATA_SZC_CNT*cgroup,
                                              _volume0, (ulong)_superblock_hdr - (ulong)_volume0 );

    if( FD_UNLIKELY( displaced_superblock_off ) )
      fd_groove_data_private_inactive_push( data->inactive_stack + obj_szc, _volume0, displaced_superblock_off );

  } else if( FD_UNLIKELY( (free_cnt+1UL)==obj_cnt ) ) {

    /* At this point, the superblock was completely empty after we freed
       from it, hence it is still in circulation.  If there is also a
       completely empty superblock on top of the inactive stack, we free
       that one for general reuse.  This is more subtle than it looks,
       see fd_alloc.c for details. */

    ulong volatile * _inactive_stack = data->inactive_stack + obj_szc;

    ulong superblock_off = fd_groove_data_private_inactive_pop( _inactive_stack, _volume0 );

    if( FD_LIKELY( superblock_off ) ) {

      _superblock_hdr = (fd_groove_data_hdr_t *)((ulong)_volume0 + superblock_off);

      _free_objs = (ulong volatile *)(_superblock_hdr+1);

#     if FD_GROOVE_PARANOID
      if( FD_UNLIKELY( !( ((ulong)_volume0<(ulong)_superblock_hdr) & ((ulong)_superblock_hdr<(ulong)_volume1) &
                          fd_ulong_is_aligned( (ulong)_superblock_hdr, FD_GROOVE_BLOCK_ALIGN ) ) ) ) {
        FD_LOG_WARNING(( "superblock not at a valid groove data local address" ));
        return FD_GROOVE_ERR_CORRUPT;
      }

      superblock_type = fd_groove_data_hdr_type( superblock_hdr );
      superblock_szc  = fd_groove_data_hdr_szc ( superblock_hdr );

      if( FD_UNLIKELY( !((superblock_type==FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK) & (superblock_szc==obj_szc)) ) ) {
        FD_LOG_WARNING(( "unexpected superblock header" ));
        return FD_GROOVE_ERR_CORRUPT;
      }
#     endif

      FD_COMPILER_MFENCE();
      free_objs = *_free_objs;
      FD_COMPILER_MFENCE();

#     if FD_GROOVE_PARANOID
      if( FD_UNLIKELY( fd_ulong_shift_right( free_objs, (int)obj_cnt ) ) ) {
        FD_LOG_WARNING(( "invalid free_objs bit field" ));
        return FD_GROOVE_ERR_CORRUPT;
      }
#     endif

      free_cnt = (ulong)fd_ulong_popcnt( free_objs );

      if( FD_LIKELY( free_cnt<obj_cnt ) ) { /* inactive top was not completely empty, return to circulation */

        fd_groove_data_private_inactive_push( _inactive_stack, _volume0, superblock_off );

      } else if( FD_LIKELY( obj_szc<(FD_GROOVE_DATA_SZC_CNT-1UL) ) ) { /* completely empty and should free from parent sb */

        int err = fd_groove_data_private_free( data, _superblock_hdr+1, FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK ); /* offset the hdr */
        if( FD_UNLIKELY( err ) ) {
          FD_LOG_WARNING(( "superblock free failed (%i-%s)", err, fd_groove_strerror( err ) ));
          return FD_GROOVE_ERR_CORRUPT;
        }

      } else { /* completely empty and should free parent volume */

        ulong volume_off = superblock_off - FD_GROOVE_BLOCK_FOOTPRINT;

        fd_groove_volume_t * _volume = (fd_groove_volume_t *)((ulong)_volume0 + volume_off);

#       if FD_GROOVE_PARANOID
        if( FD_UNLIKELY( !( (_volume0<=_volume) & (_volume<_volume1) &
                            fd_ulong_is_aligned( volume_off, FD_GROOVE_VOLUME_FOOTPRINT ) ) ) ) {
          FD_LOG_WARNING(( "volume not at a valid groove data local address" ));
          return FD_GROOVE_ERR_CORRUPT;
        }

        if( FD_UNLIKELY( !( (_volume->magic                         ==FD_GROOVE_VOLUME_MAGIC   ) &
                            (_volume->idx*FD_GROOVE_VOLUME_FOOTPRINT==volume_off               ) &
                            (_volume->info_sz                       <=FD_GROOVE_VOLUME_INFO_MAX) ) ) ) {
          FD_LOG_WARNING(( "unexpected volume header" ));
          return FD_GROOVE_ERR_CORRUPT;
        }
#       endif

        FD_COMPILER_MFENCE();
        _volume->magic = ~FD_GROOVE_VOLUME_MAGIC; /* mark volume as containing no groove data allocations */
        FD_COMPILER_MFENCE();

        int err = fd_groove_volume_pool_release( data->volume_pool, _volume, 1 /* blocking */ );
        if( FD_UNLIKELY( err ) ) {
          FD_LOG_WARNING(( "fd_groove_volume_pool_release failed (%i-%s)", err, fd_groove_volume_pool_strerror( err ) ));
          return FD_GROOVE_ERR_CORRUPT;
        }

      }
    }
  }

  return FD_GROOVE_SUCCESS;
}

#define TEST(c) do {                                                                                \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_GROOVE_ERR_CORRUPT; } \
  } while(0)

/* fd_groove_data_private_verify_superblock verifies the location
   superblock_off (relative to _volume0) seems to contain a valid
   superblock.  groove data is located in the caller's address space at
   [_volume0,_volume1).  exp_szc gives the expected sizeclass for the
   superblock.  If in_circulation is non-zero, the superblock is known
   to be in circulation (i.e. contains at least one free object / is
   either any active or an inactive superblock / is available to alloc
   for allocation).  Assumes _volume0, _volume1, exp_szc and the
   sizeclass configuration are valid. */

static int
fd_groove_data_private_verify_superblock( ulong                      superblock_off,
                                          ulong                      exp_szc,
                                          int                        in_circulation,
                                          int                        verify_descendents,
                                          fd_groove_volume_t const * _volume0,
                                          fd_groove_volume_t const * _volume1 ) {

  /* Verify superblock_off */

  fd_groove_data_hdr_t const * _superblock_hdr = (fd_groove_data_hdr_t const *)(((ulong)_volume0) + superblock_off);

  TEST( ((ulong)_volume0<(ulong)_superblock_hdr) & ((ulong)_superblock_hdr<(ulong)_volume1) );
  TEST( fd_ulong_is_aligned( (ulong)_superblock_hdr, FD_GROOVE_BLOCK_ALIGN ) );

  /* Verify superblock header */

  fd_groove_data_hdr_t hdr = *_superblock_hdr;

  TEST( fd_groove_data_hdr_type( hdr )==FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK );

  ulong szc = fd_groove_data_hdr_szc( hdr );

  TEST( szc==exp_szc );

  ulong obj_cnt       = (ulong)fd_groove_data_szc_cfg[ szc ].obj_cnt;
  ulong obj_footprint = (ulong)fd_groove_data_szc_cfg[ szc ].obj_footprint;
  ulong parent_szc    = (ulong)fd_groove_data_szc_cfg[ szc ].parent_szc;

  ulong parent_obj_idx       = fd_groove_data_hdr_idx( hdr );
  ulong parent_obj_cnt       = (parent_szc<FD_GROOVE_DATA_SZC_CNT) ? (ulong)fd_groove_data_szc_cfg[ parent_szc ].obj_cnt : 1UL;
//ulong parent_obj_footprint = (parent_szc<FD_GROOVE_DATA_SZC_CNT) ? (ulong)fd_groove_data_szc_cfg[ parent_szc ].obj_footprint :
//                             (FD_GROOVE_VOLUME_DATA_MAX - FD_GROOVE_BLOCK_FOOTPRINT);

  TEST( parent_obj_idx < parent_obj_cnt );

  TEST( fd_groove_data_hdr_align( hdr )==FD_GROOVE_DATA_HDR_ALIGN );
  TEST( fd_groove_data_hdr_sz   ( hdr )==
        fd_ulong_min( FD_GROOVE_BLOCK_FOOTPRINT - FD_GROOVE_DATA_HDR_FOOTPRINT + obj_cnt*obj_footprint, (1UL<<25)-1UL ) );

  ulong free_objs = *(ulong const *)(_superblock_hdr+1);

  TEST( !fd_ulong_shift_right( free_objs, (int)obj_cnt ) ); /* valid free obj bit field */
  if( in_circulation ) TEST( !!free_objs ); /* at least 1 free obj for superblocks in circulation */

  /* Verify superblock object headers */

  ulong rem_objs = free_objs ^ fd_ulong_mask_lsb( (int)obj_cnt );
  while( rem_objs ) {
    ulong _idx = (ulong)fd_ulong_find_lsb( rem_objs );

    ulong child_obj_off = superblock_off + FD_GROOVE_BLOCK_FOOTPRINT + _idx*obj_footprint;

    fd_groove_data_hdr_t obj_hdr = *(fd_groove_data_hdr_t const *)((ulong)_volume0 + child_obj_off);

    ulong obj_type = fd_groove_data_hdr_type( obj_hdr );
    ulong obj_idx  = fd_groove_data_hdr_idx ( obj_hdr );
    ulong obj_szc  = fd_groove_data_hdr_szc ( obj_hdr );

    TEST( (obj_type==FD_GROOVE_DATA_HDR_TYPE_ALLOC) | (obj_type==FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK) );
    TEST( obj_idx==_idx                   );
    TEST( obj_szc< FD_GROOVE_DATA_SZC_CNT );

    TEST( fd_ulong_if( obj_type==FD_GROOVE_DATA_HDR_TYPE_ALLOC,
                       obj_szc, (ulong)fd_groove_data_szc_cfg[ obj_szc ].parent_szc )==szc );

    ulong req_align = fd_groove_data_hdr_align( obj_hdr );
    ulong req_sz    = fd_groove_data_hdr_sz   ( obj_hdr );
  //ulong req_info  = fd_groove_data_hdr_info ( obj_hdr );

    ulong req_footprint =
      fd_ulong_align_up( fd_ulong_align_up( FD_GROOVE_DATA_HDR_FOOTPRINT, req_align ) + req_sz, FD_GROOVE_BLOCK_ALIGN );

    TEST( fd_ulong_is_pow2( req_align )        );
    TEST( req_align    <=FD_GROOVE_BLOCK_ALIGN );
    TEST( req_footprint<=obj_footprint         );

    /* Note that recursion depth is bounded due to the finite number of
       sizeclasses and the validation above the children are respecting
       the szc hierarchy above. */

    if( (!!verify_descendents) & (obj_type==FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK) ) /* verify superblock descendents */
      TEST( !fd_groove_data_private_verify_superblock( child_obj_off, obj_szc, 0 /* don't know if in circulation */,
                                                       verify_descendents, _volume0, _volume1 ) );

    rem_objs = fd_ulong_pop_lsb( rem_objs );
  }

  return FD_GROOVE_SUCCESS;
}

int
fd_groove_data_verify( fd_groove_data_t const * data ) {

  /* Verify join */

  TEST( data );
  TEST( fd_ulong_is_aligned( (ulong)data, alignof(fd_groove_data_t) ) );

  fd_groove_volume_pool_t const * pool           = data->volume_pool;
  ulong                   const * active_slot    = data->active_slot;
  ulong                   const * inactive_stack = data->inactive_stack;
  /* cgroup_hint is arbitrary */

  /* Verify volume pool */

  TEST( !fd_groove_volume_pool_verify( pool ) );

  fd_groove_volume_pool_shmem_t const * shpool = (fd_groove_volume_pool_shmem_t const *)fd_groove_volume_pool_shpool_const( pool );

  fd_groove_volume_t const * _volume0   = (fd_groove_volume_t const *)fd_groove_volume_pool_shele_const ( pool );
  ulong                      volume_max =                             fd_groove_volume_pool_ele_max     ( pool );
  fd_groove_volume_t const * _volume1   = _volume0 + volume_max;

  TEST( (!!_volume0) | (!volume_max) );
  TEST( _volume0<=_volume1 );
  TEST( fd_ulong_is_aligned( (ulong)_volume0, FD_GROOVE_VOLUME_ALIGN ) );

  ulong volume_idx = fd_groove_volume_pool_private_vidx_idx( shpool->ver_top );
  while( volume_idx<volume_max ) { /* note: cyclic check already done by volume_pool_verify above */
    TEST( _volume0[ volume_idx ].magic==~FD_GROOVE_VOLUME_MAGIC );
    TEST( _volume0[ volume_idx ].idx  ==volume_idx              );
    volume_idx = fd_groove_volume_pool_private_idx( _volume0[ volume_idx ].next );
  }

  /* Verify data shmem */

  fd_groove_data_shmem_t const * shdata = (fd_groove_data_shmem_t const *)fd_groove_data_shdata_const( data );

  TEST( fd_ulong_is_aligned( (ulong)shdata, fd_groove_data_align() ) );

  TEST( shdata->magic         ==FD_GROOVE_DATA_MAGIC );
  TEST( shdata->volume_pool   ==shpool               );
  TEST( shdata->active_slot   ==active_slot          );
  TEST( shdata->inactive_stack==inactive_stack       );

  /* Verify sizeclass configuration */

  for( ulong szc_idx=0UL; szc_idx<FD_GROOVE_DATA_SZC_CNT; szc_idx++ ) {
    ulong obj_cnt       = (ulong)fd_groove_data_szc_cfg[ szc_idx ].obj_cnt;
    ulong obj_footprint = (ulong)fd_groove_data_szc_cfg[ szc_idx ].obj_footprint;
    ulong cgroup_mask   = (ulong)fd_groove_data_szc_cfg[ szc_idx ].cgroup_mask;
    ulong parent_szc    = (ulong)fd_groove_data_szc_cfg[ szc_idx ].parent_szc;

    ulong cgroup_cnt = cgroup_mask + 1UL;

    ulong superblock_footprint = FD_GROOVE_BLOCK_FOOTPRINT + obj_cnt*obj_footprint;

    ulong parent_obj_footprint = (parent_szc<FD_GROOVE_DATA_SZC_CNT) ?
      (ulong)fd_groove_data_szc_cfg[ parent_szc ].obj_footprint : (FD_GROOVE_VOLUME_DATA_MAX - FD_GROOVE_BLOCK_FOOTPRINT);

    TEST( (1UL<=obj_cnt) & (obj_cnt<=64UL)                                );
    TEST( fd_ulong_is_aligned( obj_footprint, FD_GROOVE_BLOCK_FOOTPRINT ) );
    TEST( fd_ulong_is_pow2( cgroup_cnt )                                  );
    TEST( parent_szc<=FD_GROOVE_DATA_SZC_CNT                              );
    TEST( superblock_footprint <= parent_obj_footprint                    );
  }

  /* Verify all active superblocks */

  for( ulong szc_idx=0UL; szc_idx<FD_GROOVE_DATA_SZC_CNT; szc_idx++ ) {
    ulong cgroup_cnt = (ulong)fd_groove_data_szc_cfg[ szc_idx ].cgroup_mask + 1UL;
    for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
      ulong superblock_off = active_slot[ szc_idx + FD_GROOVE_DATA_SZC_CNT*cgroup_idx ];
      if( !superblock_off ) continue;

      TEST( !fd_groove_data_private_verify_superblock( superblock_off, szc_idx, 1 /* is in circulation */,
                                                       0 /* don't verify children */, _volume0, _volume1 ) );
      fd_groove_data_hdr_t hdr = *(fd_groove_data_hdr_t const *)(((ulong)_volume0) + superblock_off);
      TEST( fd_groove_data_hdr_szc( hdr )==szc_idx );
    }
  }

  /* Verify all inactive superblocks for sizeclass szc_idx */

  for( ulong szc_idx=0UL; szc_idx<FD_GROOVE_DATA_SZC_CNT; szc_idx++ ) {
    ulong superblock_off = inactive_stack[ szc_idx ] & ~(FD_GROOVE_BLOCK_FOOTPRINT-1UL);
    ulong rem            = volume_max*FD_GROOVE_VOLUME_FOOTPRINT / (2UL*FD_GROOVE_BLOCK_FOOTPRINT); /* FIXME: tighter bound? */
    while( superblock_off ) {
      FD_TEST( rem ); rem--; /* avoid cycles */

      TEST( !fd_groove_data_private_verify_superblock( superblock_off, szc_idx, 1 /* is in circulation */,
                                                       0 /* don't verify children */, _volume0, _volume1 ) );
      fd_groove_data_hdr_t hdr = *(fd_groove_data_hdr_t const *)(((ulong)_volume0) + superblock_off);
      TEST( fd_groove_data_hdr_szc( hdr )==szc_idx );

      superblock_off = fd_groove_data_hdr_info( hdr );
    }
  }

  return FD_GROOVE_SUCCESS;
}

int
fd_groove_data_volume_verify( fd_groove_data_t   const * data,
                              fd_groove_volume_t const * _volume ) {

  TEST( data );

  fd_groove_volume_t const * _volume0 = (fd_groove_volume_t const *)fd_groove_data_volume0_const( data );
  fd_groove_volume_t const * _volume1 = (fd_groove_volume_t const *)fd_groove_data_volume1_const( data );

  ulong volume_off = (ulong)_volume - (ulong)_volume0;

  TEST( (_volume0<=_volume) & (_volume<_volume1)                      );
  TEST( fd_ulong_is_aligned( volume_off, FD_GROOVE_VOLUME_FOOTPRINT ) );

  ulong magic   = _volume->magic;
  ulong idx     = _volume->idx;
  ulong info_sz = _volume->info_sz;

  TEST( (magic==FD_GROOVE_VOLUME_MAGIC) | (magic==~FD_GROOVE_VOLUME_MAGIC) );
  TEST( idx*FD_GROOVE_VOLUME_FOOTPRINT==volume_off                         );
  TEST( info_sz                       <=FD_GROOVE_VOLUME_INFO_MAX          );

  if( magic==FD_GROOVE_VOLUME_MAGIC ) {
    ulong superblock_off = volume_off + FD_GROOVE_BLOCK_FOOTPRINT;
    ulong superblock_szc = FD_GROOVE_DATA_SZC_CNT-1UL;
    TEST( !fd_groove_data_private_verify_superblock( superblock_off, superblock_szc, 0 /* don't know if in circulation */,
                                                     1 /* verify children */, _volume0, _volume1 ) );
  }

  return FD_GROOVE_SUCCESS;
}

#undef TEST
