#include "fd_groove_data.h"

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

/* FIXME: ADD CORRUPTION TESTING */

static ulong
fd_groove_data_alloc_block( fd_groove_data_t * data,
                            ulong              szc,
                            ulong *            _block_idx ) {

  fd_groove_volume_t * volume0 = (fd_groove_volume_t *)fd_groove_volume_pool_shele( data->volume_pool );

  ulong block_footprint = (ulong)fd_groove_data_szc_cfg[ szc ].block_footprint;

  /* At this point, we are allocating a block from a sizeclass szc
     superblock.  Get the locations of the active slot and inactive
     stack for this sizeclass and our concurrency group. */

  ulong cgroup = data->cgroup_hint & (ulong)fd_groove_data_szc_cfg[ szc ].cgroup_mask;

  ulong volatile * _active_slot    = data->active_slot    + szc + FD_GROOVE_DATA_SZC_CNT*cgroup;
  ulong volatile * _inactive_stack = data->inactive_stack + szc;

  ulong superblock_off;

  /* Try to get exclusive access to the active superblock.  Note that
     active superblocks have at least one free block.  We do this
     test-and-test-and-set style to avoid atomic operations if there is
     no current active_superblock for this cgroup. */

  FD_COMPILER_MFENCE();
  superblock_off = *_active_slot;
  FD_COMPILER_MFENCE();
  if( FD_LIKELY( superblock_off ) ) superblock_off = fd_groove_data_active_displace( _active_slot, volume0, 0UL );

  if( FD_UNLIKELY( !superblock_off ) ) {

    /* At this point, there was no active superblock for our cgroup when
       we observed it.  Try to pop the inactive superblock stack for
       this sizeclass instead.  Note that inactive superblocks also have
       at least one free block. */

    superblock_off = fd_groove_data_inactive_pop( _inactive_stack, volume0 );

    if( FD_UNLIKELY( !superblock_off ) ) {

      /* At this point, there were no inactive superblocks for this
         sizeclass when we observed the inactive stack.  Try to create a
         new superblock for this sizeclass */

      ulong parent_szc = (ulong)fd_groove_data_szc_cfg[ szc ].parent_szc;
      ulong parent_idx;

      if( FD_UNLIKELY( parent_szc==FD_GROOVE_DATA_SZC_CNT ) ) { /* Allocate a superblock from the volume pool */

        int                  err;
        fd_groove_volume_t * v = fd_groove_volume_pool_acquire( data->volume_pool, NULL, 1 /* blocking */, &err );
        if( FD_UNLIKELY( !v ) ) {
          if( FD_UNLIKELY( err!=FD_POOL_ERR_EMPTY ) )
            FD_LOG_WARNING(( "fd_groove_volume_pool_acquire failed (%i-%s); attempting to continue",
                             err, fd_groove_volume_pool_strerror( err ) ));
          *_block_idx = 0UL;
          return 0UL;
        }

        parent_idx     = 0UL;
        superblock_off = (ulong)v->data - ((ulong)volume0);

      } else { /* Allocate a szc superblock from the parent superblock*/

        superblock_off = fd_groove_data_alloc_block( data, parent_szc, &parent_idx );
        if( FD_UNLIKELY( !superblock_off ) ) {
          *_block_idx = 0UL;
          return 0UL;
        }

      }

      fd_groove_data_hdr_t * superblock = (fd_groove_data_hdr_t *)(((ulong)volume0) + superblock_off);
      ulong                  block_cnt  = (ulong)fd_groove_data_szc_cfg[ szc ].block_cnt;

      *superblock = fd_groove_data_hdr( FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK, parent_szc, parent_idx, 0UL, 0UL, 0UL /* no next */ );
      *(ulong *)(superblock+1) = (1UL<<block_cnt)-1UL; /* all free */
    }
  }

  /* At this point, we have exclusive access to the superblock, there is
     at least one free block in it and only we can allocate blocks from
     it.  (Other threads could free blocks to it concurrently though.)
     Allocate a free block.  If there were more free blocks, put the
     superblock back into circulation as the active superblock for our
     cgroup.  Otherwise, free will put in back into circulation when the
     application frees a block in it.  See fd_alloc.c for details. */

  fd_groove_data_hdr_t * superblock = (fd_groove_data_hdr_t *)(((ulong)volume0) + superblock_off);

  ulong volatile * _free_blocks = (ulong *)(superblock+1);

  FD_COMPILER_MFENCE();
  ulong free_blocks = *_free_blocks;
  FD_COMPILER_MFENCE();

  ulong block = fd_ulong_lsb( free_blocks );

  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  free_blocks = FD_ATOMIC_FETCH_AND_SUB( _free_blocks, block ); /* Marginally better asm than FETCH_AND_AND */
# else
  free_blocks   = *_free_blocks;
  *_free_blocks = free_blocks & ~block;
# endif
  FD_COMPILER_MFENCE();

  if( FD_LIKELY( free_blocks!=block ) ) {
    ulong displaced_superblock_off = fd_groove_data_active_displace( _active_slot, volume0, superblock_off );
    if( FD_UNLIKELY( displaced_superblock_off ) )
      fd_groove_data_inactive_push( _inactive_stack, volume0, displaced_superblock_off );
  }

  /* At this point, we've allocated the block */

  ulong block_idx = (ulong)fd_ulong_find_lsb( block );

  *_block_idx = block_idx;
  return superblock_off + FD_GROOVE_DATA_BLOCK_FOOTPRINT + block_idx*block_footprint;
}

void *
fd_groove_data_alloc( fd_groove_data_t * data,
                      ulong              align,
                      ulong              sz,
                      ulong              tag,
                      int *              _err ) {

  int stack_err[1]; if( !_err ) _err = stack_err;

  /* Check input args */

  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_WARNING(( "NULL data" ));
    *_err = FD_GROOVE_ERR_INVAL;
    return NULL;
  }

  align = fd_ulong_if( !!align, align, FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT );
  if( FD_UNLIKELY( !(fd_ulong_is_pow2( align ) & (align<=FD_GROOVE_DATA_BLOCK_ALIGN)) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    *_err = FD_GROOVE_ERR_INVAL;
    return NULL;
  }

  ulong off_obj   = fd_ulong_align_up( sizeof(fd_groove_data_hdr_t), align );
  ulong off_pad   = off_obj + sz;
  ulong footprint = fd_ulong_align_up( off_pad, FD_GROOVE_DATA_BLOCK_ALIGN );

  if( FD_UNLIKELY( !((sz<footprint) & (footprint<=FD_GROOVE_DATA_ALLOC_FOOTPRINT_MAX)) ) ) {
    FD_LOG_WARNING(( "bad sz/align" ));
    *_err = FD_GROOVE_ERR_INVAL;
    return NULL;
  }

  /* Acquire a block */

  ulong szc = fd_groove_data_szc( footprint );

  ulong idx;
  ulong off = fd_groove_data_alloc_block( data, szc, &idx );
  if( FD_UNLIKELY( !off ) ) {
    *_err = FD_GROOVE_ERR_FULL;
    return NULL;
  }

  /* Carve an allocation into it. */

  fd_groove_data_hdr_t * block = (fd_groove_data_hdr_t *)((ulong)fd_groove_volume_pool_shele( data->volume_pool ) + off);
  *block = fd_groove_data_hdr( FD_GROOVE_DATA_HDR_TYPE_BLOCK, szc, idx, align, sz, tag );

  *_err = FD_GROOVE_SUCCESS;
  return (void *)((ulong)block + off_obj);
}

void
fd_groove_data_free( fd_groove_data_t * data,
                     void *             obj ) {

  if( FD_UNLIKELY( !obj ) ) return;

  if( FD_UNLIKELY( !data ) ) { FD_LOG_WARNING(( "NULL data" )); return; }

  fd_groove_data_hdr_t * _block = fd_groove_data_block_hdr( obj );

  fd_groove_data_hdr_t hdr = *_block;

  ulong szc = fd_groove_data_hdr_szc( hdr );
  ulong idx = fd_groove_data_hdr_idx( hdr );

  ulong cgroup    = data->cgroup_hint & (ulong)fd_groove_data_szc_cfg[ szc ].cgroup_mask;
  ulong block_cnt = (ulong)fd_groove_data_szc_cfg[ szc ].block_cnt;

  fd_groove_volume_t * volume0         = (fd_groove_volume_t *)fd_groove_volume_pool_shele( data->volume_pool );
  ulong volatile *     _active_slot    = data->active_slot    + szc + FD_GROOVE_DATA_SZC_CNT*cgroup;
  ulong volatile *     _inactive_stack = data->inactive_stack + szc;

  fd_groove_data_hdr_t * superblock     = fd_groove_data_superblock_hdr( obj, szc, idx );
  ulong                  superblock_off = (ulong)superblock - (ulong)volume0;
  ulong                  block          = 1UL<<idx;

  /* Free the block */

  ulong volatile * _free_blocks = (ulong *)(superblock+1);

  ulong free_blocks;

  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  free_blocks = FD_ATOMIC_FETCH_AND_ADD( _free_blocks, block ); /* Marginally better asm than FETCH_AND_OR */
# else
  free_blocks   = *_free_blocks;
  *_free_blocks = free_blocks | block;
# endif
  FD_COMPILER_MFENCE();

  ulong free_cnt = (ulong)fd_ulong_popcnt( free_blocks );

  if( FD_UNLIKELY( !free_cnt ) ) {

    /* At this point, the superblock was full before we freed it.  We
       need to put the superblock back into circulation.  This is more
       subtle than it looks, see fd_alloc.c for details. */

    superblock_off = fd_groove_data_active_displace( _active_slot, volume0, superblock_off );

    if( FD_UNLIKELY( superblock_off ) ) fd_groove_data_inactive_push( _inactive_stack, volume0, superblock_off );

  } else if( FD_UNLIKELY( (free_cnt+1UL)==block_cnt ) ) {

    /* At this point, the superblock was completely empty after we freed
       from it, hence it is still in circulation.  If there is also a
       complete empty superblock on top of the inactive stack, we free
       that one for general reuse.  This is more subtle than it looks,
       see fd_alloc.c for details. */

    superblock_off = fd_groove_data_inactive_pop( _inactive_stack, volume0 );

    if( FD_LIKELY( superblock_off ) ) {

      superblock = (fd_groove_data_hdr_t *)((ulong)volume0 + superblock_off);
      _free_blocks = (ulong *)(superblock+1);

      FD_COMPILER_MFENCE();
      free_blocks = *_free_blocks;
      FD_COMPILER_MFENCE();

      free_cnt = (ulong)fd_ulong_popcnt( free_blocks );

      if( FD_LIKELY( free_cnt<block_cnt ) ) { /* inactive top was not completely empty, return to circulation */

        fd_groove_data_inactive_push( _inactive_stack, volume0, superblock_off );

      } else if( FD_LIKELY( szc<(FD_GROOVE_DATA_SZC_CNT-1UL) ) ) { /* completely empty and should free from parent sb */

        fd_groove_data_free( data, superblock+1 ); /* offset the hdr */

      } else { /* completely empty and should free entire volume */

/* FIXME: NEED TO TEST THIS CODE PATH */
        fd_groove_volume_t * volume = (fd_groove_volume_t *)((ulong)volume0 + superblock_off - FD_GROOVE_DATA_BLOCK_FOOTPRINT);
        int err = fd_groove_volume_pool_release( data->volume_pool, volume, 1 /* blocking */ );
        if( FD_UNLIKELY( err ) )
          FD_LOG_WARNING(( "fd_groove_volume_pool_release failed (%i-%s)", err, fd_groove_volume_pool_strerror( err ) ));

      }
    }
  }
}
