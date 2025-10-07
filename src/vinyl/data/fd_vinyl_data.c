#include "fd_vinyl_data.h"

FD_FN_PURE static inline ulong /* FIXME: FD_FN_CONST? (i.e. szc_cfg is const) */
fd_vinyl_data_szc_all_blocks( ulong szc ) {
  /* sigh ... deal with wide shift UB (obj_cnt in [1,64]) */
  return ((1UL << ((int)fd_vinyl_data_szc_cfg[ szc ].obj_cnt - 1)) << 1) - 1UL;
}

FD_FN_CONST static inline ulong
fd_vinyl_data_obj_off( void const *                laddr0,
                       fd_vinyl_data_obj_t const * obj ) {
  return fd_ulong_if( !!obj, (ulong)obj - (ulong)laddr0, 0UL );
}

FD_FN_CONST static inline fd_vinyl_data_obj_t *
fd_vinyl_data_obj_ptr( void const * laddr0,
                       ulong        off ) {
  return (fd_vinyl_data_obj_t *)fd_ulong_if( !!off, (ulong)laddr0 + off, 0UL );
}

FD_FN_PURE static int
fd_vinyl_data_superblock_test( fd_vinyl_data_t const *     data,
                               fd_vinyl_data_obj_t const * superblock,
                               ulong                       szc ) {

  /* Test that superblock seems to be point to a valid location for a
     superblock that holds szc objects. */

  ulong sb0 = (ulong)superblock;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( sb0, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) return FD_VINYL_ERR_CORRUPT; /* misaligned */

  ulong parent_szc = fd_vinyl_data_szc_cfg[ szc ].parent_szc;

  ulong vol_idx = (sb0 - (ulong)data->vol) / FD_VINYL_DATA_VOL_FOOTPRINT;
  if( FD_UNLIKELY( vol_idx >= data->vol_cnt ) ) return FD_VINYL_ERR_CORRUPT; /* not in a volume */

  ulong obj_cnt       = (ulong)fd_vinyl_data_szc_cfg[ szc ].obj_cnt;
  ulong obj_footprint = fd_vinyl_data_szc_obj_footprint( szc );

  ulong sb1  = sb0 + sizeof(fd_vinyl_data_obj_t) + obj_cnt*obj_footprint;

  int not_volume_sb = parent_szc<FD_VINYL_DATA_SZC_CNT;

  ulong vol0 = (ulong)&data->vol[ vol_idx ];
  ulong vol1 = vol0 + FD_VINYL_DATA_VOL_FOOTPRINT;

  if( FD_LIKELY( not_volume_sb ) ) vol0 += sizeof(fd_vinyl_data_obj_t); /* only volume sb can be at head of volume */
  else {
    if( FD_UNLIKELY( sb0!=vol0                ) ) return FD_VINYL_ERR_CORRUPT; /* vol sb not a vol */
    if( FD_UNLIKELY( superblock->idx!=vol_idx ) ) return FD_VINYL_ERR_CORRUPT; /* mismatched idx */
  }

  if( FD_UNLIKELY( !((vol0<=sb0) & (sb1<=vol1) ) ) ) return FD_VINYL_ERR_CORRUPT; /* out of bounds */

  if( FD_LIKELY( not_volume_sb ) && FD_UNLIKELY( superblock->idx >= fd_vinyl_data_szc_cfg[ parent_szc ].obj_cnt ) )
    return FD_VINYL_ERR_CORRUPT;

  /* At this point, superblock is at an appropriate position.  Test that
     its type and szc correspond to a superblock for objects of this
     size class and that free_blocks doesn't have any stray bits set in
     it.

     Note that we can't next_off fully here because we don't know if SB
     is on the inactive stack.  Even without testing here, it is fully
     tested because we test the result of all inactive stack pops (but
     it might be nice to catch issues with next_off corruption earlier). */

  ulong all_blocks = fd_vinyl_data_szc_all_blocks( szc );

  if( FD_UNLIKELY( !( (superblock->type            ==FD_VINYL_DATA_OBJ_TYPE_SUPERBLOCK) &
                      ((ulong)superblock->child_szc==szc                              ) &
                      ((ulong)superblock->szc      ==parent_szc                       ) &
                      (!(superblock->free_blocks & ~all_blocks)                       ) ) ) ) return FD_VINYL_ERR_CORRUPT;

  return FD_VINYL_SUCCESS;
}

/**********************************************************************/

ulong
fd_vinyl_data_align( void ) {
  return alignof(fd_vinyl_data_t);
}

ulong
fd_vinyl_data_footprint( void ) {
  return sizeof(fd_vinyl_data_t);
}

fd_vinyl_data_t *
fd_vinyl_data_init( void * lmem,
                    void * shmem,
                    ulong  shmem_sz,
                    void * laddr0 ) {

  if( FD_UNLIKELY( !lmem ) ) {
    FD_LOG_WARNING(( "NULL lmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)lmem, fd_vinyl_data_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned lmem" ));
    return NULL;
  }

  ulong _laddr0 = (ulong)laddr0;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( _laddr0, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_WARNING(( "misaligned laddr0" ));
    return NULL;
  }

  /* Note that the shmem has a larger guard region at the end such that
     a "try" for a block at the end of the shmem will have large enough
     guard region that it is safe to read a val up to FD_VINYL_VAL_MAX
     in size (as the val_sz returned as part of the speculation might be
     bogus and the user of a try should recognize this as part of their
     speculation). */

  ulong _shmem0 = (ulong)shmem;
  ulong _shmem1 = _shmem0 + shmem_sz - fd_vinyl_bstream_pair_sz( FD_VINYL_VAL_MAX ) + FD_VINYL_BSTREAM_BLOCK_SZ;
  ulong _vol0   = fd_ulong_align_up( _shmem0, FD_VINYL_BSTREAM_BLOCK_SZ );
  ulong vol_cnt = (_shmem1-_vol0) / FD_VINYL_DATA_VOL_FOOTPRINT;
  ulong _vol1   = _vol0 + vol_cnt*FD_VINYL_DATA_VOL_FOOTPRINT;

  if( FD_UNLIKELY( !((_laddr0<_shmem0) & (_shmem0<=_vol0) & (_vol0<_vol1) & (_vol1<=_shmem1)) ) ) {
    FD_LOG_WARNING(( "bad shmem region" ));
    return NULL;
  }

  fd_vinyl_data_t * data = (fd_vinyl_data_t *)lmem;

  memset( data, 0, fd_vinyl_data_footprint() );

  data->shmem    = shmem;
  data->shmem_sz = shmem_sz;
  data->laddr0   = laddr0;
  data->vol      = (fd_vinyl_data_vol_t *)_vol0;
  data->vol_cnt  = vol_cnt;

  return data;
}

void *
fd_vinyl_data_fini( fd_vinyl_data_t * data ) {

  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_WARNING(( "NULL data" ));
    return NULL;
  }

  return data;
}

/* Note: the algorithms below is identical to fd_alloc.  But since it
   is running single threaded and non-persistent, there's less atomic
   operation and/or address translation shenanigans going on.  See
   fd_alloc for more in depth discussions. */

fd_vinyl_data_obj_t *
fd_vinyl_data_alloc( fd_vinyl_data_t * data,
                     ulong             szc ) {

  FD_CRIT( data,                      "NULL data"     );
  FD_CRIT( szc<FD_VINYL_DATA_SZC_CNT, "bad sizeclass" );

  void *                 laddr0        = data->laddr0;
  fd_vinyl_data_vol_t *  vol           = data->vol;
  fd_vinyl_data_obj_t ** _active       = &data->superblock[ szc ].active;
  fd_vinyl_data_obj_t ** _inactive_top = &data->superblock[ szc ].inactive_top;

  /* Acquire a superblock with space for a szc object.  We first look
     if there is an active superblock for this szc.  If not, we look at
     the inactive stack for this sizeclass.  If not, we allocate
     superblock suitable for holding objects of this sizeclass.  This
     will be either from this allocator or new data volume.  (We don't
     need to use global addresses for superblock->next_off but doing so
     allows tools to non-invasively inspect the data cache real time.) */

  fd_vinyl_data_obj_t * superblock = *_active;

  if( FD_LIKELY( superblock ) ) {

    FD_ALERT( !fd_vinyl_data_superblock_test( data, superblock, szc ), "corruption detected" );

    *_active = NULL;

  } else {

    superblock = *_inactive_top;

    if( FD_LIKELY( superblock ) ) {

      FD_ALERT( !fd_vinyl_data_superblock_test( data, superblock, szc ), "corruption detected" );

      *_inactive_top = fd_vinyl_data_obj_ptr( laddr0, superblock->next_off );

    } else {

      ulong parent_szc = (ulong)fd_vinyl_data_szc_cfg[ szc ].parent_szc;
      if( FD_LIKELY( parent_szc<FD_VINYL_DATA_SZC_CNT ) ) {

        superblock = fd_vinyl_data_alloc( data, parent_szc );
        if( FD_UNLIKELY( !superblock ) ) return NULL;

        /* superblock->type        init by obj_alloc to ALLOC, reset below */
        /* superblock->szc         init by obj_alloc */
        /* superblock->idx         init by obj_alloc */
        /* superblock->child_szc   init below */
        /* superblock->free_blocks init below */
        /* superblock->next_off    init when pushed onto inactive stack */

      } else {

        ulong vol_idx = data->vol_idx_free;
        if( FD_UNLIKELY( vol_idx >= data->vol_cnt ) ) return NULL;
        data->vol_idx_free = vol[ vol_idx ].obj->idx;

        superblock = vol[ vol_idx ].obj;

        /* superblock->type        init below */
        superblock->szc = (ushort)FD_VINYL_DATA_SZC_CNT;
        superblock->idx = vol_idx;
        /* superblock->child_szc   init below */
        /* superblock->free_blocks init below */
        /* superblock->next_off    init when pushed onto inactive stack */

      }

      superblock->type        = FD_VINYL_DATA_OBJ_TYPE_SUPERBLOCK;
      superblock->child_szc   = (ushort)szc;
      superblock->free_blocks = fd_vinyl_data_szc_all_blocks( szc );
    /*superblock->next_off    init when pushed onto inactive stack */

    }
  }

  /* At this point, superblock has at least 1 free szc object, is not
     in circulation and szc has no active superblock.  Allocate the
     first free object in it. */

  ulong free_blocks = superblock->free_blocks;

  FD_CRIT( free_blocks, "corruption detected" );

  ulong idx = (ulong)fd_ulong_find_lsb( free_blocks );

  free_blocks = fd_ulong_pop_lsb( free_blocks );

  superblock->free_blocks = free_blocks;

  /* If this superblock still has free blocks in it, return it to
     circulation for future allocation as szc's active superblock,
     pushing any displaced superblock onto szc's inactive superblock
     stack.  Other strategies are possible, see fd_alloc for discussion
     of tradeoffs. */

# if 0

  if( FD_LIKELY( free_blocks ) ) {

    fd_vinyl_data_obj_t * displaced_superblock = *_active;
    *_active = superblock;

    if( FD_UNLIKELY( displaced_superblock ) ) {

      FD_ALERT( !fd_vinyl_data_superblock_test( data, displaced_superblock, szc ), "corruption detected" );

      displaced_superblock->next_off = fd_vinyl_data_obj_off( laddr0, *_inactive_top );
      *_inactive_top                 = displaced_superblock;

    }

  }

# else

    /* For a non-concurrent implementation, we know szc has no active
       superblock active at this point (because their's no concurrent
       alloc or free that could have set it behind our back).  We don't
       have to worry about displacing a superblock, simplifying the
       above. */

  fd_vinyl_data_obj_t * tmp[1];
  *(free_blocks ? _active : tmp) = superblock; /* branchless conditional store */

# endif

  /* Initialize the allocated object metadata and return. */

  fd_vinyl_data_obj_t * obj = (fd_vinyl_data_obj_t *)( (ulong)superblock + sizeof(fd_vinyl_data_obj_t)
                                                     + idx*fd_vinyl_data_szc_obj_footprint( szc ) );

  obj->type        = FD_VINYL_DATA_OBJ_TYPE_ALLOC;
  obj->szc         = (ushort)szc;
  obj->idx         = idx;
//obj->child_szc   = ... d/c (not a superblock)
//obj->free_blocks = ... d/c (not a superblock)
//obj->next_off    = ... d/c (not a superblock)

  return obj;
}

void
fd_vinyl_data_free( fd_vinyl_data_t *     data,
                    fd_vinyl_data_obj_t * obj ) {

  FD_CRIT( data, "NULL data" );

  if( FD_UNLIKELY( !obj ) ) return;

  FD_CRIT( fd_ulong_is_aligned( (ulong)obj, FD_VINYL_BSTREAM_BLOCK_SZ ),                               "obj misaligned"        );
  FD_CRIT( ((ulong)data->vol<=(ulong)obj) & ((ulong)obj<(ulong)(data->vol+data->vol_cnt)),             "obj not in data cache" );
  FD_CRIT( (obj->type==FD_VINYL_DATA_OBJ_TYPE_ALLOC) | (obj->type==FD_VINYL_DATA_OBJ_TYPE_SUPERBLOCK), "obj not freeable"      );

  /* At this point, obj appears to be a freeable obj in the data.
     Determine how obj was allocated.  If obj is a vol, push obj onto
     the vol free stack. */

  ulong szc = (ulong)obj->szc;
  ulong idx =        obj->idx;

  FD_CRIT( szc<=FD_VINYL_DATA_SZC_CNT, "corruption detected" ); /* valid szc */

  if( FD_UNLIKELY( szc>=FD_VINYL_DATA_SZC_CNT ) ) {
    FD_CRIT( idx < data->vol_cnt, "corruption detected" ); /* valid idx for vol */

    obj->type          = FD_VINYL_DATA_OBJ_TYPE_FREEVOL; /* Mark as on the free stack */
    obj->idx           = data->vol_idx_free;
    data->vol_idx_free = idx;

    return;
  }

  FD_CRIT( idx<(ulong)fd_vinyl_data_szc_cfg[ szc ].obj_cnt, "corruption detected" ); /* valid idx for szc */

  /* At this point, obj appears to be contained in a superblock at
     position idx.  Mark the object as free in the superblock. */

  fd_vinyl_data_obj_t * superblock = (fd_vinyl_data_obj_t *)
    ((ulong)obj - sizeof(fd_vinyl_data_obj_t) - idx*fd_vinyl_data_szc_obj_footprint( szc ));

  FD_ALERT( !fd_vinyl_data_superblock_test( data, superblock, szc ), "corruption detected" );

  ulong free_blocks = superblock->free_blocks;
  ulong block       = 1UL << idx;

  FD_CRIT( !(free_blocks & block), "obj already free" );

  obj->type = 0UL; /* Mark this as no longer an object (not strictly necessary but useful for things like double free detection) */

  free_blocks |= block;

  superblock->free_blocks = free_blocks;

  /* If this superblock was not in circulation for szc allocations (i.e.
     had no free objects in it before the free we just did), we return
     it to circulation as szc's active superblock, pushing any displaced
     superblock onto the szc's inactive superblock stack.

     Otherwise, if this free made the superblock totally empty, we check
     if the szc'c inactive superblock top is also totally empty.  If so,
     we pop the inactive stack and free that.

     This keeps a small bounded supply empty superblocks around for fast
     future allocations in this szc while allowing memory to reclaimed
     for different szc objs.  Note that we can't just free superblock if
     it is totally empty fast O(1) because we don't know where it is in
     circulation (and, even if we did, this is a bad idea).  Other
     strategies are possible, see fd_alloc for discussion of tradeoffs. */

  if( FD_UNLIKELY( free_blocks==block ) ) {

    fd_vinyl_data_obj_t * displaced_superblock = data->superblock[ szc ].active;
    data->superblock[ szc ].active             = superblock;

    if( displaced_superblock ) {

      FD_ALERT( !fd_vinyl_data_superblock_test( data, displaced_superblock, szc ), "corruption detected" );

      displaced_superblock->next_off       = fd_vinyl_data_obj_off( data->laddr0, data->superblock[ szc ].inactive_top );
      data->superblock[ szc ].inactive_top = displaced_superblock;

    }

  } else {

    ulong all_blocks = fd_vinyl_data_szc_all_blocks( szc );

    if( FD_UNLIKELY( free_blocks==all_blocks ) ) {

      fd_vinyl_data_obj_t * candidate_superblock = data->superblock[ szc ].inactive_top;

      if( FD_UNLIKELY( candidate_superblock ) ) {

        FD_ALERT( !fd_vinyl_data_superblock_test( data, candidate_superblock, szc ), "corruption detected" );

        if( FD_UNLIKELY( candidate_superblock->free_blocks==all_blocks ) ) {

          data->superblock[ szc ].inactive_top = fd_vinyl_data_obj_ptr( data->laddr0, candidate_superblock->next_off );

          fd_vinyl_data_free( data, candidate_superblock );
        }

      }

    }

  }

}

static FD_FOR_ALL_BEGIN( fd_vinyl_data_reset_task, 1L ) {
  fd_vinyl_data_t * data  = (fd_vinyl_data_t *)arg[0];
  int               level = (int)              arg[1];

  void *                shmem    = data->shmem;
  ulong                 shmem_sz = data->shmem_sz;
  fd_vinyl_data_vol_t * vol      = data->vol;
  ulong                 vol_cnt  = data->vol_cnt;

  ulong vol0 = (ulong)block_i0;
  ulong vol1 = (ulong)block_i1;

  /* At this point, we have been assigned the non-empty set of volumes
     [vol0,vol1) to reset.  If this is a hard reset, we zero out the
     volume we have been assigned.  If we are responsible for zeroing
     the leading/trailing volume, we also handle any leading/trailing
     zero padding in the shmem. */

  if( level ) {
    void * mem    = (void *)(vol + vol0);
    ulong  mem_sz = (vol1-vol0)*FD_VINYL_DATA_VOL_FOOTPRINT;

    if( vol0==0UL     ) mem_sz += (ulong)vol - (ulong)shmem, mem = shmem;
    if( vol1==vol_cnt ) mem_sz += shmem_sz - vol_cnt*FD_VINYL_DATA_VOL_FOOTPRINT;

    memset( mem, 0, mem_sz ); /* mem_sz guaranteed non-zero */
  }

  /* Mark the volumes as free and join them in a linked list */

  for( ulong vol_idx=vol0; vol_idx<vol1; vol_idx++ ) {
    vol[ vol_idx ].obj->type = FD_VINYL_DATA_OBJ_TYPE_FREEVOL;
    vol[ vol_idx ].obj->idx  = vol_idx + 1UL;
  }

} FD_FOR_ALL_END

void
fd_vinyl_data_reset( fd_tpool_t * tpool, ulong t0, ulong t1, int level,
                     fd_vinyl_data_t * data ) {

  FD_FOR_ALL( fd_vinyl_data_reset_task, tpool,t0,t1, 0L,(long)data->vol_cnt, data, level );

  data->vol_idx_free = 0UL;

  for( ulong szc=0UL; szc<FD_VINYL_DATA_SZC_CNT; szc++ ) {
    data->superblock[ szc ].active       = NULL;
    data->superblock[ szc ].inactive_top = NULL;
  }

}

/* FIXME: consider adding a compact function? */

#define TEST( c ) \
  do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "corruption detected (%s)", #c )); return FD_VINYL_ERR_CORRUPT; } } while(0)

/* fd_vinyl_data_verify_obj returns FD_VINYL_SUCCESS (0) if a type
   SUPERBLOCK or type ALLOC obj and all its children appear to be valid
   and FD_VINYL_ERR_CORRUPT (negative) if memory corruption was detected
   (logs details). */

FD_FN_PURE static int
fd_vinyl_data_verify_superblock( fd_vinyl_data_t     const * data,
                                 fd_vinyl_data_obj_t const * superblock ) {

  TEST( superblock );
  TEST( fd_ulong_is_aligned( (ulong)superblock, alignof(fd_vinyl_data_obj_t) ) );
  ulong szc = (ulong)superblock->child_szc;

  TEST( !fd_vinyl_data_superblock_test( data, superblock, szc ) );

  ulong free_blocks = superblock->free_blocks;

  ulong obj_footprint = fd_vinyl_data_szc_obj_footprint( szc );

  for( ulong rem=fd_vinyl_data_szc_all_blocks( szc ) & ~free_blocks; rem; rem=fd_ulong_pop_lsb( rem ) ) {
    ulong obj_idx = (ulong)fd_ulong_find_lsb( rem );

    fd_vinyl_data_obj_t const * obj = (fd_vinyl_data_obj_t const *)
      ((ulong)superblock + sizeof(fd_vinyl_data_obj_t) + obj_idx*obj_footprint);

    ulong type = obj->type;
    if( type==FD_VINYL_DATA_OBJ_TYPE_SUPERBLOCK ) TEST( !fd_vinyl_data_verify_superblock( data, obj ) );
    else                                          TEST( type==FD_VINYL_DATA_OBJ_TYPE_ALLOC );
  }

  return FD_VINYL_SUCCESS;
}

int
fd_vinyl_data_verify( fd_vinyl_data_t const * data ) {

  /* Verify data looks like a fd_vinyl_data_t */

  TEST( data );
  TEST( fd_ulong_is_aligned( (ulong)data, alignof(fd_vinyl_data_t) ) );

  ulong  vol_cnt = data->vol_cnt;

  ulong  laddr0 = (ulong)data->laddr0;
  ulong  shmem0 = (ulong)data->shmem;
  ulong  shmem1 = (ulong)data->shmem + data->shmem_sz;
  ulong  vol0   = (ulong)&data->vol[0      ];
  ulong  vol1   = (ulong)&data->vol[vol_cnt];

  TEST( fd_ulong_is_aligned( laddr0, FD_VINYL_BSTREAM_BLOCK_SZ ) );
  TEST( fd_ulong_is_aligned( vol0,   FD_VINYL_BSTREAM_BLOCK_SZ ) );
  TEST( fd_ulong_is_aligned( vol1,   FD_VINYL_BSTREAM_BLOCK_SZ ) );

  TEST( (laddr0<shmem0) & (shmem0<=vol0) & (vol0<vol1) & (vol1<=shmem1) );

  /* Verify free volume stack */

  ulong vol_free_cnt = 0UL;

  fd_vinyl_data_vol_t * vol     = data->vol;
  ulong                 vol_idx = data->vol_idx_free;
  for(;;) {
    if( vol_idx>=vol_cnt ) break;
    fd_vinyl_data_obj_t const * obj = vol[ vol_idx ].obj;
    TEST( vol_free_cnt<vol_cnt                      ); /* cycle detected */
    TEST( obj->type==FD_VINYL_DATA_OBJ_TYPE_FREEVOL ); /* volume is marked as free */
    vol_free_cnt++;
    vol_idx = obj->idx;
  }

  /* Verify volumes */

  ulong vol_free_rem =           vol_free_cnt;
  ulong vol_used_rem = vol_cnt - vol_free_cnt;

  for( vol_idx=0UL; vol_idx<vol_cnt; vol_idx++ ) {
    fd_vinyl_data_obj_t const * obj = vol[ vol_idx ].obj;

    ulong type = obj->type;

    if( type==FD_VINYL_DATA_OBJ_TYPE_FREEVOL ) { /* Free volume */
      TEST( vol_free_rem );
      /* obj->szc         ... d/c for a free vol */
      /* obj->idx         ... validated above    */
      /* obj->child_szc   ... d/c for a free vol */
      /* obj->free_blocks ... d/c for a free vol */
      /* obj->next_off    ... d/c for a free vol */
      vol_free_rem--;
      continue;
    }

    TEST( vol_used_rem );
    TEST( !fd_vinyl_data_verify_superblock( data, vol->obj ) );
    vol_used_rem--;
  }

  TEST( !vol_free_rem );
  TEST( !vol_used_rem );

  /* Verify active superblocks and inactive stacks */

  for( ulong szc=0UL; szc<FD_VINYL_DATA_SZC_CNT; szc++ ) {
    fd_vinyl_data_obj_t * active = data->superblock[ szc ].active;
    if( active ) {
      TEST( !fd_vinyl_data_superblock_test( data, active, szc ) );
      TEST( active->free_blocks );
    }

    ulong obj_footprint        = fd_vinyl_data_szc_obj_footprint( szc );
    ulong obj_cnt              = (ulong)fd_vinyl_data_szc_cfg[ szc ].obj_cnt;
    ulong superblock_footprint = sizeof(fd_vinyl_data_obj_t) + obj_cnt*obj_footprint;
    ulong rem                  = (vol1 - vol0 + superblock_footprint - 1UL) / superblock_footprint;

    fd_vinyl_data_obj_t * superblock = data->superblock[ szc ].inactive_top;
    while( superblock ) {
      TEST( rem ); rem--; /* avoid cycles */
      TEST( superblock!=active );
      TEST( !fd_vinyl_data_superblock_test( data, superblock, szc ) );
      TEST( superblock->free_blocks );
      superblock = fd_vinyl_data_obj_ptr( (void *)laddr0, superblock->next_off );
    }
  }

  return FD_VINYL_SUCCESS;
}
