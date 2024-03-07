#include "fd_wksp_private.h"

/* fd_wksp_private_split_before splits a partition (index i2) into two
   smaller partitions and returns the partition index (i1) of the
   partition created by the split.  The created partition will be
   immediately before the original partition.  It will be in the
   partitioning with a zero tag.  It will not be in the idle stack, used
   treap or free treap.

   sz is size of the original partition post split.  This should be in
   (0,original_sz) (yes, open on both ends such that the post split
   partitions both have non-zero size.

   This will pop the idle stack once to assign the index of the newly
   created partition.  Assumes the caller knows the idle stack is not
   empty.

   Assumes the original partition is in the partitioning with a zero
   tag.  Further assumes the original partition is not in the idle
   stack, used treap or free treap.

   fd_wksp_private_split_after is identical except the partition created
   by the split is after the original partition. */

static ulong                                                      /* In [0,part_max) */
fd_wksp_private_split_before( ulong                     i2,       /* In [0,part_max) */
                              ulong                     s2,       /* In (0,size of i2) */
                              fd_wksp_t *               wksp,     /* Current local join */
                              fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */

  ulong g3 = pinfo[ i2 ].gaddr_hi;                               /* Old end here */
  ulong g2 = g3 - s2;                                            /* New ends here */
  ulong g1 = pinfo[ i2 ].gaddr_lo;                               /* New starts here */

  ulong i0 = fd_wksp_private_pinfo_idx( pinfo[ i2 ].prev_cidx ); /* Old before */
  ulong i1 = fd_wksp_private_idle_stack_pop( wksp, pinfo );      /* New before */

  pinfo[ i1 ].gaddr_lo    = g1;
  pinfo[ i1 ].gaddr_hi    = g2;
  pinfo[ i1 ].tag         = 0UL;
  pinfo[ i1 ].in_same     = 0U;
  pinfo[ i1 ].prev_cidx   = fd_wksp_private_pinfo_cidx( i0 );
  pinfo[ i1 ].next_cidx   = fd_wksp_private_pinfo_cidx( i2 );
  pinfo[ i1 ].left_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i1 ].right_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i1 ].same_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i1 ].parent_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );

  pinfo[ i2 ].gaddr_lo    = g2;
  pinfo[ i2 ].prev_cidx   = fd_wksp_private_pinfo_cidx( i1 );

  if( fd_wksp_private_pinfo_idx_is_null( i0 ) ) wksp->part_head_cidx  = fd_wksp_private_pinfo_cidx( i1 );
  else                                          pinfo[ i0 ].next_cidx = fd_wksp_private_pinfo_cidx( i1 );

  return i1;
}

static ulong                                                     /* In [0,part_max) */
fd_wksp_private_split_after( ulong                     i1,       /* In [0,part_max) */
                             ulong                     s1,       /* In (0,size of i2) */
                             fd_wksp_t *               wksp,     /* Current local join */
                             fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */

  ulong g1 = pinfo[ i1 ].gaddr_lo;                               /* Old starts here */
  ulong g2 = g1 + s1;                                            /* New starts here */
  ulong g3 = pinfo[ i1 ].gaddr_hi;                               /* New end here */

  ulong i2 = fd_wksp_private_idle_stack_pop( wksp, pinfo );      /* New before */
  ulong i3 = fd_wksp_private_pinfo_idx( pinfo[ i1 ].next_cidx ); /* Old after */

  pinfo[ i2 ].gaddr_lo    = g2;
  pinfo[ i2 ].gaddr_hi    = g3;
  pinfo[ i2 ].tag         = 0UL;
  pinfo[ i2 ].in_same     = 0U;
  pinfo[ i2 ].prev_cidx   = fd_wksp_private_pinfo_cidx( i1 );
  pinfo[ i2 ].next_cidx   = fd_wksp_private_pinfo_cidx( i3 );
  pinfo[ i2 ].left_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i2 ].right_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i2 ].same_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i2 ].parent_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );

  pinfo[ i1 ].gaddr_hi    = g2;
  pinfo[ i1 ].next_cidx   = fd_wksp_private_pinfo_cidx( i2 );

  if( fd_wksp_private_pinfo_idx_is_null( i3 ) ) wksp->part_tail_cidx  = fd_wksp_private_pinfo_cidx( i2 );
  else                                          pinfo[ i3 ].prev_cidx = fd_wksp_private_pinfo_cidx( i2 );

  return i2;
}

/* fd_wksp_private_merge_before i1 into i2 where i1 is the partition
   immediately preceding i2.  Assumes that i2 and the partition before
   it are not tagged and not in the idle stack, free treap or used
   treap.

   This will push the idle stack once to make the index used for the
   preceding partition available for future use.

   fd_wksp_private_merge_after is identical except the partition to
   merge the split is after the original partition. */

static void
fd_wksp_private_merge_before( ulong                     i1,       /* In [0,part_max), == prev to i2, on idle stack on return */
                              ulong                     i2,       /* In [0,part_max) */
                              fd_wksp_t *               wksp,     /* Current local join */
                              fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */

  ulong i0 = fd_wksp_private_pinfo_idx( pinfo[ i1 ].prev_cidx ); /* Partition before that (if any) */

  pinfo[ i2 ].gaddr_lo  = pinfo[ i1 ].gaddr_lo;
  pinfo[ i2 ].prev_cidx = fd_wksp_private_pinfo_cidx( i0 );

  if( fd_wksp_private_pinfo_idx_is_null( i0 ) ) wksp->part_head_cidx  = fd_wksp_private_pinfo_cidx( i2 );
  else                                          pinfo[ i0 ].next_cidx = fd_wksp_private_pinfo_cidx( i2 );

  fd_wksp_private_idle_stack_push( i1, wksp, pinfo );
}

static void
fd_wksp_private_merge_after( ulong                     i1,       /* In [0,part_max) */
                             ulong                     i2,       /* In [0,part_max), == next to i1, on idle stack on return */
                             fd_wksp_t *               wksp,     /* Current local join */
                             fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */

  ulong i3 = fd_wksp_private_pinfo_idx( pinfo[ i2 ].next_cidx ); /* Partition after that (if any) */

  pinfo[ i1 ].gaddr_hi  = pinfo[ i2 ].gaddr_hi;
  pinfo[ i1 ].next_cidx = fd_wksp_private_pinfo_cidx( i3 );

  if( fd_wksp_private_pinfo_idx_is_null( i3 ) ) wksp->part_tail_cidx  = fd_wksp_private_pinfo_cidx( i1 );
  else                                          pinfo[ i3 ].prev_cidx = fd_wksp_private_pinfo_cidx( i1 );

  fd_wksp_private_idle_stack_push( i2, wksp, pinfo );
}

static void
fd_wksp_private_free( ulong                     i,        /* Partition to free, in [0,part_max) */
                      fd_wksp_t *               wksp,     /* Current local join */
                      fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */

  ulong part_max = wksp->part_max;

  /* Officially free i */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pinfo[ i ].tag ) = 0UL;
  FD_COMPILER_MFENCE();

  /* Remove it from various structures.  It is okay if we are killed in
     this as next person to try to lock the wksp will detect this and
     rebuild the workspace. */

  if( FD_UNLIKELY( fd_wksp_private_used_treap_remove( i, wksp, pinfo ) ) ) {
    FD_LOG_WARNING(( "corrupt wksp detected" ));
    return;
  }

  ulong p = fd_wksp_private_pinfo_idx( pinfo[ i ].prev_cidx );
  if( FD_LIKELY( p<part_max ) && !pinfo[ p ].tag ) {
    if( FD_UNLIKELY( fd_wksp_private_free_treap_remove( p, wksp, pinfo ) ) ) {
      FD_LOG_WARNING(( "corrupt wksp detected" ));
      return;
    }
    fd_wksp_private_merge_before( p, i, wksp, pinfo );
  }

  ulong n = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
  if( FD_LIKELY( n<part_max ) && !pinfo[ n ].tag ) {
    if( FD_UNLIKELY( fd_wksp_private_free_treap_remove( n, wksp, pinfo ) ) ) {
      FD_LOG_WARNING(( "corrupt wksp detected" ));
      return;
    }
    fd_wksp_private_merge_after( i, n, wksp, pinfo );
  }

  if( FD_UNLIKELY( fd_wksp_private_free_treap_insert( i, wksp, pinfo ) ) ) {
    FD_LOG_WARNING(( "corrupt wksp detected" ));
    return;
  }
}

/* user APIs **********************************************************/

void *
fd_wksp_laddr( fd_wksp_t const * wksp,
               ulong             gaddr ) {
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return NULL; }

  if( !gaddr ) return NULL; /* "NULL" maps to NULL */

  /* Note: <= used for gaddr_hi below to support mapping ranges of the
     form [lo,hi) between local and global address spaces with no
     special handling if allocation put hi at the very end of the
     workspace. */

  if( FD_UNLIKELY( !((wksp->gaddr_lo<=gaddr) & (gaddr<=wksp->gaddr_hi)) ) ) { FD_LOG_WARNING(( "bad gaddr" )); return NULL; }

  return fd_wksp_laddr_fast( wksp, gaddr );
}

ulong
fd_wksp_gaddr( fd_wksp_t const * wksp,
               void const *      laddr ) {
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return 0UL; }

  if( !laddr ) return 0UL; /* NULL maps to "NULL" */

  ulong gaddr = fd_wksp_gaddr_fast( wksp, laddr );

  /* See note above about why <= for gaddr_hi */

  if( FD_UNLIKELY( !((wksp->gaddr_lo<=gaddr) & (gaddr<=wksp->gaddr_hi)) ) ) { FD_LOG_WARNING(( "bad laddr" )); return 0UL; }

  return gaddr;
}

ulong
fd_wksp_alloc_at_least( fd_wksp_t * wksp,
                        ulong       align,
                        ulong       sz,
                        ulong       tag,
                        ulong *     _lo,
                        ulong *     _hi ) {
  align = fd_ulong_if( !align, FD_WKSP_ALIGN_DEFAULT, align );

  if( FD_UNLIKELY( !sz                        ) ) goto fail; /* silent */
  if( FD_UNLIKELY( !wksp                      ) ) { FD_LOG_WARNING(( "NULL wksp"   )); goto fail; }
  if( FD_UNLIKELY( !fd_ulong_is_pow2( align ) ) ) { FD_LOG_WARNING(( "bad align"   )); goto fail; }
  if( FD_UNLIKELY( !tag                       ) ) { FD_LOG_WARNING(( "bad tag"     )); goto fail; }

  #if FD_HAS_DEEPASAN
    /* ASan requires 8 byte alignment for poisoning because memory is mapped in
       8 byte intervals to ASan shadow bytes. */
    align = fd_ulong_if( align < FD_ASAN_ALIGN, FD_ASAN_ALIGN, align );
    if ( sz && sz < ULONG_MAX )
      sz = fd_ulong_align_up( sz, FD_ASAN_ALIGN );
  #endif 

  ulong footprint = sz + align - 1UL;

  if( FD_UNLIKELY( footprint < sz             ) ) { FD_LOG_WARNING(( "sz overflow" )); goto fail; }

  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) goto fail; /* logs details */

  /* Find the smallest free partition size that can handle footprint.
     Note: it is theoretically possible when there is corruption that a
     failure to find a suitable partition could be fixed by rebuilding
     the wksp.  But this should not be common and is expensive and we
     can't tell if this is a run-of-the-mill allocation failure
     (insufficient space or too much fragmentation) or an exotic data
     corruption case.  So we just fail to keep algo cost strict and let
     the user decide if they want to attempt extreme measures. */

  ulong i = fd_wksp_private_free_treap_query( footprint, wksp, pinfo );
  if( FD_UNLIKELY( fd_wksp_private_pinfo_idx_is_null( i ) ) ) {
    fd_wksp_private_unlock( wksp );
    FD_LOG_WARNING(( "no usable workspace free space available" ));
    goto fail;
  }

  /* At this point, i in [0,max), there is at least one suitable
     partition.  If there is more than one, use one from the same list. */

  if( !fd_wksp_private_free_treap_same_is_empty( i, wksp, pinfo ) ) i = fd_wksp_private_free_treap_same_remove( i, wksp, pinfo );
  else if( FD_UNLIKELY( fd_wksp_private_free_treap_remove( i, wksp, pinfo ) ) ) {
    fd_wksp_private_unlock( wksp );
    FD_LOG_WARNING(( "corrupt wksp detected" ));
    goto fail;
  }

  /* At this point, partition i has a zero tag and is not in the idle
     stack, free treap, or used treap.  Further, it is guaranteed to be
     large enough to hold the request.  Trim it to fit the request as
     tightly as possible. */
  /* TODO: consider failing if can't trim and overallocation >> sz */

  ulong lo = pinfo[ i ].gaddr_lo;
  ulong hi = pinfo[ i ].gaddr_hi;

  ulong r0 = fd_ulong_align_up( lo, align );
  ulong r1 = r0 + sz;

  if( FD_UNLIKELY( r0>lo ) ) { /* opt for reasonable alignments */
    if( FD_UNLIKELY( fd_wksp_private_idle_stack_is_empty( wksp ) ) ) goto trimmed; /* No partitions avail ... use untrimmed */
    ulong j = fd_wksp_private_split_before( i, hi-r0, wksp, pinfo );
    if( FD_UNLIKELY( fd_wksp_private_free_treap_insert( j, wksp, pinfo ) ) ) {
      fd_wksp_private_unlock( wksp );
      FD_LOG_WARNING(( "corrupt wksp detected" ));
      goto fail;
    }
    lo = r0;
  }

  if( FD_LIKELY( r1<hi ) ) { /* opt for splitting a final large partition */
    if( FD_UNLIKELY( fd_wksp_private_idle_stack_is_empty( wksp ) ) ) goto trimmed; /* No partitions avail ... use untrimmed */
    ulong j = fd_wksp_private_split_after( i, sz, wksp, pinfo );
    if( FD_UNLIKELY( fd_wksp_private_free_treap_insert( j, wksp, pinfo ) ) ) {
      fd_wksp_private_unlock( wksp );
      FD_LOG_WARNING(( "corrupt wksp detected" ));
      goto fail;
    }
    hi = r1;
  }

trimmed:
  if( FD_UNLIKELY( fd_wksp_private_used_treap_insert( i, wksp, pinfo ) ) ) {
    fd_wksp_private_unlock( wksp );
    FD_LOG_WARNING(( "corrupt wksp detected" ));
    goto fail;
  }

  /* At this point, i is unofficially allocated.  It is okay if we get
     killed at any point above as the next wksp user to try to lock the
     wksp will detect that we died in the middle of an operation,
     potentially leaving the partitioning, idle stack, used treap and/or
     free treap might be in an inconsistent state and thus proceed to
     rebuild them.  We now update the tag in the array to make the
     allocation official. */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pinfo[ i ].tag ) = tag;
  FD_COMPILER_MFENCE();

  #if FD_HAS_DEEPASAN
  fd_asan_unpoison( fd_wksp_laddr_fast( wksp, lo ), hi - lo );
  #endif 

  fd_wksp_private_unlock( wksp );
  *_lo = lo;
  *_hi = hi;
  return r0;

fail:
  *_lo = 0UL;
  *_hi = 0UL;
  return 0UL;
}

void
fd_wksp_free( fd_wksp_t * wksp,
              ulong       gaddr ) {
  if( FD_UNLIKELY( !gaddr ) ) return;

  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return; }

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) return; /* logs details */

  ulong i = fd_wksp_private_used_treap_query( gaddr, wksp, pinfo );
  if( FD_UNLIKELY( i<part_max ) ) fd_wksp_private_free( i, wksp, pinfo ); /* logs details */

  fd_wksp_private_unlock( wksp );

  if( FD_UNLIKELY( i>=part_max ) ) FD_LOG_WARNING(( "gaddr does not appear to be a current wksp allocation" ));
  else {
    #if FD_HAS_DEEPASAN
    fd_asan_poison( fd_wksp_laddr_fast( wksp, pinfo[ i ].gaddr_lo ), pinfo[ i ].gaddr_hi - pinfo[ i ].gaddr_lo );
    #endif 
  }
}

ulong
fd_wksp_tag( fd_wksp_t * wksp,
             ulong       gaddr ) {
  if( FD_UNLIKELY( !wksp ) ) return 0UL;

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) return 0UL; /* logs details */

  ulong i   = fd_wksp_private_used_treap_query( gaddr, wksp, pinfo );
  ulong tag = FD_LIKELY( i<part_max ) ? pinfo[ i ].tag : 0UL;

  fd_wksp_private_unlock( wksp );

  return tag;
}

ulong
fd_wksp_tag_query( fd_wksp_t *                wksp,
                   ulong const *              tag,
                   ulong                      tag_cnt,
                   fd_wksp_tag_query_info_t * info,
                   ulong                      info_max ) {

  if( FD_UNLIKELY( !tag_cnt ) ) return 0UL; /* No tags to query */

  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return 0UL; }
  if( FD_UNLIKELY( !tag  ) ) { FD_LOG_WARNING(( "bad tag" ));   return 0UL; }

  if( FD_UNLIKELY( (!!info_max) & (!info) ) ) { FD_LOG_WARNING(( "NULL info" )); return 0UL; }

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  ulong info_cnt = 0UL;

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) return 0UL; /* logs details */

  ulong cycle_tag = wksp->cycle_tag++;

  ulong i = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
  while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
    if( FD_UNLIKELY( i>=part_max ) || FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) {
      fd_wksp_private_unlock( wksp );
      FD_LOG_WARNING(( "corrupt wksp detected" ));
      return 0UL;
    }
    pinfo[ i ].cycle_tag = cycle_tag; /* mark i as visited */

    ulong _tag = pinfo[ i ].tag;
    for( ulong tag_idx=0UL; tag_idx<tag_cnt; tag_idx++ ) { /* TODO: USE BETTER MATCHER */
      if( tag[ tag_idx ]==_tag ) {
        if( FD_LIKELY( info_cnt<info_max ) ) {
          info[ info_cnt ].gaddr_lo = pinfo[ i ].gaddr_lo;
          info[ info_cnt ].gaddr_hi = pinfo[ i ].gaddr_hi;
          info[ info_cnt ].tag      = pinfo[ i ].tag;
        }
        info_cnt++;
        break;
      }
    }

    i = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
  }

  fd_wksp_private_unlock( wksp );
  return info_cnt;
}

void
fd_wksp_tag_free( fd_wksp_t *   wksp,
                  ulong const * tag,
                  ulong         tag_cnt ) {
  if( FD_UNLIKELY( !tag_cnt ) ) return; /* No tags to free */

  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return; }
  if( FD_UNLIKELY( !tag  ) ) { FD_LOG_WARNING(( "bad tag" ));   return; }

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) return; /* logs details */

  /* Push matching used partitions onto a stack */

  ulong top = FD_WKSP_PRIVATE_PINFO_IDX_NULL;

  ulong cycle_tag = wksp->cycle_tag++;

  ulong i = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
  while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
    if( FD_UNLIKELY( i>=part_max ) || FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) {
      fd_wksp_private_unlock( wksp );
      FD_LOG_WARNING(( "corrupt wksp detected" ));
      return;
    }
    pinfo[ i ].cycle_tag = cycle_tag; /* mark i as visited */

    ulong _tag = pinfo[ i ].tag;
    if( _tag ) { /* TODO: use a more efficient matcher */
      ulong tag_idx; for( tag_idx=0UL; tag_idx<tag_cnt; tag_idx++ ) if( tag[ tag_idx ]==_tag ) break;
      if( tag_idx<tag_cnt ) {
        pinfo[ i ].stack_cidx = fd_wksp_private_pinfo_cidx( top );
        top = i;
      }
    }
    i = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
  }

  /* Free partitions on the stack */

  while( !fd_wksp_private_pinfo_idx_is_null( top ) ) {
    i   = top;
    top = fd_wksp_private_pinfo_idx( pinfo[ i ].stack_cidx );
    fd_wksp_private_free( i, wksp, pinfo );
  }

  fd_wksp_private_unlock( wksp );
}

void
fd_wksp_memset( fd_wksp_t * wksp,
                ulong       gaddr,
                int         c ) {
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return; }

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  int err;

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) return; /* logs details */

  ulong i = fd_wksp_private_used_treap_query( gaddr, wksp, pinfo );
  if( FD_UNLIKELY( i>=part_max ) ) err = 1;
  else {
    fd_memset( fd_wksp_laddr_fast( wksp, pinfo[ i ].gaddr_lo ), c, fd_wksp_private_pinfo_sz( pinfo + i ) );
    err = 0;
  }

  fd_wksp_private_unlock( wksp );

  if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "gaddr does not seem to point to a current wksp allocation" ));
}

void
fd_wksp_reset( fd_wksp_t * wksp,
               uint        seed ) {
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return; }

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) return; /* logs details */

  for( ulong i=0; i<part_max; i++ ) pinfo[ i ].tag = 0UL;
  int err = fd_wksp_rebuild( wksp, seed );

  fd_wksp_private_unlock( wksp );

  if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "corrupt wksp detected" ));
}

fd_wksp_usage_t *
fd_wksp_usage( fd_wksp_t *       wksp,
               ulong const *     tag,
               ulong             tag_cnt,
               fd_wksp_usage_t * usage ) {

  /* Check input args */

  if( FD_UNLIKELY( !usage ) ) { FD_LOG_WARNING(( "bad usage" )); return usage; }

  fd_memset( usage, 0, sizeof(fd_wksp_usage_t) );

  if( FD_UNLIKELY( !wksp                ) ) { FD_LOG_WARNING(( "bad wksp" )); return usage; }
  if( FD_UNLIKELY( (!tag) & (!!tag_cnt) ) ) { FD_LOG_WARNING(( "bad tag" ));  return usage; }

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) { FD_LOG_WARNING(( "fd_wksp_private_lock failed" )); return usage; }

  /* Push matching used partitions onto a stack */

  usage->total_max = part_max;

  ulong cycle_tag = wksp->cycle_tag++;

  ulong i = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
  while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
    if( FD_UNLIKELY( i>=part_max ) || FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) {
      fd_wksp_private_unlock( wksp );
      FD_LOG_WARNING(( "corrupt wksp detected" ));
      fd_memset( usage, 0, sizeof(fd_wksp_usage_t) );
    }
    pinfo[ i ].cycle_tag = cycle_tag; /* mark i as visited */

    ulong part_sz  = fd_wksp_private_pinfo_sz( pinfo + i );
    ulong part_tag = pinfo[ i ].tag;

    /* TODO: use a more efficient matcher */
    ulong tag_idx; for( tag_idx=0UL; tag_idx<tag_cnt; tag_idx++ ) if( tag[ tag_idx ]==part_tag ) break;

    int is_free = !part_tag;
    int is_used = tag_idx<tag_cnt;

    usage->total_cnt += 1UL;            usage->total_sz +=                       part_sz;
    usage->free_cnt  += (ulong)is_free; usage->free_sz  += fd_ulong_if( is_free, part_sz, 0UL );
    usage->used_cnt  += (ulong)is_used; usage->used_sz  += fd_ulong_if( is_used, part_sz, 0UL );

    i = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
  }

  fd_wksp_private_unlock( wksp );
  return usage;
}
