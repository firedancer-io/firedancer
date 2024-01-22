#include "fd_wksp_private.h"

ulong
fd_wksp_private_used_treap_query( ulong                     gaddr,
                                  fd_wksp_t *               wksp,
                                  fd_wksp_private_pinfo_t * pinfo ) {
  if( FD_UNLIKELY( !((wksp->gaddr_lo<=gaddr) & (gaddr<wksp->gaddr_hi)) ) ) return FD_WKSP_PRIVATE_PINFO_IDX_NULL; /* Not in range */

  ulong part_max  = wksp->part_max;
  ulong cycle_tag = wksp->cycle_tag++;

  ulong i = fd_wksp_private_pinfo_idx( wksp->part_used_cidx );
  while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
    if( FD_UNLIKELY( i>=part_max                     ) ) return FD_WKSP_PRIVATE_PINFO_IDX_NULL; /* Bad index */
    if( FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) return FD_WKSP_PRIVATE_PINFO_IDX_NULL; /* Cycle detected */
    pinfo[ i ].cycle_tag = cycle_tag;                                                           /* Mark i as visited */

    ulong gaddr_lo = pinfo[ i ].gaddr_lo;
    ulong gaddr_hi = pinfo[ i ].gaddr_hi;
    if( gaddr <  gaddr_lo ) { i = fd_wksp_private_pinfo_idx( pinfo[ i ].left_cidx  ); continue; }
    if( gaddr >= gaddr_hi ) { i = fd_wksp_private_pinfo_idx( pinfo[ i ].right_cidx ); continue; }
    break;
  }

  return i;
}

#define TEST(c) do { if( FD_UNLIKELY( !(c) ) ) { /*FD_LOG_WARNING(( "FAIL: %s", #c ));*/ return FD_WKSP_ERR_CORRUPT; } } while(0)

#define TEST_AND_MARK( i ) do {                                                                              \
    ulong _i = (i);                                                                                          \
    TEST( fd_wksp_private_pinfo_idx_is_null( _i ) | ((_i<part_max) && (pinfo[ _i ].cycle_tag!=cycle_tag)) ); \
    if( !fd_wksp_private_pinfo_idx_is_null( _i ) ) pinfo[ _i ].cycle_tag = cycle_tag;                        \
  } while(0)

#define TEST_PARENT( i, p ) do {                                                       \
    ulong _i = (i);                                                                    \
    if( _i<part_max ) TEST( fd_wksp_private_pinfo_idx( pinfo[_i].parent_cidx )==(p) ); \
  } while(0)

int
fd_wksp_private_used_treap_insert( ulong                     n,
                                   fd_wksp_t *               wksp,
                                   fd_wksp_private_pinfo_t * pinfo ) {

  ulong part_max  = wksp->part_max;
  ulong cycle_tag = wksp->cycle_tag++;

  TEST( n<part_max );               /* Make sure valid n */
  pinfo[ n ].cycle_tag = cycle_tag; /* Mark n */

  ulong g0 = pinfo[ n ].gaddr_lo;
  ulong g1 = pinfo[ n ].gaddr_hi;

  TEST( (wksp->gaddr_lo<=g0) & (g0<g1) & (g1<=wksp->gaddr_hi) ); /* Make sure valid range */

  /* Note: zero tag is okay temporarily.  We assume the caller will set
     the tag to non-zero immediately afterward to make the allocation
     "official". */

  uint * _p_child_cidx = &wksp->part_used_cidx;

  ulong i = fd_wksp_private_pinfo_idx( *_p_child_cidx ); TEST_AND_MARK( i );

  /* If an empty treap, make n the root and we are done */

  if( FD_UNLIKELY( fd_wksp_private_pinfo_idx_is_null( i ) ) ) { /* Assume lots of used partitions typically */
    pinfo[ n ].in_same     = 0U;
    pinfo[ n ].left_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
    pinfo[ n ].right_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
    pinfo[ n ].same_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
    pinfo[ n ].parent_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
    *_p_child_cidx = fd_wksp_private_pinfo_cidx( n );
    return FD_WKSP_SUCCESS;
  }

  TEST_PARENT( i, FD_WKSP_PRIVATE_PINFO_IDX_NULL ); /* Make sure good parent link */

  /* Find the leaf node where we can insert n */

  /* TODO: Consider pushing path down onto stack and bubble up
     using the stack? */

  for(;;) {

    /* At this point, i is a valid marked idx with good parent
       connectivity.  TODO: Consider validating ranges of visited nodes
       and tags of visited nodes */

    /* We need to validate both left and right child links to make the
       bubble up phase robust (because we do that after we insert). */

    ulong l = fd_wksp_private_pinfo_idx( pinfo[ i ].left_cidx  ); TEST_AND_MARK( l ); TEST_PARENT( l, i );
    ulong r = fd_wksp_private_pinfo_idx( pinfo[ i ].right_cidx ); TEST_AND_MARK( r ); TEST_PARENT( r, i );

    int go_left = (g1 <= pinfo[ i ].gaddr_lo);
    if( go_left ) { /* 50/50 unpredictable */
      _p_child_cidx = &pinfo[ i ].left_cidx;
      if( fd_wksp_private_pinfo_idx_is_null( l ) ) break;
      i = l;
      continue;
    }

    int go_right = (g0 >= pinfo[ i ].gaddr_hi);
    if( FD_LIKELY( go_right ) ) {
      _p_child_cidx = &pinfo[ i ].right_cidx;
      if( fd_wksp_private_pinfo_idx_is_null( r ) ) break;
      i = r;
      continue;
    }

    /* Looks like n overlaps i */

    return FD_WKSP_ERR_CORRUPT;
  }

  /* Make n the appropriate child of i.  This might momentarily break
     the heap property. */

  pinfo[ n ].in_same     = 0U;
  pinfo[ n ].left_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ n ].right_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ n ].same_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ n ].parent_cidx = fd_wksp_private_pinfo_cidx( i );
  *_p_child_cidx         = fd_wksp_private_pinfo_cidx( n );

  /* Bubble n up until the heap property is restored.  Note that in the
     traversal above, we also validated parent links for this traversal
     (so that we could insert without worrying about encountering
     unpleasantness after we changed the treap). */

  while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
    uint n_prio = pinfo[ n ].heap_prio;
    uint i_prio = pinfo[ i ].heap_prio;
    int heap_intact = (n_prio<i_prio) | ((n_prio==i_prio) & (!((n ^ i) & 1UL))); /* Flip coin on equal priority */
    if( heap_intact ) break;

    ulong nl = fd_wksp_private_pinfo_idx( pinfo[ n ].left_cidx   ); /* Validated above */
    ulong nr = fd_wksp_private_pinfo_idx( pinfo[ n ].right_cidx  ); /* Validated above */
    ulong il = fd_wksp_private_pinfo_idx( pinfo[ i ].left_cidx   ); /* Validated above */
  //ulong ir = fd_wksp_private_pinfo_idx( pinfo[ i ].right_cidx  ); /* Validated above */
    ulong p  = fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx ); /* Validated above */
    _p_child_cidx = fd_wksp_private_pinfo_idx_is_null( p )                 ? &wksp->part_used_cidx 
                  : (fd_wksp_private_pinfo_idx( pinfo[ p ].left_cidx )==i) ? &pinfo[ p ].left_cidx   /* Validated above */
                  :                                                          &pinfo[ p ].right_cidx;

    int left_child = (il==n);
    if( left_child ) { /* 50/50 unpredictable */

      pinfo[ n ].right_cidx  = fd_wksp_private_pinfo_cidx( i  ); pinfo[ i ].parent_cidx = fd_wksp_private_pinfo_cidx( n  );
      pinfo[ n ].parent_cidx = fd_wksp_private_pinfo_cidx( p  ); *_p_child_cidx         = fd_wksp_private_pinfo_cidx( n );

      pinfo[ i ].left_cidx = fd_wksp_private_pinfo_cidx( nr );
      if( !fd_wksp_private_pinfo_idx_is_null( nr ) ) pinfo[ nr ].parent_cidx = fd_wksp_private_pinfo_cidx( i );

    } else {

      pinfo[ n ].left_cidx   = fd_wksp_private_pinfo_cidx( i  ); pinfo[ i  ].parent_cidx = fd_wksp_private_pinfo_cidx( n );
      pinfo[ n ].parent_cidx = fd_wksp_private_pinfo_cidx( p  ); *_p_child_cidx          = fd_wksp_private_pinfo_cidx( n );

      pinfo[ i ].right_cidx = fd_wksp_private_pinfo_cidx( nl );
      if( !fd_wksp_private_pinfo_idx_is_null( nl ) ) pinfo[ nl ].parent_cidx = fd_wksp_private_pinfo_cidx( i );

    }

    i = p;
  }

  return FD_WKSP_SUCCESS;
}

int
fd_wksp_private_used_treap_remove( ulong                     d,
                                   fd_wksp_t *               wksp,
                                   fd_wksp_private_pinfo_t * pinfo ) {

  ulong part_max  = wksp->part_max;
  ulong cycle_tag = wksp->cycle_tag++;

  TEST( d<part_max );
  pinfo[ d ].cycle_tag = cycle_tag; /* Mark d */

  /* d should not be in or have a same list in a used treap */

  TEST( !pinfo[ d ].in_same );
  TEST( fd_wksp_private_pinfo_idx_is_null( fd_wksp_private_pinfo_idx( pinfo[ d ].same_cidx ) ) );

  /* Load and validate the environment surrounding d. */

  ulong l = fd_wksp_private_pinfo_idx( pinfo[ d ].left_cidx   ); TEST_AND_MARK( l ); TEST_PARENT( l, d );
  ulong r = fd_wksp_private_pinfo_idx( pinfo[ d ].right_cidx  ); TEST_AND_MARK( r ); TEST_PARENT( r, d );
  ulong p = fd_wksp_private_pinfo_idx( pinfo[ d ].parent_cidx ); TEST_AND_MARK( p );

  uint * _p_child_cidx;
  if( fd_wksp_private_pinfo_idx_is_null( p ) ) {
    _p_child_cidx = &wksp->part_used_cidx;
    TEST( (*_p_child_cidx)==d );
  } else {
    ulong pl = fd_wksp_private_pinfo_idx( pinfo[ p ].left_cidx  ); /* One should be marked from above */
    ulong pr = fd_wksp_private_pinfo_idx( pinfo[ p ].right_cidx ); /* The other should not */
    int is_left_child  = (pl==d);
    int is_right_child = (pr==d);
    TEST( is_left_child!=is_right_child );
    _p_child_cidx = fd_ptr_if( is_left_child, &pinfo[ p ].left_cidx, &pinfo[ p ].right_cidx );
  }

  for(;;) {

    /* At this point, we have a non-trivial hole to fill at d.

       i and j are IDX_NULL as d has no overlapping partitions
       l is the hole's left subtree (if any), validated and marked
       r is the hole's right subtree (if any), validated and marked
       p is the hole's parent (if any), if non-NULL, validated and marked

       _p_child_cidx is the location of link from the parent to the hole
       (or the pointer to the tree root if d is the root), validated. */

    /* If the hole has no left subtree (and maybe no right subtree and
       maybe no parent), fill the hole with the right subtree (or with
       nothing if no right subtree) and we are done. */

    if( fd_wksp_private_pinfo_idx_is_null( l ) ) {
      if( !fd_wksp_private_pinfo_idx_is_null( r ) ) pinfo[ r ].parent_cidx = fd_wksp_private_pinfo_cidx( p );
      *_p_child_cidx = fd_wksp_private_pinfo_cidx( r );
      break;
    }

    /* If the hole has no right subtree but has a left subtree (and
       maybe no parent), fill the hole with the left subtree and we are
       done. */

    if( fd_wksp_private_pinfo_idx_is_null( r ) ) {
      pinfo[ l ].parent_cidx = fd_wksp_private_pinfo_cidx( p );
      *_p_child_cidx = fd_wksp_private_pinfo_cidx( l );
      break;
    }

    /* At this point we have to push the hole down the left or right
       subtree (and we still maybe have no parent).  We use the heap
       priorities to decide such that we preserve the heap property (we
       flip a coin on equal priorities).  We can omit any link updates
       from d as d is getting removed and the above just needs the
       environment around d.  Likewise, we can omit any link updates to
       d these will be ultimately replaced with links to something other
       than d before this returns. */

    uint l_prio = pinfo[ l ].heap_prio;
    uint r_prio = pinfo[ r ].heap_prio;
    int promote_left = (l_prio>r_prio) | ((l_prio==r_prio) & (!((p ^ d) & 1UL)));
    if( promote_left ) {

      ulong t = fd_wksp_private_pinfo_idx( pinfo[ l ].right_cidx ); TEST_AND_MARK( t ); TEST_PARENT( t, l );

      *_p_child_cidx        = fd_wksp_private_pinfo_cidx( l ); pinfo[ l ].parent_cidx = fd_wksp_private_pinfo_cidx( p );
    //pinfo[ l ].right_cidx = fd_wksp_private_pinfo_cidx( d ); pinfo[ d ].parent_cidx = fd_wksp_private_pinfo_cidx( l );
    //pinfo[ d ].left_cidx  = fd_wksp_private_pinfo_cidx( t );
    //if( !fd_wksp_private_pinfo_idx_is_null( t ) ) pinfo[ t ].parent_cidx = fd_wksp_private_pinfo_cidx( d );

      _p_child_cidx = &pinfo[ l ].right_cidx; /* TBD next iteration */

      p = l;
      l = t;

    } else { /* This is the mirror image of the above */

      ulong t = fd_wksp_private_pinfo_idx( pinfo[ r ].left_cidx ); TEST_AND_MARK( t ); TEST_PARENT( t, r );

      *_p_child_cidx        = fd_wksp_private_pinfo_cidx( r ); pinfo[ r ].parent_cidx = fd_wksp_private_pinfo_cidx( p );
    //pinfo[ r ].left_cidx  = fd_wksp_private_pinfo_cidx( d ); pinfo[ d ].parent_cidx = fd_wksp_private_pinfo_cidx( r );
    //pinfo[ d ].right_cidx = fd_wksp_private_pinfo_cidx( t );
    //if( !fd_wksp_private_pinfo_idx_is_null( t ) ) pinfo[ t ].parent_cidx = fd_wksp_private_pinfo_cidx( d );

      _p_child_cidx = &pinfo[ r ].left_cidx; /* TBD next iteration */

      p = r;
      r = t;

    }

  }

  pinfo[ d ].in_same     = 0U;
  pinfo[ d ].left_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ d ].right_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ d ].same_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ d ].parent_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  return FD_WKSP_SUCCESS;
}

#undef TEST_PARENT
#undef TEST_AND_MARK
#undef TEST
