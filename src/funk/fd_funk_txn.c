#include "fd_funk.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* Provide the actual transaction map implementation */

#define MAP_NAME              fd_funk_txn_map
#define MAP_T                 fd_funk_txn_t
#define MAP_KEY_T             fd_funk_txn_xid_t
#define MAP_KEY               xid
#define MAP_KEY_EQ(k0,k1)     fd_funk_txn_xid_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_txn_xid_hash((k0),(seed))
#define MAP_KEY_COPY(kd,ks)   fd_funk_txn_xid_copy((kd),(ks))
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce7172db0UL) /* Firedancer trn db version 0 */
#define MAP_IMPL_STYLE        2
#include "../util/tmpl/fd_map_giant.c"

/* As described in fd_funk_txn.h, like the extensive tests in verify
   (which, by its very nature, is called on maps whose integrity is
   unclear to the caller), these have been fortified again memory
   corruption (accidental or deliberate) by doing out of bounds memory
   access detection and cycle (infinite loop) detection in all the
   various operations below.

   This is debatably overkill but, given this code is the pointy end of
   the stick for keeping transaction histories clean (i.e. cancelling a
   a wrong transaction could lose information and publishing a wrong
   transaction is even worse), the overhead for the detection is
   minimal, and these operations aren't particularly performance
   critical anyway, seems a more-than-worthwhile safeguard.  Likewise,
   it also guarantees strict algo overheads of these in the face of
   corruption.

   When there is a corruption issue detected realtime, it is prima facie
   evidence of either software bug, hardware fault or compromised
   process.  In all cases, these functions wiill refuse to proceed
   further and abort with FD_LOG_CRIT to minimize the blast radius of
   possible corruption and give the user as much details (stack trace
   and core) to diagnose the source of the issue.  This handling is
   isolated to the below macros and thus easy to modify or disable.

   The corruption detection works by ensuring all map indices are in
   bounds and then applying a unique tag during various map traversals
   such that operations can detected if a transaction has already been
   encountered earlier in the traversal (and thus will create a
   cycle/infinite loop) in the shortest possible algorithm overhead to
   detect such a cycle. */

/* fd_funk_txn_cycle_tag returns a unique tag to use for this detection.
   It is straightforward to comment out this protection if desired.

   TODO: consider stashing something akin to this in funk, fd_map_giant
   and/or using increment (or atomic increment if want to consider
   concurrent traversals) instead of a tickcount?  Note that the only
   x86 specific code in here currently is this tickcount call.  Tag
   reuse risk for the below at practical clock rates is several decades. */

static inline ulong
fd_funk_txn_cycle_tag( void ) {
  return ((ulong)fd_tickcount())<<2; /* Note that verify uses lower 2 bits for its tags */
}

#define ASSERT_IN_MAP( txn_idx ) do {                          \
    if( FD_UNLIKELY( txn_idx>=txn_max ) )                      \
      FD_LOG_CRIT(( "memory corruption detected (bad_idx)" )); \
  } while(0)

#define ASSERT_IN_PREP( txn_idx ) do {                                            \
    if( FD_UNLIKELY( txn_idx>=txn_max ) )                                         \
      FD_LOG_CRIT(( "memory corruption detected (bad_idx)" ));                    \
    if( FD_UNLIKELY( !fd_funk_txn_map_query( map, &map[ txn_idx ].xid, NULL ) ) ) \
      FD_LOG_CRIT(( "memory corruption detected (not in prep)" ));                \
  } while(0)

#define ASSERT_UNTAGGED( txn_idx ) do {                      \
    if( FD_UNLIKELY( map[ txn_idx ].tag==tag ) )             \
      FD_LOG_CRIT(( "memory corruption detected (cycle)" )); \
  } while(0)

fd_funk_txn_t *
fd_funk_txn_prepare( fd_funk_t *               funk,
                     fd_funk_txn_t *           parent,
                     fd_funk_txn_xid_t const * xid,
                     int                       verbose ) {

  if( FD_UNLIKELY( !funk ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "NULL funk" ));
    return NULL;
  }

  fd_funk_txn_t * map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );

  if( FD_UNLIKELY( fd_funk_txn_map_is_full( map ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "too many transactions in preparation" ));
    return NULL;
  }

  ulong txn_max = fd_funk_txn_map_key_max( map );

  ulong  parent_idx;
  uint * _child_head_cidx;
  uint * _child_tail_cidx;

  if( FD_LIKELY( !parent ) ) { /* opt for incr pub */

    parent_idx = FD_FUNK_TXN_IDX_NULL;

    _child_head_cidx = &funk->child_head_cidx;
    _child_tail_cidx = &funk->child_tail_cidx;

  } else {

    parent_idx = (ulong)(parent - map);

    if( FD_UNLIKELY( (parent_idx>=txn_max) /* Out of map */ | (parent!=(map+parent_idx)) /* Bad alignment */ ) ) {
      if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "parent is not a funk transaction" ));
      return NULL;
    }

    if( FD_UNLIKELY( !fd_funk_txn_map_query( map, &parent->xid, NULL ) ) ) {
      if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "parent is not in preparation" ));
      return NULL;
    }

    _child_head_cidx = &parent->child_head_cidx;
    _child_tail_cidx = &parent->child_tail_cidx;

  }

  if( FD_UNLIKELY( !xid ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "NULL xid" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_funk_txn_xid_eq( xid, funk->last_publish ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "xid is the last published" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_funk_txn_map_query( map, xid, NULL ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "id already a transaction" ));
    return NULL;
  }

  /* Get a new transaction from the map */

  fd_funk_txn_t * txn     = fd_funk_txn_map_insert( map, xid );
  ulong           txn_idx = (ulong)(txn - map);
  ASSERT_IN_MAP( txn_idx );

  /* Join the family */

  ulong sibling_prev_idx = fd_funk_txn_idx( *_child_tail_cidx );

  int first_born = fd_funk_txn_idx_is_null( sibling_prev_idx );
  if( FD_UNLIKELY( !first_born ) ) ASSERT_IN_PREP( sibling_prev_idx ); /* opt for non-compete */

  txn->parent_cidx       = fd_funk_txn_cidx( parent_idx           );
  txn->child_head_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->child_tail_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->sibling_prev_cidx = fd_funk_txn_cidx( sibling_prev_idx     );
  txn->sibling_next_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->stack_cidx        = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->tag               = 0UL;

  /* Other dirty record tracking operations go here */

  /* TODO: consider branchless impl */
  if( FD_LIKELY( first_born ) ) *_child_head_cidx                         = fd_funk_txn_cidx( txn_idx ); /* opt for non-compete */
  else                          map[ sibling_prev_idx ].sibling_next_cidx = fd_funk_txn_cidx( txn_idx );

  *_child_tail_cidx = fd_funk_txn_cidx( txn_idx );

  return txn;
}

/* fd_funk_txn_cancel_childless cancels a transaction that is known
   to be childless.  Callers have already validated our input arguments.
   Assumes that cancelling in the app can't fail but that could be
   straightforward to support by giving this an error and plumbing
   through to abort the overall cancel operation when it hits a error. */

static void
fd_funk_txn_cancel_childless( fd_funk_t *     funk,
                              fd_funk_txn_t * map,
                              ulong           txn_max,
                              ulong           txn_idx ) {

  /* Other cancel operations go here */

  /* Leave the family */

  ulong sibling_prev_idx = fd_funk_txn_idx( map[ txn_idx ].sibling_prev_cidx );
  ulong sibling_next_idx = fd_funk_txn_idx( map[ txn_idx ].sibling_next_cidx );

  /* TODO: Consider branchless impl */

  if( FD_LIKELY( fd_funk_txn_idx_is_null( sibling_prev_idx ) ) ) { /* opt for non-compete */
    ulong parent_idx = fd_funk_txn_idx( map[ txn_idx ].parent_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) { /* No older sib and is a funk child, opt for incr pub */
      funk->child_head_cidx = fd_funk_txn_cidx( sibling_next_idx );
    } else { /* No older sib and has parent */
      ASSERT_IN_PREP( parent_idx );
      map[ parent_idx ].child_head_cidx = fd_funk_txn_cidx( sibling_next_idx );
    }
  } else { /* Has older sib */
    ASSERT_IN_PREP( sibling_prev_idx );
    map[ sibling_prev_idx ].sibling_next_cidx = fd_funk_txn_cidx( sibling_next_idx );
  }

  if( FD_LIKELY( fd_funk_txn_idx_is_null( sibling_next_idx ) ) ) { /* opt for non-compete */
    ulong parent_idx = fd_funk_txn_idx( map[ txn_idx ].parent_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) { /* No younger sib and is a funk child, opt for incr pub */
      funk->child_tail_cidx = fd_funk_txn_cidx( sibling_prev_idx );
    } else { /* No younger sib and has parent */
      ASSERT_IN_PREP( parent_idx );
      map[ parent_idx ].child_tail_cidx = fd_funk_txn_cidx( sibling_prev_idx );
    }
  } else { /* Has younger sib */
    ASSERT_IN_PREP( sibling_next_idx );
    map[ sibling_next_idx ].sibling_prev_cidx = fd_funk_txn_cidx( sibling_prev_idx );
  }

  fd_funk_txn_map_remove( map, &map[ txn_idx ].xid );
}

/* fd_funk_txn_cancel_family cancels a transaction and all its
   descendants in a tree-depth-first-ordered sense from youngest to
   oldest.  Callers have already validated our input arguments.  Returns
   the number of transactions canceled. */

static ulong
fd_funk_txn_cancel_family( fd_funk_t *     funk,
                           fd_funk_txn_t * map,
                           ulong           txn_max,
                           ulong           tag,
                           ulong           txn_idx ) {
  ulong cancel_cnt = 0UL;

  map[ txn_idx ].tag = tag;

  ulong parent_stack_idx = FD_FUNK_TXN_IDX_NULL;

  for(;;) {

    /* At this point, txn_idx appears to be valid and has been tagged. */
    
    ulong youngest_idx = fd_funk_txn_idx( map[ txn_idx ].child_tail_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( youngest_idx ) ) ) { /* txn is is childless, opt for incr pub */

      fd_funk_txn_cancel_childless( funk, map, txn_max, txn_idx ); /* If this can fail, return cancel_cnt here on fail */
      cancel_cnt++;

      txn_idx = parent_stack_idx;                                  /* Pop the parent stack */
      if( FD_LIKELY( fd_funk_txn_idx_is_null( txn_idx ) ) ) break; /* If stack is empty, we are done, opt for incr pub */
      parent_stack_idx = fd_funk_txn_idx( map[ txn_idx ].stack_cidx );
      continue;
    }
    
    /* txn has at least one child and the youngest is youngest_idx.  Tag
       the youngest child, push txn onto the parent stack and recurse
       into the youngest child. */

    ASSERT_IN_PREP ( youngest_idx );
    ASSERT_UNTAGGED( youngest_idx );
    map[ youngest_idx ].tag = tag;

    map[ txn_idx ].stack_cidx = fd_funk_txn_cidx( parent_stack_idx );
    parent_stack_idx          = txn_idx;

    txn_idx = youngest_idx;
  }

  return cancel_cnt;
}

ulong
fd_funk_txn_cancel( fd_funk_t *     funk,
                    fd_funk_txn_t * txn,
                    int             verbose ) {

  if( FD_UNLIKELY( !funk ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "NULL funk" ));
    return 0UL;
  }

  fd_funk_txn_t * map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );

  ulong txn_max = fd_funk_txn_map_key_max( map );

  ulong txn_idx = (ulong)(txn - map);

  if( FD_UNLIKELY( (txn_idx>=txn_max) /* Out of map (incl NULL) */ | (txn!=(map+txn_idx)) /* Bad alignment */ ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn is not a funk transaction" ));
    return 0UL;
  }

  if( FD_UNLIKELY( !fd_funk_txn_map_query( map, &txn->xid, NULL ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn is not in preparation" ));
    return 0UL;
  }

  return fd_funk_txn_cancel_family( funk, map, txn_max, fd_funk_txn_cycle_tag(), txn_idx );
}

/* fd_funk_txn_oldest_sibling returns the index of the oldest sibling
   in txn_idx's family.  Callers have already validated our input
   argumnets.  The caller should validate the return index. */

static inline ulong
fd_funk_txn_oldest_sibling( fd_funk_t *     funk,
                            fd_funk_txn_t * map,
                            ulong           txn_max,
                            ulong           txn_idx ) {

  ulong parent_idx = fd_funk_txn_idx( map[ txn_idx ].parent_cidx );

  if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) return fd_funk_txn_idx( funk->child_head_cidx ); /* opt for incr pub */

  ASSERT_IN_PREP( parent_idx );

  return fd_funk_txn_idx( map[ parent_idx ].child_head_cidx );
}

/* fd_funk_txn_cancel_sibling_list cancels siblings from sibling_idx down
   to the youngest sibling inclusive in the order from youngest to
   sibling_idx.  Callers have already validated our input arguments
   except sibling_idx.  Returns the number of cancelled transactions
   (should be at least 1).  If any sibling is skip_idx, it will be not
   be cancelled but still tagged as visited.  Passing
   FD_FUNK_TXN_IDX_NULL for skip_idx will cancel all siblings from
   sibling_idx to the youngest inclusive. */

static ulong
fd_funk_txn_cancel_sibling_list( fd_funk_t *     funk,
                                 fd_funk_txn_t * map,
                                 ulong           txn_max,
                                 ulong           tag,
                                 ulong           sibling_idx,
                                 ulong           skip_idx ) {

  ulong cancel_stack_idx = FD_FUNK_TXN_IDX_NULL;

  /* Push siblings_idx and its younger siblings inclusive (skipping
     sibling skip_idx if encounter) onto the cancel stack from oldest to
     youngest (such that we cancel youngest to oldest). */

  for(;;) {

    /* At this point, sibling_idx is a sibling we might want to add to
       the sibling stack.  Validate and tag it. */

    ASSERT_IN_PREP ( sibling_idx );
    ASSERT_UNTAGGED( sibling_idx );
    map[ sibling_idx ].tag = tag;

    if( FD_UNLIKELY( sibling_idx!=skip_idx ) ) { /* Not skip_idx so push onto the cancel stack, opt for non-compete */
      map[ sibling_idx ].stack_cidx = fd_funk_txn_cidx( cancel_stack_idx );
      cancel_stack_idx = sibling_idx;
    }

    ulong younger_idx = fd_funk_txn_idx( map[ sibling_idx ].sibling_next_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( younger_idx ) ) ) break; /* opt for non-compete */
    sibling_idx = younger_idx;

  }

  /* Cancel all transactions and their descendants on the cancel stack */

  ulong cancel_cnt = 0UL;

  while( !fd_funk_txn_idx_is_null( cancel_stack_idx ) ) { /* TODO: peel first iter to make more predictable? */
    ulong sibling_idx = cancel_stack_idx;
    cancel_stack_idx  = fd_funk_txn_idx( map[ sibling_idx ].stack_cidx );

    cancel_cnt += fd_funk_txn_cancel_family( funk, map, txn_max, tag, sibling_idx );
  }

  return cancel_cnt;
}

ulong
fd_funk_txn_cancel_siblings( fd_funk_t *     funk,
                             fd_funk_txn_t * txn,
                             int             verbose ) {

  if( FD_UNLIKELY( !funk ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "NULL funk" ));
    return 0UL;
  }

  fd_funk_txn_t * map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );

  ulong txn_max = fd_funk_txn_map_key_max( map );

  ulong txn_idx = (ulong)(txn - map);

  if( FD_UNLIKELY( (txn_idx>=txn_max) /* Out of map (incl NULL) */ | (txn!=(map+txn_idx)) /* Bad alignment */ ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn is not a funk transaction" ));
    return 0UL;
  }
  
  ulong oldest_idx = fd_funk_txn_oldest_sibling( funk, map, txn_max, txn_idx );

  return fd_funk_txn_cancel_sibling_list( funk, map, txn_max, fd_funk_txn_cycle_tag(), oldest_idx, txn_idx );
}

ulong
fd_funk_txn_cancel_children( fd_funk_t *     funk,
                             fd_funk_txn_t * txn,
                             int             verbose ) {

  if( FD_UNLIKELY( !funk ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "NULL funk" ));
    return 0UL;
  }

  fd_funk_txn_t * map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );

  ulong txn_max = fd_funk_txn_map_key_max( map );

  ulong oldest_idx;

  if( FD_LIKELY( !txn ) ) oldest_idx = fd_funk_txn_idx( funk->child_head_cidx ); /* opt for non-compete */
  else {

    ulong txn_idx = (ulong)(txn - map);
    if( FD_UNLIKELY( (txn_idx>=txn_max) /* Out of map */ | (txn!=(map+txn_idx)) /* Bad alignment */ ) ) {
      if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn is not a funk transaction" ));
      return 0UL;
    }

    if( FD_UNLIKELY( !fd_funk_txn_map_query( map, &txn->xid, NULL ) ) ) {
      if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn is not in preparation" ));
      return 0UL;
    }

    oldest_idx = fd_funk_txn_idx( txn->child_head_cidx );

  }
  
  return fd_funk_txn_cancel_sibling_list( funk, map, txn_max, fd_funk_txn_cycle_tag(), oldest_idx, FD_FUNK_TXN_IDX_NULL );
}

/* fd_funk_txn_publish_funk_child publishes a transaction that is known
   to be a child of funk.  Callers have already validated our input
   arguments.  Returns FD_FUNK_SUCCESS on success and an FD_FUNK_ERR_*
   code on failure. */

static int
fd_funk_txn_publish_funk_child( fd_funk_t *     funk,
                                fd_funk_txn_t * map,
                                ulong           txn_max,
                                ulong           tag,
                                ulong           txn_idx ) {

  /* Publish txn here.  If fail, preserve txn and return an error code. */

  /* At this point, txn has been committed to permanent storage */

  /* Cancel all competing transaction histories */

  ulong oldest_idx = fd_funk_txn_oldest_sibling( funk, map, txn_max, txn_idx );
  fd_funk_txn_cancel_sibling_list( funk, map, txn_max, tag, oldest_idx, txn_idx );

  /* Make all the children children of funk */

  ulong child_head_idx = fd_funk_txn_idx( map[ txn_idx ].child_head_cidx );
  ulong child_tail_idx = fd_funk_txn_idx( map[ txn_idx ].child_tail_cidx );

  ulong child_idx = child_head_idx;
  while( FD_UNLIKELY( !fd_funk_txn_idx_is_null( child_idx ) ) ) { /* opt for incr pub */

    ASSERT_IN_PREP ( child_idx );
    ASSERT_UNTAGGED( child_idx );
    map[ child_idx ].tag = tag;

    map[ child_idx ].parent_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );

    child_idx = fd_funk_txn_idx( map[ child_idx ].sibling_next_cidx );
  }

  funk->child_head_cidx = fd_funk_txn_cidx( child_head_idx );
  funk->child_tail_cidx = fd_funk_txn_cidx( child_tail_idx );

  /* Remove the mapping */

  fd_funk_txn_xid_copy( funk->last_publish, &map[ txn_idx ].xid );

  fd_funk_txn_map_remove( map, &map[ txn_idx ].xid );

  return FD_FUNK_SUCCESS;
}

ulong
fd_funk_txn_publish( fd_funk_t *     funk,
                     fd_funk_txn_t * txn,
                     int             verbose ) {

  if( FD_UNLIKELY( !funk ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "NULL funk" ));
    return 0UL;
  }

  fd_funk_txn_t * map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );

  ulong txn_max = fd_funk_txn_map_key_max( map );

  ulong txn_idx = (ulong)(txn - map);

  if( FD_UNLIKELY( (txn_idx>=txn_max) /* Out of map (incl NULL) */ | (txn!=(map+txn_idx)) /* Bad alignment */ ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn is not a funk transaction" ));
    return 0UL;
  }

  if( FD_UNLIKELY( !fd_funk_txn_map_query( map, &txn->xid, NULL ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn is not in preparation" ));
    return 0UL;
  }

  ulong tag = fd_funk_txn_cycle_tag();

  map[ txn_idx ].tag = tag;

  ulong publish_stack_idx = FD_FUNK_TXN_IDX_NULL;

  for(;;) {

    /* At this point, txn_idx is a transaction that needs to be
       published and has been tagged.  If txn is a child of funk, we are
       ready to publish txn and everything on the publish stack. */

    ulong parent_idx = fd_funk_txn_idx( map[ txn_idx ].parent_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) break; /* opt for incr pub */

    /* txn_idx has a parent.  Validate and tag it.  Push txn to the
       publish stack and recurse into the parent. */

    ASSERT_IN_PREP ( parent_idx );
    ASSERT_UNTAGGED( parent_idx );
    map[ parent_idx ].tag = tag;

    map[ txn_idx ].stack_cidx  = fd_funk_txn_cidx( publish_stack_idx );
    publish_stack_idx          = txn_idx;

    txn_idx = parent_idx;
  }

  ulong publish_cnt = 0UL;

  for(;;) {

    /* At this point, all the transactions we need to publish are
       tagged, txn is the next up publish funk and publish_stack has the
       transactions to follow in order by pop.  We use a new tag for
       each publish as txn and its sibligns we potentially visited in a
       previous iteration of this loop. */

    if( FD_UNLIKELY( fd_funk_txn_publish_funk_child( funk, map, txn_max, fd_funk_txn_cycle_tag(), txn_idx ) ) ) break;
    publish_cnt++;

    txn_idx = publish_stack_idx;
    if( FD_LIKELY( fd_funk_txn_idx_is_null( txn_idx ) ) ) break; /* opt for incr pub */
    publish_stack_idx = fd_funk_txn_idx( map[ txn_idx ].stack_cidx );
  }

  return publish_cnt;
}

int
fd_funk_txn_merge( fd_funk_t *     funk,
                   fd_funk_txn_t * txn,
                   int             verbose ) {
  if( FD_UNLIKELY( !funk ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "NULL funk" ));
    return FD_FUNK_ERR_INVAL;
  }

  fd_funk_txn_t * map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );

  ulong txn_max = fd_funk_txn_map_key_max( map );

  ulong txn_idx = (ulong)(txn - map);

  ASSERT_IN_PREP(txn_idx);
  
  if( FD_UNLIKELY(!( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->sibling_prev_cidx ) ) &
                     fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->sibling_next_cidx ) ) ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn must be an only child" ));
    return FD_FUNK_ERR_INVAL;
  }

  if( FD_UNLIKELY(!( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->child_head_cidx ) ) &
                     fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->child_tail_cidx ) ) ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn must not have children" ));
    return FD_FUNK_ERR_INVAL;
  }

  ulong parent_idx = fd_funk_txn_idx( txn->parent_cidx );
  if( FD_UNLIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) {
    if( FD_UNLIKELY( verbose ) ) FD_LOG_WARNING(( "txn must have an unpublished parent" ));
    return FD_FUNK_ERR_INVAL;
  }

  ASSERT_IN_PREP(parent_idx);

  /* Merge updated records from child into parent. Clean up child transaction. */

  /* Erase the child. This is easy because we know it is an only child. */
  fd_funk_txn_t * parent = map + parent_idx;
  parent->child_head_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  parent->child_tail_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );

  fd_funk_txn_map_remove( map, &txn->xid );

  return FD_FUNK_SUCCESS;
}

int
fd_funk_txn_verify( fd_funk_t * funk ) {
  fd_wksp_t *     wksp = fd_funk_wksp( funk );          /* Previously verified */
  fd_funk_txn_t * map  = fd_funk_txn_map( funk, wksp ); /* Previously verified */

  ulong funk_child_head_idx = fd_funk_txn_idx( funk->child_head_cidx ); /* Previously verified */
  ulong funk_child_tail_idx = fd_funk_txn_idx( funk->child_tail_cidx ); /* Previously verified */

  fd_funk_txn_xid_t const * last_publish = funk->last_publish; /* Previously verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

# define IS_VALID( idx ) ((idx==FD_FUNK_TXN_IDX_NULL) || ((idx<txn_max) && (!fd_funk_txn_xid_eq( &map[idx].xid, last_publish ))))

  TEST( !fd_funk_txn_map_verify( map ) );

  ulong txn_max  =           fd_funk_txn_map_key_max( map );
  ulong free_cnt = txn_max - fd_funk_txn_map_key_cnt( map );

  /* Tag all transactions as not visited yet */

  for( ulong txn_idx=0UL; txn_idx<txn_max; txn_idx++ ) map[ txn_idx ].tag = 0UL;

  /* Visit all transactions in preparation, traversing from oldest to
     youngest. */

  ulong prep_cnt = 0UL;
  do {

    /* Push all children of funk to the stack */

    ulong stack_idx = FD_FUNK_TXN_IDX_NULL;
    ulong child_idx = funk_child_head_idx;
    while( !fd_funk_txn_idx_is_null( child_idx ) ) {

      /* Make sure valid idx, not tagged (detects cycles) and child
         knows it is a child of funk.  Then tag as visited / in-prep,
         push to stack and update prep_cnt */

      TEST( IS_VALID( child_idx ) );
      TEST( !map[ child_idx ].tag );
      TEST( fd_funk_txn_idx_is_null( fd_funk_txn_idx( map[ child_idx ].parent_cidx ) ) );
      map[ child_idx ].tag        = 1UL;
      map[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
      stack_idx                   = child_idx;
      prep_cnt++;

      child_idx = fd_funk_txn_idx( map[ child_idx ].sibling_next_cidx );
    }

    while( !fd_funk_txn_idx_is_null( stack_idx ) ) {

      /* Pop the next transaction to traverse */

      ulong txn_idx = stack_idx;
      stack_idx = fd_funk_txn_idx( map[ txn_idx ].stack_cidx );

      /* Push all children of txn to the stack */

      ulong child_idx = fd_funk_txn_idx( map[ txn_idx ].child_head_cidx );
      while( !fd_funk_txn_idx_is_null( child_idx ) ) {

        /* Make sure valid idx, not tagged (detects cycles) and child
           knows it is a child of txn_idx.  Then tag as visited /
           in-prep, push to stack and update prep_cnt */

        TEST( IS_VALID( child_idx ) );
        TEST( !map[ child_idx ].tag );
        TEST( fd_funk_txn_idx( map[ child_idx ].parent_cidx )==txn_idx );
        map[ child_idx ].tag        = 1UL;
        map[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
        stack_idx                   = child_idx;
        prep_cnt++;

        child_idx = fd_funk_txn_idx( map[ child_idx ].sibling_next_cidx );
      }
    }

  } while(0);

  TEST( (free_cnt+prep_cnt)==txn_max );

  /* Do it again with a youngest to oldest traversal to test reverse
     link integrity */

  prep_cnt = 0UL;
  do {

    /* Push all children of funk to the stack */

    ulong stack_idx = FD_FUNK_TXN_IDX_NULL;
    ulong child_idx = funk_child_tail_idx;
    while( !fd_funk_txn_idx_is_null( child_idx ) ) {

      /* Make sure valid idx, tagged as visited above (detects cycles)
         and child knows it is a child of funk.  Then tag as visited /
         in-prep, push to stack and update prep_cnt */

      TEST( IS_VALID( child_idx ) );
      TEST( map[ child_idx ].tag==1UL );
      TEST( fd_funk_txn_idx_is_null( fd_funk_txn_idx( map[ child_idx ].parent_cidx ) ) );
      map[ child_idx ].tag        = 2UL;
      map[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
      stack_idx                   = child_idx;
      prep_cnt++;

      child_idx = fd_funk_txn_idx( map[ child_idx ].sibling_prev_cidx );
    }

    while( !fd_funk_txn_idx_is_null( stack_idx ) ) {

      /* Pop the next transaction to traverse */

      ulong txn_idx = stack_idx;
      stack_idx = fd_funk_txn_idx( map[ txn_idx ].stack_cidx );

      /* Push all children of txn to the stack */

      ulong child_idx = fd_funk_txn_idx( map[ txn_idx ].child_tail_cidx );
      while( !fd_funk_txn_idx_is_null( child_idx ) ) {

        /* Make sure valid idx, tagged as visted above (detects cycles)
           and child knows it is a child of txn_idx.  Then, tag as
           visited / in-prep, push to stack and update prep_cnt */

        TEST( IS_VALID( child_idx ) );
        TEST( map[ child_idx ].tag==1UL );
        TEST( fd_funk_txn_idx( map[ child_idx ].parent_cidx )==txn_idx );
        map[ child_idx ].tag        = 2UL;
        map[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
        stack_idx                   = child_idx;
        prep_cnt++;

        child_idx = fd_funk_txn_idx( map[ child_idx ].sibling_prev_cidx );
      }
    }
  } while(0);

  TEST( (free_cnt+prep_cnt)==txn_max );

  TEST( fd_funk_txn_cnt( map )==prep_cnt );

# undef IS_VALID
# undef TEST

  return FD_FUNK_SUCCESS;
}

#undef ASSERT_UNTAGGED
#undef ASSERT_IN_PREP
#undef ASSERT_IN_MAP

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */
