#include "fd_funk_txn.h"
#include "fd_funk.h"

/* Provide the actual transaction map implementation */

#define POOL_NAME          fd_funk_txn_pool
#define POOL_ELE_T         fd_funk_txn_t
#define POOL_IDX_T         uint
#define POOL_NEXT          map_next
#define POOL_IMPL_STYLE    2
#include "../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_funk_txn_map
#define MAP_ELE_T             fd_funk_txn_t
#define MAP_KEY_T             fd_funk_txn_xid_t
#define MAP_KEY               xid
#define MAP_KEY_EQ(k0,k1)     fd_funk_txn_xid_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_txn_xid_hash((k0),(seed))
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce7172db0UL) /* Firedancer txn db version 0 */
#define MAP_IMPL_STYLE        2
#include "../util/tmpl/fd_map_chain_para.c"

#define fd_funk_txn_state_transition(txn, before, after) do {             \
  FD_LOG_INFO(( "funk_txn laddr=%p xid=%lu:%lu state change (%u-%s) -> (%u-%s)", \
                (void *)(txn),                                            \
                (txn)->xid.ul[0], (txn)->xid.ul[1],                       \
                (before), fd_funk_txn_state_str( (before) ),              \
                (after),  fd_funk_txn_state_str( (after)  ) ));           \
  if( FD_HAS_ATOMIC ) {                                                   \
    if( FD_LIKELY( __sync_bool_compare_and_swap( &(txn)->state, before, after ) ) ) break; \
  } else {                                                                \
    if( FD_LIKELY( (txn)->state == (before) ) ) {                         \
      (txn)->state = (after);                                             \
      break;                                                              \
    }                                                                     \
  }                                                                       \
  uint have_ = FD_VOLATILE_CONST( (txn)->state );                         \
  FD_LOG_CRIT(( "Detected data race on funk txn %p: expected state %u-%s, found %u-%s, while transitioning to %u-%s", \
                (void *)(txn),                                            \
                (before), fd_funk_txn_state_str( before ),                \
                have_,    fd_funk_txn_state_str( have_  ),                \
                (after),  fd_funk_txn_state_str( after  ) ));             \
} while(0)

#define fd_funk_last_publish_transition(funk_shmem, after) do {           \
    fd_funk_shmem_t *   _shmem    = (funk_shmem);                         \
    fd_funk_txn_xid_t * _last_pub = _shmem->last_publish;                 \
    fd_funk_txn_xid_t   _prev_pub[1]; fd_funk_txn_xid_copy( _prev_pub, _last_pub ); \
    fd_funk_txn_xid_copy( _last_pub, (after) );                           \
    FD_LOG_INFO(( "funk last_publish (%lu:%lu) -> (%lu:%lu)",             \
                  _prev_pub->ul[0], _prev_pub->ul[1],                     \
                  _last_pub->ul[0], _last_pub->ul[1] ));                  \
  } while(0)

void
fd_funk_txn_prepare( fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * parent_xid,
                     fd_funk_txn_xid_t const * xid ) {

  if( FD_UNLIKELY( !funk       ) ) FD_LOG_CRIT(( "NULL funk"       ));
  if( FD_UNLIKELY( !parent_xid ) ) FD_LOG_CRIT(( "NULL parent_xid" ));
  if( FD_UNLIKELY( !xid        ) ) FD_LOG_CRIT(( "NULL xid"        ));
  if( FD_UNLIKELY( fd_funk_txn_xid_eq_root( xid ) ) ) FD_LOG_CRIT(( "xid is root" ));

  if( FD_UNLIKELY( fd_funk_txn_xid_eq( xid, funk->shmem->last_publish ) ) ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare failed: xid %lu:%lu is the last published",
                 xid->ul[0], xid->ul[1] ));
  }

  fd_funk_txn_map_query_t query[1];
  if( FD_UNLIKELY( fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 ) != FD_MAP_ERR_KEY ) ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare failed: xid %lu:%lu already in use",
                 xid->ul[0], xid->ul[1] ));
  }

  ulong  parent_idx;
  uint * _child_head_cidx;
  uint * _child_tail_cidx;

  if( FD_UNLIKELY( fd_funk_txn_xid_eq( parent_xid, funk->shmem->last_publish ) ) ) {

    parent_idx = FD_FUNK_TXN_IDX_NULL;

    _child_head_cidx = &funk->shmem->child_head_cidx;
    _child_tail_cidx = &funk->shmem->child_tail_cidx;

  } else {

    int query_err = fd_funk_txn_map_query_try( funk->txn_map, parent_xid, NULL, query, 0 );
    if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) {
      FD_LOG_CRIT(( "fd_funk_txn_prepare failed: user provided invalid parent XID %lu:%lu (err %i-%s)",
                    parent_xid->ul[0], parent_xid->ul[1],
                    query_err, fd_map_strerror( query_err ) ));
    }

    fd_funk_txn_t * parent = fd_funk_txn_map_query_ele( query );
    fd_funk_txn_state_assert( parent, FD_FUNK_TXN_STATE_ACTIVE );
    parent_idx = (ulong)(parent - funk->txn_pool->ele);

    _child_head_cidx = &parent->child_head_cidx;
    _child_tail_cidx = &parent->child_tail_cidx;

  }

  /* Get a new transaction from the map */

  fd_funk_txn_t * txn = fd_funk_txn_pool_acquire( funk->txn_pool, NULL, 1, NULL );
  if( FD_UNLIKELY( !txn ) ) FD_LOG_ERR(( "fd_funk_txn_prepare failed: transaction object pool out of memory" ));
  fd_funk_txn_xid_copy( &txn->xid, xid );
  ulong txn_idx = (ulong)(txn - funk->txn_pool->ele);

  /* Join the family */

  ulong sibling_prev_idx = fd_funk_txn_idx( *_child_tail_cidx );

  int first_born = fd_funk_txn_idx_is_null( sibling_prev_idx );

  txn->parent_cidx       = fd_funk_txn_cidx( parent_idx           );
  txn->child_head_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->child_tail_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->sibling_prev_cidx = fd_funk_txn_cidx( sibling_prev_idx     );
  txn->sibling_next_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->stack_cidx        = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->tag               = 0UL;

  fd_funk_txn_state_transition( txn, FD_FUNK_TXN_STATE_FREE, FD_FUNK_TXN_STATE_ACTIVE );
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;

  /* TODO: consider branchless impl */
  if( FD_LIKELY( first_born ) ) *_child_head_cidx                = fd_funk_txn_cidx( txn_idx ); /* opt for non-compete */
  else funk->txn_pool->ele[ sibling_prev_idx ].sibling_next_cidx = fd_funk_txn_cidx( txn_idx );

  *_child_tail_cidx = fd_funk_txn_cidx( txn_idx );

  if( parent_xid ) {
    if( FD_UNLIKELY( fd_funk_txn_map_query_test( query )!=FD_MAP_SUCCESS ) ) {
      FD_LOG_CRIT(( "Detected data race while preparing a funk txn" ));
    }
  }

  fd_funk_txn_map_insert( funk->txn_map, txn, FD_MAP_FLAG_BLOCKING );
}

int
fd_funk_txn_verify( fd_funk_t * funk ) {
  fd_funk_txn_map_t *  txn_map  = funk->txn_map;
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;
  ulong                txn_max  = fd_funk_txn_pool_ele_max( txn_pool );

  ulong funk_child_head_idx = fd_funk_txn_idx( funk->shmem->child_head_cidx ); /* Previously verified */
  ulong funk_child_tail_idx = fd_funk_txn_idx( funk->shmem->child_tail_cidx ); /* Previously verified */

  fd_funk_txn_xid_t const * last_publish = funk->shmem->last_publish; /* Previously verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

# define IS_VALID( idx ) ( (idx==FD_FUNK_TXN_IDX_NULL) || \
                           ((idx<txn_max) && (!fd_funk_txn_xid_eq( fd_funk_txn_xid( &txn_pool->ele[idx] ), last_publish ))) )

  TEST( !fd_funk_txn_map_verify( txn_map ) );
  TEST( !fd_funk_txn_pool_verify( txn_pool ) );

  /* Tag all transactions as not visited yet */

  for( ulong txn_idx=0UL; txn_idx<txn_max; txn_idx++ ) txn_pool->ele[ txn_idx ].tag = 0UL;

  /* Visit all transactions in preparation, traversing from oldest to
     youngest. */

  do {

    /* Push all children of funk to the stack */

    ulong stack_idx = FD_FUNK_TXN_IDX_NULL;
    ulong child_idx = funk_child_head_idx;
    while( !fd_funk_txn_idx_is_null( child_idx ) ) {

      /* Make sure valid idx, not tagged (detects cycles) and child
         knows it is a child of funk.  Then tag as visited / in-prep,
         push to stack and update prep_cnt */

      TEST( IS_VALID( child_idx ) );
      TEST( !txn_pool->ele[ child_idx ].tag );
      TEST( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx ) ) );
      txn_pool->ele[ child_idx ].tag        = 1UL;
      txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
      stack_idx                   = child_idx;

      ulong next_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_next_cidx );
      if( !fd_funk_txn_idx_is_null( next_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ next_idx ].sibling_prev_cidx )==child_idx );
      child_idx = next_idx;
    }

    while( !fd_funk_txn_idx_is_null( stack_idx ) ) {

      /* Pop the next transaction to traverse */

      ulong txn_idx = stack_idx;
      stack_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].stack_cidx );

      /* Push all children of txn to the stack */

      ulong child_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].child_head_cidx );
      while( !fd_funk_txn_idx_is_null( child_idx ) ) {

        /* Make sure valid idx, not tagged (detects cycles) and child
           knows it is a child of txn_idx.  Then tag as visited /
           in-prep, push to stack and update prep_cnt */

        TEST( IS_VALID( child_idx ) );
        TEST( !txn_pool->ele[ child_idx ].tag );
        TEST( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx )==txn_idx );
        txn_pool->ele[ child_idx ].tag        = 1UL;
        txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
        stack_idx                   = child_idx;

        ulong next_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_next_cidx );
        if( !fd_funk_txn_idx_is_null( next_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ next_idx ].sibling_prev_cidx )==child_idx );
        child_idx = next_idx;
      }
    }

  } while(0);

  /* Do it again with a youngest to oldest traversal to test reverse
     link integrity */

  do {

    /* Push all children of funk to the stack */

    ulong stack_idx = FD_FUNK_TXN_IDX_NULL;
    ulong child_idx = funk_child_tail_idx;
    while( !fd_funk_txn_idx_is_null( child_idx ) ) {

      /* Make sure valid idx, tagged as visited above (detects cycles)
         and child knows it is a child of funk.  Then tag as visited /
         in-prep, push to stack and update prep_cnt */

      TEST( IS_VALID( child_idx ) );
      TEST( txn_pool->ele[ child_idx ].tag==1UL );
      TEST( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx ) ) );
      txn_pool->ele[ child_idx ].tag        = 2UL;
      txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
      stack_idx                             = child_idx;

      ulong prev_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_prev_cidx );
      if( !fd_funk_txn_idx_is_null( prev_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ prev_idx ].sibling_next_cidx )==child_idx );
      child_idx = prev_idx;
    }

    while( !fd_funk_txn_idx_is_null( stack_idx ) ) {

      /* Pop the next transaction to traverse */

      ulong txn_idx = stack_idx;
      stack_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].stack_cidx );

      /* Push all children of txn to the stack */

      ulong child_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].child_tail_cidx );
      while( !fd_funk_txn_idx_is_null( child_idx ) ) {

        /* Make sure valid idx, tagged as visited above (detects cycles)
           and child knows it is a child of txn_idx.  Then, tag as
           visited / in-prep, push to stack and update prep_cnt */

        TEST( IS_VALID( child_idx ) );
        TEST( txn_pool->ele[ child_idx ].tag==1UL );
        TEST( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx )==txn_idx );
        txn_pool->ele[ child_idx ].tag        = 2UL;
        txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
        stack_idx                             = child_idx;

        ulong prev_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_prev_cidx );
        if( !fd_funk_txn_idx_is_null( prev_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ prev_idx ].sibling_next_cidx )==child_idx );
        child_idx = prev_idx;
      }
    }
  } while(0);

# undef IS_VALID
# undef TEST

  return FD_FUNK_SUCCESS;
}
