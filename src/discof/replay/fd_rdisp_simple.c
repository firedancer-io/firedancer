#include "fd_rdisp.h"

struct fd_rdisp_txn {
  uint index; /* technically not even needed */
  union {
    struct {
      uint  staged:1;
      uint  staging_lane:2; /* ignored if staged==0 */
      uint  dispatched:1;
    };
    int flags;
  };
  uint next;
};
typedef struct fd_rdisp_txn fd_rdisp_txn_t;

#define POOL_NAME     pool
#define POOL_T        fd_rdisp_txn_t
#define POOL_IDX_T    uint
#define POOL_SENTINEL 1
#include "../../util/tmpl/fd_pool.c"


#define SLIST_NAME  txn_ll
#define SLIST_ELE_T fd_rdisp_txn_t
#define SLIST_IDX_T uint
#include "../../util/tmpl/fd_slist.c"

struct fd_rdisp_blockinfo {
  FD_RDISP_BLOCK_TAG_T block;
  uint  insert_ready:1;
  uint  schedule_ready:1;
  uint  staged:1;
  uint  staging_lane:2; /* ignored if staged==0 */
  uint inserted_cnt;
  uint map_chain_next;
  uint ll_next;
  txn_ll_t ll[ 1 ];
};
typedef struct fd_rdisp_blockinfo fd_rdisp_blockinfo_t;

#define POOL_NAME     block_pool
#define POOL_T        fd_rdisp_blockinfo_t
#define POOL_IDX_T    uint
#define POOL_NEXT     ll_next
#define POOL_SENTINEL 1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  block_map
#define MAP_ELE_T fd_rdisp_blockinfo_t
#define MAP_KEY_T FD_RDISP_BLOCK_TAG_T
#define MAP_KEY   block
#define MAP_NEXT  map_chain_next
#define MAP_IDX_T uint
#include "../../util/tmpl/fd_map_chain.c"

#define SLIST_NAME  block_slist
#define SLIST_ELE_T fd_rdisp_blockinfo_t
#define SLIST_IDX_T uint
#define SLIST_NEXT  ll_next
#include "../../util/tmpl/fd_slist.c"

struct fd_rdisp_unstaged {
  FD_RDISP_BLOCK_TAG_T block;
};
typedef struct fd_rdisp_unstaged fd_rdisp_unstaged_t;

struct fd_rdisp {
  ulong depth;
  ulong block_depth;

  fd_rdisp_txn_t       * pool;
  fd_rdisp_unstaged_t  * unstaged; /* parallel to pool with additional info */

  int free_lanes; /* a bitmask */
  block_map_t          * blockmap; /* map chain */
  block_slist_t          lanes[ 4 ];
  fd_rdisp_blockinfo_t * block_pool;
};

typedef struct fd_rdisp fd_rdisp_t;


//FIXME: Make sure this is the largest alignment
ulong fd_rdisp_align( void ) { return alignof(fd_rdisp_t); }

ulong
fd_rdisp_footprint( ulong depth,
                    ulong block_depth ) {
  ulong chain_cnt = block_map_chain_cnt_est( block_depth );
  // FIXME: check that vals are in bounds
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  l = FD_LAYOUT_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) ); /* pool       */
  l = FD_LAYOUT_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) ); /* unstaged   */
  l = FD_LAYOUT_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) ); /* blockmap   */
  l = FD_LAYOUT_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) ); /* block_pool */
  return FD_LAYOUT_FINI( l, fd_rdisp_align() );
}

void *
fd_rdisp_new( void * mem,
              ulong  depth,
              ulong  block_depth ) {
  // FIXME: check that vals are in bounds
  ulong chain_cnt = block_map_chain_cnt_est( block_depth );
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_rdisp_t * disp   = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  void       * _pool  = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) );
  void       * _unstg = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) );
  void       * _bmap  = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) );
  void       * _bpool = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_rdisp_align() );

  disp->depth      = depth;
  disp->block_depth = block_depth;

  pool_new( _pool, depth );
  memset( _unstg, '\0', sizeof(fd_rdisp_unstaged_t)*(depth+1UL) );

  disp->free_lanes = 0xF;
  block_map_new( _bmap, chain_cnt, 12UL ); // TODO: seed
  for( ulong i=0UL; i<4UL; i++ ) block_slist_new( disp->lanes+i );
  block_pool_new( _bpool, block_depth+1UL );

  fd_rdisp_txn_t * temp_join = pool_join( _pool );
  for( ulong i=0UL; i<depth+1UL; i++ ) temp_join[ i ].index = (uint)i;
  pool_leave( temp_join);

  return disp;
}

fd_rdisp_t *
fd_rdisp_join( void * mem ) {
  fd_rdisp_t * disp = (fd_rdisp_t *)mem;

  ulong depth       = disp->depth;
  ulong block_depth = disp->block_depth;
  ulong chain_cnt   = block_map_chain_cnt_est( block_depth );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*                */  FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             sizeof(fd_rdisp_t)                              );
  void       * _pool  = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                 pool_footprint              ( depth+1UL       ) );
  void       * _unstg = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_unstaged_t), sizeof(fd_rdisp_unstaged_t)*( depth+1UL       ) );
  void       * _bmap  = FD_SCRATCH_ALLOC_APPEND( l, block_map_align(),            block_map_footprint         ( chain_cnt       ) );
  void       * _bpool = FD_SCRATCH_ALLOC_APPEND( l, block_pool_align(),           block_pool_footprint        ( block_depth+1UL ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_rdisp_align() );

  disp->pool       = pool_join( _pool );
  disp->unstaged   = (fd_rdisp_unstaged_t *)_unstg;
  disp->blockmap   = block_map_join( _bmap );
  for( ulong i=0UL; i<4UL; i++ ) block_slist_join( disp->lanes+i );
  disp->block_pool = block_pool_join( _bpool );

  return disp;
}

ulong
fd_rdisp_suggest_staging_lane( fd_rdisp_t const *   disp,
                               FD_RDISP_BLOCK_TAG_T parent_block,
                               int                  duplicate ) {

  /* 1. If it's a duplicate, suggest FD_RDISP_UNSTAGED */
  if( FD_UNLIKELY( duplicate ) ) return FD_RDISP_UNSTAGED;

  /* 2. If parent is the last block in any existing staging lane, suggest
        that lane */
  fd_rdisp_blockinfo_t const * block_pool = disp->block_pool;
  fd_rdisp_blockinfo_t const * block = block_map_ele_query_const( disp->blockmap, &parent_block, NULL, block_pool );
  if( FD_LIKELY( block && block->insert_ready && block->staged ) ) return block->staging_lane;

  /* 3. If there is at least one free lane, suggest a free lane */
  if( FD_LIKELY( disp->free_lanes!=0 ) ) return (ulong)fd_uint_find_lsb( (uint)disp->free_lanes );

  /* 4. Else, suggest FD_RDISP_UNSTAGED */
  return FD_RDISP_UNSTAGED;
}

int
fd_rdisp_add_block( fd_rdisp_t          * disp,
                   FD_RDISP_BLOCK_TAG_T   new_block,
                   ulong                  staging_lane ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  if( FD_UNLIKELY( !block_pool_free( block_pool )                                                             ) ) return -1;
  if( FD_UNLIKELY(  ULONG_MAX!=block_map_idx_query_const( disp->blockmap, &new_block, ULONG_MAX, block_pool ) ) ) return -1;
  fd_rdisp_blockinfo_t * block = block_pool_ele_acquire( block_pool );
  block->block = new_block;
  block_map_ele_insert( disp->blockmap, block, block_pool );

  block->inserted_cnt = 0U;
  block->insert_ready = 1;
  block->staged       = staging_lane!=FD_RDISP_UNSTAGED;
  block->staging_lane = (uint)(staging_lane & 0x3UL);
  txn_ll_join( txn_ll_new( block->ll ) );

  if( FD_UNLIKELY( staging_lane==FD_RDISP_UNSTAGED ) ) block->schedule_ready = 1;
  else {
    block_slist_t * sl = disp->lanes + staging_lane;

    block->schedule_ready = (uint)(1 & (disp->free_lanes >> staging_lane));
    disp->free_lanes &= ~(1 << staging_lane);
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) )  block_slist_ele_peek_tail( sl, block_pool )->insert_ready = 0;
    block_slist_ele_push_tail( sl, block, block_pool );
  }
  return 0;
}

int
fd_rdisp_remove_block( fd_rdisp_t          * disp,
                       FD_RDISP_BLOCK_TAG_T   block_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, block_pool );
  if( FD_UNLIKELY( block==NULL ) ) return -1;

  FD_TEST( block->schedule_ready );
  FD_TEST( txn_ll_is_empty( block->ll, disp->pool ) );

  if( FD_LIKELY( block->staged ) ) {
    ulong staging_lane = (ulong)block->staging_lane;
    block_slist_t * sl = disp->lanes + staging_lane;

    FD_TEST( block==block_slist_ele_peek_head( sl, block_pool ) );
    block_slist_idx_pop_head( sl, block_pool );
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
    else                                                       disp->free_lanes |= 1<<staging_lane;
  }
  txn_ll_delete( txn_ll_leave( block->ll ) );
  block_pool_idx_release( block_pool, block_map_idx_remove( disp->blockmap, &block_tag, ULONG_MAX, block_pool ) );

  return 0;
}


int
fd_rdisp_abandon_block( fd_rdisp_t          * disp,
                        FD_RDISP_BLOCK_TAG_T   block_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, disp->block_pool );
  if( FD_UNLIKELY( block==NULL ) ) return -1;

  FD_TEST( block->schedule_ready );
  while( !txn_ll_is_empty( block->ll, disp->pool ) ) {
    pool_idx_release( disp->pool, txn_ll_idx_pop_head( block->ll, disp->pool ) );
  }

  if( FD_LIKELY( block->staged ) ) {
    ulong staging_lane = (ulong)block->staging_lane;
    block_slist_t * sl = disp->lanes + staging_lane;

    FD_TEST( block==block_slist_ele_peek_head( sl, block_pool ) );
    block_slist_idx_pop_head( sl, block_pool );
    if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
    else                                                       disp->free_lanes |= 1<<staging_lane;
  }
  txn_ll_delete( txn_ll_leave( block->ll ) );
  block_pool_idx_release( disp->block_pool, block_map_idx_remove( disp->blockmap, &block_tag, ULONG_MAX, disp->block_pool ) );

  return 0;
}

int
fd_rdisp_promote_block( fd_rdisp_t *          disp,
                        FD_RDISP_BLOCK_TAG_T  block_tag,
                        ulong                 staging_lane ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;
  block_slist_t * sl = disp->lanes + staging_lane;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, block_pool );
  if( FD_UNLIKELY( block==NULL   ) ) return -1;
  if( FD_UNLIKELY( block->staged ) ) return -1;

  block->staged = 1;
  block->staging_lane = (uint)(staging_lane & 0x3);
  block->insert_ready = 1;
  block->schedule_ready = (uint)(1 & (disp->free_lanes >> staging_lane));

  disp->free_lanes &= ~(1 << staging_lane);
  if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) )  block_slist_ele_peek_tail( sl, block_pool )->insert_ready = 0;
  block_slist_ele_push_tail( disp->lanes + staging_lane, block, block_pool );

  int dispatched = 0;
  for( txn_ll_iter_t iter = txn_ll_iter_init( block->ll, disp->pool );
      !txn_ll_iter_done( iter, block->ll, disp->pool );
      iter = txn_ll_iter_next( iter, block->ll, disp->pool ) ) {
    fd_rdisp_txn_t * ele = txn_ll_iter_ele( iter, block->ll, disp->pool );
    ele->staged = 1;
    ele->staging_lane = (uint)(staging_lane & 0x3);
    dispatched |= ele->dispatched;
  }
  if( FD_UNLIKELY( dispatched ) ) FD_LOG_ERR(( "promote_block called with dispatched txn" ));

  return 0;
}

int
fd_rdisp_demote_block( fd_rdisp_t *          disp,
                       FD_RDISP_BLOCK_TAG_T  block_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &block_tag, NULL, block_pool );
  if( FD_UNLIKELY(  block==NULL           ) ) return -1;
  if( FD_UNLIKELY( !block->staged         ) ) return -1;
  if( FD_UNLIKELY( !block->schedule_ready ) ) return -1;
  if( FD_UNLIKELY( !txn_ll_is_empty( block->ll, disp->pool ) ) ) FD_LOG_ERR(( "demote_block called with non-empty block" ));
  ulong staging_lane = block->staging_lane;
  block->staged = 0;

  block_slist_t * sl = disp->lanes + staging_lane;

  /* staged and schedule_ready means it must be the head of the staging lane */
  FD_TEST( block_slist_ele_peek_head( disp->lanes + staging_lane, block_pool )==block );
  block_slist_idx_pop_head( disp->lanes + staging_lane, block_pool );

  if( FD_LIKELY( !block_slist_is_empty( sl, block_pool ) ) ) block_slist_ele_peek_head( sl, block_pool )->schedule_ready = 1;
  else                                                       disp->free_lanes |= 1<<staging_lane;
  return 0;
}

int
fd_rdisp_rekey_block( fd_rdisp_t *           disp,
                      FD_RDISP_BLOCK_TAG_T   new_tag,
                      FD_RDISP_BLOCK_TAG_T   old_tag ) {
  fd_rdisp_blockinfo_t * block_pool = disp->block_pool;

  if( FD_UNLIKELY(        NULL!= block_map_ele_query_const( disp->blockmap, &new_tag, NULL, block_pool ) ) ) return -1;
  fd_rdisp_blockinfo_t * block = block_map_ele_query      ( disp->blockmap, &old_tag, NULL, block_pool );
  if( FD_UNLIKELY(        NULL== block ) )                                                                   return -1;

  block->block = new_tag;
  block_map_ele_insert( disp->blockmap, block, block_pool );
  return 0;
}

ulong
fd_rdisp_add_txn( fd_rdisp_t          *  disp,
                  FD_RDISP_BLOCK_TAG_T   insert_block,
                  fd_txn_t const       * txn,
                  uchar const          * payload,
                  fd_acct_addr_t const * alts,
                  int                    serializing ) {
  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &insert_block, NULL, disp->block_pool );
  if( FD_UNLIKELY( !block || !block->insert_ready ) ) return 0UL;
  if( FD_UNLIKELY( !pool_free( disp->pool   ) ) ) return 0UL;
  block->inserted_cnt++;

  ulong idx = pool_idx_acquire( disp->pool );
  fd_rdisp_txn_t * rtxn = disp->pool + idx;
  FD_TEST( rtxn->index==(uint)idx );

  rtxn->flags = 0;
  rtxn->staged = block->staged;
  rtxn->staging_lane = block->staging_lane;

  (void)txn;
  (void)payload;
  (void)alts;
  (void)serializing; /* they're all serializing in this version */

  if( FD_UNLIKELY( !block->staged ) ) disp->unstaged[ idx ]=(fd_rdisp_unstaged_t) { .block = insert_block };

  txn_ll_ele_push_tail( block->ll, rtxn, disp->pool );
  return idx;
}

ulong
fd_rdisp_get_next_ready( fd_rdisp_t           * disp,
                         FD_RDISP_BLOCK_TAG_T   schedule_block ) {
  fd_rdisp_blockinfo_t * block   = block_map_ele_query( disp->blockmap, &schedule_block, NULL, disp->block_pool );
  if( FD_UNLIKELY( !block || !block->schedule_ready ) ) return 0UL;

  if( FD_UNLIKELY( txn_ll_is_empty( block->ll, disp->pool ) ) ) return 0UL;
  ulong idx = txn_ll_idx_peek_head( block->ll, disp->pool );
  fd_rdisp_txn_t * rtxn = disp->pool + idx;
  if( FD_UNLIKELY( rtxn->dispatched ) ) return 0UL;

  rtxn->dispatched = 1;
  return idx;
}

void
fd_rdisp_complete_txn( fd_rdisp_t * disp,
                       ulong        txn_idx ) {
  fd_rdisp_txn_t * rtxn = disp->pool + txn_idx;
  FD_TEST( rtxn->dispatched );
  fd_rdisp_blockinfo_t * block;
  if( FD_LIKELY( rtxn->staged ) ) {
    block = block_slist_ele_peek_head( disp->lanes + rtxn->staging_lane, disp->block_pool );
  } else {
    block = block_map_ele_query( disp->blockmap, &disp->unstaged[ txn_idx ].block, NULL, disp->block_pool );
  }
  FD_TEST( rtxn==txn_ll_ele_peek_head( block->ll, disp->pool ) );
  txn_ll_ele_pop_head( block->ll, disp->pool );
}


ulong
fd_rdisp_staging_lane_info( fd_rdisp_t           const * disp,
                            fd_rdisp_staging_lane_info_t out_sched[ static 4 ] ) {
  (void)out_sched; /* TODO: poplulate */
  return 0xFUL & ~(ulong)disp->free_lanes;
}

void * fd_rdisp_leave ( fd_rdisp_t * disp ) { return disp; }
void * fd_rdisp_delete( void * mem        ) { return  mem; }
