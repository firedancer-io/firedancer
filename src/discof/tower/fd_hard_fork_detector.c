#include "fd_hard_fork_detector.h"

struct stake {
  fd_pubkey_t pubkey;
  ulong       stake;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong next;
  } pool;
};

typedef struct stake stake_t;

#define POOL_NAME  stake_pool
#define POOL_T     stake_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               stake_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              stake_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct voted_on_key {
  fd_pubkey_t block_id;
  fd_pubkey_t vote_account;
};

typedef struct voted_on_key voted_on_key_t;

struct voted_on {
  voted_on_key_t key;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong next;
    ulong prev;
  } dlist;

  struct {
    ulong next;
  } pool;
};

typedef struct voted_on voted_on_t;

#define POOL_NAME  voted_on_pool
#define POOL_T     voted_on_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               voted_on_map
#define MAP_KEY                key
#define MAP_ELE_T              voted_on_t
#define MAP_KEY_T              voted_on_key_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      ( fd_pubkey_eq( &((k0)->block_id), &((k1)->block_id) ) &\
                                fd_pubkey_eq( &((k0)->vote_account), &((k1)->vote_account) ) )
#define MAP_KEY_HASH(key,seed) ( seed ^ fd_ulong_load_8( (key)->block_id.uc ) ^ fd_ulong_load_8( (key)->vote_account.uc ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  voted_on_lru
#define DLIST_ELE_T voted_on_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct block_result_key {
  fd_pubkey_t block_id;
  fd_pubkey_t bank_hash;
};

typedef struct block_result_key block_result_key_t;

struct block_result {
  block_result_key_t key;
  ulong              voter_count;
  ulong              stake;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong prev;
    ulong next;
  } dlist;

  struct {
    ulong next;
  } pool;
};

typedef struct block_result block_result_t;

#define POOL_NAME  block_result_pool
#define POOL_T     block_result_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               block_result_map
#define MAP_KEY                key
#define MAP_ELE_T              block_result_t
#define MAP_KEY_T              block_result_key_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      ( fd_pubkey_eq( &((k0)->block_id),   &((k1)->block_id)   ) &\
                                fd_pubkey_eq( &((k0)->bank_hash), &((k1)->bank_hash) ) )
#define MAP_KEY_HASH(key,seed) ( seed ^ fd_ulong_load_8( (key)->block_id.uc ) ^ fd_ulong_load_8( (key)->bank_hash.uc ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  block_result_dlist
#define DLIST_ELE_T block_result_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct my_result {
  fd_pubkey_t block_id;
  fd_pubkey_t bank_hash;

  ulong slot;

  int invalid;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong next;
    ulong prev;
  } dlist;

  struct {
    ulong next;
  } pool;
};

typedef struct my_result my_result_t;

#define POOL_NAME  my_vote_pool
#define POOL_T     my_result_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               my_vote_map
#define MAP_KEY                block_id
#define MAP_ELE_T              my_result_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  my_vote_lru
#define DLIST_ELE_T my_result_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct block_id {
  fd_pubkey_t block_id;

  block_result_dlist_t * dlist;

  struct {
    ulong next;
    ulong prev;
  } map;

  struct {
    ulong next;
  } pool;
};

typedef struct block_id block_id_t;

#define POOL_NAME  block_id_pool
#define POOL_T     block_id_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               block_id_map
#define MAP_KEY                block_id
#define MAP_ELE_T              block_id_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_hard_fork_detector_private {
  ulong total_stake;

  int fatal;

  stake_t *     stake_pool;
  stake_map_t * stake_map;

  voted_on_t *     voted_on_pool;
  voted_on_map_t * voted_on_map;
  voted_on_lru_t * voted_on_lru;

  block_result_t *     block_result_pool;
  block_result_map_t * block_result_map;

  my_result_t *   my_vote_pool;
  my_vote_map_t * my_vote_map;
  my_vote_lru_t * my_vote_lru;

  block_id_t *     block_id_pool;
  block_id_map_t * block_id_map;

  ulong magic;
};

FD_FN_CONST ulong
fd_hard_fork_detector_align( void ) {
  return FD_HARD_FORK_DETECTOR_ALIGN;
}

FD_FN_CONST ulong
fd_hard_fork_detector_footprint( ulong max_live_slots,
                                 ulong max_vote_accounts ) {
  if( FD_UNLIKELY( !max_vote_accounts ) ) return 0UL;

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, stake_pool_align(),        stake_pool_footprint( 2UL*max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),         stake_map_footprint( fd_ulong_pow2_up( 2UL*max_vote_accounts ) ) );
  l = FD_LAYOUT_APPEND( l, voted_on_pool_align(),     voted_on_pool_footprint( max_live_slots*max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, voted_on_map_align(),      voted_on_map_footprint( fd_ulong_pow2_up( max_live_slots*max_vote_accounts ) ) );
  l = FD_LAYOUT_APPEND( l, voted_on_lru_align(),      voted_on_lru_footprint() );
  l = FD_LAYOUT_APPEND( l, block_result_pool_align(), block_result_pool_footprint( max_live_slots*max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, block_result_map_align(),  block_result_map_footprint( fd_ulong_pow2_up( max_live_slots*max_vote_accounts ) ) );
  l = FD_LAYOUT_APPEND( l, my_vote_pool_align(),      my_vote_pool_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, my_vote_map_align(),       my_vote_map_footprint( fd_ulong_pow2_up( max_live_slots ) ) );
  l = FD_LAYOUT_APPEND( l, my_vote_lru_align(),       my_vote_lru_footprint() );
  l = FD_LAYOUT_APPEND( l, block_id_pool_align(),     block_id_pool_footprint( max_live_slots*max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, block_id_map_align(),      block_id_map_footprint( fd_ulong_pow2_up( max_live_slots*max_vote_accounts ) ) );
  return FD_LAYOUT_FINI( l, FD_HARD_FORK_DETECTOR_ALIGN );
}

void *
fd_hard_fork_detector_new( void *        shmem,
                           ulong         max_live_slots,
                           ulong         max_vote_accounts,
                           int           fatal,
                           ulong         seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_hard_fork_detector_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_vote_accounts ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_hard_fork_detector_t * hf = FD_SCRATCH_ALLOC_APPEND( l, FD_HARD_FORK_DETECTOR_ALIGN, sizeof(fd_hard_fork_detector_t) );
  void * _stake_pool           = FD_SCRATCH_ALLOC_APPEND( l, stake_pool_align(),          stake_pool_footprint( 2UL*max_vote_accounts ) );
  void * _stake_map            = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(),           stake_map_footprint( fd_ulong_pow2_up( 2UL*max_vote_accounts ) ) );
  void * _voted_on_pool        = FD_SCRATCH_ALLOC_APPEND( l, voted_on_pool_align(),       voted_on_pool_footprint( max_live_slots*max_vote_accounts ) );
  void * _voted_on_map         = FD_SCRATCH_ALLOC_APPEND( l, voted_on_map_align(),        voted_on_map_footprint( fd_ulong_pow2_up( max_live_slots*max_vote_accounts ) ) );
  void * _voted_on_lru         = FD_SCRATCH_ALLOC_APPEND( l, voted_on_lru_align(),        voted_on_lru_footprint() );
  void * _block_result_pool    = FD_SCRATCH_ALLOC_APPEND( l, block_result_pool_align(),   block_result_pool_footprint( max_live_slots*max_vote_accounts ) );
  void * _block_result_map     = FD_SCRATCH_ALLOC_APPEND( l, block_result_map_align(),    block_result_map_footprint( fd_ulong_pow2_up( max_live_slots*max_vote_accounts ) ) );
  void * _my_vote_pool         = FD_SCRATCH_ALLOC_APPEND( l, my_vote_pool_align(),        my_vote_pool_footprint( max_live_slots ) );
  void * _my_vote_map          = FD_SCRATCH_ALLOC_APPEND( l, my_vote_map_align(),         my_vote_map_footprint( fd_ulong_pow2_up( max_live_slots ) ) );
  void * _my_vote_lru          = FD_SCRATCH_ALLOC_APPEND( l, my_vote_lru_align(),         my_vote_lru_footprint() );
  void * _block_id_pool        = FD_SCRATCH_ALLOC_APPEND( l, block_id_pool_align(),       block_id_pool_footprint( max_live_slots*max_vote_accounts ) );
  void * _block_id_map         = FD_SCRATCH_ALLOC_APPEND( l, block_id_map_align(),        block_id_map_footprint( fd_ulong_pow2_up( max_live_slots*max_vote_accounts ) ) );

  hf->stake_pool = stake_pool_join( stake_pool_new( _stake_pool, 2UL*max_vote_accounts ) );
  FD_TEST( hf->stake_pool );

  hf->stake_map = stake_map_join( stake_map_new( _stake_map, fd_ulong_pow2_up( 2UL*max_vote_accounts ), seed ) );
  FD_TEST( hf->stake_map );

  hf->voted_on_pool = voted_on_pool_join( voted_on_pool_new( _voted_on_pool, max_live_slots*max_vote_accounts ) );
  FD_TEST( hf->voted_on_pool );

  hf->voted_on_map = voted_on_map_join( voted_on_map_new( _voted_on_map, fd_ulong_pow2_up( max_live_slots*max_vote_accounts ), seed ) );
  FD_TEST( hf->voted_on_map );

  hf->voted_on_lru = voted_on_lru_join( voted_on_lru_new( _voted_on_lru ) );
  FD_TEST( hf->voted_on_lru );

  hf->block_result_pool = block_result_pool_join( block_result_pool_new( _block_result_pool, max_live_slots*max_vote_accounts ) );
  FD_TEST( hf->block_result_pool );

  hf->block_result_map = block_result_map_join( block_result_map_new( _block_result_map, fd_ulong_pow2_up( max_live_slots*max_vote_accounts ), seed ) );
  FD_TEST( hf->block_result_map );

  hf->my_vote_pool = my_vote_pool_join( my_vote_pool_new( _my_vote_pool, max_live_slots ) );
  FD_TEST( hf->my_vote_pool );

  hf->my_vote_map = my_vote_map_join( my_vote_map_new( _my_vote_map, fd_ulong_pow2_up( max_live_slots ), seed ) );
  FD_TEST( hf->my_vote_map );

  hf->my_vote_lru = my_vote_lru_join( my_vote_lru_new( _my_vote_lru ) );
  FD_TEST( hf->my_vote_lru );

  hf->block_id_pool = block_id_pool_join( block_id_pool_new( _block_id_pool, max_live_slots*max_vote_accounts ) );
  FD_TEST( hf->block_id_pool );

  hf->block_id_map = block_id_map_join( block_id_map_new( _block_id_map, fd_ulong_pow2_up( max_live_slots*max_vote_accounts ), seed ) );
  FD_TEST( hf->block_id_map );

  hf->fatal = fatal;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hf->magic ) = FD_HARD_FORK_DETECTOR_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)hf;
}

fd_hard_fork_detector_t *
fd_hard_fork_detector_join( void * shhf ) {
  if( FD_UNLIKELY( !shhf ) ) {
    FD_LOG_WARNING(( "NULL shhf" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhf, fd_hard_fork_detector_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhf" ));
    return NULL;
  }

  fd_hard_fork_detector_t * hf = (fd_hard_fork_detector_t *)shhf;

  if( FD_UNLIKELY( hf->magic!=FD_HARD_FORK_DETECTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return hf;
}

void
fd_hard_fork_detector_stakes( fd_hard_fork_detector_t *     detector,
                              fd_stake_weight_msg_t const * epoch_stakes ) {
  FD_TEST( epoch_stakes->staked_cnt<=stake_pool_max( detector->stake_pool ) );

  detector->total_stake = 0UL;

  stake_pool_reset( detector->stake_pool );
  stake_map_reset( detector->stake_map );

  for( ulong i=0UL; i<epoch_stakes->staked_cnt; i++ ) {
    fd_vote_stake_weight_t const * sw = &epoch_stakes->weights[ i ];

    stake_t * entry = stake_pool_ele_acquire( detector->stake_pool );
    fd_memcpy( entry->pubkey.uc, sw->vote_key.uc, 32UL );
    entry->stake = sw->stake;

    detector->total_stake += sw->stake;

    stake_map_ele_insert( detector->stake_map, entry, detector->stake_pool );
  }
}

static void
check( fd_hard_fork_detector_t const * detector,
       block_result_t const *          block_result ) {
  my_result_t const * my_result = my_vote_map_ele_query_const( detector->my_vote_map, fd_type_pun_const( block_result->key.block_id.uc ), NULL, detector->my_vote_pool );
  if( FD_UNLIKELY( !my_result ) ) return; /* Haven't got a result yet, so can't have hard forked */

  if( FD_UNLIKELY( my_result->invalid ) ) {
    char msg[ 4096UL ];
    FD_TEST( fd_cstr_printf_check( msg, sizeof( msg ), NULL,
                                  "HARD FORK DETECTED: our validator has marked slot %lu with block ID `%s` dead, but %lu validators with %.1f of stake have voted on it",
                                  my_result->slot,
                                  FD_BASE58_ENC_32_ALLOCA( block_result->key.block_id.uc ),
                                  block_result->voter_count,
                                  100.0*(double)block_result->stake/(double)detector->total_stake ) );

    if( detector->fatal ) FD_LOG_ERR(( "%s", msg ));
    else                  FD_LOG_WARNING(( "%s", msg ));
  } else {
    if( FD_UNLIKELY( memcmp( my_result->bank_hash.uc, block_result->key.bank_hash.uc, 32UL ) ) ) {
      char msg[ 4096UL ];
      FD_TEST( fd_cstr_printf_check( msg, sizeof( msg ), NULL,
                                    "HARD FORK DETECTED: our validator has produced block hash `%s` for slot %lu with block ID `%s`, but %lu validators with %.1f of stake have voted on a different block hash `%s` for the same slot",
                                    FD_BASE58_ENC_32_ALLOCA( my_result->bank_hash.uc ),
                                    my_result->slot,
                                    FD_BASE58_ENC_32_ALLOCA( my_result->block_id.uc ),
                                    block_result->voter_count,
                                    100.0*(double)block_result->stake/(double)detector->total_stake,
                                    FD_BASE58_ENC_32_ALLOCA( block_result->key.bank_hash.uc ) ) );

      if( detector->fatal ) FD_LOG_ERR(( "%s", msg ));
      else                  FD_LOG_WARNING(( "%s", msg ));
    }
  }
}

void
fd_hard_fork_detector_vote( fd_hard_fork_detector_t * detector,
                            uchar const *             vote_account,
                            uchar const *             block_id,
                            uchar const *             bank_hash ) {
  stake_t const * _stake = stake_map_ele_query_const( detector->stake_map, fd_type_pun_const( vote_account ), NULL, detector->stake_pool );
  if( FD_UNLIKELY( !_stake ) ) return; /* Don't care about votes from unstaked */

  voted_on_key_t vo_key;
  fd_memcpy( vo_key.block_id.uc,     block_id,     32UL );
  fd_memcpy( vo_key.vote_account.uc, vote_account, 32UL );
  voted_on_t const * already_visited = voted_on_map_ele_query_const( detector->voted_on_map, &vo_key, NULL, detector->voted_on_pool );
  if( FD_UNLIKELY( already_visited ) ) return; /* Don't care about another vote for same thing */

  if( FD_UNLIKELY( !voted_on_pool_free( detector->voted_on_pool ) ) ) {
    /* TODO: Currently we just evict from the voted_on pool by LRU, but
       it would be better to evict a bit more intelligently, by age
       (older than root can evict first), then by max per vote account
       (>4096 votes per account can evict, by account LRU), and then by
       stake weight (lower stake weight evict first, LRU).  It's a bit
       annoying to implement, and this whole structure is best-effort so
       it's not critical. */

    voted_on_t * lru_voted_on = voted_on_lru_ele_pop_tail( detector->voted_on_lru, detector->voted_on_pool );
    FD_TEST( voted_on_map_ele_remove( detector->voted_on_map, fd_type_pun_const( &lru_voted_on->key ), NULL, detector->voted_on_pool ) );
    voted_on_pool_ele_release( detector->voted_on_pool, lru_voted_on );

    block_result_t * lru_block_result = block_result_map_ele_query( detector->block_result_map, fd_type_pun_const( lru_voted_on->key.block_id.uc ), NULL, detector->block_result_pool );
    FD_TEST( lru_block_result );

    lru_block_result->voter_count -= 1UL;
    if( FD_UNLIKELY( !lru_block_result->voter_count ) ) {
      FD_TEST( block_result_map_ele_remove( detector->block_result_map, fd_type_pun_const( &lru_block_result->key ), NULL, detector->block_result_pool ) );
      block_result_pool_ele_release( detector->block_result_pool, lru_block_result );

      block_id_t * lru_block_id = block_id_map_ele_query( detector->block_id_map, fd_type_pun_const( lru_block_result->key.block_id.uc ), NULL, detector->block_id_pool );
      FD_TEST( lru_block_id );
      block_result_dlist_ele_remove( lru_block_id->dlist, lru_block_result, detector->block_result_pool );
      if( FD_UNLIKELY( block_result_dlist_is_empty( lru_block_id->dlist, detector->block_result_pool ) ) ) {
        FD_TEST( block_id_map_ele_remove( detector->block_id_map, fd_type_pun_const( &lru_block_id->block_id ), NULL, detector->block_id_pool ) );
        block_id_pool_ele_release( detector->block_id_pool, lru_block_id );
      }
    }
  }

  voted_on_t * voted_on = voted_on_pool_ele_acquire( detector->voted_on_pool );
  fd_memcpy( voted_on->key.block_id.uc,     block_id,     32UL );
  fd_memcpy( voted_on->key.vote_account.uc, vote_account, 32UL );
  voted_on_map_ele_insert( detector->voted_on_map, voted_on, detector->voted_on_pool );
  voted_on_lru_ele_push_head( detector->voted_on_lru, voted_on, detector->voted_on_pool );

  block_result_key_t br_key;
  fd_memcpy( br_key.block_id.uc,   block_id,   32UL );
  fd_memcpy( br_key.bank_hash.uc, bank_hash, 32UL );

  block_result_t * block_result = block_result_map_ele_query( detector->block_result_map, fd_type_pun_const( bank_hash ), NULL, detector->block_result_pool );
  if( FD_UNLIKELY( !block_result ) ) {
    /* Guaranteed to be space, because the block result pool is larger
       than the voted on pool, and there can be at most one unique
       block result per vote. */
    FD_TEST( block_result_pool_free( detector->block_result_pool ) );

    block_result = block_result_pool_ele_acquire( detector->block_result_pool );
    fd_memcpy( block_result->key.block_id.uc,   block_id,   32UL );
    fd_memcpy( block_result->key.bank_hash.uc, bank_hash, 32UL );
    block_result->stake = 0UL;
    block_result_map_ele_insert( detector->block_result_map, block_result, detector->block_result_pool );
  }

  block_id_t * block_id_entry = block_id_map_ele_query( detector->block_id_map, fd_type_pun_const( block_id ), NULL, detector->block_id_pool );
  if( FD_UNLIKELY( !block_id_entry ) ) {
    /* Guaranteed to be space, because the block id pool is larger than
       the block result pool, and there can be at most one unique
       block id per block result. */
    FD_TEST( block_id_pool_free( detector->block_id_pool ) );

    block_id_entry = block_id_pool_ele_acquire( detector->block_id_pool );
    fd_memcpy( block_id_entry->block_id.uc, block_id, 32UL );
    block_result_dlist_remove_all( block_id_entry->dlist, detector->block_result_pool );
    block_id_map_ele_insert( detector->block_id_map, block_id_entry, detector->block_id_pool );
  }

  int majority_before = block_result->stake*100UL/detector->total_stake>=52UL;
  block_result->stake += _stake->stake;
  block_result->voter_count += 1UL;
  int majority_after  = block_result->stake*100UL/detector->total_stake>=52UL;

  if( FD_UNLIKELY( !majority_before && majority_after ) ) check( detector, block_result );
}

void
fd_hard_fork_detector_block( fd_hard_fork_detector_t * detector,
                             ulong                     slot,
                             uchar const *             block_id,
                             uchar const *             bank_hash ) {
  if( FD_LIKELY( !my_vote_pool_free( detector->my_vote_pool ) ) ) {
    /* Might also be good eventually to evict a little bit smarter here ... */
    my_result_t * lru_result = my_vote_lru_ele_pop_tail( detector->my_vote_lru, detector->my_vote_pool );
    FD_TEST( my_vote_map_ele_remove( detector->my_vote_map, fd_type_pun_const( lru_result->block_id.uc ), NULL, detector->my_vote_pool ) );
    my_vote_pool_ele_release( detector->my_vote_pool, lru_result );
  }

  my_result_t * my_result = my_vote_pool_ele_acquire( detector->my_vote_pool );
  my_result->slot = slot;
  fd_memcpy( my_result->block_id.uc,   block_id,   32UL );
  fd_memcpy( my_result->bank_hash.uc, bank_hash, 32UL );

  uchar zero32[32] = {0};
  if( FD_UNLIKELY( !memcmp( bank_hash, zero32, 32UL ) ) ) my_result->invalid = 1;

  my_vote_map_ele_insert( detector->my_vote_map, my_result, detector->my_vote_pool );
  my_vote_lru_ele_push_head( detector->my_vote_lru, my_result, detector->my_vote_pool );

  block_id_t * found_block_id = block_id_map_ele_query( detector->block_id_map, fd_type_pun_const( block_id ), NULL, detector->block_id_pool );
  if( FD_UNLIKELY( !found_block_id ) ) return;

  for( block_result_dlist_iter_t iter = block_result_dlist_iter_fwd_init( found_block_id->dlist, detector->block_result_pool );
        !block_result_dlist_iter_done( iter, found_block_id->dlist, detector->block_result_pool );
        iter = block_result_dlist_iter_fwd_next( iter, found_block_id->dlist, detector->block_result_pool ) ) {
    block_result_t * block_result = block_result_dlist_iter_ele( iter, found_block_id->dlist, detector->block_result_pool );
    if( FD_LIKELY( block_result->stake*100UL/detector->total_stake<52UL ) ) continue;

    check( detector, block_result );
  }
}
