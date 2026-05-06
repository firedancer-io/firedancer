#include "fd_voter.h"
#include "../../choreo/fd_choreo_base.h"
#include "../../choreo/tower/fd_tower_serde.h"
#include "../../flamenco/accdb/fd_accdb_pipe.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

#define MAP_NAME               vtr_map
#define MAP_ELE_T              fd_voter_vtr_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY                vote_acc
#define MAP_KEY_EQ(k0,k1)     (!memcmp((k0),(k1),sizeof(fd_pubkey_t)))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash((key)->ul[1]^(seed))
#define MAP_NEXT               map.next
#define MAP_PREV               map.prev
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME vtr_pool
#define POOL_T    fd_voter_vtr_t
#define POOL_NEXT map.next
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  vtr_dlist
#define DLIST_ELE_T fd_voter_vtr_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct fd_voter {
  ulong               root_epoch;
  ulong               seed;
  ulong               vtr_max;
  fd_epoch_schedule_t epoch_schedule[1];

  vtr_map_t *      curr_map;
  fd_voter_vtr_t * curr_pool;
  vtr_dlist_t *    curr_dlist;

  vtr_map_t *      next_map;
  fd_voter_vtr_t * next_pool;
  vtr_dlist_t *    next_dlist;
};

static void
clear( vtr_map_t *      map,
                fd_voter_vtr_t * pool,
                vtr_dlist_t *    dlist ) {
  while( !vtr_dlist_is_empty( dlist, pool ) ) {
    fd_voter_vtr_t * ele = vtr_dlist_ele_pop_head( dlist, pool );
    vtr_map_ele_remove_fast( map, ele, pool );
    vtr_pool_ele_release( pool, ele );
  }
}

static void
update( vtr_map_t *               map,
        fd_voter_vtr_t *          pool,
        vtr_dlist_t *             dlist,
        fd_top_votes_t const *    top_votes,
        ulong                     target_epoch,
        fd_accdb_user_t *         accdb,
        fd_funk_txn_xid_t const * xid ) {
  uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) top_votes_iter_[ FD_TOP_VOTES_ITER_FOOTPRINT ];
  fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes, top_votes_iter_ );

  fd_accdb_ro_pipe_t ro_pipe[1];
  fd_accdb_ro_pipe_init( ro_pipe, accdb, xid );

  ulong pending_cnt = 0;
  for(;;) {
    if( FD_UNLIKELY( fd_top_votes_iter_done( top_votes, iter ) ) ) {
      if( !pending_cnt ) break;
      fd_accdb_ro_pipe_flush( ro_pipe );
    } else {
      fd_pubkey_t vote_acc;
      ulong       stake;
      int is_valid = fd_top_votes_iter_ele( top_votes, iter, &vote_acc, NULL, &stake, NULL, NULL, NULL );
      fd_top_votes_iter_next( top_votes, iter );
      if( FD_UNLIKELY( !is_valid ) ) continue;

      fd_accdb_ro_pipe_enqueue( ro_pipe, vote_acc.key );
      pending_cnt++;
    }

    fd_accdb_ro_t * ro;
    while( FD_LIKELY( ro = fd_accdb_ro_pipe_poll( ro_pipe ) ) ) {
      pending_cnt--;
      fd_pubkey_t const * vote_acc = fd_accdb_ref_address( ro );

      ulong stake;
      int is_valid = fd_top_votes_query( top_votes, vote_acc, NULL, &stake, NULL, NULL, NULL );
      if( FD_UNLIKELY( !is_valid ) ) continue;

      if( FD_UNLIKELY( !fd_accdb_ref_lamports( ro ) || !fd_vsv_is_correct_size_owner_and_init( ro->meta ) ) ) continue;

      uchar const * data = (uchar const *)fd_accdb_ref_data_const( ro );

      ulong av_cnt = fd_vote_acc_authorized_voter_cnt( data );
      fd_authorized_voter_t const * avs = fd_vote_acc_authorized_voters( data );
      fd_pubkey_t auth_voter = pubkey_null;
      for( ulong i = 0; i < av_cnt; i++ ) {
        if( avs[i].epoch <= target_epoch ) auth_voter = avs[i].pubkey;
        else break;
      }

      fd_voter_vtr_t * vtr = vtr_pool_ele_acquire( pool );
      vtr->vote_acc         = *vote_acc;
      vtr->stake            = stake;
      vtr->authorized_voter = auth_voter;
      vtr_map_ele_insert( map, vtr, pool );
      vtr_dlist_ele_push_tail( dlist, vtr, pool );
    }
  }
  fd_accdb_ro_pipe_fini( ro_pipe );
}

FD_FN_CONST ulong
fd_voter_align( void ) {
  return FD_VOTER_ALIGN;
}

FD_FN_PURE ulong
fd_voter_footprint( ulong vtr_max ) {
  ulong pool_max  = fd_ulong_pow2_up( vtr_max );
  ulong chain_cnt = vtr_map_chain_cnt_est( vtr_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_voter_t), sizeof(fd_voter_t) );
  for( ulong i = 0; i < 2; i++ ) {
    l = FD_LAYOUT_APPEND( l, vtr_pool_align(),  vtr_pool_footprint( pool_max )  );
    l = FD_LAYOUT_APPEND( l, vtr_map_align(),   vtr_map_footprint( chain_cnt )  );
    l = FD_LAYOUT_APPEND( l, vtr_dlist_align(), vtr_dlist_footprint()            );
  }
  return FD_LAYOUT_FINI( l, fd_voter_align() );
}

void *
fd_voter_new( void * shmem,
              ulong  vtr_max,
              ulong  seed ) {
  ulong pool_max  = fd_ulong_pow2_up( vtr_max );
  ulong chain_cnt = vtr_map_chain_cnt_est( vtr_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_voter_t * voter      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_voter_t), sizeof(fd_voter_t)                );
  void       * curr_pool  = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),    vtr_pool_footprint( pool_max )    );
  void       * curr_map   = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),     vtr_map_footprint( chain_cnt )    );
  void       * curr_dlist = FD_SCRATCH_ALLOC_APPEND( l, vtr_dlist_align(),   vtr_dlist_footprint()              );
  void       * next_pool  = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),    vtr_pool_footprint( pool_max )    );
  void       * next_map   = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),     vtr_map_footprint( chain_cnt )    );
  void       * next_dlist = FD_SCRATCH_ALLOC_APPEND( l, vtr_dlist_align(),   vtr_dlist_footprint()              );
  FD_SCRATCH_ALLOC_FINI( l, fd_voter_align() );

  vtr_pool_new ( curr_pool,  pool_max );
  vtr_map_new  ( curr_map,   chain_cnt, seed );
  vtr_dlist_new( curr_dlist );

  vtr_pool_new ( next_pool,  pool_max );
  vtr_map_new  ( next_map,   chain_cnt, seed );
  vtr_dlist_new( next_dlist );

  voter->root_epoch = ULONG_MAX;
  voter->seed       = seed;
  voter->vtr_max    = vtr_max;

  return shmem;
}

fd_voter_t *
fd_voter_join( void * shvoter ) {
  FD_SCRATCH_ALLOC_INIT( l, shvoter );
  fd_voter_t * voter = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_voter_t), sizeof(fd_voter_t) );

  ulong pool_max  = fd_ulong_pow2_up( voter->vtr_max );
  ulong chain_cnt = vtr_map_chain_cnt_est( voter->vtr_max );

  void * curr_pool  = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),  vtr_pool_footprint( pool_max )  );
  void * curr_map   = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),   vtr_map_footprint( chain_cnt )  );
  void * curr_dlist = FD_SCRATCH_ALLOC_APPEND( l, vtr_dlist_align(), vtr_dlist_footprint()            );
  void * next_pool  = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),  vtr_pool_footprint( pool_max )  );
  void * next_map   = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),   vtr_map_footprint( chain_cnt )  );
  void * next_dlist = FD_SCRATCH_ALLOC_APPEND( l, vtr_dlist_align(), vtr_dlist_footprint()            );
  FD_SCRATCH_ALLOC_FINI( l, fd_voter_align() );

  voter->curr_pool  = vtr_pool_join ( curr_pool  );
  voter->curr_map   = vtr_map_join  ( curr_map   );
  voter->curr_dlist = vtr_dlist_join( curr_dlist );

  voter->next_pool  = vtr_pool_join ( next_pool  );
  voter->next_map   = vtr_map_join  ( next_map   );
  voter->next_dlist = vtr_dlist_join( next_dlist );

  return voter;
}

void *
fd_voter_leave( fd_voter_t const * voter ) {
  return (void *)voter;
}

void *
fd_voter_delete( void * shvoter ) {
  return shvoter;
}

fd_voter_vtr_t const *
fd_voter_query( fd_voter_t        * voter,
                fd_pubkey_t const * vote_acc,
                ulong               slot ) {
  ulong epoch = fd_slot_to_epoch( voter->epoch_schedule, slot, NULL );

  if( FD_LIKELY( epoch==voter->root_epoch ) ) {
    return vtr_map_ele_query_const( voter->curr_map, vote_acc, NULL, voter->curr_pool );
  } else if( FD_LIKELY( epoch==voter->root_epoch + 1 ) ) {
    return vtr_map_ele_query_const( voter->next_map, vote_acc, NULL, voter->next_pool );
  }

  return NULL;
}

void
fd_voter_update( fd_voter_t      * voter,
                 fd_accdb_user_t * accdb,
                 fd_banks_t      * banks,
                 ulong             slot,
                 ulong             bank_idx ) {

  clear( voter->curr_map, voter->curr_pool, voter->curr_dlist );
  clear( voter->next_map, voter->next_pool, voter->next_dlist );

  fd_bank_t * bank = fd_banks_bank_query( banks, bank_idx );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_CRIT(( "invariant violation: bank %lu is missing", bank_idx ));

  *voter->epoch_schedule = bank->f.epoch_schedule;
  ulong epoch = fd_slot_to_epoch( voter->epoch_schedule, slot, NULL );
  fd_funk_txn_xid_t xid  = { .ul = { slot, bank_idx } };

  fd_top_votes_t const * top_votes_t_2 = fd_bank_top_votes_t_2_query( bank );
  if( FD_LIKELY( top_votes_t_2 ) ) {
    update( voter->curr_map, voter->curr_pool, voter->curr_dlist, top_votes_t_2, epoch, accdb, &xid );
  }

  fd_top_votes_t const * top_votes_t_1 = fd_bank_top_votes_t_1_query( bank );
  if( FD_LIKELY( top_votes_t_1 ) ) {
    update( voter->next_map, voter->next_pool, voter->next_dlist, top_votes_t_1, epoch + 1, accdb, &xid );
  }

  voter->root_epoch = epoch;
}
