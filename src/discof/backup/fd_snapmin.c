#include "fd_snapmin.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/fd_builtin_programs.h"
#include "../../flamenco/runtime/program/fd_precompiles.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/rewards/fd_epoch_inflation_account.h"
#include "../../flamenco/rewards/fd_reward_epoch_delegated_stakes.h"
#include "../../flamenco/alpenglow/fd_alpenglow.h"
#include "../../util/pod/fd_pod_format.h"

#define MAP_NAME                  fd_snapmin_map
#define MAP_ELE_T                 fd_snapmin_ele_t
#define MAP_KEY_T                 fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)         fd_pubkey_eq( (k0), (k1) )
#define MAP_KEY_HASH(key,seed)    fd_hash( (seed), (key), sizeof(fd_pubkey_t) )
#define MAP_ELE_IS_FREE(ctx,ele)  (!(ele)->used)
#define MAP_ELE_FREE(ctx,ele)     do { (ele)->used = 0UL; } while(0)
#define MAP_ELE_MOVE(ctx,dst,src) do { *(dst) = *(src); (src)->used = 0UL; } while(0)
#define MAP_VERSION_T             ushort
#define MAP_LOCK_MAX              (8192)
#define MAP_IMPL_STYLE            2
#include "../../util/tmpl/fd_map_slot_para.c"

#define FD_SNAPMIN_MAGIC (0xf17eda2c375a9a10UL) /* firedancer snapmin version 0 */

/* sha256 of "firedancer snapshot minimizer" */
fd_pubkey_t const fd_snapmin_balance_key = { .uc = {
  0x7aU,0xbbU,0xc4U,0xdcU,0xbdU,0xbdU,0x61U,0x47U,0x28U,0xf3U,0x1dU,0xfdU,0xa6U,0x73U,0x63U,0xe8U,
  0xdfU,0x58U,0x89U,0xbfU,0x9fU,0x85U,0x87U,0x04U,0x25U,0x24U,0xd2U,0x52U,0x9dU,0x0aU,0x74U,0x58U
} };

static ulong
map_footprint( ulong ele_max ) {
  return fd_snapmin_map_footprint( ele_max,
                                   fd_snapmin_map_lock_cnt_est ( ele_max ),
                                   fd_snapmin_map_probe_max_est( ele_max ) );
}

ulong
fd_snapmin_align( void ) {
  return fd_snapmin_map_align();
}

/* The header takes the first fd_snapmin_align() bytes, the map
   follows and the element store comes last. */

ulong
fd_snapmin_footprint( ulong ele_max ) {
  if( FD_UNLIKELY( !map_footprint( ele_max ) ) ) return 0UL;
  ulong ele_sz = fd_ulong_align_up( ele_max*sizeof(fd_snapmin_ele_t), fd_snapmin_align() );
  return fd_snapmin_align() + map_footprint( ele_max ) + ele_sz;
}

void *
fd_snapmin_new( void * shmem,
                ulong  ele_max,
                ulong  seed ) {
  if( FD_UNLIKELY( !fd_snapmin_footprint( ele_max ) ) ) {
    FD_LOG_WARNING(( "ele_max %lu is not a power of two", ele_max ));
    return NULL;
  }
  fd_snapmin_shmem_t * hdr = shmem;
  void *               map = (uchar *)shmem + fd_snapmin_align();
  fd_snapmin_ele_t *   ele = (fd_snapmin_ele_t *)( (uchar *)map + map_footprint( ele_max ) );
  fd_memset( ele, 0, ele_max*sizeof(fd_snapmin_ele_t) );
  ulong lock_cnt  = fd_snapmin_map_lock_cnt_est ( ele_max );
  ulong probe_max = fd_snapmin_map_probe_max_est( ele_max );
  if( FD_UNLIKELY( !fd_snapmin_map_new( map, ele_max, lock_cnt, probe_max, seed ) ) ) return NULL;
  hdr->ele_max = ele_max;
  FD_COMPILER_MFENCE();
  hdr->magic = FD_SNAPMIN_MAGIC;
  return shmem;
}

fd_snapmin_t *
fd_snapmin_join( void * ljoin,
                 void * shmem ) {
  fd_snapmin_shmem_t * hdr = shmem;
  if( FD_UNLIKELY( hdr->magic!=FD_SNAPMIN_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  void *             map = (uchar *)shmem + fd_snapmin_align();
  fd_snapmin_ele_t * ele = (fd_snapmin_ele_t *)( (uchar *)map + map_footprint( hdr->ele_max ) );
  fd_snapmin_t * set = ljoin;
  set->shmem = hdr;
  if( FD_UNLIKELY( !fd_snapmin_map_join( set->map, map, ele ) ) ) return NULL;
  return set;
}

void
fd_snapmin_insert( fd_snapmin_t * set,
                   uchar const *  pubkey ) {
  fd_pubkey_t key;
  fd_memcpy( key.uc, pubkey, sizeof(fd_pubkey_t) );
  fd_snapmin_map_query_t query[1];
  if( FD_UNLIKELY( fd_snapmin_map_prepare( set->map, &key, NULL, query, FD_MAP_FLAG_BLOCKING ) ) ) {
    FD_LOG_ERR(( "keep set is full, raise --max-accounts" ));
  }
  fd_snapmin_ele_t * ele = fd_snapmin_map_query_ele( query );
  if( ele->used ) {
    fd_snapmin_map_cancel( query );
    return;
  }
  /* The reader takes no lock, so the key lands before the flag */
  ele->key = key;
  __atomic_store_n( &ele->used, 1UL, __ATOMIC_RELEASE );
  fd_snapmin_map_publish( query );
}

ulong
fd_snapmin_next( fd_snapmin_t * set,
                 ulong *        cursor,
                 fd_pubkey_t *  out,
                 ulong          out_max ) {
  fd_snapmin_ele_t const * ele     = fd_snapmin_map_shele_const( set->map );
  ulong                    ele_max = set->shmem->ele_max;
  ulong i   = *cursor;
  ulong cnt = 0UL;
  while( i<ele_max && cnt<out_max ) {
    if( __atomic_load_n( &ele[ i ].used, __ATOMIC_ACQUIRE ) ) out[ cnt++ ] = ele[ i ].key;
    i++;
  }
  *cursor = i;
  return cnt;
}

void
fd_snapmin_keep_boot_accounts( fd_snapmin_t * set,
                               fd_bank_t *    bank,
                               fd_banks_t *   banks,
                               ulong          end_slot ) {
  /* A missing feature account reads as disabled, so keep them all. */
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    fd_snapmin_insert( set, id->id.uc );
  }

  fd_pubkey_t const * keys[] = {
    &fd_sysvar_clock_id,
    &fd_sysvar_epoch_rewards_id,
    &fd_sysvar_epoch_schedule_id,
    &fd_sysvar_last_restart_slot_id,
    &fd_sysvar_recent_block_hashes_id,
    &fd_sysvar_rent_id,
    &fd_sysvar_slot_hashes_id,
    &fd_sysvar_slot_history_id,
    &fd_sysvar_stake_history_id,
    &fd_sysvar_fees_id,
    &fd_sysvar_instructions_id,
    &fd_sysvar_rewards_id,
    &fd_sysvar_owner_id,
    &fd_sysvar_incinerator_id,
    &fd_solana_native_loader_id,
    &fd_solana_stake_program_id,
    &fd_solana_stake_program_config_id,
    &fd_solana_config_program_id,
    &fd_solana_address_lookup_table_program_id,
    &fd_solana_spl_token_id,
  };
  for( ulong i=0UL; i<sizeof(keys)/sizeof(keys[0]); i++ ) fd_snapmin_insert( set, keys[ i ]->uc );

  fd_builtin_program_t const * builtins = fd_builtins();
  for( ulong i=0UL; i<fd_num_builtins(); i++ ) fd_snapmin_insert( set, builtins[ i ].pubkey->uc );
  fd_stateless_builtin_program_t const * stateless = fd_stateless_builtins();
  for( ulong i=0UL; i<fd_num_stateless_builtins(); i++ ) fd_snapmin_insert( set, stateless[ i ].pubkey->uc );
  for( fd_precompile_program_t const * p=fd_precompiles(); p->verify_fn; p++ ) fd_snapmin_insert( set, p->pubkey->uc );

  fd_pubkey_t pda[ 4 ];
  fd_alpenglow_pda( "carlgration", &pda[ 0 ] );
  fd_alpenglow_pda( "alpenclock",  &pda[ 1 ] );
  pda[ 2 ] = fd_epoch_inflation_account_address();
  pda[ 3 ] = fd_reward_epoch_stakes_account_address();
  for( ulong i=0UL; i<sizeof(pda)/sizeof(pda[0]); i++ ) fd_snapmin_insert( set, pda[ i ].uc );

  /* Every vote set the bank carries, from three epochs back to one
     ahead, fewer when the chain is younger than three epochs. */
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;
  int                kind_max    = (int)fd_ulong_min( bank->f.epoch, 3UL ) + 2;
  for( int kind=FD_VOTE_STAKES_ITER_T_1; kind<=kind_max; kind++ ) {
    uchar iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN)));
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, kind, iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, fork_id, kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, fork_id, kind, iter ) ) {
      fd_vote_stakes_ele_t ele[1];
      fd_vote_stakes_iter_ele( vote_stakes, fork_id, kind, iter, ele );
      fd_snapmin_insert( set, ele->pubkey.uc );
      fd_snapmin_insert( set, ele->node_account.uc );
      fd_snapmin_insert( set, ele->block_collector.uc );
      fd_snapmin_insert( set, ele->inflation_collector.uc );
    }
  }

  /* Replay credits stake accounts outside transactions at an epoch
     boundary and while rewards are paying out. */
  fd_sysvar_epoch_rewards_t rewards[1];
  int paying = fd_sysvar_cache_epoch_rewards_read( &bank->f.sysvar_cache, rewards ) && rewards->active;
  if( fd_slot_to_epoch( &bank->f.epoch_schedule, end_slot, NULL )==bank->f.epoch && !paying ) return;

  fd_stake_delegations_t * delegations = fd_banks_stake_delegations_root_query( banks );
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * delegation = fd_stake_delegations_iter_ele( iter );
    fd_snapmin_insert( set, delegation->stake_account.uc );
    fd_snapmin_insert( set, delegation->vote_account.uc );
  }

  fd_pubkey_t const * buffers[] = {
    &fd_solana_feature_program_buffer_address,
    &fd_solana_stake_program_vote_state_v4_buffer_address,
    &fd_solana_stake_program_v5_buffer_address,
    &fd_solana_stake_program_v5_1_buffer_address,
    &fd_solana_slashing_program_buffer_address,
    &fd_solana_ptoken_program_buffer_address,
  };
  for( ulong i=0UL; i<sizeof(buffers)/sizeof(buffers[0]); i++ ) fd_snapmin_insert( set, buffers[ i ]->uc );
}

#define VAL(name) (__extension__({                                                             \
  ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
  if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
  __x; }))

static ulong
snapmin_footprint( fd_topo_t const *     topo,
                   fd_topo_obj_t const * obj ) {
  return fd_snapmin_footprint( VAL("ele_max") );
}

static ulong
snapmin_align( fd_topo_t const *     topo FD_PARAM_UNUSED,
               fd_topo_obj_t const * obj  FD_PARAM_UNUSED ) {
  return fd_snapmin_align();
}

static void
snapmin_new( fd_topo_t const *     topo,
             fd_topo_obj_t const * obj ) {
  FD_TEST( fd_snapmin_new( fd_topo_obj_laddr( topo, obj->id ), VAL("ele_max"), 0UL ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_snapmin = {
  .name      = "snapmin",
  .footprint = snapmin_footprint,
  .align     = snapmin_align,
  .new       = snapmin_new,
};

#undef VAL
