#define _GNU_SOURCE
#include "fd_svm_mini.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../accdb/fd_accdb_funk.h"
#include "../../progcache/fd_progcache_admin.h"
#include "../../progcache/fd_progcache_user.h"
#include "../../runtime/fd_bank.h"
#include "../../runtime/program/fd_builtin_programs.h"
#include "../../runtime/fd_system_ids.h"
#include "../../runtime/fd_runtime_const.h"
#include "../../log_collector/fd_log_collector.h"
#include "../../runtime/fd_runtime.h"
#include "../../runtime/sysvar/fd_sysvar_cache.h"
#include "../../runtime/sysvar/fd_sysvar_rent.h"
#include "../../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../runtime/program/fd_vote_program.h"
#include "../../stakes/fd_stake_types.h"
#include "../../stakes/fd_vote_stakes.h"
#include "../../stakes/fd_stake_delegations.h"
#include "../../stakes/fd_top_votes.h"
#include "../../leaders/fd_leaders.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

static fd_wksp_t *
fd_wksp_new_lazy( ulong footprint ) {
  footprint = fd_ulong_align_up( footprint, FD_SHMEM_NORMAL_PAGE_SZ );
  void * mem = mmap( NULL, footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS) failed (%i-%s)",
                 footprint>>10, errno, fd_io_strerror( errno ) ));
  }

  ulong part_max = fd_wksp_part_max_est( footprint, 64UL<<10 );
  FD_TEST( part_max );
  ulong data_max = fd_wksp_data_max_est( footprint, part_max );
  FD_TEST( data_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, "wksp", 1U, part_max, data_max ) );
  FD_TEST( wksp );

  FD_TEST( 0==fd_shmem_join_anonymous( "wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, FD_SHMEM_NORMAL_PAGE_SZ, footprint>>FD_SHMEM_NORMAL_LG_PAGE_SZ ) );
  return wksp;
}

fd_svm_mini_t *
fd_svm_test_boot( int *    pargc,
                  char *** pargv,
                  fd_svm_mini_limits_t const * limits ) {

  fd_boot( pargc, pargv );

  char const * page_sz_cstr = fd_env_strip_cmdline_cstr ( pargc, pargv, "--page-sz",  NULL, NULL            );
  ulong        page_cnt     = fd_env_strip_cmdline_ulong( pargc, pargv, "--page-cnt", NULL, 0UL             );
  char const * wksp_name    = fd_env_strip_cmdline_cstr ( pargc, pargv, "--wksp",     NULL, NULL            );
  ulong        near_cpu     = fd_env_strip_cmdline_ulong( pargc, pargv, "--near-cpu", NULL, fd_log_cpu_id() );
  ulong        wksp_tag     = limits->wksp_tag ? limits->wksp_tag : 42UL;

  ulong data_max = fd_svm_mini_wksp_data_max( limits );
  ulong part_max = fd_wksp_part_max_est( data_max, 64UL<<10 );
  ulong wksp_sz  = fd_wksp_footprint( part_max, data_max );
  fd_wksp_t * wksp = NULL;
  if( wksp_name && !!wksp_name[0] ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
  } else if( page_sz_cstr ) {
    ulong page_sz = fd_cstr_to_shmem_page_sz( page_sz_cstr );
    if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "Invalid --page-sz %s", page_sz_cstr ));
    if( FD_UNLIKELY( page_sz*page_cnt < wksp_sz ) ) {
      FD_LOG_WARNING(( "--page-sz %s * --page-cnt %lu is smaller than required wksp_sz %lu KiB; falling back to lazy anonymous memory",
                       page_sz_cstr, page_cnt, wksp_sz>>10 ));
      goto fallback;
    }
    FD_LOG_NOTICE(( "--wksp not specified, using anonymous pinned shmem" ));
    wksp = fd_wksp_new_anonymous( page_sz, page_cnt, near_cpu, "wksp", wksp_tag );
  } else {
fallback:
    FD_LOG_NOTICE(( "--page-sz not specified, using lazy paged memory" ));
    wksp = fd_wksp_new_lazy( wksp_sz );
  }
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  return fd_svm_mini_create( wksp, limits );
}

void
fd_svm_test_halt( fd_svm_mini_t * mini ) {
  fd_svm_mini_destroy( mini );
  fd_halt();
}

ulong
fd_svm_mini_wksp_data_max( fd_svm_mini_limits_t const * limits ) {
  ulong txn_max = limits->max_live_slots;
  ulong rec_max = limits->max_accounts;

  ulong acc_pool_cnt     = fd_ulong_max( limits->max_txn_write_locks + 2UL, FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX );
  ulong funk_sz           = fd_funk_shmem_footprint( txn_max, rec_max );
  ulong funk_lock_sz      = fd_funk_locks_footprint( txn_max, rec_max );
  ulong pcache_sz         = fd_progcache_shmem_footprint( txn_max, limits->max_progcache_recs );
  ulong banks_sz          = fd_banks_footprint( txn_max, limits->max_fork_width, limits->max_stake_accounts, limits->max_vote_accounts );
  ulong acc_pool_sz       = fd_acc_pool_footprint( acc_pool_cnt );
  ulong runtime_stack_sz  = fd_runtime_stack_footprint( limits->max_vote_accounts, limits->max_vote_accounts, limits->max_stake_accounts );

# define WKSP_ALLOC(a,s) fd_ulong_align_up( fd_ulong_max((s),1UL), fd_ulong_max((a),FD_WKSP_ALIGN_DEFAULT) )
  ulong sz = 0UL;
  sz += WKSP_ALLOC( alignof(fd_svm_mini_t),     sizeof(fd_svm_mini_t)            );
  sz += WKSP_ALLOC( fd_funk_align(),            funk_sz                          );
  sz += WKSP_ALLOC( fd_funk_align(),            funk_lock_sz                     );
  sz += WKSP_ALLOC( fd_progcache_shmem_align(), pcache_sz                        );
  sz += WKSP_ALLOC( FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT   );
  sz += WKSP_ALLOC( fd_banks_align(),           banks_sz                         );
  sz += WKSP_ALLOC( fd_acc_pool_align(),        acc_pool_sz                      );
  sz += WKSP_ALLOC( alignof(fd_runtime_t),      sizeof(fd_runtime_t)             );
  sz += WKSP_ALLOC( fd_runtime_stack_align(),   runtime_stack_sz                 );
  sz += WKSP_ALLOC( fd_vm_align(),              fd_vm_footprint()                );
  sz += WKSP_ALLOC( 16UL,                       limits->max_account_space_bytes  );
  sz += WKSP_ALLOC( 1UL,                        limits->max_progcache_heap_bytes );
# undef WKSP_ALLOC

  return sz;
}

fd_svm_mini_t *
fd_svm_mini_create( fd_wksp_t *                  wksp,
                    fd_svm_mini_limits_t const * limits ) {

  ulong const wksp_tag = limits->wksp_tag ? limits->wksp_tag : 42UL;
  ulong const txn_max  = limits->max_live_slots;
  ulong const rec_max  = limits->max_accounts;

  ulong acc_pool_cnt     = fd_ulong_max( limits->max_txn_write_locks + 2UL, FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX );
  ulong funk_sz          = fd_funk_shmem_footprint( txn_max, rec_max );
  ulong funk_lock_sz     = fd_funk_locks_footprint( txn_max, rec_max );
  ulong pcache_sz        = fd_progcache_shmem_footprint( txn_max, limits->max_progcache_recs );
  ulong banks_sz         = fd_banks_footprint( txn_max, limits->max_fork_width,
                                               limits->max_stake_accounts, limits->max_vote_accounts );
  ulong acc_pool_sz      = fd_acc_pool_footprint( acc_pool_cnt );
  ulong runtime_stack_sz = fd_runtime_stack_footprint( limits->max_vote_accounts, limits->max_vote_accounts, limits->max_stake_accounts );

  /* Allocate objects */

  fd_svm_mini_t * mini;          FD_TEST( (mini         = fd_wksp_alloc_laddr( wksp, alignof(fd_svm_mini_t),     sizeof(fd_svm_mini_t),          wksp_tag )) );
  void *          funk_mem;      FD_TEST( (funk_mem     = fd_wksp_alloc_laddr( wksp, fd_funk_align(),            funk_sz,                        wksp_tag )) );
  void *          funk_locks;    FD_TEST( (funk_locks   = fd_wksp_alloc_laddr( wksp, fd_funk_align(),            funk_lock_sz,                   wksp_tag )) );
  void *          pcache_mem;    FD_TEST( (pcache_mem   = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), pcache_sz,                      wksp_tag )) );
  uchar *         scratch;       FD_TEST( (scratch      = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, wksp_tag )) );
  void *          banks_mem;     FD_TEST( (banks_mem    = fd_wksp_alloc_laddr( wksp, fd_banks_align(),           banks_sz,                       wksp_tag )) );
  void *          acc_pool_mem;  FD_TEST( (acc_pool_mem = fd_wksp_alloc_laddr( wksp, fd_acc_pool_align(),        acc_pool_sz,                    wksp_tag )) );
  fd_runtime_t *  runtime;       FD_TEST( (runtime      = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t),      sizeof(fd_runtime_t),           wksp_tag )) );
  void *          rstack_mem;    FD_TEST( (rstack_mem   = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(),   runtime_stack_sz,               wksp_tag )) );
  void *          vm_mem;        FD_TEST( (vm_mem       = fd_wksp_alloc_laddr( wksp, fd_vm_align(),              fd_vm_footprint(),              wksp_tag )) );

  /* Initialize objects */

  fd_memset( mini, 0, sizeof(fd_svm_mini_t) );
  mini->wksp = wksp;

  void * shfunk   = fd_funk_shmem_new     ( funk_mem,   wksp_tag, 1UL, txn_max, rec_max );
  void * shpcache = fd_progcache_shmem_new( pcache_mem, wksp_tag, 1UL, txn_max, limits->max_progcache_recs );
  if( FD_UNLIKELY( !shfunk   ) ) FD_LOG_ERR(( "fd_funk_shmem_new failed"      ));
  if( FD_UNLIKELY( !shpcache ) ) FD_LOG_ERR(( "fd_progcache_shmem_new failed" ));
  FD_TEST( fd_funk_locks_new( funk_locks, txn_max, rec_max ) );

  FD_TEST( fd_accdb_admin_v1_init( mini->accdb_admin, funk_mem, funk_locks ) );
  FD_TEST( fd_accdb_user_v1_init ( mini->accdb,       funk_mem, funk_locks, txn_max ) );

  FD_TEST( fd_progcache_join( mini->progcache, pcache_mem, scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );

  mini->banks = fd_banks_join( fd_banks_new( banks_mem, txn_max, limits->max_fork_width,
                               limits->max_stake_accounts, limits->max_vote_accounts, 0, 8888UL ) );
  FD_TEST( mini->banks );

  mini->acc_pool = fd_acc_pool_join( fd_acc_pool_new( acc_pool_mem, acc_pool_cnt ) );
  FD_TEST( mini->acc_pool );

  mini->runtime = runtime;

  runtime->accdb        = mini->accdb;
  runtime->status_cache = NULL;
  runtime->progcache    = mini->progcache;
  runtime->acc_pool     = mini->acc_pool;

  runtime->instr.stack_sz          = 0;
  runtime->instr.trace_length      = 0;
  runtime->instr.current_idx       = 0;
  runtime->accounts.executable_cnt = 0;
  fd_memset( &runtime->log,     0, sizeof(runtime->log)     );
  fd_memset( &runtime->metrics, 0, sizeof(runtime->metrics) );
  fd_memset( &runtime->fuzz,    0, sizeof(runtime->fuzz)    );

  mini->runtime_stack = fd_runtime_stack_join( fd_runtime_stack_new( rstack_mem,
      limits->max_vote_accounts, limits->max_vote_accounts, limits->max_stake_accounts, 42UL ) );
  FD_TEST( mini->runtime_stack );

  fd_log_collector_init( mini->log_collector, 1 );
  runtime->log.enable_log_collector = 0;
  runtime->log.log_collector        = mini->log_collector;

  fd_features_disable_all( mini->features );
  fd_features_enable_cleaned_up( mini->features );

  FD_TEST( fd_sha256_join( fd_sha256_new( mini->sha256 ) ) );

  mini->vm = fd_vm_join( fd_vm_new( vm_mem ) );
  FD_TEST( mini->vm );

  return mini;
}

void
fd_svm_mini_destroy( fd_svm_mini_t * mini ) {
  if( FD_UNLIKELY( !mini ) ) return;

  if( mini->vm ) fd_wksp_free_laddr( fd_vm_delete( fd_vm_leave( mini->vm ) ) );
  if( mini->runtime_stack ) fd_wksp_free_laddr( mini->runtime_stack );
  if( mini->runtime ) fd_wksp_free_laddr( mini->runtime );
  if( mini->acc_pool ) fd_wksp_free_laddr( mini->acc_pool );
  if( mini->banks ) fd_wksp_free_laddr( mini->banks );

  uchar * scratch = mini->progcache->scratch;
  fd_progcache_shmem_t * shpcache = NULL;
  fd_progcache_leave( mini->progcache, &shpcache );
  if( scratch  ) fd_wksp_free_laddr( scratch );
  if( shpcache ) fd_wksp_free_laddr( fd_progcache_shmem_delete( shpcache ) );

  void * shfunk      = fd_accdb_user_v1_funk( mini->accdb )->shmem;
  void * shfunk_lock = (void *)fd_accdb_user_v1_funk( mini->accdb )->txn_lock;
  fd_accdb_user_fini ( mini->accdb );
  fd_accdb_admin_fini( mini->accdb_admin );
  fd_wksp_free_laddr( shfunk_lock );
  fd_wksp_free_laddr( fd_funk_delete( shfunk ) );

  fd_wksp_free_laddr( mini );
}

static void
fd_svm_mini_init_mock_validators( fd_svm_mini_t *              mini,
                                  fd_bank_t *                  bank,
                                  fd_svm_mini_params_t const * params ) {

  ulong const N             = params->mock_validator_cnt;
  ulong const uniform_stake = 1000000000UL; /* 1 SOL */
  ulong const vote_min_bal  = fd_rent_exempt_minimum_balance( &bank->f.rent, FD_VOTE_STATE_V3_SZ );
  ulong const stake_min_bal = fd_rent_exempt_minimum_balance( &bank->f.rent, FD_STAKE_STATE_SZ );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  fd_vote_stakes_reset( vote_stakes );

  fd_top_votes_t * top_votes_t_1 = fd_bank_top_votes_t_1_modify( bank );
  fd_top_votes_init( top_votes_t_1 );
  fd_top_votes_t * top_votes_t_2 = fd_bank_top_votes_t_2_modify( bank );
  fd_top_votes_init( top_votes_t_2 );

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( mini->banks );

  fd_vote_stake_weight_t * stakes = calloc( N, sizeof(fd_vote_stake_weight_t) );
  FD_TEST( stakes );

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)params->hash_seed, 0UL ) );

  for( ulong i=0UL; i<N; i++ ) {

    /* Generate deterministic pubkeys */

    fd_pubkey_t identity_key, vote_key, stake_key;
    for( ulong j=0UL; j<4UL; j++ ) identity_key.ul[j] = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_key.ul[j]     = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_key.ul[j]     = fd_rng_ulong( rng );

    /* Identity account */

    fd_svm_mini_add_lamports_rooted( mini, &identity_key, 500000000000UL /* 500 SOL */ );

    /* Vote account */

    {
      uchar vote_state_data[ FD_VOTE_STATE_V3_SZ ] = {0};

      fd_vote_state_versioned_t versioned[1];
      fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v3 );

      fd_vote_state_v3_t * vs   = &versioned->v3;
      vs->node_pubkey           = identity_key;
      vs->authorized_withdrawer = identity_key;
      vs->commission            = 100;

      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( vs->authorized_voters.pool );
      *ele = (fd_vote_authorized_voter_t){
        .epoch  = 0UL,
        .pubkey = identity_key,
        .prio   = identity_key.uc[0],
      };
      fd_vote_authorized_voters_treap_ele_insert( vs->authorized_voters.treap, ele, vs->authorized_voters.pool );
      FD_TEST( !fd_vote_state_versioned_serialize( versioned, vote_state_data, sizeof(vote_state_data) ) );

      fd_account_meta_t meta = { .lamports = vote_min_bal, .dlen = FD_VOTE_STATE_V3_SZ };
      memcpy( meta.owner, fd_solana_vote_program_id.uc, 32UL );
      fd_accdb_ro_t ro[1];
      fd_accdb_ro_init_nodb_oob( ro, &vote_key, &meta, vote_state_data );
      fd_svm_mini_put_account_rooted( mini, ro );
    }

    /* Stake account */

    {
      uchar stake_data[ FD_STAKE_STATE_SZ ] = {0};
      FD_STORE( fd_stake_state_t, stake_data, ((fd_stake_state_t) {
        .stake_type = FD_STAKE_STATE_STAKE,
        .stake = {
          .meta = {
            .rent_exempt_reserve = stake_min_bal,
            .staker              = identity_key,
            .withdrawer          = identity_key,
          },
          .stake = (fd_stake_t) {
            .delegation = (fd_delegation_t) {
              .voter_pubkey         = vote_key,
              .stake                = uniform_stake,
              .activation_epoch     = ULONG_MAX,
              .deactivation_epoch   = ULONG_MAX,
              .warmup_cooldown_rate = 0.25,
            },
            .credits_observed = 0UL,
          },
        },
      }) );

      fd_account_meta_t meta = {
        .lamports = fd_ulong_max( stake_min_bal, uniform_stake ),
        .dlen     = FD_STAKE_STATE_SZ,
      };
      memcpy( meta.owner, fd_solana_stake_program_id.uc, 32UL );
      fd_accdb_ro_t ro[1];
      fd_accdb_ro_init_nodb_oob( ro, &stake_key, &meta, stake_data );
      fd_svm_mini_put_account_rooted( mini, ro );
    }

    /* Populate bank structures */

    fd_vote_stakes_root_insert_key ( vote_stakes, &vote_key, &identity_key, uniform_stake, 0, 0UL );
    fd_vote_stakes_root_update_meta( vote_stakes, &vote_key, &identity_key, uniform_stake, 0, 0UL );

    fd_top_votes_insert( top_votes_t_1, &vote_key, &identity_key, uniform_stake, 0 );
    fd_top_votes_insert( top_votes_t_2, &vote_key, &identity_key, uniform_stake, 0 );

    fd_stake_delegations_root_update( stake_delegations,
                                      &stake_key, &vote_key,
                                      uniform_stake,
                                      ULONG_MAX,  /* activation_epoch (bootstrap) */
                                      ULONG_MAX,  /* deactivation_epoch */
                                      0UL,        /* credits_observed */
                                      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 /* warmup_cooldown_rate */ );

    stakes[i] = (fd_vote_stake_weight_t){
      .vote_key = vote_key,
      .id_key   = identity_key,
      .stake    = uniform_stake,
    };
  }

  fd_vote_stakes_genesis_fini( vote_stakes );

  /* Create leader schedule */

  ulong epoch    = bank->f.epoch;
  ulong slot0    = fd_epoch_slot0( &bank->f.epoch_schedule, epoch );
  ulong slot_cnt = bank->f.epoch_schedule.slots_per_epoch;

  void * leaders_mem = fd_bank_epoch_leaders_modify( bank );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, N, stakes, 0UL ) ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  free( stakes );
}

ulong
fd_svm_mini_reset( fd_svm_mini_t *        mini,
                   fd_svm_mini_params_t * params ) {

  fd_accdb_v1_clear ( mini->accdb_admin     );
  fd_progcache_clear( mini->progcache->join );
  fd_banks_clear    ( mini->banks           );

  fd_bank_t * bank = fd_banks_init_bank( mini->banks );
  FD_TEST( bank );
  ulong bank_idx = bank->idx;

  bank->f.slot = params->root_slot;

  fd_xid_t root_xid = { .ul = { params->root_slot, bank_idx } };
  fd_funk_t * funk = fd_accdb_user_v1_funk( mini->accdb );
  fd_funk_txn_xid_copy( funk->shmem->last_publish, &root_xid );
  fd_funk_txn_xid_copy( mini->progcache->join->shmem->txn.last_publish, &root_xid );

  if( params->clock ) {
    bank->f.slot  = params->clock->slot;
    bank->f.epoch = params->clock->epoch;
  }

  if( params->epoch_schedule ) {
    bank->f.epoch_schedule = *params->epoch_schedule;
  } else {
    bank->f.epoch_schedule = (fd_epoch_schedule_t) {
      .slots_per_epoch             = params->slots_per_epoch,
      .leader_schedule_slot_offset = params->slots_per_epoch,
      .warmup                      = 0,
      .first_normal_epoch          = 0UL,
      .first_normal_slot           = 0UL,
    };
  }

  /* Default slots_per_year matches Solana mainnet genesis defaults
     (target_tick_duration=6250000ns, ticks_per_slot=64). */
  bank->f.slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / 6250000.0) / 64.0;

  if( params->rent ) {
    bank->f.rent = *params->rent;
  } else {
    bank->f.rent = (fd_rent_t) {
      .lamports_per_uint8_year = 3480UL,
      .exemption_threshold     = 2.0,
      .burn_percent            = 50,
    };
  }

  fd_features_disable_all( &bank->f.features );
  fd_features_enable_cleaned_up( &bank->f.features );

  if( params->init_builtins ) {
    fd_builtin_program_t const * builtins = fd_builtins();
    for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
      char const * data = builtins[i].data;
      ulong        sz   = strlen( data );
      fd_account_meta_t meta = { .lamports = 1UL, .dlen = (uint)sz, .executable = 1 };
      memcpy( meta.owner, fd_solana_native_loader_id.uc, 32UL );
      fd_accdb_ro_t ro[1];
      fd_accdb_ro_init_nodb_oob( ro, builtins[i].pubkey, &meta, data );
      fd_svm_mini_put_account_rooted( mini, ro );
    }

    fd_pubkey_t const * precompiles[] = {
      &fd_solana_keccak_secp_256k_program_id,
      &fd_solana_ed25519_sig_verify_program_id,
      &fd_solana_secp256r1_program_id,
    };
    for( ulong i=0UL; i<3UL; i++ ) {
      fd_account_meta_t meta = { .lamports = 1UL, .dlen = 0, .executable = 1 };
      memcpy( meta.owner, fd_solana_native_loader_id.uc, 32UL );
      fd_accdb_ro_t ro[1];
      fd_accdb_ro_init_nodb_oob( ro, precompiles[i], &meta, NULL );
      fd_svm_mini_put_account_rooted( mini, ro );
    }
  }

  if( params->init_feature_accounts ) {
    for( fd_feature_id_t const * id = fd_feature_iter_init();
         !fd_feature_iter_done( id );
         id = fd_feature_iter_next( id ) ) {
      ulong activation_slot = fd_features_get( &bank->f.features, id );
      if( activation_slot==FD_FEATURE_DISABLED ) continue;

      fd_feature_t feature = { .is_active = 1, .activation_slot = activation_slot };
      fd_account_meta_t meta = { .lamports = 1UL, .dlen = sizeof(fd_feature_t) };
      memcpy( meta.owner, fd_solana_feature_program_id.uc, 32UL );
      fd_accdb_ro_t ro[1];
      fd_accdb_ro_init_nodb_oob( ro, &id->id, &meta, &feature );
      fd_svm_mini_put_account_rooted( mini, ro );
    }
  }

  if( params->init_sysvars ) {

    /* Blockhash queue -- must be initialized before recent_hashes sysvar */
    fd_blockhashes_t * bhq = fd_blockhashes_init( &bank->f.block_hash_queue, params->hash_seed );
    fd_hash_t genesis_hash = {0};
    fd_memset( genesis_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
    fd_blockhash_info_t * bh_info = fd_blockhashes_push_new( bhq, &genesis_hash );
    bh_info->lamports_per_signature = 0UL;
    bank->f.poh = genesis_hash;

    /* Clock */
    fd_sol_sysvar_clock_t clock = {
      .slot                  = bank->f.slot,
      .leader_schedule_epoch = 1,
    };
    if( params->clock ) clock = *params->clock;

    /* Last restart slot */
    uchar last_restart_enc[ FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ ] = {0};

    /* Recent hashes (encodes from blockhash queue -- initially 1 entry) */
    uchar recent_hashes_enc[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] = {0};
    ulong rbh_cnt = 1UL;
    memcpy( recent_hashes_enc, &rbh_cnt, sizeof(ulong) );
    memcpy( recent_hashes_enc + sizeof(ulong), genesis_hash.uc, 32 );
    /* lamports_per_signature = 0 already zeroed */

    /* Slot hashes (empty) */
    uchar slot_hashes_enc[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ] = {0};

    /* Slot history (empty -- large, heap alloc) */
    uchar * slot_history_enc = calloc( 1, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
    FD_TEST( slot_history_enc );

    /* Stake history (empty) */
    uchar stake_history_enc[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ] = {0};

    struct { fd_pubkey_t const * addr; void const * data; ulong sz; } sysvars[] = {
      { &fd_sysvar_clock_id,               &clock,                  sizeof(clock)                     },
      { &fd_sysvar_epoch_schedule_id,      &bank->f.epoch_schedule, sizeof(bank->f.epoch_schedule)    },
      { &fd_sysvar_rent_id,                &bank->f.rent,           sizeof(bank->f.rent)              },
      { &fd_sysvar_last_restart_slot_id,   last_restart_enc,        sizeof(last_restart_enc)          },
      { &fd_sysvar_recent_block_hashes_id, recent_hashes_enc,       sizeof(recent_hashes_enc)         },
      { &fd_sysvar_slot_hashes_id,         slot_hashes_enc,         sizeof(slot_hashes_enc)           },
      { &fd_sysvar_slot_history_id,        slot_history_enc,        FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ },
      { &fd_sysvar_stake_history_id,       stake_history_enc,       sizeof(stake_history_enc)         },
    };
    for( ulong i=0UL; i<8UL; i++ ) {
      fd_account_meta_t meta = {
        .lamports = fd_rent_exempt_minimum_balance( &bank->f.rent, sysvars[i].sz ),
        .dlen     = (uint)sysvars[i].sz,
      };
      memcpy( meta.owner, fd_sysvar_owner_id.uc, 32UL );
      fd_accdb_ro_t ro[1];
      fd_accdb_ro_init_nodb_oob( ro, sysvars[i].addr, &meta, sysvars[i].data );
      fd_svm_mini_put_account_rooted( mini, ro );
    }

    free( slot_history_enc );

    fd_sysvar_cache_restore( bank, mini->accdb, &root_xid );
  }

  if( params->mock_validator_cnt ) {
    fd_svm_mini_init_mock_validators( mini, bank, params );
  }

  return bank_idx;
}

ulong
fd_svm_mini_attach_child( fd_svm_mini_t * mini,
                          ulong           parent_bank_idx,
                          ulong           child_slot ) {

  fd_bank_t * parent_bank = fd_banks_bank_query( mini->banks, parent_bank_idx );
  if( FD_UNLIKELY( !parent_bank ) ) FD_LOG_ERR(( "invalid parent_bank_idx" ));
  ulong parent_slot = parent_bank->f.slot;
  if( FD_UNLIKELY( child_slot<=parent_slot ) ) FD_LOG_ERR(( "child_slot (%lu) <= parent_slot (%lu)", child_slot, parent_slot ));
  fd_xid_t parent_xid = { .ul = { parent_slot, parent_bank_idx } };

  fd_bank_t * bank = fd_banks_new_bank( mini->banks, parent_bank_idx, 0L );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_ERR(( "fd_banks_new_bank failed" ));
  bank = fd_banks_clone_from_parent( mini->banks, bank->idx );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_ERR(( "fd_banks_clone_from_parent failed" ));
  ulong bank_idx = bank->idx;
  bank->f.slot = child_slot;
  fd_xid_t xid = { .ul = { child_slot, bank_idx } };

  fd_accdb_attach_child    ( mini->accdb_admin,     &parent_xid, &xid );
  fd_progcache_attach_child( mini->progcache->join, &parent_xid, &xid );

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( mini->banks, bank, mini->accdb, mini->runtime_stack, NULL, &is_epoch_boundary );

  return bank_idx;
}

void
fd_svm_mini_freeze( fd_svm_mini_t * mini,
                    ulong           bank_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_ERR(( "invalid bank_idx" ));
  /* Derive a mock POH hash so each frozen slot registers a unique
     blockhash.  (Real POH is computed by the PoH tile.) */
  fd_sha256_hash( bank->f.poh.hash, 32UL, bank->f.poh.hash );
  fd_runtime_block_execute_finalize( bank, mini->accdb, NULL );
}

void
fd_svm_mini_cancel_fork( fd_svm_mini_t * mini,
                         ulong           bank_idx ) {

  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_ERR(( "invalid bank_idx" ));
  fd_xid_t xid = { .ul = { bank->f.slot, bank->idx } };

  fd_accdb_cancel    ( mini->accdb_admin,     &xid );
  fd_progcache_cancel( mini->progcache->join, &xid );
}

void
fd_svm_mini_advance_root( fd_svm_mini_t * mini,
                          ulong           bank_idx ) {

  fd_bank_t * bank = fd_banks_bank_query( mini->banks, bank_idx );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_ERR(( "invalid bank_idx" ));
  ulong slot = bank->f.slot;
  fd_xid_t xid = { .ul = { slot, bank_idx } };

  fd_accdb_advance_root    ( mini->accdb_admin,     &xid );
  fd_progcache_advance_root( mini->progcache->join, &xid );
  fd_banks_advance_root    ( mini->banks, bank_idx );
}

fd_bank_t *
fd_svm_mini_bank( fd_svm_mini_t * mini,
                  ulong           bank_idx ) {
  if( FD_UNLIKELY( bank_idx>=fd_banks_pool_max_cnt( mini->banks ) ) ) return NULL;
  fd_bank_t * bank = fd_banks_bank_query( mini->banks, bank_idx );
  if( FD_UNLIKELY( !bank ) ) return NULL;
  return bank;
}

fd_xid_t
fd_svm_mini_xid( fd_svm_mini_t * mini,
                 ulong           bank_idx ) {
  fd_bank_t * bank = fd_banks_bank_query( mini->banks, bank_idx );
  if( FD_UNLIKELY( !bank ) ) FD_LOG_ERR(( "invalid bank_idx" ));
  return (fd_xid_t){ .ul = { bank->f.slot, bank->idx } };
}

void
fd_svm_mini_put_account_rooted( fd_svm_mini_t *       mini,
                                fd_accdb_ro_t const * ro ) {
  fd_funk_t * funk = fd_accdb_user_v1_funk( mini->accdb );
  fd_funk_xid_key_pair_t pair = { .xid = {{ .ul = { ULONG_MAX, ULONG_MAX } }} };
  memcpy( pair.key, ro->ref->address, sizeof(fd_funk_rec_key_t) );
  fd_funk_rec_map_query_t query[1];
  int remove_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, 0 );
  FD_TEST( remove_err==FD_MAP_SUCCESS || remove_err==FD_MAP_ERR_KEY );
  ulong old_lamports = 0UL;
  if( remove_err==FD_MAP_SUCCESS ) {
    fd_funk_rec_t * old_rec = query->ele;
    fd_account_meta_t const * old_meta = fd_funk_val_const( old_rec, funk->wksp );
    if( old_meta ) old_lamports = old_meta->lamports;
    memset( &old_rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
    old_rec->map_next = FD_FUNK_REC_IDX_NULL;
    fd_funk_val_flush( old_rec, funk->alloc, funk->wksp );
    fd_funk_rec_pool_release( funk->rec_pool, old_rec );
  }

  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_funk_create( funk, rw, NULL, ro->ref->address, fd_accdb_ref_data_sz( ro ) ) );
  fd_accdb_ref_lamports_set( rw, fd_accdb_ref_lamports( ro ) );
  fd_accdb_ref_owner_set   ( rw, fd_accdb_ref_owner   ( ro ) );
  fd_accdb_ref_exec_bit_set( rw, fd_accdb_ref_exec_bit( ro ) );
  fd_accdb_ref_slot_set    ( rw, fd_accdb_ref_slot    ( ro ) );
  fd_accdb_ref_data_set( mini->accdb, rw, fd_accdb_ref_data_const( ro ), fd_accdb_ref_data_sz( ro ) );
  fd_funk_rec_t * rec = (fd_funk_rec_t *)rw->ref->user_data;
  fd_funk_rec_prepare_t prepare = { .rec = rec, .rec_head_idx = NULL, .rec_tail_idx = NULL };
  fd_funk_rec_publish( funk, &prepare );
  memset( rw, 0, sizeof(fd_accdb_rw_t) );

  fd_bank_t * root = fd_banks_root( mini->banks );
  if( root ) {
    ulong new_lamports = fd_accdb_ref_lamports( ro );
    if( new_lamports >= old_lamports )
      root->f.capitalization += new_lamports - old_lamports;
    else
      root->f.capitalization -= old_lamports - new_lamports;
  }
}

void
fd_svm_mini_add_lamports_rooted( fd_svm_mini_t *     mini,
                                 fd_pubkey_t const * pubkey,
                                 ulong               lamports ) {
  fd_funk_t * funk = fd_accdb_user_v1_funk( mini->accdb );
  fd_funk_xid_key_pair_t pair = { .xid = {{ .ul = { ULONG_MAX, ULONG_MAX } }} };
  memcpy( pair.key, pubkey, sizeof(fd_funk_rec_key_t) );
  fd_funk_rec_map_query_t query[1];
  int query_err = fd_funk_rec_map_query_try( funk->rec_map, &pair, NULL, query, 0 );
  FD_TEST( query_err==FD_MAP_SUCCESS || query_err==FD_MAP_ERR_KEY );
  if( query_err==FD_MAP_SUCCESS ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_query_ele( query );
    fd_account_meta_t * meta = fd_funk_val( rec, funk->wksp );
    ulong balance = meta->lamports;
    FD_TEST( !__builtin_uaddl_overflow( balance, lamports, &balance ) );
    meta->lamports = balance;
    FD_TEST( !fd_funk_rec_map_query_test( query ) );
  } else if( query_err==FD_MAP_ERR_KEY ) {
    fd_accdb_rw_t rw[1];
    FD_TEST( fd_accdb_funk_create( funk, rw, NULL, pubkey, 0UL ) );
    fd_accdb_ref_lamports_set( rw, lamports );
    fd_funk_rec_t * rec = (fd_funk_rec_t *)rw->ref->user_data;
    fd_funk_rec_prepare_t prepare = { .rec = rec, .rec_head_idx = NULL, .rec_tail_idx = NULL };
    fd_funk_rec_publish( funk, &prepare );
    memset( rw, 0, sizeof(fd_accdb_rw_t) );
  } else {
    FD_LOG_ERR(( "fd_funk_rec_map_query_try failed (%i-%s)", query_err, fd_map_strerror( query_err ) ));
  }

  fd_bank_t * root = fd_banks_root( mini->banks );
  if( root ) root->f.capitalization += lamports;
}

void
fd_svm_mini_add_lamports( fd_svm_mini_t *     mini,
                          fd_xid_t const *    xid,
                          fd_pubkey_t const * pubkey,
                          ulong               lamports ) {
  fd_accdb_user_t * accdb = mini->accdb;

  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( accdb, rw, xid, pubkey, 0UL, FD_ACCDB_FLAG_CREATE ) );
  ulong balance = fd_accdb_ref_lamports( rw->ro );
  FD_TEST( !__builtin_uaddl_overflow( balance, lamports, &balance ) );
  fd_accdb_ref_lamports_set( rw, balance );
  fd_accdb_close_rw( accdb, rw );

  fd_bank_t * bank = fd_svm_mini_bank( mini, xid->ul[1] );
  if( bank ) bank->f.capitalization += lamports;
}
