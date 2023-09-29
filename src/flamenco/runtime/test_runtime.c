/****

build/native/gcc/bin/fd_frank_ledger --rocksdb $LEDGER/rocksdb --genesis $LEDGER/genesis.bin --cmd ingest --indexmax 10000 --txnmax 100 --backup test_ledger_backup

build/native/gcc/unit-test/test_runtime --load test_ledger_backup --cmd replay --end-slot 25 --confirm_hash AsHedZaZkabNtB8XBiKWQkKwaeLy2y4Hrqm6MkQALT5h --confirm_parent CvgPeR54qpVRZGBuiQztGXecxSXREPfTF8wALujK4WdE --confirm_account_delta 7PL6JZgcNy5vkPSc6JsMHET9dvpvsFMWR734VtCG29xN  --confirm_signature 2  --confirm_last_block G4YL2SieHDGNZGjiwBsJESK7jMDfazg33ievuCwbkjrv --validate true

build/native/gcc/bin/fd_shmem_cfg reset

build/native/gcc/bin/fd_wksp_ctl new giant_wksp 200 gigantic 32-127 0666

build/native/gcc/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /home/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /home/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --rocksdb /home/jsiegel/mainnet-ledger/rocksdb --endslot 179249378 --backup /home/asiegel/mainnet_backup

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --reset true --load /home/asiegel/mainnet_backup --cmd replay --index-max 350000000

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0xc7ce180 --cmd replay
  NOTE: gaddr argument may be different

build/native/gcc/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /data/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /data/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --rocksdb /data/jsiegel/mainnet-ledger/rocksdb --endslot 179248378 --backup /data/jsiegel/mainnet_backup

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0x000000000c7ce180 --cmd replay

/data/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst
/data/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0xc7ce180 --cmd verifyonly

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0xc7ce180 --cmd verifyonly --tile-cpus 32-100

****/

#include "../fd_flamenco.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>
#include <fcntl.h>
#include "fd_rocksdb.h"
#include "fd_banks_solana.h"
#include "fd_hashes.h"
#include "fd_account.h"
#include "fd_executor.h"
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "../../util/alloc/fd_alloc.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/poh/fd_poh.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar.h"
#include "fd_runtime.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stake_program.h"

#include <dirent.h>

struct slot_capitalization {
  ulong key;
  uint  hash;
  ulong capitalization;
};
typedef struct slot_capitalization slot_capitalization_t;

#define MAP_NAME        capitalization_map
#define MAP_T           slot_capitalization_t
#define LG_SLOT_CNT 15
#define MAP_LG_SLOT_CNT LG_SLOT_CNT
#include "../../util/tmpl/fd_map.c"

struct global_state {
  fd_global_ctx_t*       global;

  int                    argc;
  char       **          argv;

  char const *           name;
  ulong                  pages;
  char const *           gaddr;
  char const *           persist;
  ulong                  end_slot;
  char const *           cmd;
  char const *           reset;
  char const *           load;
  char const *           capitalization_file;
  slot_capitalization_t  capitalization_map_mem[ 1UL << LG_SLOT_CNT ];
  slot_capitalization_t *map;

  FILE * capture_file;
};
typedef struct global_state global_state_t;

static void
usage( char const * progname ) {
  fprintf( stderr, "USAGE: %s\n", progname );
  fprintf( stderr,
      " --wksp        <name>       workspace name\n"
      " --gaddr       <num>        global address of funky in the workspace\n"
      " --persist     <file>       funky persistence file\n"
      " --load        <file>       load funky backup file\n"
      " --end-slot    <num>        stop iterating at block...\n"
      " --cmd         <operation>  What operation should we test\n"
      " --index-max   <bool>       How big should the index table be?\n"
      " --validate    <bool>       Validate the funk db\n"
      " --reset       <bool>       Reset the workspace\n"
      " --capture     <file>       Write bank preimage to capture file\n"
      " --abort-on-mismatch {0,1}  If 1, stop on bank hash mismatch\n",
      " --loglevel    <level>      Set logging level\n",
      " --cap         <file>       Slot capitalization file\n",
      " --trace       <dir>        Export traces to given directory\n",
      " --retrace     <bool>       Immediately replay captured traces\n" );
}

#define SORT_NAME sort_pubkey_hash_pair
#define SORT_KEY_T fd_pubkey_hash_pair_t
#define SORT_BEFORE(a,b) ((memcmp(&a, &b, 32) < 0))
#include "../../util/tmpl/fd_sort.c"

int
accounts_hash( global_state_t *state ) {
  fd_funk_t * funk = state->global->funk;
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
  ulong num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );

  FD_LOG_NOTICE(( "NIA %lu", num_iter_accounts ));

  ulong zero_accounts = 0;
  ulong num_pairs = 0;
  fd_pubkey_hash_pair_t * pairs = fd_valloc_malloc( state->global->valloc, 8UL, num_iter_accounts*sizeof(fd_pubkey_hash_pair_t));
  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
    if ( !fd_acc_mgr_is_key( rec->pair.key ) )
      continue;

    if (num_pairs % 1000000 == 0) {
      FD_LOG_NOTICE(( "PAIRS: %lu", num_pairs ));
    }

    fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
    if ((metadata->magic != FD_ACCOUNT_META_MAGIC) || (metadata->hlen != sizeof(fd_account_meta_t))) {
      FD_LOG_ERR(("invalid magic on metadata"));
    }

    if ((metadata->info.lamports == 0) | ((metadata->info.executable & ~1) != 0)) {
      zero_accounts++;
      continue;
    }


    fd_memcpy(pairs[num_pairs].pubkey.key, rec->pair.key, 32);
    fd_memcpy(pairs[num_pairs].hash.hash, metadata->hash, 32);
    num_pairs++;
  }

  FD_LOG_WARNING(("num_iter_accounts %ld zero_accounts %lu", num_iter_accounts, zero_accounts));
  FD_LOG_NOTICE(( "HASHING ACCOUNTS" ));
  fd_hash_t accounts_hash;
  fd_hash_account_deltas(state->global, pairs, num_pairs, &accounts_hash);

  FD_LOG_WARNING(("accounts_hash %32J", accounts_hash.hash));
  FD_LOG_WARNING(("num_iter_accounts %ld", num_iter_accounts));

  return 0;
}

int
replay( global_state_t * state,
        int              justverify,
        fd_tpool_t *     tpool,
        ulong            max_workers ) {
  /* Create scratch allocator */

  ulong  smax = 512 /*MiB*/ << 20;
  void * smem = fd_wksp_alloc_laddr( state->global->local_wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));
  ulong  scratch_depth = 4UL;
  void * fmem = fd_wksp_alloc_laddr( state->global->local_wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( scratch_depth ), 2UL );
  if( FD_UNLIKELY( !fmem ) ) FD_LOG_ERR(( "Failed to alloc scratch frames" ));

  fd_scratch_attach( smem, fmem, smax, scratch_depth );

  fd_features_restore( state->global );

  fd_funk_rec_key_t key = fd_runtime_block_meta_key(ULONG_MAX);
  fd_funk_rec_t const * rec = fd_funk_rec_query( state->global->funk, NULL, &key );
  if (rec == NULL)
    FD_LOG_ERR(("missing meta record"));
  fd_slot_meta_meta_t mm;
  int err;
  const void * val = fd_funk_val_cache( state->global->funk, rec, &err );
  if (val == NULL)
    FD_LOG_ERR(("corrupt meta record"));
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data    = val;
  ctx2.dataend = (uchar*)val + fd_funk_val_sz(rec);
  ctx2.valloc  = state->global->valloc;
  if ( fd_slot_meta_meta_decode( &mm, &ctx2 ) )
    FD_LOG_ERR(("fd_slot_meta_meta_decode failed"));

  if (mm.end_slot < state->end_slot)
    state->end_slot = mm.end_slot;

  /* Load epoch schedule sysvar */
  fd_epoch_schedule_t schedule;
  fd_sysvar_epoch_schedule_read( state->global, &schedule );
  FD_LOG_INFO(( "schedule->slots_per_epoch = %lu", schedule.slots_per_epoch ));
  FD_LOG_INFO(( "schedule->leader_schedule_slot_offset = %lu", schedule.leader_schedule_slot_offset ));
  FD_LOG_INFO(( "schedule->warmup = %d", schedule.warmup ));
  FD_LOG_INFO(( "schedule->first_normal_epoch = %lu", schedule.first_normal_epoch ));
  FD_LOG_INFO(( "schedule->first_normal_slot = %lu", schedule.first_normal_slot ));

  /* Slot of next epoch boundary */
  ulong epoch           = fd_slot_to_epoch( &schedule, state->global->bank.slot+1, NULL );
  ulong last_epoch_slot = fd_epoch_slot0  ( &schedule, epoch+1UL );

  /* Find epoch stakes for current epoch */
  fd_vote_accounts_t const * epoch_vaccs = &state->global->bank.epoch_stakes;

  FD_LOG_INFO(( "starting rent list init" ));
  state->global->rentlists = fd_rent_lists_new(fd_epoch_slot_cnt( &schedule, epoch ));
  fd_funk_set_notify(state->global->funk, fd_rent_lists_cb, state->global->rentlists);
  fd_rent_lists_startup_done_tpool(state->global->rentlists, tpool, max_workers);
  FD_LOG_INFO(( "rent list init done" ));
  ulong stake_weight_cnt;
  {
    FD_SCRATCH_SCOPED_FRAME;

    /* Derive node stake weights for epoch vote accounts */

    ulong vote_acc_cnt = fd_vote_accounts_pair_t_map_size( epoch_vaccs->vote_accounts_pool, epoch_vaccs->vote_accounts_root );
    fd_stake_weight_t * epoch_weights = fd_scratch_alloc( alignof(fd_stake_weight_t), vote_acc_cnt * sizeof(fd_stake_weight_t) );
    if( FD_UNLIKELY( !epoch_weights ) ) FD_LOG_ERR(( "fd_scratch_alloc() failed" ));

    stake_weight_cnt = fd_stake_weights_by_node( epoch_vaccs, epoch_weights );
    if( FD_UNLIKELY( stake_weight_cnt==ULONG_MAX ) ) FD_LOG_ERR(( "fd_stake_weights_by_node() failed" ));

    /* Derive leader schedule */
    /* TODO This wksp alloc probably shouldn't be here */
    ulong sched_cnt = fd_epoch_slot_cnt( &schedule, epoch ) / 4UL;  /* Every leader rotation lasts four slots - TODO remove hardcode */
    FD_LOG_INFO(( "stake_weight_cnt=%lu sched_cnt=%lu", stake_weight_cnt, sched_cnt ));
    ulong epoch_leaders_footprint = fd_epoch_leaders_footprint( stake_weight_cnt, sched_cnt );
    FD_LOG_INFO(( "epoch_leaders_footprint=%lu", epoch_leaders_footprint ));
    if( FD_LIKELY( epoch_leaders_footprint ) ) {
      /* Only available when we are importing from snapshot */
      void * epoch_leaders_mem = fd_wksp_alloc_laddr( state->global->local_wksp, fd_epoch_leaders_align(), epoch_leaders_footprint, 1UL );
      state->global->leaders = fd_epoch_leaders_join( fd_epoch_leaders_new( epoch_leaders_mem, stake_weight_cnt, sched_cnt ) );
      FD_TEST( state->global->leaders );
      /* Derive */
      fd_epoch_leaders_derive( state->global->leaders, epoch_weights, epoch );
    }
  }

  ulong prev_slot = state->global->bank.slot;
  for ( ulong slot = state->global->bank.slot+1; slot < state->end_slot; ++slot ) {
    state->global->bank.prev_slot = prev_slot;
    state->global->bank.slot      = slot;

    FD_LOG_INFO(("reading slot %ld (epoch %lu)", slot, epoch));

    fd_slot_meta_t m;
    fd_memset(&m, 0, sizeof(m));
    fd_slot_meta_new(&m);

    /* Read block meta */

    key = fd_runtime_block_meta_key(slot);
    rec = fd_funk_rec_query( state->global->funk, NULL, &key );
    if( FD_UNLIKELY( !rec ) ) continue;
    val = fd_funk_val_cache( state->global->funk, rec, &err );
    if( FD_UNLIKELY( !val ) ) FD_LOG_ERR(("corrupt meta record"));
    fd_bincode_decode_ctx_t ctx3;
    ctx3.data = val;
    ctx3.dataend = (uchar*)val + fd_funk_val_sz(rec);
    ctx3.valloc  = state->global->valloc;
    if( FD_UNLIKELY( fd_slot_meta_decode( &m, &ctx3 )!=FD_BINCODE_SUCCESS ) )
      FD_LOG_ERR(("fd_slot_meta_decode failed"));

    /* Read block */

    key = fd_runtime_block_key( slot );
    rec = fd_funk_rec_query( state->global->funk, NULL, &key );
    if( FD_UNLIKELY( !rec ) ) FD_LOG_ERR(("missing block record"));
    val = fd_funk_val_cache( state->global->funk, rec, &err );
    if( FD_UNLIKELY( !val ) ) FD_LOG_ERR(("missing block record"));

    if ( justverify ) {
      if ( tpool )
        fd_runtime_block_verify_tpool( state->global, &m, val, fd_funk_val_sz(rec), tpool, max_workers );
      else
        fd_runtime_block_verify( state->global, &m, val, fd_funk_val_sz(rec) );
    } else {
      FD_TEST (fd_runtime_block_eval( state->global, &m, val, fd_funk_val_sz(rec) ) == FD_RUNTIME_EXECUTE_SUCCESS);
    }

    fd_bincode_destroy_ctx_t ctx = { .valloc = state->global->valloc };
    fd_slot_meta_destroy(&m, &ctx);

    /* Read bank hash */

    fd_hash_t const * known_bank_hash = fd_get_bank_hash( state->global->funk, slot );
    if( known_bank_hash ) {
      if( FD_UNLIKELY( 0!=memcmp( state->global->bank.banks_hash.hash, known_bank_hash->hash, 32UL ) ) ) {
        FD_LOG_WARNING(( "Bank hash mismatch! slot=%lu expected=%32J, got=%32J",
                         slot,
                         known_bank_hash->hash,
                         state->global->bank.banks_hash.hash ));
        if( state->global->abort_on_mismatch ) {
          fd_solcap_writer_fini( state->global->capture );
          return 1;
        }
      }
    }

    if (NULL != state->capitalization_file) {
      slot_capitalization_t *c = capitalization_map_query(state->map, slot, NULL);
      if (NULL != c) {
        if (state->global->bank.capitalization != c->capitalization)
          FD_LOG_NOTICE(( "capitalization missmatch!  slot=%lu got=%ld != expected=%ld  (%ld)", slot, state->global->bank.capitalization, c->capitalization,  state->global->bank.capitalization - c->capitalization  ));
      }
    }

    if( slot == last_epoch_slot ) {
      FD_LOG_NOTICE(( "EPOCH TRANSITION" ));
    }

    prev_slot = slot;
  }

  // fd_funk_txn_publish( state->global->funk, state->global->funk_txn, 1);

  fd_rent_lists_delete(state->global->rentlists);
  state->global->rentlists = NULL;

  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_wksp_free_laddr( fmem                      );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  global_state_t state;
  fd_memset(&state, 0, sizeof(state));

  char global_mem[FD_GLOBAL_CTX_FOOTPRINT] __attribute__((aligned(FD_GLOBAL_CTX_ALIGN)));
  state.global = fd_global_ctx_join( fd_global_ctx_new( global_mem ) );

  fd_acc_mgr_t _acc_mgr[1];
  state.global->acc_mgr = fd_acc_mgr_new( _acc_mgr, state.global );

  state.argc = argc;
  state.argv = argv;

  state.name                = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",         NULL, NULL );
  state.gaddr               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--gaddr",        NULL, NULL);
  state.persist             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--persist",      NULL, NULL);
  state.end_slot            = fd_env_strip_cmdline_ulong( &argc, &argv, "--end-slot",     NULL, ULONG_MAX);
  state.cmd                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",          NULL, NULL);
  state.reset               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--reset",        NULL, NULL);
  state.load                = fd_env_strip_cmdline_cstr ( &argc, &argv, "--load",         NULL, NULL);
  state.capitalization_file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cap",          NULL, NULL);

  state.pages               = fd_env_strip_cmdline_ulong ( &argc, &argv, "--pages",      NULL, 5);

  char const * index_max_opt           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--index-max", NULL, NULL );
  char const * validate_db             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--validate",  NULL, NULL );
  char const * log_level               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--loglevel", NULL, NULL );
  char const * capture_fpath           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--capture",   NULL, NULL );
  char const * trace_fpath             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--trace",     NULL, NULL );
  int          retrace                 = fd_env_strip_cmdline_int  ( &argc, &argv, "--retrace",   NULL, 0    );

  char const * confirm_hash            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_hash",          NULL, NULL);
  char const * confirm_parent          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_parent",        NULL, NULL);
  char const * confirm_account_delta   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_account_delta", NULL, NULL);
  char const * confirm_signature       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_signature",     NULL, NULL);
  char const * confirm_last_block      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_last_block",    NULL, NULL);

  state.global->abort_on_mismatch = (uchar)fd_env_strip_cmdline_int( &argc, &argv, "--abort-on-mismatch", NULL, 0 );

  if (state.cmd == NULL) {
    usage(argv[0]);
    return 1;
  }

  state.map = capitalization_map_join(capitalization_map_new(state.capitalization_map_mem));

  if (NULL != state.capitalization_file) {
    FILE *fp = fopen(state.capitalization_file, "r");
    if (NULL == fp) {
      perror(state.capitalization_file);
      return -1;
    }
    ulong slot = 0;
    ulong cap = 0;
    while (fscanf(fp, "%ld,%ld", &slot, &cap) == 2) {
      slot_capitalization_t *c = capitalization_map_insert(state.map, slot);
      c->capitalization = cap;
    }
    fclose(fp);
  }

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  fd_wksp_t *local_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, state.pages, 0, "local_wksp", 0UL );
  if ( FD_UNLIKELY( !local_wksp ) )
    FD_LOG_ERR(( "Unable to create local wksp" ));

  fd_wksp_t *funk_wksp;
  if ( state.name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", state.name ));
    funk_wksp = fd_wksp_attach( state.name );
    if ( FD_UNLIKELY( !funk_wksp ) )
      FD_LOG_ERR(( "Unable to attach to wksp" ));
    if ( state.reset && strcmp(state.reset, "true") == 0 ) {
      fd_wksp_reset( funk_wksp, (uint)hashseed);
    }
  } else {
    funk_wksp = local_wksp;
  }

  if (NULL != state.load) {
    FD_LOG_NOTICE(("loading %s", state.load));
    int fd = open(state.load, O_RDONLY);
    if (fd == -1)
      FD_LOG_ERR(("restore failed: %s", strerror(errno)));
    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1)
      FD_LOG_ERR(("restore failed: %s", strerror(errno)));
    uchar* p = (uchar*)funk_wksp;
    uchar* pend = p + statbuf.st_size;
    while ( p < pend ) {
      ulong sz = fd_ulong_min((ulong)(pend - p), 4UL<<20);
      if ( read(fd, p, sz) < 0 )
        FD_LOG_ERR(("restore failed: %s", strerror(errno)));
      p += sz;
    }
    close(fd);
  }

  void* shmem;
  if( !state.gaddr ) {
    if (NULL != state.load)
      FD_LOG_ERR(( "when you load a backup, you still need a --gaddr" ));
    shmem = fd_wksp_alloc_laddr( funk_wksp, fd_funk_align(), fd_funk_footprint(), 1 );
    if (shmem == NULL)
      FD_LOG_ERR(( "failed to allocate a funky" ));
    ulong index_max = 1000000;    // Maximum size (count) of master index
    if (index_max_opt)
      index_max = (ulong) atoi((char *) index_max_opt);
    ulong xactions_max = 100;     // Maximum size (count) of transaction index
    FD_LOG_NOTICE(("creating new funk db, index_max=%lu xactions_max=%lu", index_max, xactions_max));
    state.global->funk = fd_funk_join(fd_funk_new(shmem, 1, hashseed, xactions_max, index_max));
    if (state.global->funk == NULL) {
      fd_wksp_free_laddr(shmem);
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }

  } else {
    if (state.gaddr[0] == '0' && state.gaddr[1] == 'x')
      shmem = fd_wksp_laddr_fast( funk_wksp, (ulong)strtol(state.gaddr+2, NULL, 16) );
    else
      shmem = fd_wksp_laddr_fast( funk_wksp, (ulong)strtol(state.gaddr, NULL, 10) );
    state.global->funk = fd_funk_join(shmem);
    if (state.global->funk == NULL) {
      FD_LOG_ERR(( "failed to join a funky" ));
    }
    ulong r = fd_funk_txn_cancel_all( state.global->funk, 1 );
    if (r)
      FD_LOG_NOTICE(("cancelled %lu old transactions", r));
  }
  FD_LOG_NOTICE(( "funky at global address 0x%lx", fd_wksp_gaddr_fast( funk_wksp, shmem ) ));

  if ((validate_db != NULL) && (strcmp(validate_db, "true") == 0)) {
    FD_LOG_INFO(("starting validate"));
    if ( fd_funk_verify(state.global->funk) != FD_FUNK_SUCCESS )
      FD_LOG_ERR(("valdation failed"));
    FD_LOG_INFO(("finishing validate"));
  }

  if (NULL != log_level)
    state.global->log_level = (uchar) atoi(log_level);

  void * alloc_shmem = fd_wksp_alloc_laddr( local_wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) {
    FD_LOG_ERR(( "fd_alloc too large for workspace" ));
  }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) {
    FD_LOG_ERR(( "fd_allow_new failed" ));
  }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR(( "fd_alloc_join failed" ));
  }

  state.global->funk_wksp = funk_wksp;
  state.global->local_wksp = local_wksp;
  state.global->valloc = fd_libc_alloc_virtual();

  if (NULL != state.persist) {
    FD_LOG_NOTICE(("using %s for persistence", state.persist));
    if ( fd_funk_persist_open_fast( state.global->funk, state.persist ) != FD_FUNK_SUCCESS )
      FD_LOG_ERR(("failed to open persistence file"));
  }

  if( capture_fpath ) {
    state.capture_file = fopen( capture_fpath, "w+" );
    if( FD_UNLIKELY( !state.capture_file ) )
      FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", capture_fpath, errno, fd_io_strerror( errno ) ));

    void * capture_writer_mem = fd_alloc_malloc( alloc, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
    FD_TEST( capture_writer_mem );
    state.global->capture = fd_solcap_writer_new( capture_writer_mem );

    FD_TEST( fd_solcap_writer_init( state.global->capture, state.capture_file ) );
  }

  if( trace_fpath ) {
    FD_LOG_NOTICE(( "Exporting traces to %s", trace_fpath ));

    if( FD_UNLIKELY( 0!=mkdir( trace_fpath, 0777 ) && errno!=EEXIST ) )
      FD_LOG_ERR(( "mkdir(%s) failed (%d-%s)", trace_fpath, errno, fd_io_strerror( errno ) ));

    int fd = open( trace_fpath, O_DIRECTORY );
    if( FD_UNLIKELY( fd<=0 ) )  /* technically 0 is valid, but it serves as a sentinel here */
      FD_LOG_ERR(( "open(%s) failed (%d-%s)", trace_fpath, errno, fd_io_strerror( errno ) ));

    state.global->trace_mode |= FD_RUNTIME_TRACE_SAVE;
    state.global->trace_dirfd = fd;
  }

  if( retrace ) {
    FD_LOG_NOTICE(( "Retrace mode enabled" ));

    state.global->trace_mode |= FD_RUNTIME_TRACE_REPLAY;
  }

  {
    FD_LOG_NOTICE(("reading banks record"));
    fd_funk_rec_key_t id = fd_runtime_banks_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(state.global->funk, NULL, &id);
    if ( rec == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    int err;
    void * val = fd_funk_val_cache( state.global->funk, rec, &err );
    if (val == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    fd_bincode_decode_ctx_t ctx2;
    ctx2.data = val;
    ctx2.dataend = (uchar*)val + fd_funk_val_sz( rec );
    ctx2.valloc  = state.global->valloc;
    FD_TEST( fd_firedancer_banks_decode(&state.global->bank, &ctx2 )==FD_BINCODE_SUCCESS );

    FD_LOG_NOTICE(( "decoded slot=%ld banks_hash=%32J poh_hash %32J",
                    (long)state.global->bank.slot,
                    state.global->bank.banks_hash.hash,
                    state.global->bank.poh.hash ));

    state.global->bank.collected_fees = 0;
    state.global->bank.collected_rent = 0;

    FD_LOG_NOTICE(( "decoded slot=%ld capitalization=%ld",
                    (long)state.global->bank.slot,
                    state.global->bank.capitalization));
  }

  ulong tcnt = fd_tile_cnt();
  uchar tpool_mem[ FD_TPOOL_FOOTPRINT(FD_TILE_MAX) ] __attribute__((aligned(FD_TPOOL_ALIGN)));
  fd_tpool_t * tpool = NULL;
  if ( tcnt > 1) {
    tpool = fd_tpool_init(tpool_mem, tcnt);
    if ( tpool == NULL )
      FD_LOG_ERR(("failed to create thread pool"));
    for ( ulong i = 1; i < tcnt; ++i ) {
      if ( fd_tpool_worker_push( tpool, i, NULL, 0UL ) == NULL )
        FD_LOG_ERR(("failed to launch worker"));
    }
  }

  if (strcmp(state.cmd, "replay") == 0) {
    int err = replay(&state, 0, tpool, tcnt);
    if( err!=0 ) return err;

    if (NULL != confirm_hash) {
      uchar h[32];
      fd_base58_decode_32( confirm_hash,  h);
      FD_TEST(memcmp(h, &state.global->bank.banks_hash, sizeof(h)) == 0);
    }

    if (NULL != confirm_parent) {
      uchar h[32];
      fd_base58_decode_32( confirm_parent,  h);
      FD_TEST(memcmp(h, state.global->prev_banks_hash.uc, sizeof(h)) == 0);
    }

    if (NULL != confirm_account_delta) {
      uchar h[32];
      fd_base58_decode_32( confirm_account_delta,  h);
      FD_TEST(memcmp(h, state.global->account_delta_hash.uc, sizeof(h)) == 0);
    }

    if (NULL != confirm_signature)
      FD_TEST((ulong) atoi(confirm_signature) == state.global->signature_cnt);

    if (NULL != confirm_last_block) {
      uchar h[32];
      fd_base58_decode_32( confirm_last_block,  h);
      FD_TEST(memcmp(h, &state.global->bank.poh, sizeof(h)) == 0);
    }

  }
  if (strcmp(state.cmd, "verifyonly") == 0)
    replay(&state, 1, tpool, tcnt);
  if (strcmp(state.cmd, "accounts_hash") == 0)
    accounts_hash(&state);

  fd_alloc_free( alloc, fd_solcap_writer_delete( fd_solcap_writer_fini( state.global->capture ) ) );
  if( state.capture_file  ) fclose( state.capture_file );
  if( state.global->trace_dirfd>0 ) close( state.global->trace_dirfd );

  fd_global_ctx_delete(fd_global_ctx_leave(state.global));

  FD_TEST(fd_alloc_is_empty(alloc));
  fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );

  fd_wksp_delete_anonymous( state.global->local_wksp );
  if( state.name )
    fd_wksp_detach( state.global->funk_wksp );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
