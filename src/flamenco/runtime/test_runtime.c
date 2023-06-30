/****

build/linux/gcc/x86_64/bin/fd_frank_ledger --rocksdb $LEDGER/rocksdb --genesis $LEDGER/genesis.bin --cmd ingest --indexmax 10000 --txnmax 100 --backup test_ledger_backup

build/linux/gcc/x86_64/unit-test/test_runtime --load test_ledger_backup --cmd replay --end-slot 25 --confirm_hash AsHedZaZkabNtB8XBiKWQkKwaeLy2y4Hrqm6MkQALT5h --confirm_parent CvgPeR54qpVRZGBuiQztGXecxSXREPfTF8wALujK4WdE --confirm_account_delta 7PL6JZgcNy5vkPSc6JsMHET9dvpvsFMWR734VtCG29xN  --confirm_signature 2  --confirm_last_block G4YL2SieHDGNZGjiwBsJESK7jMDfazg33ievuCwbkjrv --validate true

build/linux/gcc/x86_64/bin/fd_shmem_cfg reset

build/linux/gcc/x86_64/bin/fd_wksp_ctl new giant_wksp 200 gigantic 8-63 0666

build/linux/gcc/x86_64/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /home/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /home/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --rocksdb /home/jsiegel/mainnet-ledger/rocksdb --endslot 179248378 --backup /home/asiegel/mainnet_backup

build/linux/gcc/x86_64/unit-test/test_runtime --wksp giant_wksp --reset true --load /home/asiegel/mainnet_backup --cmd replay --index-max 350000000

build/linux/gcc/x86_64/unit-test/test_runtime --wksp giant_wksp --gaddr 0xc7ce180 --cmd replay
  NOTE: gaddr argument may be different

build/linux/gcc/x86_64/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /data/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /data/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --rocksdb /data/jsiegel/mainnet-ledger/rocksdb --endslot 179248378 --backup /data/jsiegel/mainnet_backup

build/linux/gcc/x86_64/unit-test/test_runtime --wksp giant_wksp --gaddr 0x000000000c7ce180 --cmd replay

/data/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst
/data/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst
****/

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

#include <dirent.h>

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

// #define MALLOC_NOT_FDALLOC
#ifdef MALLOC_NOT_FDALLOC
int fd_alloc_fprintf( fd_alloc_t * join, FILE *       stream );

char* local_allocf(void * arg, ulong align, ulong len) {
  (void)arg;
  char * ptr = malloc(fd_ulong_align_up(sizeof(char *) + len, align));
  char * ret = (char *) fd_ulong_align_up( (ulong) (ptr + sizeof(char *)), align );
  *((char **)(ret - sizeof(char *))) = ptr;
  return ret;
}

void local_freef(void * arg, void *ptr) {
  (void)arg;
  free(*((char **)((char *) ptr - sizeof(char *))));
}
#endif

struct global_state {
  fd_global_ctx_t*    global;

  int                 argc;
  char       **       argv;

  char const *        name;
  ulong               pages;
  char const *        gaddr;
  char const *        persist;
  ulong               end_slot;
  char const *        end_slot_opt;
  char const *        cmd;
  char const *        net;
  char const *        reset;
  char const *        load;
};
typedef struct global_state global_state_t;

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --wksp        <name>       workspace name\n");
  fprintf(stderr, " --gaddr       <num>        global address of funky in the workspace\n");
  fprintf(stderr, " --persist     <file>       funky persistence file\n");
  fprintf(stderr, " --load        <file>       load funky backup file\n");
  fprintf(stderr, " --end-slot    <num>        stop iterating at block...\n");
  fprintf(stderr, " --cmd         <operation>  What operation should we test\n");
  fprintf(stderr, " --index-max   <bool>       How big should the index table be?\n");
  fprintf(stderr, " --validate    <bool>       Validate the funk db\n");
  fprintf(stderr, " --reset       <bool>       Reset the workspace\n");
}

#define SORT_NAME sort_pubkey_hash_pair
#define SORT_KEY_T fd_pubkey_hash_pair_t
#define SORT_BEFORE(a,b) ((memcmp(&a, &b, 32) < 0))
#include "../../util/tmpl/fd_sort.c"

int accounts_hash(global_state_t *state) {
  fd_funk_t * funk = state->global->funk;
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
  ulong num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );

  FD_LOG_NOTICE(( "NIA %lu", num_iter_accounts ));

  ulong zero_accounts = 0;
  ulong num_pairs = 0;
  fd_pubkey_hash_pair_t * pairs = (fd_pubkey_hash_pair_t *) state->global->allocf(state->global->allocf_arg , 8UL, num_iter_accounts*sizeof(fd_pubkey_hash_pair_t));
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

  char accounts_hash_58[FD_BASE58_ENCODED_32_SZ];
  fd_base58_encode_32((uchar const *)accounts_hash.hash, NULL, accounts_hash_58);

  FD_LOG_WARNING(("accounts_hash %s", accounts_hash_58));
  FD_LOG_WARNING(("num_iter_accounts %ld", num_iter_accounts));

  return 0;
}

void print_file(global_state_t *state, const char *file) {
  char  buf[1000];
  char *p = (char *) &file[strlen(file) - 1];
//  ulong slot = 0;
//  ulong id = 0;

  while ((p > file) && *p != '/')
    p--;
  if (*p == '/')
    p++;

  strcpy(buf, p);
  p = buf;
  while (*p != '.') p++;

  if (*p == '.') {
    *p++ = '\0';
//    id = (ulong) atol(p);
  }
//  slot = (ulong) atol(buf);

  struct stat s;

  stat(file,  &s);
  unsigned char *r = (unsigned char *)state->global->allocf(state->global->allocf_arg, 8UL, (unsigned long) (unsigned long) s.st_size);
  unsigned char *b = r;
  int            fd = open(file, O_RDONLY);
  ssize_t        n = read(fd, b, (unsigned long) s.st_size);
  if (n != s.st_size) {
    FD_LOG_ERR(( "Read failure" ));
  }

  unsigned char *eptr = &b[(ulong) ((ulong)n - (ulong)sizeof(fd_solana_account_hdr_t))];

  while (b < eptr) {
    fd_solana_account_hdr_t *hdr = (fd_solana_account_hdr_t *)b;
    // Look for corruption...
    if ((b + hdr->meta.data_len) > (r + n)) {
      // some kind of corruption in the file?
      break;
    }
    // Sanitize accounts...
    if ((hdr->info.lamports == 0) | ((hdr->info.executable & ~1) != 0))
      break;

    char pubkey[50];
    fd_memset(pubkey, 0, sizeof(pubkey));
    fd_base58_encode_32((uchar *) hdr->meta.pubkey, 0, pubkey);

    char owner[50];
    fd_memset(owner, 0, sizeof(owner));
    fd_base58_encode_32((uchar *) hdr->info.owner, 0, owner);

    char encoded_hash[50];
    fd_base58_encode_32((uchar *) hdr->hash.value, 0, encoded_hash);

//    printf("owner: %48s pubkey: %48s hash: %48s file: %s size: %lu\n", owner, pubkey, encoded_hash, file, hdr->meta.data_len);

    printf("%s owner: %s hash: %48s file: %s size: %lu\n", pubkey, owner, encoded_hash, file, hdr->meta.data_len);

//    fd_account_meta_t result;
//    fd_acc_mgr_get_metadata(state->global->acc_mgr, fd_funk_root(state->global->acc_mgr->funk), (fd_pubkey_t *) hdr->meta.pubkey, &result);
//
//    if (memcmp(result.hash, hash, sizeof(hash))) {
//      uchar *           account_data = (uchar *) fd_alloca(8UL,  hdr->meta.data_len);
//      fd_acc_mgr_get_account_data( state->global->acc_mgr, fd_funk_root(state->global->acc_mgr->funk), (fd_pubkey_t *) &hdr->meta.pubkey, account_data, sizeof(fd_account_meta_t), hdr->meta.data_len);
//      printf("Hmm.. bad dog\n");
//    }

    fd_bincode_decode_ctx_t ctx2;
    ctx2.data = &b[sizeof(*hdr)];
    ctx2.dataend = (uchar *)ctx2.data + hdr->meta.data_len;
    ctx2.allocf = state->global->allocf;
    ctx2.allocf_arg = state->global->allocf_arg;

    if (strcmp(pubkey, "SysvarC1ock11111111111111111111111111111111") == 0) {
      fd_sol_sysvar_clock_t a;
      memset(&a, 0, sizeof(a));
      fd_sol_sysvar_clock_new(&a);
      if ( fd_sol_sysvar_clock_decode(&a, &ctx2) )
        FD_LOG_ERR(("fd_sol_sysvar_clock_decode failed"));
      printf("  {slot = %ld, epoch_start_timestamp = %ld, epoch = %ld, leader_schedule_epoch = %ld, unix_timestamp = %ld}\n",
        a.slot, a.epoch_start_timestamp, a.epoch, a.leader_schedule_epoch, a.unix_timestamp);
      fd_bincode_destroy_ctx_t ctx;
      ctx.freef = state->global->freef;
      ctx.freef_arg = state->global->allocf_arg;
      fd_sol_sysvar_clock_destroy(&a, &ctx);

    } else if (strcmp(pubkey, "SysvarRecentB1ockHashes11111111111111111111") == 0) {
      fd_recent_block_hashes_t a;
      memset(&a, 0, sizeof(a));
      fd_recent_block_hashes_new(&a);
      if ( fd_recent_block_hashes_decode(&a, &ctx2) )
        FD_LOG_ERR(("fd_recent_block_hashes_decode failed"));
      fd_block_block_hash_entry_t * hashes = a.hashes;
      for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( hashes );
            !deq_fd_block_block_hash_entry_t_iter_done( hashes, iter );
            iter = deq_fd_block_block_hash_entry_t_iter_next( hashes, iter ) ) {
        fd_block_block_hash_entry_t * e = deq_fd_block_block_hash_entry_t_iter_ele( hashes, iter );
        char encoded_hash[50];
        fd_base58_encode_32((uchar *) e->blockhash.hash, 0, encoded_hash);

        printf("  {blockhash = %s,  fee_calculator={lamports_per_signature = %ld}}\n", encoded_hash, e->fee_calculator.lamports_per_signature);
      }
      fd_bincode_destroy_ctx_t ctx;
      ctx.freef = state->global->freef;
      ctx.freef_arg = state->global->allocf_arg;
      fd_recent_block_hashes_destroy(&a, &ctx);
    }

    b += fd_ulong_align_up(hdr->meta.data_len + sizeof(*hdr), 8);
  }

  close(fd);
  state->global->freef(state->global->allocf_arg, r);
}

int replay(global_state_t *state) {
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
  ctx2.data = val;
  ctx2.dataend = (uchar*)val + fd_funk_val_sz(rec);
  ctx2.allocf = state->global->allocf;
  ctx2.allocf_arg = state->global->allocf_arg;
  if ( fd_slot_meta_meta_decode( &mm, &ctx2 ) )
    FD_LOG_ERR(("fd_slot_meta_meta_decode failed"));

  if (mm.end_slot < state->end_slot)
    state->end_slot = mm.end_slot;

  if (0 != state->global->bank.slot)
    fd_update_features(state->global);

  for ( ulong slot = state->global->bank.slot+1; slot < state->end_slot; ++slot ) {
    state->global->bank.slot = slot;

    FD_LOG_NOTICE(("reading slot %ld", slot));

    fd_slot_meta_t m;
    fd_memset(&m, 0, sizeof(m));
    fd_slot_meta_new(&m);

    key = fd_runtime_block_meta_key(slot);
    rec = fd_funk_rec_query( state->global->funk, NULL, &key );
    if (rec == NULL)
      continue;
    val = fd_funk_val_cache( state->global->funk, rec, &err );
    if (val == NULL)
      FD_LOG_ERR(("corrupt meta record"));
    fd_bincode_decode_ctx_t ctx3;
    ctx3.data = val;
    ctx3.dataend = (uchar*)val + fd_funk_val_sz(rec);
    ctx3.allocf = state->global->allocf;
    ctx3.allocf_arg = state->global->allocf_arg;
    if ( fd_slot_meta_decode( &m, &ctx3 ) )
      FD_LOG_ERR(("fd_slot_meta_decode failed"));

    key = fd_runtime_block_key(slot);
    rec = fd_funk_rec_query( state->global->funk, NULL, &key );
    if (rec == NULL)
      FD_LOG_ERR(("missing block record"));
    val = fd_funk_val_cache( state->global->funk, rec, &err );
    if (val == NULL)
      FD_LOG_ERR(("missing block record"));

    FD_TEST (fd_runtime_block_eval( state->global, &m, val, fd_funk_val_sz(rec) ) == FD_RUNTIME_EXECUTE_SUCCESS);

    fd_bincode_destroy_ctx_t ctx;
    ctx.freef = state->global->freef;
    ctx.freef_arg = state->global->allocf_arg;
    fd_slot_meta_destroy(&m, &ctx);
  }

  // fd_funk_txn_publish( state->global->funk, state->global->funk_txn, 1);

  return 0;
}

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  global_state_t state;
  fd_memset(&state, 0, sizeof(state));

  char global_mem[FD_GLOBAL_CTX_FOOTPRINT] __attribute__((aligned(FD_GLOBAL_CTX_ALIGN)));
  memset(global_mem, 0, sizeof(global_mem));
  state.global = fd_global_ctx_join( fd_global_ctx_new( global_mem ) );

  char acc_mgr_mem[FD_ACC_MGR_FOOTPRINT] __attribute__((aligned(FD_ACC_MGR_ALIGN)));
  memset(acc_mgr_mem, 0, sizeof(acc_mgr_mem));
  state.global->acc_mgr = fd_acc_mgr_join( fd_acc_mgr_new( acc_mgr_mem, state.global, FD_ACC_MGR_FOOTPRINT ) );

  state.argc = argc;
  state.argv = argv;

  state.name                = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",         NULL, NULL );
  state.gaddr               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--gaddr",        NULL, NULL);
  state.persist             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--persist",      NULL, NULL);
  state.end_slot_opt        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--end-slot",     NULL, NULL);
  state.cmd                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",          NULL, NULL);
  state.net                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--net",          NULL, NULL);
  state.reset               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--reset",        NULL, NULL);
  state.load                = fd_env_strip_cmdline_cstr ( &argc, &argv, "--load",         NULL, NULL);

  state.pages               = fd_env_strip_cmdline_ulong ( &argc, &argv, "--pages",      NULL, 5);

  const char *index_max_opt           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--index-max",    NULL, NULL);
  const char *validate_db             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--validate",     NULL, NULL);
  const char *log_level               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--log_level",     NULL, NULL);

  const char *confirm_hash            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_hash",          NULL, NULL);
  const char *confirm_parent          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_parent",        NULL, NULL);
  const char *confirm_account_delta   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_account_delta", NULL, NULL);
  const char *confirm_signature       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_signature",     NULL, NULL);
  const char *confirm_last_block      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_last_block",    NULL, NULL);

  if (state.cmd == NULL) {
    usage(argv[0]);
    return 1;
  }

  if (NULL != state.net) {
    if (!strncmp(state.net, "main", 4))
      fd_enable_mainnet(&state.global->features);
    if (!strcmp(state.net, "test"))
      fd_enable_testnet(&state.global->features);
    if (!strcmp(state.net, "dev"))
      fd_enable_devnet(&state.global->features);
  } else
    fd_enable_everything(&state.global->features);

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  fd_wksp_t *wksp = NULL;
  if ( state.name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", state.name ));
    wksp = fd_wksp_attach( state.name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous workspace with %lu pages", state.pages ));
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, state.pages, 0, "wksp", 0UL );
    state.gaddr = 0;
  }
  if ( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "Unable to attach to wksp" ));

  if ( state.reset && strcmp(state.reset, "true") == 0 ) {
    fd_wksp_reset( wksp, (uint)hashseed);
    state.gaddr = 0;
  }

  void* shmem;
  if( !state.gaddr ) {
    shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), 1 );
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
      shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(state.gaddr+2, NULL, 16) );
    else
      shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(state.gaddr, NULL, 10) );
    state.global->funk = fd_funk_join(shmem);
    if (state.global->funk == NULL) {
      FD_LOG_ERR(( "failed to join a funky" ));
    }
    ulong r = fd_funk_txn_cancel_all( state.global->funk, 1 );
    if (r)
      FD_LOG_NOTICE(("cancelled %lu old transactions", r));
  }
  FD_LOG_NOTICE(( "funky at global address 0x%lx", fd_wksp_gaddr_fast( wksp, shmem ) ));

  if (NULL != log_level)
    state.global->log_level = (uchar) atoi(log_level);

  state.global->wksp = wksp;
#ifdef MALLOC_NOT_FDALLOC
  state.global->allocf = (fd_alloc_fun_t)local_allocf;
  state.global->freef = (fd_free_fun_t)local_freef;
#else
  state.global->allocf = (fd_alloc_fun_t)fd_alloc_malloc;
  state.global->freef = (fd_free_fun_t)fd_alloc_free;
#endif
  state.global->allocf_arg = fd_wksp_laddr_fast( wksp, state.global->funk->alloc_gaddr );

  if (NULL != state.persist) {
    FD_LOG_NOTICE(("using %s for persistence", state.persist));
    if ( fd_funk_persist_open_fast( state.global->funk, state.persist ) != FD_FUNK_SUCCESS )
      FD_LOG_ERR(("failed to open persistence file"));
  }

  if (NULL != state.load) {
    FD_LOG_NOTICE(("loading %s", state.load));
    if ( fd_funk_load_backup( state.global->funk, state.load, 0 ) != FD_FUNK_SUCCESS )
      FD_LOG_ERR(("failed to open backup file"));
  }

  if ((validate_db != NULL) && (strcmp(validate_db, "true") == 0)) {
    FD_LOG_WARNING(("starting validate"));
    if ( fd_funk_verify(state.global->funk) != FD_FUNK_SUCCESS )
      FD_LOG_ERR(("valdation failed"));
    FD_LOG_WARNING(("finishing validate"));
  }

  if (NULL != state.end_slot_opt)
    state.end_slot = (ulong) atoi(state.end_slot_opt);
  else
    state.end_slot = ULONG_MAX;

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
    ctx2.allocf = state.global->allocf;
    ctx2.allocf_arg = state.global->allocf_arg;
    if ( fd_firedancer_banks_decode(&state.global->bank, &ctx2 ) )
      FD_LOG_ERR(("failed to read banks record"));
  }

  if (strcmp(state.cmd, "replay") == 0) {
    replay(&state);

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
  if (strcmp(state.cmd, "accounts_hash") == 0)
    accounts_hash(&state);

  fd_global_ctx_delete(fd_global_ctx_leave(state.global));

  if( state.name )
    fd_wksp_detach( state.global->wksp );
  else
    fd_wksp_delete_anonymous( state.global->wksp );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
