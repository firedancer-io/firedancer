
//- sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" ~/repos/solana/nonce-ledger/validator.log | grep 'bank frozen:' | grep 'solana_runtime::bank' | sed -e 's/.*bank frozen://g' > q

// sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" ~/repos/solana/nonce-ledger/validator.log > q2

// sudo /home/jsiegel/repos/firedancer/build/linux/gcc/x86_64/bin/fd_shmem_cfg init 0777 jsiegel ""
// sudo /home/jsiegel/repos/firedancer/build/linux/gcc/x86_64/bin/fd_shmem_cfg alloc 64 gigantic 0
// sudo /home/jsiegel/repos/firedancer/build/linux/gcc/x86_64/bin/fd_shmem_cfg alloc 512 huge 0

// build/linux/gcc/x86_64/bin/fd_wksp_ctl new giant_wksp 200 gigantic 0-127 0666

// build/linux/gcc/x86_64/bin/fd_frank_ledger --cmd ingest --snapshotfile /home/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --wksp giant_wksp --verifyhash 2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu
// build/linux/gcc/x86_64/bin/fd_frank_ledger --wksp giant_wksp  --cmd ingest --snapshotfile /home/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /home/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --verifyhash 6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw --reset true
// build/linux/gcc/x86_64/bin/fd_frank_ledger --gaddr 0x000000000c7ce180 --wksp giant_wksp --verifyhash 2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu
// build/linux/gcc/x86_64/bin/fd_frank_ledger --wksp giant_wksp  --cmd ingest --snapshotfile /home/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /home/jsiegel/mainnet-ledger/incremental-snapshot-179244882-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --reset true --persist /home/asiegel/funktest

// fpid-devworkl187 asiegel/firedancer-private $ build/linux/gcc/x86_64/bin/fd_frank_ledger --wksp giant_wksp --reset true --persist ~/testfunk --rocksdb ~/firedancer-private/test-ledger-4/rocksdb --cmd ingest --gaddrout gaddr

// /home/jsiegel/repos/firedancer-private/build/linux/gcc/x86_64/bin/fd_wksp_ctl new test_wksp 32 gigantic 0 0777
// /home/jsiegel/repos/firedancer-private/build/linux/gcc/x86_64/bin/fd_wksp_ctl query test_wksp

// --ledger /home/jsiegel/repos/solana/nonce-ledger --db /home/jsiegel/funk --cmd replay --accounts /home/jsiegel/repos/solana/nonce-ledger/accounts/ --pages 15 --index-max 12000000 --start-slot 0 --end-slot 100

//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd replay --start-slot 179138256 --end-slot 179138258  --txn-exe sim  --index-max 12000000 --pages 15

// --ledger /home/jsiegel/multi-node-cluster-ledger --db /dev/shm/funk --cmd replay --start-slot 0 --end-slot 280   --index-max 12000000 --pages 15

//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd manifest --manifest /home/jsiegel/mainnet-ledger/snapshot/tmp-snapshot-archive-JfVTLu/snapshots/179248368/179248368

//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd replay --start-slot 179138205 --end-slot 279138205  --txn-exe sim  --index-max 12000000 --pages 15
//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd ingest --start-slot 179138205 --end-slot 279138205 --manifest /dev/shm/mainnet-ledger/snapshot/tmp-snapshot-archive-JfVTLu/snapshots/179248368/179248368
// run --ledger /home/jsiegel/mainnet-ledger --db /home/jsiegel/funk --cmd ingest --accounts /home/jsiegel/mainnet-ledger/accounts --pages 15 --index-max 12000000
// run --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd ingest --accounts /dev/shm/mainnet-ledger/accounts --pages 15 --index-max 12000000

// --ledger /home/jsiegel/repos/solana/test-ledger --db /home/jsiegel/repos/solana//test-ledger/funk --cmd replay --start-slot 0 --end-slot 200  --txn-exe sim  --index-max 12000000 --pages 15

// run --ledger /home/jsiegel/test-ledger --db /home/jsiegel/test-ledger/funk --cmd replay --start-slot 0 --end-slot 200 --index-max 12000000 --pages 15

// --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd validate --accounts /home/jsiegel/test-ledger/accounts/ --pages 15 --index-max 12000000 --manifest /home/jsiegel/test-ledger/200/snapshots/200/200 --start-slot 200
// --ledger /home/jsiegel/repos/firedancer-testbins/test-ledger --db /home/jsiegel/funk --cmd validate --accounts /home/jsiegel/repos/firedancer-testbins/test-ledger/accounts/ --pages 15 --index-max 12000000 --manifest /home/jsiegel/repos/firedancer-testbins/test-ledger/200/snapshots/200/200 --start-slot 200

// --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd validate --accounts /home/jsiegel/test-ledger/accounts/ --pages 15 --index-max 12000000 --manifest /home/jsiegel/test-ledger/100/snapshots/100/100 --start-slot 100

// --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd accounts --accounts /home/jsiegel/test-ledger/accounts/ --pages 15 --index-max 12000000 --start-slot 4 --end-slot 5 --start-id 41 --end-id 43

// --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd replay --pages 15 --index-max 12000000 --start-slot 0 --end-slot 6

// --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd replay --pages 15 --index-max 12000000 --start-slot 0 --end-slot 35

//  --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd accounts --accounts /home/jsiegel/test-ledger/accounts/ --pages 15 --index-max 12000000 --start-slot 0 --end-slot 0 --start-id 35 --end-id 35

//owner:      Sysvar1111111111111111111111111111111111111 pubkey:      SysvarRecentB1ockHashes11111111111111111111 hash:     EeEiSR3bwzfALaqzJdNSgf81c6dsnb4Cvb7f1rEqUaE9 file: /home/jsiegel/test-ledger/accounts//0.35
//  {blockhash = Ha5DVgnD1xSA8oQc337jtA3atEfQ4TFX1ajeZG1Y2tUx,  fee_calculator={lamports_per_signature = 0}}

// #define _VHASH


// --ledger /home/jsiegel/repos/solana/test-ledger --db /home/jsiegel/funk --cmd accounts --accounts /home/jsiegel/repos/solana/test-ledger/accounts/ --pages 15 --index-max 12000000 --start-slot 0 --end-slot 1 --start-id 0 --end-id 1
// --ledger /home/jsiegel/repos/solana/test-ledger --db /home/jsiegel/funk --cmd replay --accounts /home/jsiegel/repos/solana/test-ledger/accounts/ --pages 15 --index-max 12000000 --start-slot 0 --end-slot 6 --log_level 3

// --ledger /home/jsiegel/repos/solana/test-ledger --db /home/jsiegel/funk --cmd replay --accounts /home/jsiegel/repos/solana/test-ledger/accounts/ --pages 15 --index-max 12000000 --start-slot 0 --end-slot 25  --confirm_hash AsHedZaZkabNtB8XBiKWQkKwaeLy2y4Hrqm6MkQALT5h --confirm_parent CvgPeR54qpVRZGBuiQztGXecxSXREPfTF8wALujK4WdE --confirm_account_delta 7PL6JZgcNy5vkPSc6JsMHET9dvpvsFMWR734VtCG29xN  --confirm_signature 2  --confirm_last_block G4YL2SieHDGNZGjiwBsJESK7jMDfazg33ievuCwbkjrv

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
#include "../base58/fd_base58.h"
#include "../poh/fd_poh.h"
#include "../sha256/fd_sha256.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar.h"
#include "fd_runtime.h"

#include <dirent.h>

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

uchar do_valgrind = 0;

int fd_alloc_fprintf( fd_alloc_t * join, FILE *       stream );

struct global_state {
  fd_global_ctx_t*    global;

  ulong               start_slot;
  ulong               end_slot;
  ulong               start_id;
  ulong               end_id;
  ulong               pages;
  uchar               txn_exe;

  int                 argc;
  char       **       argv;

  char const *        name;
  char const *        ledger;
  char const *        gaddr;
  char const *        persist;
  char const *        start_slot_opt;
  char const *        end_slot_opt;
  char const *        start_id_opt;
  char const *        end_id_opt;
  char const *        accounts;
  char const *        cmd;
  char const *        txn_exe_opt;
  char const *        net;
};
typedef struct global_state global_state_t;

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --wksp        <name>       workspace name\n");
  fprintf(stderr, " --ledger      <dir>        ledger directory\n");
  fprintf(stderr, " --gaddr       <num>        global address of funky in the workspace\n");
  fprintf(stderr, " --persist     <file>       funky persistence file\n");
  fprintf(stderr, " --end-slot    <num>        stop iterating at block...\n");
  fprintf(stderr, " --start-slot  <num>        start iterating at block...\n");
  fprintf(stderr, " --accounts    <dir>        What accounts should I slurp in\n");
  fprintf(stderr, " --cmd         <operation>  What operation should we test\n");
  fprintf(stderr, " --skip-exe    [skip,sim]   Should we skip executing transactions\n");
  fprintf(stderr, " --index-max   <bool>       How big should the index table be?\n");
  fprintf(stderr, " --validate    <bool>       Validate the funk db\n");
}

// pub const FULL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz|tar\.lz4)$";
// pub const INCREMENTAL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^incremental-snapshot-(?P<base>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz|tar\.lz4)$";


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

int slot_dump(global_state_t *state) {
  fd_runtime_boot_slot_zero(state->global);

  if (NULL == state->accounts)  {
    usage(state->argv[0]);
    exit(1);
  }
  regex_t reg;
  // Where were those regular expressions for snapshots?
  if (regcomp(&reg, "[0-9]+\\.[0-9]+", REG_EXTENDED) != 0) {
    FD_LOG_ERR(( "compile failed" ));
  }

  FD_LOG_WARNING(("starting read of %s", state->accounts));

  DIR *dir = opendir(state->accounts);

  struct dirent * ent;

  while ( NULL != (ent = readdir(dir)) ) {
    if ( regexec(&reg, ent->d_name, 0, NULL, 0) == 0 )  {
      char buf[1000];

      strcpy(buf, ent->d_name);
      char *p = buf;
      while (*p != '.') p++;
      *p++ = '\0';

      ulong slot = (ulong) atol(buf);
      ulong id = (ulong) atol(p);

      if ((slot < state->start_slot) | (slot > state->end_slot))
        continue;

      if ((id < state->start_id) | ((state->end_id > 0) & (id > state->end_id)))
        continue;

      sprintf(buf, "%s/%s", state->accounts, ent->d_name);

      print_file(state, buf);
    }
  }

  closedir(dir);
  regfree(&reg);

  return 0;
}

int replay(global_state_t *state) {
  if (0 == state->start_slot)
    fd_runtime_boot_slot_zero(state->global);

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

  if (mm.start_slot > state->start_slot)
    state->start_slot = mm.start_slot;
  if (mm.end_slot < state->end_slot)
    state->end_slot = mm.end_slot;

  for ( ulong slot = state->start_slot; slot < state->end_slot; ++slot ) {
    state->global->bank.solana_bank.slot = slot;

    if ((state->end_slot < 10) || ((slot % 10) == 0))
      FD_LOG_WARNING(("reading slot %ld", slot));

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

  fd_funk_txn_publish( state->global->funk, state->global->funk_txn, 1);

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
  state.ledger              = fd_env_strip_cmdline_cstr ( &argc, &argv, "--ledger",       NULL, NULL);
  state.gaddr               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--gaddr",        NULL, NULL);
  state.persist             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--persist",      NULL, NULL);
  state.start_slot_opt      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--start-slot",   NULL, NULL);
  state.end_slot_opt        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--end-slot",     NULL, NULL);
  state.start_id_opt        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--start-id",     NULL, NULL);
  state.end_id_opt          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--end-id",       NULL, NULL);
  state.accounts            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--accounts",     NULL, NULL);
  state.cmd                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",          NULL, NULL);
  state.txn_exe_opt         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--txn-exe",      NULL, NULL);
  state.net                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--net",          NULL, NULL);

  state.pages         = fd_env_strip_cmdline_ulong ( &argc, &argv, "--pages",      NULL, 0);

  const char *index_max_opt           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--index-max",    NULL, NULL);
  const char *validate_db             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--validate",     NULL, NULL);
  const char *log_level               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--log_level",     NULL, NULL);

  const char *confirm_hash            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_hash",          NULL, NULL);
  const char *confirm_parent          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_parent",        NULL, NULL);
  const char *confirm_account_delta   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_account_delta", NULL, NULL);
  const char *confirm_signature       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_signature",     NULL, NULL);
  const char *confirm_last_block      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--confirm_last_block",    NULL, NULL);

  if (NULL == state.ledger) {
    usage(argv[0]);
    exit(1);
  }

  if (state.txn_exe_opt) {
    state.txn_exe = (strcmp(state.txn_exe_opt, "skip") == 0) ? 1 : 0;
    state.txn_exe = (strcmp(state.txn_exe_opt, "sim") == 0) ? 2 : 0;
  }

  if (NULL != state.net) {
    if (!strncmp(state.net, "main", 4))
      enable_mainnet(&state.global->features);
    if (!strcmp(state.net, "test"))
      enable_testnet(&state.global->features);
    if (!strcmp(state.net, "dev"))
      enable_devnet(&state.global->features);
  } else
    memset(&state.global->features, 1, sizeof(state.global->features));

  fd_wksp_t *wksp = NULL;
  if ( state.name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", state.name ));
    wksp = fd_wksp_attach( state.name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, state.pages, 0, "wksp", 0UL );
  }
  if ( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "Unable to attach to wksp" ));

  if( !state.gaddr ) {
    FD_LOG_NOTICE(("creating new funk db"));
    void* shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), 1 );
    if (shmem == NULL)
      FD_LOG_ERR(( "failed to allocate a funky" ));
    ulong index_max = 1000000;    // Maximum size (count) of master index
    if (index_max_opt)
      index_max = (ulong) atoi((char *) index_max_opt);
    ulong xactions_max = 100;     // Maximum size (count) of transaction index
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));
    state.global->funk = fd_funk_join(fd_funk_new(shmem, 1, hashseed, xactions_max, index_max));
    if (state.global->funk == NULL) {
      fd_wksp_free_laddr(shmem);
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
    FD_LOG_WARNING(( "funky at global address %lu", fd_wksp_gaddr_fast( wksp, shmem ) ));

  } else {
    void* shmem;
    if (state.gaddr[0] == '0' && state.gaddr[1] == 'x')
      shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(state.gaddr+2, NULL, 16) );
    else
      shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(state.gaddr, NULL, 10) );
    state.global->funk = fd_funk_join(shmem);
    if (state.global->funk == NULL) {
      FD_LOG_ERR(( "failed to join a funky" ));
    }
  }

  if (NULL != log_level)
    state.global->log_level = (uchar) atoi(log_level);

  state.global->wksp = wksp;
  state.global->allocf = (fd_alloc_fun_t)fd_alloc_malloc;
  state.global->freef = (fd_free_fun_t)fd_alloc_free;
  state.global->allocf_arg = fd_wksp_laddr_fast( wksp, state.global->funk->alloc_gaddr );

  if (NULL != state.persist) {
    if ( fd_funk_persist_open_fast( state.global->funk, state.persist ) != FD_FUNK_SUCCESS )
      FD_LOG_ERR(("failed to open persistence file"));
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
  if (NULL != state.start_slot_opt)
    state.start_slot = (ulong) atoi(state.start_slot_opt);
  else
    state.start_slot = 0;
  if (NULL != state.end_id_opt)
    state.end_id = (ulong) atoi(state.end_id_opt);
  if (NULL != state.start_id_opt)
    state.start_id = (ulong) atoi(state.start_id_opt);

  // Eventually we will have to add support for reading compressed genesis blocks...
  char genesis[128];
  sprintf(genesis, "%s/genesis.bin", state.ledger);

  {
    struct stat sbuf;
    stat(genesis, &sbuf);
    int fd = open(genesis, O_RDONLY);
    if (fd < 0) {
      FD_LOG_ERR(("Cannot open %s", genesis));
    }
    uchar * buf = malloc((ulong) sbuf.st_size);
    ssize_t n = read(fd, buf, (ulong) sbuf.st_size);
    close(fd);

    fd_genesis_solana_new(&state.global->genesis_block);
    fd_bincode_decode_ctx_t ctx;
    ctx.data = buf;
    ctx.dataend = &buf[n];
    ctx.allocf = state.global->allocf;
    ctx.allocf_arg = state.global->allocf_arg;
    if ( fd_genesis_solana_decode(&state.global->genesis_block, &ctx) )
      FD_LOG_ERR(("fd_genesis_solana_decode failed"));

    // The hash is generated from the raw data... don't mess with this..
    fd_sha256_t sha;
    fd_sha256_init( &sha );
    fd_sha256_append( &sha, buf, (ulong) n );
    fd_sha256_fini( &sha, state.global->genesis_hash );

    free(buf);
  }

  if (strcmp(state.cmd, "accounts_hash") != 0) {
    FD_LOG_WARNING(("loading genesis account into funk db"));

    fd_funk_rec_t * rec_map = fd_funk_rec_map( state.global->funk, state.global->wksp );

    for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
         !fd_funk_rec_map_iter_done( rec_map, iter );
         iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
      fd_funk_rec_t * trec = fd_funk_rec_map_iter_ele( rec_map, iter );

      fd_funk_rec_key_t *k = trec->pair.key;

      if (!fd_acc_mgr_is_key(k))
        continue;

      if (fd_funk_rec_persist_erase(state.global->funk, trec) != FD_FUNK_SUCCESS)
        FD_LOG_WARNING(("persist erase failed"));

      if (fd_funk_rec_remove(state.global->funk, trec, 1) != FD_FUNK_SUCCESS)
        FD_LOG_WARNING(("remove failed"));
    }

    for (ulong i = 0; i < state.global->genesis_block.accounts_len; i++) {
      fd_pubkey_account_pair_t *a = &state.global->genesis_block.accounts[i];

      char pubkey[50];

      fd_base58_encode_32((uchar *) state.global->genesis_block.accounts[i].key.key, NULL, pubkey);

      fd_acc_mgr_write_structured_account(state.global->acc_mgr, state.global->funk_txn, 0, &a->key, &a->account);
    }
  }

  for (ulong i = 0; i < state.global->genesis_block.native_instruction_processors_len; i++) {
    fd_string_pubkey_pair_t * ins = &state.global->genesis_block.native_instruction_processors[i];

    char pubkey[50];

    fd_base58_encode_32((uchar *) ins->pubkey.key, NULL, pubkey);

    FD_LOG_WARNING(("native program:  %s <= %s", ins->string, pubkey));
  }

  if (strcmp(state.cmd, "replay") == 0) {
    replay(&state);

    if (NULL != confirm_hash) {
      uchar h[32];
      fd_base58_decode_32( confirm_hash,  h);
      FD_TEST(memcmp(h, state.global->banks_hash.uc, sizeof(h)) == 0);
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
      FD_TEST(memcmp(h, state.global->block_hash, sizeof(h)) == 0);
    }

  }
  if (strcmp(state.cmd, "accounts_hash") == 0)
    accounts_hash(&state);
  if (strcmp(state.cmd, "accounts") == 0)
    slot_dump(&state);

  fd_global_ctx_delete(fd_global_ctx_leave(state.global));

  if( state.name )
    fd_wksp_detach( state.global->wksp );
  else
    fd_wksp_delete_anonymous( state.global->wksp );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
