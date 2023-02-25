//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd replay --start-slot 179138205 --end-slot 279138205  --skip-exe true
//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd injest --start-slot 179138205 --end-slot 279138205 --manifest /dev/shm/mainnet-ledger/snapshot/tmp-snapshot-archive-JfVTLu/snapshots/179248368/179248368

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "fd_rocksdb.h"
#include "fd_banks_solana.h"
#include "fd_executor.h"
#include "../../funk/fd_funk.h"
#include "../../util/alloc/fd_alloc.h"

bool do_valgrind = true;

char* allocf(unsigned long len, FD_FN_UNUSED unsigned long align, FD_FN_UNUSED void* arg) {
  if (NULL == arg) {
    FD_LOG_ERR(( "yo dawg.. you passed a NULL as a fd_alloc pool"));
  }

  if (do_valgrind) {
    char * ptr = malloc(sizeof(char *) + len + align);
    char * ret = (char *) fd_ulong_align_up( (ulong) (ptr + sizeof(char *)), align );
    *((char **)(ret - sizeof(char *))) = ptr;
    return ret;
  } else 
    return fd_alloc_malloc(arg, align, len);
}

void freef(void *ptr, FD_FN_UNUSED void* arg) {
  if (NULL == arg) {
    FD_LOG_ERR(( "yo dawg.. you passed a NULL as a fd_alloc pool"));
  }

  if (do_valgrind) 
    free(*((char **)((char *) ptr - sizeof(char *))));
  else
    fd_alloc_free(arg, ptr);
}

struct global_state {
  ulong        end_slot;
  ulong        start_slot;
  bool         skip_exe;

  char const * name;
  char const * ledger;
  char const * db;
  char const * end_slot_opt;
  char const * start_slot_opt;
  char const * manifest;
  char const * accounts;
  char const * cmd;
  char const * skip_exe_opt;

  fd_wksp_t *  wksp;
  fd_alloc_t * alloc;
  fd_funk_t*   funk;
  fd_acc_mgr_t* acc_mgr;
  fd_rocksdb_t rocks_db;
};
typedef struct global_state global_state_t;

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --wksp       <name>       workspace name\n");
  fprintf(stderr, " --ledger     <dir>        ledger directory\n");
  fprintf(stderr, " --db         <file>       firedancer db file\n");
  fprintf(stderr, " --end-slot   <num>        stop iterating at block...\n");
  fprintf(stderr, " --start-slot <num>        start iterating at block...\n");
  fprintf(stderr, " --manifest   <file>       What manifest file should I pay attention to\n");
  fprintf(stderr, " --accounts   <dir>        What accounts should I slurp in\n");
  fprintf(stderr, " --cmd        <operation>  What operation should we test\n");
  fprintf(stderr, " --skip-exe   <bool>       Should we skip executing transactions\n");
}

int manifest(global_state_t *state) {
  struct stat s;
  stat(state->manifest,  &s);

  FD_LOG_WARNING(("reading manifest: %s", state->manifest));

  unsigned char *b = (unsigned char *)allocf((unsigned long) (unsigned long) s.st_size, 1, state->alloc);
  int fd = open(state->manifest, O_RDONLY);
  ssize_t n = read(fd, b, (unsigned long) s.st_size);

  FD_TEST(n == s.st_size);
  unsigned char *outend = &b[n];
  const void * o = b;

  FD_LOG_WARNING(("deserializing version bank"));

  struct fd_deserializable_versioned_bank a;
  memset(&a, 0, sizeof(a));
  fd_deserializable_versioned_bank_decode(&a, &o, outend, allocf, state->alloc);


  FD_LOG_WARNING(("deserializing accounts"));
  struct fd_solana_accounts_db_fields db;
  memset(&db, 0, sizeof(b));
  fd_solana_accounts_db_fields_decode(&db, &o, outend, allocf, state->alloc);

  FD_LOG_WARNING(("cleaning up"));

  fd_deserializable_versioned_bank_destroy(&a, freef, state->alloc);
  fd_solana_accounts_db_fields_destroy(&db, freef, state->alloc);
  freef(b, state->alloc);

  return 0;
}

int replay(global_state_t *state) {
  // Lets start executing!
  void *fd_executor_raw = malloc(FD_EXECUTOR_FOOTPRINT);
  fd_executor_t* executor = fd_executor_join(fd_executor_new(fd_executor_raw, state->acc_mgr, FD_EXECUTOR_FOOTPRINT));
  char *err = NULL;

  for (ulong slot = state->start_slot; slot < state->end_slot; slot++) {
    FD_LOG_WARNING(("reading slot %ld", slot));
//    fd_log_flush();

    fd_slot_meta_t m;
    fd_memset(&m, 0, sizeof(m));
    err = NULL;
    fd_rocksdb_get_meta(&state->rocks_db, slot, &m, allocf, state->alloc, &err);
    if (err != NULL) {
      FD_LOG_WARNING(("fd_rocksdb_last_slot returned %s", err));
      free (err);
      continue;
    }

    fd_slot_blocks_t *slot_data = fd_rocksdb_get_microblocks(&state->rocks_db, &m, allocf, state->alloc);

    // free 
    fd_slot_meta_destroy(&m, freef, state->alloc);

    if (NULL == slot_data) {
      FD_LOG_WARNING(("fd_rocksdb_get_microblocks returned NULL for slot %ld", slot));
      continue;
    }

    if (!state->skip_exe) {
      // execute slot_block...
      uchar *blob = slot_data->first_blob;
      while (NULL != blob) {
        uchar *blob_ptr = blob + FD_BLOB_DATA_START;
        uint cnt = *((uint *) (blob + 8));
        while (cnt > 0) {
          fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );

          for ( ulong txn_idx = 0; txn_idx < micro_block->txn_max_cnt; txn_idx++ ) {
            fd_txn_t* txn_descriptor = (fd_txn_t *)&micro_block->txn_tbl[ txn_idx ];
            fd_rawtxn_b_t* txn_raw   = (fd_rawtxn_b_t *)&micro_block->raw_tbl[ txn_idx ];
            fd_execute_txn( executor, txn_descriptor, txn_raw );
          }      
          fd_microblock_leave(micro_block);

          blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);
        
          cnt--;
        }
        blob = *((uchar **) blob);
      }
    }
    // free the slot data...
    fd_slot_blocks_destroy(slot_data, freef, state->alloc);
    freef(slot_data, state->alloc);
  }

  fd_executor_delete(fd_executor_leave(executor));
  free(fd_executor_raw);

  return 0;
}

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  global_state_t state;
  fd_memset(&state, 0, sizeof(state));

  state.end_slot = 73;
  state.start_slot = 0;

  state.name           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",         NULL, NULL );
  state.ledger         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--ledger",       NULL, NULL);
  state.db             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--db",           NULL, NULL);
  state.end_slot_opt   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--end-slot",     NULL, NULL);
  state.start_slot_opt = fd_env_strip_cmdline_cstr ( &argc, &argv, "--start-slot",   NULL, NULL);
  state.manifest       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--manifest",     NULL, NULL);
  state.accounts       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--account",      NULL, NULL);
  state.cmd            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",          NULL, NULL);
  state.skip_exe_opt   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--skip-exe",     NULL, NULL);

  if ((NULL == state.ledger) || (NULL == state.db)) {
    usage(argv[0]);
    exit(1);
  }

  if (state.skip_exe_opt) {
    state.skip_exe = !strcmp(state.skip_exe_opt, "true");
  }

  if( state.name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", state.name ));
    state.wksp = fd_wksp_attach( state.name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    state.wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );
  } 

  if( FD_UNLIKELY( !state.wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  void * shmem = fd_wksp_alloc_laddr( state.wksp, fd_alloc_align(), fd_alloc_footprint(), 1 );

  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "Unable to allocate wksp memory for fd_alloc" ));

  void * shalloc = fd_alloc_new ( shmem, 1 ); 

  state.alloc = fd_alloc_join( shalloc, 0UL );

  void * fd_funk_raw = fd_alloc_malloc(state.alloc, fd_funk_align(), fd_funk_footprint_min());
  state.funk = fd_funk_join(fd_funk_new(fd_funk_raw, fd_funk_footprint_min(), state.db));
  // fd_funk_validate(state.funk);

  if (NULL != state.end_slot_opt) {
    state.end_slot = (ulong) atoi(state.end_slot_opt);
  }
  if (NULL != state.start_slot_opt) {
    state.start_slot = (ulong) atoi(state.start_slot_opt);
  }

  // Eventually we will have to add support for reading compressed genesis blocks...
  char genesis[128];
  sprintf(genesis, "%s/genesis.bin", state.ledger);

  char db_name[128];
  sprintf(db_name, "%s/rocksdb", state.ledger);

  struct stat sbuf;
  stat(genesis, &sbuf);
  int fd = open(genesis, O_RDONLY);
  uchar *buf = malloc((ulong) sbuf.st_size);
  ssize_t n = read(fd, buf, (ulong) sbuf.st_size);
  close(fd);
    
  void *data = buf;
  void *dataend = &buf[n];
  fd_genesis_solana_t gen;
  fd_memset(&gen, 0, sizeof(gen));
  fd_genesis_solana_decode(&gen, ( void const** )&data, dataend, allocf, state.alloc);

  // Jam all the accounts into the database....  (gen.accounts)

  /* Initialize the account manager */
  struct fd_funk_xactionid const* xroot = fd_funk_root(state.funk);

  void *fd_acc_mgr_raw = malloc(FD_ACC_MGR_FOOTPRINT);
  state.acc_mgr = fd_acc_mgr_join(fd_acc_mgr_new(fd_acc_mgr_raw, state.funk, xroot, FD_ACC_MGR_FOOTPRINT));

  FD_LOG_WARNING(("loading genesis account into funk db"));

  uchar *dbuf = NULL;
  ulong datalen = 0;

  for (ulong i = 0; i < gen.accounts_len; i++) {
    fd_pubkey_account_pair_t *a = &gen.accounts[i];

    // Here be dragons and the subject of debate

    // Lets have another 2 hour debate over fd_account_meta_t... 
    ulong dlen =  sizeof(fd_account_meta_t) + a->account.data_len;
    if (dlen > datalen) {
      if (NULL != data) 
        free(dbuf);
      datalen = dlen;
      dbuf = malloc(datalen);
    }

    // Lets set some values...
    //  (Obviously this will get factored out)
    fd_account_meta_t *m = (fd_account_meta_t *) dbuf;
    m->info.lamports = a->account.lamports;
    m->info.rent_epoch = a->account.rent_epoch;
    memcpy(m->info.owner, a->account.owner.key, sizeof(a->account.owner.key));
    m->info.executable = (char) a->account.executable;
    fd_memset(m->info.padding, 0, sizeof(m->info.padding));

    // What is the correct hash function we should be using?
    fd_memset(m->hash.value, 0, sizeof(m->hash.value));

    fd_memcpy(&dbuf[sizeof(fd_account_meta_t)], a->account.data, a->account.data_len);

    if (fd_acc_mgr_write_account(state.acc_mgr, &a->key, dbuf, dlen) != FD_ACC_MGR_SUCCESS) {
      FD_LOG_ERR(("write account failed"));
    }
  }

  // Clean up a little...
  if (NULL != dbuf)  {
    free(dbuf);
    dbuf = NULL;
  }

  fd_genesis_solana_destroy(&gen, freef, state.alloc);

  //  we good?
//  FD_LOG_WARNING(("validating funk db"));
//  fd_funk_validate(state.funk);

  // Initialize the rocksdb 
  char *err = fd_rocksdb_init(&state.rocks_db, db_name);

  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_init returned %s", err));
  }

  ulong last_slot = fd_rocksdb_last_slot(&state.rocks_db, &err);
  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_last_slot returned %s", err));
  }

  if (state.end_slot > last_slot) {
    state.end_slot = last_slot;
    FD_LOG_WARNING(("setting the end_slot to %ld since that is the last slot we see in the rocksdb", state.end_slot));
  }

  ulong first_slot = fd_rocksdb_first_slot(&state.rocks_db, &err);
  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_first_slot returned %s", err));
  }

  if (state.start_slot < first_slot) {
    state.start_slot = first_slot;
    FD_LOG_WARNING(("setting the start_slot to %ld since that is the first slot we see in the rocksdb", state.start_slot));
  }

  if (strcmp(state.cmd, "replay") == 0)
    replay(&state);
  if (strcmp(state.cmd, "manifest") == 0)
    manifest(&state);

  fd_acc_mgr_delete(fd_acc_mgr_leave(state.acc_mgr));
  free(fd_acc_mgr_raw);

  // The memory management model is odd...  how do I know how to destroy this
  fd_rocksdb_destroy(&state.rocks_db);

  fd_funk_delete(fd_funk_leave(state.funk));

  fd_alloc_free(state.alloc, fd_funk_raw);

  free(buf);

  fd_wksp_free_laddr( shmem );
  if( state.name ) 
    fd_wksp_detach( state.wksp );
  else  
    fd_wksp_delete_anonymous( state.wksp );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
