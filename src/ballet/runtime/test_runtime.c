// test_xdp.init

//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd replay --start-slot 179138205 --end-slot 279138205  --skip-exe true
//  --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd ingest --start-slot 179138205 --end-slot 279138205 --manifest /dev/shm/mainnet-ledger/snapshot/tmp-snapshot-archive-JfVTLu/snapshots/179248368/179248368
// run --ledger /home/jsiegel/mainnet-ledger --db /home/jsiegel/funk --cmd ingest --accounts /home/jsiegel/mainnet-ledger/accounts --pages 50 --index-max 120000000
// run --ledger /dev/shm/mainnet-ledger --db /dev/shm/funk --cmd ingest --accounts /dev/shm/mainnet-ledger/accounts --pages 50 --index-max 120000000

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
#include "fd_executor.h"
#include "../../funk/fd_funk.h"
#include "../../util/alloc/fd_alloc.h"
#include "../base58/fd_base58.h"

#include <dirent.h>

uchar do_valgrind = 1;

int fd_alloc_fprintf( fd_alloc_t * join, FILE *       stream );

char* allocf(unsigned long len, FD_FN_UNUSED unsigned long align, FD_FN_UNUSED void* arg) {
  if (NULL == arg) {
    FD_LOG_ERR(( "yo dawg.. you passed a NULL as a fd_alloc pool"));
  }

  if (do_valgrind) {
    char * ptr = malloc(fd_ulong_align_up(sizeof(char *) + len, align));
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
  ulong        pages;
  uchar        skip_exe;

  int          argc;
  char       **argv;

  char const * name;
  char const * ledger;
  char const * db;
  char const * end_slot_opt;
  char const * start_slot_opt;
  char const * manifest;
  char const * accounts;
  char const * cmd;
  char const * skip_exe_opt;
  char const * pages_opt;

  fd_wksp_t *  wksp;
  fd_alloc_t * alloc;
  fd_funk_t*   funk;
  fd_acc_mgr_t* acc_mgr;
  fd_rocksdb_t rocks_db;
  fd_genesis_solana_t gen;
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

// pub const FULL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz|tar\.lz4)$";
// pub const INCREMENTAL_SNAPSHOT_ARCHIVE_FILENAME_REGEX: &str = r"^incremental-snapshot-(?P<base>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar|tar\.bz2|tar\.zst|tar\.gz|tar\.lz4)$";

int ingest(global_state_t *state) {
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
  uchar sprog[32];
  fd_memset(sprog, 0, sizeof(sprog));

  ulong files = 0;
  ulong accounts = 0;
  ulong odd = 0;

  while ( NULL != (ent = readdir(dir)) ) {
    if ( regexec(&reg, ent->d_name, 0, NULL, 0) == 0 )  {
        struct stat s;
        char buf[1000];

        strcpy(buf, ent->d_name);
        char *p = buf;
        while (*p != '.') p++; // It sure as heck better have a . or the regexec would fail
        *p = '\0';

        ulong slot = (ulong) atol(buf);

        sprintf(buf, "%s/%s", state->accounts, ent->d_name);
        stat(buf,  &s);
        unsigned char *r = (unsigned char *)allocf((unsigned long) (unsigned long) s.st_size, 8UL, state->alloc);
        unsigned char *b = r;
        files++;
        int fd = open(buf, O_RDONLY);
        ssize_t n = read(fd, b, (unsigned long) s.st_size);
        if (n < 0) {
          FD_LOG_ERR(( "??" ));
        }
        unsigned char *eptr = &b[(ulong) ((ulong)n - (ulong)sizeof(fd_solana_account_hdr_t))];
        if (n != s.st_size) {
          FD_LOG_ERR(( "??" ));
        }

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

          accounts++;

          if ((accounts % 1000000) == 0) {
            FD_LOG_WARNING(("accounts %ld", accounts));
          }

          do {
            fd_account_meta_t metadata;
            int read_result = fd_acc_mgr_get_metadata( state->acc_mgr, (fd_pubkey_t *) &hdr->meta.pubkey, &metadata );
            if ( FD_UNLIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
              if (metadata.slot > slot)
                break;
            }

            if (fd_acc_mgr_write_append_vec_account( state->acc_mgr,  slot, hdr) != FD_ACC_MGR_SUCCESS) {
              FD_LOG_ERR(("writing failed: accounts %ld", accounts));
            }
            read_result = fd_acc_mgr_get_metadata( state->acc_mgr, (fd_pubkey_t *) &hdr->meta.pubkey, &metadata );
            if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) 
              FD_LOG_ERR(("wtf"));
            if ((metadata.magic != FD_ACCOUNT_META_MAGIC) || (metadata.hlen != sizeof(metadata))) 
              FD_LOG_ERR(("wtf2"));
          } while (0);

#if 0
          if (memcmp(hdr->info.owner, sprog, sizeof(sprog)) != 0) {
            // system progs are exempt no matter their lamports...
            ulong exempt = (hdr->meta.data_len + 128) * ((ulong) ((double)state->gen.rent.lamports_per_uint8_year * state->gen.rent.exemption_threshold));
            if (hdr->info.lamports < exempt) {
              odd++;
              char pubkey[50];
              fd_memset(pubkey, 0, sizeof(pubkey));
              fd_base58_encode_32((uchar *) hdr->meta.pubkey, pubkey);
              char owner[50];
              fd_memset(owner, 0, sizeof(owner));
              fd_base58_encode_32((uchar *) hdr->info.owner, owner);
              printf("file: %s owner: %s pubkey: %s datalen: %ld lamports: %ld  rent_epoch: %ld\n", buf, owner, pubkey, hdr->meta.data_len, hdr->info.lamports, hdr->info.rent_epoch);
            }
          }
#endif
          b += fd_ulong_align_up(hdr->meta.data_len + sizeof(*hdr), 8);
        }

        close(fd);
        freef(r, state->alloc);
    }
  }

  closedir(dir);
  regfree(&reg);

  FD_LOG_WARNING(("files %ld  accounts %ld  odd %ld", files, accounts, odd));

  return 0;
}

int manifest(global_state_t *state) {
  struct stat s;
  stat(state->manifest,  &s);

  FD_LOG_WARNING(("reading manifest: %s", state->manifest));

  unsigned char *b = (unsigned char *)allocf((unsigned long) (unsigned long) s.st_size, 1, state->alloc);
  int fd = open(state->manifest, O_RDONLY);
  ssize_t n = read(fd, b, (unsigned long) s.st_size);
  close(fd);

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

  state.argc = argc;
  state.argv = argv;

  state.end_slot = 73;
  state.start_slot = 0;

  state.name           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",         NULL, NULL );
  state.ledger         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--ledger",       NULL, NULL);
  state.db             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--db",           NULL, NULL);
  state.end_slot_opt   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--end-slot",     NULL, NULL);
  state.start_slot_opt = fd_env_strip_cmdline_cstr ( &argc, &argv, "--start-slot",   NULL, NULL);
  state.manifest       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--manifest",     NULL, NULL);
  state.accounts       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--accounts",     NULL, NULL);
  state.cmd            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",          NULL, NULL);
  state.skip_exe_opt   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--skip-exe",     NULL, NULL);
  state.pages_opt      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pages",        NULL, NULL);
  const char *index_max_opt = fd_env_strip_cmdline_cstr ( &argc, &argv, "--index-max",        NULL, NULL);

  if ((NULL == state.ledger) || (NULL == state.db)) {
    usage(argv[0]);
    exit(1);
  }

  if (state.skip_exe_opt)
    state.skip_exe = !strcmp(state.skip_exe_opt, "true");

  if (state.pages_opt) 
    state.pages = (ulong) atoi(state.pages_opt);
  else
    state.pages = 2;

  if( state.name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", state.name ));
    state.wksp = fd_wksp_attach( state.name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    state.wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, state.pages, 0, "wksp", 0UL );
  } 

  if( FD_UNLIKELY( !state.wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  void * shmem = fd_wksp_alloc_laddr( state.wksp, fd_alloc_align(), fd_alloc_footprint(), 1 );

  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "Unable to allocate wksp memory for fd_alloc" ));

  void * shalloc = fd_alloc_new ( shmem, 1 ); 

  state.alloc = fd_alloc_join( shalloc, 0UL );

  ulong index_max = 1000000;    // Maximum size (count) of master index

  if (index_max_opt) 
    index_max = (ulong) atoi((char *) index_max_opt);

  ulong xactions_max = 100;     // Maximum size (count) of transaction index
  ulong cache_max = 10000;      // Maximum number of cache entries
  state.funk = fd_funk_new(state.db, state.wksp, 2, index_max, xactions_max, cache_max);
  fd_funk_validate(state.funk);

  if (NULL != state.end_slot_opt)
    state.end_slot = (ulong) atoi(state.end_slot_opt);
  if (NULL != state.start_slot_opt) 
    state.start_slot = (ulong) atoi(state.start_slot_opt);

  // Eventually we will have to add support for reading compressed genesis blocks...
  char genesis[128];
  sprintf(genesis, "%s/genesis.bin", state.ledger);

  char db_name[128];
  sprintf(db_name, "%s/rocksdb", state.ledger);

  {
    struct stat sbuf;
    stat(genesis, &sbuf);
    int fd = open(genesis, O_RDONLY);
    if (fd < 0) {
      FD_LOG_ERR(("Cannot open %s", genesis));
    }
    uchar *buf = malloc((ulong) sbuf.st_size);
    ssize_t n = read(fd, buf, (ulong) sbuf.st_size);
    close(fd);
    
    void *data = buf;
    void *dataend = &buf[n];
    fd_memset(&state.gen, 0, sizeof(state.gen));
    fd_genesis_solana_decode(&state.gen, ( void const** )&data, dataend, allocf, state.alloc);

    free(buf);
  }

  // Jam all the accounts into the database....  (gen.accounts)

  /* Initialize the account manager */
  struct fd_funk_xactionid const* xroot = fd_funk_root(state.funk);

  void *fd_acc_mgr_raw = allocf(FD_ACC_MGR_FOOTPRINT, FD_ACC_MGR_ALIGN, state.alloc);
  state.acc_mgr = fd_acc_mgr_join(fd_acc_mgr_new(fd_acc_mgr_raw, state.funk, xroot, FD_ACC_MGR_FOOTPRINT));

  FD_LOG_WARNING(("loading genesis account into funk db"));

  for (ulong i = 0; i < state.gen.accounts_len; i++) {
    fd_pubkey_account_pair_t *a = &state.gen.accounts[i];

    fd_acc_mgr_write_structured_account(state.acc_mgr, 0, &a->key, &a->account);
  }

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
  if (strcmp(state.cmd, "ingest") == 0)
    ingest(&state);

  fd_acc_mgr_delete(fd_acc_mgr_leave(state.acc_mgr));
  freef(fd_acc_mgr_raw, state.alloc);

  fd_genesis_solana_destroy(&state.gen, freef, state.alloc);

  // The memory management model is odd...  how do I know how to destroy this
  fd_rocksdb_destroy(&state.rocks_db);

//  fd_alloc_fprintf( state.alloc, stdout );

//  fd_alloc_free(state.alloc, fd_funk_raw);

  fd_funk_delete(state.funk);

  // ??
  //fd_wksp_tag_free(state.wksp, 2);

  fd_wksp_free_laddr( shmem );

  // dump wksp state

  if( state.name ) 
    fd_wksp_detach( state.wksp );
  else  
    fd_wksp_delete_anonymous( state.wksp );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
