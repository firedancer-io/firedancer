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

//#define _VALGRIND

#ifdef _VALGRIND
char* allocf(unsigned long len, FD_FN_UNUSED unsigned long align, FD_FN_UNUSED void* arg) {
  return malloc(len);
}

void freef(void *ptr, FD_FN_UNUSED void* arg) {
  free(ptr);
}
#else

char* allocf(unsigned long len, unsigned long align, void* arg) {
  if (NULL == arg) {
    FD_LOG_ERR(( "yo dawg.. you passed a NULL as a fd_alloc pool"));
  }

  char *ret = fd_alloc_malloc(arg, align, len);
//  FD_LOG_NOTICE(( "0x%lx  0x%lx  allocf(len:%ld, align:%ld)", (ulong) ret, (ulong) arg,  len, align));
  return ret;
}

void freef(void *ptr, void* arg) {
//  FD_LOG_NOTICE(( "0x%lx  0x%lx  free()", (ulong) ptr, (ulong) arg));

  if (NULL == arg) {
    FD_LOG_ERR(( "yo dawg.. you passed a NULL as a fd_alloc pool"));
  }

  fd_alloc_free(arg, ptr);
}
#endif

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --wksp       <name>       workspace name\n");
  fprintf(stderr, " --ledger     <dir>        ledger directory\n");
  fprintf(stderr, " --db         <file>       firedancer db file\n");
  fprintf(stderr, " --end-slot   <num>        stop iterating at block...\n");
  fprintf(stderr, " --start-slot <num>        start iterating at block...\n");
}

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  ulong end_slot = 73;
  ulong start_slot = 0;

  char const * name           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",       NULL, NULL );
  char const * ledger         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--ledger",     NULL, NULL);
  char const * db             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--db",         NULL, NULL);
  char const * end_slot_opt   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--end-slot",   NULL, NULL);
  char const * start_slot_opt = fd_env_strip_cmdline_cstr ( &argc, &argv, "--start-slot", NULL, NULL);

  if ((NULL == ledger) || (NULL == db)) {
    usage(argv[0]);
    exit(1);
  }

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );
  } 

  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  void * shmem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 0 );

  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "Unable to allocate wksp memory for fd_alloc" ));

  void * shalloc = fd_alloc_new ( shmem, 0 ); 

  fd_alloc_t * alloc = fd_alloc_join( shalloc, 0UL );

  void * fd_funk_raw = fd_alloc_malloc(alloc, fd_funk_align(), fd_funk_footprint_min());
  fd_funk_t* funk = fd_funk_join(fd_funk_new(fd_funk_raw, fd_funk_footprint_min(), db));
  fd_funk_validate(funk);

  if (NULL != end_slot_opt) {
    end_slot = (ulong) atoi(end_slot_opt);
  }
  if (NULL != start_slot_opt) {
    start_slot = (ulong) atoi(start_slot_opt);
  }

  // Eventually we will have to add support for reading compressed genesis blocks...
  char genesis[128];
  sprintf(genesis, "%s/genesis.bin", ledger);

  char db_name[128];
  sprintf(db_name, "%s/rocksdb", ledger);

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
  fd_genesis_solana_decode(&gen, ( void const** )&data, dataend, allocf, alloc);

  // Jam all the accounts into the database....  (gen.accounts)

  /* Initialize the account manager */
  struct fd_funk_xactionid const* xroot = fd_funk_root(funk);

  void *fd_acc_mgr_raw = malloc(FD_ACC_MGR_FOOTPRINT);
  fd_acc_mgr_t* acc_mgr = fd_acc_mgr_join(fd_acc_mgr_new(fd_acc_mgr_raw, funk, xroot, FD_ACC_MGR_FOOTPRINT));

  FD_LOG_INFO(("loading genesis account into funk db"));

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

    if (fd_acc_mgr_write_account(acc_mgr, &a->key, dbuf, dlen) != FD_ACC_MGR_SUCCESS) {
      FD_LOG_ERR(("write account failed"));
    }
  }

  // Clean up a little...
  if (NULL != dbuf)  {
    free(dbuf);
    dbuf = NULL;
  }

  fd_genesis_solana_destroy(&gen, freef, alloc);

  //  we good?
  FD_LOG_INFO(("validating funk db"));
  fd_funk_validate(funk);

  // Initialize the rocksdb 
  fd_rocksdb_t rocks_db;
  char *err = fd_rocksdb_init(&rocks_db, db_name);

  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_init returned %s", err));
  }

  ulong last_slot = fd_rocksdb_last_slot(&rocks_db, &err);
  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_last_slot returned %s", err));
  }

  if (end_slot > last_slot) {
    end_slot = last_slot;
    FD_LOG_INFO(("setting the end_slot to %ld since that is the last slot we see in the rocksdb", end_slot));
  }

  ulong first_slot = fd_rocksdb_first_slot(&rocks_db, &err);
  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_first_slot returned %s", err));
  }

  if (start_slot < first_slot) {
    start_slot = first_slot;
    FD_LOG_INFO(("setting the start_slot to %ld since that is the first slot we see in the rocksdb", start_slot));
  }

  // Lets start executing!
  void *fd_executor_raw = malloc(FD_EXECUTOR_FOOTPRINT);
  fd_executor_t* executor = fd_executor_join(fd_executor_new(fd_executor_raw, acc_mgr, FD_EXECUTOR_FOOTPRINT));

  for (ulong slot = start_slot; slot < end_slot; slot++) {
    fd_slot_meta_t m;
    fd_memset(&m, 0, sizeof(m));
    fd_rocksdb_get_meta(&rocks_db, slot, &m, allocf, alloc, &err);
    if (err != NULL) {
      FD_LOG_ERR(("fd_rocksdb_last_slot returned %s", err));
    }

    fd_slot_blocks_t *slot_data = fd_rocksdb_get_microblocks(&rocks_db, &m, allocf, alloc);
    FD_LOG_INFO(("fd_rocksdb_get_microblocks got %d microblocks", slot_data->block_cnt));

    // free 
    fd_slot_meta_destroy(&m, freef, alloc);

    // execute slot_block...
    FD_LOG_INFO(("executing micro blocks... profit"));

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
    // free the slot data...
    fd_slot_blocks_destroy(slot_data, freef, alloc);
    freef(slot_data, alloc);
  }

  fd_executor_delete(fd_executor_leave(executor));
  free(fd_executor_raw);

  fd_acc_mgr_delete(fd_acc_mgr_leave(acc_mgr));
  free(fd_acc_mgr_raw);

  // The memory management model is odd...  how do I know how to destroy this
  fd_rocksdb_destroy(&rocks_db);

  fd_funk_delete(fd_funk_leave(funk));

  fd_alloc_free(alloc, fd_funk_raw);

  free(buf);

  fd_wksp_free_laddr( shmem );
  if( name ) 
    fd_wksp_detach( wksp );
  else  
    fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
