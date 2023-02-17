// git clone https://github.com/facebook/rocksdb.git
// cd rocksdb
// make static_lib -j10
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "fd_rocksdb.h"
#include "fd_banks_solana.h"
#include "../../funk/fd_funk.h"

char* allocf(unsigned long len, FD_FN_UNUSED unsigned long align, FD_FN_UNUSED void* arg) {
  return malloc(len);
}

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --ledger   <dir>        ledger directory\n");
  fprintf(stderr, " --db       <file>       firedancer db file\n");
  fprintf(stderr, " --end-slot <num>        stop iterating at block...\n");
}

int main(int argc, char **argv) {
  ulong end_slot = 73;

  const char* ledger = fd_env_strip_cmdline_cstr(&argc, &argv, "--ledger", NULL, NULL);
  const char* db = fd_env_strip_cmdline_cstr(&argc, &argv, "--db", NULL, NULL);
  if ((NULL == ledger) || (NULL == db)) {
    usage(argv[0]);
    exit(1);
  }

  ulong footprint = fd_funk_footprint_min();
  void * fd_funk_raw = malloc(footprint);
  fd_funk_t* funk = fd_funk_join(fd_funk_new(fd_funk_raw, footprint, db));
  fd_funk_validate(funk);

  const char* end_slot_opt = fd_env_strip_cmdline_cstr(&argc, &argv, "--end-slot", NULL, NULL);
  if (NULL != end_slot_opt) {
    end_slot = (ulong) atoi(end_slot_opt);
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
  fd_genesis_solana_decode(&gen, ( void const** )&data, dataend, allocf, NULL);

  // Jam all the accounts into the database....  (gen.accounts)

  struct fd_funk_xactionid const* xroot = fd_funk_root(funk);

  FD_LOG_INFO(("loading genesis account into funk db"));

  for (ulong i = 0; i < gen.accounts_len; i++) {
    fd_pubkey_account_pair_t *a = &gen.accounts[i];

    // Here be dragons and the subject of debate

    // My key is the pubkey of the account.. today.. we need a
    // convenience function to create account keys from pubkeys so
    // that we can debate this later... 
    struct fd_funk_recordid _id;
    fd_memset(&_id, 0, sizeof(_id));
    fd_memcpy(_id.id, a->key.key, sizeof(a->key));

    // Lets have another 2 hour debate over fd_account_meta_t... 
    ulong datalen =  sizeof(fd_account_meta_t) + a->account.data_len;
    uchar *data = malloc(datalen);

    // Lets set some values...
    fd_account_meta_t *m = (fd_account_meta_t *) data;
    m->info.lamports = a->account.lamports;
    m->info.rent_epoch = a->account.rent_epoch;
    memcpy(m->info.owner, a->account.owner.key, sizeof(a->account.owner.key));
    m->info.executable = (char) a->account.executable;
    fd_memset(m->info.padding, 0, sizeof(m->info.padding));

    // What is the correct hash function?
    fd_memset(m->hash.value, 0, sizeof(m->hash.value));

    fd_memcpy(&data[sizeof(fd_account_meta_t)], a->account.data, a->account.data_len);

    if (fd_funk_write(funk, xroot, &_id, data, 0, datalen) != (long)datalen) {
      FD_LOG_ERR(("write failed"));
    }
  }

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

  if (end_slot > last_slot) 
    end_slot = last_slot;

  // Lets start executing!
  for (ulong slot = 0; slot < end_slot; slot++) {
    fd_slot_meta_t m;
    fd_memset(&m, 0, sizeof(m));
    fd_rocksdb_get_meta(&rocks_db, slot, &m, allocf, &err);
    if (err != NULL) {
      FD_LOG_ERR(("fd_rocksdb_last_slot returned %s", err));
    }

    fd_slot_blocks_t *slot_data = fd_rocksdb_get_microblocks(&rocks_db, &m);
    FD_LOG_INFO(("fd_rocksdb_get_microblocks got %d microblocks", slot_data->block_cnt));

    // execute slot_block...
    FD_LOG_INFO(("executing micro blocks"));

    // free the slot data...
    free(slot_data);
  }

  // The memory management model is odd...  how do I know how to destroy this
  fd_rocksdb_destroy(&rocks_db);

  return 0;
}
