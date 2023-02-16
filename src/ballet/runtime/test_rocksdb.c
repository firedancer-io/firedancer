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

char* allocf(unsigned long len, FD_FN_UNUSED unsigned long align, FD_FN_UNUSED void* arg) {
  return malloc(len);
}

int main() {

    const char *genesis = "/home/jsiegel/repos/solana/test-ledger/genesis.bin";
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

    const char *db_name = "/home/jsiegel/repos/solana/test-ledger/rocksdb";

    fd_rocksdb_t db;
    char *err = fd_rocksdb_init(&db, db_name);

    if (err != NULL) {
      FD_LOG_ERR(("fd_rocksdb_init returned %s", err));
    }

    ulong slot = fd_rocksdb_last_slot(&db, &err);
    if (err != NULL) {
      FD_LOG_ERR(("fd_rocksdb_last_slot returned %s", err));
    }

    fd_slot_meta_t m;
    fd_memset(&m, 0, sizeof(m));
    fd_rocksdb_get_meta(&db, slot, &m, allocf, &err);
    if (err != NULL) {
      FD_LOG_ERR(("fd_rocksdb_last_slot returned %s", err));
    }

    fd_slot_blocks_t *slot_data = fd_rocksdb_get_microblocks(&db, &m);
    FD_LOG_INFO(("fd_rocksdb_get_microblocks got %d microblocks", slot_data->block_cnt));

    // shreds, err := d.GetDataShreds(meta.Slot, 0, uint32(meta.Received), shredRevision)


// ~/repos/radiance/pkg/blockstore/

// func MakeShredKey(slot, index uint64) (key [16]byte) {
// 	binary.BigEndian.PutUint64(key[0:8], slot)
// 	binary.BigEndian.PutUint64(key[8:16], index)
// 	return
// }

// func (d *DB) GetEntries(meta *SlotMeta, shredRevision int) ([]Entries, error) {
// 	shreds, err := d.GetDataShreds(meta.Slot, 0, uint32(meta.Received), shredRevision)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return DataShredsToEntries(meta, shreds)
// }

    fd_rocksdb_destroy(&db);

    return 0;
}
