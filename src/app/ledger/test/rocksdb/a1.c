// git clone https://github.com/facebook/rocksdb.git
// cd rocksdb
// make static_lib -j10
//
// back to this directory
// make

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rocksdb/c.h>

int main()
{
    const char *db_name = "/home/jsiegel/repos/solana/test-ledger/rocksdb";
    rocksdb_options_t *opts = rocksdb_options_create();
//    rocksdb_options_set_create_if_missing(opts, 1);
//    rocksdb_options_set_error_if_exists(opts, 1);
//    rocksdb_options_set_compression(opts, rocksdb_snappy_compression);
    char *err = NULL;

    size_t lencf = 0;
    char **cf = rocksdb_list_column_families(opts, db_name, &lencf, &err);

    const char *cfs[] = {"default", "meta"};
    const rocksdb_options_t *cf_options[] = {opts, opts};

    rocksdb_column_family_handle_t* column_family_handles = NULL;

    rocksdb_t *db = rocksdb_open_for_read_only_column_families(
      opts, db_name, 1, 
        (const char * const *) &cfs, 
        (const rocksdb_options_t * const*) cf_options,
        &column_family_handles, 
        false, &err);

    if (err != NULL) {
        fprintf(stderr, "database open %s\n", err);
        return -1;
    }

    rocksdb_writeoptions_t *wo = rocksdb_writeoptions_create();
    char *key = "name";
    char *value = "foo";
    rocksdb_put(db, wo, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "put key %s\n", err);
        rocksdb_close(db);
        return -1;
    }
    free(err);
    err = NULL;

    rocksdb_readoptions_t *ro = rocksdb_readoptions_create();
    size_t rlen;
    value = rocksdb_get(db, ro, key, strlen(key), &rlen, &err);
    if (err != NULL) {
        fprintf(stderr, "get key %s\n", err);
        rocksdb_close(db);
        return -1;
    }
    free(err);
    err = NULL;
    printf("get key len: %lu, value: %s\n", rlen, value);

    rocksdb_close(db);
    return 0;
}
