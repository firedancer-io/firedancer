#include "fd_backtest_rocksdb.h"

#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/types/fd_types.h"

#ifdef FD_HAS_ROCKSDB
#include <rocksdb/c.h>
#else
#include "../../../opt/include/rocksdb/c.h"
#endif

struct fd_backtest_rocksdb_private {
  rocksdb_t * db;

  rocksdb_readoptions_t * readoptions;

  rocksdb_iterator_t * iter_root;

  rocksdb_column_family_handle_t * cfs[ 5 ];

  ulong magic;
};

FD_FN_CONST ulong
fd_backtest_rocksdb_align( void ) {
  return alignof(fd_backtest_rocksdb_t);
}

FD_FN_CONST ulong
fd_backtest_rocksdb_footprint( void ) {
  return sizeof(fd_backtest_rocksdb_t);
}

void *
fd_backtest_rocksdb_new( void *       shmem,
                         char const * path ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_backtest_rocksdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_backtest_rocksdb_t * db = (fd_backtest_rocksdb_t *)shmem;

  char const * cf_names[ 5 ] = {
    "default",
    "root",
    "meta",
    "data_shred",
    "bank_hashes",
  };

  rocksdb_options_t * options = rocksdb_options_create();

  rocksdb_options_t const * cf_options[ 5 ] = {
    options,
    options,
    options,
    options,
    options,
  };

  char * err = NULL;
  db->db = rocksdb_open_for_read_only_column_families(
    options,
    path,
    5,
    cf_names,
    cf_options,
    db->cfs,
    false,
    &err );
  FD_TEST( !err );
  FD_TEST( db->db );

  db->readoptions = rocksdb_readoptions_create();

  db->iter_root = rocksdb_create_iterator_cf( db->db, db->readoptions, db->cfs[ 1 ] );
  FD_TEST( db->iter_root );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( db->magic ) = FD_BACKTEST_ROCKSDB_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)db;
}

fd_backtest_rocksdb_t *
fd_backtest_rocksdb_join( void * shdb ) {
  if( FD_UNLIKELY( !shdb ) ) {
    FD_LOG_WARNING(( "NULL shdb" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shdb, fd_backtest_rocksdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shdb" ));
    return NULL;
  }

  fd_backtest_rocksdb_t * db = (fd_backtest_rocksdb_t *)shdb;

  if( FD_UNLIKELY( db->magic!=FD_BACKTEST_ROCKSDB_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return db;
}

void
fd_backtest_rocksdb_init( fd_backtest_rocksdb_t * db,
                          ulong                   root_slot ) {
  ulong key = fd_ulong_bswap( root_slot );

  rocksdb_iter_seek( db->iter_root, (char const *)&key, sizeof(ulong) );
  FD_TEST( rocksdb_iter_valid( db->iter_root ) );
}

int
fd_backtest_rocksdb_next_root_slot( fd_backtest_rocksdb_t * db,
                                    ulong *                 root_slot,
                                    ulong *                 shred_cnt ) {
  rocksdb_iter_next( db->iter_root );
  if( FD_UNLIKELY( !rocksdb_iter_valid(db->iter_root) ) ) return 0;

  ulong keylen;
  char const * key = rocksdb_iter_key( db->iter_root, &keylen );

  ulong vallen;
  char * err = NULL;
  char * slot_meta = rocksdb_get_cf( db->db, db->readoptions, db->cfs[ 2 ], key, keylen, &vallen, &err );
  FD_TEST( !err );

  fd_bincode_decode_ctx_t ctx = {
    .data    = slot_meta,
    .dataend = slot_meta+vallen,
  };

  ulong total_sz = 0UL;
  FD_TEST( !fd_slot_meta_decode_footprint( &ctx, &total_sz ) );

  void * mem = fd_alloca_check( FD_SLOT_META_ALIGN, total_sz );
  fd_slot_meta_t const * meta = fd_slot_meta_decode( mem, &ctx );

  *root_slot = meta->slot;
  *shred_cnt = meta->received;

  return 1;
}

void const *
fd_backtest_rocksdb_shred( fd_backtest_rocksdb_t * db,
                           ulong                   slot,
                           ulong                   shred_idx ) {
  char key[ 16UL ];
  FD_STORE( ulong, key, fd_ulong_bswap( slot ) );
  FD_STORE( ulong, key+8UL, fd_ulong_bswap( shred_idx ) );

  ulong vallen;
  char * err = NULL;
  char const * shred = rocksdb_get_cf( db->db, db->readoptions, db->cfs[ 3 ], key, 16UL, &vallen, &err );
  FD_TEST( !err );
  FD_TEST( vallen<=FD_SHRED_MAX_SZ );
  FD_TEST( fd_shred_parse( (uchar const*)shred, vallen ) );

  return shred;
}

uchar const *
fd_backtest_rocksdb_bank_hash( fd_backtest_rocksdb_t * db,
                               ulong                   slot ) {
  char key[ 8UL ];
  FD_STORE( ulong, key, fd_ulong_bswap( slot ) );

  ulong vallen;
  char * err = NULL;
  char const * frozen_hash = rocksdb_get_cf( db->db, db->readoptions, db->cfs[ 4 ], key, 8UL, &vallen, &err );
  FD_TEST( !err );

  fd_bincode_decode_ctx_t decode = {
    .data    = frozen_hash,
    .dataend = frozen_hash+vallen,
  };

  ulong total_sz = 0UL;
  FD_TEST( !fd_frozen_hash_versioned_decode_footprint( &decode, &total_sz ) );

  void * mem = fd_alloca_check( FD_FROZEN_HASH_VERSIONED_ALIGN, total_sz );
  fd_frozen_hash_versioned_t const * fhv = fd_frozen_hash_versioned_decode( mem, &decode );
  return fhv->inner.current.frozen_hash.uc;
}
