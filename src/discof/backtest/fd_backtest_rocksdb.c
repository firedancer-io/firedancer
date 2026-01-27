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
  rocksdb_iterator_t * iter_dead;
  rocksdb_iterator_t * iter_shred;

  rocksdb_column_family_handle_t * cfs[ 6 ];

  int ingests_dead_slots;

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
                         char const * path,
                         int          ingests_dead_slots ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_backtest_rocksdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_backtest_rocksdb_t * db = (fd_backtest_rocksdb_t *)shmem;

  char const * cf_names[ 6 ] = {
    "default",
    "root",
    "meta",
    "data_shred",
    "bank_hashes",
    "dead_slots"
  };

  rocksdb_options_t * options = rocksdb_options_create();

  rocksdb_options_t const * cf_options[ 6 ] = {
    options,
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
    6,
    cf_names,
    cf_options,
    db->cfs,
    false,
    &err );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "rocksdb_open_for_read_only_column_families(%s) failed: %s", path, err ));
  FD_TEST( db->db );

  db->readoptions = rocksdb_readoptions_create();

  db->ingests_dead_slots = ingests_dead_slots;
  if( db->ingests_dead_slots )  {
    db->iter_dead = rocksdb_create_iterator_cf( db->db, db->readoptions, db->cfs[ 5 ] );
    FD_TEST( db->iter_dead );
  }

  db->iter_root = rocksdb_create_iterator_cf( db->db, db->readoptions, db->cfs[ 1 ] );
  FD_TEST( db->iter_root );

  db->iter_shred = rocksdb_create_iterator_cf( db->db, db->readoptions, db->cfs[ 3 ] );
  FD_TEST( db->iter_shred );

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

  if( db->ingests_dead_slots ) {
    rocksdb_iter_seek( db->iter_dead, (char const *)&key, sizeof(ulong) );
    FD_TEST( rocksdb_iter_valid( db->iter_dead ) );
  }

  char shred_key[ 16UL ];
  FD_STORE( ulong, shred_key, fd_ulong_bswap( root_slot ) );
  FD_STORE( ulong, shred_key+8UL, 0UL );
  rocksdb_iter_seek( db->iter_shred, shred_key, 16UL );
}

int
fd_backtest_rocksdb_next_slot( fd_backtest_rocksdb_t * db,
                               ulong *                 slot_out,
                               ulong *                 shred_cnt_out,
                               int *                   is_slot_rooted ) {

  FD_TEST( rocksdb_iter_valid( db->iter_root ) );
  rocksdb_iter_next( db->iter_root );
  if( FD_UNLIKELY( !rocksdb_iter_valid(db->iter_root) ) ) return 0;

  ulong keylen;
  char const * key = rocksdb_iter_key( db->iter_root, &keylen );

  ulong vallen;
  char * err = NULL;
  char * slot_meta = rocksdb_get_cf( db->db, db->readoptions, db->cfs[ 2 ], key, keylen, &vallen, &err );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "rocksdb_get_cf(\"meta\",...) failed: %s", err ));

  fd_bincode_decode_ctx_t ctx = {
    .data    = slot_meta,
    .dataend = slot_meta+vallen,
  };

  ulong total_sz = 0UL;
  FD_TEST( !fd_slot_meta_decode_footprint( &ctx, &total_sz ) );

  void * mem = fd_alloca_check( FD_SLOT_META_ALIGN, total_sz );
  fd_slot_meta_t * next_root_meta = fd_slot_meta_decode( mem, &ctx );

  fd_slot_meta_t * next_dead_meta = NULL;
  if( db->ingests_dead_slots ) {
    FD_TEST( rocksdb_iter_valid( db->iter_dead ) );
    rocksdb_iter_next( db->iter_dead );
    if( FD_UNLIKELY( !rocksdb_iter_valid( db->iter_dead ) ) ) return 0;

    ulong keylen;
    char const * key = rocksdb_iter_key( db->iter_dead, &keylen );

    ulong vallen;
    char * err = NULL;
    char * slot_meta = rocksdb_get_cf( db->db, db->readoptions, db->cfs[ 2 ], key, keylen, &vallen, &err );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "rocksdb_get_cf(\"meta\",...) failed: %s", err ));

    fd_bincode_decode_ctx_t ctx = {
      .data    = slot_meta,
      .dataend = slot_meta+vallen,
    };

    ulong total_sz = 0UL;
    FD_TEST( !fd_slot_meta_decode_footprint( &ctx, &total_sz ) );

    void * mem = fd_alloca_check( FD_SLOT_META_ALIGN, total_sz );
    next_dead_meta = fd_slot_meta_decode( mem, &ctx );
  }

  /* Pick the next slot with the lowest slot number.  This is a policy
     decision and not necesarily the next slot that would've been
     replayed on a live node.  Reverse the iterator of the cf with the
     greater slot value.  If dead slots are not being ingested, there
     is no dead slots iterator to reverse. */

  if( !db->ingests_dead_slots || next_root_meta->slot<next_dead_meta->slot ) {
    *slot_out       = next_root_meta->slot;
    *shred_cnt_out  = next_root_meta->received;
    *is_slot_rooted = 1;
    if( db->ingests_dead_slots ) rocksdb_iter_prev( db->iter_dead );
  } else {
    *slot_out       = next_dead_meta->slot;
    *shred_cnt_out  = next_dead_meta->received;
    *is_slot_rooted = 0;
    rocksdb_iter_prev( db->iter_root );
  }

  char shred_key[ 16UL ];
  FD_STORE( ulong, shred_key, fd_ulong_bswap( *slot_out ) );
  FD_STORE( ulong, shred_key+8UL, 0UL );
  rocksdb_iter_seek( db->iter_shred, shred_key, 16UL );
  return 1;
}

void const *
fd_backtest_rocksdb_shred( fd_backtest_rocksdb_t * db,
                           ulong                   slot,
                           ulong                   shred_idx ) {
  if( shred_idx>0UL ) {
    rocksdb_iter_next( db->iter_shred );
  }

  FD_TEST( rocksdb_iter_valid( db->iter_shred ) );

  ulong keylen;
  char const * key = rocksdb_iter_key( db->iter_shred, &keylen );
  FD_TEST( keylen==16UL );

  ulong key_slot      = fd_ulong_bswap( FD_LOAD( ulong, key ) );
  ulong key_shred_idx = fd_ulong_bswap( FD_LOAD( ulong, key+8UL ) );
  FD_TEST( key_slot==slot );
  FD_TEST( key_shred_idx==shred_idx );

  ulong vallen;
  char const * shred = rocksdb_iter_value( db->iter_shred, &vallen );
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
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "rocksdb_get_cf(\"bank_hashes\",%lu) failed: %s", slot, err ));

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
