#include "fd_backtest_src.h"
#include <stdlib.h>
#include <rocksdb/c.h>

extern fd_backt_src_vt_t const fd_backt_src_rocksdb_vt;

#define CF_IDX_DEFAULT    0
#define CF_IDX_CODE_SHRED 1
#define CF_IDX_DATA_SHRED 2
#define CF_IDX_ROOT       3
#define CF_IDX_BANK_HASH  4
#define CF_IDX_DEAD_SLOT  5
#define CF_CNT            6

struct fd_backt_src_rocksdb {
  fd_backt_src_t src[1];
  rocksdb_t * db;
  rocksdb_readoptions_t * ro;
  rocksdb_column_family_handle_t * code_shred_cf;
  rocksdb_column_family_handle_t * data_shred_cf;
  rocksdb_column_family_handle_t * root_cf;
  rocksdb_column_family_handle_t * bank_hash_cf;
  rocksdb_column_family_handle_t * dead_slot_cf;
  rocksdb_iterator_t * code_shred_iter;
  rocksdb_iterator_t * data_shred_iter;
  rocksdb_iterator_t * root_iter;

  uint rooted_only : 1;
  uint code_shreds : 1;
  uint code_iter_done : 1;
  uint data_iter_done : 1;
  uint code_slot_done : 1;
  uint data_slot_done : 1;

  ulong current_slot; /* ULONG_MAX if slot not started */
};

typedef struct fd_backt_src_rocksdb fd_backt_src_rocksdb_t;

static ulong
iter_cur_slot( rocksdb_iterator_t * iter ) {
  rocksdb_slice_t key = rocksdb_iter_key_slice( iter );
  if( FD_UNLIKELY( key.size < sizeof(ulong) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "invalid key", key.data, key.size ));
    FD_LOG_ERR(( "corrupt RocksDB: invalid key in iterator" ));
  }
  return fd_ulong_bswap( FD_LOAD( ulong, key.data ) );
}

fd_backt_src_t *
fd_backt_src_rocksdb_create( fd_backtest_src_opts_t const * opts ) {
  FD_TEST( opts );
  /* opts->format ignored */

  static char const * cf_names[ CF_CNT ] = {
    [ CF_IDX_DEFAULT    ] = "default",
    [ CF_IDX_CODE_SHRED ] = "code_shred",
    [ CF_IDX_DATA_SHRED ] = "data_shred",
    [ CF_IDX_ROOT       ] = "root",
    [ CF_IDX_BANK_HASH  ] = "bank_hashes",
    [ CF_IDX_DEAD_SLOT  ] = "dead_slots"
  };

  rocksdb_options_t * options = rocksdb_options_create();
  if( FD_UNLIKELY( !options ) ) FD_LOG_ERR(( "rocksdb_options_create failed" ));

  rocksdb_options_t const * cf_options[ CF_CNT ];
  for( ulong i=0UL; i<CF_CNT; i++ ) cf_options[ i ] = options;

  rocksdb_column_family_handle_t * cfs[ CF_CNT ] = {0};

  char * err = NULL;
  rocksdb_t * db = rocksdb_open_for_read_only_column_families(
    options,
    opts->path,
    CF_CNT,
    cf_names,
    cf_options,
    cfs,
    0,
    &err
  );
  rocksdb_options_destroy( options );
  if( FD_UNLIKELY( !db ) ) {
    FD_LOG_WARNING(( "rocksdb_open_for_read_only_column_families failed: %s", err ));
    rocksdb_free( err );
    return NULL;
  }

  rocksdb_column_family_handle_destroy( cfs[ CF_IDX_DEFAULT ] );

  rocksdb_readoptions_t * ro = rocksdb_readoptions_create();
  if( FD_UNLIKELY( !ro ) ) {
    FD_LOG_ERR(( "rocksdb_readoptions_create failed" ));
  }

  fd_backt_src_rocksdb_t * src = calloc( 1UL, sizeof(fd_backt_src_rocksdb_t) );
  if( FD_UNLIKELY( !src ) ) FD_LOG_ERR(( "out of memory" ));

  rocksdb_iterator_t * code_shred_iter = rocksdb_create_iterator_cf( db, ro, cfs[ CF_IDX_CODE_SHRED ] );
  rocksdb_iterator_t * data_shred_iter = rocksdb_create_iterator_cf( db, ro, cfs[ CF_IDX_DATA_SHRED ] );
  rocksdb_iterator_t * root_iter       = rocksdb_create_iterator_cf( db, ro, cfs[ CF_IDX_ROOT       ] );
  if( FD_UNLIKELY( !code_shred_iter || !data_shred_iter || !root_iter ) ) {
    FD_LOG_ERR(( "rocksdb_create_iterator_cf failed" ));
  }

  rocksdb_iter_seek_to_first( code_shred_iter );
  rocksdb_iter_seek_to_first( data_shred_iter );
  rocksdb_iter_seek_to_first( root_iter );

  *src = (fd_backt_src_rocksdb_t){
    .src = {{
      .vt = &fd_backt_src_rocksdb_vt
    }},
    .db = db,
    .ro = ro,

    .code_shred_cf   = cfs[ CF_IDX_CODE_SHRED ],
    .data_shred_cf   = cfs[ CF_IDX_DATA_SHRED ],
    .root_cf         = cfs[ CF_IDX_ROOT       ],
    .bank_hash_cf    = cfs[ CF_IDX_BANK_HASH  ],
    .dead_slot_cf    = cfs[ CF_IDX_DEAD_SLOT  ],
    .code_shred_iter = code_shred_iter,
    .data_shred_iter = data_shred_iter,
    .root_iter       = root_iter,

    .rooted_only     = !!opts->rooted_only,
    .code_shreds     = !!opts->code_shreds,
    .code_iter_done  = !opts->code_shreds,
    .data_iter_done  = 0,
    .code_slot_done  = !opts->code_shreds,
    .data_slot_done  = 0,

    .current_slot = ULONG_MAX
  };
  return src->src;
}

void
fd_backt_src_rocksdb_destroy( fd_backt_src_t * this ) {
  if( FD_UNLIKELY( !this ) ) return;
  fd_backt_src_rocksdb_t * src = (fd_backt_src_rocksdb_t *)this;
  rocksdb_iter_destroy( src->code_shred_iter );
  rocksdb_iter_destroy( src->data_shred_iter );
  rocksdb_iter_destroy( src->root_iter );
  rocksdb_column_family_handle_destroy( src->code_shred_cf );
  rocksdb_column_family_handle_destroy( src->data_shred_cf );
  rocksdb_column_family_handle_destroy( src->root_cf );
  rocksdb_column_family_handle_destroy( src->bank_hash_cf );
  rocksdb_column_family_handle_destroy( src->dead_slot_cf );
  rocksdb_readoptions_destroy( src->ro );
  rocksdb_close( src->db );
  free( src );
}

ulong
fd_backt_src_rocksdb_first_shred( fd_backt_src_t * this,
                                  uchar *          buf,
                                  ulong            buf_sz ) {
  fd_backt_src_rocksdb_t * src = (fd_backt_src_rocksdb_t *)this;
  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf(
      src->db, src->ro, src->data_shred_cf );
  if( FD_UNLIKELY( !iter ) ) {
    FD_LOG_WARNING(( "rocksdb_create_iterator_cf(data_shred) failed" ));
    return 0UL;
  }
  rocksdb_iter_seek_to_first( iter );
  ulong sz = 0UL;
  if( FD_LIKELY( rocksdb_iter_valid( iter ) ) ) {
    size_t vlen = 0UL;
    char const * value = rocksdb_iter_value( iter, &vlen );
    if( FD_LIKELY( value && vlen<=buf_sz ) ) {
      fd_memcpy( buf, value, vlen );
      sz = (ulong)vlen;
    } else {
      FD_LOG_WARNING(( "RocksDB contains oversz data shred (sz=%lu buf_sz=%lu)", (ulong)vlen, buf_sz ));
    }
  } else {
    FD_LOG_WARNING(( "RocksDB does not contain any data shreds" ));
  }
  rocksdb_iter_destroy( iter );
  return sz;
}

ulong
fd_backt_src_rocksdb_shred( fd_backt_src_t * this,
                            uchar *          buf,
                            ulong            buf_sz ) {
  fd_backt_src_rocksdb_t * src = (fd_backt_src_rocksdb_t *)this;

  for(;;) {

    if( FD_UNLIKELY( src->current_slot==ULONG_MAX && src->rooted_only ) ) {
      if( FD_UNLIKELY( !rocksdb_iter_valid( src->root_iter ) ) ) {
        src->data_iter_done = 1;
        src->code_iter_done = 1;
        return ULONG_MAX;
      }
      src->current_slot = iter_cur_slot( src->root_iter );
    }

    if( !src->data_slot_done ) {
      rocksdb_iterator_t * iter = src->data_shred_iter;
      if( FD_UNLIKELY( !rocksdb_iter_valid( iter ) ) ) {
        src->data_slot_done = 1;
        src->data_iter_done = 1;
        continue;
      }
      ulong found_slot = iter_cur_slot( iter );
      if( FD_UNLIKELY( src->current_slot == ULONG_MAX ) ) {
        src->current_slot = found_slot;
      } else if( FD_UNLIKELY( found_slot > src->current_slot ) ) {
        src->data_slot_done = 1;
        continue;
      } else if( FD_UNLIKELY( found_slot < src->current_slot ) ) {
        char key[8]; FD_STORE( ulong, key, fd_ulong_bswap( src->current_slot ) );
        rocksdb_iter_seek( iter, key, sizeof(ulong) );
        continue;
      }
      rocksdb_slice_t value = rocksdb_iter_value_slice( iter );
      ulong sz = fd_ulong_min( value.size, buf_sz );
      fd_memcpy( buf, value.data, sz );
      rocksdb_iter_next( iter );
      return sz;
    }

    if( !src->code_slot_done ) {
      rocksdb_iterator_t * iter = src->code_shred_iter;
      if( FD_UNLIKELY( !rocksdb_iter_valid( iter ) ) ) {
        src->code_slot_done = 1;
        src->code_iter_done = 1;
        continue;
      }
      ulong found_slot = iter_cur_slot( iter );
      if( FD_UNLIKELY( found_slot > src->current_slot ) ) {
        src->code_slot_done = 1;
        continue;
      } else if( FD_UNLIKELY( found_slot < src->current_slot ) ) {
        char key[8]; FD_STORE( ulong, key, fd_ulong_bswap( src->current_slot ) );
        rocksdb_iter_seek( iter, key, sizeof(ulong) );
        continue;
      }
      rocksdb_slice_t value = rocksdb_iter_value_slice( iter );
      ulong sz = fd_ulong_min( value.size, buf_sz );
      fd_memcpy( buf, value.data, sz );
      rocksdb_iter_next( iter );
      return sz;
    }

    if( FD_UNLIKELY( src->data_iter_done && src->code_iter_done ) ) {
      return ULONG_MAX;
    }
    if( src->current_slot!=ULONG_MAX ) {
      char next_root_key[8]; FD_STORE( ulong, next_root_key, fd_ulong_bswap( src->current_slot+1UL ) );
      rocksdb_iter_seek( src->root_iter, next_root_key, sizeof(ulong) );
    }
    src->current_slot   = ULONG_MAX;
    src->code_slot_done = !src->code_shreds;
    src->data_slot_done = 0;
  }

}

fd_backt_slot_info_t *
fd_backt_src_rocksdb_slot_info( fd_backt_src_t *       this,
                                fd_backt_slot_info_t * out,
                                ulong                  slot ) {
  fd_backt_src_rocksdb_t * src = (fd_backt_src_rocksdb_t *)this;

  char key[8]; FD_STORE( ulong, key, fd_ulong_bswap( slot ) );

  char * err = NULL;
  ulong  root_val_len;
  char * root_val = rocksdb_get_cf( src->db, src->ro, src->root_cf, key, sizeof(ulong), &root_val_len, &err );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "rocksdb_get_cf(root) failed: %s", err ));

  ulong  bank_hash_len;
  char * bank_hash_val = rocksdb_get_cf( src->db, src->ro, src->bank_hash_cf, key, sizeof(ulong), &bank_hash_len, &err );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "rocksdb_get_cf(bank_hashes) failed: %s", err ));

  ulong  dead_slot_len;
  char * dead_slot_val = rocksdb_get_cf( src->db, src->ro, src->dead_slot_cf, key, sizeof(ulong), &dead_slot_len, &err );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "rocksdb_get_cf(dead_slot) failed: %s", err ));

  memset( out, 0, sizeof(fd_backt_slot_info_t) );
  out->slot = slot;

  if( bank_hash_val && bank_hash_len>=36UL ) {
    fd_memcpy( &out->bank_hash, bank_hash_val+4UL, sizeof(fd_hash_t) );
    out->bank_hash_set = 1;
  }

  if( root_val && root_val_len>=1UL ) {
    out->rooted = !!root_val[ 0 ];
  }

  if( dead_slot_val && dead_slot_len>=1UL ) {
    out->dead = !!dead_slot_val[ 0 ];
  }

  rocksdb_free( root_val );
  rocksdb_free( bank_hash_val );
  rocksdb_free( dead_slot_val );

  return out;
}

fd_backt_src_vt_t const fd_backt_src_rocksdb_vt = {
  .destroy      = fd_backt_src_rocksdb_destroy,
  .first_shred  = fd_backt_src_rocksdb_first_shred,
  .shred        = fd_backt_src_rocksdb_shred,
  .slot_info    = fd_backt_src_rocksdb_slot_info
};
