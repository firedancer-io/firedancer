#include "fd_snapshot.h"
#include "../../util/archive/fd_tar.h"
#include "../types/fd_types.h"
#include "../runtime/fd_acc_mgr.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>       /* sscanf */
#include <string.h>      /* strncmp */
#include <sys/random.h>  /* getrandom */

fd_tar_read_vtable_t const fd_snapshot_restore_tar_vt =
  { .file = fd_snapshot_restore_file,
    .read = fd_snapshot_restore_chunk };


/* Accounts are loaded from a snapshot via "account vec" files, each
   containing multiple accounts.  However, external information is
   required to determine the size of these files.  This information is
   stored in the "manifest" file, which is loaded at the beginning of
   the snapshot.

   The below map serves to store the file size information. */

struct fd_snapshot_accv_key {
  ulong slot;
  ulong id;
};

typedef struct fd_snapshot_accv_key fd_snapshot_accv_key_t;

static const fd_snapshot_accv_key_t
fd_snapshot_accv_key_null = { 0UL, 0UL };

static FD_TL ulong fd_snapshot_acc_hash_seed = 0UL;

static inline ulong
fd_snapshot_accv_key_hash( fd_snapshot_accv_key_t key ) {
  return fd_hash( fd_snapshot_acc_hash_seed, &key, sizeof(fd_snapshot_accv_key_t) );
}

struct fd_snapshot_accv_map {
  fd_snapshot_accv_key_t key;
  ulong                  sz;
  ulong                  hash;  /* use uint or ulong hash? */
};

typedef struct fd_snapshot_accv_map fd_snapshot_accv_map_t;

#define MAP_NAME              fd_snapshot_accv_map
#define MAP_T                 fd_snapshot_accv_map_t
#define MAP_LG_SLOT_CNT       23  /* 8.39 million */
#define MAP_KEY_T             fd_snapshot_accv_key_t
#define MAP_KEY_NULL          fd_snapshot_accv_key_null
#define MAP_KEY_INVAL(k)      ( (k).slot==0UL && (k).id==0UL )
#define MAP_KEY_EQUAL(k0,k1)  ( (k0).slot==(k1).slot && (k0).id==(k1).id )
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_HASH_T            ulong
#define MAP_KEY_HASH(k0)      fd_snapshot_accv_key_hash(k0)
#include "../../util/tmpl/fd_map.c"


/* Main snapshot restore **********************************************/

struct fd_snapshot_restore {
  fd_exec_slot_ctx_t * slot_ctx;

  uchar state;
  uchar manifest_done : 1;

  /* Buffer params.  This buffer is used to gather file content into
     a contiguous byte array.  Currently in use for the manifest and the
     account headers.  (Account data does not use this buffer) */

  uchar * buf;      /* points to first byte of buffer */
  uchar * buf_end;  /* points one right to last byte of buffer */
  ulong   buf_ctr;  /* number of bytes allocated in buffer */
  ulong   buf_sz;   /* target buffer size (buf_ctr<buf_sz implies incomplete read) */

  /* Account vec params.  Sadly, Solana Labs encodes account vecs with
     garbage at the end of the file.  The actual account vec sz can be
     smaller.  In this case, we have to stop reading account data early
     and skip the garbage/padding. */

  ulong   accv_slot;   /* account vec slot */
  ulong   accv_sz;     /* account vec size */
  fd_snapshot_accv_map_t * accv_map;

  /* Account size.  Used when reading account data. */

  ulong   acc_sz;    /* acc bytes pending write */
  uchar * acc_data;  /* pointer into funk acc data pending write */
  ulong   acc_pad;   /* padding size at end of account */
};

/* STATE_{...} are the state IDs that control file processing in the
   snapshot streaming state machine. */

#define STATE_IGNORE            ((uchar)0)  /* ignore file content */
#define STATE_READ_MANIFEST     ((uchar)1)  /* reading manifest (buffered) */
#define STATE_READ_ACCOUNT_HDR  ((uchar)2)  /* reading account hdr (buffered) */
#define STATE_READ_ACCOUNT_DATA ((uchar)3)  /* reading account data (direct copy into funk) */
#define STATE_DONE              ((uchar)4)  /* expect no more data */

ulong
fd_snapshot_restore_align( void ) {
  return fd_ulong_max( alignof(fd_snapshot_restore_t), fd_snapshot_accv_map_align() );
}

ulong
fd_snapshot_restore_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_restore_t), sizeof(fd_snapshot_restore_t) );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_accv_map_align(), fd_snapshot_accv_map_footprint() );
  return FD_LAYOUT_FINI( l, fd_snapshot_restore_align() );
}

fd_snapshot_restore_t *
fd_snapshot_restore_new( void *               mem,
                         fd_exec_slot_ctx_t * slot_ctx,
                         void *               scratch,
                         ulong                scratch_sz ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_restore_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( (!slot_ctx->valloc.vt->malloc)
                 | (!slot_ctx->valloc.vt->free  ) ) ) {
    FD_LOG_WARNING(( "NULL valloc" ));
    return NULL;
  }
  if( FD_UNLIKELY( scratch_sz < sizeof(fd_solana_account_hdr_t) ) ) {
    FD_LOG_WARNING(( "undersz scratch_sz (%lu)", scratch_sz ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_restore_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_restore_t), sizeof(fd_snapshot_restore_t) );
  fd_memset( self, 0, sizeof(fd_snapshot_restore_t) );
  self->slot_ctx = slot_ctx;
  self->state    = STATE_DONE;
  self->buf      = scratch;
  self->buf_end  = self->buf + scratch_sz;

  void * accv_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_accv_map_align(), fd_snapshot_accv_map_footprint() );
  self->accv_map = fd_snapshot_accv_map_join( fd_snapshot_accv_map_new( accv_map_mem ) );
  FD_TEST( self->accv_map );

  return self;
}

void *
fd_snapshot_restore_delete( fd_snapshot_restore_t * self ) {
  if( FD_UNLIKELY( !self ) ) return NULL;
  fd_memset( self, 0, sizeof(fd_snapshot_restore_t) );

  fd_snapshot_accv_map_delete( fd_snapshot_accv_map_leave( self->accv_map ) );

  return (void *)self;
}

/* fd_snapshot_restore_account_hdr deserializes an account header and
   allocates a corresponding funk record. */

static int
fd_snapshot_restore_account_hdr( fd_snapshot_restore_t * restore ) {

  /* Advance state machine */
  restore->state    = STATE_READ_ACCOUNT_DATA;
  restore->buf_ctr  = 0UL;
  restore->buf_sz   = 0UL;
  restore->acc_data = NULL;

  fd_solana_account_hdr_t const * hdr = fd_type_pun_const( restore->buf );

  /* Prepare for account lookup */
  fd_acc_mgr_t *      acc_mgr  = restore->slot_ctx->acc_mgr;
  fd_funk_txn_t *     funk_txn = restore->slot_ctx->funk_txn;
  fd_pubkey_t const * key      = fd_type_pun_const( hdr->meta.pubkey );
  fd_borrowed_account_t rec[1]; fd_borrowed_account_init( rec );
  char key_cstr[ FD_BASE58_ENCODED_32_SZ ];

  /* Sanity checks */
  if( FD_UNLIKELY( hdr->meta.data_len > FD_ACC_SZ_MAX ) ) {
    FD_LOG_WARNING(( "account %s too large: data_len=%lu",
                     fd_addr_cstr( key_cstr, key->uc ), hdr->meta.data_len ));
    FD_LOG_HEXDUMP_WARNING(( "account header", hdr, sizeof(fd_solana_account_hdr_t) ));
    return 0;
  }

  int is_dupe = 0;

  /* Check if account exists */
  rec->const_meta = fd_acc_mgr_view_raw( acc_mgr, funk_txn, key, &rec->const_rec, NULL );
  if (NULL != rec->const_meta) {
    if( rec->const_meta->slot > restore->accv_slot )
      is_dupe = 1;
  }

  /* Write account */
  if( !is_dupe ) {
    int write_result = fd_acc_mgr_modify( acc_mgr, funk_txn, key, /* do_create */ 1, hdr->meta.data_len, rec );
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_acc_mgr_modify(%s) failed modify", fd_addr_cstr( key_cstr, key->uc )));
      return 0;
    }
    rec->meta->dlen = hdr->meta.data_len;
    rec->meta->slot = restore->accv_slot;
    memcpy( &rec->meta->hash, hdr->hash.value, 32UL );
    memcpy( &rec->meta->info, &hdr->info, sizeof(fd_solana_account_meta_t) );
    restore->acc_data = rec->data;
  }
  restore->acc_sz   = hdr->meta.data_len;
  restore->acc_pad  = fd_ulong_align_up( restore->acc_sz, FD_SNAPSHOT_ACC_ALIGN ) - restore->acc_sz;

  /* Fail if account data is cut off */
  if( restore->accv_sz < restore->acc_sz ) {
    FD_LOG_WARNING(( "account %s data past end of account vec (acc_sz=%lu accv_sz=%lu)",
                     fd_addr_cstr( key_cstr, key->uc ), restore->acc_sz, restore->accv_sz ));
    FD_LOG_HEXDUMP_WARNING(( "account header", hdr, sizeof(fd_solana_account_hdr_t) ));
    return 0;
  }

  return 1;
}

/* fd_snapshot_accv_index populates the index of account vecs.  This
   index will be used when loading accounts. */

static int
fd_snapshot_accv_index( fd_snapshot_accv_map_t *               map,
                        fd_solana_accounts_db_fields_t const * fields ) {

  /* Choose random seed to prevent collision attacks */
  if( FD_UNLIKELY( !fd_snapshot_acc_hash_seed ) )
    if( FD_UNLIKELY( sizeof(ulong)!=getrandom( &fd_snapshot_acc_hash_seed, sizeof(ulong), 0 ) ) )
      FD_LOG_ERR(( "getrandom failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0UL; i < fields->storages_len; i++ ) {

    fd_snapshot_slot_acc_vecs_t * slot = &fields->storages[ i ];

    for( ulong j=0UL; j < slot->account_vecs_len; j++ ) {
      fd_snapshot_acc_vec_t * accv = &slot->account_vecs[ j ];

      /* Insert new AppendVec */
      fd_snapshot_accv_key_t key = { .slot = slot->slot, .id = accv->id };
      fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_insert( map, key );
      if( FD_UNLIKELY( !rec ) ) {
        FD_LOG_WARNING(( "fd_snapshot_accv_map_insert failed" ));
        return 0;
      }

      /* Remember size */
      rec->sz = accv->file_sz;
    }

  }

  return 1;
}

/* fd_snapshot_restore_manifest imports a snapshot manifest into the
   given slot context.  Also populates the accv index.  Destroys the
   existing bank structure. */

static int
fd_snapshot_restore_manifest( fd_exec_slot_ctx_t *     slot_ctx,
                              fd_snapshot_accv_map_t * accv_map,
                              uchar const *            manifest_buf,
                              ulong                    manifest_bufsz ) {

  fd_valloc_t slot_valloc = slot_ctx->valloc;

  /* Decode manifest placing dynamic data structures onto slot context
     heap.  Once the epoch context heap is separated out, we need to
     revisit this. */

  fd_solana_manifest_t manifest[1];
  fd_bincode_decode_ctx_t decode =
      { .data    = manifest_buf,
        .dataend = manifest_buf + manifest_bufsz,
        .valloc  = slot_valloc /* expected by fd_exec_slot_ctx_recover */ };
  int decode_err = fd_solana_manifest_decode( manifest, &decode );
  if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_solana_manifest_decode failed (%d)", decode_err ));
    return 0;
  }

  /* Move over accounts DB fields */

  fd_solana_accounts_db_fields_t accounts_db = manifest->accounts_db;
  fd_memset( &manifest->accounts_db, 0, sizeof(fd_solana_accounts_db_fields_t) );

  /* Move over objects and recover state
     This destroys all remaining fields with the slot context valloc. */

  int ok = !!fd_exec_slot_ctx_recover( slot_ctx, manifest );

  /* Read AccountVec map */

  if( FD_LIKELY( ok ) )
    ok = fd_snapshot_accv_index( accv_map, &accounts_db );

  fd_bincode_destroy_ctx_t destroy = { .valloc = slot_valloc };
  fd_solana_accounts_db_fields_destroy( &accounts_db, &destroy );

  return ok;
}

/* Streaming state machine ********************************************/

/* fd_snapshot_restore_accv_prepare prepares for consumption of an
   account vec file. */

static int
fd_snapshot_restore_accv_prepare( fd_snapshot_restore_t * restore,
                                  fd_tar_meta_t const *   meta,
                                  ulong                   sz ) {

  ulong id, slot;
  if( FD_UNLIKELY( sscanf( meta->name, "accounts/%lu.%lu", &slot, &id)!=2 ) ) {
    /* ignore if file name invalid */
    restore->state  = STATE_DONE;
    restore->buf_sz = 0UL;
    return 0;
  }

  /* Lookup account vec file size */
  fd_snapshot_accv_key_t key = { .slot = slot, .id = id };
  fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_query( restore->accv_map, key, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    FD_LOG_WARNING(( "account vec missing file size, assuming full: %s", meta->name ));
  } else {
    sz = rec->sz;
  }
  restore->accv_sz   = sz;
  restore->accv_slot = slot;

  /* Prepare read of account header */
  restore->state     = STATE_READ_ACCOUNT_HDR;
  restore->buf_sz    = sizeof(fd_solana_account_hdr_t);

  FD_LOG_DEBUG(( "Loading account vec %s", meta->name ));
  return 0;
}

/* fd_snapshot_restore_manifest_prepare prepares for consumption of the
   snapshot manifest. */

static int
fd_snapshot_restore_manifest_prepare( fd_snapshot_restore_t * restore,
                                      ulong                   sz ) {
  /* Only read once */
  if( restore->manifest_done ) {
    restore->state = STATE_IGNORE;
    return 0;
  }

  ulong buf_cap = (ulong)(restore->buf_end - restore->buf);
  if( FD_UNLIKELY( buf_cap<sz ) ) {
    FD_LOG_WARNING(( "scratch buffer too small for manifest (buf_sz=%lu, file_sz=%lu)", buf_cap, sz ));
    return -1;
  }

  restore->state  = STATE_READ_MANIFEST;
  restore->buf_sz = sz;

  return 0;
}

/* fd_snapshot_restore_file gets called by fd_tar before processing a
   new file.  We use this opportunity to init the state machine that
   will process the incoming file chunks, and set the buffer size if
   required. */

int
fd_snapshot_restore_file( void *                restore_,
                          fd_tar_meta_t const * meta,
                          ulong                 sz ) {

  fd_snapshot_restore_t * restore = restore_;

  restore->buf_ctr  = 0UL;   /* reset buffer */
  restore->acc_data = NULL;  /* reset account write state */
  restore->acc_sz   = 0UL;
  restore->acc_pad  = 0UL;

  if( (sz==0UL) | (!fd_tar_meta_is_reg( meta )) ) {
    restore->state = STATE_IGNORE;
    return 0;
  }

  /* Detect account vec files.  These are files that contain a vector
     of accounts in Solana Labs "AppendVec" format. */
  assert( sizeof("accounts/")<FD_TAR_NAME_SZ );
  if( 0==strncmp( meta->name, "accounts/", sizeof("accounts/")-1) ) {
    if( FD_UNLIKELY( !restore->manifest_done ) ) {
      FD_LOG_WARNING(( "Unsupported snapshot: encountered AppendVec before manifest" ));
      return -1;
    }
    return fd_snapshot_restore_accv_prepare( restore, meta, sz );
  }

  /* Snapshot manifest */
  assert( sizeof("snapshots/status_cache")<FD_TAR_NAME_SZ );
  if( 0==strncmp( meta->name, "snapshots/", sizeof("snapshots/")-1) &&
      0!=strcmp ( meta->name, "snapshots/status_cache" ) )
    return fd_snapshot_restore_manifest_prepare( restore, sz );

  restore->state = STATE_IGNORE;
  return 0;
}

/* fd_snapshot_read_buffered appends bytes to a buffer. */

static uchar const *
fd_snapshot_read_buffered( fd_snapshot_restore_t * restore,
                           uchar const *           buf,
                           ulong                   bufsz ) {
  /* Should not be called if read is complete */
  FD_TEST( restore->buf_ctr < restore->buf_sz );

  /* Determine number of bytes to buffer */
  ulong sz = restore->buf_sz - restore->buf_ctr;
  if( sz>bufsz ) sz = bufsz;

  /* Append to buffer */
  fd_memcpy( restore->buf + restore->buf_ctr, buf, sz );
  restore->buf_ctr += sz;

  return buf+sz;
}

/* fd_snapshot_read_is_complete returns 1 if all requested bytes have
   been buffered. */

FD_FN_PURE static inline int
fd_snapshot_read_is_complete( fd_snapshot_restore_t const * restore ) {
  return restore->buf_ctr == restore->buf_sz;
}

/* fd_snapshot_read_account_hdr_chunk reads a partial account header. */

static uchar const *
fd_snapshot_read_account_hdr_chunk( fd_snapshot_restore_t * restore,
                                    uchar const *           buf,
                                    ulong                   bufsz ) {
  if( !restore->accv_sz ) {
    /* Reached end of AppendVec */
    restore->state   = STATE_IGNORE;
    restore->buf_ctr = restore->buf_sz = 0UL;
    return buf;
  }
  bufsz = fd_ulong_min( bufsz, restore->accv_sz );

  /* Skip alignment padding */
  ulong pad_sz = fd_ulong_min( restore->acc_pad, bufsz );
  buf              += pad_sz;
  bufsz            -= pad_sz;
  restore->acc_pad -= pad_sz;
  restore->accv_sz -= pad_sz;

  /* Actually read account header */
  uchar const * end = fd_snapshot_read_buffered( restore, buf, bufsz );
  if( fd_snapshot_read_is_complete( restore ) )
    if( FD_UNLIKELY( !fd_snapshot_restore_account_hdr( restore ) ) )
      return NULL;
  restore->accv_sz -= (ulong)(end-buf);
  return end;
}

/* fd_snapshot_read_account_chunk reads partial account content. */

static uchar const *
fd_snapshot_read_account_chunk( fd_snapshot_restore_t * restore,
                                uchar const *           buf,
                                ulong                   bufsz ) {

  ulong data_sz = fd_ulong_min( restore->acc_sz, bufsz );
  if( FD_LIKELY( restore->acc_data ) ) {
    fd_memcpy( restore->acc_data, buf, data_sz );
    restore->acc_data += data_sz;
  }

  restore->acc_sz   -= data_sz;
  restore->accv_sz  -= data_sz;
  buf               += data_sz;
  bufsz             -= data_sz;

  if( restore->acc_sz == 0UL ) {
    /* Advance to next account */
    restore->state    = STATE_READ_ACCOUNT_HDR;
    restore->acc_data = NULL;
    restore->buf_ctr  = 0UL;
    restore->buf_sz   = sizeof(fd_solana_account_hdr_t);
  }

  return buf;
}

/* fd_snapshot_read_manifest_chunk reads partial manifest content. */

static uchar const *
fd_snapshot_read_manifest_chunk( fd_snapshot_restore_t * restore,
                                 uchar const *           buf,
                                 ulong                   bufsz ) {
  uchar const * end = fd_snapshot_read_buffered( restore, buf, bufsz );
  if( fd_snapshot_read_is_complete( restore ) ) {
    int ok = fd_snapshot_restore_manifest( restore->slot_ctx, restore->accv_map, restore->buf, restore->buf_ctr );
    if( FD_UNLIKELY( !ok ) ) {
      FD_LOG_WARNING(( "fd_snapshot_restore_manifest failed" ));
      return NULL;
    }
    restore->manifest_done = 1;
    restore->state = STATE_DONE;
  }
  return end;
}

/* fd_snapshot_restore_chunk1 consumes at least one byte from the given
   buffer (unless bufsz==0).  Returns pointer to first byte that has
   not been consumed yet. */

static uchar const *
fd_snapshot_restore_chunk1( fd_snapshot_restore_t * restore,
                            uchar const *           buf,
                            ulong                   bufsz ) {

  switch( restore->state ) {
  case STATE_IGNORE:
    return buf+bufsz;
  case STATE_DONE:
    FD_LOG_WARNING(( "unexpected trailing data" ));
    return NULL;
  case STATE_READ_ACCOUNT_HDR:
    return fd_snapshot_read_account_hdr_chunk( restore, buf, bufsz );
  case STATE_READ_ACCOUNT_DATA:
    return fd_snapshot_read_account_chunk    ( restore, buf, bufsz );
  case STATE_READ_MANIFEST:
    return fd_snapshot_read_manifest_chunk   ( restore, buf, bufsz );
  default:
    __builtin_unreachable();
  }

}

int
fd_snapshot_restore_chunk( void *       restore_,
                           void const * buf_,
                           ulong        bufsz ) {

  fd_snapshot_restore_t * restore = restore_;
  uchar const * buf               = buf_;

  while( bufsz ) {
    uchar const * buf_new = fd_snapshot_restore_chunk1( restore, buf, bufsz );
    if( FD_UNLIKELY( !buf_new ) ) {
      FD_LOG_WARNING(( "Aborting snapshot read" ));
      return -1;
    }
    bufsz -= (ulong)(buf_new-buf);
    buf    = buf_new;
  }

  return 0;
}
