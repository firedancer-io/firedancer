#include "fd_snapshot_restore_private.h"
#include "../../util/archive/fd_tar.h"
#include "../types/fd_types.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/fd_account.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>       /* sscanf */
#include <string.h>      /* strncmp */
#include <sys/random.h>  /* getrandom */

/* Snapshot Restore Buffer Handling ***********************************/

void
fd_snapshot_restore_discard_buf( fd_snapshot_restore_t * self ) {
  /* self->buf might be NULL */
  fd_valloc_free( self->valloc, self->buf );
  self->buf     = NULL;
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;
  self->buf_cap = 0UL;
}

static void *
fd_snapshot_restore_prepare_buf( fd_snapshot_restore_t * self,
                                 ulong                   sz ) {

  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;

  if( FD_LIKELY( sz <= self->buf_cap ) )
    return self->buf;

  fd_snapshot_restore_discard_buf( self );
  uchar * buf = fd_valloc_malloc( self->valloc, 1UL, sz );
  if( FD_UNLIKELY( !buf ) ) {
    self->failed = 1;
    return NULL;
  }
  self->buf     = buf;
  self->buf_cap = sz;
  return buf;
}

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
fd_snapshot_restore_new( void *                               mem,
                         fd_acc_mgr_t *                       acc_mgr,
                         fd_funk_txn_t *                      funk_txn,
                         fd_valloc_t                          valloc,
                         void *                               cb_ctx,
                         fd_snapshot_restore_cb_manifest_fn_t cb ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_restore_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !acc_mgr ) ) {
    FD_LOG_WARNING(( "NULL acc_mgr" ));
    return NULL;
  }
  if( FD_UNLIKELY( !valloc.vt ) ) {
    FD_LOG_WARNING(( "NULL valloc" ));
    return NULL;
  }
  if( FD_UNLIKELY( !cb ) ) {
    FD_LOG_WARNING(( "NULL callback" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_restore_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_restore_t), sizeof(fd_snapshot_restore_t) );
  fd_memset( self, 0, sizeof(fd_snapshot_restore_t) );
  self->acc_mgr     = acc_mgr;
  self->funk_txn    = funk_txn;
  self->valloc      = valloc;
  self->state       = STATE_DONE;
  self->buf         = NULL;
  self->buf_sz      = 0UL;
  self->buf_ctr     = 0UL;
  self->buf_cap     = 0UL;

  self->cb_manifest     = cb;
  self->cb_manifest_ctx = cb_ctx;

  void * accv_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_accv_map_align(), fd_snapshot_accv_map_footprint() );
  self->accv_map = fd_snapshot_accv_map_join( fd_snapshot_accv_map_new( accv_map_mem ) );
  FD_TEST( self->accv_map );

  return self;
}

void *
fd_snapshot_restore_delete( fd_snapshot_restore_t * self ) {
  if( FD_UNLIKELY( !self ) ) return NULL;
  fd_snapshot_restore_discard_buf( self );
  fd_snapshot_accv_map_delete( fd_snapshot_accv_map_leave( self->accv_map ) );
  fd_memset( self, 0, sizeof(fd_snapshot_restore_t) );
  return (void *)self;
}

/* Streaming state machine ********************************************/

/* fd_snapshot_expect_account_hdr sets up the snapshot restore to
   expect an account header on the next iteration.  Returns EINVAL if
   the current AppendVec doesn't fit an account header. */

static int
fd_snapshot_expect_account_hdr( fd_snapshot_restore_t * restore ) {

  ulong accv_sz = restore->accv_sz;
  if( accv_sz < sizeof(fd_solana_account_hdr_t) ) {
    if( FD_LIKELY( accv_sz==0UL ) ) {
      restore->state = STATE_READ_ACCOUNT_HDR;
      return 0;
    }
    FD_LOG_WARNING(( "encountered unexpected EOF while reading account header" ));
    restore->failed = 1;
    return EINVAL;
  }

  restore->state    = STATE_READ_ACCOUNT_HDR;
  restore->acc_data = NULL;
  restore->buf_ctr  = 0UL;
  restore->buf_sz   = sizeof(fd_solana_account_hdr_t);
  return 0;
}

/* fd_snapshot_restore_account_hdr deserializes an account header and
   allocates a corresponding funk record. */

static int
fd_snapshot_restore_account_hdr( fd_snapshot_restore_t * restore ) {

  fd_solana_account_hdr_t const * hdr = fd_type_pun_const( restore->buf );

  /* Prepare for account lookup */
  fd_acc_mgr_t *      acc_mgr  = restore->acc_mgr;
  fd_funk_txn_t *     funk_txn = restore->funk_txn;
  fd_pubkey_t const * key      = fd_type_pun_const( hdr->meta.pubkey );
  fd_borrowed_account_t rec[1]; fd_borrowed_account_init( rec );
  char key_cstr[ FD_BASE58_ENCODED_32_SZ ];

  /* Sanity checks */
  if( FD_UNLIKELY( hdr->meta.data_len > MAX_PERMITTED_DATA_LENGTH ) ) {
    FD_LOG_WARNING(( "accounts/%lu.%lu: account %s too large: data_len=%lu",
                     restore->accv_slot, restore->accv_id, fd_acct_addr_cstr( key_cstr, key->uc ), hdr->meta.data_len ));
    FD_LOG_HEXDUMP_WARNING(( "account header", hdr, sizeof(fd_solana_account_hdr_t) ));
    return EINVAL;
  }

  int is_dupe = 0;

  /* Check if account exists */
  rec->const_meta = fd_acc_mgr_view_raw( acc_mgr, funk_txn, key, &rec->const_rec, NULL );
  if( rec->const_meta )
    if( rec->const_meta->slot > restore->accv_slot )
      is_dupe = 1;

  /* Write account */
  if( !is_dupe ) {
    int write_result = fd_acc_mgr_modify( acc_mgr, funk_txn, key, /* do_create */ 1, hdr->meta.data_len, rec );
    if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_acc_mgr_modify(%s) failed (%d)", fd_acct_addr_cstr( key_cstr, key->uc ), write_result ));
      return ENOMEM;
    }
    rec->meta->dlen = hdr->meta.data_len;
    rec->meta->slot = restore->accv_slot;
    memcpy( &rec->meta->hash, hdr->hash.uc, 32UL );
    memcpy( &rec->meta->info, &hdr->info, sizeof(fd_solana_account_meta_t) );
    restore->acc_data = rec->data;
  }
  ulong data_sz    = hdr->meta.data_len;
  restore->acc_sz  = data_sz;
  restore->acc_pad = fd_ulong_align_up( data_sz, FD_SNAPSHOT_ACC_ALIGN ) - data_sz;

  /* Next step */
  if( data_sz == 0UL )
    return fd_snapshot_expect_account_hdr( restore );

  /* Fail if account data is cut off */
  if( FD_UNLIKELY( restore->accv_sz < data_sz ) ) {
    FD_LOG_WARNING(( "accounts/%lu.%lu: account %s data exceeds past end of account vec (acc_sz=%lu accv_sz=%lu)",
                     restore->accv_slot, restore->accv_id, fd_acct_addr_cstr( key_cstr, key->uc ), data_sz, restore->accv_sz ));
    FD_LOG_HEXDUMP_WARNING(( "account header", hdr, sizeof(fd_solana_account_hdr_t) ));
    restore->failed = 1;
    return EINVAL;
  }

  restore->state    = STATE_READ_ACCOUNT_DATA;
  restore->buf_ctr  = 0UL;
  restore->buf_sz   = 0UL;
  return 0;
}

/* fd_snapshot_accv_index populates the index of account vecs.  This
   index will be used when loading accounts.  Returns errno-compatible
   error code. */

static int
fd_snapshot_accv_index( fd_snapshot_accv_map_t *               map,
                        fd_solana_accounts_db_fields_t const * fields ) {

  for( ulong i=0UL; i < fields->storages_len; i++ ) {

    fd_snapshot_slot_acc_vecs_t * slot = &fields->storages[ i ];

    for( ulong j=0UL; j < slot->account_vecs_len; j++ ) {
      fd_snapshot_acc_vec_t * accv = &slot->account_vecs[ j ];

      /* Insert new AppendVec */
      fd_snapshot_accv_key_t key = { .slot = slot->slot, .id = accv->id };
      fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_insert( map, key );
      if( FD_UNLIKELY( !rec ) ) {
        FD_LOG_WARNING(( "fd_snapshot_accv_map_insert failed" ));
        return ENOMEM;
      }

      /* Remember size */
      rec->sz = accv->file_sz;
    }

  }

  return 0;
}

/* fd_snapshot_restore_manifest imports a snapshot manifest into the
   given slot context.  Also populates the accv index.  Destroys the
   existing bank structure. */

static int
fd_snapshot_restore_manifest( fd_snapshot_restore_t * restore ) {

  /* Decode manifest placing dynamic data structures onto slot context
     heap.  Once the epoch context heap is separated out, we need to
     revisit this. */

  fd_solana_manifest_t manifest[1];
  fd_bincode_decode_ctx_t decode =
      { .data    = restore->buf,
        .dataend = restore->buf + restore->buf_sz,
        .valloc  = restore->valloc };
  int decode_err = fd_solana_manifest_decode( manifest, &decode );
  if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) {
    /* TODO: The types generator does not yet handle OOM correctly.
             OOM failures won't always end up here, but could also
             result in a NULL pointer dereference. */
    FD_LOG_WARNING(( "fd_solana_manifest_decode failed (%d)", decode_err ));
    return EINVAL;
  }

  /* Move over accounts DB fields */

  fd_solana_accounts_db_fields_t accounts_db = manifest->accounts_db;
  fd_memset( &manifest->accounts_db, 0, sizeof(fd_solana_accounts_db_fields_t) );

  /* Remember slot number */

  ulong slot = manifest->bank.slot;

  /* Move over objects and recover state
     This destroys all remaining fields with the slot context valloc. */

  int err = restore->cb_manifest( restore->cb_manifest_ctx, manifest );

  /* Read AccountVec map */

  if( FD_LIKELY( !err ) )
    err = fd_snapshot_accv_index( restore->accv_map, &accounts_db );

  /* Discard superfluous fields that the callback didn't move */

  fd_bincode_destroy_ctx_t destroy = { .valloc = restore->valloc };
  fd_solana_accounts_db_fields_destroy( &accounts_db, &destroy );

  /* Discard buffer to reclaim heap space (which could be used by
     fd_funk accounts instead) */

  fd_snapshot_restore_discard_buf( restore );

  restore->slot          = slot;
  restore->manifest_done = 1;
  return err;
}

/* fd_snapshot_restore_accv_prepare prepares for consumption of an
   account vec file. */

static int
fd_snapshot_restore_accv_prepare( fd_snapshot_restore_t * const restore,
                                  fd_tar_meta_t const *   const meta,
                                  ulong                   const real_sz ) {

  if( FD_UNLIKELY( !fd_snapshot_restore_prepare_buf( restore, FD_SNAPSHOT_RESTORE_BUFSZ ) ) ) {
    FD_LOG_WARNING(( "Failed to allocate read buffer while restoring accounts from snapshot" ));
    return ENOMEM;
  }

  /* Parse file name */
  ulong id, slot;
  if( FD_UNLIKELY( sscanf( meta->name, "accounts/%lu.%lu", &slot, &id )!=2 ) ) {
    /* Ignore entire file if file name invalid */
    restore->state  = STATE_DONE;
    restore->buf_sz = 0UL;
    return 0;
  }

  /* Reject if slot number is too high */
  if( FD_UNLIKELY( slot > restore->slot ) ) {
    FD_LOG_WARNING(( "%s has slot number %lu, which exceeds bank slot number %lu",
                     meta->name, slot, restore->slot ));
    restore->failed = 1;
    return EINVAL;
  }

  /* Lookup account vec file size */
  fd_snapshot_accv_key_t key = { .slot = slot, .id = id };
  fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_query( restore->accv_map, key, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    /* Ignore account vec files that are not explicitly mentioned in the
       manifest. */
    FD_LOG_DEBUG(( "Ignoring %s (sz %lu)", meta->name, real_sz ));
    restore->state  = STATE_DONE;
    restore->buf_sz = 0UL;
    return 0;
  }
  ulong sz = rec->sz;

  /* Validate the supposed file size against real size */
  if( FD_UNLIKELY( sz > real_sz ) ) {
    FD_LOG_WARNING(( "AppendVec %lu.%lu is %lu bytes long according to manifest, but actually only %lu bytes",
                     slot, id, sz, real_sz ));
    restore->failed = 1;
    return EINVAL;
  }
  restore->accv_sz   = sz;
  restore->accv_slot = slot;
  restore->accv_id   = id;

  /* Prepare read of account header */
  FD_LOG_DEBUG(( "Loading account vec %s", meta->name ));
  return fd_snapshot_expect_account_hdr( restore );
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

  /* We don't support streaming manifest deserialization yet.  Thus,
     buffer the whole manifest in one place. */
  if( FD_UNLIKELY( !fd_snapshot_restore_prepare_buf( restore, sz ) ) ) {
    restore->failed = 1;
    return ENOMEM;
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
  if( restore->failed ) return EINVAL;

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
      restore->failed = 1;
      return EINVAL;
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
  uchar const * end = fd_snapshot_read_buffered( restore, buf, bufsz );
  restore->accv_sz -= (ulong)(end-buf);
  if( fd_snapshot_read_is_complete( restore ) )
    if( FD_UNLIKELY( 0!=fd_snapshot_restore_account_hdr( restore ) ) )
      return NULL;
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
  if( FD_UNLIKELY( data_sz > restore->accv_sz ) )
    FD_LOG_CRIT(( "OOB account vec read: data_sz=%lu accv_sz=%lu", data_sz, restore->accv_sz ));

  buf               += data_sz;
  bufsz             -= data_sz;
  restore->acc_sz   -= data_sz;
  restore->accv_sz  -= data_sz;

  if( restore->acc_sz == 0UL ) {
    ulong pad_sz = fd_ulong_min( fd_ulong_min( restore->acc_pad, bufsz ), restore->accv_sz );
    buf              += pad_sz;
    bufsz            -= pad_sz;
    restore->acc_pad -= pad_sz;
    restore->accv_sz -= pad_sz;

    if( restore->accv_sz == 0UL ) {
      restore->state = STATE_IGNORE;
      return buf;
    }
    if( restore->acc_pad == 0UL )
      return (0==fd_snapshot_expect_account_hdr( restore )) ? buf : NULL;
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
    int err = fd_snapshot_restore_manifest( restore );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_snapshot_restore_manifest failed" ));
      restore->failed = 1;
      return NULL;
    }
    restore->state = STATE_IGNORE;
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

  if( restore->failed ) return EINVAL;

  while( bufsz ) {
    uchar const * buf_new = fd_snapshot_restore_chunk1( restore, buf, bufsz );
    if( FD_UNLIKELY( !buf_new ) ) {
      FD_LOG_WARNING(( "Aborting snapshot read" ));
      return EINVAL;
    }
    bufsz -= (ulong)(buf_new-buf);
    buf    = buf_new;
  }

  return 0;
}

/* fd_snapshot_restore_t implements the consumer interface of a TAR
   reader. */

fd_tar_read_vtable_t const fd_snapshot_restore_tar_vt =
  { .file = fd_snapshot_restore_file,
    .read = fd_snapshot_restore_chunk };
