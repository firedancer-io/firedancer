#include "fd_snapshot_parser.h"
#include "fd_ssmsg.h"
#include "../../../util/archive/fd_tar.h"
#include "../../../flamenco/runtime/fd_acc_mgr.h" /* FD_ACC_SZ_MAX */

#include <errno.h>
#include <assert.h>
#include <stdio.h>

ulong fd_snapshot_accv_seed;

FD_FN_CONST ulong
fd_snapshot_parser_footprint( int accv_lg_slot_cnt ) {
  ulong map_fp = fd_snapshot_accv_map_footprint( accv_lg_slot_cnt );
  if( FD_UNLIKELY( !map_fp ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_parser_t), sizeof(fd_snapshot_parser_t) );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_accv_map_align(),  map_fp                       );
  l = FD_LAYOUT_APPEND( l, 16UL,                          1UL<<31UL                    );
  return FD_LAYOUT_FINI( l, fd_snapshot_parser_align() );
}

fd_snapshot_parser_t *
fd_snapshot_parser_new( void * mem,
                        int    accv_lg_slot_cnt,
                        void * cb_arg,
                        fd_snapshot_parser_process_manifest_fn_t manifest_cb,
                        fd_snapshot_process_acc_hdr_fn_t         acc_hdr_cb,
                        fd_snapshot_process_acc_data_fn_t        acc_data_cb ) {
  FD_ONCE_BEGIN {
    FD_TEST( fd_rng_secure( &fd_snapshot_accv_seed, sizeof(ulong) ) );
  }
  FD_ONCE_END;

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_parser_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_snapshot_parser_footprint( accv_lg_slot_cnt );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Invalid accv_lg_slot_cnt %d", accv_lg_slot_cnt ));

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_parser_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_parser_t), sizeof(fd_snapshot_parser_t) );
  void * accv_map_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_accv_map_align(),  fd_snapshot_accv_map_footprint( accv_lg_slot_cnt ) );
  void * _buf_mem             = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                          1UL<<31UL                    );
  ulong  mem_end              = FD_SCRATCH_ALLOC_FINI( l, fd_snapshot_parser_align() );
  if( FD_UNLIKELY( mem_end-(ulong)mem != footprint ) ) FD_LOG_CRIT(( "Memory layout bug detected" ));

  self->state         = SNAP_STATE_TAR;
  self->flags         = 0;
  self->manifest_done = 0;

  self->buf_sz  = 0UL;
  self->buf_ctr = 0UL;
  self->buf_max = 1UL<<31UL;

  self->accv_map = fd_snapshot_accv_map_join( fd_snapshot_accv_map_new( accv_map_mem, accv_lg_slot_cnt ) );
  FD_TEST( self->accv_map );

  self->buf = _buf_mem;

  self->manifest_cb = manifest_cb;
  self->acc_hdr_cb  = acc_hdr_cb;
  self->acc_data_cb = acc_data_cb;
  self->cb_arg      = cb_arg;

  self->metrics.accounts_files_processed = 0UL;
  self->metrics.accounts_files_total     = 0UL;
  self->metrics.accounts_processed       = 0UL;
  self->processing_accv                  = 0;
  self->goff                             = 0UL;

  /* Bound AppendVec map utilization to 75% */
  self->accv_key_max = (ulong)( (float)(1UL<<accv_lg_slot_cnt) * 0.75f );

  return self;
}

static void
fd_snapshot_parser_discard_buf( fd_snapshot_parser_t * self ) {
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;
}

static void *
fd_snapshot_parser_prepare_buf( fd_snapshot_parser_t * self,
                                 ulong              sz ) {
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;

  fd_snapshot_parser_discard_buf( self );
  if( FD_UNLIKELY( sz > self->buf_max ) ) {
    FD_LOG_WARNING(( "Alloc failed (need %lu bytes, have %lu)", sz, self->buf_max ));
    self->state = SNAP_FLAG_FAILED;
    return NULL;
  }

  return self->buf;
}

static int
fd_snapshot_parser_expect_account_hdr( fd_snapshot_parser_t * self ) {
  ulong accv_sz = self->accv_sz;
  if( accv_sz < sizeof(fd_solana_account_hdr_t) ) {
    if( FD_LIKELY( accv_sz==0UL ) ) {
      self->state = SNAP_STATE_ACCOUNT_HDR;
      return 0;
    }
    FD_LOG_WARNING(( "encountered unexpected EOF while reading account header" ));
    self->flags |= SNAP_FLAG_FAILED;
    return EINVAL;
  }

  self->state   = SNAP_STATE_ACCOUNT_HDR;
  self->buf_ctr = 0UL;
  self->buf_sz  = sizeof(fd_solana_account_hdr_t);

  return 0;
}

static int
fd_snapshot_parser_accv_prepare( fd_snapshot_parser_t * const self,
                                  fd_tar_meta_t const *  const meta,
                                  ulong                  const real_sz ) {

  if( FD_UNLIKELY( !fd_snapshot_parser_prepare_buf( self, sizeof(fd_solana_account_hdr_t) ) ) ) {
    FD_LOG_WARNING(( "Failed to allocate read buffer while restoring accounts from snapshot" ));
    return ENOMEM;
  }

  /* Parse file name */
  ulong id, slot;
  if( FD_UNLIKELY( sscanf( meta->name, "accounts/%lu.%lu", &slot, &id )!=2 ) ) {
    /* Ignore entire file if file name invalid */
    self->state = SNAP_STATE_IGNORE;
    return 0;
  }

  /* Lookup account vec file size */
  fd_snapshot_accv_key_t key = { .slot = slot, .id = id };
  fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_query( self->accv_map, key, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    /* Ignore account vec files that are not explicitly mentioned in the
        manifest. */
    FD_LOG_DEBUG(( "Ignoring %s (sz %lu)", meta->name, real_sz ));
    self->state = SNAP_STATE_IGNORE;
    return 0;
  }
  ulong sz = rec->sz;

  /* Validate the supposed file size against real size */
  if( FD_UNLIKELY( sz > real_sz ) ) {
    FD_LOG_WARNING(( "AppendVec %lu.%lu is %lu bytes long according to manifest, but actually only %lu bytes",
                     slot, id, sz, real_sz ));
    self->flags |= SNAP_FLAG_FAILED;
    return EINVAL;
  }
  self->accv_sz         = sz;
  self->accv_slot       = slot;
  self->accv_id         = id;
  self->processing_accv = 1;

  /* Prepare read of account header */
  FD_LOG_DEBUG(( "Loading account vec %s", meta->name ));
  return fd_snapshot_parser_expect_account_hdr( self );
}

/* fd_snapshot_restore_manifest_prepare prepares for consumption of the
   snapshot manifest. */

static int
fd_snapshot_parser_manifest_prepare( fd_snapshot_parser_t * self,
                                      ulong                  sz ) {
  /* Only read once */
  if( self->manifest_done ) {
    FD_LOG_WARNING(( "Snapshot file contains multiple manifests" ));
    self->state = SNAP_STATE_IGNORE;
    return 0;
  }

  /* We don't support streaming manifest deserialization yet.  Thus,
     buffer the whole manifest in one place. */
  if( FD_UNLIKELY( !fd_snapshot_parser_prepare_buf( self, sz ) ) ) {
    self->flags |= SNAP_FLAG_FAILED;
    return ENOMEM;
  }

  self->state  = SNAP_STATE_MANIFEST;
  self->buf_sz = sz;

  return 0;
}

static void
fd_snapshot_parser_restore_file( void *                self_,
                                 fd_tar_meta_t const * meta,
                                 ulong                 sz ) {
  fd_snapshot_parser_t * self = self_;

  self->buf_ctr = 0UL;  /* reset buffer */
  self->state   = SNAP_STATE_IGNORE;

  if( (sz==0UL) | (!fd_tar_meta_is_reg( meta )) ) return;

  /* Detect account vec files.  These are files that contain a vector
     of accounts in Solana Labs "AppendVec" format. */
  assert( sizeof("accounts/")<FD_TAR_NAME_SZ );
  if( 0==strncmp( meta->name, "accounts/", sizeof("accounts/")-1) ) {
    if( FD_UNLIKELY( !self->manifest_done ) ) {
      FD_LOG_WARNING(( "Unsupported snapshot: encountered AppendVec before manifest" ));
      self->flags |= SNAP_FLAG_FAILED;
      return;
    }
    fd_snapshot_parser_accv_prepare( self, meta, sz );
  } else if( fd_memeq( meta->name, "snapshots/status_cache", sizeof("snapshots/status_cache") ) ) {
    /* TODO */
  } else if(0==strncmp( meta->name, "snapshots/", sizeof("snapshots/")-1 ) ) {
    fd_snapshot_parser_manifest_prepare( self, sz );
  }

}

static uchar const *
fd_snapshot_parser_tar_process_hdr( fd_snapshot_parser_t * self,
                                    uchar const *          cur,
                                    uchar const *          end ) {

  fd_tar_meta_t const * hdr = (fd_tar_meta_t const *)self->buf;

  /* "ustar\x00" and "ustar  \x00" (overlaps with version) are both
     valid values for magic.  These are POSIX ustar and OLDGNU versions
     respectively. */
  if( FD_UNLIKELY( 0!=memcmp( hdr->magic, FD_TAR_MAGIC, 5UL ) ) ) {

    /* Detect EOF.  A TAR EOF is marked by 1024 bytes of zeros.
       We abort after 512 bytes. */
    int not_zero=0;
    for( ulong i=0UL; i<sizeof(fd_tar_meta_t); i++ )
      not_zero |= self->buf[ i ];
    if( !not_zero ) {
      self->flags |= SNAP_FLAG_DONE;
      return end;
    }
    /* Not an EOF, so must be a protocol error */
    ulong goff = self->goff - sizeof(fd_tar_meta_t);
    FD_LOG_WARNING(( "Invalid tar header magic at goff=0x%lx", goff ));
    FD_LOG_HEXDUMP_WARNING(( "Tar header", hdr, sizeof(fd_tar_meta_t) ));
    self->flags |= SNAP_FLAG_FAILED;
    return cur;
  }

  ulong file_sz = fd_tar_meta_get_size( hdr );
  if( FD_UNLIKELY( file_sz==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Failed to parse file size in tar header" ));
    self->flags |= SNAP_FLAG_FAILED;
    return cur;
  }
  self->tar_file_rem = file_sz;
  self->buf_ctr      = (ushort)0U;

  /* Call back to recipient */
  fd_snapshot_parser_restore_file( self, hdr, file_sz );
  return cur;
}

static uchar const *
fd_snapshot_parser_tar_read_hdr( fd_snapshot_parser_t * self,
                                 uchar const *          cur,
                                 ulong                  bufsz ) {
  uchar const * end = cur+bufsz;

  /* Skip padding */
  if( self->buf_ctr==0UL ) {
    ulong  pad_sz = fd_ulong_align_up( self->goff, 512UL ) - self->goff;
           pad_sz = fd_ulong_min( pad_sz, (ulong)( end-cur ) );
    cur += pad_sz;
  }

  /* Determine number of bytes to read */
  long chunk_sz = (long)sizeof(fd_tar_meta_t) - (long)self->buf_ctr;
  FD_TEST( chunk_sz>=0L );
  if( end-cur < chunk_sz ) chunk_sz = end-cur;

  /* Copy to header */
  fd_memcpy( self->buf + self->buf_ctr, cur, (ulong)chunk_sz );
  cur           +=        chunk_sz;
  self->buf_ctr += (ulong)chunk_sz;

  /* Handle complete header */
  if( FD_LIKELY( self->buf_ctr == sizeof(fd_tar_meta_t) ) ) {
    cur = fd_snapshot_parser_tar_process_hdr( self, cur, end );
  }

  return cur;
}

/* fd_snapshot_accv_index populates the index of account vecs.  This
   index will be used when loading accounts.  Returns errno-compatible
   error code. */

static int
fd_snapshot_parser_accv_index( fd_snapshot_parser_t *              self,
                               fd_solana_manifest_global_t const * manifest ) {
  fd_snapshot_slot_acc_vecs_global_t * slots
      = fd_solana_accounts_db_fields_storages_join( &manifest->accounts_db );
  for( ulong i=0UL; i < manifest->accounts_db.storages_len; i++ ) {
    fd_snapshot_slot_acc_vecs_global_t * slot = &slots[ i ];
    fd_snapshot_acc_vec_t * account_vecs = fd_snapshot_slot_acc_vecs_account_vecs_join( slot );

    ulong key_used_cnt      = fd_snapshot_accv_map_key_cnt( self->accv_map );
    ulong key_used_post_cnt = key_used_cnt + slot->account_vecs_len;
    if( FD_UNLIKELY( key_used_post_cnt > self->accv_key_max ) ) {
      FD_LOG_WARNING(( "Snapshot is incompatible with this Firedancer build (too many account vecs: cnt=%lu max=%lu)",
                       key_used_post_cnt, self->accv_key_max ));
      return ENOMEM;
    }

    for( ulong j=0UL; j < slot->account_vecs_len; j++ ) {
      fd_snapshot_acc_vec_t * accv = &account_vecs[ j ];

      /* Insert new AppendVec */
      fd_snapshot_accv_key_t key = { .slot = slot->slot, .id = accv->id };
      fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_insert( self->accv_map, key );
      if( FD_UNLIKELY( !rec ) ) {
        /* unreachable since map size is checked above */
        FD_LOG_WARNING(( "fd_snapshot_accv_map_insert failed" ));
        return ENOMEM;
      }

      /* Remember size */
      rec->sz = accv->file_sz;
    }

  }

  return 0;
}

/* snapshot_restore_manifest imports a snapshot manifest into the
   given slot context.  Also populates the accv index.  Destroys the
   existing bank structure. */

static void
fd_snapshot_parser_restore_manifest( fd_snapshot_parser_t * self ) {
  /* Decode manifest placing dynamic data structures onto slot context
  heap.  Once the epoch context heap is separated out, we need to
  revisit this.

  This is horrible.  Plenty of room for optimization, including:
  - Streaming decoding
  - Fixing the decoder (does 2 walks in decode_footprint, decode)
  - Unpack directly into slot_ctx */

  fd_bincode_decode_ctx_t decode = {
    .data    = self->buf,
    .dataend = self->buf + self->buf_sz
  };

  ulong total_sz = 0UL;
  int err = fd_solana_manifest_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "fd_solana_manifest_decode_footprint failed (%d)", err ));
  }

  ulong decoded_manifest_offset = fd_ulong_align_up( sizeof(fd_snapshot_manifest_t), FD_SOLANA_MANIFEST_GLOBAL_ALIGN );
  if( FD_UNLIKELY( decoded_manifest_offset+total_sz>self->manifest_bufsz ) ) {
    FD_LOG_ERR(( "Cannot decode snapshot. Insufficient scratch buffer size (need %lu, %lu raw, have %lu bytes)",
                 decoded_manifest_offset+total_sz, total_sz, self->manifest_bufsz ));
  }

  fd_solana_manifest_global_t * manifest = fd_solana_manifest_decode_global( self->manifest_buf+decoded_manifest_offset, &decode );
  fd_snapshot_manifest_init_from_solana_manifest( self->manifest_buf, manifest );

  /* Read AccountVec map */

  self->metrics.accounts_files_total = manifest->accounts_db.storages_len;
  if( FD_LIKELY( !err ) ) {
    err = fd_snapshot_parser_accv_index( self, manifest );
  }

  /* manifest cb */
  if( FD_LIKELY( self->manifest_cb ) ) self->manifest_cb( self->cb_arg, total_sz );

  /* Discard buffer to reclaim heap space */

  fd_snapshot_parser_discard_buf( self );
  self->manifest_done = 1;
}

FD_FN_PURE static inline int
fd_snapshot_parser_hdr_read_is_complete( fd_snapshot_parser_t const * self ) {
  return self->buf_ctr == self->buf_sz;
}

static uchar const *
fd_snapshot_parser_read_buffered( fd_snapshot_parser_t * self,
                        uchar const *          buf,
                        ulong                  bufsz ) {
  /* Should not be called if read is complete */
  FD_TEST( self->buf_ctr < self->buf_sz );

  /* Determine number of bytes to buffer */
  ulong sz = self->buf_sz - self->buf_ctr;
  if( sz>bufsz ) sz = bufsz;

  /* Append to buffer */
  fd_memcpy( self->buf + self->buf_ctr, buf, sz );
  self->buf_ctr += sz;

  return buf+sz;
}

static uchar const *
fd_snapshot_parser_read_discard( fd_snapshot_parser_t * self,
                                 uchar const *          buf,
                                 ulong                  bufsz ) {
  ulong avail = fd_ulong_min( bufsz, self->tar_file_rem );
  return buf + avail;
}

/* snapshot_read_manifest_chunk reads partial manifest content. */

static uchar const *
fd_snapshot_parser_read_manifest_chunk( fd_snapshot_parser_t * self,
                                        uchar const *          buf,
                                        ulong                  bufsz ) {
  uchar const * end = fd_snapshot_parser_read_buffered( self, buf, bufsz );
  ulong chunksz     = (ulong)(end - buf);
  ulong consumed_sz = chunksz;

  if( fd_snapshot_parser_hdr_read_is_complete( self ) ) {
    fd_snapshot_parser_restore_manifest( self );
    self->state = SNAP_STATE_IGNORE;
  }

  return buf+consumed_sz;
}

static int
fd_snapshot_parser_restore_account_hdr( fd_snapshot_parser_t * self ) {
  fd_solana_account_hdr_t const * hdr = fd_type_pun_const( self->buf );

  if( FD_UNLIKELY( hdr->meta.data_len > FD_ACC_SZ_MAX ) ) {
    FD_LOG_ERR(( "account data size (%lu) exceeds max (%lu) (possible memory corruption?)", hdr->meta.data_len, FD_ACC_SZ_MAX ));
  }

  ulong data_sz    = hdr->meta.data_len;
  self->acc_sz  = data_sz;
  self->acc_rem = data_sz;
  self->acc_pad = fd_ulong_align_up( data_sz, 8UL ) - data_sz;

  if( FD_UNLIKELY( data_sz>(10UL<<20) ) ) {
    FD_LOG_ERR(( "Oversize account found (%lu bytes)", data_sz ));
  }

  if( FD_LIKELY( self->acc_hdr_cb ) ) {
    self->acc_hdr_cb(  self->cb_arg, hdr );
    self->metrics.accounts_processed++;
  }

  /* Next step */
  if( FD_LIKELY( data_sz == 0UL ) ) {
    return fd_snapshot_parser_expect_account_hdr( self );
  }

  self->state   = SNAP_STATE_ACCOUNT_DATA;
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;
  return 0;
}

static uchar const *
fd_snapshot_parser_read_account_hdr_chunk( fd_snapshot_parser_t * self,
                                           uchar const *          buf,
                                           ulong                  bufsz ) {
  if( FD_UNLIKELY( !self->accv_sz ) ) {
    /* Reached end of AppendVec */
    self->state   = SNAP_STATE_IGNORE;
    self->buf_ctr = self->buf_sz = 0UL;
    return buf;
  }
  bufsz = fd_ulong_min( bufsz, self->accv_sz );

  uchar const * buf_next = fd_snapshot_parser_read_buffered( self, buf, bufsz );
  ulong hdr_read = (ulong)(buf_next-buf);
  self->accv_sz -= hdr_read;
  bufsz         -= hdr_read;

  // ulong peek_sz = 0UL;
  if( FD_LIKELY( fd_snapshot_parser_hdr_read_is_complete( self ) ) ) {
    if( FD_UNLIKELY( 0!=fd_snapshot_parser_restore_account_hdr( self ) ) ) {
      return buf; /* parse error */
    }
    // peek_sz = fd_ulong_min( self->acc_rem, bufsz );
  }

  // self->acc_rem -= peek_sz;
  // self->accv_sz -= peek_sz;
  // buf_next         += peek_sz;

  return buf_next;
}

static uchar const *
fd_snapshot_parser_read_account_chunk( fd_snapshot_parser_t * self,
                                       uchar const *          buf,
                                       ulong                  bufsz ) {

  ulong chunk_sz = fd_ulong_min( self->acc_rem, bufsz );
  if( FD_UNLIKELY( chunk_sz > self->accv_sz ) )
    FD_LOG_CRIT(( "OOB account vec read: chunk_sz=%lu accv_sz=%lu", chunk_sz, self->accv_sz ));

  if( FD_LIKELY( chunk_sz ) ) {

    /* TODO: make callback here */
    if( FD_LIKELY( self->acc_data_cb ) ) self->acc_data_cb( self->cb_arg, buf, chunk_sz );

    self->acc_rem -= chunk_sz;
    self->accv_sz -= chunk_sz;
    buf           += chunk_sz;
    bufsz         -= chunk_sz;

  }

  if( FD_UNLIKELY( self->acc_rem == 0UL ) ) {
    ulong pad_sz = fd_ulong_min( fd_ulong_min( self->acc_pad, bufsz ), self->accv_sz );
    buf              += pad_sz;
    bufsz            -= pad_sz;
    self->acc_pad -= pad_sz;
    self->accv_sz -= pad_sz;

    if( FD_UNLIKELY( self->accv_sz == 0UL ) ) {
      self->state = SNAP_STATE_IGNORE;
      return buf;
    }
    if( FD_UNLIKELY( self->acc_pad == 0UL ) ) {
      return (0==fd_snapshot_parser_expect_account_hdr( self )) ? buf : NULL;
    }
  }

  return buf;
}

uchar const *
fd_snapshot_parser_process_chunk( fd_snapshot_parser_t * self,
                                  uchar const *          buf,
                                  ulong                  bufsz ) {
  uchar const * buf_next = NULL;
  if( FD_UNLIKELY( self->state==SNAP_STATE_TAR ) ) {
    buf_next       = fd_snapshot_parser_tar_read_hdr( self, buf, bufsz );
    ulong consumed = (ulong)buf_next - (ulong)buf;
    self->goff    += consumed;
    self->goff    += self->tar_file_rem;
    return buf_next;
  }

  bufsz = fd_ulong_min( bufsz, self->tar_file_rem );

  switch( self->state ) {
  case SNAP_STATE_ACCOUNT_DATA:
    buf_next = fd_snapshot_parser_read_account_chunk( self, buf, bufsz );
    break;
  case SNAP_STATE_ACCOUNT_HDR:
    buf_next = fd_snapshot_parser_read_account_hdr_chunk( self, buf, bufsz );
    break;
  case SNAP_STATE_IGNORE:
    buf_next = fd_snapshot_parser_read_discard( self, buf, bufsz );
    break;
  case SNAP_STATE_MANIFEST:
    buf_next = fd_snapshot_parser_read_manifest_chunk( self, buf, bufsz );
    break;
  default:
    FD_LOG_ERR(( "Invalid parser state %u (this is a bug)", self->state ));
  }

  ulong consumed = (ulong)buf_next - (ulong)buf;
  if( FD_UNLIKELY( consumed>bufsz ) ) FD_LOG_CRIT(( "Buffer overflow (consumed=%lu bufsz=%lu)", consumed, bufsz ));
  self->tar_file_rem -= consumed;
  if( self->tar_file_rem==0UL ) {
    fd_snapshot_parser_reset_tar( self );
    if( self->processing_accv ) {
      self->metrics.accounts_files_processed++;
    }
  }
  return buf_next;
}
