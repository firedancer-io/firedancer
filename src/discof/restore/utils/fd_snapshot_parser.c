#include "fd_snapshot_parser.h"
#include "fd_ssmanifest_parser.h"

#include "../../../util/archive/fd_tar.h"

#include <errno.h>
#include <assert.h>
#include <stdio.h>

FD_FN_CONST ulong
fd_snapshot_parser_footprint( ulong max_acc_vecs ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_parser_t), sizeof(fd_snapshot_parser_t)                   );
  l = FD_LAYOUT_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint( max_acc_vecs ) );
  l = FD_LAYOUT_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()               );
  l = FD_LAYOUT_APPEND( l, 16UL,                          1UL<<20UL                                      );
  return FD_LAYOUT_FINI( l, fd_snapshot_parser_align() );
}

fd_snapshot_parser_t *
fd_snapshot_parser_new( void * mem,
                        void * cb_arg,
                        ulong  seed,
                        ulong  max_acc_vecs,
                        fd_snapshot_parser_process_manifest_fn_t manifest_cb,
                        fd_slot_delta_parser_process_group_fn_t  status_cache_group_cb,
                        fd_slot_delta_parser_process_entry_fn_t  status_cache_entry_cb,
                        fd_snapshot_process_acc_hdr_fn_t         acc_hdr_cb,
                        fd_snapshot_process_acc_data_fn_t        acc_data_cb ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_parser_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_parser_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_parser_t), sizeof(fd_snapshot_parser_t)                   );
  void * parser               = FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint( max_acc_vecs ) );
  void * _slot_delta_parser   = FD_SCRATCH_ALLOC_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()               );
  void * _buf_mem             = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                          1UL<<20UL                                      );

  self->state         = SNAP_STATE_TAR;
  self->flags         = 0;
  self->manifest_done = 0;

  self->buf_sz  = 0UL;
  self->buf_ctr = 0UL;
  self->buf_max = 1UL<<20UL;

  self->manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( parser, max_acc_vecs, seed ) );
  FD_TEST( self->manifest_parser );

  self->slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( _slot_delta_parser ) );
  FD_TEST( self->slot_delta_parser );

  self->buf = _buf_mem;

  self->manifest_cb           = manifest_cb;
  self->status_cache_group_cb = status_cache_group_cb;
  self->status_cache_entry_cb = status_cache_entry_cb;
  self->acc_hdr_cb            = acc_hdr_cb;
  self->acc_data_cb           = acc_data_cb;
  self->cb_arg                = cb_arg;

  self->metrics.accounts_files_processed = 0UL;
  self->metrics.accounts_files_total     = 0UL;
  self->metrics.accounts_processed       = 0UL;
  self->processing_accv                  = 0;
  self->goff                             = 0UL;
  return self;
}

static void
fd_snapshot_parser_discard_buf( fd_snapshot_parser_t * self ) {
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;
}

static void *
fd_snapshot_parser_prepare_buf( fd_snapshot_parser_t * self,
                                 ulong                 sz ) {
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;

  fd_snapshot_parser_discard_buf( self );
  if( FD_UNLIKELY( sz > self->buf_max ) ) {
    FD_LOG_WARNING(( "Alloc failed (need %lu bytes, have %lu)", sz, self->buf_max ));
    self->flags |= SNAP_FLAG_FAILED;
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

  ulong sz = fd_ssmanifest_acc_vec_sz( self->manifest_parser, slot, id );
  if( FD_UNLIKELY( sz==ULONG_MAX ) ) {
    FD_LOG_DEBUG(( "Ignoring %s (sz %lu)", meta->name, real_sz ));
    self->state = SNAP_STATE_IGNORE;
    return 0;
  }

  /* Validate the supposed file size against real size */
  if( FD_UNLIKELY( sz>real_sz ) ) {
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
  // FD_LOG_DEBUG(( "Loading account vec %s", meta->name ));
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

  self->state  = SNAP_STATE_MANIFEST;
  self->buf_sz = sz;

  return 0;
}

static int
fd_snapshot_parser_status_cache_prepare( fd_snapshot_parser_t * self,
                                         ulong                  sz ) {
  /* Only read once */
  if( FD_UNLIKELY( self->status_cache_done) ) {
    FD_LOG_WARNING(( "Snapshot file contains multiple status caches" ));
    self->state = SNAP_STATE_IGNORE;
    return 0;
  }

  self->state  = SNAP_STATE_STATUS_CACHE;
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
    fd_snapshot_parser_status_cache_prepare( self, sz );
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
  FD_TEST( self->buf_ctr==0UL );

  int result = fd_ssmanifest_parser_consume( self->manifest_parser, buf, bufsz );
  if( -1==result ) self->flags |= SNAP_FLAG_FAILED;
  if( 0==result ) {
    /* manifest cb */
    if( FD_LIKELY( self->manifest_cb ) ) self->manifest_cb( self->cb_arg );

    /* Discard buffer to reclaim heap space */

    fd_snapshot_parser_discard_buf( self );
    self->manifest_done = 1;
    self->state = SNAP_STATE_IGNORE;
  }

  return buf+bufsz;
}

static uchar const *
fd_snapshot_parser_read_status_cache_chunk( fd_snapshot_parser_t * self,
                                            uchar const *          buf,
                                            ulong                  bufsz ) {
  int result = fd_slot_delta_parser_consume( self->slot_delta_parser, buf, bufsz );
  if( FD_UNLIKELY( -1==result ) ) self->flags |= SNAP_FLAG_FAILED;
  if( FD_LIKELY( 0==result ) ) {
    self->status_cache_done = 1;
    self->state = SNAP_STATE_IGNORE;
  }

  return buf+bufsz;
}

static int
fd_snapshot_parser_restore_account_hdr( fd_snapshot_parser_t * self ) {
  fd_solana_account_hdr_t const * hdr = fd_type_pun_const( self->buf );

  if( FD_UNLIKELY( hdr->meta.data_len > FD_RUNTIME_ACC_SZ_MAX ) ) {
    FD_LOG_ERR(( "account data size (%lu) exceeds max (%lu) (possible memory corruption?)", hdr->meta.data_len, FD_RUNTIME_ACC_SZ_MAX ));
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

  if( FD_LIKELY( fd_snapshot_parser_hdr_read_is_complete( self ) ) ) {
    if( FD_UNLIKELY( 0!=fd_snapshot_parser_restore_account_hdr( self ) ) ) {
      return buf; /* parse error */
    }
  }

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
  case SNAP_STATE_STATUS_CACHE:
    buf_next = fd_snapshot_parser_read_status_cache_chunk( self, buf, bufsz );
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
