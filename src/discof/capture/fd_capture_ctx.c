#include "fd_capture_ctx.h"
#include "../../flamenco/capture/fd_solcap_writer.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../tango/fd_tango_base.h"
#include "../../tango/fseq/fd_fseq.h"

#include <time.h>

void *
fd_capture_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_capture_ctx_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_capture_ctx_t *   capture_ctx = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),   sizeof(fd_capture_ctx_t) );
  fd_solcap_writer_t * capture     = FD_SCRATCH_ALLOC_APPEND( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_capture_ctx_align() ) == (ulong)mem + fd_capture_ctx_footprint() );

  fd_memset( capture_ctx, 0, sizeof(fd_capture_ctx_t) );

  capture_ctx->capture = fd_solcap_writer_new( capture );
  if( FD_UNLIKELY( !capture_ctx->capture ) ) {
    FD_LOG_WARNING(( "failed to create solcap writer" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( capture_ctx->magic ) = FD_CAPTURE_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_capture_ctx_t *
fd_capture_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_capture_ctx_t * ctx = (fd_capture_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_capture_ctx_leave( fd_capture_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_capture_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_capture_ctx_align() ) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_capture_ctx_t * hdr = (fd_capture_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_solcap_writer_delete( hdr->capture ) == NULL ) ) {
    FD_LOG_WARNING(( "failed deleting capture" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}


static void
_wait_to_write_solcap_msg(fd_capture_link_buf_t * buf) {
  if( FD_LIKELY( buf->fseq ) ) {
    while( FD_UNLIKELY( fd_seq_diff( buf->seq, fd_fseq_query( buf->fseq ) ) > 2L ) ) {
      FD_SPIN_PAUSE();
    }
  }
}

static uint
_valid_slot_range(fd_capture_ctx_t * ctx, ulong slot) {
  /* When solcap_start_slot is 0 (not set), capture all slots */
  if( FD_LIKELY( ctx->solcap_start_slot == 0UL ) ) {
    return 1;
  }
  if( FD_UNLIKELY( slot < ctx->solcap_start_slot ) ) {
    return 0;
  }
  return 1;
}

void
fd_cap_link_translate_account_update_buf( fd_capture_ctx_t *               ctx,
                                          ulong                            txn_idx,
                                          fd_pubkey_t const *              key,
                                          fd_solana_account_meta_t const * info,
                                          ulong                            slot,
                                          uchar const *                    data,
                                          ulong                            data_sz) {

  if( FD_UNLIKELY( !ctx || !ctx->capctx_buf.buf ) ) return;
  if ( FD_UNLIKELY( !_valid_slot_range( ctx, slot ) ) ) return;

  fd_capture_link_buf_t * buf = ctx->capctx_buf.buf;

  _wait_to_write_solcap_msg(buf);

  ulong msg_sz = sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_account_update_hdr_t);

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  char * ptr = (char *)dst;

  fd_solcap_buf_msg_t msg = {
    .sig = SOLCAP_WRITE_ACCOUNT_HDR,
    .slot = slot,
    .txn_idx = txn_idx,
  };
  fd_memcpy(ptr, &msg, sizeof(fd_solcap_buf_msg_t));
  ptr += sizeof(fd_solcap_buf_msg_t);

  fd_solcap_account_update_hdr_t account_hdr = {
    .key = *key,
    .info = *info,
    .data_sz = data_sz,
  };

  fd_memcpy(ptr, &account_hdr, sizeof(fd_solcap_account_update_hdr_t));

  ulong write_cnt = (data_sz + SOLCAP_WRITE_ACCOUNT_DATA_MTU - 1) / SOLCAP_WRITE_ACCOUNT_DATA_MTU;
  if( data_sz == 0 ) write_cnt = 0;

  int has_data = (write_cnt > 0);
  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, has_data ? 0UL : 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, msg_sz, ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, msg_sz, buf->chunk0, buf->wmark );
  buf->seq++;

  if( !has_data ) return;

  for ( ulong i = 0; i < write_cnt; i++ ) {
    _wait_to_write_solcap_msg(buf);

    dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
    ptr = (char *)dst;

    ulong fragment_data_sz = SOLCAP_WRITE_ACCOUNT_DATA_MTU;
    int is_last = (i == write_cnt - 1);

    if( is_last ) {
      fragment_data_sz = data_sz - i * SOLCAP_WRITE_ACCOUNT_DATA_MTU;
    }

    fd_memcpy(ptr, &fragment_data_sz, sizeof(ulong));
    ptr += sizeof(ulong);
    fd_memcpy(ptr, data + i * SOLCAP_WRITE_ACCOUNT_DATA_MTU, fragment_data_sz);

    msg_sz = sizeof(ulong) + fragment_data_sz;

    ctl = fd_frag_meta_ctl( 0UL, 0UL, is_last ? 1UL : 0UL, 0UL );

    fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, msg_sz, ctl, 0UL, 0UL );
    buf->chunk = fd_dcache_compact_next( buf->chunk, msg_sz, buf->chunk0, buf->wmark );
    buf->seq++;
  }
}

void
fd_cap_link_translate_account_update_file(fd_capture_ctx_t *               ctx,
                                          ulong                            txn_idx,
                                          fd_pubkey_t const *              key,
                                          fd_solana_account_meta_t const * info,
                                          ulong                            slot,
                                          uchar const *                    data,
                                          ulong                            data_sz) {
  if( FD_UNLIKELY( !ctx || !ctx->capture ) ) return;
  if ( FD_UNLIKELY( !_valid_slot_range( ctx, slot ) ) ) return;

  fd_solcap_writer_t * writer = ctx->capture;

  /* Prepare message header */
  fd_solcap_buf_msg_t msg_hdr = {
    .sig = SOLCAP_WRITE_ACCOUNT_HDR,
    .slot = slot,
    .txn_idx = txn_idx,
  };

  /* Prepare account update header */
  fd_solcap_account_update_hdr_t account_update = {
    .key = *key,
    .info = *info,
    .data_sz = data_sz,
  };

  /* Write the header (EPB + internal header + account metadata) */
  uint32_t block_len = fd_solcap_write_account_hdr( writer, &msg_hdr, &account_update );

  /* Write the account data */
  fd_solcap_write_account_data( writer, data, data_sz );

  /* Write the footer */
  fd_solcap_write_ftr( writer, block_len );
}

void
fd_cap_link_write_bank_preimage_buf(fd_capture_ctx_t * ctx,
                                    ulong              slot,
                                    fd_hash_t const *  bank_hash,
                                    fd_hash_t const *  prev_bank_hash,
                                    fd_hash_t const *  accounts_lt_hash_checksum,
                                    fd_hash_t const *  poh_hash,
                                    ulong              signature_cnt) {
  if( FD_UNLIKELY( !ctx || !ctx->capctx_buf.buf ) ) return;
  if ( FD_UNLIKELY( !_valid_slot_range( ctx, slot ) ) ) return;

  fd_capture_link_buf_t * buf = ctx->capctx_buf.buf;

  _wait_to_write_solcap_msg(buf);

  uchar * dst = (uchar *)fd_chunk_to_laddr( buf->mem, buf->chunk );
  char * ptr = (char *)dst;

  fd_solcap_buf_msg_t msg = {
    .sig = SOLCAP_WRITE_BANK_PREIMAGE,
    .slot = slot,
    .txn_idx = 0
  };
  fd_memcpy(ptr, &msg, sizeof(fd_solcap_buf_msg_t));
  ptr += sizeof(fd_solcap_buf_msg_t);

  fd_solcap_bank_preimage_t bank_preimage = {
    .bank_hash = *bank_hash,
    .prev_bank_hash = *prev_bank_hash,
    .accounts_lt_hash_checksum = *accounts_lt_hash_checksum,
    .poh_hash = *poh_hash,
    .signature_cnt = signature_cnt
  };
  fd_memcpy(ptr, &bank_preimage, sizeof(fd_solcap_bank_preimage_t));
  ulong ctl = fd_frag_meta_ctl( 0UL, 1UL, 1UL, 0UL );
  fd_mcache_publish( buf->mcache, buf->depth, buf->seq, 0UL, buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_bank_preimage_t), ctl, 0UL, 0UL );
  buf->chunk = fd_dcache_compact_next( buf->chunk, sizeof(fd_solcap_buf_msg_t) + sizeof(fd_solcap_bank_preimage_t), buf->chunk0, buf->wmark );
  buf->seq++;
}

void
fd_cap_link_write_bank_preimage_file(fd_capture_ctx_t * ctx,
                                     ulong              slot,
                                     fd_hash_t const *  bank_hash,
                                     fd_hash_t const *  prev_bank_hash,
                                     fd_hash_t const *  accounts_lt_hash_checksum,
                                     fd_hash_t const *  poh_hash,
                                     ulong              signature_cnt) {
  if( FD_UNLIKELY( !ctx || !ctx->capture ) ) return;
  if ( FD_UNLIKELY( !_valid_slot_range( ctx, slot ) ) ) return;

  fd_solcap_writer_t * writer = ctx->capture;

  fd_solcap_buf_msg_t msg_hdr = {
    .sig = SOLCAP_WRITE_BANK_PREIMAGE,
    .slot = slot,
    .txn_idx = 0
  };

  fd_solcap_bank_preimage_t bank_preimage = {
    .bank_hash = *bank_hash,
    .prev_bank_hash = *prev_bank_hash,
    .accounts_lt_hash_checksum = *accounts_lt_hash_checksum,
    .poh_hash = *poh_hash,
    .signature_cnt = signature_cnt
  };

  uint32_t block_len = fd_solcap_write_bank_preimage( writer, &msg_hdr, &bank_preimage );

  fd_solcap_write_ftr( writer, block_len );
}
