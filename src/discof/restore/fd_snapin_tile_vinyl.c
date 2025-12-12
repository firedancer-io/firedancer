#define _DEFAULT_SOURCE /* madvise */
#include "fd_snapin_tile_private.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_vinyl_io_wd.h"

void
fd_snapin_vinyl_unprivileged_init( fd_snapin_tile_t * ctx,
                                   fd_topo_t *        topo,
                                   fd_topo_tile_t *   tile,
                                   void *             io_mm_mem,
                                   void *             io_wd_mem ) {
  /* Nothing to do */
  (void)ctx; (void)topo; (void)tile; (void)io_mm_mem; (void)io_wd_mem;
}

/* bstream_push_account finishes processing a single account (pair).
   A single fd_stem_publish is issued, and the chunk always advances
   by mtu size. */

static inline void
bstream_push_account( fd_snapin_tile_t * ctx ) {
  FD_CRIT( !ctx->vinyl_op.data_rem, "incomplete account store" );
  FD_CRIT( ctx->vinyl_op.pair,      "no store in progres"      );

  fd_stem_publish( ctx->stem, ctx->hash_out.idx, FD_SNAPSHOT_MSG_DATA/*sig*/, ctx->hash_out.chunk, 1UL/*sz=acc_cnt*/, 0UL, 0UL/*tsorig*/, 0UL/*tspub*/ );
  ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, ctx->hash_out.mtu, ctx->hash_out.chunk0, ctx->hash_out.wmark );

  ctx->vinyl_op.pair     = NULL;
  ctx->vinyl_op.pair_sz  = 0UL;
  ctx->vinyl_op.dst      = NULL;
  ctx->vinyl_op.dst_rem  = 0UL;
  ctx->vinyl_op.meta_ele = NULL;
}

/* fd_snapin_process_account_header_vinyl starts processing a
   (possibly fragmented) account (slow). */

int
fd_snapin_process_account_header_vinyl( fd_snapin_tile_t *            ctx,
                                        fd_ssparse_advance_result_t * result ) {
  FD_CRIT( !ctx->vinyl_op.dst_rem, "incomplete account store" );
  FD_CRIT( !ctx->vinyl_op.pair,    "incomplete account store" );

  ulong val_sz = sizeof(fd_account_meta_t) + result->account_header.data_len;
  FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

  ulong   pair_sz = fd_vinyl_bstream_pair_sz( val_sz );
  FD_TEST( pair_sz<=ctx->hash_out.mtu );
  uchar * pair    = fd_chunk_to_laddr( ctx->hash_out.mem, ctx->hash_out.chunk );

  uchar * dst     = pair;
  ulong   dst_rem = pair_sz;

  FD_CRIT( dst_rem >= sizeof(fd_vinyl_bstream_phdr_t), "corruption detected" );
  fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)dst;

  phdr->ctl = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
  fd_vinyl_key_init( &phdr->key, result->account_header.pubkey, 32UL );
  phdr->info.val_sz = (uint)val_sz;
  phdr->info.ul[1]  = result->account_header.slot;

  dst     += sizeof(fd_vinyl_bstream_phdr_t);
  dst_rem -= sizeof(fd_vinyl_bstream_phdr_t);

  FD_CRIT( dst_rem >= sizeof(fd_account_meta_t), "corruption detected" );
  fd_account_meta_t * meta = (fd_account_meta_t *)dst;
  memset( meta, 0, sizeof(fd_account_meta_t) ); /* bulk zero */
  memcpy( meta->owner, result->account_header.owner, sizeof(fd_pubkey_t) );
  meta->lamports   = result->account_header.lamports;
  meta->slot       = result->account_header.slot;
  meta->dlen       = (uint)result->account_header.data_len;
  meta->executable = (uchar)result->account_header.executable;

  dst     += sizeof(fd_account_meta_t);
  dst_rem -= sizeof(fd_account_meta_t);

  ctx->metrics.accounts_loaded++;
  FD_CRIT( dst_rem >= result->account_header.data_len, "corruption detected" );

  ctx->vinyl_op.pair     = pair;
  ctx->vinyl_op.pair_sz  = pair_sz;
  ctx->vinyl_op.dst      = dst;
  ctx->vinyl_op.dst_rem  = dst_rem;
  ctx->vinyl_op.data_rem = result->account_header.data_len;

  if( !ctx->vinyl_op.data_rem ) {
    bstream_push_account( ctx );
    return 1;
  }
  return 0;
}

/* fd_snapin_process_account_data_vinyl continues processing a
   fragmented account (slow). */

int
fd_snapin_process_account_data_vinyl( fd_snapin_tile_t *            ctx,
                                      fd_ssparse_advance_result_t * result ) {
  if( FD_UNLIKELY( !ctx->vinyl_op.pair ) ) return 0; /* ignored account */

  ulong chunk_sz = result->account_data.data_sz;
  if( FD_LIKELY( chunk_sz ) ) {
    FD_CRIT( chunk_sz <= ctx->vinyl_op.dst_rem,  "corruption detected" );
    FD_CRIT( chunk_sz <= ctx->vinyl_op.data_rem, "corruption detected" );
    fd_memcpy( ctx->vinyl_op.dst, result->account_data.data, chunk_sz );
    ctx->vinyl_op.dst      += chunk_sz;
    ctx->vinyl_op.dst_rem  -= chunk_sz;
    ctx->vinyl_op.data_rem -= chunk_sz;
  }
  if( !ctx->vinyl_op.data_rem ) {  /* finish store */
    bstream_push_account( ctx );
    return 1;
  }
  return 0;
}

/* fd_snapin_process_account_batch_vinyl processes a batch of unfragmented
   accounts (fast path), converting them into vinyl bstream pairs.
   A single fd_stem_publish is issued for the complete batch, and the
   chunk always advances by mtu size. */

int
fd_snapin_process_account_batch_vinyl( fd_snapin_tile_t *            ctx,
                                       fd_ssparse_advance_result_t * result ) {

  uchar * pair = fd_chunk_to_laddr( ctx->hash_out.mem, ctx->hash_out.chunk );

  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {

    uchar const *  frame      = result->account_batch.batch[ i ];
    ulong const    data_len   = fd_ulong_load_8_fast( frame+0x08UL );
    uchar const *  pubkey     = frame+0x10UL;
    fd_vinyl_key_t key[1];    fd_vinyl_key_init( key, pubkey, 32UL );
    ulong          lamports   = fd_ulong_load_8_fast( frame+0x30UL );
    uchar          owner[32]; memcpy( owner, frame+0x40UL, 32UL );
    _Bool          executable = !!frame[ 0x60UL ];

    ulong val_sz = sizeof(fd_account_meta_t) + data_len;
    FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

    ulong   pair_sz = fd_vinyl_bstream_pair_sz( val_sz );
    FD_TEST( pair_sz<=ctx->hash_out.mtu );

    uchar * dst     = pair;
    ulong   dst_rem = pair_sz;

    FD_CRIT( dst_rem >= sizeof(fd_vinyl_bstream_phdr_t), "corruption detected" );
    fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)dst;
    phdr->ctl         = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
    phdr->key         = *key;
    phdr->info.val_sz = (uint)val_sz;
    phdr->info.ul[1]  = result->account_batch.slot;

    dst     += sizeof(fd_vinyl_bstream_phdr_t);
    dst_rem -= sizeof(fd_vinyl_bstream_phdr_t);

    FD_CRIT( dst_rem >= sizeof(fd_account_meta_t), "corruption detected" );
    fd_account_meta_t * meta = (fd_account_meta_t *)dst;
    memset( meta, 0, sizeof(fd_account_meta_t) ); /* bulk zero */
    memcpy( meta->owner, owner, sizeof(fd_pubkey_t) );
    meta->lamports   = lamports;
    meta->slot       = result->account_batch.slot;
    meta->dlen       = (uint)data_len;
    meta->executable = !!executable;

    dst     += sizeof(fd_account_meta_t);
    dst_rem -= sizeof(fd_account_meta_t);

    FD_CRIT( dst_rem >= data_len, "corruption detected" );
    fd_memcpy( dst, frame+0x88UL, data_len );

    dst     += data_len;
    dst_rem -= data_len;

    pair += pair_sz;

    ctx->metrics.accounts_loaded++;
  }
  fd_stem_publish( ctx->stem, ctx->hash_out.idx, FD_SNAPSHOT_MSG_DATA/*sig*/, ctx->hash_out.chunk, FD_SSPARSE_ACC_BATCH_MAX/*sz=acc_cnt*/, 0UL, 0UL/*tsorig*/, 0UL/*tspub*/ );
  ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, ctx->hash_out.mtu, ctx->hash_out.chunk0, ctx->hash_out.wmark );
  return 1;
}

void
fd_snapin_vinyl_shutdown( fd_snapin_tile_t * ctx ) {
  (void)ctx;
}
