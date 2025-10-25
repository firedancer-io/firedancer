#include "fd_snapin_tile_private.h"
#include "utils/fd_ssparse.h"

/**********************************************************************\

  Vinyl 101:
   - Vinyl is Firedancer's main account database
   - Vinyl is comprised of several components on-disk and in-memory
   - vinyl_bstream is a single file containing all vinyl records
   - vinyl_bstream is the source of truth
   - vinyl_meta indexes the latest revisions of all elements in
     vinyl_bstream
   - Vinyl has an in-memory caching layer, but snapin does not use it

  The snapshot loader must:
  - Load the most recent version of each account into bstream
  - Create a full vinyl_meta index of accounts

  Full snapshot logic:
  - Writes accounts to bstream
  - Synchronously populates the vinyl_meta index while writing
  - Uses batching (process_account_batch)
  - On load failure, destroys and recreates the bstream

  Incremental snapshot logic:
  - Phase 1: while reading the incremental snapshot
    - Writes accounts to bstream without updating the index
    - On load failure, undoes writes done to bstream
  - Phase 2: once read is done
    - Replays all elements written to bstream
    - Populates the vinyl_meta index while replaying

\**********************************************************************/

/* bstream_push_account writes a single account out to bstream. */

static void
bstream_push_account( fd_snapin_tile_t * ctx ) {
  FD_CRIT( !ctx->vinyl_op.data_rem, "incomplete account store" );
  FD_CRIT( ctx->vinyl_op.pair,      "no store in progres"      );

  fd_vinyl_io_t * io  = ctx->vinyl.io;

  uchar * pair    = ctx->vinyl_op.pair;
  ulong   pair_sz = ctx->vinyl_op.pair_sz;

  fd_vinyl_bstream_pair_hash( fd_vinyl_io_seed( io ), (fd_vinyl_bstream_block_t *)pair );

  ulong seq_after = fd_vinyl_io_append( io, pair, pair_sz );
  if( ctx->full ) ctx->vinyl_op.meta_ele->seq = seq_after;

  ctx->vinyl_op.pair     = NULL;
  ctx->vinyl_op.pair_sz  = 0UL;
  ctx->vinyl_op.dst      = NULL;
  ctx->vinyl_op.dst_rem  = 0UL;
  ctx->vinyl_op.meta_ele = NULL;

  ctx->metrics.accounts_inserted++;
}

/* fd_snapin_process_account_header_vinyl prepares a bstream write for
   one account (slow) */

void
fd_snapin_process_account_header_vinyl( fd_snapin_tile_t *            ctx,
                                        fd_ssparse_advance_result_t * result ) {
  FD_CRIT( !ctx->vinyl_op.dst_rem, "incomplete account store" );
  FD_CRIT( !ctx->vinyl_op.pair,    "incomplete account store" );

  fd_vinyl_io_t *   io  = ctx->vinyl.io;
  fd_vinyl_meta_t * map = ctx->vinyl.map;

  ulong val_sz = sizeof(fd_account_meta_t) + result->account_header.data_len;
  FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

  ulong   pair_sz = fd_vinyl_bstream_pair_sz( val_sz );
  uchar * pair    = (uchar *)fd_vinyl_io_alloc( io, pair_sz, FD_VINYL_IO_FLAG_BLOCKING );

  uchar * dst     = pair;
  ulong   dst_rem = pair_sz;

  FD_CRIT( dst_rem >= sizeof(fd_vinyl_bstream_phdr_t), "corruption detected" );
  fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)dst;

  phdr->ctl = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
  fd_vinyl_key_init( &phdr->key, result->account_header.pubkey, 32UL );
  phdr->info.ul[0] = result->account_header.data_len;
  phdr->info.ul[1] = result->account_header.slot;

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

  FD_CRIT( dst_rem >= result->account_header.data_len, "corruption detected" );
  if( ctx->full ) {  /* update index immediately */
    /* FIXME use publish_fast */
    fd_vinyl_meta_query_t query[1];
    int prep_err = fd_vinyl_meta_prepare( map, &phdr->key, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( prep_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "Failed to update vinyl index (index full?) (%i-%s)", prep_err, fd_map_strerror( prep_err ) ));
    fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_query_ele( query );
  //ele->memo      = already init
    ele->phdr.ctl  = phdr->ctl;
  //ele->phdr.key  = already init
    ele->phdr.info = phdr->info;
    ele->seq       = ULONG_MAX; /* later init */
    ele->line_idx  = ULONG_MAX;
    fd_vinyl_meta_publish( query );
    ctx->vinyl_op.meta_ele = ele;
  }

  ctx->vinyl_op.pair     = pair;
  ctx->vinyl_op.pair_sz  = pair_sz;
  ctx->vinyl_op.dst      = dst;
  ctx->vinyl_op.dst_rem  = dst_rem;
  ctx->vinyl_op.data_rem = result->account_header.data_len;

  if( !ctx->vinyl_op.data_rem ) {
    bstream_push_account( ctx );
  }
}

/* fd_snapin_process_account_data_vinyl continues a bstream write (slow) */

void
fd_snapin_process_account_data_vinyl( fd_snapin_tile_t *            ctx,
                                      fd_ssparse_advance_result_t * result ) {
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
  }
}

/* fd_snapin_process_account_batch_vinyl inserts a batch of unfragmented
   accounts (fast path).

   The main optimization implemented is prefetching hash map accesses to
   amortize DRAM latency. */

void
fd_snapin_process_account_batch_vinyl( fd_snapin_tile_t *            ctx,
                                       fd_ssparse_advance_result_t * result ) {
  FD_CRIT( ctx->full, "invariant violation" );

  fd_vinyl_meta_t *     const map  = ctx->vinyl.map;
  fd_vinyl_meta_ele_t * const ele0 = ctx->vinyl.map->ele;

  /* Derive map slot heads */

  ulong memo[ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong const slot_mask = map->ele_max-1UL;
  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    uchar const *  frame  = result->account_batch.batch[ i ];
    uchar const *  pubkey = frame+0x10UL;
    fd_vinyl_key_t key[1];  fd_vinyl_key_init( key, pubkey, 32UL );
    memo[ i ] = fd_vinyl_meta_key_hash( key, map->seed );;
  }

  /* Prefetch slots */

  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    ulong slot_idx = (uint)( memo[ i ]&slot_mask );
    __builtin_prefetch( ele0+slot_idx );
  }

  /* Insert map entries */

  fd_vinyl_meta_ele_t * batch_ele[ FD_SSPARSE_ACC_BATCH_MAX ];
  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    uchar const *  frame    = result->account_batch.batch[ i ];
    ulong const    data_len = fd_ulong_load_8_fast( frame+0x08UL );
    uchar const *  pubkey   = frame+0x10UL;
    fd_vinyl_key_t key[1]; fd_vinyl_key_init( key, pubkey, 32UL );

    fd_vinyl_meta_query_t query = { .memo=memo[ i ] };
    int prep_err = fd_vinyl_meta_prepare( map, key, NULL, &query, FD_MAP_FLAG_USE_HINT );
    if( FD_UNLIKELY( prep_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "Failed to update vinyl index (index full?) (%i-%s)", prep_err, fd_map_strerror( prep_err ) ));

    fd_vinyl_meta_ele_t * ele = batch_ele[ i ] = fd_vinyl_meta_query_ele( &query );
    if( FD_UNLIKELY( fd_vinyl_meta_ele_in_use( ele ) ) ) {  /* key exists */
      /* Drop current value if existing is newer */
      ulong exist_slot = ele->phdr.info.ul[ 1 ];
      if( exist_slot > result->account_batch.slot ) {
        batch_ele[ i ] = NULL;
        continue;
      }
    }

    ulong val_sz = sizeof(fd_account_meta_t) + data_len;
    FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

    fd_vinyl_bstream_phdr_t * phdr = &ele->phdr;
    phdr->ctl = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
    phdr->key = *key;
    phdr->info.ul[0] = data_len;
    phdr->info.ul[1] = result->account_batch.slot;

  //ele->memo      = already init
    ele->phdr.ctl  = phdr->ctl;
  //ele->phdr.key  = already init
    ele->phdr.info = phdr->info;
    ele->seq       = ULONG_MAX; /* later init */
    ele->line_idx  = ULONG_MAX;

    fd_vinyl_meta_publish( &query );
  }

  /* Write out to bstream */

  fd_vinyl_io_t * io = ctx->vinyl.io;
  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    fd_vinyl_meta_ele_t * ele = batch_ele[ i ];
    if( FD_UNLIKELY( !ele ) ) continue;

    uchar const *  frame      = result->account_batch.batch[ i ];
    ulong const    data_len   = fd_ulong_load_8_fast( frame+0x08UL );
    ulong          lamports   = fd_ulong_load_8_fast( frame+0x30UL );
    uchar          owner[32];   memcpy( owner, frame+0x40UL, 32UL );
    _Bool          executable = !!frame[ 0x60UL ];

    ulong val_sz = sizeof(fd_account_meta_t) + data_len;
    FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

    ulong   pair_sz = fd_vinyl_bstream_pair_sz( val_sz );
    uchar * pair    = (uchar *)fd_vinyl_io_alloc( io, pair_sz, FD_VINYL_IO_FLAG_BLOCKING );

    uchar * dst     = pair;
    ulong   dst_rem = pair_sz;

    FD_CRIT( dst_rem >= sizeof(fd_vinyl_bstream_phdr_t), "corruption detected" );
    fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)dst;
    *phdr = ele->phdr;

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

    ulong seq_after = fd_vinyl_io_append( io, pair, pair_sz );
    ele->seq = seq_after;

    ctx->metrics.accounts_inserted++;
  }
}
