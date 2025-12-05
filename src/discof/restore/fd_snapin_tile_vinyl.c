#define _DEFAULT_SOURCE /* madvise */
#include "fd_snapin_tile_private.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_vinyl_io_wd.h"

#include <errno.h>
#include <fcntl.h>     /* open */
#include <sys/mman.h>  /* mmap, madvise */
#include <sys/stat.h>  /* fstat */
#include <unistd.h>    /* close */

#include "generated/fd_snapin_tile_vinyl_seccomp.h"

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
  - Recover from load failures and retry

  Note on I/O layers:
  - io_mm is the slow/generic memory mapped I/O backend.
  - io_wd is the fast/dumb O_DIRECT backend.  Can only append, thus used
    for hot path account writing.
  - io_mm and io_wd cannot be active at the same time -- snapin will
    switch between them as necessary.

  Full snapshot logic:
  - Write accounts to bstream (io_wd)
  - Synchronously populate the vinyl_meta index while writing
  - On load failure, destroy and recreate the bstream (io_mm)

  Incremental snapshot logic:
  - Phase 1: while reading the incremental snapshot
    - Write accounts to bstream without updating the index (io_wd)
    - On load failure, undo writes done to bstream (io_mm)
  - Phase 2: once read is done
    - Replay all elements written to bstream (io_mm)
    - Populate the vinyl_meta index while replaying

\**********************************************************************/

void
fd_snapin_vinyl_privileged_init( fd_snapin_tile_t * ctx,
                                 fd_topo_t *        topo,
                                 fd_topo_tile_t *   tile ) {
  void * shmap = fd_topo_obj_laddr( topo, tile->snapin.vinyl_meta_map_obj_id  );
  void * shele = fd_topo_obj_laddr( topo, tile->snapin.vinyl_meta_pool_obj_id );

  FD_TEST( fd_vinyl_meta_join( ctx->vinyl.map, shmap, shele ) );

  /* Set up io_mm dependencies */

  char const * bstream_path = tile->snapin.vinyl_path;
  int bstream_fd = open( bstream_path, O_RDWR|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( bstream_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s,O_RDWR|O_CLOEXEC,0644) failed (%i-%s)",
                 bstream_path, errno, fd_io_strerror( errno ) ));
  }

  struct stat st;
  if( FD_UNLIKELY( fstat( bstream_fd, &st )!=0 ) ) {
    FD_LOG_ERR(( "fstat(%s) failed (%i-%s)",
                 bstream_path, errno, fd_io_strerror( errno ) ));
  }
  ulong bstream_sz = (ulong)st.st_size;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( bstream_sz, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_ERR(( "vinyl file %s has misaligned size (%lu bytes)", bstream_path, bstream_sz ));
  }

  void * bstream_mem = mmap( NULL, bstream_sz, PROT_READ|PROT_WRITE, MAP_SHARED, bstream_fd, 0 );
  if( FD_UNLIKELY( bstream_mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(sz=%lu,PROT_READ|PROT_WRITE,MAP_SHARED,path=%s,off=0) failed (%i-%s)",
                 bstream_sz, bstream_path, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=close( bstream_fd ) ) ) {  /* clean up unused fd */
    FD_LOG_ERR(( "close(fd=%i) failed (%i-%s)",
                 bstream_fd, errno, fd_io_strerror( errno ) ));
  }

  ctx->vinyl.bstream_mem = bstream_mem;
  ctx->vinyl.bstream_sz  = bstream_sz;

  FD_TEST( fd_rng_secure( &ctx->vinyl.io_seed, 8UL ) );
}

static void
io_mm_align_4k( fd_snapin_tile_t * ctx ) {
  fd_vinyl_io_t * io_mm = ctx->vinyl.io_mm;
  if( FD_UNLIKELY( io_mm->seq_future!=0UL ) ) {
    FD_LOG_CRIT(( "unexpected io_mm state (seq_future=%lu)", io_mm->seq_future ));
  }
  uchar * mmio    = fd_vinyl_mmio   ( io_mm );
  ulong   mmio_sz = fd_vinyl_mmio_sz( io_mm );

  ulong bstream_preamble = fd_ulong_align_up( FD_VINYL_BSTREAM_BLOCK_SZ, 4096UL ) - FD_VINYL_BSTREAM_BLOCK_SZ;
  FD_CRIT( bstream_preamble<=mmio_sz, "bstream too small for 4k alignment" );

  fd_memset( mmio, 0, bstream_preamble );
  io_mm->seq_present += bstream_preamble;
  io_mm->seq_future  += bstream_preamble;
}

void
fd_snapin_vinyl_unprivileged_init( fd_snapin_tile_t * ctx,
                                   fd_topo_t *        topo,
                                   fd_topo_tile_t *   tile,
                                   void *             io_mm_mem,
                                   void *             io_wd_mem ) {

  /* Set up io_mm */

  ctx->vinyl.io_mm =
    fd_vinyl_io_mm_init( io_mm_mem,
                         FD_SNAPIN_IO_SPAD_MAX,
                         ctx->vinyl.bstream_mem,
                         ctx->vinyl.bstream_sz,
                         1,
                         "accounts-v0", 12UL,
                         ctx->vinyl.io_seed );
  if( FD_UNLIKELY( !ctx->vinyl.io_mm ) ) {
    FD_LOG_ERR(( "fd_vinyl_io_mm_init failed" ));
  }

  /* Write out zero blocks to align the bstream by 4096 bytes
     (Assuming a 512 byte sync block) */

  io_mm_align_4k( ctx );

  /* Set up io_wd dependencies */

  ulong wr_link_id = fd_topo_find_tile_out_link( topo, tile, "snapin_wh", 0UL );
  if( FD_UNLIKELY( wr_link_id==ULONG_MAX ) ) FD_LOG_CRIT(( "snapin_wh link not found" ));
  fd_topo_link_t * wr_link = &topo->links[ tile->out_link_id[ wr_link_id ] ];

  if( FD_UNLIKELY( tile->snapin.snapwr_depth != fd_mcache_depth( wr_link->mcache ) ) ) {
    /* FIXME TOCTOU issue ... A malicious downstream tile could
             theoretically corrupt mcache->depth and cause an OOB access
             while snapin is still initializing.  Practically not an
             issue because the system is not exposed to attacker-
             controlled input at boot time. */
    FD_LOG_CRIT(( "snapin_wr link mcache depth %lu does not match snapwr_depth %lu",
                  fd_mcache_depth( wr_link->mcache ), tile->snapin.snapwr_depth ));
  }

  if( FD_UNLIKELY( fd_topo_link_reliable_consumer_cnt( topo, wr_link )!=1UL ) ) {
    FD_LOG_CRIT(( "snapin_wr link must have exactly one reliable consumer" ));
  }

  ulong wh_tile_id = fd_topo_find_tile( topo, "snapwh", 0UL );
  FD_TEST( wh_tile_id!=ULONG_MAX );
  fd_topo_tile_t * wh_tile = &topo->tiles[ wh_tile_id ];
  FD_TEST( wh_tile->in_cnt==1 );
  FD_TEST( wh_tile->in_link_id[0] == wr_link->id );
  FD_CRIT( 0==strcmp( topo->links[ wh_tile->in_link_id[ 0 ] ].name, "snapin_wh" ), "unexpected link found" );
  ulong const * wh_fseq = wh_tile->in_link_fseq[ 0 ];
  if( FD_UNLIKELY( !wh_fseq ) ) {
    FD_LOG_CRIT(( "snapin_wr link reliable consumer fseq not found" ));
  }

  /* Set up io_wd */

  ctx->vinyl.io_wd =
    fd_vinyl_io_wd_init( io_wd_mem,
                         ctx->vinyl.bstream_sz,
                         ctx->vinyl.io_mm->seed,
                         wr_link->mcache,
                         wr_link->dcache,
                         wh_fseq,
                         wr_link->mtu );
  if( FD_UNLIKELY( !ctx->vinyl.io_wd ) ) {
    FD_LOG_ERR(( "fd_vinyl_io_wd_init failed" ));
  }

  /* Start by using io_mm */

  ctx->vinyl.io = ctx->vinyl.io_mm;
}

ulong
fd_snapin_vinyl_seccomp( ulong                out_cnt,
                         struct sock_filter * out ) {
  populate_sock_filter_policy_fd_snapin_tile_vinyl( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snapin_tile_vinyl_instr_cnt;
}

static void
vinyl_mm_sync( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( 0!=msync( ctx->vinyl.bstream_mem, ctx->vinyl.bstream_sz, MS_SYNC ) ) ) {
    FD_LOG_ERR(( "msync(addr=%p,sz=%lu,MS_SYNC) failed (%i-%s)",
                 (void *)ctx->vinyl.bstream_mem, ctx->vinyl.bstream_sz,
                 errno, fd_io_strerror( errno ) ));
  }
}

/* Faster vinyl meta accesses *****************************************/

static fd_vinyl_meta_ele_t *
fd_vinyl_meta_prepare_nolock( fd_vinyl_meta_t *      join,
                              fd_vinyl_key_t const * key,
                              ulong                  memo ) {
  fd_vinyl_meta_ele_t * ele0      = join->ele;
  ulong                 ele_max   = join->ele_max;
  ulong                 probe_max = join->probe_max;
  void *                ctx       = join->ctx;

  ulong start_idx = memo & (ele_max-1UL);

  for(;;) {

    ulong ele_idx = start_idx;

    for( ulong probe_rem=probe_max; probe_rem; probe_rem-- ) {
      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;

      if( FD_LIKELY( fd_vinyl_meta_private_ele_is_free( ctx, ele ) ) || /* opt for low collision */
          (
            FD_LIKELY( ele->memo==memo                        ) &&
            FD_LIKELY( fd_vinyl_key_eq( &ele->phdr.key, key ) ) /* opt for already in map */
          ) ) {
        return ele;
      }

      ele_idx = (ele_idx+1UL) & (ele_max-1UL);
    }

    return NULL;

  }

  /* never get here */
}

/* Transactional APIs *************************************************/

void
fd_snapin_vinyl_txn_begin( fd_snapin_tile_t * ctx ) {
  FD_CRIT( !ctx->vinyl.txn_active, "txn_begin called while already in txn" );
  FD_CRIT( ctx->vinyl.io==ctx->vinyl.io_mm, "vinyl not in io_mm mode" );
  fd_vinyl_io_t * io = ctx->vinyl.io_mm;

  /* Finish any outstanding writes */
  int commit_err = fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( commit_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_commit failed (%i-%s)", commit_err, fd_vinyl_strerror( commit_err ) ));

  ctx->vinyl.txn_seq    = io->seq_present;
  ctx->vinyl.txn_active = 1;
}

void
fd_snapin_vinyl_txn_commit( fd_snapin_tile_t * ctx ) {
  FD_CRIT( ctx->vinyl.txn_active, "txn_commit called while not in txn" );
  FD_CRIT( ctx->vinyl.io==ctx->vinyl.io_mm, "vinyl not in io_mm mode" );
  fd_vinyl_io_t * io = ctx->vinyl.io_mm;

  long dt = -fd_log_wallclock();

  /* Finish any outstanding writes */

  int commit_err = fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( commit_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_commit failed (%i-%s)", commit_err, fd_vinyl_strerror( commit_err ) ));

  /* Hint to kernel to start prefetching to speed up reads */

  uchar * mmio      = fd_vinyl_mmio   ( io ); FD_TEST( mmio );
  ulong   mmio_sz   = fd_vinyl_mmio_sz( io );

  ulong txn_seq0 = ctx->vinyl.txn_seq;
  ulong txn_seq1 = ctx->vinyl.io_mm->seq_present;
  FD_LOG_INFO(( "vinyl txn_commit starting for seq [%lu,%lu)", txn_seq0, txn_seq1 ));
  ulong txn_sz   = txn_seq1-txn_seq0;
  FD_CRIT( fd_vinyl_seq_le( txn_seq0, txn_seq1 ), "invalid txn seq range" );
  FD_CRIT( txn_seq1 <= mmio_sz,                   "invalid txn seq range" );
  if( FD_UNLIKELY( fd_vinyl_seq_eq( txn_seq0, txn_seq1 ) ) ) return;

  void *  madv_base = (void *)fd_ulong_align_dn( (ulong)mmio+txn_seq0, FD_SHMEM_NORMAL_PAGE_SZ );
  ulong   madv_sz   = /*    */fd_ulong_align_up(             txn_sz,   FD_SHMEM_NORMAL_PAGE_SZ );
  if( FD_UNLIKELY( madvise( madv_base, madv_sz, MADV_SEQUENTIAL ) ) ) {
    FD_LOG_WARNING(( "madvise(addr=%p,sz=%lu,MADV_SEQUENTIAL) failed (%i-%s)",
                     madv_base, madv_sz,
                     errno, fd_io_strerror( errno ) ));
  }

  /* Replay incremental account updates */

  fd_vinyl_meta_t * meta_map = ctx->vinyl.map;
  for( ulong seq=txn_seq0; fd_vinyl_seq_lt( seq, txn_seq1 ); ) {
    fd_vinyl_bstream_block_t * block = (void *)( mmio+seq );

    /* Speculatively read block info */
    ulong                   ctl  = FD_VOLATILE_CONST( block->ctl  );
    fd_vinyl_bstream_phdr_t phdr = FD_VOLATILE_CONST( block->phdr );

    ulong val_esz    = fd_vinyl_bstream_ctl_sz  ( ctl );
    int   block_type = fd_vinyl_bstream_ctl_type( ctl );
    ulong block_sz;

    if( FD_LIKELY( block_type==FD_VINYL_BSTREAM_CTL_TYPE_PAIR ) ) {
      block_sz = fd_vinyl_bstream_pair_sz( val_esz );
      ulong                 memo = fd_vinyl_key_memo( meta_map->seed, &phdr.key );
      fd_vinyl_meta_ele_t * ele  = fd_vinyl_meta_prepare_nolock( meta_map, &phdr.key, memo );
      if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "fd_vinyl_meta_prepare failed (full)" ));

      /* Erase value if existing is newer */
      if( FD_UNLIKELY( fd_vinyl_meta_ele_in_use( ele ) ) ) {  /* key exists */
        ulong exist_slot = ele->phdr.info.ul[ 1 ];
        ulong cur_slot   =      phdr.info.ul[ 1 ];
        if( exist_slot > cur_slot ) {
          fd_memset( block, 0, block_sz );
          goto next;
        }
      }

      /* Overwrite map entry */
      ele->memo     = memo;
      ele->phdr     = phdr;
      ele->seq      = seq;
      ele->line_idx = ULONG_MAX;
    } else if( block_type==FD_VINYL_BSTREAM_CTL_TYPE_ZPAD ) {
      block_sz = FD_VINYL_BSTREAM_BLOCK_SZ;
    } else {
      FD_LOG_CRIT(( "unexpected block type %d", block_type ));
    }


    if( FD_UNLIKELY( !block_sz ) ) {
      FD_LOG_CRIT(( "Invalid block header at vinyl seq %lu, ctl=%016lx (zero block_sz)", seq, ctl ));
    }
    if( FD_UNLIKELY( block_sz > 64UL<<20 ) ) {
      FD_LOG_CRIT(( "Invalid block header at vinyl seq %lu, ctl=%016lx, block_sz=%lu (unreasonably large block size)", seq, ctl, block_sz ));
    }

next:
    seq += block_sz;
  }

  /* Persist above erases to disk */

  int sync_err = fd_vinyl_io_sync( ctx->vinyl.io_mm, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( sync_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_sync(io_mm) failed (%i-%s)", sync_err, fd_vinyl_strerror( sync_err ) ));
  vinyl_mm_sync( ctx );

  dt += fd_log_wallclock();
  FD_LOG_INFO(( "vinyl txn_commit took %g seconds", (double)dt/1e9 ));
}

void
fd_snapin_vinyl_txn_cancel( fd_snapin_tile_t * ctx ) {
  FD_CRIT( ctx->vinyl.txn_active, "txn_cancel called while not in txn" );
  FD_CRIT( ctx->vinyl.io==ctx->vinyl.io_mm, "vinyl not in io_mm mode" );

  fd_vinyl_io_t * io = ctx->vinyl.io_mm;
  fd_vinyl_io_rewind( io, ctx->vinyl.txn_seq );
  fd_vinyl_io_sync  ( io, FD_VINYL_IO_FLAG_BLOCKING );
}

/* Fast writer ********************************************************/

void
fd_snapin_vinyl_wd_init( fd_snapin_tile_t * ctx ) {
  FD_CRIT( ctx->vinyl.io==ctx->vinyl.io_mm, "vinyl not in io_mm mode" );

  int commit_err = fd_vinyl_io_commit( ctx->vinyl.io_mm, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( commit_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_commit(io_mm) failed (%i-%s)", commit_err, fd_vinyl_strerror( commit_err ) ));

  /* Flush io_mm */

  int sync_err = fd_vinyl_io_sync( ctx->vinyl.io_mm, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( sync_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_sync(io_mm) failed (%i-%s)", sync_err, fd_vinyl_strerror( sync_err ) ));
  vinyl_mm_sync( ctx );

  /* Synchronize sequence numbers */

  ctx->vinyl.io_wd->seq_ancient = ctx->vinyl.io_mm->seq_ancient;
  ctx->vinyl.io_wd->seq_past    = ctx->vinyl.io_mm->seq_past;
  ctx->vinyl.io_wd->seq_present = ctx->vinyl.io_mm->seq_present;
  ctx->vinyl.io_wd->seq_future  = ctx->vinyl.io_mm->seq_future;
  ctx->vinyl.io_wd->spad_used   = 0UL;

  ctx->vinyl.io = ctx->vinyl.io_wd;
}

void
fd_snapin_vinyl_wd_fini( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->vinyl.io!=ctx->vinyl.io_wd ) ) return;

  int commit_err = fd_vinyl_io_commit( ctx->vinyl.io_wd, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( commit_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_commit(io_wd) failed (%i-%s)", commit_err, fd_vinyl_strerror( commit_err ) ));

  /* Synchronize sequence numbers */

  ctx->vinyl.io_mm->seq_ancient = ctx->vinyl.io_wd->seq_ancient;
  ctx->vinyl.io_mm->seq_past    = ctx->vinyl.io_wd->seq_past;
  ctx->vinyl.io_mm->seq_present = ctx->vinyl.io_wd->seq_present;
  ctx->vinyl.io_mm->seq_future  = ctx->vinyl.io_wd->seq_future;
  ctx->vinyl.io_mm->spad_used   = 0UL;

  ctx->vinyl.io = ctx->vinyl.io_mm;
}

/* bstream_push_account writes a single account out to bstream. */

static void
bstream_push_account( fd_snapin_tile_t * ctx ) {
  FD_CRIT( !ctx->vinyl_op.data_rem, "incomplete account store" );
  FD_CRIT( ctx->vinyl_op.pair,      "no store in progres"      );

  fd_vinyl_io_t * io  = ctx->vinyl.io;

  uchar * pair    = ctx->vinyl_op.pair;
  ulong   pair_sz = ctx->vinyl_op.pair_sz;

  ulong seq_after = fd_vinyl_io_append( io, pair, pair_sz );
  if( ctx->full ) ctx->vinyl_op.meta_ele->seq = seq_after;

  ctx->vinyl_op.pair     = NULL;
  ctx->vinyl_op.pair_sz  = 0UL;
  ctx->vinyl_op.dst      = NULL;
  ctx->vinyl_op.dst_rem  = 0UL;
  ctx->vinyl_op.meta_ele = NULL;

  ctx->metrics.accounts_inserted++;
}

/* bstream_alloc is a faster version of fd_vinyl_io_alloc.  Indirect
   calls have significant overhead on Zen 5. */

static uchar *
bstream_alloc( fd_vinyl_io_t * io,
               ulong           sz,
               int             flags ) {
  if( FD_LIKELY( io->impl==&fd_vinyl_io_wd_impl ) )
    return fd_vinyl_io_wd_alloc( io, sz, flags );
  return fd_vinyl_io_alloc( io, sz, flags );
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
  uchar * pair    = bstream_alloc( io, pair_sz, FD_VINYL_IO_FLAG_BLOCKING );

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
  meta->dlen       = (uint)result->account_header.data_len;
  meta->executable = (uchar)result->account_header.executable;

  dst     += sizeof(fd_account_meta_t);
  dst_rem -= sizeof(fd_account_meta_t);

  FD_CRIT( dst_rem >= result->account_header.data_len, "corruption detected" );
  if( ctx->full ) {  /* update index immediately */
    ulong                 memo = fd_vinyl_key_memo( map->seed, &phdr->key );
    fd_vinyl_meta_ele_t * ele  = fd_vinyl_meta_prepare_nolock( map, &phdr->key, memo );
    if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "Failed to update vinyl index (full)" ));

    if( FD_UNLIKELY( fd_vinyl_meta_ele_in_use( ele ) ) ) {
      /* Drop current value if existing is newer */
      ulong exist_slot = ele->phdr.info.ul[ 1 ];
      if( exist_slot > result->account_header.slot ) {
        ctx->vinyl_op.pair = NULL;
        return;
      }
    }

    ele->memo      = memo;
    ele->phdr.ctl  = phdr->ctl;
    ele->phdr.key  = phdr->key;
    ele->phdr.info = phdr->info;
    ele->seq       = ULONG_MAX; /* later init */
    ele->line_idx  = ULONG_MAX;
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
  if( FD_UNLIKELY( !ctx->vinyl_op.pair ) ) return; /* ignored account */

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
  fd_vinyl_meta_t *     const map  = ctx->vinyl.map;
  fd_vinyl_meta_ele_t * const ele0 = ctx->vinyl.map->ele;

  /* Derive map slot heads */

  ulong memo[ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong const slot_mask = map->ele_max-1UL;
  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    uchar const *  frame  = result->account_batch.batch[ i ];
    uchar const *  pubkey = frame+0x10UL;
    fd_vinyl_key_t key[1];  fd_vinyl_key_init( key, pubkey, 32UL );
    memo[ i ] = fd_vinyl_key_memo( map->seed, key );
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

    fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_prepare_nolock( map, key, memo[ i ] );
    if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "Failed to update vinyl index (full)" ));
    batch_ele[ i ] = ele;

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
    phdr->info.val_sz = (uint)val_sz;
    phdr->info.ul[1]  = result->account_batch.slot;

    ele->memo      = memo[ i ];
    ele->phdr.ctl  = phdr->ctl;
    ele->phdr.key  = *key;
    ele->phdr.info = phdr->info;
    ele->seq       = ULONG_MAX; /* later init */
    ele->line_idx  = ULONG_MAX;
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
    uchar * pair    = fd_vinyl_io_wd_alloc_fast( io, pair_sz );
    if( FD_UNLIKELY( !pair ) ) {
      pair = fd_vinyl_io_wd_alloc( io, pair_sz, FD_VINYL_IO_FLAG_BLOCKING );
    }

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

void
fd_snapin_vinyl_shutdown( fd_snapin_tile_t * ctx ) {
  int commit_err = fd_vinyl_io_commit( ctx->vinyl.io, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( commit_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_commit(io) failed (%i-%s)", commit_err, fd_vinyl_strerror( commit_err ) ));
  int sync_err = fd_vinyl_io_sync( ctx->vinyl.io_mm, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( sync_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_sync(io_mm) failed (%i-%s)", sync_err, fd_vinyl_strerror( sync_err ) ));
  vinyl_mm_sync( ctx );

  fd_vinyl_io_wd_ctrl( ctx->vinyl.io_wd, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL );
}

void
fd_snapin_read_account_vinyl( fd_snapin_tile_t *  ctx,
                              void const *        acct_addr,
                              fd_account_meta_t * meta,
                              uchar *             data,
                              ulong               data_max ) {
  if( FD_UNLIKELY( ctx->vinyl.io!=ctx->vinyl.io_mm ) ) {
    FD_LOG_CRIT(( "vinyl not in io_mm mode" ));
  }

  memset( meta, 0, sizeof(fd_account_meta_t) );

  /* Query database index */

  fd_vinyl_key_t key[1];
  fd_vinyl_key_init( key, acct_addr, 32UL );
  ulong memo = fd_vinyl_key_memo( ctx->vinyl.map->seed, key );
  fd_vinyl_meta_ele_t const * ele = fd_vinyl_meta_prepare_nolock( ctx->vinyl.map, key, memo );
  if( FD_UNLIKELY( !ele || !fd_vinyl_meta_ele_in_use( ele ) ) ) {
    /* account not found */
    return;
  }

  uchar * mmio    = fd_vinyl_mmio   ( ctx->vinyl.io_mm );
  ulong   mmio_sz = fd_vinyl_mmio_sz( ctx->vinyl.io_mm );

  /* Validate index record */

  ulong const seq0        = ele->seq;
  ulong const ctl         = ele->phdr.ctl;
  int   const ctl_type    = fd_vinyl_bstream_ctl_type( ctl );
  ulong const val_esz     = fd_vinyl_bstream_ctl_sz  ( ctl );
  ulong const pair_sz     = fd_vinyl_bstream_pair_sz( val_esz );
  ulong const seq1        = seq0 + pair_sz;
  ulong const seq_past    = ctx->vinyl.io->seq_past;
  ulong const seq_present = ctx->vinyl.io->seq_present;
  if( FD_UNLIKELY( ctl_type!=FD_VINYL_BSTREAM_CTL_TYPE_PAIR ) ) {
    FD_LOG_CRIT(( "corrupt bstream record in index: ctl=%016lx", ctl ));
  }
  if( FD_UNLIKELY( val_esz<sizeof(fd_account_meta_t) ||
                   val_esz>sizeof(fd_account_meta_t)+FD_RUNTIME_ACC_SZ_MAX ) ) {
    FD_LOG_CRIT(( "corrupt bstream record in index: val_esz=%lu", val_esz ));
  }
  int bad_past = !(fd_vinyl_seq_le( seq_past, seq0 ) & fd_vinyl_seq_lt( seq0, seq1 ) & fd_vinyl_seq_le( seq1, seq_present ));
  if( FD_UNLIKELY( bad_past ) ) {
    FD_LOG_CRIT(( "corrupt bstream record in index: seq[%lu,%lu) not in [seq_past=%lu,seq_present=%lu)",
                  seq0, seq1, seq_past, seq_present ));
  }

  /* Map seq range to underlying device
     In the snapshot loader, it is safe to assume that bstream reads
     do not wrap around. */

  if( FD_UNLIKELY( seq1>mmio_sz ) ) {
    FD_LOG_CRIT(( "corrupt bstream record in index: seq[%lu,%lu) exceeds bstream addressable range [0,%lu)",
                  seq0, seq1, mmio_sz ));
  }

  /* Read from bstream */

  ulong seq_meta = seq0     + sizeof(fd_vinyl_bstream_phdr_t);
  ulong seq_data = seq_meta + sizeof(fd_account_meta_t);

  memcpy( meta, mmio+seq_meta, sizeof(fd_account_meta_t) );
  if( FD_UNLIKELY( sizeof(fd_account_meta_t)+(ulong)meta->dlen > val_esz ) ) {
    FD_LOG_CRIT(( "corrupt bstream record: seq0=%lu val_esz=%lu dlen=%u", seq0, val_esz, meta->dlen ));
  }
  if( FD_UNLIKELY( meta->dlen > data_max ) ) {
    FD_BASE58_ENCODE_32_BYTES( acct_addr, acct_addr_b58 );
    FD_LOG_WARNING(( "failed to read account %s: account data size (%lu bytes) exceeds buffer size (%lu bytes)",
                     acct_addr_b58, (ulong)meta->dlen, data_max ));
  }
  memcpy( data, mmio+seq_data, meta->dlen );
}
