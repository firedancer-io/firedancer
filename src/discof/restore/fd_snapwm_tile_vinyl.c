#define _DEFAULT_SOURCE /* madvise */
#include "fd_snapwm_tile_private.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_vinyl_io_wd.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"

#include <errno.h>
#include <fcntl.h>     /* open */
#include <sys/mman.h>  /* mmap, madvise */
#include <sys/stat.h>  /* fstat */
#include <unistd.h>    /* close */

#include "generated/fd_snapwm_tile_vinyl_seccomp.h"

FD_STATIC_ASSERT( WD_WR_FSEQ_CNT_MAX<=FD_TOPO_MAX_TILE_IN_LINKS, "WD_WR_FSEQ_CNT_MAX" );

/**********************************************************************\

  Vinyl 101:
   - Vinyl is Firedancer's main account database
   - Vinyl is comprised of several components on-disk and in-memory
   - vinyl_bstream is a single file containing all vinyl records
   - vinyl_bstream is the source of truth
   - vinyl_meta indexes the latest revisions of all elements in
     vinyl_bstream
   - Vinyl has an in-memory caching layer, but snapwm does not use it

  The snapshot loader must:
  - Load the most recent version of each account into bstream
  - Create a full vinyl_meta index of accounts
  - Recover from load failures and retry

  Note on I/O layers:
  - io_mm is the slow/generic memory mapped I/O backend.
  - io_wd is the fast/dumb O_DIRECT backend.  Can only append, thus used
    for hot path account writing.
  - io_mm and io_wd cannot be active at the same time -- snapwm will
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
fd_snapwm_vinyl_privileged_init( fd_snapwm_tile_t * ctx,
                                 fd_topo_t *        topo,
                                 fd_topo_tile_t *   tile ) {
  void * shmap = fd_topo_obj_laddr( topo, tile->snapwm.vinyl_meta_map_obj_id  );
  void * shele = fd_topo_obj_laddr( topo, tile->snapwm.vinyl_meta_pool_obj_id );

  FD_TEST( fd_vinyl_meta_join( ctx->vinyl.map, shmap, shele ) );

  /* Set up io_mm dependencies */

  char const * bstream_path = tile->snapwm.vinyl_path;
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
io_mm_align_4k( fd_snapwm_tile_t * ctx ) {
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
fd_snapwm_vinyl_unprivileged_init( fd_snapwm_tile_t * ctx,
                                   fd_topo_t *        topo,
                                   fd_topo_tile_t *   tile,
                                   void *             io_mm_mem,
                                   void *             io_wd_mem ) {

  /* Set up io_mm */

  ctx->vinyl.io_mm =
    fd_vinyl_io_mm_init( io_mm_mem,
                         FD_SNAPWM_IO_SPAD_MAX,
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

  ulong wr_link_id = fd_topo_find_tile_out_link( topo, tile, "snapwm_wh", 0UL );
  if( FD_UNLIKELY( wr_link_id==ULONG_MAX ) ) FD_LOG_CRIT(( "snapwm_wh link not found" ));
  fd_topo_link_t * wr_link = &topo->links[ tile->out_link_id[ wr_link_id ] ];

  if( FD_UNLIKELY( tile->snapwm.snapwr_depth != fd_mcache_depth( wr_link->mcache ) ) ) {
    /* FIXME TOCTOU issue ... A malicious downstream tile could
             theoretically corrupt mcache->depth and cause an OOB access
             while snapwm is still initializing.  Practically not an
             issue because the system is not exposed to attacker-
             controlled input at boot time. */
    FD_LOG_CRIT(( "snapwm_wr link mcache depth %lu does not match snapwr_depth %lu",
                  fd_mcache_depth( wr_link->mcache ), tile->snapwm.snapwr_depth ));
  }

  ulong expected_wr_link_consumers_cnt = fd_topo_tile_name_cnt( topo, "snapwh" );
  if( FD_UNLIKELY( fd_topo_link_reliable_consumer_cnt( topo, wr_link )!=expected_wr_link_consumers_cnt ) ) {
    FD_LOG_CRIT(( "snapwm_wr link must have exactly %lu reliable consumers", expected_wr_link_consumers_cnt ));
  }

  ulong const * wh_fseq[WD_WR_FSEQ_CNT_MAX];
  ulong wh_fseq_cnt = 0UL;
  ulong wh_fseq_cnt_expected = fd_topo_tile_name_cnt( topo, "snapwh" );
  FD_TEST( wh_fseq_cnt_expected<=WD_WR_FSEQ_CNT_MAX );
  FD_TEST( wh_fseq_cnt_expected==fd_topo_link_reliable_consumer_cnt( topo, wr_link ) );
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ tile_idx ];
    for( ulong in_idx=0UL; in_idx<consumer_tile->in_cnt; in_idx++ ) {
      if( consumer_tile->in_link_id[ in_idx ]==wr_link->id ) {
        FD_TEST( wh_fseq_cnt<WD_WR_FSEQ_CNT_MAX );
        wh_fseq[ wh_fseq_cnt ] = consumer_tile->in_link_fseq[ in_idx ];
        wh_fseq_cnt++;
      }
    }
  }
  if( FD_UNLIKELY( wh_fseq_cnt!=wh_fseq_cnt_expected ) ) {
    FD_LOG_ERR(( "unable to find %lu fseq(s) for output link %s:%lu",
                 wh_fseq_cnt, wr_link->name, wr_link->kind_id ));
  }

  /* Set up io_wd */

  ctx->vinyl.io_wd =
    fd_vinyl_io_wd_init( io_wd_mem,
                         ctx->vinyl.bstream_sz,
                         ctx->vinyl.io_mm->seed,
                         wr_link->mcache,
                         wr_link->dcache,
                         wh_fseq,
                         wh_fseq_cnt,
                         wr_link->mtu );
  if( FD_UNLIKELY( !ctx->vinyl.io_wd ) ) {
    FD_LOG_ERR(( "fd_vinyl_io_wd_init failed" ));
  }

  /* Start by using io_mm */

  ctx->vinyl.io = ctx->vinyl.io_mm;

  ctx->vinyl.duplicate_accounts_batch_sz  = 0UL;
  ctx->vinyl.duplicate_accounts_batch_cnt = 0UL;

  fd_lthash_adder_new( &ctx->vinyl.adder );
  fd_lthash_zero( &ctx->vinyl.running_lthash );
}

ulong
fd_snapwm_vinyl_seccomp( ulong                out_cnt,
                         struct sock_filter * out ) {
  populate_sock_filter_policy_fd_snapwm_tile_vinyl( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snapwm_tile_vinyl_instr_cnt;
}

static void
vinyl_mm_sync( fd_snapwm_tile_t * ctx ) {
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
fd_snapwm_vinyl_txn_begin( fd_snapwm_tile_t * ctx ) {
  FD_CRIT( !ctx->vinyl.txn_active, "txn_begin called while already in txn" );
  FD_CRIT( ctx->vinyl.io==ctx->vinyl.io_mm, "vinyl not in io_mm mode" );
  fd_vinyl_io_t * io = ctx->vinyl.io_mm;

  /* Finish any outstanding writes */
  int commit_err = fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( commit_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_commit failed (%i-%s)", commit_err, fd_vinyl_strerror( commit_err ) ));

  ctx->vinyl.txn_seq    = io->seq_present;
  ctx->vinyl.txn_active = 1;
}

FD_FN_UNUSED static void
streamlined_hash( fd_lthash_adder_t * restrict adder,
                  fd_lthash_value_t * restrict running_lthash,
                  uchar const *       restrict _pair ) {
  uchar const * pair = _pair;
  fd_vinyl_bstream_phdr_t const * phdr = (fd_vinyl_bstream_phdr_t const *)pair;
  pair += sizeof(fd_vinyl_bstream_phdr_t);
  fd_account_meta_t const * meta = (fd_account_meta_t const *)pair;
  pair += sizeof(fd_account_meta_t);
  uchar const * data = pair;

  ulong data_len      = meta->dlen;
  const char * pubkey = phdr->key.c;
  ulong lamports      = meta->lamports;
  const uchar * owner = meta->owner;
  uchar executable = (uchar)( !meta->executable ? 0U : 1U) ;

  if( FD_UNLIKELY( data_len > FD_RUNTIME_ACC_SZ_MAX ) ) FD_LOG_ERR(( "Found unusually large account (data_sz=%lu), aborting", data_len ));
  if( FD_UNLIKELY( lamports==0UL ) ) return;

  fd_lthash_adder_push_solana_account( adder,
                                       running_lthash,
                                       pubkey,
                                       data,
                                       data_len,
                                       lamports,
                                       executable,
                                       owner );
}

void
fd_snapwm_vinyl_txn_commit( fd_snapwm_tile_t * ctx,
                            fd_stem_context_t * stem ) {
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
  fd_snapwm_vinyl_duplicate_accounts_batch_init( ctx, stem );
  fd_snapwm_vinyl_duplicate_accounts_lthash_init( ctx, stem );
  ulong dup_batch_cnt = 0UL;

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
          ctx->metrics.accounts_ignored++;
          FD_COMPILER_MFENCE();
          fd_snapwm_vinyl_duplicate_accounts_lthash_append( ctx, (uchar*)block/*pair*/ );
          FD_COMPILER_MFENCE();
          fd_memset( block, 0, block_sz );
          goto next;
        } else {
          dup_batch_cnt += (ulong)fd_snapwm_vinyl_duplicate_accounts_batch_append( ctx, &ele->phdr, ele->seq );
        }
        ctx->metrics.accounts_replaced++;
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

    if( FD_UNLIKELY( dup_batch_cnt >= FD_SNAPWM_DUP_META_BATCH_CNT_MAX ) ) {
      fd_snapwm_vinyl_duplicate_accounts_batch_fini( ctx, stem );
      FD_COMPILER_MFENCE();
      fd_snapwm_vinyl_duplicate_accounts_batch_init( ctx, stem );
      dup_batch_cnt = 0UL;
    }
  }

  /* Batch fini must be invoked before lthash fini for two reasons:
     the batch still needs to be processed downstream and there should
     be no fd_stem_publish between batch init and fini. */
  fd_snapwm_vinyl_duplicate_accounts_batch_fini( ctx, stem );
  FD_COMPILER_MFENCE();
  fd_snapwm_vinyl_duplicate_accounts_lthash_fini( ctx, stem );

  /* Persist above erases to disk */

  int sync_err = fd_vinyl_io_sync( ctx->vinyl.io_mm, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( sync_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_sync(io_mm) failed (%i-%s)", sync_err, fd_vinyl_strerror( sync_err ) ));
  vinyl_mm_sync( ctx );

  dt += fd_log_wallclock();
  FD_LOG_INFO(( "vinyl txn_commit took %g seconds", (double)dt/1e9 ));
}

void
fd_snapwm_vinyl_txn_cancel( fd_snapwm_tile_t * ctx ) {
  FD_CRIT( ctx->vinyl.txn_active, "txn_cancel called while not in txn" );
  FD_CRIT( ctx->vinyl.io==ctx->vinyl.io_mm, "vinyl not in io_mm mode" );

  fd_vinyl_io_t * io = ctx->vinyl.io_mm;
  fd_vinyl_io_rewind( io, ctx->vinyl.txn_seq );
  fd_vinyl_io_sync  ( io, FD_VINYL_IO_FLAG_BLOCKING );
}

/* Fast writer ********************************************************/

void
fd_snapwm_vinyl_wd_init( fd_snapwm_tile_t * ctx ) {
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
fd_snapwm_vinyl_wd_fini( fd_snapwm_tile_t * ctx ) {
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

/* fd_snapwm_vinyl_process_account reads and processes a batch of
   pre-generated bstream pairs, handles the meta_map, and determines
   whether to forward each of the accounts (pairs) to the database. */

void
fd_snapwm_vinyl_process_account( fd_snapwm_tile_t *  ctx,
                                 ulong               chunk,
                                 ulong               acc_cnt,
                                 fd_stem_context_t * stem ) {
  fd_vinyl_io_t *   io  = ctx->vinyl.io;
  fd_vinyl_meta_t * map = ctx->vinyl.map;

  uchar * src = fd_chunk_to_laddr( ctx->in.wksp, chunk );

  fd_snapwm_vinyl_duplicate_accounts_batch_init( ctx, stem );

  for( ulong acc_i=0UL; acc_i<acc_cnt; acc_i++ ) {

    fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)src;

    ulong val_esz    = fd_vinyl_bstream_ctl_sz  ( phdr->ctl );

    ulong   pair_sz = fd_vinyl_bstream_pair_sz( val_esz );
    uchar * pair    = bstream_alloc( io, pair_sz, FD_VINYL_IO_FLAG_BLOCKING );
    uchar * dst     = pair;

    ulong const account_header_slot = phdr->info.ul[1];

    ctx->metrics.accounts_loaded++;

    fd_vinyl_meta_ele_t * ele = NULL;
    if( ctx->full ) {
      ulong memo = fd_vinyl_key_memo( map->seed, &phdr->key );
      ele = fd_vinyl_meta_prepare_nolock( map, &phdr->key, memo );
      if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "Failed to update vinyl index (full)" ));

      if( FD_UNLIKELY( fd_vinyl_meta_ele_in_use( ele ) ) ) {
        /* Drop current value if existing is newer */
        ulong const exist_slot = ele->phdr.info.ul[ 1 ];
        if( FD_UNLIKELY( exist_slot > account_header_slot ) ) {
          ctx->metrics.accounts_ignored++;
          src += pair_sz;
          continue;
        } else {
          fd_snapwm_vinyl_duplicate_accounts_batch_append( ctx, &ele->phdr, ele->seq );
        }
        ctx->metrics.accounts_replaced++;
      }

      ele->memo      = memo;
      ele->phdr.ctl  = phdr->ctl;
      ele->phdr.key  = phdr->key;
      ele->phdr.info = phdr->info;
      ele->seq       = ULONG_MAX; /* later init */
      ele->line_idx  = ULONG_MAX;
    }

    fd_memcpy( dst, src, pair_sz );
    src += pair_sz;

    ulong seq_after = fd_vinyl_io_append( io, pair, pair_sz );
    if( ctx->full ) ele->seq = seq_after;
  }

  fd_snapwm_vinyl_duplicate_accounts_batch_fini( ctx, stem );
}

void
fd_snapwm_vinyl_shutdown( fd_snapwm_tile_t * ctx ) {
  int commit_err = fd_vinyl_io_commit( ctx->vinyl.io, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( commit_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_commit(io) failed (%i-%s)", commit_err, fd_vinyl_strerror( commit_err ) ));
  int sync_err = fd_vinyl_io_sync( ctx->vinyl.io_mm, FD_VINYL_IO_FLAG_BLOCKING );
  if( FD_UNLIKELY( sync_err ) ) FD_LOG_CRIT(( "fd_vinyl_io_sync(io_mm) failed (%i-%s)", sync_err, fd_vinyl_strerror( sync_err ) ));
  vinyl_mm_sync( ctx );

  fd_vinyl_io_wd_ctrl( ctx->vinyl.io_wd, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL );
}

void
fd_snapwm_vinyl_read_account( fd_snapwm_tile_t *  ctx,
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
    FD_LOG_CRIT(( "failed to read account %s: account data size (%lu bytes) exceeds buffer size (%lu bytes)",
                  acct_addr_b58, (ulong)meta->dlen, data_max ));
  }
  memcpy( data, mmio+seq_data, meta->dlen );
}

/* handle_hash_out_fseq_check is a blocking operation */
static inline void
handle_hash_out_fseq_check( fd_snapwm_tile_t *  ctx,
                            fd_stem_context_t * stem,
                            ulong               min_credit ) {
  ulong producer_fseq = fd_fseq_query( &stem->seqs[ ctx->hash_out.idx ] );
  ulong consumer_fseq = fd_fseq_query( ctx->hash_out.consumer_fseq );
  for(;;) {
    ulong avail = ctx->hash_out.depth - ( producer_fseq - consumer_fseq );
    if( FD_LIKELY( avail > min_credit ) ) break;
    FD_SPIN_PAUSE();
    consumer_fseq = fd_fseq_query( ctx->hash_out.consumer_fseq );
  }
}

int
fd_snapwm_vinyl_duplicate_accounts_batch_init( fd_snapwm_tile_t *  ctx,
                                               fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return 0;
  ctx->vinyl.duplicate_accounts_batch_sz  = 0UL;
  ctx->vinyl.duplicate_accounts_batch_cnt = 0UL;

  /* fseq check is mandatory here, since append writes directly to
     the dcache. */
  handle_hash_out_fseq_check( ctx, stem, FD_SNAPWM_DUP_BATCH_CREDIT_MIN );
  return 1;
}

int
fd_snapwm_vinyl_duplicate_accounts_batch_append( fd_snapwm_tile_t *        ctx,
                                                 fd_vinyl_bstream_phdr_t * phdr,
                                                 ulong                     seq ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return 0;
  uchar * data = fd_chunk_to_laddr( ctx->hash_out.mem, ctx->hash_out.chunk );
  data += ctx->vinyl.duplicate_accounts_batch_sz; /* offset into the chunk */
  memcpy( data, &seq, sizeof(ulong) );
  memcpy( data + sizeof(ulong), phdr, sizeof(fd_vinyl_bstream_phdr_t) );
  ctx->vinyl.duplicate_accounts_batch_sz  += FD_SNAPWM_DUP_META_SZ;
  ctx->vinyl.duplicate_accounts_batch_cnt +=1UL;
  return 1;
}

int
fd_snapwm_vinyl_duplicate_accounts_batch_fini( fd_snapwm_tile_t * ctx,
                                               fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return 0;

  /* There is no fseq check in batch_fini.  This is a performance
     optimization, which requires no other fd_stem_publish on the
     output link in between init and fini. */

  ulong batch_sz  = ctx->vinyl.duplicate_accounts_batch_sz;
  ulong batch_cnt = ctx->vinyl.duplicate_accounts_batch_cnt;
  if( FD_UNLIKELY( batch_cnt>FD_SSPARSE_ACC_BATCH_MAX ) ) {
    FD_LOG_CRIT(( "batch_cnt %lu exceeds FD_SSPARSE_ACC_BATCH_MAX %lu", batch_cnt, FD_SSPARSE_ACC_BATCH_MAX ));
  }
  if( FD_UNLIKELY( !batch_sz ) ) return 0;
  fd_stem_publish( stem, ctx->hash_out.idx, FD_SNAPSHOT_HASH_MSG_SUB_META_BATCH, ctx->hash_out.chunk, batch_sz, 0UL, 0UL, batch_cnt/*tspub*/ );
  ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, batch_sz, ctx->hash_out.chunk0, ctx->hash_out.wmark );
  return 1;
}

int
fd_snapwm_vinyl_duplicate_accounts_lthash_init( fd_snapwm_tile_t *  ctx,
                                                fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return 0;
  fd_lthash_zero( &ctx->vinyl.running_lthash );

  (void)stem;
  /* There is no fseq check in lthash_init, since append uses internal
     adder and running_lthash, without accessing the dcache. */
  return 1;
}

int
fd_snapwm_vinyl_duplicate_accounts_lthash_append( fd_snapwm_tile_t * ctx,
                                                  uchar *            pair ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return 0;
  streamlined_hash( &ctx->vinyl.adder, &ctx->vinyl.running_lthash, pair );
  return 1;
}

int
fd_snapwm_vinyl_duplicate_accounts_lthash_fini( fd_snapwm_tile_t * ctx,
                                               fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->lthash_disabled ) ) return 0;

  /* fseq check is mandatory here. */
  handle_hash_out_fseq_check( ctx, stem, FD_SNAPWM_DUP_LTHASH_CREDIT_MIN );

  fd_lthash_adder_flush( &ctx->vinyl.adder, &ctx->vinyl.running_lthash );
  uchar * data = fd_chunk_to_laddr( ctx->hash_out.mem, ctx->hash_out.chunk );
  fd_memcpy( data, &ctx->vinyl.running_lthash, FD_LTHASH_LEN_BYTES );
  fd_stem_publish( stem, ctx->hash_out.idx, FD_SNAPSHOT_HASH_MSG_RESULT_SUB, ctx->hash_out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
  ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, FD_LTHASH_LEN_BYTES, ctx->hash_out.chunk0, ctx->hash_out.wmark );
  return 1;
}
