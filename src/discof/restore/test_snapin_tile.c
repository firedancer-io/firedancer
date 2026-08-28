/* Unit tests for the N symmetric fused snapin tiles of the parallel
   (tar-boundary-sharded) snapshot loader.

   There is no coordinator and no message-passing protocol between the
   tiles, so the harness models a cluster directly: N real
   fd_snapin_tile_t contexts sharing one real snapio_snoop object, each
   driven frag by frag through returnable_frag/before_frag.  The accdb,
   ssparse and stem entry points the tile calls out to are mocked, so
   what these tests pin is the tile's own protocol: the attempt-slot
   gate, the eager-claim counter, the per-attempt resets, the FINI
   malform gates and the FINI->totals fold. */

#define _GNU_SOURCE
#include "../../disco/stem/fd_stem.h"
#include "../../flamenco/accdb/fd_accdb_base.h"
#include "utils/fd_ssparse.h"

/* Recorded stem publishes. */
static ulong test_pub_sig[ 64UL ];
static ulong test_pub_out_idx[ 64UL ];
static ulong test_pub_cnt;

/* Mock accdb call counters. */
static ulong test_accdb_reset_cnt;
static ulong test_accdb_attach_cnt;
static ulong test_accdb_purge_cnt;
static ulong test_accdb_advance_root_cnt;
static ulong test_accdb_writer_begin_cnt;
static ulong test_accdb_writer_end_cnt;
static ulong test_accdb_worker_close_cnt;
static ulong test_accdb_load_begin_writers;
static ulong test_accdb_load_end_cnt;
static ulong test_accdb_readback_cnt;
static ulong test_accdb_recover_delta_cnt;
static ulong test_accdb_release_cnt;      /* release_partitions calls */
static ulong test_accdb_release_total;    /* partitions released */
static ulong test_feature_finalize_cnt;
static ulong test_appendvec_parse_cnt;

/* Mock ssparse stream: test_av_cnt appendvec entries, then DONE.  Every
   tile walks the same stream independently, so the position is
   per-tile and the driver stamps test_cur_tile before each frag. */
#define TEST_TILE_MAX (8UL)
#define TEST_AV_MAX   (32UL)

static ulong test_av_cnt;
static ulong test_av_sz[ TEST_AV_MAX ];
static ulong test_stream_pos[ TEST_TILE_MAX ];
static ulong test_cur_tile;

static int
test_ssparse_advance( fd_ssparse_t *                parser,
                      uchar const *                 data,
                      ulong                         data_sz,
                      fd_ssparse_advance_result_t *  result );

static void
test_ssparse_appendvec_parse( fd_ssparse_t * parser );

static ulong
test_stem_publish( fd_stem_context_t * stem,
                   ulong               out_idx,
                   ulong               sig,
                   ulong               chunk,
                   ulong               sz,
                   ulong               ctl,
                   ulong               tsorig,
                   ulong               tspub ) {
  (void)stem;
  (void)chunk;
  (void)sz;
  (void)ctl;
  (void)tsorig;
  (void)tspub;
  FD_TEST( test_pub_cnt<sizeof(test_pub_sig)/sizeof(test_pub_sig[0]) );
  test_pub_out_idx[ test_pub_cnt ] = out_idx;
  test_pub_sig    [ test_pub_cnt ] = sig;
  test_pub_cnt++;
  return test_pub_cnt-1UL;
}

#define fd_accdb_reset                               mock_accdb_reset
#define fd_accdb_attach_child                        mock_accdb_attach_child
#define fd_accdb_purge                               mock_accdb_purge
#define fd_accdb_advance_root                        mock_accdb_advance_root
#define fd_accdb_snapshot_writer_begin               mock_accdb_snapshot_writer_begin
#define fd_accdb_snapshot_writer_end                 mock_accdb_snapshot_writer_end
#define fd_accdb_snapshot_load_begin_with_writers    mock_accdb_snapshot_load_begin_with_writers
#define fd_accdb_snapshot_load_end                   mock_accdb_snapshot_load_end
#define fd_accdb_snapshot_worker_close               mock_accdb_snapshot_worker_close
#define fd_accdb_snapshot_flush_worker_metrics       mock_accdb_snapshot_flush_worker_metrics
#define fd_accdb_snapshot_verify_readback            mock_accdb_snapshot_verify_readback
#define fd_accdb_snapshot_recover_delta              mock_accdb_snapshot_recover_delta
#define fd_accdb_snapshot_worker_release_partitions  mock_accdb_snapshot_worker_release_partitions
#define fd_txncache_reset                            mock_txncache_reset
#define fd_ssmanifest_parser_init                    mock_ssmanifest_parser_init
#define fd_stake_delegations_reset                   mock_stake_delegations_reset
#define fd_feature_snoop_finalize                    mock_feature_snoop_finalize
#define fd_stem_publish                              test_stem_publish
#define fd_ssparse_advance                           test_ssparse_advance
#define fd_ssparse_appendvec_parse                   test_ssparse_appendvec_parse
#include "fd_snapin_tile.c"
#undef fd_ssparse_appendvec_parse
#undef fd_ssparse_advance
#undef fd_stem_publish
#undef fd_feature_snoop_finalize
#undef fd_stake_delegations_reset
#undef fd_ssmanifest_parser_init
#undef fd_txncache_reset
#undef fd_accdb_snapshot_worker_release_partitions
#undef fd_accdb_snapshot_recover_delta
#undef fd_accdb_snapshot_verify_readback
#undef fd_accdb_snapshot_flush_worker_metrics
#undef fd_accdb_snapshot_worker_close
#undef fd_accdb_snapshot_load_end
#undef fd_accdb_snapshot_load_begin_with_writers
#undef fd_accdb_snapshot_writer_end
#undef fd_accdb_snapshot_writer_begin
#undef fd_accdb_advance_root
#undef fd_accdb_purge
#undef fd_accdb_attach_child
#undef fd_accdb_reset

#include <stdlib.h>

/* Mocks ***************************************************************/

void mock_accdb_reset                            ( fd_accdb_t * accdb ) { (void)accdb; test_accdb_reset_cnt++;         }
void mock_accdb_snapshot_writer_begin            ( fd_accdb_t * accdb ) { (void)accdb; test_accdb_writer_begin_cnt++;  }
void mock_accdb_snapshot_writer_end              ( fd_accdb_t * accdb ) { (void)accdb; test_accdb_writer_end_cnt++;    }
void mock_accdb_snapshot_load_end                ( fd_accdb_t * accdb ) { (void)accdb; test_accdb_load_end_cnt++;      }

fd_accdb_fork_id_t
mock_accdb_attach_child( fd_accdb_t *       accdb,
                         fd_accdb_fork_id_t parent_fork_id ) {
  (void)accdb;
  (void)parent_fork_id;
  test_accdb_attach_cnt++;
  return (fd_accdb_fork_id_t){ .val = 7U };
}

void
mock_accdb_purge( fd_accdb_t *       accdb,
                  fd_accdb_fork_id_t fork_id ) {
  (void)accdb;
  (void)fork_id;
  test_accdb_purge_cnt++;
}

void
mock_accdb_advance_root( fd_accdb_t *       accdb,
                         fd_accdb_fork_id_t fork_id ) {
  (void)accdb;
  (void)fork_id;
  test_accdb_advance_root_cnt++;
}

void
mock_accdb_snapshot_load_begin_with_writers( fd_accdb_t * accdb,
                                             ulong        writer_cnt ) {
  (void)accdb;
  test_accdb_load_begin_writers = writer_cnt;
}

/* The real close hands off the final partition and resets the whead.
   The tile reads whead.attempt_partition_cnt right after (to stamp its
   FAIL partition list), so the mock deliberately leaves the tracker
   count alone: the driver seeds it to model a writer that acquired
   partitions during the attempt. */
void
mock_accdb_snapshot_worker_close( fd_accdb_t *                accdb,
                                  fd_accdb_snapshot_whead_t * whead ) {
  (void)accdb;
  whead->val           = 0UL;
  whead->has_partition = 0;
  test_accdb_worker_close_cnt++;
}

/* Mirrors the real function: folds (and zeroes) the shared-counter
   deltas, leaves the eq_slot_* diagnostics untouched. */
void
mock_accdb_snapshot_flush_worker_metrics( fd_accdb_t *                         accdb,
                                          fd_accdb_snapshot_worker_metrics_t * m ) {
  (void)accdb;
  m->disk_used_added      = 0UL;
  m->disk_used_removed    = 0UL;
  m->accounts_total_added = 0UL;
}

void
mock_accdb_snapshot_verify_readback( fd_accdb_t * accdb,
                                     ulong        sample_max ) {
  (void)accdb;
  (void)sample_max;
  test_accdb_readback_cnt++;
}

int
mock_accdb_snapshot_recover_delta( fd_accdb_t *       accdb,
                                   fd_accdb_fork_id_t fork_id ) {
  (void)accdb;
  (void)fork_id;
  test_accdb_recover_delta_cnt++;
  return 0;
}

void
mock_accdb_snapshot_worker_release_partitions( fd_accdb_t * accdb,
                                               uint const * partition_idxs,
                                               ulong        cnt ) {
  (void)accdb;
  (void)partition_idxs;
  test_accdb_release_cnt++;
  test_accdb_release_total += cnt;
}

void mock_txncache_reset( fd_txncache_t * tc ) { (void)tc; }

void
mock_ssmanifest_parser_init( fd_ssmanifest_parser_t * parser,
                             fd_snapshot_manifest_t * manifest ) {
  (void)parser;
  (void)manifest;
}

void mock_stake_delegations_reset( fd_stake_delegations_t * sd ) { (void)sd; }

void
mock_feature_snoop_finalize( fd_features_t *             features,
                             ulong                       slot,
                             fd_epoch_schedule_t const * epoch_schedule,
                             fd_feature_snoop_t const *  snoop ) {
  (void)features;
  (void)slot;
  (void)epoch_schedule;
  (void)snoop;
  test_feature_finalize_cnt++;
}

static void
test_ssparse_appendvec_parse( fd_ssparse_t * parser ) {
  (void)parser;
  test_appendvec_parse_cnt++;
}

static int
test_ssparse_advance( fd_ssparse_t *                parser,
                      uchar const *                 data,
                      ulong                         data_sz,
                      fd_ssparse_advance_result_t *  result ) {
  (void)parser;
  (void)data;
  fd_memset( result, 0, sizeof(*result) );
  result->bytes_consumed = data_sz;
  ulong i = test_stream_pos[ test_cur_tile ]++;
  if( FD_LIKELY( i<test_av_cnt ) ) {
    result->appendvec.slot    = 100UL+i;
    result->appendvec.data_sz = test_av_sz[ i ];
    return FD_SSPARSE_ADVANCE_APPENDVEC;
  }
  return FD_SSPARSE_ADVANCE_DONE;
}

/* Cluster harness *****************************************************/

#define TEST_LANE_MAX (2UL)
#define TEST_FRAG_SZ  (4096UL)

typedef struct {
  fd_snapio_snoop_hdr_t * hdr;
  void *                  hdr_mem;
  void *                  sd_mem;    /* tile 0's real slot delta parser */
  ulong                   tile_cnt;
  ulong                   lane_cnt;
  uchar *                 in_mem;    /* tile_cnt*lane_cnt frag buffers */
  uchar *                 write_buf; /* tile_cnt staging buffers */
  fd_stake_delegations_t * stake_delegations;
  fd_bank_t *              bank;
  fd_snapin_tile_t        ctx[ TEST_TILE_MAX ];
} test_cluster_t;

static void
test_counters_reset( void ) {
  test_pub_cnt                  = 0UL;
  test_accdb_reset_cnt          = 0UL;
  test_accdb_attach_cnt         = 0UL;
  test_accdb_purge_cnt          = 0UL;
  test_accdb_advance_root_cnt   = 0UL;
  test_accdb_writer_begin_cnt   = 0UL;
  test_accdb_writer_end_cnt     = 0UL;
  test_accdb_worker_close_cnt   = 0UL;
  test_accdb_load_begin_writers = 0UL;
  test_accdb_load_end_cnt       = 0UL;
  test_accdb_readback_cnt       = 0UL;
  test_accdb_recover_delta_cnt  = 0UL;
  test_accdb_release_cnt        = 0UL;
  test_accdb_release_total      = 0UL;
  test_feature_finalize_cnt     = 0UL;
  test_appendvec_parse_cnt      = 0UL;
  for( ulong t=0UL; t<TEST_TILE_MAX; t++ ) test_stream_pos[ t ] = 0UL;
}

/* Build a cluster of tile_cnt symmetric snapin tiles sharing one real
   snapio_snoop object, wired the way unprivileged_init wires them. */
static test_cluster_t *
test_cluster_new( ulong tile_cnt,
                  ulong lane_cnt ) {
  FD_TEST( tile_cnt && tile_cnt<=TEST_TILE_MAX );
  FD_TEST( lane_cnt && lane_cnt<=TEST_LANE_MAX );

  test_cluster_t * cl = aligned_alloc( 4096UL, fd_ulong_align_up( sizeof(test_cluster_t), 4096UL ) );
  FD_TEST( cl );
  fd_memset( cl, 0, sizeof(test_cluster_t) );
  cl->tile_cnt = tile_cnt;
  cl->lane_cnt = lane_cnt;

  cl->hdr_mem = aligned_alloc( fd_snapio_snoop_align(), fd_ulong_align_up( fd_snapio_snoop_footprint( tile_cnt ), fd_snapio_snoop_align() ) );
  FD_TEST( cl->hdr_mem );
  cl->hdr = fd_snapio_snoop_join( fd_snapio_snoop_new( cl->hdr_mem, tile_cnt ) );
  FD_TEST( cl->hdr );

  cl->sd_mem = aligned_alloc( fd_slot_delta_parser_align(), fd_ulong_align_up( fd_slot_delta_parser_footprint(), fd_slot_delta_parser_align() ) );
  FD_TEST( cl->sd_mem );

  cl->in_mem = aligned_alloc( 4096UL, tile_cnt*lane_cnt*TEST_FRAG_SZ );
  FD_TEST( cl->in_mem );
  fd_memset( cl->in_mem, 0, tile_cnt*lane_cnt*TEST_FRAG_SZ );

  cl->write_buf = aligned_alloc( 4096UL, tile_cnt*TEST_FRAG_SZ );
  FD_TEST( cl->write_buf );

  /* log_snoop_checksums walks the root stake delegation pool; a zeroed
     struct (pool_idx_wmk_==0) is an empty pool. */
  cl->stake_delegations = aligned_alloc( 128UL, fd_ulong_align_up( sizeof(fd_stake_delegations_t), 128UL ) );
  FD_TEST( cl->stake_delegations );
  fd_memset( cl->stake_delegations, 0, sizeof(fd_stake_delegations_t) );

  cl->bank = aligned_alloc( 128UL, fd_ulong_align_up( sizeof(fd_bank_t), 128UL ) );
  FD_TEST( cl->bank );
  fd_memset( cl->bank, 0, sizeof(fd_bank_t) );

  for( ulong t=0UL; t<tile_cnt; t++ ) {
    fd_snapin_tile_t * ctx = &cl->ctx[ t ];
    fd_memset( ctx, 0, sizeof(*ctx) );
    ctx->tile_idx = t;
    ctx->tile_cnt = tile_cnt;
    ctx->lane_cnt = lane_cnt;
    ctx->full     = 1;
    ctx->state    = FD_SNAPSHOT_STATE_IDLE;
    clear_control_barrier( ctx );

    ctx->snoop_hdr    = cl->hdr;
    ctx->stripe_locks = fd_snapio_snoop_stripes( cl->hdr );
    ctx->my_snoop     = fd_snapio_snoop_worker( cl->hdr, t );
    if( FD_UNLIKELY( !t ) ) {
      for( ulong w=0UL; w<tile_cnt; w++ ) ctx->snoops[ w ] = fd_snapio_snoop_worker( cl->hdr, w );
    }

    ctx->whead.attempt_partitions    = ctx->my_snoop->fail_partitions;
    ctx->whead.attempt_partition_cnt = 0UL;
    ctx->whead.attempt_partition_max = FD_SNAPIO_FAIL_PARTITION_MAX;

    ctx->wb_kick_sz = FD_SNAPIN_WB_KICK_SZ;
    ctx->wb_window  = 0UL; /* write-behind off: the mocks never pwrite */

    ctx->stake_delegations = cl->stake_delegations;
    ctx->write_buf         = cl->write_buf + t*TEST_FRAG_SZ;

    ctx->ct_out.idx       = 1UL+t;
    ctx->manifest_out.idx = ULONG_MAX;
    ctx->gui_out.idx      = ULONG_MAX;
    if( FD_UNLIKELY( !t ) ) {
      ctx->manifest_out.idx = 0UL;
      ctx->bank             = cl->bank;
      ctx->slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( cl->sd_mem ) );
      FD_TEST( ctx->slot_delta_parser );
    }

    for( ulong lane=0UL; lane<lane_cnt; lane++ ) {
      ctx->in[ lane ].wksp   = (fd_wksp_t *)( cl->in_mem + (t*lane_cnt+lane)*TEST_FRAG_SZ );
      ctx->in[ lane ].chunk0 = 0UL;
      ctx->in[ lane ].wmark  = 0UL;
      ctx->in[ lane ].mtu    = TEST_FRAG_SZ;
      ctx->in[ lane ].pos    = 0UL;
      /* Control frags for tile 0 are read as an fd_ssctrl_init_t. */
      fd_ssctrl_init_t * msg = (fd_ssctrl_init_t *)( cl->in_mem + (t*lane_cnt+lane)*TEST_FRAG_SZ );
      msg->slot = 440123518UL;
    }

    ctx->accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->boot_timestamp     = fd_log_wallclock();

    worker_reset_attempt( ctx );
  }

  return cl;
}

static void
test_cluster_delete( test_cluster_t * cl ) {
  free( cl->bank );
  free( cl->stake_delegations );
  free( cl->write_buf );
  free( cl->in_mem );
  free( cl->sd_mem );
  free( cl->hdr_mem );
  free( cl );
}

static void
tile_send_control( fd_snapin_tile_t * ctx,
                   ulong              lane,
                   ulong              sig ) {
  FD_TEST( !returnable_frag( ctx, lane, 0UL, sig, 0UL, 0UL, 0UL, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
}

/* Drive one control barrier to completion on every tile, in tile order.
   Tile order matters for INIT: tile 0 publishes the attempt slot the
   other tiles' gates hold on, and this harness is single-threaded (a
   non-tile-0-first order would just park every other tile's gate until
   tile 0's INIT ran). */
static void
cluster_barrier( test_cluster_t * cl,
                 ulong            sig ) {
  for( ulong t=0UL; t<cl->tile_cnt; t++ ) {
    for( ulong lane=0UL; lane<cl->lane_cnt; lane++ ) {
      tile_send_control( &cl->ctx[ t ], lane, sig );
    }
  }
}

static int
tile_send_data( fd_snapin_tile_t * ctx,
                ulong              lane,
                ulong              sz ) {
  ulong sig = FD_SNAPSHOT_MSG_DATA;
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 0, 0 );
  test_cur_tile = ctx->tile_idx;
  FD_TEST( !before_frag( ctx, lane, 0UL, sig ) );
  return returnable_frag( ctx, lane, 0UL, sig, 0UL, sz, ctl, 0UL, 0UL, (fd_stem_context_t *)1UL );
}

/* Feed one stream event to one tile and report which appendvec ordinal
   (if any) the tile took ownership of. */
static ulong
tile_step( fd_snapin_tile_t * ctx ) {
  ulong owned0 = ctx->owned_appendvecs;
  FD_TEST( !tile_send_data( ctx, 0UL, TEST_FRAG_SZ ) );
  if( FD_UNLIKELY( ctx->owned_appendvecs==owned0 ) ) return ULONG_MAX;
  FD_TEST( ctx->owned_appendvecs==owned0+1UL );
  return ctx->appendvec_seq-1UL;
}

/* Stream orders the eager-claim coverage test drives.  Ownership is
   schedule dependent (that is the point of the counter), the coverage
   invariant is not. */
#define TEST_ORDER_ROUND_ROBIN (0)
#define TEST_ORDER_TILE_MAJOR  (1)
#define TEST_ORDER_REVERSE     (2)

/* Walk every tile through the whole mock stream in the given order,
   recording the owner of each appendvec ordinal.  owner[] must hold
   test_av_cnt entries. */
static void
cluster_stream( test_cluster_t * cl,
                int              order,
                ulong *          owner ) {
  ulong n = cl->tile_cnt;
  ulong T = test_av_cnt;
  for( ulong i=0UL; i<T; i++ ) owner[ i ] = ULONG_MAX;

  /* T appendvec events plus one trailing event that yields DONE. */
  if( order==TEST_ORDER_ROUND_ROBIN ) {
    for( ulong step=0UL; step<T+1UL; step++ ) {
      for( ulong t=0UL; t<n; t++ ) {
        ulong av = tile_step( &cl->ctx[ t ] );
        if( av!=ULONG_MAX ) { FD_TEST( av<T && owner[ av ]==ULONG_MAX ); owner[ av ] = t; }
      }
    }
  } else {
    for( ulong j=0UL; j<n; j++ ) {
      ulong t = order==TEST_ORDER_REVERSE ? n-1UL-j : j;
      for( ulong step=0UL; step<T+1UL; step++ ) {
        ulong av = tile_step( &cl->ctx[ t ] );
        if( av!=ULONG_MAX ) { FD_TEST( av<T && owner[ av ]==ULONG_MAX ); owner[ av ] = t; }
      }
    }
  }

  for( ulong t=0UL; t<n; t++ ) {
    FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_FINISHING );
    FD_TEST( cl->ctx[ t ].appendvec_seq==T );
  }
  for( ulong i=0UL; i<T; i++ ) FD_TEST( owner[ i ]!=ULONG_MAX ); /* every ordinal claimed exactly once */
}

static void
test_stream_init( ulong av_cnt ) {
  FD_TEST( av_cnt<=TEST_AV_MAX );
  test_av_cnt = av_cnt;
  for( ulong i=0UL; i<av_cnt; i++ ) test_av_sz[ i ] = 1024UL*(i+1UL);
}

/* A SlotHistory sysvar the winner-gated capture would have snooped:
   has_bits, 16384 blocks of zeroed bits, then (bits_len, next_slot).
   The tile's verify_slot_deltas_with_slot_history gate needs
   next_slot-1 == bank_slot, bits_len == FD_SLOT_HISTORY_MAX_ENTRIES, and
   (with an empty slot delta set) nothing else. */
static void
test_stamp_slot_history( test_cluster_t * cl,
                         ulong            bank_slot ) {
  fd_snapio_snoop_hdr_t * hdr = cl->hdr;
  ulong blocks_len = FD_SLOT_HISTORY_MAX_ENTRIES/64UL;
  FD_TEST( 9UL+blocks_len*8UL+16UL==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  uchar * buf = hdr->slot_history.buf;
  fd_memset( buf, 0, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  buf[ 0 ] = 1;
  FD_STORE( ulong, buf+1UL, blocks_len );
  uchar * footer = buf + 9UL + blocks_len*8UL;
  FD_STORE( ulong, footer,      FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_STORE( ulong, footer+8UL,  bank_slot+1UL               );

  hdr->slot_history.captured   = 1;
  hdr->slot_history.executable = 0;
  hdr->slot_history.slot       = bank_slot;
  hdr->slot_history.lamports   = 1UL;
  hdr->slot_history.data_len   = FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ;
  fd_memcpy( hdr->slot_history.owner, fd_sysvar_owner_id.uc, 32UL );

  cl->ctx[ 0 ].bank_slot = bank_slot;
}

/* Regression: scratch_align() must cover the largest FD_LAYOUT_APPEND
   alignment in scratch_footprint (the 4096-aligned write buffer).  The
   footprint is computed from a zero base, so if the topology placed the
   tile object at a smaller alignment the runtime layout could consume
   up to align-scratch_align more bytes than the footprint and overflow
   into the next workspace object. */

static void
test_scratch_layout_fits( void ) {
  FD_TEST( scratch_align()>=alignof(fd_snapin_tile_t) );
  FD_TEST( scratch_align()>=fd_accdb_align() );
  FD_TEST( scratch_align()>=4096UL ); /* write buffer */

  fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(fd_topo_tile_t) );
  tile->snapin.max_live_slots = 1024UL;

  /* Replay unprivileged_init's layout for both tile kinds and verify it
     fits within the declared footprint. */
  for( ulong kind_id=0UL; kind_id<2UL; kind_id++ ) {
    tile->kind_id = kind_id;
    ulong footprint = scratch_footprint( tile );

    FD_SCRATCH_ALLOC_INIT( l, NULL );
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
    FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),          fd_accdb_footprint( tile->snapin.max_live_slots ) );
    if( !kind_id ) {
      FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),           fd_txncache_footprint( tile->snapin.max_live_slots )        );
      FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint()                            );
      FD_SCRATCH_ALLOC_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()                            );
      FD_SCRATCH_ALLOC_APPEND( l, alignof(blockhash_group_t),    sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS   );
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_hash_t), sizeof(fd_sstxncache_hash_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
    }
    FD_SCRATCH_ALLOC_APPEND( l, 4096UL, FD_SNAPIN_WRITE_BUF_SZ );
    ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
    FD_TEST( end<=footprint );
  }
}

/* Attempt-slot gate ***************************************************/

/* A tile whose INIT barrier completes before tile 0 published the
   attempt slot must not insert: nothing else orders tile 0's INIT-time
   accdb work against this tile's first insert.  The gate is
   non-blocking, so the tile acks INIT immediately and then HOLDS its
   data lane (before_frag returns -1) without opening its writer or
   drawing a claim.  Once the slot carries this attempt's generation the
   next data frag opens the gate: the fork id is cached, the writer is
   opened and the eager claim is taken. */
static void
test_init_gate_holds_data( void ) {
  test_cluster_t * cl = test_cluster_new( 2UL, 1UL );
  test_counters_reset();
  test_stream_init( 4UL );

  fd_snapin_tile_t * ctx = &cl->ctx[ 1 ];

  /* Stale attempt slot: generation 0 while the tile will be on
     generation 1 (bumped at its first INIT frag).  The stale fork id is
     left plausible (USHORT_MAX, i.e. what a previous full attempt would
     have published) so that only the generation gate can stop the tile
     -- the fork-id sanity check must not be what saves us. */
  FD_TEST( cl->hdr->attempt.generation==0UL );
  cl->hdr->attempt.fork_id = (ulong)USHORT_MAX;

  for( ulong lane=0UL; lane<cl->lane_cnt; lane++ ) tile_send_control( ctx, lane, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );

  /* The INIT barrier completed and was acked, but the write path is
     armed, not open. */
  FD_TEST( ctx->generation==1UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( ctx->gate_pending );
  FD_TEST( ctx->incr_fork==ULONG_MAX );
  FD_TEST( !test_accdb_writer_begin_cnt );
  FD_TEST( !cl->hdr->next_appendvec );
  FD_TEST( test_pub_cnt==1UL && test_pub_sig[ 0 ]==FD_SNAPSHOT_MSG_CTRL_INIT_FULL );

  /* Data is held, repeatedly and without side effects.  Controls are
     not: an ERROR (and, after it, a FAIL) must still be deliverable. */
  test_cur_tile = ctx->tile_idx;
  for( ulong i=0UL; i<8UL; i++ ) {
    FD_TEST( before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA )==-1 );
    FD_TEST( ctx->gate_pending );
    FD_TEST( !test_accdb_writer_begin_cnt );
    FD_TEST( !cl->hdr->next_appendvec );
    FD_TEST( !ctx->appendvec_seq );
  }
  FD_TEST( before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR )==0 );
  FD_TEST( before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL  )==0 );

  /* Publish the attempt slot exactly as tile 0's INIT does. */
  FD_VOLATILE( cl->hdr->attempt.fork_id ) = (ulong)USHORT_MAX;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cl->hdr->attempt.generation ) = 1UL;

  /* The next data frag opens the gate and is admitted. */
  FD_TEST( tile_step( ctx )==0UL );
  FD_TEST( !ctx->gate_pending );
  FD_TEST( ctx->incr_fork==(ulong)USHORT_MAX );
  FD_TEST( test_accdb_writer_begin_cnt==1UL );
  FD_TEST( cl->hdr->next_appendvec==2UL );  /* the eager claim, then its replacement */
  FD_TEST( ctx->owned_appendvecs==1UL );
  FD_TEST( test_pub_cnt==1UL );             /* still just the INIT ack */

  test_cluster_delete( cl );
}

/* An ERROR can abort tile 0's INIT barrier mid-way (the remaining INIT
   frags are dropped by the ERROR-state filter), so the attempt slot is
   never published for that generation.  A tile that DID complete its
   INIT barrier for the attempt must not wedge: it holds its data,
   consumes the ERROR, acks the FAIL, and the retry (generation G+1)
   loads cleanly.  This is the sequence the old blocking spin gate
   deadlocked on -- and then crashed the validator on. */
static void
test_init_aborted_barrier_retries( void ) {
  ulong const n = 2UL;
  ulong const T = 5UL;

  test_cluster_t * cl = test_cluster_new( n, 2UL );
  test_counters_reset();
  test_stream_init( T );

  fd_snapin_tile_t * t0 = &cl->ctx[ 0 ];
  fd_snapin_tile_t * t1 = &cl->ctx[ 1 ];

  /* Tile 1 completes its INIT barrier on both lanes. */
  for( ulong lane=0UL; lane<cl->lane_cnt; lane++ ) tile_send_control( t1, lane, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( t1->generation==1UL );
  FD_TEST( t1->gate_pending );

  /* Tile 0 consumes INIT on lane 0 only, then the ERROR that sits right
     behind it: its barrier is abandoned, so the INIT handler never runs
     and nothing is published. */
  tile_send_control( t0, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( t0->generation==1UL );
  FD_TEST( before_frag( t0, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR )==0 );
  tile_send_control( t0, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( t0->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( !t0->init_completed );
  FD_TEST( !cl->hdr->attempt.generation );  /* slot never published */
  FD_TEST( !test_accdb_writer_begin_cnt );

  /* Tile 1 holds its data behind the unpublished slot, but the ERROR at
     its lane head is still deliverable. */
  test_cur_tile = 1UL;
  FD_TEST( before_frag( t1, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA )==-1 );
  FD_TEST( before_frag( t1, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR )==0 );
  tile_send_control( t1, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( t1->state==FD_SNAPSHOT_STATE_ERROR );
  /* In ERROR everything but FAIL is dropped, so the tile drains to the
     FAIL barrier instead of stalling on the held data. */
  FD_TEST( before_frag( t1, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA )==1 );

  /* Both tiles ack the FAIL. */
  ulong pub0 = test_pub_cnt;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( test_pub_cnt==pub0+n );
  for( ulong i=pub0; i<test_pub_cnt; i++ ) FD_TEST( test_pub_sig[ i ]==FD_SNAPSHOT_MSG_CTRL_FAIL );
  for( ulong t=0UL; t<n; t++ ) {
    FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_IDLE );
    FD_TEST( !cl->ctx[ t ].gate_pending );
  }
  /* Tile 0's INIT never ran, so there is nothing to roll back -- and in
     particular the root fork id must not have been wiped on the stale
     `full` flag. */
  FD_TEST( !t0->rollback.pending );

  /* Retry: generation 2 is published and the load completes. */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( cl->hdr->attempt.generation==2UL );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].generation==2UL );
  FD_TEST( !t0->gate_pending );  /* tile 0 publishes, so it never gates */
  FD_TEST( t1->gate_pending );   /* ... and tile 1 opens on its first data frag */

  ulong owner[ TEST_AV_MAX ];
  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( !cl->ctx[ t ].gate_pending );
  FD_TEST( test_accdb_writer_begin_cnt==n );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( cl->hdr->totals.appendvecs_processed==T );
  FD_TEST( cl->hdr->next_appendvec==T+n );

  test_cluster_delete( cl );
}

/* The attempt slot left behind by an earlier attempt must not release
   the gate: the retry compares generations, not a flag. */
static void
test_init_gate_rejects_stale_generation( void ) {
  test_cluster_t * cl = test_cluster_new( 2UL, 1UL );
  test_counters_reset();
  test_stream_init( 4UL );

  fd_snapin_tile_t * t1 = &cl->ctx[ 1 ];

  /* Attempt 1 loads normally on tile 1 (tile 0 publishes generation 1). */
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( cl->hdr->attempt.generation==1UL );
  (void)tile_step( t1 );  /* the first data frag opens tile 1's gate */
  FD_TEST( !t1->gate_pending );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );

  /* Attempt 2: only tile 1's barrier completes.  The slot still holds
     generation 1, which must NOT open the gate. */
  for( ulong lane=0UL; lane<cl->lane_cnt; lane++ ) tile_send_control( t1, lane, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( t1->generation==2UL );
  FD_TEST( cl->hdr->attempt.generation==1UL );
  test_cur_tile = 1UL;
  FD_TEST( before_frag( t1, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA )==-1 );
  FD_TEST( t1->gate_pending );

  test_cluster_delete( cl );
}

/* Tile 0's INIT critical sequence publishes the slot LAST, after
   re-zeroing every attempt-scoped shared field.  A stale workspace
   (crashed load) must not leak into the new attempt. */
static void
test_init_publishes_after_reset( void ) {
  test_cluster_t * cl = test_cluster_new( 4UL, 1UL );
  test_counters_reset();

  /* Dirty every attempt-scoped shared field, as a killed load would
     leave them. */
  fd_snapio_snoop_hdr_t * hdr = cl->hdr;
  hdr->next_appendvec            = 999UL;
  hdr->totals.accounts_loaded    = 1234UL;
  hdr->totals.input_lamports     = 5678UL;
  hdr->totals.appendvecs_processed = 42UL;
  hdr->slot_history.captured     = 1;
  hdr->feature_snoop.present[ 0 ] = 1;

  /* Only tile 0's INIT: it re-zeroes and publishes. */
  for( ulong lane=0UL; lane<cl->lane_cnt; lane++ ) tile_send_control( &cl->ctx[ 0 ], lane, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );

  FD_TEST( !hdr->totals.accounts_loaded );
  FD_TEST( !hdr->totals.input_lamports );
  FD_TEST( !hdr->totals.appendvecs_processed );
  FD_TEST( !hdr->slot_history.captured );
  FD_TEST( !hdr->feature_snoop.present[ 0 ] );
  FD_TEST( hdr->attempt.generation==1UL );
  FD_TEST( hdr->attempt.fork_id==(ulong)USHORT_MAX );
  /* Re-zeroed, then tile 0's own eager claim (it publishes the slot, so
     its gate opens inside the INIT handler; the other tiles draw theirs
     when their first data frag arrives). */
  FD_TEST( hdr->next_appendvec==1UL );
  FD_TEST( cl->ctx[ 0 ].claimed_appendvec==0UL );
  FD_TEST( !cl->ctx[ 0 ].gate_pending );

  FD_TEST( test_accdb_reset_cnt==1UL );
  FD_TEST( test_accdb_attach_cnt==1UL );
  FD_TEST( test_accdb_load_begin_writers==4UL );

  test_cluster_delete( cl );
}

/* Eager claim coverage ************************************************/

/* Every appendvec in the stream is claimed by exactly one tile, no
   matter how the tiles interleave; every tile ends the attempt holding
   exactly one unmatched claim, so next_appendvec lands on T+N. */
static void
test_eager_claim_coverage( void ) {
  ulong const tile_cnts[] = { 1UL, 2UL, 4UL, 8UL };
  int   const orders   [] = { TEST_ORDER_ROUND_ROBIN, TEST_ORDER_TILE_MAJOR, TEST_ORDER_REVERSE };
  ulong const T = 13UL;

  for( ulong n_idx=0UL; n_idx<sizeof(tile_cnts)/sizeof(tile_cnts[0]); n_idx++ ) {
    ulong n = tile_cnts[ n_idx ];
    for( ulong o_idx=0UL; o_idx<sizeof(orders)/sizeof(orders[0]); o_idx++ ) {
      test_cluster_t * cl = test_cluster_new( n, 1UL );
      test_counters_reset();
      test_stream_init( T );

      cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
      /* Only tile 0 claims at INIT (it publishes the slot its own gate
         waits on); every other tile draws its claim when its first data
         frag opens its gate. */
      FD_TEST( cl->hdr->next_appendvec==1UL );
      FD_TEST( cl->ctx[ 0 ].claimed_appendvec==0UL );
      for( ulong t=1UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].gate_pending );

      ulong owner[ TEST_AV_MAX ];
      cluster_stream( cl, orders[ o_idx ], owner );
      for( ulong t=0UL; t<n; t++ ) FD_TEST( !cl->ctx[ t ].gate_pending );

      ulong owned_sum = 0UL;
      for( ulong t=0UL; t<n; t++ ) owned_sum += cl->ctx[ t ].owned_appendvecs;
      FD_TEST( owned_sum==T );
      FD_TEST( test_appendvec_parse_cnt==T ); /* the parser was flipped exactly once per ordinal */

      /* A single tile owns everything, in stream order. */
      if( n==1UL ) {
        FD_TEST( cl->ctx[ 0 ].owned_appendvecs==T );
        for( ulong i=0UL; i<T; i++ ) FD_TEST( owner[ i ]==0UL );
        ulong bytes = 0UL;
        for( ulong i=0UL; i<T; i++ ) bytes += test_av_sz[ i ];
        FD_TEST( cl->ctx[ 0 ].owned_bytes==bytes );
      }

      /* Owned bytes always add up to the owned ordinals' body sizes. */
      for( ulong t=0UL; t<n; t++ ) {
        ulong bytes = 0UL;
        for( ulong i=0UL; i<T; i++ ) if( owner[ i ]==t ) bytes += test_av_sz[ i ];
        FD_TEST( cl->ctx[ t ].owned_bytes==bytes );
      }

      cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
      FD_TEST( cl->hdr->totals.appendvecs_processed==T );
      FD_TEST( cl->hdr->next_appendvec==T+n ); /* T consumed claims + N unmatched */

      test_cluster_delete( cl );
    }
  }
}

/* Retry resets ********************************************************/

/* A failed attempt leaves nothing behind for the retry: the shared
   claim counter is re-zeroed and the claim sequence restarts at 0, no
   ordinal is processed twice, and every tile's per-attempt parse state
   is back to zero. */
static void
test_retry_resets( void ) {
  ulong const n = 4UL;
  ulong const T = 9UL;

  test_cluster_t * cl = test_cluster_new( n, 1UL );
  test_counters_reset();
  test_stream_init( T );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( cl->hdr->next_appendvec==1UL );

  /* Partial walk: every tile gets three events in. */
  for( ulong step=0UL; step<3UL; step++ ) {
    for( ulong t=0UL; t<n; t++ ) (void)tile_step( &cl->ctx[ t ] );
  }
  ulong mid_claims = cl->hdr->next_appendvec;
  FD_TEST( mid_claims>n );

  /* Every tile acquired partitions during the attempt; the FAIL handler
     must publish each list for tile 0's deferred rollback. */
  for( ulong t=0UL; t<n; t++ ) {
    cl->ctx[ t ].whead.attempt_partition_cnt = 2UL+t;
    for( ulong i=0UL; i<2UL+t; i++ ) cl->ctx[ t ].my_snoop->fail_partitions[ i ] = (uint)(100UL*t+i);
  }

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  for( ulong t=0UL; t<n; t++ ) {
    fd_snapin_tile_t * ctx = &cl->ctx[ t ];
    FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
    FD_TEST( !ctx->appendvec_seq );
    FD_TEST( !ctx->owned_appendvecs );
    FD_TEST( !ctx->owned_bytes );
    FD_TEST( ctx->incr_fork==ULONG_MAX );
    FD_TEST( ctx->my_snoop->fail_partition_cnt==2UL+t ); /* published for the rollback */
  }
  FD_TEST( cl->ctx[ 0 ].rollback.pending );
  FD_TEST( cl->ctx[ 0 ].rollback.full );
  /* The claim counter is deliberately NOT reset by FAIL: only tile 0's
     next INIT re-zeroes it. */
  FD_TEST( cl->hdr->next_appendvec==mid_claims );

  /* Retry.  Tile 0 rolls back first, then re-zeroes and republishes. */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );

  FD_TEST( !cl->ctx[ 0 ].rollback.pending );
  FD_TEST( test_accdb_reset_cnt==1UL );      /* full retry wipes the fork wholesale */
  FD_TEST( !test_accdb_purge_cnt );          /* ... so no incremental purge */
  FD_TEST( !test_accdb_release_cnt );        /* ... and no partition release */
  FD_TEST( !cl->ctx[ 0 ].doomed_partition_cnt );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( !cl->ctx[ t ].my_snoop->fail_partition_cnt ); /* gathered and cleared */

  FD_TEST( cl->hdr->next_appendvec==1UL );   /* claim sequence restarted at 0 */
  FD_TEST( cl->ctx[ 0 ].claimed_appendvec==0UL );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].generation==2UL );
  for( ulong t=1UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].gate_pending );

  /* The retry covers every ordinal exactly once (cluster_stream would
     trip on a double claim). */
  ulong owner[ TEST_AV_MAX ];
  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( cl->hdr->totals.appendvecs_processed==T );
  FD_TEST( cl->hdr->next_appendvec==T+n );
  FD_TEST( !cl->hdr->totals.eq_slot_dups );

  test_cluster_delete( cl );
}

/* FINI gates **********************************************************/

/* FINI can only arrive after the tile's own parser reached EOF (every
   tile walks the whole tar itself).  A FINI in PROCESSING means the
   stream was truncated: the tile must flag the snapshot malformed and
   NOT ack the FINI. */
static void
test_fini_truncated_malform( void ) {
  ulong const n = 2UL;
  test_cluster_t * cl = test_cluster_new( n, 1UL );
  test_counters_reset();
  test_stream_init( 4UL );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );

  /* Two of four appendvecs in: the parser never returned DONE. */
  for( ulong t=0UL; t<n; t++ ) { (void)tile_step( &cl->ctx[ t ] ); (void)tile_step( &cl->ctx[ t ] ); }
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_PROCESSING );

  ulong pub0 = test_pub_cnt;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );

  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_ERROR );
  /* One unsolicited ERROR per tile, and no FINI ack from any of them. */
  FD_TEST( test_pub_cnt==pub0+n );
  for( ulong i=pub0; i<test_pub_cnt; i++ ) FD_TEST( test_pub_sig[ i ]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  /* Nothing was folded: tile 0 must not read a partial attempt. */
  FD_TEST( !cl->hdr->totals.appendvecs_processed );

  /* In ERROR only FAIL flows; everything else is held. */
  FD_TEST( before_frag( &cl->ctx[ 0 ], 0UL, 0UL, FD_SNAPSHOT_MSG_DATA )==1 );
  FD_TEST( before_frag( &cl->ctx[ 0 ], 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_NEXT )==1 );
  FD_TEST( before_frag( &cl->ctx[ 0 ], 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL )==0 );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_IDLE );

  test_cluster_delete( cl );
}

/* Equal-slot cross-appendvec duplicates are accepted, not fatal (see
   the eq-slot branch in fd_accdb_snapshot_write_batch_worker): the
   load completes and every tile, including the one that saw the
   duplicates, acks FINI normally and folds its counters. */
static void
test_eq_slot_fini_accepts( void ) {
  ulong const n = 4UL;
  ulong const T = 6UL;

  /* Drive the duplicate from a non-zero tile: counting is per tile,
     not a tile-0 privilege. */
  for( ulong bad=1UL; bad<n; bad+=2UL ) {
    test_cluster_t * cl = test_cluster_new( n, 1UL );
    test_counters_reset();
    test_stream_init( T );

    cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
    ulong owner[ TEST_AV_MAX ];
    cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );

    for( ulong t=0UL; t<n; t++ ) cl->ctx[ t ].worker.accounts_loaded = 10UL;
    cl->ctx[ bad ].worker_metrics->eq_slot_dups          = 3UL;
    cl->ctx[ bad ].worker_metrics->eq_slot_lamports_diff = 2UL;

    ulong pub0 = test_pub_cnt;
    cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );

    /* Every tile acks FINI, no ERROR, no withheld fold. */
    FD_TEST( test_pub_cnt==pub0+n );
    for( ulong t=0UL; t<n; t++ ) FD_TEST( test_pub_sig[ pub0+t ]==FD_SNAPSHOT_MSG_CTRL_FINI );
    for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_FINISHING );

    /* The flagging tile's counters, dups included, are folded like
       everyone else's. */
    FD_TEST( cl->hdr->totals.accounts_loaded==10UL*n );
    FD_TEST( cl->hdr->totals.eq_slot_dups==3UL );
    FD_TEST( cl->hdr->totals.eq_slot_lamports_diff==2UL );
    FD_TEST( cl->hdr->totals.appendvecs_processed==T );

    test_cluster_delete( cl );
  }
}

/* Accumulator fold ****************************************************/

/* Every tile FD_ATOMIC_FETCH_AND_ADDs its FINI-time locals straight
   into hdr->totals, and tile 0 reads that fold at NEXT: known per-tile
   locals must produce exact totals and exact derived tile-0 gauges. */
static void
test_accumulator_fold( void ) {
  ulong const n = 4UL;
  ulong const T = 8UL;
  ulong const bank_slot = 440123518UL;

  test_cluster_t * cl = test_cluster_new( n, 1UL );
  test_counters_reset();
  test_stream_init( T );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  ulong owner[ TEST_AV_MAX ];
  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );

  /* Known per-tile locals.  owned_appendvecs is left as the stream walk
     produced it: tile 0's fold asserts the claim identity against it. */
  ulong exp_loaded=0UL, exp_replaced=0UL, exp_ignored=0UL;
  ulong exp_input=0UL, exp_repl_l=0UL, exp_ign_l=0UL, exp_bytes=0UL;
  for( ulong t=0UL; t<n; t++ ) {
    fd_snapin_tile_t * ctx = &cl->ctx[ t ];
    ctx->worker.accounts_loaded   = 1000UL+t;
    ctx->worker.accounts_replaced =   20UL+t;
    ctx->worker.accounts_ignored  =    3UL+t;
    ctx->worker.input_lamports    = 1000000UL*(t+1UL);
    ctx->worker.replaced_lamports =   5000UL*(t+1UL);
    ctx->worker.ignored_lamports  =    700UL*(t+1UL);
    ctx->bytes_written            = 4096UL*(t+1UL);
    /* Gauges the tile must keep live through FINI: the dashboards sum
       them across all snapin tiles, so a per-tile dip at the barrier (or
       tile 0 folding the cross-tile total into its own) breaks them. */
    ctx->metrics.accounts_loaded   = 77UL;
    ctx->metrics.accounts_replaced = 78UL;
    ctx->metrics.accounts_ignored  = 79UL;

    exp_loaded   += ctx->worker.accounts_loaded;
    exp_replaced += ctx->worker.accounts_replaced;
    exp_ignored  += ctx->worker.accounts_ignored;
    exp_input    += ctx->worker.input_lamports;
    exp_repl_l   += ctx->worker.replaced_lamports;
    exp_ign_l    += ctx->worker.ignored_lamports;
    exp_bytes    += ctx->bytes_written;
  }

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );

  fd_snapio_totals_t const * tot = &cl->hdr->totals;
  FD_TEST( tot->accounts_loaded      ==exp_loaded   );
  FD_TEST( tot->accounts_replaced    ==exp_replaced );
  FD_TEST( tot->accounts_ignored     ==exp_ignored  );
  FD_TEST( tot->input_lamports       ==exp_input    );
  FD_TEST( tot->replaced_lamports    ==exp_repl_l   );
  FD_TEST( tot->ignored_lamports     ==exp_ign_l    );
  FD_TEST( tot->bytes_written        ==exp_bytes    );
  FD_TEST( tot->appendvecs_processed ==T            );
  FD_TEST( !tot->eq_slot_dups && !tot->eq_slot_lamports_diff );
  for( ulong t=0UL; t<n; t++ ) {
    FD_TEST( cl->ctx[ t ].metrics.accounts_loaded  ==77UL );
    FD_TEST( cl->ctx[ t ].metrics.accounts_replaced==78UL );
    FD_TEST( cl->ctx[ t ].metrics.accounts_ignored ==79UL );
  }

  /* Tile 0 reads the fold at NEXT.  A full attempt's capitalization is
     input - ignored - replaced; the manifest value it is checked
     against is what process_manifest would have parsed. */
  test_stamp_slot_history( cl, bank_slot );
  cl->ctx[ 0 ].manifest_capitalization = exp_input-exp_ign_l-exp_repl_l;

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_NEXT );

  fd_snapin_tile_t * t0 = &cl->ctx[ 0 ];
  FD_TEST( t0->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( t0->attempt_folded );
  /* The cross-tile fold lands in tile 0's diagnostic totals, NOT in its
     gauge: the gauges stay per-tile so the dashboards' sum is exact. */
  FD_TEST( t0->totals_fold.accounts_loaded  ==exp_loaded   );
  FD_TEST( t0->totals_fold.accounts_replaced==exp_replaced );
  FD_TEST( t0->totals_fold.accounts_ignored ==exp_ignored  );
  FD_TEST( t0->dup_capitalization       ==exp_repl_l   );
  FD_TEST( t0->capitalization           ==exp_input-exp_ign_l-exp_repl_l );
  FD_TEST( t0->worker_fold.bytes_written==exp_bytes    );
  FD_TEST( !t0->worker_fold.eq_slot_dups && !t0->worker_fold.eq_slot_lamports_diff );
  /* The full snapshot's totals are saved for the incremental revert. */
  FD_TEST( t0->recovery.capitalization    ==t0->capitalization );
  /* Every tile latched its own share, and the cross-tile sum is
     unchanged by the barrier -- that is the continuity the GUI and the
     snapshot-load watch depend on. */
  ulong gauge_sum = 0UL;
  for( ulong t=0UL; t<n; t++ ) {
    FD_TEST( cl->ctx[ t ].metrics.full_accounts_loaded  ==77UL );
    FD_TEST( cl->ctx[ t ].metrics.accounts_loaded       ==77UL );
    gauge_sum += cl->ctx[ t ].metrics.accounts_loaded;
  }
  FD_TEST( gauge_sum==77UL*n );
  FD_TEST( t0->slot_history.captured );
  FD_TEST( t0->slot_history.data_len==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  test_cluster_delete( cl );
}

/* The per-tile ACCOUNT_LOADED gauges must never dip mid-load: the GUI
   and the snapshot-load watch sum them across all snapin tiles and take
   deltas off that sum.  Walk a full load, an incremental load and a
   failed-then-retried incremental, sampling the sum at every barrier. */
static void
test_gauge_sum_continuity( void ) {
  ulong const n = 4UL;
  ulong const T = 6UL;
  ulong const bank_slot = 440123518UL;

  test_cluster_t * cl = test_cluster_new( n, 1UL );
  test_counters_reset();
  test_stream_init( T );
  ulong owner[ TEST_AV_MAX ];

# define GAUGE_SUM() (__extension__({                                            \
    ulong _s = 0UL;                                                              \
    for( ulong _t=0UL; _t<n; _t++ ) _s += cl->ctx[ _t ].metrics.accounts_loaded;  \
    _s; }))

  /* --- Full load ------------------------------------------------- */
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( !GAUGE_SUM() );
  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );

  ulong full_share = 100UL;
  for( ulong t=0UL; t<n; t++ ) {
    cl->ctx[ t ].metrics.accounts_loaded = full_share;
    cl->ctx[ t ].worker.accounts_loaded  = full_share;
  }
  FD_TEST( GAUGE_SUM()==full_share*n );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( GAUGE_SUM()==full_share*n );   /* was ~0 before: every tile zeroed here */

  test_stamp_slot_history( cl, bank_slot );
  cl->ctx[ 0 ].manifest_capitalization = 0UL;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_NEXT );
  FD_TEST( GAUGE_SUM()==full_share*n );   /* was full_share*n + the fold: double counted */
  FD_TEST( cl->ctx[ 0 ].totals_fold.accounts_loaded==full_share*n );

  /* --- Incremental that fails ------------------------------------ */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( GAUGE_SUM()==full_share*n );   /* resumes from the full share */

  for( ulong t=0UL; t<n; t++ ) cl->ctx[ t ].metrics.accounts_loaded += 7UL;
  FD_TEST( GAUGE_SUM()==(full_share+7UL)*n );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( GAUGE_SUM()==(full_share+7UL)*n ); /* FAIL alone does not rewind */

  /* --- Incremental retry ----------------------------------------- */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  /* The retry's INIT is the one point the sum steps back, and only by
     the failed attempt's own contribution -- never to zero. */
  FD_TEST( GAUGE_SUM()==full_share*n );

  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );
  ulong incr_share = 11UL;
  for( ulong t=0UL; t<n; t++ ) {
    cl->ctx[ t ].metrics.accounts_loaded += incr_share;
    cl->ctx[ t ].worker.accounts_loaded   = incr_share;
  }
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( GAUGE_SUM()==(full_share+incr_share)*n );

  test_stamp_slot_history( cl, bank_slot );
  cl->ctx[ 0 ].manifest_capitalization = cl->ctx[ 0 ].recovery.capitalization;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_DONE );
  FD_TEST( GAUGE_SUM()==(full_share+incr_share)*n );
  /* Tile 0's diagnostic total accumulates over the session. */
  FD_TEST( cl->ctx[ 0 ].totals_fold.accounts_loaded==(full_share+incr_share)*n );

# undef GAUGE_SUM

  test_cluster_delete( cl );
}

/* Full lifecycle ******************************************************/

/* Eight tiles through a whole load: full attempt, an incremental
   attempt that fails and is retried, then the successful incremental
   promotion.  Pins the cross-attempt bookkeeping the individual cases
   above only touch in isolation. */
static void
test_full_lifecycle_8_tiles( void ) {
  ulong const n = 8UL;
  ulong const T = 11UL;
  ulong const bank_slot = 440123518UL;

  test_cluster_t * cl = test_cluster_new( n, 2UL );
  test_counters_reset();
  test_stream_init( T );
  ulong owner[ TEST_AV_MAX ];

  /* --- Full attempt --------------------------------------------- */
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( test_accdb_reset_cnt==1UL );
  FD_TEST( test_accdb_load_begin_writers==n );
  FD_TEST( test_accdb_writer_begin_cnt==1UL );   /* tile 0 only; the rest are gated */
  FD_TEST( cl->hdr->next_appendvec==1UL );
  FD_TEST( cl->ctx[ 0 ].incr_fork==(ulong)USHORT_MAX );

  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );
  FD_TEST( test_accdb_writer_begin_cnt==n );     /* every gate opened on first data */
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].incr_fork==(ulong)USHORT_MAX );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_accdb_worker_close_cnt==n );
  FD_TEST( test_accdb_writer_end_cnt==n );
  FD_TEST( cl->hdr->totals.appendvecs_processed==T );

  test_stamp_slot_history( cl, bank_slot );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_NEXT );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !cl->ctx[ 0 ].init_completed );

  /* --- Incremental attempt that fails --------------------------- */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( !test_accdb_reset_cnt );
  FD_TEST( test_accdb_attach_cnt==1UL );          /* child fork for the incremental writes */
  FD_TEST( cl->hdr->attempt.fork_id==7UL );
  FD_TEST( cl->ctx[ 0 ].incr_fork==7UL );
  FD_TEST( cl->hdr->next_appendvec==1UL );

  for( ulong step=0UL; step<4UL; step++ ) {
    for( ulong t=0UL; t<n; t++ ) (void)tile_step( &cl->ctx[ t ] );
  }
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].incr_fork==7UL );
  ulong exp_release = 0UL;
  for( ulong t=0UL; t<n; t++ ) {
    cl->ctx[ t ].whead.attempt_partition_cnt = 1UL+t;
    exp_release += 1UL+t;
  }
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( cl->ctx[ 0 ].rollback.pending );
  FD_TEST( !cl->ctx[ 0 ].rollback.full );
  FD_TEST( cl->ctx[ 0 ].accdb_incr_fork_id.val==USHORT_MAX );

  /* --- Incremental retry ---------------------------------------- */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( test_accdb_purge_cnt==1UL );                    /* failed fork purged */
  FD_TEST( test_accdb_release_cnt==1UL );                  /* its partitions released */
  FD_TEST( test_accdb_release_total==exp_release );
  FD_TEST( !cl->ctx[ 0 ].doomed_partition_cnt );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( !cl->ctx[ t ].my_snoop->fail_partition_cnt );
  FD_TEST( cl->hdr->next_appendvec==1UL );

  cluster_stream( cl, TEST_ORDER_REVERSE, owner );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( cl->hdr->totals.appendvecs_processed==T );
  FD_TEST( cl->hdr->next_appendvec==T+n );

  /* An incremental load's capitalization starts from the full
     snapshot's saved total; nothing was inserted here, so it is
     unchanged. */
  test_stamp_slot_history( cl, bank_slot );
  cl->ctx[ 0 ].manifest_capitalization = cl->ctx[ 0 ].recovery.capitalization;

  ulong pub0 = test_pub_cnt;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_DONE );
  FD_TEST( test_accdb_readback_cnt==1UL );
  FD_TEST( test_accdb_recover_delta_cnt==1UL );
  FD_TEST( test_accdb_advance_root_cnt==1UL );
  FD_TEST( test_accdb_load_end_cnt==1UL );
  FD_TEST( test_feature_finalize_cnt==1UL );
  FD_TEST( cl->ctx[ 0 ].accdb_root_fork_id.val==7U );
  FD_TEST( cl->ctx[ 0 ].accdb_incr_fork_id.val==USHORT_MAX );
  /* n DONE acks plus tile 0's replay notification on snapin_manif. */
  FD_TEST( test_pub_cnt==pub0+n+1UL );
  ulong manif_pubs = 0UL;
  for( ulong i=pub0; i<test_pub_cnt; i++ ) manif_pubs += test_pub_out_idx[ i ]==0UL;
  FD_TEST( manif_pubs==1UL );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN );
  for( ulong t=0UL; t<n; t++ ) {
    FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_SHUTDOWN );
    FD_TEST( should_shutdown( &cl->ctx[ t ] ) );
  }

  test_cluster_delete( cl );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_scratch_layout_fits();
  test_init_gate_holds_data();
  test_init_aborted_barrier_retries();
  test_init_gate_rejects_stale_generation();
  test_init_publishes_after_reset();
  test_eager_claim_coverage();
  test_retry_resets();
  test_fini_truncated_malform();
  test_eq_slot_fini_accepts();
  test_accumulator_fold();
  test_gauge_sum_continuity();
  test_full_lifecycle_8_tiles();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
