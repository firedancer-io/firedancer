/* Unit tests for the N symmetric fused snapin tiles of the parallel
   (tar-boundary-sharded) snapshot loader.

   There is no coordinator and no message-passing protocol between the
   tiles, so the harness models a cluster directly: N real
   fd_snapin_tile_t contexts sharing one real snapin_shmem object, each
   driven frag by frag through returnable_frag/before_frag.  The accdb,
   ssparse and stem entry points the tile calls out to are mocked, so
   what these tests pin is the tile's own protocol: shared fork
   publication, claim counter, per-attempt resets, FINI malform gates
   and the FINI->totals fold. */

#define _GNU_SOURCE
#include "../../disco/stem/fd_stem.h"
#include "../../flamenco/accdb/fd_accdb_base.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_slot_delta_parser.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

struct test_io_step {
  long result;
  int  err;
};

typedef struct test_io_step test_io_step_t;

static test_io_step_t test_pwrite_steps[ 16UL ];
static ulong test_pwrite_step_cnt;
static ulong test_pwrite_step_idx;
static ulong test_pwrite_call_cnt;
static ulong test_pwrite_sz  [ 16UL ];
static ulong test_pwrite_off [ 16UL ];
static uchar test_pwrite_data[ 16UL ][ 8UL ];

static void
test_io_reset( void ) {
  test_pwrite_step_cnt = 0UL;
  test_pwrite_step_idx = 0UL;
  test_pwrite_call_cnt = 0UL;
  fd_memset( test_pwrite_sz,   0, sizeof(test_pwrite_sz)   );
  fd_memset( test_pwrite_off,  0, sizeof(test_pwrite_off)  );
  fd_memset( test_pwrite_data, 0, sizeof(test_pwrite_data) );
}

static void
test_pwrite_push( long result,
                  int  err ) {
  FD_TEST( test_pwrite_step_cnt<16UL );
  test_pwrite_steps[ test_pwrite_step_cnt++ ] = (test_io_step_t){ result, err };
}

static long
test_pwrite( int          fd,
             void const * buf,
             ulong        sz,
             long         off ) {
  (void)fd;
  FD_TEST( test_pwrite_call_cnt<16UL );
  ulong call_idx = test_pwrite_call_cnt++;
  test_pwrite_sz [ call_idx ] = sz;
  test_pwrite_off[ call_idx ] = (ulong)off;
  fd_memcpy( test_pwrite_data[ call_idx ], buf, fd_ulong_min( sz, 8UL ) );
  if( test_pwrite_step_idx>=test_pwrite_step_cnt ) return (long)sz;
  test_io_step_t step = test_pwrite_steps[ test_pwrite_step_idx++ ];
  if( step.result<0L ) errno = step.err;
  return step.result;
}

/* Recorded stem publishes. */
static ulong test_pub_sig[ 64UL ];
static ulong test_pub_out_idx[ 64UL ];
static ulong test_pub_cnt;

/* Mock accdb call counters. */
static ulong test_accdb_reset_cnt;
static ulong test_accdb_attach_cnt;
static ulong test_accdb_purge_cnt;
static int   test_parser_script;
static ulong test_parser_call_cnt;
static ulong test_accdb_advance_root_cnt;
static ulong test_accdb_load_begin_cnt;
static ulong test_accdb_load_end_cnt;
static ulong test_accdb_flush_metrics_cnt;
static ulong test_accdb_recover_delta_cnt;
static ulong test_accdb_save_whead_cnt;
static ulong test_accdb_revert_whead_cnt;
static ulong test_feature_restore_cnt;
static fd_accdb_fork_id_t test_feature_restore_fork;
static ulong  test_stake_new_fork_cnt;
static ulong  test_stake_publish_cnt;
static ushort test_stake_publish_fork;
static ulong  test_stake_evict_cnt;
static ushort test_stake_evict_fork;
static ulong test_accdb_read_one_cnt;
static fd_accdb_fork_id_t test_accdb_read_one_fork;
static ulong test_appendvec_parse_cnt;
static ulong test_file_off;

/* Mock ssparse stream: test_av_cnt appendvec entries, then DONE.  Every
   tile walks the same stream independently, so the position is
   per-tile and the driver stamps test_cur_tile before each frag. */
#define TEST_TILE_MAX (9UL)
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

void
mock_txncache_reset( fd_txncache_t * txncache );

void *
mock_txncache_snapin_scratch( fd_txncache_t * txncache,
                              ulong *         out_sz );

void
mock_slot_delta_parser_init( fd_slot_delta_parser_t * parser );

static fd_txncache_fork_id_t
record_txncache_attach_child( fd_txncache_t *       txncache,
                              fd_txncache_fork_id_t parent_fork_id );

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
#define fd_accdb_snapshot_load_begin                 mock_accdb_snapshot_load_begin
#define fd_accdb_snapshot_load_end                   mock_accdb_snapshot_load_end
#define fd_accdb_flush_metrics                       mock_accdb_flush_metrics
#define fd_accdb_snapshot_recover_delta              mock_accdb_snapshot_recover_delta
#define fd_accdb_snapshot_save_whead                 mock_accdb_snapshot_save_whead
#define fd_accdb_snapshot_revert_whead               mock_accdb_snapshot_revert_whead
#define fd_accdb_snapshot_reserve_write              mock_accdb_snapshot_reserve_write
#define fd_accdb_snapshot_write_batch                mock_accdb_snapshot_write_batch
#define fd_accdb_read_one_nocache                    mock_accdb_read_one_nocache
#define fd_txncache_reset                            mock_txncache_reset
#define fd_txncache_snapin_scratch                   mock_txncache_snapin_scratch
#define fd_ssmanifest_parser_init                    mock_ssmanifest_parser_init
#define fd_slot_delta_parser_init                    mock_slot_delta_parser_init
#define fd_stake_delegations_reset                   mock_stake_delegations_reset
#define fd_stake_delegations_new_fork                mock_stake_delegations_new_fork
#define fd_stake_delegations_snapshot_publish_fork   mock_stake_delegations_snapshot_publish_fork
#define fd_stake_delegations_evict_fork              mock_stake_delegations_evict_fork
#define fd_features_restore_chunk                    mock_features_restore_chunk
#define fd_stem_publish                              test_stem_publish
#define fd_ssparse_advance                           test_ssparse_advance
#define fd_ssparse_appendvec_parse                   test_ssparse_appendvec_parse
#define fd_txncache_attach_child                     record_txncache_attach_child
#define pwrite                                       test_pwrite
#include "fd_snapin_tile.c"

/* Size of a flush after direct-IO padding (mirrors writer_flush). */
static ulong
test_padded_sz( ulong used ) {
  return fd_ulong_align_up( used+sizeof(fd_accdb_disk_meta_t), FD_SNAPIN_DIRECT_ALIGN );
}
#undef pwrite
#include "../../disco/pack/fd_pack_cost.h"
#undef fd_txncache_attach_child
#undef fd_ssparse_appendvec_parse
#undef fd_ssparse_advance
#undef fd_stem_publish
#undef fd_features_restore_chunk
#undef fd_stake_delegations_evict_fork
#undef fd_stake_delegations_snapshot_publish_fork
#undef fd_stake_delegations_new_fork
#undef fd_stake_delegations_reset
#undef fd_slot_delta_parser_init
#undef fd_ssmanifest_parser_init
#undef fd_txncache_snapin_scratch
#undef fd_txncache_reset
#undef fd_accdb_read_one_nocache
#undef fd_accdb_snapshot_write_batch
#undef fd_accdb_snapshot_reserve_write
#undef fd_accdb_snapshot_revert_whead
#undef fd_accdb_snapshot_save_whead
#undef fd_accdb_snapshot_recover_delta
#undef fd_accdb_flush_metrics
#undef fd_accdb_snapshot_load_end
#undef fd_accdb_snapshot_load_begin
#undef fd_accdb_advance_root
#undef fd_accdb_purge
#undef fd_accdb_attach_child
#undef fd_accdb_reset

#include <stdlib.h>
#include "../../flamenco/stakes/test_stake_delegations_util.h"

static fd_snapin_tile_t * test_ctx;

/* Sysvar accounts served by the accdb mock (lamports==0: absent). */
struct test_sysvar {
  ulong lamports;
  ulong data_len;
  uchar owner[ 32UL ];
  uchar data[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ+64UL ];
};
typedef struct test_sysvar test_sysvar_t;
static test_sysvar_t test_sysvars[ FD_SYSVAR_CACHE_ENTRY_CNT ];

/* Outcome mock_accdb_snapshot_write_batch reports for every account. */
static uchar test_write_result = FD_ACCDB_SNAPSHOT_WRITE_LOADED;

/* The mocks above hide these prototypes; tests reach the real ones. */
ushort fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations );
void   fd_stake_delegations_snapshot_publish_fork( fd_stake_delegations_t * stake_delegations, ushort fork_idx );
static uchar test_slot_history_data[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];

/* Production per-slot limits (tile->snapin.max_txn_per_slot and its
   derived staging bounds). */
#define TEST_MAX_GROUPS_PER_SLOT  (FD_MAX_TXN_PER_SLOT)
#define TEST_MAX_ENTRIES_PER_SLOT (2UL*FD_MAX_TXN_PER_SLOT)
#define TEST_MAX_STAGED_GROUPS    (FD_TXNCACHE_MAX_SLOT_DELTAS*TEST_MAX_GROUPS_PER_SLOT)
#define TEST_MAX_ENTRIES          (FD_TXNCACHE_MAX_SLOT_DELTAS*TEST_MAX_ENTRIES_PER_SLOT)

static fd_txncache_fork_id_t test_attached_fork_id[ FD_BLOCKHASHES_MAX ];
static ulong                 test_attached_fork_cnt;

static fd_txncache_fork_id_t
record_txncache_attach_child( fd_txncache_t *       txncache,
                              fd_txncache_fork_id_t parent_fork_id ) {
  fd_txncache_fork_id_t fork_id = fd_txncache_attach_child( txncache, parent_fork_id );
  FD_TEST( test_attached_fork_cnt<FD_BLOCKHASHES_MAX );
  test_attached_fork_id[ test_attached_fork_cnt++ ] = fork_id;
  return fork_id;
}

/* Mocks ***************************************************************/

void mock_accdb_reset                            ( fd_accdb_t * accdb ) { (void)accdb; test_file_off=0UL; test_accdb_reset_cnt++; }
void mock_accdb_snapshot_load_end                ( fd_accdb_t * accdb ) { (void)accdb; test_accdb_load_end_cnt++;      }
void mock_accdb_flush_metrics                    ( fd_accdb_t * accdb ) { (void)accdb; test_accdb_flush_metrics_cnt++; }

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

void mock_accdb_snapshot_load_begin( fd_accdb_t * accdb ) { (void)accdb; test_accdb_load_begin_cnt++; }

int
mock_accdb_snapshot_recover_delta( fd_accdb_t *       accdb,
                                   fd_accdb_fork_id_t fork_id ) {
  (void)accdb;
  (void)fork_id;
  test_accdb_recover_delta_cnt++;
  return 0;
}

void
mock_accdb_snapshot_save_whead( fd_accdb_t *                   accdb,
                                fd_accdb_snapshot_recovery_t * out ) {
  (void)accdb;
  fd_memset( out, 0, sizeof(*out) );
  out->whead_val = test_file_off;
  test_accdb_save_whead_cnt++;
}

void
mock_accdb_snapshot_revert_whead( fd_accdb_t *                         accdb,
                                  fd_accdb_snapshot_recovery_t const * recover ) {
  (void)accdb;
  test_file_off = recover->whead_val;
  test_accdb_revert_whead_cnt++;
}

ulong
mock_accdb_snapshot_reserve_write( fd_accdb_t * accdb,
                                   ulong        sz ) {
  (void)accdb;
  return FD_ATOMIC_FETCH_AND_ADD( &test_file_off, sz );
}

int
mock_accdb_read_one_nocache( fd_accdb_t *       accdb,
                             fd_accdb_fork_id_t fork_id,
                             uchar const *      pubkey,
                             ulong *            out_lamports,
                             int *              out_executable,
                             uchar *            out_owner,
                             uchar *            out_data,
                             ulong *            out_data_len ) {
  (void)accdb;
  ulong idx;
  for( idx=0UL; idx<FD_SYSVAR_CACHE_ENTRY_CNT; idx++ ) {
    if( !memcmp( pubkey, snapin_sysvar_tbl[ idx ].id->uc, 32UL ) ) break;
  }
  FD_TEST( idx<FD_SYSVAR_CACHE_ENTRY_CNT );
  test_accdb_read_one_cnt++;
  test_accdb_read_one_fork = fork_id;
  test_sysvar_t const * sv = &test_sysvars[ idx ];
  *out_lamports = sv->lamports;
  if( FD_UNLIKELY( !sv->lamports ) ) return FD_ACCDB_READ_ONE_NOCACHE_MISS;
  *out_executable = 0;
  *out_data_len   = sv->data_len;
  fd_memcpy( out_owner, sv->owner, 32UL );
  fd_memcpy( out_data,  sv->data,  sv->data_len );
  return FD_ACCDB_READ_ONE_NOCACHE_DISK;
}

int
mock_accdb_snapshot_write_batch( fd_accdb_t *                         accdb,
                                 fd_accdb_fork_id_t                   fork_id,
                                 ulong                                cnt,
                                 uchar const * const                  pubkeys[],
                                 ulong const                          slots[],
                                 ulong const                          lamports[],
                                 ulong const                          data_lens[],
                                 int const                            executables[],
                                 ulong const                          file_offsets[],
                                 ulong *                              accounts_ignored,
                                 ulong *                              accounts_replaced,
                                 ulong *                              accounts_loaded,
                                 ulong *                              out_replaced_lamports,
                                 ulong *                              out_ignored_lamports,
                                 uchar *                              results ) {
  (void)accdb;
  (void)fork_id;
  (void)pubkeys;
  (void)slots;
  (void)lamports;
  (void)data_lens;
  (void)executables;
  (void)file_offsets;
  *accounts_ignored      = 0UL;
  *accounts_replaced     = 0UL;
  *accounts_loaded       = cnt;
  *out_replaced_lamports = 0UL;
  *out_ignored_lamports  = 0UL;
  fd_memset( results, test_write_result, cnt );
  return 0;
}

void mock_txncache_reset( fd_txncache_t * tc ) { (void)tc; }

void *
mock_txncache_snapin_scratch( fd_txncache_t * txncache,
                              ulong *         out_sz ) {
  if( FD_UNLIKELY( !txncache ) ) {
    *out_sz = TEST_MAX_STAGED_GROUPS*sizeof(blockhash_group_t);
    return (void *)4096UL;
  }
  return fd_txncache_snapin_scratch( txncache, out_sz );
}

void
mock_ssmanifest_parser_init( fd_ssmanifest_parser_t * parser,
                             fd_snapshot_manifest_t * manifest ) {
  (void)parser;
  (void)manifest;
}

void
mock_slot_delta_parser_init( fd_slot_delta_parser_t * parser ) {
  (void)parser;
}

void mock_stake_delegations_reset( fd_stake_delegations_t * sd ) { (void)sd; }

ushort
mock_stake_delegations_new_fork( fd_stake_delegations_t * sd ) {
  (void)sd;
  test_stake_new_fork_cnt++;
  return (ushort)3;
}

void
mock_stake_delegations_snapshot_publish_fork( fd_stake_delegations_t * sd,
                                              ushort                   fork_idx ) {
  (void)sd;
  test_stake_publish_cnt++;
  test_stake_publish_fork = fork_idx;
}

void
mock_stake_delegations_evict_fork( fd_stake_delegations_t * sd,
                                   ushort                   fork_idx ) {
  (void)sd;
  test_stake_evict_cnt++;
  test_stake_evict_fork = fork_idx;
}

void
mock_features_restore_chunk( fd_features_t *             features,
                             fd_accdb_t *                accdb,
                             fd_accdb_fork_id_t          fork_id,
                             ulong                       slot,
                             fd_epoch_schedule_t const * epoch_schedule,
                             ulong                       chunk_idx,
                             ulong                       chunk_cnt ) {
  (void)features;
  (void)accdb;
  (void)slot;
  (void)epoch_schedule;
  FD_TEST( !chunk_idx );
  FD_TEST( chunk_cnt==1UL );
  test_feature_restore_fork = fork_id;
  test_feature_restore_cnt++;
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
                      fd_ssparse_advance_result_t * result ) {
  (void)parser;
  if( FD_UNLIKELY( !test_parser_script ) ) {
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

  FD_TEST( test_parser_script>=1 && test_parser_script<=4 );
  if( test_parser_script==4 ) {
    FD_TEST( !test_parser_call_cnt );
    fd_memset( result, 0, sizeof(*result) );
    result->bytes_consumed       = data_sz;
    result->status_cache.data    = data;
    result->status_cache.data_sz = data_sz;
    result->status_cache.done    = 1;
    test_parser_call_cnt++;
    return FD_SSPARSE_ADVANCE_STATUS_CACHE;
  }
  if( test_parser_script==3 ) {
    FD_TEST( data_sz==1UL );
    fd_memset( result, 0, sizeof(*result) );
    result->bytes_consumed = 1UL;
    test_parser_call_cnt++;
    return test_parser_call_cnt==2UL ? FD_SSPARSE_ADVANCE_DONE : FD_SSPARSE_ADVANCE_AGAIN;
  }
  if( test_parser_script==2 ) {
    FD_TEST( data_sz==1UL );
    fd_memset( result, 0, sizeof(*result) );
    result->bytes_consumed = 1UL;
    test_parser_call_cnt++;
    return FD_SSPARSE_ADVANCE_DONE;
  }

  FD_TEST( data_sz==2UL-(test_parser_call_cnt&1UL) );
  fd_memset( result, 0, sizeof(*result) );
  result->bytes_consumed = 1UL;
  if( !test_parser_call_cnt ) {
    static uchar pubkey[ 32UL ];
    result->account_header.data_len   = 2UL;
    result->account_header.pubkey     = pubkey;
    result->account_header.lamports   = 1UL;
    result->account_header.owner      = fd_solana_config_program_id.key;
    result->account_header.executable = 0;
    test_parser_call_cnt++;
    return FD_SSPARSE_ADVANCE_ACCOUNT_HEADER;
  }
  if( test_parser_call_cnt++<3UL ) {
    result->account_data.data    = data;
    result->account_data.data_sz = 1UL;
    return FD_SSPARSE_ADVANCE_ACCOUNT_DATA;
  }
  return FD_SSPARSE_ADVANCE_AGAIN;
}

static void
sync_ctx_init( fd_snapin_tile_t * ctx,
               ulong              lane_cnt,
               int                state ) {
  static uchar shmem_mem[ sizeof(fd_snapin_shmem_t)
                        + 3UL*4096UL ] __attribute__((aligned(4096)));
  static uchar init_mem[ FD_TOPO_MAX_TILE_IN_LINKS ][ FD_ULONG_ALIGN_UP( sizeof(fd_ssctrl_init_t), FD_CHUNK_ALIGN ) ] __attribute__((aligned(FD_CHUNK_ALIGN)));

  fd_memset( ctx, 0, sizeof(*ctx) );
  fd_memset( init_mem, 0, sizeof(init_mem) );
  ctx->shmem = (fd_snapin_shmem_t *)shmem_mem;
  fd_memset( ctx->shmem, 0, sizeof(fd_snapin_shmem_t) );
  ctx->shmem->fork_id    = (ulong)USHORT_MAX;
  ctx->shmem->stake_fork = USHORT_MAX;

  ctx->state        = state;
  ctx->full         = 1;
  ctx->tile_idx     = 0UL;
  ctx->lane_cnt     = lane_cnt;
  ctx->ct_out.idx   = 0UL;
  test_file_off = 0UL;
  reset_attempt_state( ctx );
  clear_control_barrier( ctx );

  ctx->lead.accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  ctx->lead.accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  ctx->lead.boot_timestamp     = fd_log_wallclock();
  ctx->lead.txncache_max_groups_per_slot  = TEST_MAX_GROUPS_PER_SLOT;
  ctx->lead.txncache_max_entries_per_slot = TEST_MAX_ENTRIES_PER_SLOT;

  for( ulong lane=0UL; lane<lane_cnt; lane++ ) {
    ctx->in[ lane ].wksp   = (fd_wksp_t *)init_mem[ lane ];
    ctx->in[ lane ].chunk0 = 0UL;
    ctx->in[ lane ].wmark  = 0UL;
    ctx->in[ lane ].mtu    = sizeof(fd_ssctrl_init_t);
  }
}

static void
send_control( fd_snapin_tile_t * ctx,
              ulong              lane,
              ulong              sig ) {
  FD_TEST( !returnable_frag( ctx, lane, 0UL, sig, 0UL, 0UL, 0UL, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
}

/* Cluster harness *****************************************************/

#define TEST_LANE_MAX (2UL)
#define TEST_FRAG_SZ  (4096UL)

typedef struct {
  fd_snapin_shmem_t * shmem;
  void *              shmem_mem;
  void *                  sd_mem;    /* tile 0's real slot delta parser */
  ulong                   tile_cnt;
  ulong                   lane_cnt;
  uchar *                 in_mem;    /* tile_cnt*lane_cnt frag buffers */
  fd_stake_delegations_t * stake_delegations;
  fd_bank_t *              bank;
  fd_snapin_tile_t *       ctx;
} test_cluster_t;

static void
test_counters_reset( void ) {
  test_pub_cnt                  = 0UL;
  test_accdb_reset_cnt          = 0UL;
  test_accdb_attach_cnt         = 0UL;
  test_accdb_purge_cnt          = 0UL;
  test_accdb_advance_root_cnt   = 0UL;
  test_accdb_load_begin_cnt     = 0UL;
  test_accdb_load_end_cnt       = 0UL;
  test_accdb_flush_metrics_cnt  = 0UL;
  test_accdb_recover_delta_cnt  = 0UL;
  test_accdb_save_whead_cnt     = 0UL;
  test_accdb_revert_whead_cnt   = 0UL;
  test_feature_restore_cnt      = 0UL;
  test_feature_restore_fork     = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  test_stake_new_fork_cnt       = 0UL;
  test_stake_publish_cnt        = 0UL;
  test_stake_publish_fork       = USHORT_MAX;
  test_stake_evict_cnt          = 0UL;
  test_stake_evict_fork         = USHORT_MAX;
  test_write_result             = FD_ACCDB_SNAPSHOT_WRITE_LOADED;
  test_accdb_read_one_cnt       = 0UL;
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) test_sysvars[ i ].lamports = 0UL;
  test_appendvec_parse_cnt      = 0UL;
  test_parser_script            = 0;
  test_parser_call_cnt          = 0UL;
  for( ulong t=0UL; t<TEST_TILE_MAX; t++ ) test_stream_pos[ t ] = 0UL;
}

/* Build a cluster of tile_cnt symmetric snapin tiles sharing one real
   snapin_shmem object, wired the way unprivileged_init wires them. */
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
  test_file_off = 0UL;

  ulong ctx_footprint = fd_ulong_align_up( tile_cnt*sizeof(fd_snapin_tile_t),
                                           alignof(fd_snapin_tile_t) );
  cl->ctx = aligned_alloc( alignof(fd_snapin_tile_t), ctx_footprint );
  FD_TEST( cl->ctx );
  fd_memset( cl->ctx, 0, ctx_footprint );

  cl->shmem_mem = aligned_alloc( alignof(fd_snapin_shmem_t), sizeof(fd_snapin_shmem_t) );
  FD_TEST( cl->shmem_mem );
  cl->shmem = (fd_snapin_shmem_t *)cl->shmem_mem;
  fd_memset( cl->shmem, 0, sizeof(fd_snapin_shmem_t) );
  cl->shmem->fork_id    = ULONG_MAX;
  cl->shmem->stake_fork = USHORT_MAX;

  cl->sd_mem = aligned_alloc( fd_slot_delta_parser_align(), fd_ulong_align_up( fd_slot_delta_parser_footprint(), fd_slot_delta_parser_align() ) );
  FD_TEST( cl->sd_mem );

  cl->in_mem = aligned_alloc( 4096UL, tile_cnt*lane_cnt*TEST_FRAG_SZ );
  FD_TEST( cl->in_mem );
  fd_memset( cl->in_mem, 0, tile_cnt*lane_cnt*TEST_FRAG_SZ );

  ulong stake_delegations_footprint = fd_stake_delegations_footprint( 1UL, 1UL );
  cl->stake_delegations = aligned_alloc( fd_stake_delegations_align(), stake_delegations_footprint );
  FD_TEST( cl->stake_delegations );
  fd_memset( cl->stake_delegations, 0, stake_delegations_footprint );

  cl->bank = aligned_alloc( 128UL, fd_ulong_align_up( sizeof(fd_bank_t), 128UL ) );
  FD_TEST( cl->bank );
  fd_memset( cl->bank, 0, sizeof(fd_bank_t) );

  for( ulong t=0UL; t<tile_cnt; t++ ) {
    fd_snapin_tile_t * ctx = &cl->ctx[ t ];
    ctx->tile_idx = t;
    ctx->lane_cnt = lane_cnt;
    ctx->full     = 1;
    ctx->state    = FD_SNAPSHOT_STATE_IDLE;
    clear_control_barrier( ctx );

    ctx->shmem = cl->shmem;

    ctx->stake_delegations = cl->stake_delegations;

    ctx->ct_out.idx            = 1UL+t;
    ctx->lead.manifest_out.idx = ULONG_MAX;
    ctx->gui_out.idx           = ULONG_MAX;
    if( FD_UNLIKELY( !t ) ) {
      ctx->lead.manifest_out.idx  = 0UL;
      ctx->lead.bank              = cl->bank;
      ctx->lead.slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( cl->sd_mem ) );
      FD_TEST( ctx->lead.slot_delta_parser );
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

    ctx->lead.accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->lead.accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->lead.boot_timestamp     = fd_log_wallclock();

    reset_attempt_state( ctx );
  }

  return cl;
}

static void
test_cluster_delete( test_cluster_t * cl ) {
  free( cl->ctx );
  free( cl->bank );
  free( cl->stake_delegations );
  free( cl->in_mem );
  free( cl->sd_mem );
  free( cl->shmem_mem );
  free( cl );
}

static ulong
test_loaded_sum( test_cluster_t const * cl ) {
  ulong sum = 0UL;
  for( ulong t=0UL; t<cl->tile_cnt; t++ ) sum += cl->ctx[ t ].metrics.accounts_loaded;
  return sum;
}

static void
test_control_barriers( void ) {
  ulong const lane_cnts[] = { 1UL, 2UL, 4UL };
  for( ulong n_idx=0UL; n_idx<sizeof(lane_cnts)/sizeof(lane_cnts[0]); n_idx++ ) {
    ulong lane_cnt = lane_cnts[ n_idx ];
    fd_snapin_tile_t * ctx = test_ctx;
    sync_ctx_init( ctx, lane_cnt, FD_SNAPSHOT_STATE_FINISHING );
    test_pub_cnt = 0UL;

    for( ulong lane=lane_cnt; lane; lane-- ) {
      send_control( ctx, lane-1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
      FD_TEST( test_pub_cnt==(lane==1UL) );
    }
    FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_FINI );
    FD_TEST( ctx->pending_control==ULONG_MAX );
    for( ulong lane=0UL; lane<lane_cnt; lane++ ) FD_TEST( !ctx->control_seen[ lane ] );
  }
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
      send_control( &cl->ctx[ t ], lane, sig );
    }
  }
}

static int
tile_send_data( fd_snapin_tile_t * ctx,
                ulong              lane,
                ulong              sz ) {
  ulong sig = fd_snapdc_data_sig( ctx->expected_frame );
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 0, 0 );
  test_cur_tile = ctx->tile_idx;
  FD_TEST( !before_frag( ctx, lane, 0UL, sig ) );
  return returnable_frag( ctx, lane, 0UL, sig, 0UL, sz, ctl, 0UL, 0UL, (fd_stem_context_t *)1UL );
}

/* Feed one stream event to one tile and report which appendvec ordinal
   (if any) the tile took ownership of. */
static ulong
tile_step( fd_snapin_tile_t * ctx ) {
  ulong parsed0 = test_appendvec_parse_cnt;
  FD_TEST( !tile_send_data( ctx, 0UL, TEST_FRAG_SZ ) );
  if( FD_UNLIKELY( test_appendvec_parse_cnt==parsed0 ) ) return ULONG_MAX;
  FD_TEST( test_appendvec_parse_cnt==parsed0+1UL );
  return ctx->appendvec_seq-1UL;
}

/* Stream orders the eager-claim coverage test drives.  Ownership is
   schedule dependent, but every ordinal must be parsed once. */
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

/* Install a sysvar account in the accdb mock (data NULL: zero-filled). */
static void
test_sysvar_set( ulong        idx,
                 void const * data,
                 ulong        data_len ) {
  test_sysvar_t * sv = &test_sysvars[ idx ];
  FD_TEST( data_len<=sizeof(sv->data) );
  sv->lamports = 1UL;
  sv->data_len = data_len;
  fd_memcpy( sv->owner, fd_sysvar_owner_id.uc, 32UL );
  if( data ) fd_memcpy( sv->data, data, data_len );
  else       fd_memset( sv->data, 0,    data_len );
}

/* A SlotHistory sysvar returned by the accdb mock:
   has_bits, 16384 blocks of zeroed bits, then (bits_len, next_slot).
   The tile's verify_slot_deltas_with_slot_history gate needs
   next_slot-1 == bank_slot, bits_len == FD_SLOT_HISTORY_MAX_ENTRIES, and
   (with an empty slot delta set) nothing else. */
static void
test_stamp_slot_history( ulong bank_slot ) {
  ulong blocks_len = FD_SLOT_HISTORY_MAX_ENTRIES/64UL;
  FD_TEST( 9UL+blocks_len*8UL+16UL==FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  test_sysvar_set( FD_SYSVAR_slot_history_IDX, NULL, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
  uchar * buf = test_sysvars[ FD_SYSVAR_slot_history_IDX ].data;
  buf[ 0 ] = 1;
  FD_STORE( ulong, buf+1UL, blocks_len );
  uchar * footer = buf + 9UL + blocks_len*8UL;
  FD_STORE( ulong, footer,      FD_SLOT_HISTORY_MAX_ENTRIES );
  FD_STORE( ulong, footer+8UL,  bank_slot+1UL               );
}

/* Install a complete valid sysvar set in the accdb mock. */
static void
test_stamp_sysvars( test_cluster_t * cl,
                    ulong            bank_slot ) {
  fd_sol_sysvar_clock_t clock = { .slot = bank_slot };
  test_sysvar_set( FD_SYSVAR_clock_IDX, &clock, FD_SYSVAR_CLOCK_BINCODE_SZ );

  fd_epoch_schedule_t schedule[1];
  FD_TEST( fd_epoch_schedule_derive( schedule, 432000UL, 432000UL, 0 ) );
  test_sysvar_set( FD_SYSVAR_epoch_schedule_IDX, schedule, FD_SYSVAR_EPOCH_SCHEDULE_BINCODE_SZ );

  fd_rent_t rent = { .lamports_per_uint8_year = 3480UL, .exemption_threshold = 2.0, .burn_percent = 50 };
  test_sysvar_set( FD_SYSVAR_rent_IDX, &rent, FD_SYSVAR_RENT_BINCODE_SZ );

  test_sysvar_set( FD_SYSVAR_epoch_rewards_IDX,     NULL, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ     );
  test_sysvar_set( FD_SYSVAR_last_restart_slot_IDX, NULL, FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ );
  test_sysvar_set( FD_SYSVAR_recent_hashes_IDX,     NULL, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ     );
  test_sysvar_set( FD_SYSVAR_slot_hashes_IDX,       NULL, FD_SYSVAR_SLOT_HASHES_BINCODE_SZ       );
  test_sysvar_set( FD_SYSVAR_stake_history_IDX,     NULL, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ     );
  test_stamp_slot_history( bank_slot );

  cl->ctx[ 0 ].lead.bank_slot      = bank_slot;
  cl->ctx[ 0 ].lead.epoch_schedule = *schedule;
  cl->ctx[ 0 ].lead.epoch          = fd_slot_to_epoch( schedule, bank_slot, NULL );
}

/* Install one sysvar account and run tile 0's verify_sysvars. */
static int
test_verify_with( test_cluster_t * cl,
                  ulong            idx,
                  void const *     data,
                  ulong            data_len ) {
  test_sysvar_set( idx, data, data_len );
  return verify_sysvars( &cl->ctx[ 0 ] );
}

/* Regression: scratch_align() must cover the largest FD_LAYOUT_APPEND
   alignment in scratch_footprint. */

static void
test_scratch_layout_fits( void ) {
  FD_TEST( alignof(fd_snapin_tile_t)>=64UL );
  FD_TEST( fd_ulong_is_aligned( (ulong)test_ctx->writer.buf, 64UL ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)test_ctx->staged.data, 64UL ) );
  FD_TEST( scratch_align()>=alignof(fd_snapin_tile_t) );
  FD_TEST( scratch_align()>=fd_accdb_align() );

  fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(fd_topo_tile_t) );
  tile->snapin.max_live_slots   = 1024UL;
  tile->snapin.max_txn_per_slot = FD_MAX_TXN_PER_SLOT;

  for( ulong kind_id=0UL; kind_id<2UL; kind_id++ ) {
    tile->kind_id = kind_id;
    ulong footprint = scratch_footprint( tile );

    FD_SCRATCH_ALLOC_INIT( l, NULL );
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
    FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),          fd_accdb_footprint( tile->snapin.max_live_slots, 0 ) );
    if( !kind_id ) {
      FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),               fd_txncache_footprint( tile->snapin.max_live_slots ) );
      FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(),      fd_ssmanifest_parser_footprint()                     );
      FD_SCRATCH_ALLOC_APPEND( l, fd_slot_delta_parser_align(),      fd_slot_delta_parser_footprint()                     );
      FD_SCRATCH_ALLOC_APPEND( l, alignof(recent_blockhash_group_t), sizeof(recent_blockhash_group_t)*FD_SNAPIN_MAX_RECENT_GROUPS );
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_hash_t),     sizeof(fd_sstxncache_hash_t)*FD_TXNCACHE_MAX_SLOT_DELTAS*2UL*tile->snapin.max_txn_per_slot );
    }
    ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
    FD_TEST( end<=footprint );
  }
}

static void
test_all_control_barriers_and_final_payload( void ) {
  ulong const controls[] = {
    FD_SNAPSHOT_MSG_META,
    FD_SNAPSHOT_MSG_CTRL_INIT_FULL,
    FD_SNAPSHOT_MSG_CTRL_INIT_INCR,
    FD_SNAPSHOT_MSG_CTRL_FAIL,
    FD_SNAPSHOT_MSG_CTRL_NEXT,
    FD_SNAPSHOT_MSG_CTRL_DONE,
    FD_SNAPSHOT_MSG_CTRL_SHUTDOWN,
    FD_SNAPSHOT_MSG_CTRL_FINI,
  };
  for( ulong i=0UL; i<sizeof(controls)/sizeof(controls[0]); i++ ) {
    fd_snapin_tile_t * ctx = test_ctx;
    sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_IDLE );
    test_pub_cnt = 0UL;
    send_control( ctx, 0UL, controls[i] );
    FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
    FD_TEST( ctx->pending_control==controls[i] );
    FD_TEST( ctx->control_seen[0] );
    FD_TEST( !ctx->control_seen[1] );
    FD_TEST( !test_pub_cnt );
  }

  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_PROCESSING );
  fd_ssctrl_meta_t meta[2];
  uchar meta_mem[2][ sizeof(fd_ssctrl_meta_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_memset( meta, 0, sizeof(meta) );
  meta[0].resolved_slot = 11UL;
  meta[1].resolved_slot = 22UL;
  fd_memset( meta[0].resolved_hash, 0x11, FD_HASH_FOOTPRINT );
  fd_memset( meta[1].resolved_hash, 0x22, FD_HASH_FOOTPRINT );
  fd_memcpy( meta_mem[0], &meta[0], sizeof(fd_ssctrl_meta_t) );
  fd_memcpy( meta_mem[1], &meta[1], sizeof(fd_ssctrl_meta_t) );
  ctx->in[0].wksp = (fd_wksp_t *)meta_mem[0];
  ctx->in[1].wksp = (fd_wksp_t *)meta_mem[1];
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_META, 0UL, sizeof(fd_ssctrl_meta_t),
                             0UL, 0UL, 0UL, (fd_stem_context_t *)1UL ) );
  FD_TEST( !ctx->lead.advertised_slot );
  FD_TEST( !returnable_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_META, 0UL, sizeof(fd_ssctrl_meta_t),
                             0UL, 0UL, 0UL, (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->lead.advertised_slot==22UL );
  FD_TEST( !memcmp( ctx->lead.advertised_hash, meta[1].resolved_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( !test_pub_cnt );

  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_PROCESSING );
  ctx->lead.advertised_slot = 33UL;
  fd_memset( ctx->lead.advertised_hash, 0x33, FD_HASH_FOOTPRINT );
  for( ulong i=0UL; i<2UL; i++ ) {
    meta[i].resolved_slot = ULONG_MAX;
    fd_memcpy( meta_mem[i], &meta[i], sizeof(fd_ssctrl_meta_t) );
    ctx->in[i].wksp = (fd_wksp_t *)meta_mem[i];
    FD_TEST( !returnable_frag( ctx, i, 0UL, FD_SNAPSHOT_MSG_META, 0UL, sizeof(fd_ssctrl_meta_t),
                               0UL, 0UL, 0UL, (fd_stem_context_t *)1UL ) );
  }
  FD_TEST( ctx->lead.advertised_slot==33UL );
  uchar expected_hash[ FD_HASH_FOOTPRINT ];
  fd_memset( expected_hash, 0x33, sizeof(expected_hash) );
  FD_TEST( !memcmp( ctx->lead.advertised_hash, expected_hash, sizeof(expected_hash) ) );
  FD_TEST( !test_pub_cnt );
}

static void
test_fast_lane_control_pipeline( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 4UL, FD_SNAPSHOT_STATE_FINISHING );
  test_pub_cnt = 0UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( before_frag( ctx, 0UL, 1UL, FD_SNAPSHOT_MSG_CTRL_NEXT )<0 );
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( !before_frag( ctx, 0UL, 1UL, FD_SNAPSHOT_MSG_CTRL_NEXT ) );
}

static void
data_ctx_init( fd_snapin_tile_t * ctx,
               ulong              lane_cnt,
               uchar              lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] );

static void
test_pending_control_allows_lagging_data( void ) {
  uchar lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapin_tile_t * ctx = test_ctx;
  data_ctx_init( ctx, 2UL, lane_data );
  ctx->expected_frame = 1UL;
  lane_data[1][0]     = 0U;
  test_pub_cnt         = 0UL;
  test_parser_script   = 2;
  test_parser_call_cnt = 0UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );
  FD_TEST( before_frag( ctx, 0UL, 1UL,
                        fd_snapdc_data_sig( 1UL ) )<0 );

  ulong sig = fd_snapdc_data_sig( 1UL );
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 1, 0 );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, sig ) );
  FD_TEST( !returnable_frag( ctx, 1UL, 0UL, sig, 0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==1UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( ctx->expected_frame==2UL );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );

  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_FINI );
}

static void
test_pending_control_keeps_frame_order( void ) {
  uchar lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapin_tile_t * ctx = test_ctx;
  data_ctx_init( ctx, 3UL, lane_data );
  ctx->expected_frame = 1UL;
  lane_data[1][0]     = 0U;
  lane_data[2][0]     = 0U;
  test_pub_cnt         = 0UL;
  test_parser_script   = 3;
  test_parser_call_cnt = 0UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  /* Any lane may carry the next frame; snapin orders by frame index */
  ulong sig1 = fd_snapdc_data_sig( 1UL );
  ulong sig2 = fd_snapdc_data_sig( 2UL );
  ulong ctl  = fd_frag_meta_ctl( 0UL, 0, 1, 0 );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, sig1 ) );
  FD_TEST( before_frag( ctx, 2UL, 0UL, sig2 )<0 );

  FD_TEST( !returnable_frag( ctx, 1UL, 0UL, sig1, 0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( ctx->expected_frame==2UL );
  FD_TEST( !before_frag( ctx, 2UL, 0UL, sig2 ) );
  FD_TEST( !returnable_frag( ctx, 2UL, 0UL, sig2, 0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==2UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( ctx->expected_frame==3UL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_FINI );

}

static void
test_error_interrupts_incremental_init( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  uchar init_mem[ 2UL ][ FD_CHUNK_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_memset( init_mem, 0, sizeof(init_mem) );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_IDLE );
  ctx->in[0].wksp          = (fd_wksp_t *)init_mem[0];
  ctx->in[1].wksp          = (fd_wksp_t *)init_mem[1];
  ctx->lead.accdb_root_fork_id  = (fd_accdb_fork_id_t){ .val = 3U };
  test_pub_cnt              = 0UL;
  test_accdb_reset_cnt      = 0UL;
  test_accdb_attach_cnt     = 0UL;
  test_accdb_purge_cnt      = 0UL;

  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );
  FD_TEST( ctx->full );
  FD_TEST( !ctx->lead.init_completed );

  FD_TEST( !before_frag( ctx, 0UL, 1UL, FD_SNAPSHOT_MSG_CTRL_ERROR ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( !ctx->lead.init_completed );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->control_seen[0] );
  FD_TEST( !ctx->control_seen[1] );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR )>0 );

  FD_TEST( !before_frag( ctx, 0UL, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( !ctx->lead.init_completed );
  FD_TEST( !test_accdb_reset_cnt );
  FD_TEST( !before_frag( ctx, 1UL, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !ctx->lead.init_completed );
  FD_TEST( !test_accdb_reset_cnt );
  FD_TEST( !test_accdb_attach_cnt );
  FD_TEST( !test_accdb_purge_cnt );
  FD_TEST( !ctx->lead.rollback.pending );
}

static void
test_partial_fail_survives_error( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 4UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_pub_cnt = 0UL;

  FD_TEST( !before_frag( ctx, 2UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->control_seen[2] );

  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR ) );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->control_seen[2] );

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( ctx->pending_control==ULONG_MAX );
  FD_TEST( test_pub_cnt==2UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( test_pub_sig[1]==FD_SNAPSHOT_MSG_CTRL_FAIL );

  sync_ctx_init( ctx, 4UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_pub_cnt = 0UL;
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  transition_malformed( ctx, (fd_stem_context_t *)1UL );
  FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->control_seen[2] );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( ctx->pending_control==ULONG_MAX );
}

static void
test_fail_supersedes_pending_controls( void ) {
  struct {
    ulong sig;
    int   state;
  } const cases[] = {
    { FD_SNAPSHOT_MSG_META,           FD_SNAPSHOT_STATE_PROCESSING },
    { FD_SNAPSHOT_MSG_CTRL_INIT_FULL, FD_SNAPSHOT_STATE_IDLE       },
    { FD_SNAPSHOT_MSG_CTRL_INIT_INCR, FD_SNAPSHOT_STATE_IDLE       },
    { FD_SNAPSHOT_MSG_CTRL_FINI,      FD_SNAPSHOT_STATE_PROCESSING },
    { FD_SNAPSHOT_MSG_CTRL_NEXT,      FD_SNAPSHOT_STATE_FINISHING  },
    { FD_SNAPSHOT_MSG_CTRL_DONE,      FD_SNAPSHOT_STATE_FINISHING  },
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    fd_snapin_tile_t * ctx = test_ctx;
    sync_ctx_init( ctx, 4UL, cases[i].state );
    test_pub_cnt = 0UL;

    FD_TEST( !before_frag( ctx, 0UL, 0UL, cases[i].sig ) );
    send_control( ctx, 0UL, cases[i].sig );
    FD_TEST( ctx->pending_control==cases[i].sig );
    FD_TEST( ctx->control_seen[0] );

    FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL ) );
    send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    FD_TEST( ctx->pending_control==FD_SNAPSHOT_MSG_CTRL_FAIL );
    FD_TEST( !ctx->control_seen[0] );
    FD_TEST( ctx->control_seen[1] );

    send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
    FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
    FD_TEST( ctx->pending_control==ULONG_MAX );
    FD_TEST( test_pub_cnt==1UL );
    FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_FAIL );
  }
}

static void
test_initialized_incremental_fail_rolls_back( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  uchar init_mem[ 2UL ][ FD_CHUNK_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_memset( init_mem, 0, sizeof(init_mem) );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_IDLE );
  ctx->in[0].wksp          = (fd_wksp_t *)init_mem[0];
  ctx->in[1].wksp          = (fd_wksp_t *)init_mem[1];
  ctx->lead.accdb_root_fork_id  = (fd_accdb_fork_id_t){ .val = 3U };
  test_pub_cnt              = 0UL;
  test_accdb_reset_cnt      = 0UL;
  test_accdb_attach_cnt     = 0UL;
  test_accdb_purge_cnt      = 0UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( ctx->lead.init_completed );
  FD_TEST( !ctx->full );
  FD_TEST( test_accdb_attach_cnt==1UL );
  FD_TEST( ctx->lead.accdb_incr_fork_id.val==7U );

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !ctx->lead.init_completed );
  FD_TEST( !test_accdb_reset_cnt );
  FD_TEST( !test_accdb_purge_cnt );
  FD_TEST( ctx->lead.rollback.pending );
  FD_TEST( !ctx->lead.rollback.full );
  FD_TEST( ctx->lead.rollback.fork.val==7U );
}

static void
test_error_fail_and_retry( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 4UL, FD_SNAPSHOT_STATE_FINISHING );
  ctx->lead.init_completed = 1;
  test_pub_cnt         = 0UL;
  test_accdb_reset_cnt = 0UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_DATA )>0 );
  FD_TEST( before_frag( ctx, 1UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI )>0 );

  send_control( ctx, 3UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( !test_accdb_reset_cnt );
  send_control( ctx, 2UL, FD_SNAPSHOT_MSG_CTRL_FAIL );
  /* The final loader defers rollback until the retry's INIT setup,
     after every FAIL ack has quiesced.  Run that setup through the
     INIT handler. */
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL ) );
  handle_control_frag( ctx, (fd_stem_context_t *)1UL, 0UL,
                       FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, 0UL );
  FD_TEST( test_accdb_reset_cnt==1UL );
  FD_TEST( test_pub_cnt==3UL );
  FD_TEST( test_pub_sig[1]==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( test_pub_sig[2]==FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
}

static void
data_ctx_init( fd_snapin_tile_t * ctx,
               ulong              lane_cnt,
               uchar              lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] ) {
  sync_ctx_init( ctx, lane_cnt, FD_SNAPSHOT_STATE_PROCESSING );
  fd_ssparse_init( ctx->ssparse );
  for( ulong lane=0UL; lane<lane_cnt; lane++ ) {
    ctx->in[ lane ].wksp   = (fd_wksp_t *)lane_data[ lane ];
    ctx->in[ lane ].chunk0 = 0UL;
    ctx->in[ lane ].wmark  = 0UL;
    ctx->in[ lane ].mtu    = 64UL;
  }
}

static void
send_data( fd_snapin_tile_t * ctx,
           ulong              lane,
           ulong              sz,
           int                eom ) {
  ulong sig = fd_snapdc_data_sig( ctx->expected_frame );
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, eom, 0 );
  FD_TEST( !before_frag( ctx, lane, 0UL, sig ) );
  FD_TEST( !returnable_frag( ctx, lane, 0UL, sig, 0UL, sz, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
}

static void
test_frame_ordering( void ) {
  ulong const lane_cnts[] = { 1UL, 2UL, 4UL };
  uchar lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  for( ulong n_idx=0UL; n_idx<sizeof(lane_cnts)/sizeof(lane_cnts[0]); n_idx++ ) {
    ulong lane_cnt = lane_cnts[ n_idx ];
    fd_snapin_tile_t * ctx = test_ctx;
    data_ctx_init( ctx, lane_cnt, lane_data );

    for( ulong frame=0UL; frame<2UL*lane_cnt; frame++ ) {
      ulong future = frame+1UL;
      FD_TEST( before_frag( ctx, future%lane_cnt, 0UL, fd_snapdc_data_sig( future ) )<0 );
      send_data( ctx, frame%lane_cnt, 0UL, 1 );
      FD_TEST( ctx->expected_frame==frame+1UL );
    }
  }
}

/* Eager claim coverage ************************************************/

/* Every appendvec in the stream is claimed by exactly one tile, no
   matter how the tiles interleave; every tile ends the attempt holding
   exactly one unmatched claim, so next_appendvec_ticket lands on T+N. */
static void
test_eager_claim_coverage( void ) {
  ulong const tile_cnts[] = { 1UL, 2UL, 3UL, 4UL, 5UL, 6UL, 7UL, 8UL, 9UL };
  int   const orders   [] = { TEST_ORDER_ROUND_ROBIN, TEST_ORDER_TILE_MAJOR, TEST_ORDER_REVERSE };
  ulong const T = 13UL;

  for( ulong n_idx=0UL; n_idx<sizeof(tile_cnts)/sizeof(tile_cnts[0]); n_idx++ ) {
    ulong n = tile_cnts[ n_idx ];
    for( ulong o_idx=0UL; o_idx<sizeof(orders)/sizeof(orders[0]); o_idx++ ) {
      test_cluster_t * cl = test_cluster_new( n, 1UL );
      test_counters_reset();
      test_stream_init( T );

      cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
      FD_TEST( !cl->shmem->next_appendvec_ticket );
      for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].incr_fork==ULONG_MAX );

      ulong owner[ TEST_AV_MAX ];
      cluster_stream( cl, orders[ o_idx ], owner );
      for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].incr_fork==(ulong)USHORT_MAX );

      FD_TEST( test_appendvec_parse_cnt==T ); /* the parser was flipped exactly once per ordinal */

      /* A single tile owns everything, in stream order. */
      if( n==1UL ) {
        for( ulong i=0UL; i<T; i++ ) FD_TEST( owner[ i ]==0UL );
      }

      cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
      FD_TEST( cl->shmem->next_appendvec_ticket==T+n ); /* T consumed claims + N unmatched */

      test_cluster_delete( cl );
    }
  }
}

static void
test_frame_owner_and_raw_lane( void ) {
  uchar lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapin_tile_t * ctx = test_ctx;

  data_ctx_init( ctx, 4UL, lane_data );
  test_pub_cnt = 0UL;
  FD_TEST( before_frag( ctx, 1UL, 0UL, fd_snapdc_data_sig( 1UL ) )<0 );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, fd_snapdc_data_sig( 0UL ) ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
  FD_TEST( !test_pub_cnt );

  send_data( ctx, 0UL, 0UL, 0 );
  FD_TEST( !ctx->expected_frame );
}

static void
test_partial_and_zero_byte_eom( void ) {
  uchar lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapin_tile_t * ctx = test_ctx;
  data_ctx_init( ctx, 2UL, lane_data );
  ctx->tile_idx = 1UL;
  FD_TEST( !is_lead( ctx ) );
  lane_data[0][1] = 2U;
  lane_data[1][0] = 3U;
  uchar gui_data[ 64UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  ctx->gui_out.idx       = 7UL;
  ctx->gui_out.mem       = (fd_wksp_t *)gui_data;
  ctx->gui_out.chunk0    = 0UL;
  ctx->gui_out.wmark     = 0UL;
  ctx->gui_out.chunk     = 0UL;

  test_pub_cnt         = 0UL;
  test_parser_script   = 1;
  test_parser_call_cnt = 0UL;
  ulong sig = FD_SNAPSHOT_MSG_DATA;
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 1, 0 );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, sig, 0UL, 2UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->expected_frame==1UL );
  FD_TEST( ctx->staged.bytes_received==1UL );
  FD_TEST( !test_pub_cnt );

  FD_TEST( returnable_frag( ctx, 1UL, 0UL, sig, 0UL, 2UL, ctl, 0UL, 0UL,
                            (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->expected_frame==1UL );
  FD_TEST( ctx->in[1].pos==1UL );
  FD_TEST( ctx->staged.bytes_received==ctx->staged.data_len );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_out_idx[0]==ctx->gui_out.idx );
  uchar expected_gui_data[ 2UL ] = { 2U, 3U };
  FD_TEST( !memcmp( gui_data, expected_gui_data, sizeof(expected_gui_data) ) );
  FD_TEST( !returnable_frag( ctx, 1UL, 0UL, sig, 0UL, 2UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==4UL );
  FD_TEST( ctx->expected_frame==2UL );
  FD_TEST( test_pub_cnt==1UL );

  ctx->state          = FD_SNAPSHOT_STATE_FINISHING;
  ctx->expected_frame = 2UL;
  send_data( ctx, 0UL, 0UL, 1 );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( ctx->expected_frame==3UL );
}

static void
test_malformed_stream_endings( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_pub_cnt = 0UL;
  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );

  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_FINISHING );
  test_pub_cnt = 0UL;
  ulong ctl = fd_frag_meta_ctl( 0UL, 0, 1, 0 );
  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA ) );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_DATA,
                             0UL, 1UL, ctl, 0UL, 0UL,
                             (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL );
  FD_TEST( test_pub_sig[0]==FD_SNAPSHOT_MSG_CTRL_ERROR );
}

static void
test_init_resets_lane_state( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  uchar init_mem[ 2UL ][ FD_CHUNK_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_memset( init_mem, 0, sizeof(init_mem) );
  sync_ctx_init( ctx, 2UL, FD_SNAPSHOT_STATE_IDLE );
  ctx->in[0].wksp      = (fd_wksp_t *)init_mem[0];
  ctx->in[1].wksp      = (fd_wksp_t *)init_mem[1];
  ctx->in[0].pos       = 5UL;
  ctx->in[1].pos       = 6UL;
  ctx->expected_frame  = 7UL;
  test_pub_cnt          = 0UL;

  send_control( ctx, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( ctx->in[0].pos==5UL );
  FD_TEST( ctx->in[1].pos==6UL );
  FD_TEST( ctx->expected_frame==7UL );

  send_control( ctx, 1UL, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( !ctx->in[0].pos );
  FD_TEST( !ctx->in[1].pos );
  FD_TEST( !ctx->expected_frame );
  FD_TEST( ctx->lead.init_completed );
  FD_TEST( !ctx->full );
}

static void
test_nonempty_raw_data( void ) {
  uchar lane_data[ FD_TOPO_MAX_TILE_IN_LINKS ][ 64UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapin_tile_t * ctx = test_ctx;
  data_ctx_init( ctx, 2UL, lane_data );
  lane_data[0][0]     = 0U;
  test_parser_script   = 2;
  test_parser_call_cnt = 0UL;

  FD_TEST( before_frag( ctx, 1UL, 0UL, fd_snapdc_data_sig( 1UL ) )<0 );
  send_data( ctx, 0UL, 1UL, 0 );
  FD_TEST( test_parser_call_cnt==1UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
  FD_TEST( !ctx->expected_frame );
}

static fd_banks_t *
new_banks( fd_wksp_t * wksp ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( 16UL, 4UL, 16UL, 16UL ), 1UL );
  FD_TEST( mem );
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, FD_STAKE_DELEGATIONS_FD, 16UL, 4UL, 16UL, 64UL, 16UL, 0, 42UL ) );
  FD_TEST( banks );
  return banks;
}

static void
make_stake_state( fd_stake_state_t * state,
                  fd_pubkey_t const * vote_account ) {
  fd_memset( state, 0, sizeof(*state) );
  state->stake_type                                = FD_STAKE_STATE_STAKE;
  state->stake.stake.delegation.voter_pubkey       = *vote_account;
  state->stake.stake.delegation.stake              = 1234UL;
  state->stake.stake.delegation.activation_epoch   = 7UL;
  state->stake.stake.delegation.deactivation_epoch = ULONG_MAX;
  state->stake.stake.credits_observed               = 99UL;
}

static void
assert_stake_delegation( fd_stake_delegations_t const * stake_delegations,
                         fd_pubkey_t const *            stake_account,
                         fd_pubkey_t const *            vote_account ) {
  fd_stake_delegation_t delegation[1];
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, stake_account, delegation ) );
  FD_TEST( fd_pubkey_eq( &delegation->vote_account, vote_account ) );
  FD_TEST( delegation->stake==1234UL );
  FD_TEST( delegation->activation_epoch==7UL );
  FD_TEST( delegation->deactivation_epoch==USHORT_MAX );
  FD_TEST( delegation->credits_observed==99UL );
  FD_TEST( delegation->lamports==5000UL );
  FD_TEST( delegation->acc_dlen==sizeof(fd_stake_state_t) );
}

/* Fresh cache and a full-snapshot tile context writing to its root. */
static fd_stake_delegations_t *
stake_test_init( fd_wksp_t * wksp ) {
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( new_banks( wksp ) );
  sync_ctx_init( test_ctx, 1UL, FD_SNAPSHOT_STATE_PROCESSING );
  test_ctx->stake_delegations = stake_delegations;
  return stake_delegations;
}

/* Writes one account through the snapin write path (136 byte appendvec
   header + data) with the given index outcome. */
static void
write_one( fd_snapin_tile_t *  ctx,
           fd_pubkey_t const * pubkey,
           fd_pubkey_t const * owner,
           ulong               lamports,
           void const *        data,
           ulong               data_len,
           ulong               slot,
           uchar               outcome ) {
  static uchar entry[ 136UL + 4008UL ] __attribute__((aligned(8)));
  FD_TEST( data_len<=4008UL );
  fd_memset( entry, 0, 136UL );
  FD_STORE( ulong, entry+8UL,  data_len );
  fd_memcpy( entry+16UL, pubkey, sizeof(fd_pubkey_t) );
  FD_STORE( ulong, entry+48UL, lamports );
  fd_memcpy( entry+64UL, owner,  sizeof(fd_pubkey_t) );
  if( data_len ) fd_memcpy( entry+136UL, data, data_len );

  test_write_result = outcome;
  fd_ssparse_advance_result_t result = {
    .account_batch = {
      .batch     = { entry },
      .batch_cnt = 1UL,
      .slot      = slot,
    },
  };
  FD_TEST( !process_account_batch( ctx, &result ) );
  FD_TEST( !writer_flush( ctx ) );
  test_write_result = FD_ACCDB_SNAPSHOT_WRITE_LOADED;
}

static void
test_batch_stake_delegation( fd_wksp_t * wksp ) {
  fd_stake_delegations_t * stake_delegations = stake_test_init( wksp );
  fd_pubkey_t stake_account = { .ul = { 1UL, 2UL, 3UL, 4UL } };
  fd_pubkey_t vote_account  = { .ul = { 5UL, 6UL, 7UL, 8UL } };
  fd_stake_state_t state[1];
  make_stake_state( state, &vote_account );

  write_one( test_ctx, &stake_account, &fd_solana_stake_program_id, 5000UL, state, sizeof(fd_stake_state_t), 10UL, FD_ACCDB_SNAPSHOT_WRITE_LOADED );
  assert_stake_delegation( stake_delegations, &stake_account, &vote_account );
}

static void
test_streaming_stake_delegation( fd_wksp_t * wksp ) {
  fd_stake_delegations_t * stake_delegations = stake_test_init( wksp );
  fd_pubkey_t stake_account = { .ul = { 11UL, 12UL, 13UL, 14UL } };
  fd_pubkey_t vote_account  = { .ul = { 15UL, 16UL, 17UL, 18UL } };
  fd_stake_state_t state[1];
  make_stake_state( state, &vote_account );

  fd_snapin_tile_t * ctx = test_ctx;
  fd_ssparse_advance_result_t header = {
    .account_header = {
      .pubkey     = stake_account.uc,
      .slot       = 10UL,
      .lamports   = 5000UL,
      .data_len   = sizeof(fd_stake_state_t),
      .owner      = fd_solana_stake_program_id.uc,
      .executable = 0,
    },
  };
  FD_TEST( !process_account_header( ctx, &header ) );

  ulong split = sizeof(fd_stake_state_t)/2UL;
  fd_ssparse_advance_result_t data = {
    .account_data = {
      .data    = (uchar const *)state,
      .data_sz = split,
    },
  };
  FD_TEST( !process_account_data( ctx, &data ) );
  FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account ) );

  data.account_data.data    = (uchar const *)state + split;
  data.account_data.data_sz = sizeof(fd_stake_state_t) - split;
  FD_TEST( !process_account_data( ctx, &data ) );
  FD_TEST( !writer_flush( ctx ) );
  assert_stake_delegation( stake_delegations, &stake_account, &vote_account );
}

/* Which index outcomes reach the cache, and as what. */
static void
test_snoop_outcomes( fd_wksp_t * wksp ) {
  fd_stake_delegations_t * stake_delegations = stake_test_init( wksp );
  fd_pubkey_t vote  = { .ul = { 5UL, 6UL, 7UL, 8UL } };
  fd_pubkey_t acc_a = { .ul = { 101UL } };
  fd_pubkey_t acc_b = { .ul = { 102UL } };
  fd_pubkey_t acc_c = { .ul = { 103UL } };
  fd_pubkey_t acc_d = { .ul = { 104UL } };
  fd_stake_state_t state[1];
  make_stake_state( state, &vote );
  fd_stake_state_t initialized[1] = { { .stake_type = FD_STAKE_STATE_INITIALIZED } };
  static uchar legacy[ 4008UL ]; /* early mainnet stake accounts are 4008 bytes */
  fd_memcpy( legacy, state, sizeof(fd_stake_state_t) );
  ulong const stake_sz = sizeof(fd_stake_state_t);
  fd_snapin_tile_t * ctx = test_ctx;
  fd_stake_delegation_t d[1];

  /* loaded: added. */
  write_one( ctx, &acc_a, &fd_solana_stake_program_id, 5000UL, state, stake_sz, 10UL, FD_ACCDB_SNAPSHOT_WRITE_LOADED );
  assert_stake_delegation( stake_delegations, &acc_a, &vote );

  /* ignored: no trace. */
  write_one( ctx, &acc_a, &fd_solana_stake_program_id, 7000UL, state, stake_sz, 5UL, FD_ACCDB_SNAPSHOT_WRITE_IGNORED );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &acc_a, d ) && d->lamports==5000UL );

  /* replaced by a closed account: tombstoned at the closing slot. */
  write_one( ctx, &acc_a, &fd_solana_system_program_id, 0UL, NULL, 0UL, 30UL, FD_ACCDB_SNAPSHOT_WRITE_REPLACED );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &acc_a, d ) && !d->lamports && d->slot==30U );

  /* replaced a funded version from an earlier load: tombstoned only if
     present. */
  write_one( ctx, &acc_b, &vote, 1UL, state, stake_sz, 32UL, FD_ACCDB_SNAPSHOT_WRITE_REPLACED_CROSS );
  FD_TEST( !test_stake_delegations_contains( stake_delegations, &acc_b ) );

  /* stake-owned but no longer delegated, replacing a funded version:
     tombstoned like any other non-delegation. */
  write_one( ctx, &acc_c, &fd_solana_stake_program_id, 5000UL, initialized, stake_sz, 30UL, FD_ACCDB_SNAPSHOT_WRITE_REPLACED );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &acc_c, d ) && !d->lamports );

  /* legacy 4008 byte delegation: added. */
  write_one( ctx, &acc_d, &fd_solana_stake_program_id, 5000UL, legacy, sizeof(legacy), 30UL, FD_ACCDB_SNAPSHOT_WRITE_LOADED );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &acc_d, d ) && d->acc_dlen==4008U );

  /* loaded non-delegation: nothing. */
  write_one( ctx, &acc_b, &fd_solana_system_program_id, 0UL, NULL, 0UL, 30UL, FD_ACCDB_SNAPSHOT_WRITE_LOADED );
  FD_TEST( !test_stake_delegations_contains( stake_delegations, &acc_b ) );
}

/* Incremental writes go to the fork in shmem, not the root. */
static void
test_snoop_incremental_fork( fd_wksp_t * wksp ) {
  fd_stake_delegations_t * stake_delegations = stake_test_init( wksp );
  fd_pubkey_t vote  = { .ul = { 5UL, 6UL, 7UL, 8UL } };
  fd_pubkey_t acc_a = { .ul = { 201UL } };
  fd_stake_state_t state[1];
  make_stake_state( state, &vote );
  ulong const stake_sz = sizeof(fd_stake_state_t);
  fd_snapin_tile_t * ctx = test_ctx;
  fd_stake_delegation_t d[1];

  /* Full snapshot left a delegation in the root. */
  write_one( ctx, &acc_a, &fd_solana_stake_program_id, 5000UL, state, stake_sz, 10UL, FD_ACCDB_SNAPSHOT_WRITE_LOADED );

  ctx->full = 0;
  ctx->shmem->stake_fork = fd_stake_delegations_new_fork( stake_delegations );
  write_one( ctx, &acc_a, &fd_solana_stake_program_id, 9000UL, state, stake_sz, 100UL, FD_ACCDB_SNAPSHOT_WRITE_REPLACED_CROSS );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &acc_a, d ) && d->lamports==5000UL ); /* root untouched */

  fd_stake_delegations_snapshot_publish_fork( stake_delegations, ctx->shmem->stake_fork );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &acc_a, d ) && d->lamports==9000UL && d->slot==100U );
}

static void
test_txncache_staging_entry_size( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  FD_TEST( sizeof(ctx->lead.txncache_entries[ 0 ])==20UL );
}

static void
test_txncache_staging_group_record_size( void ) {
  FD_TEST( sizeof(blockhash_group_t)==40UL );
  FD_TEST( TEST_MAX_ENTRIES_PER_SLOT==FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );
  FD_TEST( FD_SNAPIN_MAX_RECENT_GROUPS==FD_TXNCACHE_MAX_SLOT_DELTAS*FD_TXNCACHE_MAX_SLOT_DELTAS );
}

static void
test_txncache_staging_side_arrays_alloc( fd_snapin_tile_t * ctx,
                                         fd_wksp_t *        wksp ) {
  ctx->lead.recent_groups    = fd_wksp_alloc_laddr( wksp, alignof(recent_blockhash_group_t), FD_SNAPIN_MAX_RECENT_GROUPS*sizeof(recent_blockhash_group_t), 1UL );
  ctx->lead.txncache_entries = fd_wksp_alloc_laddr( wksp, alignof(fd_sstxncache_hash_t),     TEST_MAX_ENTRIES*sizeof(fd_sstxncache_hash_t), 1UL  );
  FD_TEST( ctx->lead.recent_groups );
  FD_TEST( ctx->lead.txncache_entries );
}

static void
test_txncache_staging_ctx_init( fd_snapin_tile_t * ctx,
                                fd_wksp_t *        wksp ) {
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->lead.seed = 1UL;
  ctx->lead.txncache_max_groups_per_slot  = TEST_MAX_GROUPS_PER_SLOT;
  ctx->lead.txncache_max_entries_per_slot = TEST_MAX_ENTRIES_PER_SLOT;
  txncache_staging_reset( ctx );
  ctx->lead.blockhash_groups = fd_wksp_alloc_laddr( wksp, alignof(blockhash_group_t), TEST_MAX_STAGED_GROUPS*sizeof(blockhash_group_t), 1UL );
  FD_TEST( ctx->lead.blockhash_groups );
  test_txncache_staging_side_arrays_alloc( ctx, wksp );
}

/* Builds a txncache with one live slot and returns the local join. */
static fd_txncache_t *
new_txncache( fd_wksp_t * wksp,
              ulong       max_txn_per_slot ) {
  void * shmem = fd_wksp_alloc_laddr( wksp, fd_txncache_shmem_align(), fd_txncache_shmem_footprint( 1UL, max_txn_per_slot ), 1UL );
  FD_TEST( shmem );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( fd_txncache_shmem_new( shmem, 1UL, max_txn_per_slot, 0UL ) );
  FD_TEST( txncache_shmem );

  void * local = fd_wksp_alloc_laddr( wksp, fd_txncache_align(), fd_txncache_footprint( 1UL ), 1UL );
  FD_TEST( local );
  fd_txncache_t * txncache = fd_txncache_join( fd_txncache_new( local, txncache_shmem ) );
  FD_TEST( txncache );
  return txncache;
}

static void
test_txncache_staging_groups_fit_txncache_scratch( fd_wksp_t * wksp ) {
  fd_txncache_t * txncache = new_txncache( wksp, FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );

  ulong scratch_sz = 0UL;
  void * scratch = fd_txncache_snapin_scratch( txncache, &scratch_sz );
  FD_TEST( scratch );

  blockhash_group_t * groups = txncache_staging_groups_join( scratch, scratch_sz, TEST_MAX_STAGED_GROUPS );
  FD_TEST( groups );
  FD_TEST( fd_ulong_is_aligned( (ulong)groups, alignof(blockhash_group_t) ) );
  FD_TEST( (uchar *)groups>=(uchar *)scratch );
  FD_TEST( (uchar *)(groups+TEST_MAX_STAGED_GROUPS)<=(uchar *)scratch+scratch_sz );

  ulong ring_sz = TEST_MAX_STAGED_GROUPS*sizeof(blockhash_group_t);
  FD_TEST(  txncache_staging_groups_join( (void *)64UL, ring_sz,     TEST_MAX_STAGED_GROUPS ) );
  FD_TEST( !txncache_staging_groups_join( (void *)64UL, ring_sz-1UL, TEST_MAX_STAGED_GROUPS ) );
  FD_TEST( !txncache_staging_groups_join( (void *)66UL, ring_sz,     TEST_MAX_STAGED_GROUPS ) );
  FD_TEST(  txncache_staging_groups_join( (void *)66UL, ring_sz+2UL, TEST_MAX_STAGED_GROUPS ) );
}

static void
test_txncache_staging_evicts_oldest_slot( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );

  ulong oldest_idx = ULONG_MAX;
  for( ulong i=0UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) {
    ulong slot_idx = txncache_staging_slot_begin( ctx, 1000UL+i );
    FD_TEST( slot_idx!=ULONG_MAX );
    FD_TEST( ctx->lead.txncache_current_slot_idx==slot_idx );
    if( FD_UNLIKELY( !i ) ) oldest_idx = slot_idx;
  }
  FD_TEST( oldest_idx!=ULONG_MAX );
  FD_TEST( ctx->lead.txncache_slots_len==FD_TXNCACHE_MAX_SLOT_DELTAS );

  FD_TEST( txncache_staging_slot_begin( ctx, 999UL )==ULONG_MAX );
  FD_TEST( ctx->lead.txncache_current_slot_idx==ULONG_MAX );
  FD_TEST( ctx->lead.txncache_slots[ oldest_idx ].slot==1000UL );

  ulong replacement_idx = txncache_staging_slot_begin( ctx, 1200UL );
  FD_TEST( replacement_idx==oldest_idx );
  FD_TEST( ctx->lead.txncache_slots[ replacement_idx ].slot==1200UL );
  FD_TEST( ctx->lead.txncache_slots[ replacement_idx ].entry_cnt==0UL );
  FD_TEST( ctx->lead.txncache_slots[ replacement_idx ].group_cnt==0UL );
}

static void
test_txncache_staging_evicted_slot_drops_groups( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );

  static uchar const blockhash_x[ 32UL ] = { 0x11 };
  static uchar const blockhash_y[ 32UL ] = { 0x22 };
  static uchar const txnhash[ 20UL ]     = { 0x33 };

  ulong oldest_idx = txncache_staging_slot_begin( ctx, 1000UL );
  FD_TEST( oldest_idx!=ULONG_MAX );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash_x, 3UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) );
  FD_TEST( ctx->lead.txncache_slots[ oldest_idx ].group_cnt==1UL );
  FD_TEST( ctx->lead.txncache_slots[ oldest_idx ].entry_cnt==2UL );

  blockhash_group_t const * group = &ctx->lead.blockhash_groups[ oldest_idx*TEST_MAX_GROUPS_PER_SLOT ];
  FD_TEST( !memcmp( group->blockhash, blockhash_x, 32UL ) );
  FD_TEST( group->txnhash_offset==3UL );
  FD_TEST( group->txncache_entry_cnt==2UL );
  FD_TEST( ctx->lead.txncache_entries[ oldest_idx*ctx->lead.txncache_max_entries_per_slot ].txnhash[ 0 ]==0x33 );

  for( ulong i=1UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) FD_TEST( txncache_staging_slot_begin( ctx, 1000UL+i )!=ULONG_MAX );

  FD_TEST( txncache_staging_slot_begin( ctx, 999UL )==ULONG_MAX );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash_y, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 999UL, txnhash ) );
  FD_TEST( ctx->lead.blockhash_groups_cnt==2UL );
  FD_TEST( ctx->lead.txncache_slots[ oldest_idx ].slot==1000UL );
  FD_TEST( ctx->lead.txncache_slots[ oldest_idx ].group_cnt==1UL );
  FD_TEST( ctx->lead.txncache_slots[ oldest_idx ].entry_cnt==2UL );
  FD_TEST( !memcmp( group->blockhash, blockhash_x, 32UL ) );

  ulong replacement_idx = txncache_staging_slot_begin( ctx, 1200UL );
  FD_TEST( replacement_idx==oldest_idx );
  FD_TEST( ctx->lead.txncache_slots[ replacement_idx ].group_cnt==0UL );
  FD_TEST( ctx->lead.txncache_slots[ replacement_idx ].entry_cnt==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash_y, 5UL ) );
  FD_TEST( ctx->lead.txncache_slots[ replacement_idx ].group_cnt==1UL );
  FD_TEST( !memcmp( group->blockhash, blockhash_y, 32UL ) );
  FD_TEST( group->txnhash_offset==5UL );
  FD_TEST( group->txncache_entry_cnt==0UL );
  FD_TEST( ctx->lead.blockhash_groups_cnt==3UL );
}

static void
test_txncache_staging_rejects_group_overflow( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );

  uchar blockhash[ 32UL ] = {0};
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )==0UL );
  for( ulong i=0UL; i<TEST_MAX_GROUPS_PER_SLOT; i++ ) {
    FD_STORE( ulong, blockhash, i );
    FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 0UL ) );
  }
  FD_TEST( ctx->lead.txncache_slots[ 0 ].group_cnt==TEST_MAX_GROUPS_PER_SLOT );
  FD_TEST( txncache_staging_group_begin( ctx, blockhash, 0UL )==-1 );

  /* Bound ignored slots too, so malformed input cannot bypass the
     per-slot work limit. */
  for( ulong i=1UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) FD_TEST( txncache_staging_slot_begin( ctx, 1000UL+i )!=ULONG_MAX );
  FD_TEST( txncache_staging_slot_begin( ctx, 999UL )==ULONG_MAX );
  for( ulong i=0UL; i<TEST_MAX_GROUPS_PER_SLOT; i++ ) FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 0UL ) );
  FD_TEST( txncache_staging_group_begin( ctx, blockhash, 0UL )==-1 );
}

/* The entry bound is per slot delta.  Its quota accommodates Agave's
   signature and message hash entries for one block.  Other deltas keep
   their own quota, and a discarded older delta is still bounded. */
static void
test_txncache_staging_rejects_entry_overflow( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );
  ctx->lead.txncache_max_entries_per_slot = 6UL;
  ulong const max = ctx->lead.txncache_max_entries_per_slot;

  static uchar const blockhash[ 32UL ] = { 0x11 };
  static uchar const txnhash[ 20UL ]   = { 0x33 };
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 0UL ) );
  for( ulong i=0UL; i<max; i++ ) FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) );
  FD_TEST( ctx->lead.txncache_slots[ 0 ].entry_cnt==max );
  FD_TEST( ctx->lead.blockhash_groups[ 0 ].txncache_entry_cnt==max );
  FD_TEST( txncache_staging_entry_add( ctx, 1000UL, txnhash )==-1 );

  /* Another delta has its own quota. */
  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==1UL );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 0UL ) );
  for( ulong i=0UL; i<max; i++ ) FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txnhash ) );
  FD_TEST( ctx->lead.txncache_slots[ 1 ].entry_cnt==max );
  FD_TEST( txncache_staging_entry_add( ctx, 1001UL, txnhash )==-1 );

  for( ulong i=2UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) FD_TEST( txncache_staging_slot_begin( ctx, 1000UL+i )!=ULONG_MAX );
  FD_TEST( txncache_staging_slot_begin( ctx, 999UL )==ULONG_MAX );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 0UL ) );
  for( ulong i=0UL; i<max; i++ ) FD_TEST( !txncache_staging_entry_add( ctx, 999UL, txnhash ) );
  FD_TEST( txncache_staging_entry_add( ctx, 999UL, txnhash )==-1 );
}

static blockhash_map_t *
test_txncache_staging_recent_set( void *                 mem,
                                  fd_blockhash_entry_t * pool,
                                  ulong                  seed,
                                  uchar const * const *  blockhashes,
                                  ulong                  blockhashes_cnt ) {
  blockhash_map_t * map = blockhash_map_join( blockhash_map_new( mem, 1024UL, seed ) );
  FD_TEST( map );
  for( ulong i=0UL; i<blockhashes_cnt; i++ ) {
    fd_memcpy( pool[ i ].blockhash.uc, blockhashes[ i ], 32UL );
    blockhash_map_ele_insert( map, &pool[ i ], pool );
  }
  return map;
}

static void
test_txncache_staging_filters_recent_groups( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );

  static uchar const recent_a[ 32UL ] = { 0xA1 };
  static uchar const recent_b[ 32UL ] = { 0xB2 };
  static uchar const nonce_c[ 32UL ]  = { 0xC3 };
  static uchar const nonce_d[ 32UL ]  = { 0xD4 };
  uchar txnhash[ 20UL ] = {0};
  uchar next_txn = 1;

  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, recent_a, 1UL ) );
  for( ulong i=0UL; i<2UL; i++ ) { txnhash[ 0 ] = next_txn++; FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) ); }
  FD_TEST( !txncache_staging_group_begin( ctx, nonce_c, 7UL ) );
  for( ulong i=0UL; i<2UL; i++ ) { txnhash[ 0 ] = next_txn++; FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) ); }
  FD_TEST( !txncache_staging_group_begin( ctx, recent_b, 2UL ) );
  for( ulong i=0UL; i<2UL; i++ ) { txnhash[ 0 ] = next_txn++; FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) ); }

  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==1UL );
  FD_TEST( !txncache_staging_group_begin( ctx, nonce_d, 9UL ) );
  for( ulong i=0UL; i<2UL; i++ ) { txnhash[ 0 ] = next_txn++; FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txnhash ) ); }
  FD_TEST( !txncache_staging_group_begin( ctx, recent_a, 1UL ) );
  for( ulong i=0UL; i<2UL; i++ ) { txnhash[ 0 ] = next_txn++; FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txnhash ) ); }

  uchar __attribute__((aligned(alignof(blockhash_map_t)))) _map[ blockhash_map_footprint( 1024UL ) ];
  fd_blockhash_entry_t pool[ 2UL ];
  uchar const * recent[ 2UL ] = { recent_a, recent_b };
  blockhash_map_t * map = test_txncache_staging_recent_set( _map, pool, ctx->lead.seed, recent, 2UL );

  FD_TEST( !txncache_staging_filter_groups( ctx, map, pool, 1001UL ) );
  FD_TEST( ctx->lead.recent_groups_len==3UL );

  recent_blockhash_group_t const * g = ctx->lead.recent_groups;
  FD_TEST( g[ 0 ].blockhash_bank_i==0UL );
  FD_TEST( g[ 0 ].txnhash_offset==1UL );
  FD_TEST( g[ 0 ].txncache_entry_idx==0UL );
  FD_TEST( g[ 0 ].txncache_entry_cnt==2UL );

  FD_TEST( g[ 1 ].blockhash_bank_i==1UL );
  FD_TEST( g[ 1 ].txnhash_offset==2UL );
  FD_TEST( g[ 1 ].txncache_entry_idx==4UL );
  FD_TEST( g[ 1 ].txncache_entry_cnt==2UL );

  FD_TEST( g[ 2 ].blockhash_bank_i==0UL );
  FD_TEST( g[ 2 ].txnhash_offset==1UL );
  FD_TEST( g[ 2 ].txncache_entry_idx==ctx->lead.txncache_max_entries_per_slot+2UL );
  FD_TEST( g[ 2 ].txncache_entry_cnt==2UL );

  FD_TEST( ctx->lead.txncache_entries[ g[ 0 ].txncache_entry_idx     ].txnhash[ 0 ]==1  );
  FD_TEST( ctx->lead.txncache_entries[ g[ 1 ].txncache_entry_idx     ].txnhash[ 0 ]==5  );
  FD_TEST( ctx->lead.txncache_entries[ g[ 1 ].txncache_entry_idx+1UL ].txnhash[ 0 ]==6  );
  FD_TEST( ctx->lead.txncache_entries[ g[ 2 ].txncache_entry_idx     ].txnhash[ 0 ]==9  );
  FD_TEST( ctx->lead.txncache_entries[ g[ 2 ].txncache_entry_idx+1UL ].txnhash[ 0 ]==10 );
}

static void
test_txncache_staging_rejects_recent_group_overflow( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );

  static uchar const recent_a[ 32UL ] = { 0xA1 };
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )==0UL );
  for( ulong i=0UL; i<FD_SNAPIN_MAX_RECENT_GROUPS+1UL; i++ ) FD_TEST( !txncache_staging_group_begin( ctx, recent_a, 0UL ) );

  uchar __attribute__((aligned(alignof(blockhash_map_t)))) _map[ blockhash_map_footprint( 1024UL ) ];
  fd_blockhash_entry_t pool[ 1UL ];
  uchar const * recent[ 1UL ] = { recent_a };
  blockhash_map_t * map = test_txncache_staging_recent_set( _map, pool, ctx->lead.seed, recent, 1UL );

  FD_TEST( txncache_staging_filter_groups( ctx, map, pool, 1000UL )==-1 );
}

static void
test_txncache_staging_fits_one_gigantic_page( void ) {
  fd_topo_tile_t tile = {0};
  tile.snapin.max_live_slots   = 2048UL;
  tile.snapin.max_txn_per_slot = FD_MAX_TXN_PER_SLOT;
  ulong footprint = scratch_footprint( &tile );
  FD_TEST( footprint<(1UL<<30) );

  /* The staged entries scale with the per-slot limit.  Both footprints
     are rounded up to the scratch alignment, so the difference can land
     on either side of the exact entries term by less than one
     alignment. */
  tile.snapin.max_txn_per_slot = 2UL*FD_MAX_TXN_PER_SLOT;
  ulong delta   = scratch_footprint( &tile )-footprint;
  ulong entries = TEST_MAX_ENTRIES*sizeof(fd_sstxncache_hash_t);
  FD_TEST( delta+scratch_align()>entries && delta<entries+scratch_align() );
}

/* Group and entry bounds are runtime limits, so a raised
   max_txn_per_slot admits proportionally more before rejection. */
static void
test_txncache_staging_runtime_limits( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );
  ctx->lead.txncache_max_groups_per_slot  = 3UL;
  ctx->lead.txncache_max_entries_per_slot = 6UL;

  uchar blockhash[ 32UL ] = {0};
  static uchar const txnhash[ 20UL ] = { 0x33 };
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )==0UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_STORE( ulong, blockhash, i );
    FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 0UL ) );
    FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) );
    FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash ) );
  }
  FD_TEST( txncache_staging_group_begin( ctx, blockhash, 0UL )==-1 );

  /* Slot 1's groups start at the runtime stride, not the production one. */
  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==1UL );
  FD_STORE( ulong, blockhash, 7UL );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 0UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txnhash ) );
  FD_TEST( !memcmp( ctx->lead.blockhash_groups[ 3UL ].blockhash, blockhash, 32UL ) );
  FD_TEST( ctx->lead.txncache_entries[ 6UL ].txnhash[ 0 ]==0x33 );

  uchar __attribute__((aligned(alignof(blockhash_map_t)))) _map[ blockhash_map_footprint( 1024UL ) ];
  fd_blockhash_entry_t pool[ 1UL ];
  uchar const * recent[ 1UL ] = { blockhash };
  blockhash_map_t * map = test_txncache_staging_recent_set( _map, pool, ctx->lead.seed, recent, 1UL );
  FD_TEST( !txncache_staging_filter_groups( ctx, map, pool, 1001UL ) );
  FD_TEST( ctx->lead.recent_groups_len==1UL );
  FD_TEST( ctx->lead.recent_groups[ 0 ].txncache_entry_idx==6UL );
  FD_TEST( ctx->lead.recent_groups[ 0 ].txncache_entry_cnt==1UL );
}

static int
test_txncache_staging_populate( fd_snapin_tile_t * ctx,
                                fd_wksp_t *        wksp,
                                uchar const *      recent_blockhash,
                                ulong              snapshot_slot ) {
  ctx->lead.txncache = new_txncache( wksp, 1UL );

  fd_snapshot_manifest_blockhash_t blockhashes[ FD_BLOCKHASHES_MAX ] = {{ .hash_index = 0UL }};
  fd_memcpy( blockhashes[ 0UL ].hash, recent_blockhash, 32UL );
  int res = populate_txncache( ctx, blockhashes, 1UL, snapshot_slot );
  return res;
}

static void
test_txncache_staging_rejects_conflicting_group_offsets( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );

  static uchar const blockhash[ 32UL ] = { 1U };
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )!=ULONG_MAX );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 1UL ) );
  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )!=ULONG_MAX );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 2UL ) );

  FD_TEST( test_txncache_staging_populate( ctx, wksp, blockhash, 1001UL )==1 );
}

static void
test_txncache_staging_ignores_evicted_group_offsets( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_txncache_staging_ctx_init( ctx, wksp );

  static uchar const blockhash[ 32UL ] = { 1U };
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )!=ULONG_MAX );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 1UL ) );
  for( ulong i=1UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) FD_TEST( txncache_staging_slot_begin( ctx, 1000UL+i )!=ULONG_MAX );
  FD_TEST( txncache_staging_slot_begin( ctx, 1200UL )==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, blockhash, 2UL ) );

  FD_TEST( test_txncache_staging_populate( ctx, wksp, blockhash, 1200UL )==0 );
  FD_TEST( ctx->lead.recent_groups_len==1UL );
  FD_TEST( ctx->lead.recent_groups[ 0 ].txnhash_offset==2UL );
}

static void
test_populate_txncache_ctx_init( fd_snapin_tile_t * ctx,
                                 fd_wksp_t *        wksp ) {
  sync_ctx_init( ctx, 1UL, FD_SNAPSHOT_STATE_PROCESSING );
  ctx->lead.txncache = new_txncache( wksp, FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );
  fd_txncache_reset( ctx->lead.txncache );
  ctx->lead.blockhash_groups = txncache_staging_scratch( ctx );
  test_txncache_staging_side_arrays_alloc( ctx, wksp );
  txncache_staging_reset( ctx );

  void * parser_mem = fd_wksp_alloc_laddr( wksp, fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint(), 1UL );
  FD_TEST( parser_mem );
  ctx->lead.slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  FD_TEST( ctx->lead.slot_delta_parser );
  fd_slot_delta_parser_init( ctx->lead.slot_delta_parser );

  test_attached_fork_cnt = 0UL;
}

static void
test_txncache_staging_rejects_oversized_slot_delta( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_populate_txncache_ctx_init( ctx, wksp );
  ctx->lead.txncache_max_entries_per_slot = 6UL;

  static uchar const blockhash[ 32UL ] = { 0xB1 };
  ulong const entry_cnt = 7UL;
  uchar buf[ 8UL + 17UL + 48UL + 7UL*24UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  uchar * p = buf;
  FD_STORE( ulong, p, 1UL );        p += 8UL;  /* slot_deltas_len */
  FD_STORE( ulong, p, 1000UL );     p += 8UL;  /* slot */
  *p++ = 1;                                    /* is_root */
  FD_STORE( ulong, p, 1UL );        p += 8UL;  /* status_len */
  fd_memcpy( p, blockhash, 32UL );  p += 32UL;
  FD_STORE( ulong, p, 3UL );        p += 8UL;  /* txnhash_offset */
  FD_STORE( ulong, p, entry_cnt );  p += 8UL;
  for( ulong i=0UL; i<entry_cnt; i++ ) {
    fd_memset( p, (int)(0x40UL+i), 20UL );
    p += 20UL;
    FD_STORE( uint, p, 0U );
    p += 4UL;
  }
  FD_TEST( p==buf+sizeof(buf) );

  ctx->in[ 0 ].wksp   = (fd_wksp_t *)buf;
  ctx->in[ 0 ].chunk0 = 0UL;
  ctx->in[ 0 ].wmark  = 0UL;
  ctx->in[ 0 ].mtu    = sizeof(buf);
  test_parser_script   = 4;
  test_parser_call_cnt = 0UL;
  test_pub_cnt         = 0UL;
  FD_TEST( !handle_data_frag( ctx, 0UL, 0UL, sizeof(buf), (fd_stem_context_t *)1UL ) );
  FD_TEST( ctx->lead.txncache_current_slot_entry_cnt==6UL );
  FD_TEST( ctx->lead.txncache_slots[ 0UL ].entry_cnt==6UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( test_pub_cnt==1UL && test_pub_sig[ 0 ]==FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( !ctx->lead.flags.status_cache_done );
}

static void
test_txncache_staging_populate_inserts_recent_only( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_populate_txncache_ctx_init( ctx, wksp );

  static uchar const root_parent_blockhash[ 32UL ] = { 0xA1 };
  static uchar const snapshot_blockhash[ 32UL ]    = { 0xA2 };
  static uchar const nonce[ 32UL ]                 = { 0xC3 };
  uchar txnhash_recent[ 32UL ];
  uchar txnhash_nonce [ 32UL ];
  for( ulong i=0UL; i<32UL; i++ ) {
    txnhash_recent[ i ] = (uchar)(i+1UL);
    txnhash_nonce [ i ] = (uchar)(0x80UL+i);
  }

  uchar status_cache[ 169UL ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  uchar const * status_blockhashes[ 2UL ] = { nonce,         root_parent_blockhash };
  uchar const * status_txnhashes [ 2UL ] = { txnhash_nonce, txnhash_recent        };
  ulong const   status_offsets   [ 2UL ] = { 7UL,           5UL                   };
  uchar * p = status_cache;
  FD_STORE( ulong, p, 1UL );    p += sizeof(ulong);
  FD_STORE( ulong, p, 1000UL ); p += sizeof(ulong);
  *p++ = 1U;
  FD_STORE( ulong, p, 2UL );    p += sizeof(ulong);
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_memcpy( p, status_blockhashes[ i ], 32UL ); p += 32UL;
    FD_STORE( ulong, p, status_offsets[ i ] );     p += sizeof(ulong);
    FD_STORE( ulong, p, 1UL );                     p += sizeof(ulong);
    fd_memcpy( p, status_txnhashes[ i ]+status_offsets[ i ], 20UL ); p += 20UL;
    FD_STORE( uint, p, 0U ); p += sizeof(uint);
  }
  FD_TEST( p==status_cache+sizeof(status_cache) );

  ctx->in[ 0 ].wksp   = (fd_wksp_t *)status_cache;
  ctx->in[ 0 ].chunk0 = 0UL;
  ctx->in[ 0 ].wmark  = 0UL;
  ctx->in[ 0 ].mtu    = sizeof(status_cache);
  test_parser_script   = 4;
  test_parser_call_cnt = 0UL;
  FD_TEST( !handle_data_frag( ctx, 0UL, 0UL, sizeof(status_cache), (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==1UL );
  FD_TEST( ctx->lead.flags.status_cache_done );
  FD_TEST( ctx->lead.txncache_slots_len==1UL );
  FD_TEST( ctx->lead.txncache_slots[ 0UL ].group_cnt==2UL );
  FD_TEST( ctx->lead.txncache_slots[ 0UL ].entry_cnt==2UL );

  fd_snapshot_manifest_blockhash_t blockhashes[ FD_BLOCKHASHES_MAX ] = {{ .hash_index = 0UL }, { .hash_index = 1UL }};
  fd_memcpy( blockhashes[ 0UL ].hash, root_parent_blockhash, 32UL );
  fd_memcpy( blockhashes[ 1UL ].hash, snapshot_blockhash,    32UL );
  FD_TEST( populate_txncache( ctx, blockhashes, 2UL, 1000UL )==0 );
  FD_TEST( ctx->lead.recent_groups_len==1UL );
  FD_TEST( ctx->lead.recent_groups[ 0 ].blockhash_bank_i==1UL );

  fd_txncache_fork_id_t child = fd_txncache_attach_child( ctx->lead.txncache, ctx->lead.txncache_root_fork_id );
  FD_TEST(  fd_txncache_query( ctx->lead.txncache, child, root_parent_blockhash, txnhash_recent ) );
  FD_TEST( !fd_txncache_query( ctx->lead.txncache, child, root_parent_blockhash, txnhash_nonce  ) );
}

static uchar const test_blockhash_1000[ 32UL ] = { 0xB0 };
static uchar const test_blockhash_1001[ 32UL ] = { 0xB1 };
static uchar const test_blockhash_1002[ 32UL ] = { 0xB2 };

static void
test_populate_blockhashes_init( fd_snapshot_manifest_blockhash_t * blockhashes ) {
  blockhashes[ 0UL ].hash_index = 0UL;
  fd_memcpy( blockhashes[ 0UL ].hash, test_blockhash_1000, 32UL );
  blockhashes[ 1UL ].hash_index = 1UL;
  fd_memcpy( blockhashes[ 1UL ].hash, test_blockhash_1001, 32UL );
  blockhashes[ 2UL ].hash_index = 2UL;
  fd_memcpy( blockhashes[ 2UL ].hash, test_blockhash_1002, 32UL );
}

static void
test_txnhash_init( uchar out[ static 32UL ],
                   uchar tag ) {
  for( ulong i=0UL; i<32UL; i++ ) out[ i ] = (uchar)( tag+i );
}

static void
test_populate_txncache_slot_attribution( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_populate_txncache_ctx_init( ctx, wksp );

  fd_snapshot_manifest_blockhash_t blockhashes[ FD_BLOCKHASHES_MAX ] = {0};
  test_populate_blockhashes_init( blockhashes );
  uchar txn_1001_bh_1000[ 32UL ];
  uchar txn_1002_bh_1001[ 32UL ];
  uchar txn_1002_bh_1000[ 32UL ];
  test_txnhash_init( txn_1001_bh_1000, 0x40 );
  test_txnhash_init( txn_1002_bh_1001, 0x10 );
  test_txnhash_init( txn_1002_bh_1000, 0x70 );

  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1000, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txn_1001_bh_1000+5UL ) );
  FD_TEST( txncache_staging_slot_begin( ctx, 1002UL )==1UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1001, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1002UL, txn_1002_bh_1001+5UL ) );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1000, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1002UL, txn_1002_bh_1000+5UL ) );

  FD_TEST( populate_txncache( ctx, blockhashes, 3UL, 1002UL )==0 );

  fd_txncache_fork_id_t restored_fork_1000 = test_attached_fork_id[ 0UL ];
  fd_txncache_fork_id_t restored_fork_1001 = test_attached_fork_id[ 1UL ];

  fd_txncache_fork_id_t child_of_1000 = fd_txncache_attach_child( ctx->lead.txncache, restored_fork_1000 );
  FD_TEST( !fd_txncache_query( ctx->lead.txncache, child_of_1000, test_blockhash_1000, txn_1001_bh_1000 ) );

  fd_txncache_fork_id_t child_of_1001 = fd_txncache_attach_child( ctx->lead.txncache, restored_fork_1001 );
  FD_TEST(  fd_txncache_query( ctx->lead.txncache, child_of_1001, test_blockhash_1000, txn_1001_bh_1000 ) );
  FD_TEST( !fd_txncache_query( ctx->lead.txncache, child_of_1001, test_blockhash_1000, txn_1002_bh_1000 ) );
  FD_TEST( !fd_txncache_query( ctx->lead.txncache, child_of_1001, test_blockhash_1001, txn_1002_bh_1001 ) );

  fd_txncache_fork_id_t child_of_root = fd_txncache_attach_child( ctx->lead.txncache, ctx->lead.txncache_root_fork_id );
  FD_TEST( fd_txncache_query( ctx->lead.txncache, child_of_root, test_blockhash_1000, txn_1001_bh_1000 ) );
  FD_TEST( fd_txncache_query( ctx->lead.txncache, child_of_root, test_blockhash_1000, txn_1002_bh_1000 ) );
  FD_TEST( fd_txncache_query( ctx->lead.txncache, child_of_root, test_blockhash_1001, txn_1002_bh_1001 ) );
}

static void
test_populate_txncache_rejects_invalid_blockhash_age( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_populate_txncache_ctx_init( ctx, wksp );

  fd_snapshot_manifest_blockhash_t blockhashes[ FD_BLOCKHASHES_MAX ] = {0};
  test_populate_blockhashes_init( blockhashes );
  uchar txnhash[ 32UL ];
  test_txnhash_init( txnhash, 0x10 );

  FD_TEST( txncache_staging_slot_begin( ctx, 1002UL )==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1002, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1002UL, txnhash+5UL ) );
  FD_TEST( populate_txncache( ctx, blockhashes, 3UL, 1002UL )==1 );

  fd_txncache_reset( ctx->lead.txncache );
  txncache_staging_reset( ctx );
  FD_TEST( txncache_staging_slot_begin( ctx, 1002UL )==0UL );
  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==1UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1001, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txnhash+5UL ) );
  FD_TEST( populate_txncache( ctx, blockhashes, 3UL, 1002UL )==1 );

  fd_txncache_reset( ctx->lead.txncache );
  txncache_staging_reset( ctx );
  FD_TEST( txncache_staging_slot_begin( ctx, 1002UL )==0UL );
  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==1UL );
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )==2UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1001, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1000UL, txnhash+5UL ) );
  FD_TEST( populate_txncache( ctx, blockhashes, 3UL, 1002UL )==1 );

  fd_txncache_reset( ctx->lead.txncache );
  txncache_staging_reset( ctx );
  FD_TEST( txncache_staging_slot_begin( ctx, 1002UL )==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1002, 5UL ) );
  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==1UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1000, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txnhash+5UL ) );
  FD_TEST( populate_txncache( ctx, blockhashes, 3UL, 1002UL )==0 );
}

static void
test_populate_txncache_requires_snapshot_slot_delta( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_populate_txncache_ctx_init( ctx, wksp );

  fd_snapshot_manifest_blockhash_t blockhashes[ FD_BLOCKHASHES_MAX ] = {0};
  test_populate_blockhashes_init( blockhashes );
  uchar txnhash[ 32UL ];
  test_txnhash_init( txnhash, 0x10 );

  FD_TEST( txncache_staging_slot_begin( ctx, 1001UL )==0UL );
  FD_TEST( !txncache_staging_group_begin( ctx, test_blockhash_1000, 5UL ) );
  FD_TEST( !txncache_staging_entry_add( ctx, 1001UL, txnhash+5UL ) );
  FD_TEST( txncache_staging_slot_begin( ctx, 1000UL )==1UL );
  FD_TEST( populate_txncache( ctx, blockhashes, 3UL, 1002UL )==1 );
}

static void
test_parse_status_cache( fd_snapin_tile_t * ctx,
                         uchar *            status_cache,
                         ulong              status_cache_sz ) {
  ctx->in[ 0 ].wksp   = (fd_wksp_t *)status_cache;
  ctx->in[ 0 ].chunk0 = 0UL;
  ctx->in[ 0 ].wmark  = 0UL;
  ctx->in[ 0 ].mtu    = status_cache_sz;
  test_parser_script   = 4;
  test_parser_call_cnt = 0UL;
  FD_TEST( !handle_data_frag( ctx, 0UL, 0UL, status_cache_sz, (fd_stem_context_t *)1UL ) );
  FD_TEST( test_parser_call_cnt==1UL );
  FD_TEST( ctx->lead.flags.status_cache_done );
}

static void
test_populate_txncache_accepts_empty_rooted_status_cache( fd_wksp_t * wksp ) {
  fd_snapin_tile_t * ctx = test_ctx;
  test_populate_txncache_ctx_init( ctx, wksp );

  static ulong const snapshot_slot = 1000UL;
  static uchar const blockhash[ 32UL ] = { 0xA1 };
  fd_snapshot_manifest_blockhash_t blockhashes[ FD_BLOCKHASHES_MAX ] = {{ .hash_index = 0UL }};
  fd_memcpy( blockhashes[ 0UL ].hash, blockhash, 32UL );

  uchar no_slots[ 8UL ] __attribute__((aligned(FD_CHUNK_ALIGN))) = {0};
  test_parse_status_cache( ctx, no_slots, sizeof(no_slots) );
  FD_TEST( populate_txncache( ctx, blockhashes, 1UL, snapshot_slot )==1 );

  fd_txncache_reset( ctx->lead.txncache );
  txncache_staging_reset( ctx );
  fd_slot_delta_parser_init( ctx->lead.slot_delta_parser );
  ctx->lead.flags.status_cache_done = 0;
  test_attached_fork_cnt             = 0UL;

  uchar status_cache[ 25UL ] __attribute__((aligned(FD_CHUNK_ALIGN))) = {0};
  FD_STORE( ulong, status_cache,      1UL           );
  FD_STORE( ulong, status_cache+8UL,  snapshot_slot );
  status_cache[ 16UL ] = 1U;
  FD_STORE( ulong, status_cache+17UL, 0UL           );
  test_parse_status_cache( ctx, status_cache, sizeof(status_cache) );

  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( ctx->lead.slot_delta_parser );
  FD_TEST( slot_set.ele_cnt==1UL );
  FD_TEST( slot_set_ele_query( slot_set.map, &snapshot_slot, NULL, slot_set.pool ) );
  FD_TEST( populate_txncache( ctx, blockhashes, 1UL, snapshot_slot )==0 );

  fd_txncache_fork_id_t child = fd_txncache_attach_child( ctx->lead.txncache, ctx->lead.txncache_root_fork_id );
  uchar inserted_txnhash       [ 32UL ];
  uchar matching_prefix_txnhash[ 32UL ];
  for( ulong i=0UL; i<20UL; i++ ) inserted_txnhash[ i ] = matching_prefix_txnhash[ i ] = (uchar)( i+1UL );
  for( ulong i=20UL; i<32UL; i++ ) {
    inserted_txnhash       [ i ] = (uchar)( 0x80UL+i );
    matching_prefix_txnhash[ i ] = (uchar)( 0x40UL+i );
  }
  fd_txncache_insert( ctx->lead.txncache, child, blockhash, inserted_txnhash );
  FD_TEST( fd_txncache_query( ctx->lead.txncache, child, blockhash, matching_prefix_txnhash ) );
  matching_prefix_txnhash[ 0UL ] ^= 1U;
  FD_TEST( !fd_txncache_query( ctx->lead.txncache, child, blockhash, matching_prefix_txnhash ) );
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
  FD_TEST( !cl->shmem->next_appendvec_ticket );

  /* Partial walk: every tile gets three events in. */
  for( ulong step=0UL; step<3UL; step++ ) {
    for( ulong t=0UL; t<n; t++ ) (void)tile_step( &cl->ctx[ t ] );
  }
  ulong mid_claims = cl->shmem->next_appendvec_ticket;
  FD_TEST( mid_claims>n );
  cl->ctx[ 0 ].writer.buf[ 0 ] = 1U;
  cl->ctx[ 0 ].writer.buf_used = 1UL;
  FD_TEST( cl->ctx[ 0 ].writer.buf_used );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  for( ulong t=0UL; t<n; t++ ) {
    fd_snapin_tile_t * ctx = &cl->ctx[ t ];
    FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
    FD_TEST( !ctx->appendvec_seq );
    FD_TEST( ctx->incr_fork==ULONG_MAX );
  }
  FD_TEST( cl->ctx[ 0 ].lead.rollback.pending );
  FD_TEST( cl->ctx[ 0 ].lead.rollback.full );
  /* The claim counter is deliberately NOT reset by FAIL: only tile 0's
     next INIT re-zeroes it. */
  FD_TEST( cl->shmem->next_appendvec_ticket==mid_claims );
  cl->shmem->values[ FD_TOPO_MAX_TILE_IN_LINKS-1UL ].input_lamports = 5678UL;

  /* Retry.  Tile 0 rolls back first, then re-zeroes and republishes. */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );

  FD_TEST( !cl->ctx[ 0 ].lead.rollback.pending );
  FD_TEST( test_accdb_reset_cnt==1UL );      /* full retry wipes the fork wholesale */
  FD_TEST( !test_accdb_purge_cnt );          /* ... so no incremental purge */
  FD_TEST( !test_accdb_revert_whead_cnt );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( !cl->ctx[ t ].writer.buf_used );

  FD_TEST( !cl->shmem->values[ FD_TOPO_MAX_TILE_IN_LINKS-1UL ].input_lamports );
  FD_TEST( !cl->shmem->next_appendvec_ticket );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].incr_fork==ULONG_MAX );

  /* The retry covers every ordinal exactly once (cluster_stream would
     trip on a double claim). */
  ulong owner[ TEST_AV_MAX ];
  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( cl->shmem->next_appendvec_ticket==T+n );

  test_cluster_delete( cl );
}

/* Accumulator fold ****************************************************/

/* Tile 0 folds the per-tile capitalization totals at NEXT. */
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

  ulong exp_loaded=0UL, exp_duplicates=0UL;
  ulong exp_input=0UL, exp_duplicate_lamports=0UL;
  for( ulong t=0UL; t<n; t++ ) {
    cl->shmem->values[ t ].loaded             = 100UL+t;
    cl->shmem->values[ t ].duplicates         =  11UL+2UL*t;
    cl->shmem->values[ t ].input_lamports     = 1000000UL*(t+1UL);
    cl->shmem->values[ t ].duplicate_lamports =    5700UL*(t+1UL);

    exp_loaded             += cl->shmem->values[ t ].loaded;
    exp_duplicates         += cl->shmem->values[ t ].duplicates;
    exp_input              += cl->shmem->values[ t ].input_lamports;
    exp_duplicate_lamports += cl->shmem->values[ t ].duplicate_lamports;
  }

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );

  /* Tile 0 reads the fold at NEXT. */
  test_stamp_sysvars( cl, bank_slot );
  cl->ctx[ 0 ].lead.manifest_capitalization = exp_input-exp_duplicate_lamports;

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_NEXT );

  fd_snapin_tile_t * t0 = &cl->ctx[ 0 ];
  FD_TEST( t0->state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( t0->lead.recovery.capitalization==exp_input-exp_duplicate_lamports );
  FD_TEST( t0->lead.account_counts.loaded    ==exp_loaded     );
  FD_TEST( t0->lead.account_counts.duplicates==exp_duplicates );
  /* The full snapshot's totals are saved for the incremental revert. */
  FD_TEST( t0->lead.recovery.capitalization==t0->lead.manifest_capitalization );
  FD_TEST( test_accdb_read_one_cnt==FD_SYSVAR_CACHE_ENTRY_CNT );
  FD_TEST( test_accdb_read_one_fork.val==t0->lead.accdb_root_fork_id.val );

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

  /* --- Full load ------------------------------------------------- */
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( !test_loaded_sum( cl ) );
  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );

  ulong full_share = 100UL;
  for( ulong t=0UL; t<n; t++ ) cl->ctx[ t ].metrics.accounts_loaded = full_share;
  FD_TEST( test_loaded_sum( cl )==full_share*n );

  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_loaded_sum( cl )==full_share*n );   /* was ~0 before: every tile zeroed here */

  test_stamp_sysvars( cl, bank_slot );
  cl->ctx[ 0 ].lead.manifest_capitalization = 0UL;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_NEXT );
  FD_TEST( test_loaded_sum( cl )==full_share*n );   /* was full_share*n + the fold: double counted */

  /* --- Incremental that fails ------------------------------------ */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( test_loaded_sum( cl )==full_share*n );   /* resumes from the full share */

  for( ulong t=0UL; t<n; t++ ) cl->ctx[ t ].metrics.accounts_loaded += 7UL;
  FD_TEST( test_loaded_sum( cl )==(full_share+7UL)*n );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( test_loaded_sum( cl )==(full_share+7UL)*n ); /* FAIL alone does not rewind */

  /* --- Incremental retry ----------------------------------------- */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  /* The retry's INIT is the one point the sum steps back, and only by
     the failed attempt's own contribution -- never to zero. */
  FD_TEST( test_loaded_sum( cl )==full_share*n );

  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );
  ulong incr_share = 11UL;
  for( ulong t=0UL; t<n; t++ ) cl->ctx[ t ].metrics.accounts_loaded += incr_share;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_loaded_sum( cl )==(full_share+incr_share)*n );

  test_stamp_sysvars( cl, bank_slot );
  cl->ctx[ 0 ].lead.manifest_capitalization = cl->ctx[ 0 ].lead.recovery.capitalization;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_DONE );
  FD_TEST( test_loaded_sum( cl )==(full_share+incr_share)*n );

  test_cluster_delete( cl );
}

/* Sysvar verification *************************************************/

/* Drive verify_sysvars directly against the accdb mock. */

#define TEST_SYSVAR_BANK_SLOT (440123518UL)

static test_cluster_t *
test_sysvar_cluster_new( void ) {
  test_cluster_t * cl = test_cluster_new( 1UL, 1UL );
  test_counters_reset();
  test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
  return cl;
}

static void
test_verify_sysvars_accepts_valid( void ) {
  test_cluster_t * cl = test_sysvar_cluster_new();
  fd_snapin_tile_t * ctx = &cl->ctx[ 0 ];

  FD_TEST( !verify_sysvars( ctx ) );
  FD_TEST( test_accdb_read_one_cnt==FD_SYSVAR_CACHE_ENTRY_CNT );
  FD_TEST( test_accdb_read_one_fork.val==ctx->lead.accdb_root_fork_id.val );

  /* An incremental load reads from the incremental fork. */
  ctx->full = 0;
  ctx->lead.accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = 7U };
  FD_TEST( !verify_sysvars( ctx ) );
  FD_TEST( test_accdb_read_one_fork.val==7U );

  /* Oversized accounts decode from their prefix, like at boot. */
  ctx->full = 1;
  test_sysvars[ FD_SYSVAR_clock_IDX         ].data_len = FD_SYSVAR_CLOCK_BINCODE_SZ+1UL;
  test_sysvars[ FD_SYSVAR_recent_hashes_IDX ].data_len = FD_SYSVAR_RECENT_HASHES_BINCODE_SZ+8UL;
  test_sysvars[ FD_SYSVAR_slot_hashes_IDX   ].data_len = FD_SYSVAR_SLOT_HASHES_BINCODE_SZ+8UL;
  FD_TEST( !verify_sysvars( ctx ) );

  test_cluster_delete( cl );
}

/* Only Clock, Rent and SlotHistory are required. */
static void
test_verify_sysvars_presence( void ) {
  test_cluster_t * cl = test_sysvar_cluster_new();
  for( ulong idx=0UL; idx<FD_SYSVAR_CACHE_ENTRY_CNT; idx++ ) {
    test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
    test_sysvars[ idx ].lamports = 0UL;
    int required = idx==FD_SYSVAR_clock_IDX || idx==FD_SYSVAR_rent_IDX || idx==FD_SYSVAR_slot_history_IDX;
    FD_TEST( verify_sysvars( &cl->ctx[ 0 ] )==(required ? -1 : 0) );
  }
  test_cluster_delete( cl );
}

static void
test_verify_sysvars_rejects_bad_owner( void ) {
  test_cluster_t * cl = test_sysvar_cluster_new();
  for( ulong idx=0UL; idx<FD_SYSVAR_CACHE_ENTRY_CNT; idx++ ) {
    test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
    test_sysvars[ idx ].owner[ 0 ] ^= 1;
    FD_TEST( verify_sysvars( &cl->ctx[ 0 ] )==-1 );
  }
  test_cluster_delete( cl );
}

/* Rejects anything fd_sysvar_cache_restore would not decode. */
static void
test_verify_sysvars_rejects_undecodable( void ) {
  test_cluster_t * cl = test_sysvar_cluster_new();
  fd_snapin_tile_t * ctx = &cl->ctx[ 0 ];

  /* Every sysvar has a minimum serialized size. */
  for( ulong idx=0UL; idx<FD_SYSVAR_CACHE_ENTRY_CNT; idx++ ) {
    test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
    test_sysvars[ idx ].data_len = 0UL;
    FD_TEST( verify_sysvars( ctx )==-1 );
  }

  /* Right size, bad content (the decoders themselves are covered by
     the sysvar unit tests). */
  test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
  test_sysvars[ FD_SYSVAR_epoch_schedule_IDX ].data[ offsetof(fd_epoch_schedule_t, warmup) ] = 2;
  FD_TEST( verify_sysvars( ctx )==-1 );

  /* SlotHistory must be exactly the serialized size, SlotHashes at
     least (the in-place updater rewrites the whole account). */
  test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
  test_sysvars[ FD_SYSVAR_slot_history_IDX ].data_len = FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ+1UL;
  FD_TEST( verify_sysvars( ctx )==-1 );
  test_sysvars[ FD_SYSVAR_slot_history_IDX ].data_len = FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ-1UL;
  FD_TEST( verify_sysvars( ctx )==-1 );
  test_sysvars[ FD_SYSVAR_slot_history_IDX ].data_len = FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ;
  test_sysvars[ FD_SYSVAR_slot_hashes_IDX  ].data_len = FD_SYSVAR_SLOT_HASHES_BINCODE_SZ-1UL;
  FD_TEST( verify_sysvars( ctx )==-1 );

  test_cluster_delete( cl );
}

/* lamports_per_byte is bounded only for thresholds 1.0 and 2.0. */
static void
test_verify_sysvars_rent_bounds( void ) {
  test_cluster_t * cl = test_sysvar_cluster_new();
  ulong const idx = FD_SYSVAR_rent_IDX;
  ulong const sz  = FD_SYSVAR_RENT_BINCODE_SZ;

  struct { double threshold; ulong max; } const cases[] = {
    { 1.0, 1759197129867UL },
    { 2.0,  879598564933UL },
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    fd_rent_t rent = { .lamports_per_uint8_year = cases[ i ].max, .exemption_threshold = cases[ i ].threshold, .burn_percent = 50 };
    FD_TEST( !test_verify_with( cl, idx, &rent, sz ) );
    rent.lamports_per_uint8_year++;
    FD_TEST( test_verify_with( cl, idx, &rent, sz )==-1 );
  }

  ulong const thresholds[] = { 0UL, fd_dblbits( -1.0 ), fd_dblbits( 3.5 ), 0x7ff0000000000000UL /* inf */, 0x7ff8000000000000UL /* nan */ };
  for( ulong i=0UL; i<sizeof(thresholds)/sizeof(thresholds[0]); i++ ) {
    fd_rent_t rent = { .lamports_per_uint8_year = ULONG_MAX, .exemption_threshold = fd_double( thresholds[ i ] ), .burn_percent = 50 };
    FD_TEST( !test_verify_with( cl, idx, &rent, sz ) );
  }

  test_cluster_delete( cl );
}

/* Active EpochRewards fields must satisfy the recalculation asserts. */
static void
test_verify_sysvars_epoch_rewards( void ) {
  test_cluster_t * cl = test_sysvar_cluster_new();
  fd_snapin_tile_t * ctx = &cl->ctx[ 0 ];
  ulong const idx = FD_SYSVAR_epoch_rewards_IDX;
  ulong const sz  = FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ;

  fd_sysvar_epoch_rewards_t rewards = {
    .active                             = 1,
    .num_partitions                     = 1UL,
    .total_rewards                      = 10UL,
    .distributed_rewards                = 10UL,
    .distribution_starting_block_height = ULONG_MAX-1UL,
  };
  FD_TEST( !test_verify_with( cl, idx, &rewards, sz ) );

  rewards.distributed_rewards = 11UL;
  FD_TEST( test_verify_with( cl, idx, &rewards, sz )==-1 );
  rewards.distributed_rewards = 10UL;

  rewards.distribution_starting_block_height = ULONG_MAX;
  FD_TEST( test_verify_with( cl, idx, &rewards, sz )==-1 );
  rewards.distribution_starting_block_height = 0UL;

  struct { ulong partitions; int ok; } const cases[] = {
    { 0UL,                          0 },
    { MAX_PARTITIONS_PER_EPOCH,     1 },
    { MAX_PARTITIONS_PER_EPOCH+1UL, 0 },
    { ULONG_MAX,                    0 },
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    rewards.num_partitions = cases[ i ].partitions;
    FD_TEST( test_verify_with( cl, idx, &rewards, sz )==(cases[ i ].ok ? 0 : -1) );
  }

  /* Partitions must fit inside the epoch. */
  fd_epoch_schedule_t saved = ctx->lead.epoch_schedule;
  FD_TEST( fd_epoch_schedule_derive( &ctx->lead.epoch_schedule, 64UL, 64UL, 0 ) );
  ctx->lead.epoch = fd_slot_to_epoch( &ctx->lead.epoch_schedule, TEST_SYSVAR_BANK_SLOT, NULL );
  rewards.num_partitions = 64UL;
  FD_TEST( test_verify_with( cl, idx, &rewards, sz )==-1 );
  rewards.num_partitions = 63UL;
  FD_TEST( !test_verify_with( cl, idx, &rewards, sz ) );
  ctx->lead.epoch_schedule = saved;
  ctx->lead.epoch          = fd_slot_to_epoch( &saved, TEST_SYSVAR_BANK_SLOT, NULL );

  /* Recalculation reads StakeHistory. */
  test_sysvars[ FD_SYSVAR_stake_history_IDX ].lamports = 0UL;
  FD_TEST( verify_sysvars( ctx )==-1 );
  test_sysvars[ FD_SYSVAR_stake_history_IDX ].lamports = 1UL;

  /* The reward reader requires the exact serialized size. */
  test_sysvars[ idx ].data_len = sz+1UL;
  FD_TEST( verify_sysvars( ctx )==-1 );

  /* None of this applies while rewards are inactive. */
  rewards.active              = 0;
  rewards.num_partitions      = ULONG_MAX;
  rewards.distributed_rewards = ULONG_MAX;
  test_sysvar_set( idx, &rewards, sz );
  test_sysvars[ idx ].data_len = sz+1UL;
  test_sysvars[ FD_SYSVAR_stake_history_IDX ].lamports = 0UL;
  FD_TEST( !verify_sysvars( ctx ) );

  test_cluster_delete( cl );
}

/* A failed gate at NEXT/DONE publishes ERROR instead of forwarding. */
static void
test_verify_sysvars_gates_controls( void ) {
  ulong const n = 2UL;
  ulong const T = 3UL;
  ulong owner[ TEST_AV_MAX ];

  for( ulong i=0UL; i<3UL; i++ ) {
    int   incr = i==2UL;
    ulong sig  = i ? FD_SNAPSHOT_MSG_CTRL_DONE : FD_SNAPSHOT_MSG_CTRL_NEXT;

    test_cluster_t * cl = test_cluster_new( n, 1UL );
    test_counters_reset();
    test_stream_init( T );
    cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
    cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );
    cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );

    if( incr ) {
      test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
      cl->ctx[ 0 ].lead.manifest_capitalization = 0UL;
      cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_NEXT );
      FD_TEST( cl->ctx[ 0 ].state==FD_SNAPSHOT_STATE_IDLE );

      test_counters_reset();
      test_stream_init( T );
      cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
      cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );
      cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
    }

    test_stamp_sysvars( cl, TEST_SYSVAR_BANK_SLOT );
    test_sysvars[ FD_SYSVAR_rent_IDX ].lamports = 0UL;
    cl->ctx[ 0 ].lead.manifest_capitalization = 0UL;

    ulong pub0 = test_pub_cnt;
    cluster_barrier( cl, sig );
    FD_TEST( cl->ctx[ 0 ].state==FD_SNAPSHOT_STATE_ERROR );
    FD_TEST( test_pub_sig[ pub0 ]==FD_SNAPSHOT_MSG_CTRL_ERROR );
    FD_TEST( test_pub_sig[ pub0+1UL ]==sig ); /* tile 1 does not gate */
    FD_TEST( test_pub_cnt==pub0+n );
    FD_TEST( !test_accdb_save_whead_cnt );
    FD_TEST( !test_accdb_advance_root_cnt );
    FD_TEST( !test_accdb_load_end_cnt );
    FD_TEST( !test_feature_restore_cnt );
    FD_TEST( test_accdb_read_one_fork.val==(incr ? 7U : cl->ctx[ 0 ].lead.accdb_root_fork_id.val) );

    test_cluster_delete( cl );
  }
}

/* Full lifecycle ******************************************************/

/* Nine tiles through a whole load: full attempt, an incremental
   attempt that fails and is retried, then the successful incremental
   promotion.  Pins the cross-attempt bookkeeping the individual cases
   above only touch in isolation. */
static void
test_full_lifecycle_9_tiles( void ) {
  ulong const n = 9UL;
  ulong const T = 11UL;
  ulong const bank_slot = 440123518UL;

  test_cluster_t * cl = test_cluster_new( n, 2UL );
  test_counters_reset();
  test_stream_init( T );
  ulong owner[ TEST_AV_MAX ];

  /* --- Full attempt --------------------------------------------- */
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( test_accdb_reset_cnt==1UL );
  FD_TEST( test_accdb_load_begin_cnt==1UL );
  FD_TEST( !cl->shmem->next_appendvec_ticket );
  FD_TEST( cl->ctx[ 0 ].incr_fork==ULONG_MAX );

  cluster_stream( cl, TEST_ORDER_ROUND_ROBIN, owner );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].incr_fork==(ulong)USHORT_MAX );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( test_accdb_flush_metrics_cnt==n );
  FD_TEST( !test_accdb_read_one_cnt );

  test_stamp_sysvars( cl, bank_slot );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_NEXT );
  FD_TEST( test_accdb_read_one_cnt==FD_SYSVAR_CACHE_ENTRY_CNT );
  FD_TEST( test_accdb_read_one_fork.val==cl->ctx[ 0 ].lead.accdb_root_fork_id.val );
  FD_TEST( test_accdb_save_whead_cnt==1UL );
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].state==FD_SNAPSHOT_STATE_IDLE );
  FD_TEST( !cl->ctx[ 0 ].lead.init_completed );

  /* --- Incremental attempt that fails --------------------------- */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( !test_accdb_reset_cnt );
  FD_TEST( test_accdb_attach_cnt==1UL );          /* child fork for the incremental writes */
  FD_TEST( test_stake_new_fork_cnt==1UL );        /* stake delegations fork likewise */
  FD_TEST( cl->shmem->fork_id==7UL );
  FD_TEST( cl->shmem->stake_fork==3 );
  FD_TEST( cl->ctx[ 0 ].incr_fork==ULONG_MAX );
  FD_TEST( !cl->shmem->next_appendvec_ticket );

  for( ulong step=0UL; step<4UL; step++ ) {
    for( ulong t=0UL; t<n; t++ ) (void)tile_step( &cl->ctx[ t ] );
  }
  for( ulong t=0UL; t<n; t++ ) FD_TEST( cl->ctx[ t ].incr_fork==7UL );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( cl->ctx[ 0 ].lead.rollback.pending );
  FD_TEST( !cl->ctx[ 0 ].lead.rollback.full );
  FD_TEST( cl->ctx[ 0 ].lead.accdb_incr_fork_id.val==USHORT_MAX );
  FD_TEST( cl->shmem->stake_fork==3UL );                   /* kept for the rollback at the next INIT */
  FD_TEST( !test_stake_evict_cnt );

  /* --- Incremental retry ---------------------------------------- */
  test_counters_reset();
  test_stream_init( T );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_INIT_INCR );
  FD_TEST( test_accdb_purge_cnt==1UL );                    /* failed fork purged */
  FD_TEST( test_accdb_revert_whead_cnt==1UL );
  FD_TEST( test_stake_evict_cnt==1UL && test_stake_evict_fork==3U ); /* failed stake fork evicted */
  FD_TEST( test_stake_new_fork_cnt==1UL );
  FD_TEST( !cl->shmem->next_appendvec_ticket );

  cluster_stream( cl, TEST_ORDER_REVERSE, owner );
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_FINI );
  FD_TEST( cl->shmem->next_appendvec_ticket==T+n );
  FD_TEST( !test_accdb_read_one_cnt );

  /* An incremental load's capitalization starts from the full
     snapshot's saved total; nothing was inserted here, so it is
     unchanged. */
  test_stamp_sysvars( cl, bank_slot );
  cl->ctx[ 0 ].lead.manifest_capitalization = cl->ctx[ 0 ].lead.recovery.capitalization;

  ulong pub0 = test_pub_cnt;
  cluster_barrier( cl, FD_SNAPSHOT_MSG_CTRL_DONE );
  FD_TEST( test_accdb_recover_delta_cnt==1UL );
  FD_TEST( test_accdb_advance_root_cnt==1UL );
  FD_TEST( test_accdb_load_end_cnt==1UL );
  FD_TEST( test_feature_restore_cnt==1UL );
  FD_TEST( test_feature_restore_fork.val==7U );
  FD_TEST( test_accdb_read_one_cnt==FD_SYSVAR_CACHE_ENTRY_CNT );
  FD_TEST( test_accdb_read_one_fork.val==7U );
  FD_TEST( cl->ctx[ 0 ].lead.accdb_root_fork_id.val==7U );
  FD_TEST( cl->ctx[ 0 ].lead.accdb_incr_fork_id.val==USHORT_MAX );
  FD_TEST( test_stake_publish_cnt==1UL && test_stake_publish_fork==3U ); /* stake fork published */
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

static void
test_writer_short_write_and_eintr( void ) {
  uchar data[ 5UL ] = { 1, 2, 3, 4, 5 };
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 1UL, FD_SNAPSHOT_STATE_IDLE );

  test_io_reset();
  test_pwrite_push( -1L, EINTR );
  test_pwrite_push(  2L, 0     );
  test_pwrite_push(  3L, 0     );

  writer_pwrite( ctx, data, sizeof(data), 10UL );
  FD_TEST( test_pwrite_call_cnt==3UL );
  FD_TEST( test_pwrite_sz [0]==5UL && test_pwrite_off[0]==10UL && test_pwrite_data[0][0]==1U );
  FD_TEST( test_pwrite_sz [1]==5UL && test_pwrite_off[1]==10UL && test_pwrite_data[1][0]==1U );
  FD_TEST( test_pwrite_sz [2]==3UL && test_pwrite_off[2]==12UL && test_pwrite_data[2][0]==3U );
  FD_TEST( ctx->metrics.disk_bytes_written==sizeof(data) );
}

static void
test_writer_disk_error_fatal( void ) {
  uchar data[ 1UL ] = {1};
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 1UL, FD_SNAPSHOT_STATE_IDLE );

  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_stderr_set( 6 );
    test_io_reset();
    test_pwrite_push( -1L, EIO );
    writer_pwrite( ctx, data, sizeof(data), 0UL );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  FD_TEST( WEXITSTATUS( status )==1 );
}

static int
test_writer_append( fd_snapin_tile_t * ctx,
                    uchar const *      pubkey,
                    uchar const *      owner,
                    uchar const *      data,
                    ulong              slot,
                    ulong              lamports,
                    ulong              data_len,
                    int                executable ) {
  return writer_append_account( ctx, pubkey, owner, data, slot, lamports, data_len, executable );
}

static void
test_writer_flush( void ) {
  uchar pubkey[ 32UL ] = {1};
  uchar owner [ 32UL ] = {2};
  uchar data  [ 3UL ] = {3, 4, 5};

  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 1UL, FD_SNAPSHOT_STATE_IDLE );
  test_io_reset();

  FD_TEST( !test_writer_append( ctx, pubkey, owner, data, 42UL, 7UL, sizeof(data), 1 ) );
  FD_TEST( ctx->writer.batch.cnt==1UL );
  FD_TEST( !ctx->metrics.accounts_loaded );
  FD_TEST( ctx->metrics.total_accounts_processed==1UL );
  FD_TEST( !writer_flush( ctx ) );

  ulong entry_sz = sizeof(fd_accdb_disk_meta_t)+sizeof(data);
  FD_TEST( test_pwrite_call_cnt==1UL );
  FD_TEST( test_pwrite_off[ 0 ]==0UL && test_pwrite_sz[ 0 ]==test_padded_sz( entry_sz ) );
  FD_TEST( test_file_off==test_padded_sz( entry_sz ) );
  FD_TEST( !ctx->writer.buf_used && !ctx->writer.batch.cnt );
  FD_TEST( ctx->metrics.accounts_loaded==1UL );
  FD_TEST( ctx->metrics.disk_bytes_written==test_padded_sz( entry_sz ) );
  FD_TEST( ctx->shmem->values[ ctx->tile_idx ].loaded==1UL );
  FD_TEST( ctx->shmem->values[ ctx->tile_idx ].input_lamports==7UL );
}

static void
test_writer_full_buffer_flush( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 1UL, FD_SNAPSHOT_STATE_IDLE );
  test_io_reset();

  ulong data_len = (FD_SNAPIN_WRITE_BUF_MAX-2UL)/2UL-sizeof(fd_accdb_disk_meta_t);
  uchar * data = aligned_alloc( 64UL, fd_ulong_align_up( data_len, 64UL ) );
  FD_TEST( data );
  fd_memset( data, 7, data_len );

  uchar pubkey[ 32UL ] = {1};
  uchar owner [ 32UL ] = {2};

  FD_TEST( !test_writer_append( ctx, pubkey, owner, data, 42UL, 3UL, data_len, 0 ) );
  pubkey[ 0 ] = 4U;
  FD_TEST( !test_writer_append( ctx, pubkey, owner, data, 42UL, 3UL, data_len, 0 ) );
  FD_TEST( ctx->writer.buf_used==FD_SNAPIN_WRITE_BUF_MAX-2UL );

  pubkey[ 0 ] = 5U;
  FD_TEST( !test_writer_append( ctx, pubkey, owner, data, 42UL, 3UL, 1UL, 0 ) );
  FD_TEST( test_pwrite_call_cnt==1UL );
  FD_TEST( test_pwrite_sz[ 0 ]==FD_SNAPIN_WRITE_BUF_SZ ); /* BUF_MAX-2 padded to the full buffer */
  FD_TEST( ctx->writer.buf_used==sizeof(fd_accdb_disk_meta_t)+1UL );

  FD_TEST( !writer_flush( ctx ) );
  FD_TEST( test_pwrite_call_cnt==2UL );
  FD_TEST( test_pwrite_off[ 1 ]==FD_SNAPIN_WRITE_BUF_SZ );
  FD_TEST( test_pwrite_sz [ 1 ]==test_padded_sz( sizeof(fd_accdb_disk_meta_t)+1UL ) );
  FD_TEST( test_file_off==FD_SNAPIN_WRITE_BUF_SZ+test_padded_sz( sizeof(fd_accdb_disk_meta_t)+1UL ) );
  free( data );
}

static void
test_max_account_staging( void ) {
  fd_snapin_tile_t * ctx = test_ctx;
  sync_ctx_init( ctx, 1UL, FD_SNAPSHOT_STATE_IDLE );
  test_counters_reset();
  test_io_reset();

  uchar pubkey[ 32UL ] = {4};
  uchar owner [ 32UL ] = {5};
  fd_ssparse_advance_result_t result = {
    .account_header = {
      .slot       = 42UL,
      .data_len   = FD_RUNTIME_ACC_SZ_MAX,
      .pubkey     = pubkey,
      .lamports   = 7UL,
      .owner      = owner,
      .executable = 0
    }
  };
  FD_TEST( !process_account_header( ctx, &result ) );
  FD_TEST( ctx->staged.bytes_received<ctx->staged.data_len );

  uchar data[ FD_SNAPSHOT_DATA_MTU ];
  ulong expected_sum = 0UL;
  ulong expected_mix = 0UL;
  for( ulong off=0UL; off<FD_RUNTIME_ACC_SZ_MAX; ) {
    ulong data_sz = fd_ulong_min( sizeof(data), FD_RUNTIME_ACC_SZ_MAX-off );
    for( ulong i=0UL; i<data_sz; i++ ) {
      data[ i ] = (uchar)( (off+i)*131UL+17UL );
      expected_sum += (ulong)data[ i ];
      expected_mix += (off+i+1UL)*(ulong)data[ i ];
    }
    result.account_data.data    = data;
    result.account_data.data_sz = data_sz;
    FD_TEST( !process_account_data( ctx, &result ) );
    off += data_sz;
  }

  FD_TEST( ctx->staged.bytes_received==ctx->staged.data_len );
  FD_TEST( ctx->writer.buf_used==sizeof(fd_accdb_disk_meta_t)+FD_RUNTIME_ACC_SZ_MAX );
  fd_accdb_disk_meta_t meta;
  fd_memcpy( meta.b, ctx->writer.buf, sizeof(meta) );
  FD_TEST( meta.size==FD_RUNTIME_ACC_SZ_MAX );
  ulong actual_sum = 0UL;
  ulong actual_mix = 0UL;
  for( ulong i=0UL; i<FD_RUNTIME_ACC_SZ_MAX; i++ ) {
    actual_sum += (ulong)ctx->writer.buf[ sizeof(meta)+i ];
    actual_mix += (i+1UL)*(ulong)ctx->writer.buf[ sizeof(meta)+i ];
  }
  FD_TEST( actual_sum==expected_sum );
  FD_TEST( actual_mix==expected_mix );

  FD_TEST( !ctx->metrics.accounts_loaded );
  FD_TEST( !writer_flush( ctx ) );
  FD_TEST( ctx->metrics.accounts_loaded==1UL );
  FD_TEST( test_pwrite_call_cnt==1UL );
  FD_TEST( test_pwrite_sz[ 0 ]==test_padded_sz( sizeof(fd_accdb_disk_meta_t)+FD_RUNTIME_ACC_SZ_MAX ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_ctx = aligned_alloc( alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  FD_TEST( test_ctx );

  test_writer_short_write_and_eintr();
  test_writer_disk_error_fatal();
  test_writer_flush();
  test_writer_full_buffer_flush();
  test_max_account_staging();
  test_scratch_layout_fits();

  /* The end-to-end populate test holds a full-size txncache (~1.3 GiB)
     and the staged transaction entries (~0.55 GiB) at once. */
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 3UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_control_barriers();
  test_all_control_barriers_and_final_payload();
  test_fast_lane_control_pipeline();
  test_pending_control_allows_lagging_data();
  test_pending_control_keeps_frame_order();
  test_error_interrupts_incremental_init();
  test_partial_fail_survives_error();
  test_fail_supersedes_pending_controls();
  test_initialized_incremental_fail_rolls_back();
  test_error_fail_and_retry();
  test_frame_ordering();
  test_frame_owner_and_raw_lane();
  test_partial_and_zero_byte_eom();
  test_malformed_stream_endings();
  test_init_resets_lane_state();
  test_nonempty_raw_data();
  fd_wksp_reset( wksp, 1UL ); test_batch_stake_delegation( wksp );
  fd_wksp_reset( wksp, 1UL ); test_streaming_stake_delegation( wksp );
  fd_wksp_reset( wksp, 1UL ); test_snoop_outcomes( wksp );
  fd_wksp_reset( wksp, 1UL ); test_snoop_incremental_fork( wksp );
  test_txncache_staging_entry_size();
  test_txncache_staging_group_record_size();
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_groups_fit_txncache_scratch( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_evicts_oldest_slot( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_evicted_slot_drops_groups( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_rejects_group_overflow( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_rejects_entry_overflow( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_rejects_oversized_slot_delta( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_filters_recent_groups( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_rejects_recent_group_overflow( wksp );
  test_txncache_staging_fits_one_gigantic_page();
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_runtime_limits( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_rejects_conflicting_group_offsets( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_ignores_evicted_group_offsets( wksp );
  fd_wksp_reset( wksp, 1UL ); test_txncache_staging_populate_inserts_recent_only( wksp );
  fd_wksp_reset( wksp, 1UL ); test_populate_txncache_slot_attribution( wksp );
  fd_wksp_reset( wksp, 1UL ); test_populate_txncache_rejects_invalid_blockhash_age( wksp );
  fd_wksp_reset( wksp, 1UL ); test_populate_txncache_requires_snapshot_slot_delta( wksp );
  fd_wksp_reset( wksp, 1UL ); test_populate_txncache_accepts_empty_rooted_status_cache( wksp );

  fd_wksp_delete_anonymous( wksp );

  test_eager_claim_coverage();
  test_retry_resets();
  test_accumulator_fold();
  test_gauge_sum_continuity();
  test_full_lifecycle_9_tiles();
  test_verify_sysvars_accepts_valid();
  test_verify_sysvars_presence();
  test_verify_sysvars_rejects_bad_owner();
  test_verify_sysvars_rejects_undecodable();
  test_verify_sysvars_rent_bounds();
  test_verify_sysvars_epoch_rewards();
  test_verify_sysvars_gates_controls();

  free( test_ctx );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
