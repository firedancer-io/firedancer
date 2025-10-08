#include "../../disco/store/fd_store.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../util/pod/fd_pod.h"

/* This tile looks awfully similar to backtest, maybe we could roll it
   into backtest and have an extra option to equivocate. */


#define SHRED_BUFFER_LEN (1048576UL)
#define BANK_HASH_BUFFER_LEN (4096UL)

#define IN_KIND_REPLAY (0)
#define IN_KIND_GENESI (2)
#define IN_KIND_REPAIR (3)

struct fd_eqvoct_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_eqvoct_in fd_eqvoct_in_t;

struct fd_eqvoct_out {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_eqvoct_out fd_eqvoct_out_t;

struct fd_eqvoct_tile {
  int initialized;

  uint slot_idx;

  fd_store_t * store;

  int in_kind[ 16UL ];
  fd_eqvoct_in_t in[ 16UL ];

  fd_eqvoct_out_t replay_out[ 1 ];

  ulong shreds_idx;
  ulong shreds_cnt;
  uchar shreds[ SHRED_BUFFER_LEN ][ FD_SHRED_MAX_SZ ];

  ulong bank_hash_idx;
  ulong bank_hash_cnt;
  uchar bank_hashes[ BANK_HASH_BUFFER_LEN ][ 32UL ];
};

typedef struct fd_eqvoct_tile fd_eqvoct_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_eqvoct_tile_t),    sizeof(fd_eqvoct_tile_t)         );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

#define SLOTS 5
static fd_replay_slot_completed_t slot_replayed[SLOTS] = {
  {
    .slot = 1, /* contains votes for slot 0 */
    .parent_slot = 0,
    .block_id        = { .ul[0] = 1 },
    .parent_block_id = {  .ul = { 0xf17eda2ce7b1d } },
    .bank_hash       = { .ul[0] = 1 },
    .block_hash      = { .ul[0] = 1 },
  },
  {
    .slot = 2, /* contains votes for slot 1 */
    .parent_slot = 1,
    .block_id        = { .ul[0] = 2, .ul[1] = 0 },
    .parent_block_id = { .ul[0] = 1 },
    .bank_hash       = { .ul[0] = 2, .ul[1] = 5 },
    .block_hash      = { .ul[0] = 2 },
  },
  {
    .slot = 2, /* contains votes for slot 1 (dup confirmed) */
    .parent_slot = 1,
    .block_id        = { .ul[0] = 2, .ul[1] = 1 },
    .parent_block_id = { .ul[0] = 1 },
    .bank_hash       = { .ul[0] = 2, .ul[1] = 1 },
    .block_hash      = { .ul[0] = 2 },
  },
  {
    .slot = 3, /* contains votes for slot 2, .ul[1] = 1 */
    .parent_slot = 2,
    .block_id        = { .ul[0] = 3 },
    .parent_block_id = { .ul[0] = 2, .ul[1] = 0 },
    .bank_hash       = { .ul[0] = 3 },
    .block_hash      = { .ul[0] = 3 },
  },
  {
    .slot = 4, /* contains votes for slot 3 */
    .parent_slot = 2,
    .block_id        = { .ul[0] = 4 },
    .parent_block_id = { .ul[0] = 2, .ul[1] = 1 },
    .bank_hash       = { .ul[0] = 4 },
    .block_hash      = { .ul[0] = 4 },
  }
};

#define VOTERS 4
static fd_replay_tower_t vote_accs[VOTERS];

struct vote_sequence {
  ulong slot;
  ulong votes[VOTERS];
};
typedef struct vote_sequence vote_sequence_t;

static vote_sequence_t vote_sequences[SLOTS] = {

  /*  1
     / \
    2   2'
    |   |
    3   4
  */
          /* voter_index: 0, 1, 2, 3 */
  { .slot = 1, .votes = { 1, 1, 1, 1 } }, /* everyone votes in slot 1 */
  { .slot = 2, .votes = { 0, 1, 1, 1 } }, /* everyone but v0 votes in slot 2*/
  { .slot = 2, .votes = { 1, 0, 0, 1 } }, /* v0 votes for slot 2', v4 double votes for 2' */
  { .slot = 3, .votes = { 0, 1, 1, 1 } }, /* everyone votes in slot 3 */
  { .slot = 4, .votes = { 1, 0, 0, 0 } }, /* everyone votes in slot 3, except v3 */
};

static void setup_voters( void ) {
  memset( vote_accs, 0, sizeof(vote_accs) );
  vote_accs[0] = (fd_replay_tower_t){ .key = { .uc[0] = 'A' }, .stake = 52 };
  vote_accs[1] = (fd_replay_tower_t){ .key = { .uc[0] = 'B' }, .stake = 33 };
  vote_accs[2] = (fd_replay_tower_t){ .key = { .uc[0] = 'C' }, .stake = 10 };
  vote_accs[3] = (fd_replay_tower_t){ .key = { .uc[0] = 'D' }, .stake = 5 };
}

static void
update_vote_account( uchar * data, ulong slot ) {
  /* idempotent */

  fd_voter_state_t * state = (fd_voter_state_t *)fd_type_pun( data );
  state->kind = FD_VOTER_STATE_CURRENT;
  state->votes[state->cnt].slot = slot;
  state->votes[state->cnt].conf = 1;

  for( ulong i = state->cnt; i > 0; i-- ) {
    state->votes[i - 1].conf++;
  }
  state->cnt++;
}

static void
after_credit( fd_eqvoct_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  (void)charge_busy;
  if( FD_UNLIKELY( !ctx->initialized ) ) return;

  if( ctx->slot_idx >= sizeof(slot_replayed)/sizeof(slot_replayed[0]) ) return;

  FD_LOG_NOTICE(( "[%s] sending slot completed %lu (%s)", __func__, slot_replayed[ ctx->slot_idx ].slot, FD_BASE58_ENC_32_ALLOCA( &slot_replayed[ ctx->slot_idx ].block_id ) ));
  uchar * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  fd_memcpy( msg, &slot_replayed[ ctx->slot_idx ], sizeof(fd_replay_slot_completed_t) );

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_SLOT_COMPLETED, ctx->replay_out->chunk, sizeof(fd_replay_slot_completed_t) , 0, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_slot_completed_t) , ctx->replay_out->chunk0, ctx->replay_out->wmark );

  /* pretend update vote accounts */

  /* find last voter for this slot */
  ulong last_voter = 0;
  for( ulong i = 0; i < VOTERS; i++ ) {
    if( vote_sequences[ctx->slot_idx].votes[i] == 0 ) continue;
    last_voter = i;
  }

  for( ulong i = 0; i < VOTERS; i++ ) {
    vote_sequence_t * voter_seq = &vote_sequences[ctx->slot_idx];
    if( voter_seq->votes[i] == 0 ) continue;
    update_vote_account( vote_accs[i].acc, slot_replayed[ ctx->slot_idx ].slot - 1 );

    int som = i==0;
    int eom = i==last_voter;
    fd_replay_tower_t * vote_state = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
    *vote_state = vote_accs[i];
    fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_VOTE_STATE, ctx->replay_out->chunk, sizeof(fd_replay_tower_t), fd_frag_meta_ctl( 0UL, som, eom, 0 ), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_tower_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
  }
  ctx->slot_idx++;
}

static inline int
returnable_frag( fd_eqvoct_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq;
  (void)sz;
  (void)ctl;
  (void)tsorig;
  (void)tspub;
  (void)stem;
  (void)sig;
  (void)chunk;

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_GENESI: {
      ctx->initialized = 1;
      FD_LOG_NOTICE(( "[%s] initialized", __func__ ));
      break;
    }
    default: FD_LOG_ERR(( "unhandled in_kind: %d in_idx: %lu", ctx->in_kind[ in_idx ], in_idx ));
  }

  return 0;
}

static inline fd_eqvoct_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had no output link named %s", tile->name, tile->kind_id, name ));

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_eqvoct_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_eqvoct_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoct_tile_t),    sizeof(fd_eqvoct_tile_t) );

  ctx->initialized = 0;

  ctx->shreds_idx = 0UL;
  ctx->shreds_cnt = 0UL;

  ctx->bank_hash_cnt = 0UL;
  ctx->bank_hash_idx = 0UL;

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]) );
  for( uint i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if(      !strcmp( link->name, "replay_out" ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( !strcmp( link->name, "genesi_out" ) ) ctx->in_kind[ i ] = IN_KIND_GENESI;
    else if( !strcmp( link->name, "repair_net" ) ) ctx->in_kind[ i ] = IN_KIND_REPAIR;
    else FD_LOG_ERR(( "eqvoctest tile has unexpected input link %s", link->name ));
  }

  *ctx->replay_out = out1( topo, tile, "replay_out" );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  setup_voters();
  ctx->slot_idx = 0;
}

#define STEM_BURST                  (6UL) /* 1 after_credit + 1 returnable_frag */
#define STEM_CALLBACK_CONTEXT_TYPE  fd_eqvoct_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_eqvoct_tile_t)

#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_eqvoctest = {
  .name                     = "eqvoct",
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
