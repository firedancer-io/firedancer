#include "fd_solfuzz_private.h"
#include "generated/shred.pb.h"

#include "../../../ballet/shred/fd_shred.h"
#include "../../../disco/shred/fd_fec_resolver.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../discof/reasm/fd_reasm.h"
#include "../../../discof/replay/fd_sched.h"

/* Resolver sizing.  Production sizing lives in the shred tile setup;
   the values below are much smaller because the harness consumes
   results synchronously, so partial/complete queue depth has no
   consumer-lag to absorb.  See fd_fec_resolver.h for the precise
   semantics of each depth parameter:
     - DEPTH:          max in-flight FEC sets before spill
     - PARTIAL_DEPTH:  out_shred pointer-lifetime guarantee
     - COMPLETE_DEPTH: out_fec_set pointer-lifetime guarantee
     - DONE_DEPTH:     memory of completed (slot, fec_set_idx)
                       pairs used for duplicate detection */
static ulong const RESOLVER_DEPTH          = 32UL;
static ulong const RESOLVER_PARTIAL_DEPTH  = 8UL;
static ulong const RESOLVER_COMPLETE_DEPTH = 8UL;
static ulong const RESOLVER_DONE_DEPTH     = 256UL;

/* Reasm + scheduler sizing.  Only loosely tied to the resolver depths
   above: large enough to cover any reasonable fuzz input while keeping
   spad footprint bounded. */
static ulong const REASM_POOL_MAX       = 1024UL;

/* Scheduler txn/block pool sizes, bounded to the fuzz input so
   fd_sched_new's per-run free-list init stays cheap. */
static ulong const SCHED_DEPTH          = 4096UL;
static ulong const SCHED_BLOCK_CNT_MAX  = 128UL;
static ulong const SCHED_EXEC_CNT       = 4UL;

/* Tick-verification parameters passed to fd_sched_block_verify_ticks.
   ticks_per_slot=64 (tick_height 0, max_tick_height 64) and
   hashes_per_tick=62500 to match mainnet and solfuzz-agave's reference
   bank. */
static ulong const SLOT_MAX_TICK_HEIGHT = 64UL;
static ulong const SLOT_HASHES_PER_TICK = 62500UL;

typedef struct {
  fd_hash_t mr;
  fd_hash_t cmr;
  ulong     slot;
  uint      fec_set_idx;
  ushort    parent_off;
  ushort    num_data_shreds;
  ushort    num_coding_shreds;
  uint      shred_cnt;
  uint      shred_offs[ FD_FEC_SHRED_CNT ];
  int       data_complete;
  int       slot_complete;
  ulong     payload_sz;
  uchar *   payload;
} fd_shred_completed_fec_t;

#define SORT_NAME                sort_completed_fec
#define SORT_KEY_T               fd_shred_completed_fec_t
#define SORT_BEFORE(a,b)         ( (a).slot<(b).slot || ( (a).slot==(b).slot && (a).fec_set_idx<(b).fec_set_idx ) )
#define SORT_QUICK_SWAP_MINIMIZE 1 /* ~240B key; skip no-op swaps */
#include "../../../util/tmpl/fd_sort.c"

/* Return reasm's evicted single-child chain to the pool. */
static void
release_evicted_chain( fd_reasm_t *     reasm,
                       fd_reasm_fec_t * evicted ) {
  while( evicted ) {
    fd_reasm_fec_t * next = fd_reasm_child( reasm, evicted );
    fd_reasm_pool_release( reasm, evicted );
    evicted = next;
  }
}

/* This is a harness simplification that avoids having to use store.
   Also includes logic from the shred tile to concatenate FEC set
   payloads into a contiguous buffer. */
static void
capture_completed_fec( fd_spad_t *                spad,
                       fd_fec_set_t const *       set,
                       fd_shred_completed_fec_t * out ) {
  fd_memset( out, 0, sizeof(fd_shred_completed_fec_t) );

  fd_shred_t const * base_data   = fd_shred_parse( set->data_shreds  [ 0 ].b, FD_SHRED_MIN_SZ, FD_SHRED_BLK_MAX );
  fd_shred_t const * base_parity = fd_shred_parse( set->parity_shreds[ 0 ].b, FD_SHRED_MAX_SZ, FD_SHRED_BLK_MAX );
  FD_TEST( base_data && base_parity );

  ushort data_cnt = base_parity->code.data_cnt;
  ushort code_cnt = base_parity->code.code_cnt;

  /* Concatenate data-shred payloads into a single buffer. */
  uchar * payload    = fd_spad_alloc( spad, alignof(uchar), (ulong)data_cnt*FD_SHRED_MAX_SZ );
  ulong   payload_sz = 0UL;
  for( ushort i=0U; i<data_cnt; i++ ) {
    fd_shred_t const * shred = fd_shred_parse( set->data_shreds[ i ].b, FD_SHRED_MIN_SZ, FD_SHRED_BLK_MAX );
    FD_TEST( shred );
    ulong shred_payload_sz = fd_shred_payload_sz( shred );
    if( FD_LIKELY( shred_payload_sz ) ) {
      memcpy( payload + payload_sz, fd_shred_data_payload( shred ), shred_payload_sz );
      payload_sz += shred_payload_sz;
    }
    out->shred_offs[ i ] = (uint)payload_sz;
  }

  fd_shred_t const * last = fd_shred_parse( set->data_shreds[ data_cnt-1U ].b, FD_SHRED_MIN_SZ, FD_SHRED_BLK_MAX );
  FD_TEST( last );

  /* Derive the FEC set's merkle root from a shred's inclusion proof. */
  uchar bmtree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( FD_SHRED_MERKLE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t root[1];
  FD_TEST( fd_shred_merkle_root( base_data, bmtree_mem, root ) );
  memcpy( out->mr.hash, root->hash, sizeof(out->mr.hash) );
  out->slot              = base_data->slot;
  out->fec_set_idx       = base_data->fec_set_idx;
  out->parent_off        = base_data->data.parent_off;
  out->num_data_shreds   = data_cnt;
  out->num_coding_shreds = code_cnt;
  out->shred_cnt         = data_cnt;
  out->data_complete     = !!(last->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE);
  out->slot_complete     = !!(last->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
  out->payload_sz        = payload_sz;
  out->payload           = payload;

  /* Shreds are always chained, so the chained root is present. */
  memcpy( out->cmr.hash, (uchar const *)base_data + fd_shred_chain_off( base_data->variant ), FD_SHRED_MERKLE_ROOT_SZ );
}

ulong
fd_solfuzz_pb_shred_run( fd_solfuzz_runner_t * runner,
                         void const *          input_,
                         void **               output_,
                         void *                output_buf,
                         ulong                 output_bufsz ) {
  fd_exec_test_shred_parse_context_t const * input = fd_type_pun_const( input_ );
  fd_exec_test_shred_parse_effects_t **      output = fd_type_pun( output_ );

  /* Initialize output protobuf in the caller-provided buffer.  The
     fixed-size header allocations (effects struct, per-shred result
     array, per-FEC result array) must always fit; the caller is
     responsible for sizing output_buf, and a fit-check failure here
     is a harness wiring bug.  Variable-size payload writes inside the
     pop loop are checked separately and treated as soft failures. */
  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_shred_parse_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_shred_parse_effects_t), sizeof(fd_exec_test_shred_parse_effects_t) );
  FD_TEST( _l <= output_end );
  fd_memset( effects, 0, sizeof(*effects) );
  effects->block_parse_result = FD_EXEC_TEST_BLOCK_PARSE_RESULT_ACCEPTED;

  ulong shred_cnt = (ulong)input->shreds_count;
  effects->shred_results_count = (pb_size_t)shred_cnt;
  effects->shred_results =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(bool), sizeof(bool)*shred_cnt );
  FD_TEST( _l <= output_end );
  fd_memset( effects->shred_results, 0, sizeof(bool)*shred_cnt );

  ulong max_fec_results = shred_cnt;
  effects->fec_set_results =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_fec_set_parse_result_t), sizeof(fd_exec_test_fec_set_parse_result_t)*max_fec_results );
  FD_TEST( _l <= output_end );
  fd_memset( effects->fec_set_results, 0, sizeof(fd_exec_test_fec_set_parse_result_t)*max_fec_results );
  effects->fec_set_results_count = 0U;

  /* The resolver/sched bump FD_MCNT counters (e.g. reject paths) via a
     per-thread pointer that is NULL outside a tile.  Register a dummy
     write-sink to avoid a NULL deref; the values are never read. */
  static FD_TL uchar harness_metrics[ FD_METRICS_FOOTPRINT( 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
  fd_metrics_register( (ulong *)fd_metrics_new( harness_metrics, 0UL ) );

  /* Build a resolver configured for the fixture's shred version/root
     context. */
  ulong const resolver_set_cnt = RESOLVER_DEPTH + RESOLVER_PARTIAL_DEPTH + RESOLVER_COMPLETE_DEPTH;

  fd_fec_set_t * resolver_sets =
      fd_spad_alloc( runner->spad, alignof(fd_fec_set_t), sizeof(fd_fec_set_t)*resolver_set_cnt );

  ulong  resolver_footprint = fd_fec_resolver_footprint( RESOLVER_DEPTH,
                                                         RESOLVER_PARTIAL_DEPTH,
                                                         RESOLVER_COMPLETE_DEPTH,
                                                         RESOLVER_DONE_DEPTH );
  void * resolver_mem       = fd_spad_alloc( runner->spad, fd_fec_resolver_align(), resolver_footprint );

  /* Resolver/reasm/sched construction parameters are all compile-time
     constants or sourced from the trusted runner spad -- a NULL return
     from any of these constructors is a harness setup bug. */
  fd_fec_resolver_t * resolver = fd_fec_resolver_join( fd_fec_resolver_new(
      resolver_mem,
      NULL, NULL,
      RESOLVER_DEPTH,
      RESOLVER_PARTIAL_DEPTH,
      RESOLVER_COMPLETE_DEPTH,
      RESOLVER_DONE_DEPTH,
      resolver_sets,
      0UL ) );
  FD_TEST( resolver );

  /* Configure resolver behavior for the fuzz run:
       - bypass Merkle proof + Ed25519 signature checks
         (see fd_fec_resolver_set_bypass_verify in fd_fec_resolver.h)
       - drop shreds for slots strictly older than root_slot
       - map the proto bool for the discard-unexpected-DATA_COMPLETE
         feature onto the activation_slot extremes (0 = active for
         every slot, ULONG_MAX = never active) */
  fd_fec_resolver_set_shred_version( resolver, (ushort)input->shred_version );
  fd_fec_resolver_set_bypass_verify( resolver, 1 );
  fd_fec_resolver_advance_slot_old ( resolver, input->root_slot );
  fd_fec_resolver_set_discard_unexpected_data_complete_shreds( resolver,
      input->features.discard_unexpected_data_complete_shreds ? 0UL : ULONG_MAX );

  /* Initialize reasm/sched so completed FEC sets can be
     replay-ingested in order. */
  void * reasm_mem = fd_spad_alloc( runner->spad, fd_reasm_align(), fd_reasm_footprint( REASM_POOL_MAX ) );
  fd_reasm_t * reasm = fd_reasm_join( fd_reasm_new( reasm_mem, REASM_POOL_MAX, 0UL ) );
  FD_TEST( reasm );
  int reasm_initialized = 0;

  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 0UL ) );
  void * sched_mem = fd_spad_alloc( runner->spad, fd_sched_align(), fd_sched_footprint( SCHED_DEPTH, SCHED_BLOCK_CNT_MAX ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( sched_mem, rng, SCHED_DEPTH, SCHED_BLOCK_CNT_MAX, SCHED_EXEC_CNT ) );
  FD_TEST( sched );
  fd_sched_set_bypass_poh_verify( sched, 1 ); /* skip PoH end_hash compare */
  fd_sched_set_bypass_alut_resolution( sched, 1 ); /* skip ALUT resolution (no accdb) */
  fd_sched_block_add_done( sched, 0UL, ULONG_MAX, input->root_slot );
  fd_sched_root_notify( sched, 0UL );
  fd_sched_advance_root( sched, 0UL );

  /* completed[] caches FEC payloads for sched ingestion.  This is a
     simplified version of store specifically for the harness.  Instead
     of querying store for FEC set data, we just store it in this
     local array. */
  fd_shred_completed_fec_t * completed =
    fd_spad_alloc( runner->spad, alignof(fd_shred_completed_fec_t), sizeof(fd_shred_completed_fec_t)*max_fec_results );
  ulong completed_cnt = 0UL;
  ulong next_bank_idx = 1UL; /* 0 is the reasm/sched root, so start at 1 */

  /* Parse each shred, feed resolver, and only continue when an FEC
     completes. */
  fd_pubkey_t dummy_leader_pubkey = {0};
  for( ulong i=0UL; i<shred_cnt; i++ ) {
    pb_bytes_array_t const * shred_msg = input->shreds[ i ];
    FD_TEST( shred_msg );
    FD_TEST( shred_msg->size>=FD_SHRED_MIN_SZ && shred_msg->size<=FD_SHRED_MAX_SZ );

    /* Step 1: fd_shred_parse() */
    fd_shred_t const * shred = fd_shred_parse( shred_msg->bytes, shred_msg->size, FD_SHRED_BLK_MAX );

    /* Unchained merkle shreds are dropped in the shred tile. */
    if( !shred || !fd_shred_is_chained( fd_shred_type( shred->variant ) ) ) {
      effects->shred_results[ i ] = false;
      continue;
    }

    /* Parse-level accept, matching Agave; the resolver verdict below is not folded in. */
    effects->shred_results[ i ] = true;

    /* Step 2: fd_fec_resolver_add_shred() */
    fd_fec_set_t const * out_fec_set = NULL;
    fd_shred_t const *   out_shred   = NULL;
    fd_bmtree_node_t     out_merkle_root[1];
    int rc = fd_fec_resolver_add_shred(
      resolver,
      shred,
      shred_msg->size,
      FD_SHRED_BLK_MAX,
      0,
      dummy_leader_pubkey.uc,
      &out_fec_set,
      &out_shred,
      out_merkle_root,
      NULL
    );
    (void)out_shred;

    /* We only want to replay the FEC set once it's complete. */
    if( rc!=FD_FEC_RESOLVER_SHRED_COMPLETES ) continue;

    /* completed[] is sized to shred_cnt, which is a strict upper bound
       on completion count, so overflow here is a harness sizing bug. */
    FD_TEST( completed_cnt<max_fec_results );

    /* Construct the completed FEC set record.  The merkle root is derived
       from the shred's inclusion proof inside capture_completed_fec. */
    fd_shred_completed_fec_t * rec = &completed[ completed_cnt ];
    capture_completed_fec( runner->spad, out_fec_set, rec );

    /* Buffer the completion; reasm runs after the shred loop in
       (slot, fec_set_idx) order. */
    completed_cnt++;
  }

  /* Sort by (slot, fec_set_idx) so set 0 anchors the reasm root
     before any successor inserts. */
  sort_completed_fec_inplace( completed, completed_cnt );

  for( ulong k=0UL; k<completed_cnt; k++ ) {
    fd_shred_completed_fec_t * rec = &completed[ k ];

    /* Lazily init reasm off the first (lowest slot/fec_set_idx) FEC to set the root block id. */
    if( FD_UNLIKELY( !reasm_initialized ) ) {
      fd_reasm_fec_t * root = fd_reasm_init( reasm, &rec->cmr, input->root_slot );
      if( FD_UNLIKELY( !root ) ) {
        effects->block_parse_result = FD_EXEC_TEST_BLOCK_PARSE_RESULT_REJECTED_INVALID_HEADER;
        continue;
      }
      root->bank_idx    = 0UL;
      reasm_initialized = 1;
    }

    /* Step 3: fd_reasm_insert()
       Insert completed FEC into reasm and release elements from evicted
       chains. */
    fd_reasm_fec_t * evicted = NULL;
    if( !fd_reasm_insert( reasm,
                          &rec->mr,
                          &rec->cmr,
                          rec->slot,
                          rec->fec_set_idx,
                          rec->parent_off,
                          rec->num_data_shreds,
                          rec->data_complete,
                          rec->slot_complete,
                          0,
                          NULL,
                          &evicted ) ) {
      release_evicted_chain( reasm, evicted );
      effects->block_parse_result = FD_EXEC_TEST_BLOCK_PARSE_RESULT_REJECTED_INVALID_HEADER;
      continue;
    }
    release_evicted_chain( reasm, evicted );

    /* Step 4: fd_reasm_pop() and fd_fec_set_ingest() while there are
       completed FEC sets remaining. */
    fd_reasm_fec_t * popped;
    while( FD_LIKELY( (popped = fd_reasm_pop( reasm )) ) ) {
      /* Query our "store"-adjacent structure (completed) for the FEC
         set payload */
      fd_shred_completed_fec_t * popped_rec = NULL;
      for( ulong j=0UL; j<completed_cnt; j++ ) {
        if( FD_LIKELY( !memcmp( completed[ j ].mr.hash, popped->key.hash, sizeof(fd_hash_t) ) ) ) {
          popped_rec = &completed[ j ];
          break;
        }
      }
      FD_TEST( popped_rec );
      FD_TEST( effects->fec_set_results_count<max_fec_results );

      /* Capture completed FEC set results */
      fd_exec_test_fec_set_parse_result_t * out_fec = &effects->fec_set_results[ effects->fec_set_results_count++ ];
      fd_memset( out_fec, 0, sizeof(*out_fec) );
      out_fec->completed         = true;
      out_fec->slot              = popped_rec->slot;
      out_fec->fec_set_index     = popped_rec->fec_set_idx;
      out_fec->parent_offset     = popped_rec->parent_off;
      out_fec->shred_version     = input->shred_version;
      out_fec->num_data_shreds   = popped_rec->num_data_shreds;
      out_fec->num_coding_shreds = popped_rec->num_coding_shreds;
      memcpy( out_fec->merkle_root, popped_rec->mr.hash, FD_SHRED_MERKLE_ROOT_SZ );
      memcpy( out_fec->chained_merkle_root, popped_rec->cmr.hash, FD_SHRED_MERKLE_ROOT_SZ );
      if( FD_LIKELY( popped_rec->payload_sz ) ) {
        out_fec->payload = FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( popped_rec->payload_sz ) );
        if( FD_UNLIKELY( _l > output_end ) ) {
          effects->block_parse_result = FD_EXEC_TEST_BLOCK_PARSE_RESULT_REJECTED_INVALID_HEADER;
          effects->fec_set_results_count--;
          break;
        }
        out_fec->payload->size = (pb_size_t)popped_rec->payload_sz;
        memcpy( out_fec->payload->bytes, popped_rec->payload, popped_rec->payload_sz );
      }

      /* Match Agave's model of only parsing deshreddable batches.
         Otherwise, Firedancer's eager per-FEC parsing might reject a
         block for a bad FEC set that Agave simply doesn't parse at all.
         A FEC set is deshreddable iff some FEC set at or after it in
         the same slot carries DATA_COMPLETE.  Complete batches are
         still fed one FEC set at a time.  Only the final, potentially
         incomplete batch is held back.  fec_set_results were already
         captured above, independent of the scheduler, so withholding
         does not change them.  Agave likewise emits a fec_set_result
         for every complete FEC set, deshreddable or not. */
      int deshreddable = 0;
      for( ulong j=0UL; j<completed_cnt; j++ ) {
        if( completed[ j ].slot==popped_rec->slot && completed[ j ].fec_set_idx>=popped_rec->fec_set_idx && completed[ j ].data_complete ) {
          deshreddable = 1;
          break;
        }
      }
      if( !deshreddable ) continue;

      /* Bank lineage comes from the reasm tree, like the replay tile.
         Reasm pops parents before children, so the parent's bank_idx
         was already recorded by the time we read it here. */
      fd_reasm_fec_t * parent = fd_reasm_parent( reasm, popped );
      FD_TEST( parent );
      ulong parent_bank_idx = parent->bank_idx;

      /* If the FEC set starts a new slot (no bank yet), use a fresh
         bank index; otherwise reuse the parent's.  Record it on the
         node so this slot's later FECs inherit it. */
      ulong bank_idx = ( popped->fec_set_idx==0U ) ? next_bank_idx++ : parent_bank_idx;
      popped->bank_idx = bank_idx;

      fd_store_fec_t store_fec[1] = {0};
      store_fec->key.merkle_root = popped_rec->mr;
      store_fec->data_sz         = popped_rec->payload_sz;
      memcpy( store_fec->shred_offs, popped_rec->shred_offs, sizeof(store_fec->shred_offs) );

      fd_sched_fec_t sched_fec = {
        .bank_idx          = bank_idx,
        .parent_bank_idx   = parent_bank_idx,
        .slot              = popped_rec->slot,
        .parent_slot       = fd_ulong_if( popped_rec->slot>=popped_rec->parent_off, popped_rec->slot-popped_rec->parent_off, 0UL ),
        .fec               = store_fec,
        .data              = popped_rec->payload,
        .shred_cnt         = popped_rec->shred_cnt,
        .is_last_in_batch  = !!popped_rec->data_complete,
        .is_last_in_block  = !!popped_rec->slot_complete,
        .is_first_in_block = !!(popped_rec->fec_set_idx==0U)
      };

      /* Drain abandoned blocks; fd_sched_fec_ingest requires an empty
         ref_q.  The replay tile drains the same queue (to decrement bank
         refcounts); the harness has no banks, so it just discards. */
      while( fd_sched_pruned_block_next( sched )!=ULONG_MAX ) {}

      /* Final step: ingest the completed FEC set. */
      FD_TEST( fd_sched_fec_can_ingest( sched, &sched_fec ) );
      if( !fd_sched_fec_ingest( sched, &sched_fec ) ) {
        effects->block_parse_result = FD_EXEC_TEST_BLOCK_PARSE_RESULT_REJECTED_INVALID_HEADER;
      } else if( FD_LIKELY( bank_idx!=0UL ) ) {
        /* Harness stops at FEC ingest, so verify this slot's tick
           window here; skip bank_idx 0 (reasm/sched root).  Only
           complete batches reach this point, so this matches Agave's
           model of only verifying deshredded batches. */
        if( fd_sched_block_verify_ticks( sched, bank_idx, 0UL, SLOT_MAX_TICK_HEIGHT, SLOT_HASHES_PER_TICK ) ) {
          effects->block_parse_result = FD_EXEC_TEST_BLOCK_PARSE_RESULT_REJECTED_INVALID_HEADER;
        }
      }
    }
  }

  /* Finalize scratch allocation and return encoded effects span. */
  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  *output = effects;
  return actual_end - (ulong)output_buf;
}

