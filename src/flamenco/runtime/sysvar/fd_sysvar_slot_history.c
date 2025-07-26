#include "fd_sysvar_slot_history.h"
#include "fd_sysvar_cache.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_system_ids.h"

/* TODO: move into separate bitvec library */
#define BITS_PER_BLOCK 64

#define FD_SYSVAR_SLOT_HISTORY_BLOCK_CNT ( FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES / BITS_PER_BLOCK )

static ulong *
bitvec_blocks( fd_slot_history_global_t * history ) {
  FD_TEST( history->has_bits && history->bits_bitvec_len == FD_SYSVAR_SLOT_HISTORY_BLOCK_CNT );
  return (ulong *)( (uchar *)history + history->bits_bitvec_offset );
}

/* See bv::BitVec::set */

static void
bitvec_remove( fd_slot_history_global_t * history,
               ulong                      slot ) {
  FD_TEST( history->has_bits && slot < history->bits_len );
  ulong * blocks = bitvec_blocks( history );
  ulong   key    = slot / BITS_PER_BLOCK;
  ulong   idx    = slot % BITS_PER_BLOCK;
  blocks[ key ] &= ~( 1UL << idx );
}

static void
bitvec_insert( fd_slot_history_global_t * history,
               ulong                      slot ) {
  FD_TEST( history->has_bits && slot < history->bits_len );
  ulong * blocks = bitvec_blocks( history );
  ulong   key    = slot / BITS_PER_BLOCK;
  ulong   idx    = slot % BITS_PER_BLOCK;
  blocks[ key ] |= 1UL<<idx;
}

/* See solana_slot_history::SlotHistory::add
   https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L62 */

void
fd_sysvar_slot_history_add( fd_slot_history_global_t * history,
                            ulong                      slot ) {

  /* Sanity checks: This sysvar's dimensions are hardcoded */
  FD_TEST( history->has_bits &&
           history->bits_bitvec_len == FD_SYSVAR_SLOT_HISTORY_BLOCK_CNT &&
           history->bits_len        == FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES );

  /* https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L63 */
  if( slot > history->next_slot && slot - history->next_slot >= FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES ) {

    /* https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L64-L69 */
    fd_memset( bitvec_blocks( history ), 0, sizeof(ulong) * FD_SYSVAR_SLOT_HISTORY_BLOCK_CNT );

  } else {

    /* https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L71-L73
       Obviously, there's room for optimization here, see src/util/tmpl/fd_set_dynamic.c */
    for( ulong i=history->next_slot; i<slot; i++ ) {
      bitvec_remove( history, i % FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES );
    }

  }

  /* https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L75-L76 */
  bitvec_insert( history, slot % FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES );
  history->next_slot = slot + 1UL;

}

/* See solana_slot_history::SlotHistory::default
   https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L29 */

void
fd_sysvar_slot_history_init( fd_exec_slot_ctx_t * slot_ctx,
                             fd_spad_t *          runtime_spad ) {
  ulong   sz_max = 0UL;
  uchar * data   = fd_sysvar_cache_data_modify_prepare(
      slot_ctx, &fd_sysvar_slot_history_id, NULL, &sz_max );
  if( FD_UNLIKELY( !data ) ) FD_LOG_ERR(( "fd_sysvar_cache_data_modify_prepare(slot_history) failed" ));
  FD_TEST( sz_max >= FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );

  /* Construct a position-independent slot history object */
  ulong block_cnt = FD_SYSVAR_SLOT_HISTORY_BLOCK_CNT;
  ulong total_sz  = sizeof(fd_slot_history_global_t) + alignof(fd_slot_history_global_t) +
                    (sizeof(ulong) + alignof(ulong)) * block_cnt;

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

    uchar * mem = fd_spad_alloc_check( runtime_spad, alignof(fd_slot_history_global_t), total_sz );
    fd_slot_history_global_t * history = (fd_slot_history_global_t *)mem;
    ulong *                    blocks  = (ulong *)fd_ulong_align_up( (ulong)((uchar*)history + sizeof(fd_slot_history_global_t)), alignof(ulong) );

    history->next_slot          = fd_bank_slot_get( slot_ctx->bank ) + 1UL;
    history->bits_bitvec_offset = (ulong)((uchar*)blocks - (uchar*)history);
    history->bits_len           = FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES;
    history->bits_bitvec_len    = FD_SYSVAR_SLOT_HISTORY_BLOCK_CNT;
    history->has_bits           = 1;
    memset( blocks, 0, sizeof(ulong) * FD_SYSVAR_SLOT_HISTORY_BLOCK_CNT );

  } FD_SPAD_FRAME_END;
}

/* See solana_runtime::bank::Bank::update_slot_history
   https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2276 */

void
fd_sysvar_slot_history_update( fd_exec_slot_ctx_t * slot_ctx,
                               fd_spad_t *          runtime_spad ) {
  /* Create an empty sysvar account if it doesn't exist
     https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2281 */

  fd_sysvar_cache_t * sysvar_cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  if( FD_UNLIKELY( !fd_sysvar_slot_history_is_valid( sysvar_cache ) ) ) {
    fd_sysvar_slot_history_init( slot_ctx, runtime_spad );
  }

  /* Update an existing sysvar account, but abort if deserialization of
     that existing account failed.
     https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2280 */

  fd_slot_history_global_t * history = fd_sysvar_slot_history_join( slot_ctx );
  if( FD_UNLIKELY( !history ) ) FD_LOG_ERR(( "Slot history sysvar is invalid, cannot update" ));

  /* Advance to current slot, set this slot's bit.
     https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2282 */

  fd_sysvar_slot_history_add( history, fd_bank_slot_get( slot_ctx->bank ) );

  /* Persist write */

  fd_sysvar_slot_history_leave( slot_ctx, history );
}

#undef BITS_PER_BLOCK
