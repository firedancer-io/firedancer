/* fd_sysvar_cache_db.c contains database interactions between the
   sysvar cache and the account database. */

#include "fd_sysvar_base.h"
#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"
#include "fd_sysvar_rent.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_txn_account.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include <errno.h>

static int
sysvar_data_fill( fd_sysvar_cache_t *  cache,
                  fd_exec_slot_ctx_t * slot_ctx,
                  ulong                idx,
                  int                  log_fails ) {
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_pubkey_t const *     key  = &fd_sysvar_key_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  /* Read account from database */
  fd_funk_t *     funk     = slot_ctx->funk;
  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;
  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_txn_account_init_from_funk_readonly( rec, key, funk, funk_txn );
  if( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    if( log_fails ) FD_LOG_DEBUG(( "Sysvar %s not found", pos->name ));
    return 0;
  } else if( err!=FD_ACC_MGR_SUCCESS ) {
    FD_LOG_ERR(( "fd_txn_account_init_from_funk_readonly failed: %i", err ));
    return EIO;
  }

  /* Work around instruction fuzzer quirk */
  if( FD_UNLIKELY( rec->vt->get_lamports( rec )==0 ) ) {
    if( log_fails ) FD_LOG_WARNING(( "Skipping sysvar %s: zero balance", pos->name ));
    return 0;
  }

  /* Fill data cache entry */
  ulong const data_sz = rec->vt->get_data_len( rec );
  if( FD_UNLIKELY( data_sz > pos->data_max ) ) {
    if( log_fails ) {
      FD_LOG_WARNING(( "Failed to restore sysvar %s: data_sz=%lu exceeds max=%u",
                       pos->name, data_sz, pos->data_max ));
    }
    return ENOMEM;
  }
  uchar * data = (uchar *)cache+pos->data_off;
  fd_memcpy( data, rec->vt->get_data( rec ), data_sz );
  desc->data_sz = (uint)data_sz;

  /* Recover object cache entry from data cache entry */
  return fd_sysvar_obj_restore( cache, desc, pos, log_fails );
}

static int
fd_sysvar_cache_restore1( fd_exec_slot_ctx_t * slot_ctx,
                          int                  log_fails ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new(
      fd_bank_sysvar_cache_modify( slot_ctx->bank ) ) );

  int saw_err = 0;
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    int err = sysvar_data_fill( cache, slot_ctx, i, log_fails );
    if( err ) saw_err = 1;
  }

  fd_sysvar_cache_leave( cache );

  return !saw_err;
}

int
fd_sysvar_cache_restore( fd_exec_slot_ctx_t * slot_ctx ) {
  return fd_sysvar_cache_restore1( slot_ctx, 1 );
}

void
fd_sysvar_cache_restore_fuzz( fd_exec_slot_ctx_t * slot_ctx ) {
  (void)fd_sysvar_cache_restore1( slot_ctx, 0 );
}

void
fd_sysvar_account_update( fd_exec_slot_ctx_t * slot_ctx,
                          fd_pubkey_t const *  address,
                          void const *         data,
                          ulong                sz ) {
  /* Updating a sysvar requires the rent sysvar to exist first, so the
     runtime can determine that sysvar's minimum balance.  If you hit
     this error, it means that you should change your code to insert the
     rent sysvar before anything else. */
  fd_rent_t const rent    = fd_sysvar_rent_read_nofail( fd_bank_sysvar_cache_query( slot_ctx->bank ) );
  ulong     const min_bal = fd_rent_exempt_minimum_balance( &rent, sz );

  FD_TXN_ACCOUNT_DECL( rec );
  fd_txn_account_init_from_funk_mutable( rec, address, slot_ctx->funk, slot_ctx->funk_txn, 1, sz );

  ulong const slot            = fd_bank_slot_get( slot_ctx->bank );
  ulong const lamports_before = rec->vt->get_lamports( rec );
  ulong const lamports_after  = fd_ulong_max( lamports_before, min_bal );
  rec->vt->set_lamports( rec, lamports_after      );
  rec->vt->set_owner   ( rec, &fd_sysvar_owner_id );
  rec->vt->set_slot    ( rec, slot                );
  rec->vt->set_data( rec, data, sz );

  ulong lamports_minted;
  if( FD_UNLIKELY( __builtin_usubl_overflow( lamports_after, lamports_before, &lamports_minted ) ) ) {
    char name[ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( address->uc, NULL, name );
    FD_LOG_CRIT(( "fd_sysvar_account_update: lamports overflowed: address=%s lamports_before=%lu lamports_after=%lu",
                  name, lamports_before, lamports_after ));
  }

  if( lamports_minted ) {
    ulong cap = fd_bank_capitalization_get( slot_ctx->bank );
    fd_bank_capitalization_set( slot_ctx->bank, cap+lamports_minted );
  } else if( lamports_before==lamports_after ) {
    /* no balance change */
  } else {
    __builtin_unreachable();
  }

  fd_txn_account_mutable_fini( rec, slot_ctx->funk, slot_ctx->funk_txn );

  FD_LOG_DEBUG(( "Updated sysvar: address=%s data_sz=%lu slot=%lu lamports=%lu lamports_minted=%lu",
                 FD_BASE58_ENC_32_ALLOCA( address ), sz, slot, lamports_after, lamports_minted ));
}

static void
sysvar_write_through( fd_exec_slot_ctx_t * slot_ctx,
                      fd_sysvar_cache_t *  cache,
                      ulong const          idx,
                      ulong const          min_sz ) {
  fd_sysvar_desc_t *      desc = &cache->desc[ idx ];
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_bincode_encode_ctx_t ctx  = {0};
  void *  obj  = (void *)( (ulong)cache + pos->obj_off );
  uchar * data = (uchar *)cache + pos->data_off;
  ctx.data    = data;
  ctx.dataend = data + pos->data_max;
  if( FD_UNLIKELY( pos->encode( obj, &ctx )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to encode sysvar" ));
  }
  ulong data_sz = (ulong)ctx.data - (ulong)data;
  if( data_sz<min_sz ) {
    fd_memset( data+data_sz, 0, min_sz-data_sz );
    data_sz = min_sz;
  }

  desc->flags   = FD_SYSVAR_FLAG_VALID;
  desc->data_sz = (uint)data_sz;

  /* Already setting the valid flag here to fix the chicken-and-egg
     problem where the rent sysvar has to meet rent-exemption when it is
     first written. */

  fd_pubkey_t const * addr = &fd_sysvar_key_tbl[ idx ];
  fd_sysvar_account_update( slot_ctx, addr, data, data_sz );
}

void
fd_sysvar_cache_data_modify_commit(
    fd_exec_slot_ctx_t * slot_ctx,
    void const *         address, /* 32 bytes */
    ulong                sz
) {
  fd_sysvar_cache_t * cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );

  /* Lookup sysvar entry */
  fd_pubkey_t pubkey; memcpy( pubkey.uc, address, 32UL );
  sysvar_tbl_t const * entry = sysvar_map_query( &pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) FD_LOG_CRIT(( "invalid sysvar_cache_data_modify_commit" ));

  /* Persist write to data cache and database */
  ulong const idx = entry->desc_idx;
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_pubkey_t const *     key  = &fd_sysvar_key_tbl[ idx ];
  uchar *                 data = (uchar *)cache + pos->data_off;
  if( FD_UNLIKELY( !( desc->flags & FD_SYSVAR_FLAG_WRITE_LOCK ) ) ) FD_LOG_CRIT(( "unmatched sysvar_cache_data_modify_commit" ));
  if( FD_UNLIKELY( sz > pos->data_max ) ) FD_LOG_CRIT(( "attempted to write oversize sysvar (sz=%lu max=%u)", sz, pos->data_max ));
  desc->data_sz = (uint)sz;
  fd_sysvar_account_update( slot_ctx, key, data, sz );

  /* Recover object cache entry from data cache entry */
  int err = fd_sysvar_obj_restore( cache, desc, pos, 1 );

  desc->flags &= ~FD_SYSVAR_FLAG_WRITE_LOCK;
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to modify sysvar bytes: could not recover typed representation (%d-%s)", errno, fd_io_strerror( errno ) ));
  }
}

/* All sysvar cache API functions that write (using above functions)
   These are split into a separate compile units to allow unit tests to
   build cleanly without a dependency on database symbols. */

#define SIMPLE_SYSVAR_WRITE( name, name2, typet, type )                \
  void                                                                 \
  fd_sysvar_##name##_write( fd_exec_slot_ctx_t * slot_ctx,             \
                            typet const *        name2 ) {             \
    ulong const idx = FD_SYSVAR_##name##_IDX;                          \
    fd_sysvar_cache_t *     cache = fd_bank_sysvar_cache_modify( slot_ctx->bank ); \
    fd_sysvar_pos_t const * pos   = &fd_sysvar_pos_tbl[ idx ];         \
    typet * buf = (void *)( (ulong)cache+pos->obj_off );               \
    *buf = *name2;                                                     \
    sysvar_write_through( slot_ctx, cache, idx, 0UL );                 \
  }

#define SIMPLE_SYSVAR( name, name2, type ) \
  SIMPLE_SYSVAR_WRITE( name, name2, fd_##type##_t, type )
FD_SYSVAR_SIMPLE_ITER( SIMPLE_SYSVAR )
#undef SIMPLE_SYSVAR

void
fd_sysvar_slot_hashes_leave(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_slot_hash_t *     slot_hashes
) {
  ulong const idx = FD_SYSVAR_slot_hashes_IDX;
  fd_sysvar_cache_t * cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  if( FD_UNLIKELY( FD_VOLATILE_CONST( cache->desc[ idx ].flags )!=FD_SYSVAR_FLAG_WRITE_LOCK ) ) {
    FD_LOG_CRIT(( "unmatched sysvar leave" ));
  }
  fd_slot_hashes_global_t const * var = (void *)cache->obj_slot_hashes;
  if( FD_UNLIKELY( !slot_hashes ||
                   (ulong)deq_fd_slot_hash_t_leave( slot_hashes ) !=
                   (ulong)var+var->hashes_offset ) ) {
    FD_LOG_CRIT(( "sysvar leave called with invalid pointer" ));
  }
  sysvar_write_through( slot_ctx, cache, idx, FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
}

void
fd_sysvar_slot_history_leave(
    fd_exec_slot_ctx_t *       slot_ctx,
    fd_slot_history_global_t * slot_history
) {
  ulong const idx = FD_SYSVAR_slot_history_IDX;
  fd_sysvar_cache_t * cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  if( FD_UNLIKELY( FD_VOLATILE_CONST( cache->desc[ idx ].flags )!=FD_SYSVAR_FLAG_WRITE_LOCK ) ) {
    FD_LOG_CRIT(( "unmatched sysvar leave" ));
  }
  if( FD_UNLIKELY( !slot_history ) ) {
    FD_LOG_CRIT(( "sysvar leave called with invalid pointer" ));
  }
  sysvar_write_through( slot_ctx, cache, idx, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
}

void
fd_sysvar_stake_history_leave(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_stake_history_t * stake_history
) {
  ulong const idx = FD_SYSVAR_stake_history_IDX;
  fd_sysvar_cache_t * cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  if( FD_UNLIKELY( FD_VOLATILE_CONST( cache->desc[ idx ].flags )!=FD_SYSVAR_FLAG_WRITE_LOCK ) ) {
    FD_LOG_CRIT(( "unmatched sysvar leave" ));
  }
  if( FD_UNLIKELY( !stake_history ) ) {
    FD_LOG_CRIT(( "sysvar leave called with invalid pointer" ));
  }
  sysvar_write_through( slot_ctx, cache, idx, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
}

void
fd_sysvar_epoch_schedule_write_cache_only(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_epoch_schedule_t const *   epoch_schedule
) {
  ulong const idx = FD_SYSVAR_epoch_schedule_IDX;
  fd_sysvar_cache_t *     cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  fd_sysvar_desc_t *      desc  = &cache->desc      [ idx ];
  fd_sysvar_pos_t const * pos   = &fd_sysvar_pos_tbl[ idx ];
  fd_epoch_schedule_t * buf = (void *)( (ulong)cache+pos->obj_off );
  *buf = *epoch_schedule;

  fd_bincode_encode_ctx_t ctx = {0};
  uchar * data = (uchar *)cache + pos->data_off;
  ctx.data    = data;
  ctx.dataend = data + pos->data_max;
  if( FD_UNLIKELY( pos->encode( epoch_schedule, &ctx )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to encode sysvar" ));
  }
  ulong data_sz = (ulong)ctx.data - (ulong)data;

  desc->flags   = FD_SYSVAR_FLAG_VALID;
  desc->data_sz = (uint)data_sz;
}

void
fd_sysvar_rent_write_cache_only(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_rent_t const *    rent
) {
  ulong const idx = FD_SYSVAR_rent_IDX;
  fd_sysvar_cache_t *     cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  fd_sysvar_desc_t *      desc  = &cache->desc      [ idx ];
  fd_sysvar_pos_t const * pos   = &fd_sysvar_pos_tbl[ idx ];
  fd_rent_t * buf = (void *)( (ulong)cache+pos->obj_off );
  *buf = *rent;

  fd_bincode_encode_ctx_t ctx  = {0};
  uchar * data = (uchar *)cache + pos->data_off;
  ctx.data    = data;
  ctx.dataend = data + pos->data_max;
  if( FD_UNLIKELY( pos->encode( rent, &ctx )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to encode sysvar" ));
  }
  ulong data_sz = (ulong)ctx.data - (ulong)data;

  desc->flags   = FD_SYSVAR_FLAG_VALID;
  desc->data_sz = (uint)data_sz;
}
