#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_epoch_ctx.h"
#include <assert.h>

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L36 */
#define ACCOUNT_STORAGE_OVERHEAD (128)

fd_rent_t *
fd_sysvar_rent_read( fd_rent_t *                result,
                     fd_exec_slot_ctx_t const * slot_ctx ) {

  fd_rent_t const * ret = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( NULL != ret ) ) {
    fd_memcpy(result, ret, sizeof(fd_rent_t));
    return result;
  }

  FD_BORROWED_ACCOUNT_DECL(rent_rec);

  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_rent_id, rent_rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to read rent sysvar: %d", err ));
    return NULL;
  }

  fd_bincode_decode_ctx_t decode = {
    .data    = rent_rec->const_data,
    .dataend = rent_rec->const_data + rent_rec->const_meta->dlen,
    .valloc  = slot_ctx->valloc
  };
  err = fd_rent_decode( result, &decode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_rent_decode failed" ));
    return NULL;
  }

  return result;
}

static void
write_rent( fd_exec_slot_ctx_t * slot_ctx,
            fd_rent_t const * rent ) {

  uchar enc[ 32 ];

  ulong sz = fd_rent_size( rent );
  FD_TEST( sz<=sizeof(enc) );
  memset( enc, 0, sz );

  fd_bincode_encode_ctx_t ctx;
  ctx.data    = enc;
  ctx.dataend = enc + sz;
  if( fd_rent_encode( rent, &ctx ) )
    FD_LOG_ERR(("fd_rent_encode failed"));

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_rent_id, enc, sz, slot_ctx->slot_bank.slot );
}

void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  write_rent( slot_ctx, &epoch_bank->rent );
}

ulong
fd_rent_exempt_minimum_balance( fd_rent_t const * rent,
                                ulong             data_len ) {
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/program/src/rent.rs#L74 */
  return fd_rust_cast_double_to_ulong( (double)((data_len + ACCOUNT_STORAGE_OVERHEAD) * rent->lamports_per_uint8_year) * rent->exemption_threshold );
}
