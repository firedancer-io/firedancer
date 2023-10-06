#include "fd_sysvar_rent.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L36 */
#define ACCOUNT_STORAGE_OVERHEAD ( 128 )

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

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_rent_id, enc, sz, slot_ctx->bank.slot, NULL );
}

int
fd_sysvar_rent_read( fd_exec_slot_ctx_t * slot_ctx,
                     fd_rent_t *       result ) {

  FD_BORROWED_ACCOUNT_DECL(rent_rec);

  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_rent_id, rent_rec);
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to read rent sysvar: %d", err ));
    return err;
  }

  fd_bincode_decode_ctx_t decode = {
    .data    = rent_rec->const_data,
    .dataend = rent_rec->const_data + rent_rec->const_meta->dlen,
    .valloc  = slot_ctx->valloc
  };
  err = fd_rent_decode( result, &decode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("fd_rent_decode failed"));
    return err;
  }

  return 0;
}

void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx ) {
  write_rent( slot_ctx, &slot_ctx->bank.rent );
}

/* TODO: handle update */

ulong
fd_rent_exempt_minimum_balance2( fd_rent_t const * rent,
                                 ulong             data_len ) {
  /* https://github.com/solana-labs/solana/blob/792fafe0c25ac06868e3ac80a2b13f1a5b4a1ef8/sdk/program/src/rent.rs#L72 */
  return (ulong)( (double)((data_len + ACCOUNT_STORAGE_OVERHEAD) * rent->lamports_per_uint8_year) * (double)rent->exemption_threshold );
}

ulong fd_rent_exempt_minimum_balance( fd_exec_slot_ctx_t * slot_ctx, ulong data_len ) {
  // Once we have a proper sysvar cache, we can get rid of this wrongness...
  fd_rent_t rent;
  fd_rent_new( &rent );
  fd_sysvar_rent_read( slot_ctx, &rent );
  return fd_rent_exempt_minimum_balance2( &rent, data_len );
}
