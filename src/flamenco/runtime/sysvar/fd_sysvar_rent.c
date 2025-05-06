#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include <assert.h>

static void
write_rent( fd_exec_slot_ctx_t * slot_ctx,
            fd_rent_t const *    rent ) {

  uchar enc[ 32 ];

  ulong sz = fd_rent_size( rent );
  FD_TEST( sz<=sizeof(enc) );
  memset( enc, 0, sz );

  fd_bincode_encode_ctx_t ctx;
  ctx.data    = enc;
  ctx.dataend = enc + sz;
  if( fd_rent_encode( rent, &ctx ) )
    FD_LOG_ERR(("fd_rent_encode failed"));

  fd_sysvar_set( slot_ctx, &fd_sysvar_owner_id, &fd_sysvar_rent_id, enc, sz, slot_ctx->slot_bank.slot );
}

void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  write_rent( slot_ctx, &epoch_bank->rent );
}
