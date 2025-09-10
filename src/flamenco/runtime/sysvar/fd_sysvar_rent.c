#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

#include <assert.h>

void
fd_sysvar_rent_write( fd_exec_slot_ctx_t * slot_ctx,
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

  fd_sysvar_account_update( slot_ctx, &fd_sysvar_rent_id, enc, sz );
}

void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  fd_sysvar_rent_write( slot_ctx, rent );
}

fd_rent_t const *
fd_sysvar_rent_read( fd_accdb_client_t * accdb,
                     fd_rent_t *         rent_out ) {
  FD_ACCDB_READ_BEGIN( accdb, &fd_sysvar_rent_id, rec ) {
    return fd_bincode_decode_static(
        rent, rent_out,
        fd_accdb_ref_data_const( rec ),
        fd_accdb_ref_data_sz   ( rec ),
        NULL );
  }
  FD_ACCDB_READ_END;
  return NULL;
}
