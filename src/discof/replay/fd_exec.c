#include "fd_exec.h"

#include "../../ballet/block/fd_microblock.h"

fd_slice_exec_t *
fd_slice_exec_join( void * slmem ) {
  fd_slice_exec_t * slice_exec_ctx = (fd_slice_exec_t *)slmem;
  FD_TEST( slice_exec_ctx );
  memset( slice_exec_ctx, 0, sizeof(fd_slice_exec_t) );
  return slice_exec_ctx;
}

void
fd_slice_exec_txn_parse( fd_slice_exec_t * slice_exec_ctx,
                         fd_txn_p_t      * txn_p_out ) {
  ulong pay_sz = 0UL;
  ulong txn_sz = fd_txn_parse_core( slice_exec_ctx->buf + slice_exec_ctx->wmark,
                                    fd_ulong_min( FD_TXN_MTU, slice_exec_ctx->sz - slice_exec_ctx->wmark ),
                                    TXN( txn_p_out ),
                                    NULL,
                                    &pay_sz );

  if( FD_UNLIKELY( !pay_sz || !txn_sz || txn_sz > FD_TXN_MTU ) ) {
    FD_LOG_ERR(( "failed to parse transaction in replay" ));
  }
  fd_memcpy( txn_p_out->payload, slice_exec_ctx->buf + slice_exec_ctx->wmark, pay_sz );
  txn_p_out->payload_sz = pay_sz;

  slice_exec_ctx->wmark += pay_sz;
  slice_exec_ctx->txns_rem--;
}

void
fd_slice_exec_microblock_parse( fd_slice_exec_t * slice_exec_ctx ) {
  fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)fd_type_pun( slice_exec_ctx->buf + slice_exec_ctx->wmark );
  //FD_LOG_DEBUG(( "[%s] reading microblock with %lu txns", __func__, hdr->txn_cnt ));
  slice_exec_ctx->txns_rem      = hdr->txn_cnt;
  slice_exec_ctx->last_mblk_off = slice_exec_ctx->wmark;
  slice_exec_ctx->wmark        += sizeof(fd_microblock_hdr_t);
  slice_exec_ctx->mblks_rem--;
}

void
fd_slice_exec_reset( fd_slice_exec_t * slice_exec_ctx ) {
  slice_exec_ctx->last_batch    = 0;
  slice_exec_ctx->txns_rem      = 0;
  slice_exec_ctx->mblks_rem     = 0;
  slice_exec_ctx->sz            = 0;
  slice_exec_ctx->wmark         = 0;
  slice_exec_ctx->last_mblk_off = 0;
}

void
fd_slice_exec_begin( fd_slice_exec_t * slice_exec_ctx,
                     ulong slice_sz,
                     int   last_batch ) {
  slice_exec_ctx->sz         = slice_sz;
  slice_exec_ctx->last_batch = last_batch;
  slice_exec_ctx->txns_rem   = 0;
  slice_exec_ctx->mblks_rem  = FD_LOAD( ulong, slice_exec_ctx->buf );
  slice_exec_ctx->wmark      = sizeof(ulong);
  slice_exec_ctx->last_mblk_off = 0;
}
