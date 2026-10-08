#include "fd_pack_offer.h"
#include "fd_pack_cost.h"
#include "fd_pack_tip_prog_blacklist.h"

/* System program instruction discriminant of Transfer, and the size
   of its instruction data (u32 discriminant, u64 lamports). */
#define SYSTEM_IX_TRANSFER    (2U)
#define SYSTEM_IX_TRANSFER_SZ (12UL)

static inline int
is_system_program( fd_acct_addr_t const * a ) {
  return (fd_ulong_load_8( a->b )|fd_ulong_load_8( a->b+8UL )|fd_ulong_load_8( a->b+16UL )|fd_ulong_load_8( a->b+24UL ))==0UL;
}

fd_pack_offer_t *
fd_pack_offer_compute( fd_txn_t       const * txn,
                       uchar          const * payload,
                       fd_acct_addr_t const * alt_accts,
                       fd_pack_offer_t      * out ) {
  uint  flags = 0U;
  ulong fee   = 0UL;
  out->priority_fee = fd_pack_compute_cost( txn, payload, &flags, NULL, &fee, NULL, NULL, NULL ) ? fee : 0UL;

  fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
  ulong                  imm_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
  ulong                  alt_cnt = (ulong)txn->addr_table_adtl_cnt;

  ulong static_tip = 0UL;
  for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn->instr[ i ];
    uchar          const * data  = payload + instr->data_off;
    if( FD_LIKELY( !is_system_program( accts + instr->program_id ) ||   /* program ids are always static */
                   instr->data_sz!=SYSTEM_IX_TRANSFER_SZ ||
                   instr->acct_cnt<2 ||
                   fd_uint_load_4( data )!=SYSTEM_IX_TRANSFER ) ) continue;

    ulong dst_idx = (ulong)payload[ instr->acct_off+1UL ];
    fd_acct_addr_t const * dst = NULL;
    if( FD_LIKELY( dst_idx<imm_cnt ) )                             dst = accts + dst_idx;
    else if( FD_LIKELY( alt_accts && (dst_idx-imm_cnt)<alt_cnt ) ) dst = alt_accts + (dst_idx-imm_cnt);
    if( FD_LIKELY( dst && fd_pack_tip_is_tip_account( dst ) ) ) static_tip = fd_ulong_sat_add( static_tip, fd_ulong_load_8( data+4UL ) );
  }
  out->static_tip = static_tip;
  return out;
}
