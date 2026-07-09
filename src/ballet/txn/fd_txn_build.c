#include "fd_txn_build.h"
#include "fd_txn.h"
#include "fd_compact_u16.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"

FD_STATIC_ASSERT( FD_TXN_ACCT_CAT_PIN       > FD_TXN_ACCT_CAT_ALL, flags );
FD_STATIC_ASSERT( FD_TXN_ACCT_CAT_FEE_PAYER > FD_TXN_ACCT_CAT_ALL, flags );

/* Implementation */

fd_txn_builder_t *
fd_txn_builder_new( fd_txn_builder_t * mem,
                    ulong              seed ) {

  /* Sanity check */
  if( FD_UNLIKELY(
      !mem ||
      !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_builder_t) ) ) ) {
    return NULL;
  }

  fd_txn_builder_t * builder = mem;
  memset( builder, 0, sizeof(fd_txn_builder_t) );
  builder->alut_i = UCHAR_MAX; /* sentinel: no ALUT open */
  FD_TEST( fd_txn_b_addr_map_new( &builder->map, FD_TXN_B_ADDR_CHAIN_CNT, seed ) );

  return builder;
}

void *
fd_txn_builder_delete( fd_txn_builder_t * builder ) {
  FD_TEST( fd_txn_b_addr_map_delete( &builder->map ) );
  return builder;
}

static ulong
fd_txn_b_acct_acquire( fd_txn_builder_t *     builder,
                       fd_acct_addr_t const * acct_addr ) {

  ulong idx = fd_txn_b_addr_map_idx_query( &builder->map, acct_addr, ULONG_MAX, builder->acct );
  if( idx!=ULONG_MAX ) return idx;

  if( FD_UNLIKELY( builder->acct_cnt >= FD_TXN_ACCT_ADDR_MAX ) ) return ULONG_MAX;
  idx = builder->acct_cnt;
  fd_txn_b_acct_t * acct = &builder->acct[ idx ];
  acct->key = *acct_addr;
  builder->acct_map[ idx ] = (uchar)idx;
  builder->acct_rev[ idx ] = (uchar)idx;
  builder->acct_cnt++;

  fd_txn_b_addr_map_idx_insert( &builder->map, idx, builder->acct );
  return idx;
}

fd_txn_builder_t *
fd_txn_builder_fee_payer_set( fd_txn_builder_t * builder,
                              void const *       fee_payer ) {
  if( FD_UNLIKELY( builder->fee_payer_set ) ) return NULL;
  fd_acct_addr_t addr = FD_LOAD( fd_acct_addr_t, fee_payer );
  ulong acct_idx = fd_txn_b_acct_acquire( builder, &addr );
  if( FD_UNLIKELY( acct_idx==ULONG_MAX ) ) return NULL;
  fd_txn_b_acct_t * acct = &builder->acct[ acct_idx ];
  acct->cat &= (uchar)~FD_TXN_ACCT_CAT_ALL;
  acct->cat |= FD_TXN_ACCT_CAT_WRITABLE_SIGNER | FD_TXN_ACCT_CAT_FEE_PAYER;
  builder->fee_payer_acct = (uchar)acct_idx;
  builder->fee_payer_set  = 1;
  return builder;
}

static uint
fd_txn_b_acct_cat_promote( uint prev_cat,
                           uint req_cat ) {
  int const req_signer   = ( (req_cat & FD_TXN_ACCT_CAT_SIGNER  ) == FD_TXN_ACCT_CAT_SIGNER   );
  int const req_writable = ( (req_cat & FD_TXN_ACCT_CAT_WRITABLE) == FD_TXN_ACCT_CAT_WRITABLE );
  int const is_signer    = !!( prev_cat & FD_TXN_ACCT_CAT_SIGNER   ) || req_signer;
  int const is_writable  = !!( prev_cat & FD_TXN_ACCT_CAT_WRITABLE ) || req_writable;
  uint      new_raw     = is_signer
                        ? ( is_writable ? FD_TXN_ACCT_CAT_WRITABLE_SIGNER        : FD_TXN_ACCT_CAT_READONLY_SIGNER )
                        : ( is_writable ? FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM : FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM );

  return (prev_cat & ~((uint)FD_TXN_ACCT_CAT_ALL)) | new_raw;
}

fd_txn_builder_t *
fd_txn_builder_instr_open( fd_txn_builder_t * builder,
                           void const *       program_id,
                           void const *       data,
                           ulong              data_sz ) {

  if( FD_UNLIKELY( builder->alut_set ) ) return NULL;

  /* Program account */

  fd_acct_addr_t addr = FD_LOAD( fd_acct_addr_t, program_id );
  ulong program_acct_idx = fd_txn_b_acct_acquire( builder, &addr );
  if( FD_UNLIKELY( program_acct_idx==ULONG_MAX ) ) return NULL;
  fd_txn_b_acct_t * program_acct = &builder->acct[ program_acct_idx ];
  program_acct->cat = (uchar)fd_txn_b_acct_cat_promote( program_acct->cat, FD_TXN_ACCT_CAT_NONE );
  program_acct->cat |= FD_TXN_ACCT_CAT_PIN;

  /* Instruction data */

  ulong data_off = builder->data_bump_sz;
  ulong data_end = data_off + data_sz;
  if( FD_UNLIKELY( data_end>FD_TXN_B_DATA_BUMP_MAX ) ) return NULL;
  uchar * saved_data = builder->data_bump + data_off;
  fd_memcpy( saved_data, data, data_sz );
  builder->data_bump_sz = (ushort)( (ulong)builder->data_bump_sz + data_sz );

  /* Instruction */

  if( FD_UNLIKELY( builder->instr_cnt >= FD_TXN_INSTR_MAX ) ) return NULL;
  fd_txn_b_instr_t * instr = &builder->instr[ builder->instr_cnt++ ];
  instr->program_id     = (uchar)program_acct_idx;
  instr->instr_acct0    = builder->instr_acct_cnt;
  instr->instr_acct_cnt = 0;
  instr->data_off       = (ushort)data_off;
  instr->data_sz        = (ushort)data_sz;

  return builder;
}

fd_txn_builder_t *
fd_txn_builder_instr_account_push(
    fd_txn_builder_t * builder,
    void const *       acct_addr,
    uint               acct_cat
) {
  if( FD_UNLIKELY( builder->instr_cnt==0 ) ) return NULL;
  fd_txn_b_instr_t * instr = &builder->instr[ builder->instr_cnt-1 ];

  /* Transaction Account */

  fd_acct_addr_t addr = FD_LOAD( fd_acct_addr_t, acct_addr );
  ulong acct_idx = fd_txn_b_acct_acquire( builder, &addr );
  if( FD_UNLIKELY( acct_idx==ULONG_MAX ) ) return NULL;
  fd_txn_b_acct_t * acct = &builder->acct[ acct_idx ];

  /* Instruction Account */

  if( FD_UNLIKELY( instr->instr_acct_cnt   >= FD_TXN_ACCT_ADDR_MAX ) ) return NULL;
  if( FD_UNLIKELY( builder->instr_acct_cnt >= FD_TXN_ACCT_ADDR_MAX ) ) return NULL;
  ulong instr_acct_idx =  builder->instr_acct_cnt++;
  ulong exp_instr_acct_idx = (ulong)instr->instr_acct0 + (instr->instr_acct_cnt++);
  FD_TEST( instr_acct_idx==exp_instr_acct_idx );
  builder->instr_acct[ instr_acct_idx ] = (uchar)acct_idx;

  /* Promote access category */

  acct->cat = (uchar)fd_txn_b_acct_cat_promote( acct->cat, acct_cat );

  return builder;
}

void
fd_txn_builder_instr_close( fd_txn_builder_t * builder ) {
  (void)builder;
}

fd_txn_builder_t *
fd_txn_builder_nonce_set( fd_txn_builder_t * builder,
                          void const *       nonce_account,
                          void const *       nonce_authority ) {
  /* The advance nonce instruction must be the first instruction in the
     transaction, so reject if any instruction was already opened. */
  if( FD_UNLIKELY( builder->instr_cnt!=0 ) ) return NULL;

  static fd_acct_addr_t const system_prog_id        = { .b = { SYS_PROG_ID               } };
  static fd_acct_addr_t const recent_blockhashes_id = { .b = { SYSVAR_RECENT_BLKHASH_ID } };
  uchar const data[4] = { 0x04, 0x00, 0x00, 0x00 };
  if( FD_UNLIKELY( !fd_txn_builder_instr_open(
      builder, &system_prog_id, data, sizeof(data) ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_txn_builder_instr_account_push(
      builder, nonce_account, FD_TXN_ACCT_CAT_WRITABLE ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_txn_builder_instr_account_push(
      builder, &recent_blockhashes_id, FD_TXN_ACCT_CAT_NONE ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_txn_builder_instr_account_push(
      builder, nonce_authority, FD_TXN_ACCT_CAT_SIGNER ) ) ) return NULL;
  fd_txn_builder_instr_close( builder );
  return builder;
}

fd_txn_builder_t *
fd_txn_builder_alut_open( fd_txn_builder_t * builder,
                          void const *       alut_addr ) {
  /* The builder only serializes a single ALUT, so reject a second open. */
  if( FD_UNLIKELY( builder->alut_i!=UCHAR_MAX ) ) return NULL;
  fd_acct_addr_t addr = FD_LOAD( fd_acct_addr_t, alut_addr );
  ulong alut_i = fd_txn_b_acct_acquire( builder, &addr );
  if( FD_UNLIKELY( alut_i==ULONG_MAX ) ) return NULL;
  fd_txn_b_acct_t * alut_acct = &builder->acct[ alut_i ];
  alut_acct->cat = (uchar)fd_txn_b_acct_cat_promote( alut_acct->cat, FD_TXN_ACCT_CAT_NONE );
  alut_acct->cat |= FD_TXN_ACCT_CAT_PIN; /* ALUT itself cannot be in ALUT */
  builder->alut_i     = (uchar)alut_i;
  return builder;
}

void
fd_txn_builder_alut_address_push(
    fd_txn_builder_t * builder,
    void const *       acct_addr,
    uint const         alut_j
) {
  uint const alut_i = builder->alut_i;

  /* Requires an opened ALUT.  alut_j is serialized as a u8. */
  if( FD_UNLIKELY( alut_i==UCHAR_MAX ) ) return;
  if( FD_UNLIKELY( alut_j>UCHAR_MAX  ) ) return;

  fd_acct_addr_t addr = FD_LOAD( fd_acct_addr_t, acct_addr );
  ulong const acct_idx = fd_txn_b_addr_map_idx_query(
      &builder->map, &addr, ULONG_MAX, builder->acct );
  if( FD_UNLIKELY( acct_idx==ULONG_MAX ) ) return;

  /* Can account be demoted? */

  fd_txn_b_acct_t * acct = &builder->acct[ acct_idx ];
  if( FD_UNLIKELY( acct->cat & FD_TXN_ACCT_CAT_IS_PIN ) ) return;

  /* Already demoted to an ALUT?  Ignore subsequent calls. */

  if( FD_UNLIKELY( acct->cat & FD_TXN_ACCT_CAT_ALT ) ) return;

  /* Demote account to ALUT */

  if( acct->cat & FD_TXN_ACCT_CAT_WRITABLE ) {
    acct->cat = FD_TXN_ACCT_CAT_WRITABLE_ALT;
  } else {
    acct->cat = FD_TXN_ACCT_CAT_READONLY_ALT;
  }
  acct->alut_i = (uchar)alut_i;
  acct->alut_j =        alut_j;

  builder->alut_set = 1;
}

void
fd_txn_builder_alut_close( fd_txn_builder_t * builder ) {
  (void)builder;
}

static inline uint
fd_txn_b_acct_prio( fd_txn_b_acct_t const * acct ) {
  uint const cat = acct->cat;
  return (cat & FD_TXN_ACCT_CAT_FEE_PAYER) ? 0U : (uint)( fd_uint_find_lsb( cat & FD_TXN_ACCT_CAT_ALL )+1 );
}

#define FD_TXN_B_ACCT_PRIO_CNT 7UL

/* fd_txn_b_bake prepares a transaction for building.  For now, only
   sorts accounts. */

static void
fd_txn_b_bake( fd_txn_builder_t * builder,
               ulong              cnt[ FD_TXN_B_ACCT_PRIO_CNT ] ) {
  ulong const acct_cnt = builder->acct_cnt;

  fd_memset( cnt, 0, FD_TXN_B_ACCT_PRIO_CNT*sizeof(ulong) );
  for( ulong i=0UL; i<acct_cnt; i++ ) cnt[ fd_txn_b_acct_prio( &builder->acct[ builder->acct_map[ i ] ] ) ]++;

  ulong off[ FD_TXN_B_ACCT_PRIO_CNT ];
  off[ 0 ] = 0UL;
  for( ulong i=1UL; i<FD_TXN_B_ACCT_PRIO_CNT; i++ ) off[ i ] = off[ i-1UL ] + cnt[ i-1UL ];

  uchar scratch[ FD_TXN_ACCT_ADDR_MAX ];
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    uchar const acct_i = builder->acct_map[ i ];
    scratch[ off[ fd_txn_b_acct_prio( &builder->acct[ acct_i ] ) ]++ ] = acct_i;
  }

  fd_memcpy( builder->acct_map, scratch, acct_cnt );
  for( ulong i=0UL; i<acct_cnt; i++ ) builder->acct_rev[ builder->acct_map[ i ] ] = (uchar)i;
}

static inline uchar *
fd_txn_b_cu16_write( uchar * out,
                     uchar * end,
                     ulong   val ) {
  if( FD_UNLIKELY( val>USHORT_MAX ) ) return NULL;
  ulong enc_sz = 1UL + ( val>0x7FUL ) + ( val>0x3FFFUL );
  if( FD_UNLIKELY( out+enc_sz>end ) ) return NULL;
  out += fd_cu16_enc( (ushort)val, out );
  return out;
}

__attribute__((always_inline)) static inline uint
fd_txn_build_core( fd_txn_builder_t *        builder,
                   uchar                     out_[ FD_TXN_MTU ] ) {
#define ACCT( i ) (&builder->acct[ builder->acct_map[ i ] ])

  ulong cnt[ FD_TXN_B_ACCT_PRIO_CNT ];
  fd_txn_b_bake( builder, cnt );

  uchar *       out      = out_;
  uchar * const end      = out + FD_TXN_MTU;

  ulong const rw_sig_cnt = cnt[ 0 ] + cnt[ 1 ];
  ulong const ro_sig_cnt = cnt[ 2 ];
  ulong const rw_uns_cnt = cnt[ 3 ];
  ulong const ro_uns_cnt = cnt[ 4 ];
  ulong const rw_alt_cnt = cnt[ 5 ];
  ulong const ro_alt_cnt = cnt[ 6 ];

  ulong const sig_cnt = rw_sig_cnt + ro_sig_cnt;
  ulong const imm_cnt = sig_cnt + rw_uns_cnt + ro_uns_cnt;
  ulong const alt_cnt = rw_alt_cnt + ro_alt_cnt;

  if( FD_UNLIKELY( sig_cnt > FD_TXN_SIG_MAX ) ) return 0;
  if( FD_UNLIKELY( !builder->fee_payer_set ) ) return 0;
  if( FD_UNLIKELY( builder->acct_rev[ builder->fee_payer_acct ]!=0U ) ) return 0;

  out[0] = (uchar)sig_cnt;
  out++;
  fd_memset( out, 0, sig_cnt*FD_TXN_SIGNATURE_SZ );
  out += sig_cnt*FD_TXN_SIGNATURE_SZ;
  if( FD_UNLIKELY( out>end ) ) return 0;

  if( alt_cnt ) {
    if( FD_UNLIKELY( out>=end ) ) return 0;
    out[0] = 0x80; /* txn v0 */
    out++;
  }

  if( FD_UNLIKELY( out+3>end ) ) return 0;
  out[0] = (uchar)sig_cnt;
  out[1] = (uchar)ro_sig_cnt;
  out[2] = (uchar)ro_uns_cnt;
  out += 3;

  out = fd_txn_b_cu16_write( out, end, imm_cnt );
  if( FD_UNLIKELY( !out ) ) return 0;

  ulong addr_tbl_sz = imm_cnt*FD_TXN_ACCT_ADDR_SZ;
  if( FD_UNLIKELY( out+addr_tbl_sz>end ) ) return 0;
  for( ulong i=0UL; i<imm_cnt; i++ ) {
    fd_txn_b_acct_t * acct = ACCT( i );
    fd_memcpy( out, &acct->key, FD_TXN_ACCT_ADDR_SZ );
    out += FD_TXN_ACCT_ADDR_SZ;
  }

  if( FD_UNLIKELY( out+FD_TXN_ACCT_ADDR_SZ>end ) ) return 0;
  fd_memcpy( out, &builder->recent_blockhash, FD_TXN_ACCT_ADDR_SZ );
  out += FD_TXN_ACCT_ADDR_SZ;

  if( FD_UNLIKELY( out>=end ) ) return 0;
  ulong const instr_cnt = builder->instr_cnt;
  out = fd_txn_b_cu16_write( out, end, instr_cnt );
  if( FD_UNLIKELY( !out ) ) return 0;

  for( ulong j=0UL; j<instr_cnt; j++ ) {
    fd_txn_b_instr_t * instr = &builder->instr[ j ];
    ulong const instr_acct_cnt = instr->instr_acct_cnt;

    if( FD_UNLIKELY( out+1>end ) ) return 0;
    out[0] = builder->acct_rev[ instr->program_id ];
    out++;

    out = fd_txn_b_cu16_write( out, end, instr_acct_cnt );
    if( FD_UNLIKELY( !out ) ) return 0;

    if( FD_UNLIKELY( out+instr_acct_cnt>end ) ) return 0;
    for( ulong k=0UL; k<instr_acct_cnt; k++ ) {
      ulong const acct_idx = builder->acct_rev[ builder->instr_acct[ instr->instr_acct0 + k ] ];
      out[0] = (uchar)acct_idx;
      out++;
    }

    ulong const data_sz = instr->data_sz;
    out = fd_txn_b_cu16_write( out, end, data_sz );
    if( FD_UNLIKELY( !out ) ) return 0;

    if( FD_UNLIKELY( out+data_sz>end ) ) return 0;
    fd_memcpy( out, &builder->data_bump[ instr->data_off ], data_sz );
    out += data_sz;
  }

  if( alt_cnt ) {
    out = fd_txn_b_cu16_write( out, end, 1UL );
    if( FD_UNLIKELY( !out ) ) return 0;

    fd_txn_b_acct_t * alut_acct = &builder->acct[ builder->alut_i ];
    if( FD_UNLIKELY( out+FD_TXN_ACCT_ADDR_SZ>end ) ) return 0;
    fd_memcpy( out, &alut_acct->key, FD_TXN_ACCT_ADDR_SZ );
    out += FD_TXN_ACCT_ADDR_SZ;

    out = fd_txn_b_cu16_write( out, end, rw_alt_cnt );
    if( FD_UNLIKELY( !out ) ) return 0;
    if( FD_UNLIKELY( out+rw_alt_cnt>end ) ) return 0;
    for( ulong j=imm_cnt; j<imm_cnt+rw_alt_cnt; j++ ) {
      if( FD_UNLIKELY( ACCT( j )->alut_j>255U ) ) return 0;
      out[0] = (uchar)ACCT( j )->alut_j;
      out++;
    }

    out = fd_txn_b_cu16_write( out, end, ro_alt_cnt );
    if( FD_UNLIKELY( !out ) ) return 0;
    if( FD_UNLIKELY( out+ro_alt_cnt>end ) ) return 0;
    for( ulong j=imm_cnt+rw_alt_cnt; j<imm_cnt+alt_cnt; j++ ) {
      if( FD_UNLIKELY( ACCT( j )->alut_j>255U ) ) return 0;
      out[0] = (uchar)ACCT( j )->alut_j;
      out++;
    }
  }

#undef ACCT
  return (uint)( out - out_ );
}

uint
fd_txn_build_raw( fd_txn_builder_t * builder,
                  uchar              out[ FD_TXN_MTU ] ) {
  return fd_txn_build_core( builder, out );
}

uint
fd_txn_build( fd_txn_builder_t *  builder,
              uchar               out[ FD_TXN_MTU ],
              fd_txn_t * restrict out_txn,
              ushort *            opt_out_txn_t_sz ) {
  uint payload_sz = fd_txn_build_core( builder, out );
  if( FD_UNLIKELY( !payload_sz ) ) return 0U;

  ulong txn_t_sz = fd_txn_parse( out, payload_sz, out_txn, NULL );
  if( FD_UNLIKELY( !txn_t_sz ) ) return 0U;
  if( opt_out_txn_t_sz ) *opt_out_txn_t_sz = (ushort)txn_t_sz;
  return payload_sz;
}
