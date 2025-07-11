#include "fd_txn_build.h"
#include "fd_txn.h"

FD_STATIC_ASSERT( FD_TXN_ACCT_CAT_PIN       > FD_TXN_ACCT_CAT_ALL, flags );
FD_STATIC_ASSERT( FD_TXN_ACCT_CAT_FEE_PAYER > FD_TXN_ACCT_CAT_ALL, flags );

/* Implementation */

FD_FN_CONST ulong
fd_txn_builder_align( void ) {
  return alignof(fd_txn_builder_t);
}

FD_FN_CONST ulong
fd_txn_builder_footprint( void ) {
  return sizeof(fd_txn_builder_t);
}

fd_txn_builder_t *
fd_txn_builder_new( void * mem,
                    ulong  seed ) {

  /* Sanity check */
  if( FD_UNLIKELY(
      !mem ||
      !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_builder_t) ) ) ) {
    return NULL;
  }

  fd_txn_builder_t * builder = mem;
  memset( builder, 0, sizeof(fd_txn_builder_t) );
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
  acct->cat |= FD_TXN_ACCT_CAT_FEE_PAYER;
  builder->fee_payer_acct = (uchar)acct_idx;
  builder->fee_payer_set  = 1;
  return builder;
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
  program_acct->cat |= FD_TXN_ACCT_CAT_PIN;

  /* Instruction data */

  ulong data_off = builder->data_bump_sz;
  ulong data_end = data_off + data_sz;
  if( FD_UNLIKELY( data_end>FD_TXN_B_DATA_BUMP_MAX ) ) return NULL;
  uchar * saved_data = builder->data_bump + data_off;
  fd_memcpy( saved_data, data, data_sz );
  builder->data_bump_sz += data_sz;

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

  if( FD_UNLIKELY( instr->instr_acct_cnt >= FD_TXN_ACCT_ADDR_MAX ) ) return NULL;
  ulong instr_acct_idx =  builder->instr_acct_cnt++;
  ulong exp_instr_acct_idx = (ulong)instr->instr_acct0 + (instr->instr_acct_cnt++);
  FD_TEST( instr_acct_idx==exp_instr_acct_idx );
  builder->instr_acct[ instr_acct_idx ] = (uchar)acct_idx;

  /* Promote access category */

  uint const prev_cat    = acct->cat;
  uint const mix_cat     = prev_cat|acct_cat; /* floppa */
  uint const is_signer   = !!( mix_cat&FD_TXN_ACCT_CAT_SIGNER    );
  uint const is_writable = !!( mix_cat&FD_TXN_ACCT_CAT_WRITABLE  );
  uint const is_readonly = !!( mix_cat&FD_TXN_ACCT_CAT_READONLY  );
  uint const is_pin      = !!( mix_cat&FD_TXN_ACCT_CAT_IS_PIN    );
  uint const is_alt      = !!( mix_cat&FD_TXN_ACCT_CAT_ALT       );

  /* Drop old access category */

  uint new_cat = mix_cat;
  new_cat &= (is_signer ? FD_TXN_ACCT_CAT_SIGNER : FD_TXN_ACCT_CAT_NONSIGNER );
  if( is_writable ) new_cat &= FD_TXN_ACCT_CAT_WRITABLE;
  if( is_readonly ) new_cat &= FD_TXN_ACCT_CAT_READONLY;
  if( is_pin ) {
    new_cat &= (uchar)(~FD_TXN_ACCT_CAT_ALT); /* clear ALUT bits */
  } else if( is_alt ) {
    new_cat &= FD_TXN_ACCT_CAT_ALT;
  }
  acct->cat = (uchar)new_cat;

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
  static fd_acct_addr_t const system_prog_id = {0};
  uchar const data[4] = { 0x04, 0x00, 0x00, 0x00 };
  if( FD_UNLIKELY( !fd_txn_builder_instr_open(
      builder, &system_prog_id, data, sizeof(data) ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_txn_builder_instr_account_push(
      builder, nonce_account, FD_TXN_ACCT_CAT_WRITABLE ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_txn_builder_instr_account_push(
      builder, nonce_authority, FD_TXN_ACCT_CAT_SIGNER ) ) ) return NULL;
  fd_txn_builder_instr_close( builder );
  return builder;
}

fd_txn_builder_t *
fd_txn_builder_alut_open( fd_txn_builder_t * builder,
                          void const *       alut_addr ) {
  fd_acct_addr_t addr = FD_LOAD( fd_acct_addr_t, alut_addr );
  ulong alut_i = fd_txn_b_acct_acquire( builder, &addr );
  if( FD_UNLIKELY( alut_i==ULONG_MAX ) ) return NULL;
  fd_txn_b_acct_t * alut_acct = &builder->acct[ alut_i ];
  alut_acct->cat |= FD_TXN_ACCT_CAT_PIN; /* ALUT itself cannot be in ALUT */
  builder->alut_i     = (uchar)alut_i;
  builder->alut_empty = 1;
  return builder;
}

void
fd_txn_builder_alut_address_push(
    fd_txn_builder_t * builder,
    void const *       acct_addr,
    uint const         alut_j
) {
  uint const alut_i = builder->alut_i;

  fd_acct_addr_t addr = FD_LOAD( fd_acct_addr_t, acct_addr );
  ulong const acct_idx = fd_txn_b_addr_map_idx_query(
      &builder->map, &addr, ULONG_MAX, builder->acct );
  if( FD_UNLIKELY( acct_idx==ULONG_MAX ) ) return;

  /* Can account be demoted? */

  fd_txn_b_acct_t * acct = &builder->acct[ acct_idx ];
  if( FD_UNLIKELY( acct->cat & FD_TXN_ACCT_CAT_IS_PIN ) ) return;

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
  if( builder->alut_empty ) {
    fd_txn_b_acct_t * alut_acct = &builder->acct[ builder->alut_i ];
    fd_txn_b_addr_map_ele_remove( &builder->map, &alut_acct->key, NULL, builder->acct );
  }
}

/* Declare a quicksort routine over transaction accounts */

static FD_TL fd_txn_builder_t * fd_txn_builder_cur;

static inline int
fd_txn_b_acct_cmp( uint const map_i, uint const map_j ) {
  fd_txn_builder_t const * builder = fd_txn_builder_cur;
  uint const acct_i = builder->acct_map[ map_i ];
  uint const acct_j = builder->acct_map[ map_j ];
  uint const prio_i = builder->acct[ acct_i ].prio;
  uint const prio_j = builder->acct[ acct_j ].prio;
  return prio_i<prio_j;
}

#define SORT_NAME        fd_txn_b_asort
#define SORT_KEY_T       uchar
#define SORT_BEFORE(a,b) fd_txn_b_acct_cmp( (a), (b) )
#include "../../util/tmpl/fd_sort.c"

/* fd_txn_b_bake prepares a transaction for building.  For now, only
   sorts accounts. */

static void
fd_txn_b_bake( fd_txn_builder_t * builder ) {
  /* Assign priorities */
  ulong const acct_cnt = builder->acct_cnt;
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    fd_txn_b_acct_t * acct = &builder->acct[ builder->acct_map[ i ] ];
    uint const cat = acct->cat;

    int prio = fd_uint_find_lsb( cat&FD_TXN_ACCT_CAT_ALL )+1;
    if( cat&FD_TXN_ACCT_CAT_FEE_PAYER ) prio = 0;
    acct->prio = (uchar)prio;
  }

  fd_txn_builder_cur = builder;
  uchar scratch[ FD_TXN_ACCT_ADDR_MAX ];
  fd_txn_b_asort_stable( builder->acct_map, builder->acct_cnt, scratch );
  fd_txn_builder_cur = NULL;
}

__attribute__((always_inline)) static inline int
fd_txn_build_core( fd_txn_builder_t *        builder,
                   uchar                     out_[ FD_TXN_MTU ],
                   fd_txn_t * restrict const out_txn ) {
#define ACCT( i ) (&builder->acct[ builder->acct_map[ i ] ])

  fd_txn_b_bake( builder );

  uchar *       out      = out_;
  uchar * const end      = out + FD_TXN_MTU;
  ulong   const acct_cnt = builder->acct_cnt;

  ulong rw_sig_cnt = 0UL;
  ulong ro_sig_cnt = 0UL;
  ulong rw_uns_cnt = 0UL;
  ulong ro_uns_cnt = 0UL;

  ulong i;
  for( i=0UL; i<acct_cnt; i++ ) {
    fd_txn_b_acct_t * acct = ACCT( i );
    if( acct->prio > 1 ) break;
    rw_sig_cnt++;
  }
  for( ; i<acct_cnt; i++ ) {
    fd_txn_b_acct_t * acct = ACCT( i );
    if( acct->prio > 2 ) break;
    ro_sig_cnt++;
  }
  for( ; i<acct_cnt; i++ ) {
    fd_txn_b_acct_t * acct = ACCT( i );
    if( acct->prio > 3 ) break;
    rw_uns_cnt++;
  }
  for( ; i<acct_cnt; i++ ) {
    fd_txn_b_acct_t * acct = ACCT( i );
    if( acct->prio > 4 ) break;
    ro_uns_cnt++;
  }

  ulong const sig_cnt = rw_sig_cnt + ro_sig_cnt;
  ulong const imm_cnt = sig_cnt + rw_uns_cnt + ro_uns_cnt;

  if( FD_UNLIKELY( sig_cnt > FD_TXN_SIG_MAX ) ) return 0;

  out[0] = (uchar)sig_cnt;
  out++;
  out += sig_cnt*FD_TXN_SIGNATURE_SZ;
  if( FD_UNLIKELY( out>end ) ) return 0;

  if( builder->alut_set ) {
    if( FD_UNLIKELY( out>=end ) ) return 0;
    out[0] = 0x80; /* txn v0 */
    out++;
  }

  if( FD_UNLIKELY( out+4>end ) ) return 0;
  out[0] = (uchar)sig_cnt;
  out[1] = (uchar)ro_sig_cnt;
  out[2] = (uchar)ro_uns_cnt;
  out[3] = (uchar)imm_cnt; /* FIXME cu16 */
  out += 4;

  ulong addr_tbl_sz = imm_cnt*FD_TXN_ACCT_ADDR_SZ;
  if( FD_UNLIKELY( out+addr_tbl_sz>end ) ) return 0;
  for( i=0UL; i<imm_cnt; i++ ) {
    fd_txn_b_acct_t * acct = ACCT( i );
    fd_memcpy( out, &acct->key, FD_TXN_ACCT_ADDR_SZ );
    out += FD_TXN_ACCT_ADDR_SZ;
  }

  if( FD_UNLIKELY( out+FD_TXN_ACCT_ADDR_SZ>end ) ) return 0;
  fd_memcpy( out, &builder->recent_blockhash, FD_TXN_ACCT_ADDR_SZ );
  out += FD_TXN_ACCT_ADDR_SZ;

  if( FD_UNLIKELY( out>=end ) ) return 0;
  ulong const instr_cnt = builder->instr_cnt;
  out[0] = (uchar)instr_cnt;
  out++;

  for( ulong j=0UL; j<instr_cnt; j++ ) {
    fd_txn_b_instr_t * instr = &builder->instr[ j ];
    ulong const instr_acct_cnt = instr->instr_acct_cnt;

    if( FD_UNLIKELY( out+2>end ) ) return 0;
    out[0] = instr->program_id;
    out[1] = (uchar)instr_acct_cnt; /* FIXME cu16 */
    out += 2;

    if( FD_UNLIKELY( out+instr_acct_cnt>end ) ) return 0;
    for( ulong k=0UL; k<instr_acct_cnt; k++ ) {
      ulong const acct_idx = builder->acct_map[ builder->instr_acct[ instr->instr_acct0 + k ] ];
      out[0] = (uchar)acct_idx;
      out++;
    }

    ulong const data_sz = instr->data_sz;
    if( FD_UNLIKELY( out>=end ) ) return 0;
    out[0] = (uchar)data_sz; /* FIXME cu16 */
    out++;

    if( FD_UNLIKELY( out+data_sz>end ) ) return 0;
    fd_memcpy( out, &builder->data_bump[ instr->data_off ], data_sz );
    out += data_sz;
  }

  /* FIXME addrlut */

#undef ACCT
  return 1;
}
