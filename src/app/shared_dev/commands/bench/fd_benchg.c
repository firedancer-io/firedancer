#include "bench.h"

#include "../../../../disco/topo/fd_topo.h"
#include "../../../../flamenco/genesis/fd_genesis_create.h"
#include "../../../../flamenco/runtime/fd_system_ids_pp.h"

typedef struct {
  fd_rng_t rng[ 1 ];
  fd_sha512_t sha[ 1 ];

  ulong sender_idx;
  ulong lamport_idx;
  int   changed_blockhash;

  int   has_recent_blockhash;
  uchar recent_blockhash[ 32 ];
  uchar staged_blockhash[ 32 ];

  int   transaction_mode;
  float contending_fraction;
  float cu_price_spread;

  ulong acct_cnt;
  fd_pubkey_t * acct_public_keys;
  fd_pubkey_t * acct_private_keys;
  fd_pubkey_t * token_accounts;

  ulong benchg_cnt;
  ulong benchg_idx;

  fd_wksp_t * mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_benchg_ctx_t;

FD_STATIC_ASSERT( FD_GENESIS_TOKEN_ACCOUNTS_PER_ACCOUNT>=2UL, token_accounts );

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_benchg_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_benchg_ctx_t ), sizeof( fd_benchg_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );
  l = FD_LAYOUT_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );
  l = FD_LAYOUT_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * 2UL * tile->benchg.accounts_cnt );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

typedef struct __attribute__((packed)) {
	uchar sig_cnt; /* = 1 */
	uchar signature[64];
	uchar _sig_cnt; /* also 1 */
	uchar ro_signed_cnt; /* ??? */
	uchar ro_unsigned_cnt; /* ??? */
	uchar acct_addr_cnt; /* = ??? */
	uchar fee_payer[32];
} single_signer_hdr_t;

typedef struct __attribute__((packed)) {
	uchar sig_cnt; /* = 1 */
	uchar signature[64];
	uchar _sig_cnt; /* also 1 */
	uchar ro_signed_cnt; /* = 0 */
	uchar ro_unsigned_cnt; /* = 1 . Compute Budget Program */
	uchar acct_addr_cnt; /* = 2 */
	uchar fee_payer[32];
	uchar compute_budget_program[32]; /* = {COMPUTE_BUDGET_PROG_ID} */
	uchar recent_blockhash[32];
	uchar instr_cnt; /* = 2 */
  /* Start of instruction */
  struct __attribute__((packed)) {
    uchar prog_id; /* = 1 */
    uchar acct_cnt; /* = 0 */
    uchar data_sz; /* = 9 */
    uchar set_cu_price; /* = 3 */
    ulong micro_lamports_per_cu; /* Preferably less than 10k or so */
  } _1;
  /* Start of second instruction */
  struct __attribute__((packed)) {
    uchar prog_id; /* = 1 */
    uchar acct_cnt; /* = 0 */
    uchar data_sz; /* = 5 */
    uchar set_cu_limit; /* = 2 */
    uint cus; /* = 300 */
  } _2;
} noop_t;

typedef struct __attribute__((packed)) {
  uchar sig_cnt; /* = 1 */
  uchar signature[64];
  uchar _sig_cnt; /* also 1 */
  uchar ro_signed_cnt; /* = 0 */
  uchar ro_unsigned_cnt; /* = 1 . System program */
  uchar acct_addr_cnt; /* = 3 */
  uchar fee_payer[32];
  uchar transfer_dest[32];
  uchar system_program[32]; /* = { 0 0 ...} */
  uchar recent_blockhash[32];
  uchar instr_cnt; /* = 1 */
  /* Start of instruction */
  struct __attribute__((packed)) {
    uchar prog_id; /* = 2 */
    uchar acct_cnt; /* = 2 */
    uchar from_acct; /* = 0 */
    uchar to_acct; /* = 1 */
    uchar data_sz; /* = 12 */
    uint  transfer; /* = 2 . SystemInstruction is bincode encoded, so the
                            discriminant is a u32, not a u8 */
    ulong lamports; /* variable */
  } _1;
} sol_transfer_t;

/* SOL_TRANSFER_LAMPORTS is the base amount of a system transfer.  The
   destination account does not exist yet, so the transfer has to leave
   it rent exempt (890,880 lamports for an empty account under the
   genesis rent parameters) or the transaction fails. */

#define SOL_TRANSFER_LAMPORTS (10000000UL)

typedef struct __attribute__((packed)) {
  uchar sig_cnt; /* = 1 */
  uchar signature[64];
  uchar _sig_cnt; /* also 1 */
  uchar ro_signed_cnt; /* = 0 */
  uchar ro_unsigned_cnt; /* = 2 . Compute Budget Program, SPL Token Program */
  uchar acct_addr_cnt; /* = 5 */
  uchar authority[32]; /* fee payer, also the token account owner */
  uchar transfer_src[32];
  uchar transfer_dest[32];
  uchar compute_budget_program[32]; /* = {COMPUTE_BUDGET_PROG_ID} */
  uchar token_program[32]; /* = {TOKEN_PROG_ID} */
  uchar recent_blockhash[32];
  uchar instr_cnt; /* = 2 */
  /* Start of instruction */
  struct __attribute__((packed)) {
    uchar prog_id; /* = 3 */
    uchar acct_cnt; /* = 0 */
    uchar data_sz; /* = 5 */
    uchar set_cu_limit; /* = 2 */
    uint  cus;
  } _1;
  /* Start of second instruction */
  struct __attribute__((packed)) {
    uchar prog_id; /* = 4 */
    uchar acct_cnt; /* = 3 */
    uchar src_acct; /* = 1 */
    uchar dest_acct; /* = 2 */
    uchar authority_acct; /* = 0 */
    uchar data_sz; /* = 9 */
    uchar transfer; /* = 3 . SPL Token Instruction::Transfer */
    ulong amount; /* variable */
  } _2;
} ptoken_transfer_t;

/* PTOKEN_TRANSFER_CUS bounds the compute cost of a p-token transfer.
   Without an explicit limit every transaction would be charged the
   200k CU per instruction default, which caps a block at a few hundred
   transactions and makes the benchmark measure nothing.  A transfer
   measures out at just over 200 CUs, so this leaves roughly a factor of
   two of headroom. */

#define PTOKEN_TRANSFER_CUS (500U)

static inline void
after_credit( fd_benchg_ctx_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  if( FD_UNLIKELY( !ctx->has_recent_blockhash ) ) return;

  *charge_busy = 1;

  int is_contending = fd_rng_float_c( ctx->rng ) < ctx->contending_fraction;
  ulong sender_idx = fd_ulong_if( is_contending, 0UL, ctx->sender_idx );

  float norm = 4.0f + fd_rng_float_norm( ctx->rng );
  if( FD_UNLIKELY( norm<0.0f ) ) norm = 0.0f;
  ulong cu_price_spread = (ulong)(ctx->cu_price_spread * norm);

  void * _txn = fd_chunk_to_laddr( ctx->mem, ctx->out_chunk );

  ulong   transaction_size = 0UL;
  uchar * recent_blockhash = NULL;

  switch( ctx->transaction_mode ) {
    case BENCHG_TRANSACTION_MODE_NOOP:
      {
        noop_t * txn = (noop_t *)_txn;

        txn->sig_cnt         = 1;
        txn->_sig_cnt        = 1;
        txn->ro_signed_cnt   = 0;
        txn->ro_unsigned_cnt = 1;
        txn->acct_addr_cnt   = 2;
        memcpy( txn->compute_budget_program, (uchar const[32]) { COMPUTE_BUDGET_PROG_ID }, 32UL );
        txn->instr_cnt       = 2;
        txn->_1.prog_id      = 1;
        txn->_1.acct_cnt     = 0;
        txn->_1.data_sz      = 9;
        txn->_1.set_cu_price = 3;
        txn->_2.prog_id      = 1;
        txn->_2.acct_cnt     = 0;
        txn->_2.data_sz      = 5;
        txn->_2.set_cu_limit = 2;
        txn->_2.cus          = 300;

        /* Variable */
        txn->_1.micro_lamports_per_cu = ctx->lamport_idx; /* Unique per transaction so they aren't duplicates */
        txn->_1.micro_lamports_per_cu += fd_ulong_if( is_contending, 1000000UL, 0UL ); /* +300 lamports */
        txn->_1.micro_lamports_per_cu += cu_price_spread;

        transaction_size = sizeof(noop_t);
        recent_blockhash = txn->recent_blockhash;
      }
      break;

    case BENCHG_TRANSACTION_MODE_SOL_TRANSFER:
      {
        sol_transfer_t * txn = (sol_transfer_t *)_txn;

        txn->sig_cnt         = 1;
        txn->_sig_cnt        = 1;
        txn->ro_signed_cnt   = 0;
        txn->ro_unsigned_cnt = 1;
        txn->acct_addr_cnt   = 3;
        memcpy( txn->transfer_dest, ctx->acct_public_keys[ sender_idx ].uc, 32UL );
        for( ulong j=0UL; j<32UL; j++ ) txn->transfer_dest[ j ] ^= 0xFF;
        memcpy( txn->system_program, (uchar const[32]) { SYS_PROG_ID }, 32UL );
        txn->instr_cnt       = 1;

        txn->_1.prog_id      = 2;
        txn->_1.acct_cnt     = 2;
        txn->_1.from_acct    = 0;
        txn->_1.to_acct      = 1;
        txn->_1.data_sz      = 12;
        txn->_1.transfer     = 2;

        txn->_1.lamports     = SOL_TRANSFER_LAMPORTS + ctx->lamport_idx;

        transaction_size = sizeof(sol_transfer_t);
        recent_blockhash = txn->recent_blockhash;
      }
      break;

    case BENCHG_TRANSACTION_MODE_PTOKEN_TRANSFER:
      {
        ptoken_transfer_t * txn = (ptoken_transfer_t *)_txn;

        txn->sig_cnt         = 1;
        txn->_sig_cnt        = 1;
        txn->ro_signed_cnt   = 0;
        txn->ro_unsigned_cnt = 2;
        txn->acct_addr_cnt   = 5;
        memcpy( txn->transfer_src,           ctx->token_accounts[ 2UL*sender_idx      ].uc, 32UL );
        memcpy( txn->transfer_dest,          ctx->token_accounts[ 2UL*sender_idx+1UL  ].uc, 32UL );
        memcpy( txn->compute_budget_program, (uchar const[32]) { COMPUTE_BUDGET_PROG_ID }, 32UL );
        memcpy( txn->token_program,          (uchar const[32]) { TOKEN_PROG_ID          }, 32UL );
        txn->instr_cnt       = 2;

        txn->_1.prog_id        = 3;
        txn->_1.acct_cnt       = 0;
        txn->_1.data_sz        = 5;
        txn->_1.set_cu_limit   = 2;
        txn->_1.cus            = PTOKEN_TRANSFER_CUS;

        txn->_2.prog_id        = 4;
        txn->_2.acct_cnt       = 3;
        txn->_2.src_acct       = 1;
        txn->_2.dest_acct      = 2;
        txn->_2.authority_acct = 0;
        txn->_2.data_sz        = 9;
        txn->_2.transfer       = 3;

        /* Unique per transaction so they aren't duplicates */
        txn->_2.amount         = ctx->lamport_idx;

        transaction_size = sizeof(ptoken_transfer_t);
        recent_blockhash = txn->recent_blockhash;
      }
      break;

    default:
      FD_LOG_ERR(( "Unknown transaction mode %i", ctx->transaction_mode ));
      break;
  }

  single_signer_hdr_t * txnh = (single_signer_hdr_t *)_txn;
  fd_memcpy( txnh->fee_payer,  ctx->acct_public_keys[ sender_idx ].uc, 32UL );
  fd_memcpy( recent_blockhash, ctx->recent_blockhash,                  32UL );

  fd_ed25519_sign( txnh->signature,
                   &(txnh->_sig_cnt),
                   transaction_size-65UL,
                   ctx->acct_public_keys[ sender_idx ].uc,
                   ctx->acct_private_keys[ sender_idx ].uc,
                   ctx->sha );

  fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, transaction_size, 0UL, 0UL, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, transaction_size, ctx->out_chunk0, ctx->out_wmark );

  ctx->sender_idx = (ctx->sender_idx + 1UL) % ctx->acct_cnt;
  if( FD_UNLIKELY( !ctx->sender_idx ) ) {
    if( FD_UNLIKELY( ctx->changed_blockhash ) ) {
      ctx->lamport_idx = 1UL+ctx->benchg_idx;
      ctx->changed_blockhash = 0;
      fd_memcpy( ctx->recent_blockhash, ctx->staged_blockhash, 32UL );
    } else {
      /* Increments of the number of generators so there are never
         duplicate transactions generated. */
      ctx->lamport_idx += ctx->benchg_cnt;
    }
  }
}

static inline void
during_frag( fd_benchg_ctx_t * ctx,
             ulong             in_idx FD_PARAM_UNUSED,
             ulong             seq    FD_PARAM_UNUSED,
             ulong             sig    FD_PARAM_UNUSED,
             ulong             chunk,
             ulong             sz     FD_PARAM_UNUSED,
             ulong             ctl    FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( !ctx->has_recent_blockhash ) ) {
    fd_memcpy( ctx->recent_blockhash, fd_chunk_to_laddr( ctx->mem, chunk ), 32UL );
    ctx->has_recent_blockhash = 1;
    ctx->changed_blockhash    = 0;
  } else {
    if( FD_UNLIKELY( !memcmp( ctx->recent_blockhash, fd_chunk_to_laddr( ctx->mem, chunk ), 32UL ) ) ) return;

    fd_memcpy( ctx->staged_blockhash, fd_chunk_to_laddr( ctx->mem, chunk ), 32UL );
    ctx->changed_blockhash    = 1;
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchg_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchg_ctx_t ), sizeof( fd_benchg_ctx_t ) );
  ctx->acct_public_keys = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );
  ctx->acct_private_keys = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * tile->benchg.accounts_cnt );
  ctx->token_accounts    = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pubkey_t ), sizeof( fd_pubkey_t ) * 2UL * tile->benchg.accounts_cnt );

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, (uint)tile->kind_id, 0UL ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  ctx->acct_cnt            = tile->benchg.accounts_cnt;
  ctx->transaction_mode    = tile->benchg.mode;
  ctx->contending_fraction = tile->benchg.contending_fraction;
  ctx->cu_price_spread     = tile->benchg.cu_price_spread;

  for( ulong i=0UL; i<ctx->acct_cnt; i++ ) {
    fd_memset( ctx->acct_private_keys[ i ].uc, 0, 32UL );
    FD_STORE( ulong, ctx->acct_private_keys[ i ].uc, i );
    fd_ed25519_public_from_private( ctx->acct_public_keys[ i ].uc, ctx->acct_private_keys[ i ].uc , ctx->sha );
  }

  if( FD_UNLIKELY( ctx->transaction_mode==BENCHG_TRANSACTION_MODE_PTOKEN_TRANSFER ) ) {
    for( ulong i=0UL; i<ctx->acct_cnt; i++ ) {
      fd_genesis_token_account_address( &ctx->token_accounts[ 2UL*i     ], i, 0UL );
      fd_genesis_token_account_address( &ctx->token_accounts[ 2UL*i+1UL ], i, 1UL );
    }
  }

  ctx->has_recent_blockhash = 0;

  ctx->sender_idx        = 0UL;
  ctx->lamport_idx       = 1UL+tile->kind_id;
  ctx->changed_blockhash = 0;

  ctx->benchg_cnt = fd_topo_tile_name_cnt( topo, "benchg" );
  ctx->benchg_idx = tile->kind_id;

  ctx->mem        = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_benchg_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_benchg_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_DURING_FRAG  during_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_benchg = {
  .name              = "benchg",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};
