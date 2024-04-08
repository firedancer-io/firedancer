#ifndef HEADER_fd_src_ballet_pack_fd_compute_budget_program_h
#define HEADER_fd_src_ballet_pack_fd_compute_budget_program_h
#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"

/* This header contains utility functions for parsing compute budget program
   instructions from a transaction. I.e. given a transaction, what is its
   compute budget limit (in compute units) and what is the additional reward
   for including it?  Unfortunately, due to the way compute budget program
   instructions are included in transactions, this is a per-transaction
   stateful process.

   This code is designed for high-performance use and so only error checks data
   coming from the transaction. */


/* In general, compute budget instructions can occur at most once in a
   transaction.  If an instruction is duplicated, the transaction is malformed
   and fails.  However, there's an exception to this rule, which is that
   RequestUnitsDeprecated counts as both a SetComputeUnitLimit and a
   SetComputeUnitPrice instruction.  These flags are used to keep track of what
   instructions have been seen so far.
   Have I seen a ... */
#define FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU             ((ushort)0x01) /* ... SetComputeUnitLimit ... */
#define FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_FEE            ((ushort)0x02) /* ... SetComputeUnitPrice ... */
#define FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_HEAP           ((ushort)0x04) /* ... RequestHeapFrame ... */
#define FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_TOTAL_FEE      ((ushort)0x08) /* ... RequestUnitsDeprecated ... */
                                                                            /* ... so far? */


/* NOTE: THE FOLLOWING CONSTANTS ARE CONSENSUS CRITICAL AND CANNOT BE
   CHANGED WITHOUT COORDINATING WITH SOLANA LABS. */

/* base58 decode of ComputeBudget111111111111111111111111111111 */
static const uchar FD_COMPUTE_BUDGET_PROGRAM_ID[FD_TXN_ACCT_ADDR_SZ] = {
  0x03,0x06,0x46,0x6f,0xe5,0x21,0x17,0x32,0xff,0xec,0xad,0xba,0x72,0xc3,0x9b,0xe7,
  0xbc,0x8c,0xe5,0xbb,0xc5,0xf7,0x12,0x6b,0x2c,0x43,0x9b,0x3a,0x40,0x00,0x00,0x00
};

/* Any requests for larger heap frames must be a multiple of 1k or the
   transaction is malformed. */
#define FD_COMPUTE_BUDGET_HEAP_FRAME_GRANULARITY          (1024UL)
/* SetComputeUnitPrice specifies the price in "micro-lamports," which is
   10^(-6) lamports, so 10^(-15) SOL. */
#define FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT     (1000000UL)

#define FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT         ( 200000UL)
#define FD_COMPUTE_BUDGET_MAX_CU_LIMIT                   (1400000UL)

/* ---- End consensus-critical constants */


struct fd_compute_budget_program_private_state {
  /* flags: Which instructions have been parsed so far in this transaction? See
     above for their meaning. */
  ushort  flags;
  /* compute_budge_instr_cnt: How many compute budget instructions have been
     parsed so far? compute_budget_instr_cnt in [0, 3]. */
  ushort  compute_budget_instr_cnt;
  /* compute_units: if SET_CU is in flags, this stores the total requested
     compute units for the whole transaction. Otherwise 0. Realistically should
     be less than 12M, but there's nothing enforcing that at this stage. */
  uint    compute_units;
  /* total_fee: if SET_TOTAL_FEE is in flags, this stores the total additional
     fee for the transaction. Otherwise 0. */
  uint    total_fee;
  /* heap_size: if SET_HEAP is in flags, this stores the size in bytes of the
     BPF heap used for executing this transaction. Otherwise, 0. Must be a
     multiple of 1024. */
  uint    heap_size;
  /* micro_lamports_per_cu: if SET_FEE is in flags but SET_TOTAL_FEE is not,
     this stores the requested prioritization fee in micro-lamports per compute
     unit. Otherwise, 0. */
  ulong   micro_lamports_per_cu;
};
typedef struct fd_compute_budget_program_private_state fd_compute_budget_program_state_t;

/* fd_compute_budge_program_init: initializes an
   fd_compute_budget_program_state_t to prepare it for parsing a transaction.
   Also equivalent to just initializing the state on the stack with = {0}. */
static inline void fd_compute_budget_program_init( fd_compute_budget_program_state_t * state ) {
  fd_compute_budget_program_state_t zero = {0};
  *state = zero;
}
/* fd_compute_budget_program_parse: Parses a single ComputeBudgetProgram
   instruction.  Updates the state stored in state.  Returns 0 if the
   instruction was invalid, which means the transaction should fail.
   instr_data points to the first byte of the instruction data from the
   transaction.  data_sz specifies the length of the instruction data, so
   instr_data[ i ] for i in [0, data_sz) gives the instruction data. */
static inline int
fd_compute_budget_program_parse( uchar const * instr_data,
                                 ulong         data_sz,
                                 fd_compute_budget_program_state_t * state ) {
  if( FD_UNLIKELY( data_sz<5 ) ) return 0;
  switch( *instr_data ) {
    case 0:
      /* Parse a RequestUnitsDeprecated instruction */
      if( FD_UNLIKELY( data_sz!=9 ) ) return 0;
      if( FD_UNLIKELY( (state->flags & (FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU | FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_FEE))!=0 ) )
        return 0;
      state->compute_units = *(uint*)(instr_data+1);
      state->total_fee     = *(uint*)(instr_data+5);
      if( FD_UNLIKELY( state->compute_units > FD_COMPUTE_BUDGET_MAX_CU_LIMIT ) ) return 0;
      state->flags |= (FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU | FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_FEE |
                                                               FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_TOTAL_FEE);
      state->compute_budget_instr_cnt++;
      return 1;
    case 1:
      /* Parse a RequestHeapFrame instruction */
      if( FD_UNLIKELY( data_sz!=5 ) ) return 0;
      if( FD_UNLIKELY( (state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_HEAP)!=0 ) ) return 0;
      state->heap_size = *(uint*)(instr_data+1);
      if( (state->heap_size%FD_COMPUTE_BUDGET_HEAP_FRAME_GRANULARITY) ) return 0;
      state->flags |= FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_HEAP;
      state->compute_budget_instr_cnt++;
      return 1;
    case 2:
      /* Parse a SetComputeUnitLimit instruction */
      if( FD_UNLIKELY( data_sz!=5 ) ) return 0;
      if( FD_UNLIKELY( (state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU)!=0 ) ) return 0;
      state->compute_units = *(uint*)(instr_data+1);
      if( FD_UNLIKELY( state->compute_units > FD_COMPUTE_BUDGET_MAX_CU_LIMIT ) ) return 0;
      state->flags |= FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU;
      state->compute_budget_instr_cnt++;
      return 1;
    case 3:
      /* Parse a SetComputeUnitPrice instruction */
      if( FD_UNLIKELY( data_sz!=9 ) ) return 0;
      if( FD_UNLIKELY( (state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_FEE)!=0 ) ) return 0;
      state->micro_lamports_per_cu = *(ulong*)(instr_data+1);
      state->flags |= FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_FEE;
      state->compute_budget_instr_cnt++;
      return 1;
    default:
      return 0;
  }
}

/* fd_compute_budget_program_finalize: digests the state that resulted from
   processing all of the ComputeBudgetProgram instructions in a transaction to
   compute the total priority rewards for the transaction.  state must point to
   a previously initialized fd_compute_budget_program_state_t.  instr_cnt is the
   total number of instructions in the transaction, including
   ComputeBudgetProgram instructions.  out_rewards and out_compute must be
   non-null.  The total priority rewards for the transaction (i.e. not counting
   the per-signature fee) is stored in out_rewards.  The maximum number of
   compute units this transaction can consume is stored in out_compute.  If the
   transaction execution has not completed by this limit, it is terminated and
   considered failed. */
static inline void
fd_compute_budget_program_finalize( fd_compute_budget_program_state_t const * state,
                                    ulong                                     instr_cnt,
                                    ulong *                                   out_rewards,
                                    uint *                                    out_compute ) {
  ulong cu_limit = 0UL;
  if( FD_LIKELY( (state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU)==0U ) ) {
    /* Use default compute limit */
    cu_limit = (instr_cnt - state->compute_budget_instr_cnt) * FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT;
  } else cu_limit = state->compute_units;

  cu_limit = fd_ulong_min( cu_limit, FD_COMPUTE_BUDGET_MAX_CU_LIMIT );

  *out_compute = (uint)cu_limit;

  /* Note: Prior to feature flag use_default_units_in_fee_calculation
     (e.g. Solana mainnet today), the per-instruction version of the CU
     limit is used as the actual CU limit, but a flat amount of 1.4M CUs
     is used to calculate the fee when no limit is provided. */
#if PRE_USE_DEFAULT_UNITS_IN_FEE_CALCULATION
  if( FD_LIKELY( (state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU)==0U ) ) {
    cu_limit = FD_COMPUTE_BUDGET_MAX_CU_LIMIT;
  }
#endif

  ulong total_fee = 0UL;
  if( FD_LIKELY( (state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_TOTAL_FEE)==0U ) ) {
    /* We need to compute max(ceil((cu_limit * micro_lamports_per_cu)/10^6),
       ULONG_MAX).  Unfortunately, the product can overflow.  Solana solves
       this by doing the arithmetic with ultra-wide integers, but that puts a
       128-bit division on the critical path.  Gross.  It's frustrating because
       the overflow case likely results in a transaction that's so expensive
       nobody can afford it anyways, but we should not break compatibility with
       Solana over this.  Instead we'll do the arithmetic carefully:
       Let cu_limit = c_h*10^6 + c_l, where 0 <= c_l < 10^6.
       Similarly, let micro_lamports_per_cu = p_h*10^6 + p_l, where
       0 <= p_l < 10^6.  Since cu_limit < 2^32, c_h < 2^13;
       micro_lamports_per_cu < 2^64, so p_h<2^45.

       ceil( (cu_limit * micro_lamports_per_cu)/10^6)
              = ceil( ((c_h*10^6+c_l)*(p_h*10^6+p_l))/10^6 )
              = c_h*p_h*10^6 + c_h*p_l + c_l*p_h + ceil( (c_l*p_l)/10^6 )
       c_h*p_h < 2^58, so we can compute it with normal multiplication.
       If c_h*p_h > floor(ULONG_MAX/10^6), then we know c_h*p_h*10^6 will hit
       the saturation point.  The "cross" terms are less than 2^64 by
       construction (since we divided by 10^6 and then multiply by something
       strictly less than 10^6).  c_l*p_l < 10^12 < 2^40, so that's safe as
       well.
       In fact, the sum of the right three terms is no larger than:
       floor((2^32-1)/10^6)*(10^6-1) + (10^6-1)*floor((2^64-1)/10^6) + 10^6-1
        == 0xffffef3a08574e4c < 2^64, so we can do the additions without
       worrying about overflow.
       Of course, we still need to check the final addition of the first term
       with the remaining terms.  As a bonus, all of the divisions can now be
       done via "magic multiplication."

       Note that this computation was done before I was aware of the
       1.4M CU limit.  Taking that limit into account could make the
       code a little cleaner, but we'll just keep the version that
       supports CU limits up to UINT_MAX, since I'm sure the limit will
       go up someday. */
    do {
      ulong c_h  =                     cu_limit / FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT;
      ulong c_l  =                     cu_limit % FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT;
      ulong p_h  = state->micro_lamports_per_cu / FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT;
      ulong p_l  = state->micro_lamports_per_cu % FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT;

      ulong hh = c_h * p_h;
      if( FD_UNLIKELY( hh>(ULONG_MAX/FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT) ) ) {
        total_fee = ULONG_MAX;
        break;
      }
      hh *= FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT;

      ulong hl = c_h*p_l + c_l*p_h;
      ulong ll = (c_l*p_l + FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT - 1UL)/FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT;
      ulong right_three_terms = hl + ll;

      total_fee = hh + right_three_terms;
      if( FD_UNLIKELY( total_fee<hh ) ) total_fee = ULONG_MAX;
    } while( 0 );
  } else total_fee = state->total_fee;
  *out_rewards = total_fee;
}

#endif /* HEADER_fd_src_ballet_pack_fd_compute_budget_program_h */
