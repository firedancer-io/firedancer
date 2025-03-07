#include "fd_exec_test_utils.h"
#include "fd_pack_test.h"
#include "../../../disco/pack/fd_pack.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../disco/pack/fd_compute_budget_program.h"


const fd_acct_addr_t cbp_prog_id = { .b= { COMPUTE_BUDGET_PROG_ID } };

ulong
fd_exec_pack_cpb_test_run( fd_exec_instr_test_runner_t * _unused FD_PARAM_UNUSED,
                           void const *                  input_,
                           void **                       output_,
                           void *                        output_buf,
                           ulong                         output_bufsz ){
  fd_exec_test_pack_compute_budget_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_pack_compute_budget_effects_t **      output = fd_type_pun( output_ );

  ulong output_end = (ulong) output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_pack_compute_budget_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_pack_compute_budget_effects_t),
                                sizeof (fd_exec_test_pack_compute_budget_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    return 0UL;
  }
  *effects = (fd_exec_test_pack_compute_budget_effects_t) FD_EXEC_TEST_PACK_COMPUTE_BUDGET_EFFECTS_INIT_ZERO;

  fd_compute_budget_program_state_t cbp_state[1];
  fd_compute_budget_program_init( cbp_state );
do {
  int ok = 1;
  for( ulong i=0UL; i<input->instr_datas_count; ++i ){
    pb_bytes_array_t * instr_data = input->instr_datas[i];
    // Reject if any of the instructions fail to parse
    if( !fd_compute_budget_program_parse( instr_data->bytes, instr_data->size, cbp_state ) ) {
      ok = 0;
      break;
    };
  }

  if( !ok ) {
    effects->is_empty = 1;
    break;
  }
  ulong rewards;
  uint compute_unit_limit;
  ulong loaded_accounts_data_cost = 0UL;
  fd_compute_budget_program_finalize( cbp_state,
                                      input->instr_datas_count,
                                      &rewards,
                                      &compute_unit_limit,
                                      &loaded_accounts_data_cost );
  effects->rewards = rewards;

  /* TODO: Make this query compile-time  */
  uint cbp_instr_cost = (uint)fd_pack_builtin_query( &cbp_prog_id, 0UL )->cost_per_instr;

  /* FEATURE GATE SIMULATIONS

    Pack is (currently) not feature-aware. Any feature
    gate that touches pack code in Agave is hardcoded
    (if implemented) in FD.

    We manually check and apply overrides for the
    following scenarios:

      1. The feature is active, but not implemented in pack.
        Here we simulate the feature being implemented in pack.

      2. The feature is inactive, but implemented in pack
        Here we simulate the feature being unimplemented in pack.

  FIXME: Remove this entirely once pack becomes feature-aware. */

  if( input->has_features ){
    fd_features_t features[1];

    fd_exec_test_restore_feature_flags( features, &input->features );

#define FEATURE_ACTIVE( feature ) ( features->feature != FD_FEATURE_DISABLED )

    /* reserve_minimal_cus_for_builtin_instructions
       changes default CU limit behaviors. This scenario 1
       override assumes all instructions are builtin CBP
       instructions, which is true because we would have
       terminated in the fd_compute_budget_program_parse
       for-loop above otherwise. */
    if( FEATURE_ACTIVE( reserve_minimal_cus_for_builtin_instructions ) ){
      if( cbp_state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU ) {
        compute_unit_limit = cbp_instr_cost * input->instr_datas_count;
      }
    }

#undef FEATURE_ACTIVE
  /* END OF FEATURE GATE SIMULATIONS */
  }


  effects->compute_unit_limit = compute_unit_limit;

  /*  If not set, use defaults.  See:
      https://github.com/firedancer-io/firedancer/blob/688cb04408cf20b0600d900900cdbebebd181e5b/src/ballet/pack/fd_compute_budget_program.h#L64-L70
      https://github.com/firedancer-io/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/runtime-transaction/src/compute_budget_instruction_details.rs#L49-L101
  */
  effects->heap_sz             = !!( cbp_state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_HEAP )           ? cbp_state->heap_size : FD_VM_HEAP_DEFAULT;
  effects->loaded_acct_data_sz = !!( cbp_state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_LOADED_DATA_SZ ) ? cbp_state->loaded_acct_data_sz : FD_COMPUTE_BUDGET_MAX_LOADED_DATA_SZ;
} while(0);

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );

  *output = effects;
  return actual_end - (ulong) output_buf;

}
