#include "fd_pack_test.h"
#include "../../../ballet/pack/fd_compute_budget_program.h"

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

  fd_compute_budget_program_state_t cbp[1];
  fd_compute_budget_program_init( cbp );
do {

  int ok = 1;
  for( ulong i=0UL; i<input->instr_datas_count; ++i ){
    pb_bytes_array_t * instr_data = input->instr_datas[i];
    // Reject 
    if( !fd_compute_budget_program_parse( instr_data->bytes, instr_data->size, cbp ) ) {
      ok = 0;
      break;
    };
  }

  if( !ok ) {
    break;
  }
  ulong rewards;
  uint compute_unit_limit;
  fd_compute_budget_program_finalize( cbp,
                                      input->instr_datas_count,
                                      &rewards,
                                      &compute_unit_limit
                                      );
  effects->rewards = rewards;
  effects->compute_unit_limit = compute_unit_limit;
} while(0);

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );

  *output = effects;
  return actual_end - (ulong) output_buf;

}
