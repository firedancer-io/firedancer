#include "fd_cost_tracker_harness.h"
#include "fd_solfuzz_private.h"
#include "generated/cost_model.pb.h"
#include "../fd_runtime.h"
#include "../fd_cost_tracker.h"

ulong
fd_solfuzz_pb_calc_allocated_accounts_data_size_run(
    fd_solfuzz_runner_t * runner,
    void const *          input_,
    void **               output_,
    void *                output_buf,
    ulong                 output_bufsz
) {
  fd_exec_test_calc_allocated_accounts_data_size_input_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_calc_allocated_accounts_data_size_output_t **     output = fd_type_pun( output_ );

  fd_banks_clear_bank( runner->banks, runner->bank, 4UL );

  runner->bank->f.slot = 1UL;
  FD_TEST( input->has_features );
  fd_features_t * features = &runner->bank->f.features;
  fd_exec_test_feature_set_t const * feature_set = &input->features;
  FD_TEST( fd_solfuzz_pb_restore_features( features, feature_set ) );

  fd_txn_in_t * txn_in = fd_spad_alloc( runner->spad, alignof(fd_txn_in_t), sizeof(fd_txn_in_t) );
  memset( txn_in, 0, sizeof(fd_txn_in_t) );

  fd_txn_p_t * txn_p = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
  memset( txn_p, 0, sizeof(fd_txn_p_t) );

  fd_txn_t * txn = TXN( txn_p );
  ushort instr_cnt = (ushort)input->instructions_count;
  if( FD_UNLIKELY( instr_cnt>FD_TXN_INSTR_MAX ) ) return 0UL;

  txn->instr_cnt     = instr_cnt;
  txn->acct_addr_cnt = instr_cnt;
  txn->acct_addr_off = 0;

  ushort off = (ushort)( instr_cnt * 32U );
  if( FD_UNLIKELY( off>FD_TPU_MTU ) ) return 0UL;

  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_exec_test_program_instruction_t const * pb_instr = &input->instructions[ i ];
    memcpy( txn_p->payload + i * 32U, pb_instr->program_id, 32 );
    txn->instr[ i ].program_id = (uchar)i;
    txn->instr[ i ].acct_cnt   = 0;
    txn->instr[ i ].acct_off   = 0;
    if( pb_instr->data!=NULL ) {
      ushort data_sz = (ushort)pb_instr->data->size;
      if( FD_UNLIKELY( off+data_sz>FD_TPU_MTU ) ) return 0UL;
      memcpy( txn_p->payload + off, pb_instr->data->bytes, data_sz );
      txn->instr[ i ].data_off = off;
      txn->instr[ i ].data_sz  = data_sz;
      off = (ushort)( off + data_sz );
    } else {
      txn->instr[ i ].data_off = 0;
      txn->instr[ i ].data_sz  = 0;
    }
  }
  txn_in->txn = txn_p;

  ulong res = fd_calculate_allocated_accounts_data_size( runner->bank, txn_in );

  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  fd_exec_test_calc_allocated_accounts_data_size_output_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_calc_allocated_accounts_data_size_output_t),
                                sizeof (fd_exec_test_calc_allocated_accounts_data_size_output_t) );
  if( FD_UNLIKELY( _l > output_end ) ) return 0UL;
  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  memset( effects, 0, sizeof(fd_exec_test_calc_allocated_accounts_data_size_output_t) );
  effects->allocated_accounts_data_size = res;

  *output = effects;
  return actual_end - (ulong)output_buf;
}
