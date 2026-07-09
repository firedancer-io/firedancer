#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h

/* fd_solfuzz_private.h contains internal components for the solfuzz
   Protobuf shim. */

#include "fd_solfuzz.h"
#include "../../features/fd_features.h"
#include "../../../third_party/nanopb/pb_encode.h"
#include "../../../third_party/nanopb/pb_decode.h"
#include "generated/context.pb.h"

FD_PROTOTYPES_BEGIN

/* Creates / overwrites an account in the accdb given an input account
   state.  On success, loads the account into acc.  Optionally, reject
   any zero-lamport accounts from being loaded in. */
int
fd_solfuzz_pb_load_account( fd_runtime_t *                    runtime,
                            fd_accdb_t *                      accdb,
                            fd_accdb_fork_id_t                fork_id,
                            fd_exec_test_acct_state_t const * state,
                            ulong                             acc_idx );

/* Restores the fee rate governor in the bank from the given protobuf
   fee rate governor. */
void
fd_solfuzz_pb_restore_fee_rate_governor( fd_bank_t *                              bank,
                                         fd_exec_test_fee_rate_governor_t const * fee_rate_governor );

/* Initializes the blockhash queue in the bank from the given protobuf
   blockhash queue entries. */
void
fd_solfuzz_pb_restore_blockhash_queue( fd_bank_t *                                    bank,
                                       fd_exec_test_blockhash_queue_entry_t const *   entries,
                                       ulong                                          entries_cnt );

/* Retrieves the slot number from the clock sysvar account within the
   given account states list.  Throws FD_LOG_ERR if the clock sysvar
   is not found or is malformed. */
ulong
fd_solfuzz_pb_get_slot( fd_exec_test_acct_state_t const * acct_states,
                        ulong                             acct_states_cnt );

/* Activates features in the runtime given an input feature set.  Fails
   if a passed-in feature is unknown / not supported. */
int
fd_solfuzz_pb_restore_features( fd_features_t *                    features,
                                fd_exec_test_feature_set_t const * feature_set );

/* Due to how Firedancer's VM CU accounting works, when
   virtual_address_space_adjustments is enabled and execution
   fails with the CU meter exhausted, we cannot compare the data
   region of the accounts with Agave. This function clears the
   data field on each captured account in this case. */
void
fd_solfuzz_direct_mapping_handle_cu_exhaustion( fd_solfuzz_runner_t *       runner,
                                                ulong                       cu_avail,
                                                int                         has_err,
                                                fd_exec_test_acct_state_t * accounts,
                                                pb_size_t                   accounts_cnt );

/* Create feature accounts for all active features in the given feature
   set, with an activation slot of 0.  Skip any feature whose pubkey
   already appears in acct_states so the caller-supplied state wins
   (matches solfuzz-agave's accounts_to_store filter). */
void
fd_solfuzz_pb_create_feature_accounts( fd_accdb_t *                       accdb,
                                       fd_accdb_fork_id_t                 fork_id,
                                       fd_exec_test_feature_set_t const * feature_set,
                                       fd_exec_test_acct_state_t const *  acct_states,
                                       pb_size_t                          acct_states_count );

typedef ulong( exec_test_run_pb_fn_t )( fd_solfuzz_runner_t *,
                                        void const *,
                                        void **,
                                        void *,
                                        ulong );

static inline void
fd_solfuzz_pb_execute_wrapper( fd_solfuzz_runner_t *   runner,
                               void const *            input,
                               void **                 output,
                               exec_test_run_pb_fn_t * exec_test_run_fn ) {
  ulong out_bufsz = 100000000;  /* 100 MB */
  void * out0 = fd_spad_alloc( runner->spad, 1UL, out_bufsz );
  FD_TEST( out_bufsz <= fd_spad_alloc_max( runner->spad, 1UL ) );

  ulong out_used = exec_test_run_fn( runner, input, output, out0, out_bufsz );
  if( FD_UNLIKELY( !out_used ) ) {
    *output = NULL;
  }
}

/* Utils */

static FD_FN_UNUSED void *
sol_compat_decode_lenient( void *               decoded,
                           uchar const *        in,
                           ulong                in_sz,
                           pb_msgdesc_t const * decode_type ) {
  pb_istream_t istream = pb_istream_from_buffer( in, in_sz );
  int decode_ok = pb_decode_ex( &istream, decode_type, decoded, PB_DECODE_NOINIT );
  if( !decode_ok ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  return decoded;
}

static FD_FN_UNUSED void *
sol_compat_decode( void *               decoded,
                   uchar const *        in,
                   ulong                in_sz,
                   pb_msgdesc_t const * decode_type ) {
  pb_istream_t istream = pb_istream_from_buffer( in, in_sz );
  int decode_ok = pb_decode_ex( &istream, decode_type, decoded, PB_DECODE_NOINIT );
  if( !decode_ok ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  ulong size;
  if( FD_UNLIKELY( !pb_get_encoded_size( &size, decode_type, decoded ) ) ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  if( FD_UNLIKELY( size != in_sz ) ) {
    pb_release( decode_type, decoded );
    return NULL;
  }
  return decoded;
}

static FD_FN_UNUSED void const *
sol_compat_encode( uchar *              out,
                   ulong *              out_sz,
                   void const *         to_encode,
                   pb_msgdesc_t const * encode_type ) {
  pb_ostream_t ostream = pb_ostream_from_buffer( out, *out_sz );
  int encode_ok = pb_encode( &ostream, encode_type, to_encode );
  if( !encode_ok ) {
    return NULL;
  }
  *out_sz = ostream.bytes_written;
  return to_encode;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h */
