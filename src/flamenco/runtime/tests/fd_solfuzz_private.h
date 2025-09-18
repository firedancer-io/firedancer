#ifndef HEADER_fd_src_flamenco_runtime_tests_harness_fd_solfuzz_private_h
#define HEADER_fd_src_flamenco_runtime_tests_harness_fd_solfuzz_private_h

/* fd_solfuzz_private.h contains internal components for the solfuzz
   Protobuf shim. */

#include "fd_solfuzz.h"
#include "../../features/fd_features.h"
#include "../../../ballet/nanopb/pb_encode.h"
#include "../../../ballet/nanopb/pb_decode.h"
#include "generated/context.pb.h"

FD_PROTOTYPES_BEGIN

/* Creates / overwrites an account in funk given an input account state.
   On success, loads the account into `acc`. Optionally, reject any zero-lamport
   accounts from being loaded in. */
int
fd_runtime_fuzz_load_account( fd_txn_account_t *                acc,
                              fd_funk_t *                       funk,
                              fd_funk_txn_t *                   funk_txn,
                              fd_exec_test_acct_state_t const * state,
                              uchar                             reject_zero_lamports );

/* Activates features in the runtime given an input feature set. Fails if a passed-in feature
   is unknown / not supported. */
int
fd_runtime_fuzz_restore_features( fd_features_t *                    features,
                                  fd_exec_test_feature_set_t const * feature_set );

void
fd_runtime_fuzz_refresh_program_cache( fd_exec_slot_ctx_t *              slot_ctx,
                                       fd_exec_test_acct_state_t const * acct_states,
                                       ulong                             acct_states_count,
                                       fd_spad_t *                       runtime_spad );

typedef ulong( exec_test_run_fn_t )( fd_solfuzz_runner_t *,
                                     void const *,
                                     void **,
                                     void *,
                                     ulong );

static inline void
fd_solfuzz_execute_wrapper( fd_solfuzz_runner_t * runner,
                            void * input,
                            void ** output,
                            exec_test_run_fn_t * exec_test_run_fn ) {

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

#endif /* HEADER_fd_src_flamenco_runtime_tests_harness_fd_solfuzz_private_h */
