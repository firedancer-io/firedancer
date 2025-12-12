#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h

/* fd_solfuzz_private.h contains internal components for the solfuzz
   Protobuf shim. */

#include "fd_solfuzz.h"
#include "../../features/fd_features.h"
#include "../../../ballet/nanopb/pb_encode.h"
#include "../../../ballet/nanopb/pb_decode.h"
#include "generated/context.pb.h"

#if FD_HAS_FLATCC
#include "flatcc/flatcc_builder.h"
#include "flatbuffers/generated/context_reader.h"
#endif

FD_PROTOTYPES_BEGIN

#undef ns
#define SOL_COMPAT_NS(x) FLATBUFFERS_WRAP_NAMESPACE(fd_org_solana_sealevel_v2, x)

#define SOL_COMPAT_V2_SUCCESS (0)
#define SOL_COMPAT_V2_FAILURE (-1)

/* Creates / overwrites an account in funk given an input account state.
   On success, loads the account into acc.  Optionally, reject any
   zero-lamport accounts from being loaded in. */
fd_account_meta_t *
fd_solfuzz_pb_load_account( fd_accdb_user_t *                 accdb,
                            fd_funk_txn_xid_t const *         xid,
                            fd_exec_test_acct_state_t const * state,
                            uchar                             reject_zero_lamports );

/* Activates features in the runtime given an input feature set.  Fails
   if a passed-in feature is unknown / not supported. */
int
fd_solfuzz_pb_restore_features( fd_features_t *                    features,
                                fd_exec_test_feature_set_t const * feature_set );

#if FD_HAS_FLATCC
/* Flatbuffers variant of the above. This function call should never
   fail (all passed in features should be supported). Throws FD_LOG_ERR
   if any unsupported features are inputted. */
void
fd_solfuzz_fb_restore_features( fd_features_t *                   features,
                                SOL_COMPAT_NS(FeatureSet_table_t) feature_set );
#endif

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

typedef int( exec_test_run_fb_fn_t )( fd_solfuzz_runner_t *, void const * );

#if FD_HAS_FLATCC
/* Returns SOL_COMPAT_V2_SUCCESS on success and SOL_COMPAT_V2_FAILURE on
   failure */
static inline int
fd_solfuzz_fb_execute_wrapper( fd_solfuzz_runner_t *   runner,
                               void const *            input,
                               exec_test_run_fb_fn_t * exec_test_run_fn ) {
  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    flatcc_builder_reset( runner->fb_builder );
    return exec_test_run_fn( runner, input );
  } FD_SPAD_FRAME_END;
}
#endif /* FD_HAS_FLATCC */

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
