#include "fd_solfuzz_private.h"
#include "fd_votor_harness.h"
#include "generated/votor.pb.h"
#include "../../../choreo/votor/ag_vote_serde.h"

int
fd_solfuzz_votor_vote_deserialize( fd_solfuzz_runner_t * runner,
                                   uchar *               out,
                                   ulong *               out_sz,
                                   uchar const *         in,
                                   ulong                 in_sz ) {
  (void)runner;

  fd_exec_test_votor_vote_deserialize_context_t ctx[1] = {0};
  if( FD_UNLIKELY( !sol_compat_decode_lenient( ctx, in, in_sz, &fd_exec_test_votor_vote_deserialize_context_t_msg ) ) ) return 0;

  uchar const * data    = ctx->data.bytes;
  ulong         data_sz = ctx->data.size;

  fd_exec_test_votor_vote_deserialize_effects_t effects = FD_EXEC_TEST_VOTOR_VOTE_DESERIALIZE_EFFECTS_INIT_ZERO;

  /* valid means the node would accept the vote.  FD's votor tile rejects
     a shred version mismatch and an identity (infinity) signature right
     after ag_vote_de; Agave rejects the former in its wire decoder and
     the latter in signature verification.  Apply both here so both
     sides answer the same question. */

  ag_vote_t vote;
  if( ag_vote_de( &vote, data, data_sz )==AG_VOTE_DE_SUCCESS &&
      ag_vote_shred_version( &vote )==ctx->expected_shred_version &&
      !blst_p2_is_inf( ag_vote_sig( &vote ) ) ) {
    effects.valid         = true;
    effects.has_vote      = true;
    effects.shred_version = ag_vote_shred_version( &vote );

    fd_exec_test_votor_vote_t * v = &effects.vote;
    ulong slot = ag_vote_slot( &vote );
    switch( vote.kind ) {
    case AG_VOTE_KIND_NOTAR:
      v->which_vote = FD_EXEC_TEST_VOTOR_VOTE_NOTAR_TAG;
      v->vote.notar.slot = slot;
      fd_memcpy( v->vote.notar.block_id, ag_vote_block_hash( &vote ), sizeof(ag_block_hash_t) );
      break;
    case AG_VOTE_KIND_FINAL:
      v->which_vote = FD_EXEC_TEST_VOTOR_VOTE_FINAL_VOTE_TAG;
      v->vote.final_vote.slot = slot;
      break;
    case AG_VOTE_KIND_SKIP:
      v->which_vote = FD_EXEC_TEST_VOTOR_VOTE_SKIP_TAG;
      v->vote.skip.slot = slot;
      break;
    case AG_VOTE_KIND_NOTAR_FALLBACK:
      v->which_vote = FD_EXEC_TEST_VOTOR_VOTE_NOTAR_FALLBACK_TAG;
      v->vote.notar_fallback.slot = slot;
      fd_memcpy( v->vote.notar_fallback.block_id, ag_vote_block_hash( &vote ), sizeof(ag_block_hash_t) );
      break;
    case AG_VOTE_KIND_SKIP_FALLBACK:
      v->which_vote = FD_EXEC_TEST_VOTOR_VOTE_SKIP_FALLBACK_TAG;
      v->vote.skip_fallback.slot = slot;
      break;
    default:
      FD_LOG_CRIT(( "unexpected vote kind %u", vote.kind ));
    }

    /* Report the signature as it appeared on the wire, so both sides
       report the same bytes without re-encoding the point.  It is the
       192 bytes just before the trailing shred_version. */

    fd_memcpy( effects.signature, data+data_sz-sizeof(ushort)-FD_BLS_SIG_SZ, FD_BLS_SIG_SZ );
  }

  return !!sol_compat_encode( out, out_sz, &effects, &fd_exec_test_votor_vote_deserialize_effects_t_msg );
}
