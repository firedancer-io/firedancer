#include "fd_failover_proto.h"

#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/keyguard/fd_keyguard.h"

FD_STATIC_ASSERT( sizeof(FD_KEYGUARD_FAILOVER_CLIENT_DOMAIN)-1UL==FD_KEYGUARD_FAILOVER_DOMAIN_SZ, client_proof_domain );
FD_STATIC_ASSERT( sizeof(FD_KEYGUARD_FAILOVER_SERVER_DOMAIN)-1UL==FD_KEYGUARD_FAILOVER_DOMAIN_SZ, server_proof_domain );

int
fd_failover_hello_check( fd_failover_hello_t const * self,
                         fd_failover_hello_t const * peer ) {
  if( FD_UNLIKELY( self->version!=peer->version ) )                                return FD_FAILOVER_HELLO_ERR_VERSION;
  if( FD_UNLIKELY( self->holds>1 || peer->holds>1 ) )                              return FD_FAILOVER_HELLO_ERR_HOLDS;
  if( FD_UNLIKELY( self->mode!=FD_FAILOVER_MODE_ALPENGLOW ||
                   self->mode!=peer->mode ) )                                      return FD_FAILOVER_HELLO_ERR_MODE;
  if( FD_UNLIKELY( !self->boot_id || !peer->boot_id ) )                            return FD_FAILOVER_HELLO_ERR_BOOT_ID;
  if( FD_UNLIKELY( !fd_memeq( self->staked_pubkey, peer->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_STAKED;
  if( FD_UNLIKELY( self->boot_id==peer->boot_id ) )                                return FD_FAILOVER_HELLO_ERR_SELF;
  if( FD_UNLIKELY( self->holds && peer->holds ) )                                  return FD_FAILOVER_HELLO_ERR_BOTH_HOLD;
  return FD_FAILOVER_HELLO_OK;
}

void
fd_failover_admission_hash( fd_failover_admission_start_t const *     start,
                            uchar const *                            client_hello,
                            fd_failover_admission_challenge_t const * challenge,
                            uchar                                    out[ 32 ] ) {
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, start,        sizeof(*start)       );
  fd_sha256_append( sha, client_hello, start->client_hello_sz );
  fd_sha256_append( sha, challenge,    sizeof(*challenge)   );
  fd_sha256_fini( sha, out );
}

void
fd_failover_response_hash( uchar const   transcript[ 32 ],
                           uchar const   client_proof[ 64 ],
                           uchar const * server_flight,
                           ushort        server_flight_sz,
                           uchar         out[ 32 ] ) {
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, transcript,        32UL                     );
  fd_sha256_append( sha, client_proof,      64UL                     );
  fd_sha256_append( sha, &server_flight_sz, sizeof(server_flight_sz) );
  fd_sha256_append( sha, server_flight,     server_flight_sz         );
  fd_sha256_fini( sha, out );
}

void
fd_failover_proof_msg( uchar       out[ FD_KEYGUARD_FAILOVER_PROOF_SZ ],
                       int         server,
                       uchar const transcript[ 32 ] ) {
  fd_memcpy( out, server ? FD_KEYGUARD_FAILOVER_SERVER_DOMAIN : FD_KEYGUARD_FAILOVER_CLIENT_DOMAIN,
             FD_KEYGUARD_FAILOVER_DOMAIN_SZ );
  fd_memcpy( out+FD_KEYGUARD_FAILOVER_DOMAIN_SZ, transcript, 32UL );
}

int
fd_failover_handoff_request_decode( fd_failover_handoff_request_t * out,
                                    uchar const *                   payload,
                                    ulong                           payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_handoff_request_t) ) ) return 0;
  fd_failover_handoff_request_t request;
  fd_memcpy( &request, payload, sizeof(request) );
  if( FD_UNLIKELY( !request.handoff_id || !request.target_boot_id ) ) return 0;
  *out = request;
  return 1;
}

int
fd_failover_handoff_result_decode( fd_failover_handoff_result_t * out,
                                   uchar const *                  payload,
                                   ulong                          payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_handoff_result_t) ) ) return 0;
  fd_failover_handoff_result_t result;
  fd_memcpy( &result, payload, sizeof(result) );
  if( FD_UNLIKELY( !result.handoff_id ) ) return 0;
  *out = result;
  return 1;
}

ulong
fd_failover_demoted_encode( uchar *       out,
                            ulong         handoff_id,
                            ulong         target_boot_id,
                            ulong         last_vote_slot,
                            uchar const * state,
                            ulong         state_sz ) {
  if( FD_UNLIKELY( !state_sz || state_sz>FD_FAILOVER_ALPENGLOW_STATE_MAX ) ) return 0UL;

  fd_failover_demoted_t demoted = {
    .handoff_id     = handoff_id,
    .target_boot_id = target_boot_id,
    .last_vote_slot = last_vote_slot,
    .mode           = (uchar)FD_FAILOVER_MODE_ALPENGLOW,
    .state_len      = (ushort)state_sz,
  };
  fd_memcpy( out, &demoted, sizeof(demoted) );
  fd_memcpy( out+sizeof(demoted), state, state_sz );
  return sizeof(demoted)+state_sz;
}

int
fd_failover_demoted_decode( fd_failover_demoted_t * out,
                            uchar const *           payload,
                            ulong                   payload_sz ) {
  if( FD_UNLIKELY( payload_sz<sizeof(fd_failover_demoted_t) ||
                   payload_sz>FD_FAILOVER_DEMOTED_PAYLOAD_MAX ) ) return 0;

  fd_failover_demoted_t demoted;
  fd_memcpy( &demoted, payload, sizeof(demoted) );

  ulong state_sz = payload_sz-sizeof(fd_failover_demoted_t);
  /* The history itself is votor's to decode, the controller checks that
     the adopted history ends at last_vote_slot. */
  if( FD_UNLIKELY( (ulong)demoted.state_len!=state_sz ||
                   !state_sz || state_sz>FD_FAILOVER_ALPENGLOW_STATE_MAX ||
                   demoted.mode!=(uchar)FD_FAILOVER_MODE_ALPENGLOW ||
                   demoted.last_vote_slot==FD_FAILOVER_SLOT_NULL ) ) return 0;

  *out = demoted;
  return 1;
}

ulong
fd_failover_promote_ack_encode( uchar * out,
                                ulong   handoff_id ) {
  fd_failover_promote_ack_t ack = { .handoff_id=handoff_id };
  fd_memcpy( out, &ack, sizeof(ack) );
  return sizeof(ack);
}

ulong
fd_failover_promote_rejected_encode( uchar * out,
                                     ulong   handoff_id,
                                     uchar   reason ) {
  if( FD_UNLIKELY( reason==(uchar)FD_FAILOVER_REJECT_NONE || reason>=(uchar)FD_FAILOVER_REJECT_CNT ) ) return 0UL;
  fd_failover_promote_rejected_t rej = { .handoff_id=handoff_id, .reason=reason };
  fd_memcpy( out, &rej, sizeof(rej) );
  return sizeof(rej);
}

int
fd_failover_promote_ack_decode( fd_failover_promote_ack_t * out,
                                uchar const *               payload,
                                ulong                       payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_promote_ack_t) ) ) return 0;
  fd_memcpy( out, payload, sizeof(fd_failover_promote_ack_t) );
  return 1;
}

int
fd_failover_promote_rejected_decode( fd_failover_promote_rejected_t * out,
                                     uchar const *                    payload,
                                     ulong                            payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_promote_rejected_t) ) ) return 0;
  fd_failover_promote_rejected_t rej;
  fd_memcpy( &rej, payload, sizeof(rej) );
  if( FD_UNLIKELY( rej.reason==(uchar)FD_FAILOVER_REJECT_NONE || rej.reason>=(uchar)FD_FAILOVER_REJECT_CNT ) ) return 0;
  *out = rej;
  return 1;
}
