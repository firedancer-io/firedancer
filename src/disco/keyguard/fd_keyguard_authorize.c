#include "fd_keyguard.h"
#include "fd_keyguard_client.h"
#include "../bundle/fd_bundle_crank_constants.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../waltz/tls/fd_tls.h"

struct fd_keyguard_sign_req {
  fd_keyguard_authority_t * authority;
};

typedef struct fd_keyguard_sign_req fd_keyguard_sign_req_t;

static int
fd_keyguard_authorize_vote_txn( fd_keyguard_authority_t const * authority,
                                uchar const *                   data,
                                ulong                           sz,
                                int                             sign_type ) {
  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;
  if( sz > FD_TXN_MTU ) return 0;
  /* Each vote transaction may have 1 or 2 signers.  The first byte in
     the transaction message is the number of signers. */
  ulong off = 0UL;
  uchar signer_cnt = data[off];
  if( signer_cnt!=1 && signer_cnt!=2 ) return 0;
  if( signer_cnt==1 && sz<=139 ) return 0;
  if( signer_cnt==2 && sz<=171 ) return 0;
  /* The authority's public key will be the first listed account in the
     transaction message. */

  /* r/o signers = 1 when there are 2 signers and 1 otherwise. */
  off++;
  if( data[off]!=signer_cnt-1 ) return 0;

  /* There will always be 1 r/o unsigned account. */
  off++;
  if( data[off]!=1 ) return 0;

  /* The only accounts should be the 1 or 2 signers, the vote account,
     and the vote program.  The number of accounts is represented as a
     compact u16. */
  off++;
  ulong bytes = fd_cu16_dec_sz( data+off, 3UL );
  if( bytes!=1UL ) return 0;
  ulong acc_cnt = 2+signer_cnt;
  if( data[off]!=acc_cnt ) return 0;

  /* The first account should always be the authority's public key. */
  off++;
  ulong acct_off = off;
  if( memcmp( authority->identity_pubkey, data + acct_off, 32 ) ) return 0;

  /* Each transaction account key is listed out and is followed by a 32
     byte blockhash.  The instruction count is after this. */
  off += (acc_cnt+1) * 32;
  bytes = fd_cu16_dec_sz( data+off, 3UL );
  uchar instr_cnt = data[ off ];
  if( bytes!=1UL ) return 0;
  if( instr_cnt!=1 ) return 0;

  /* The program id will be the first byte of the instruction payload
     and should be the vote program. */
  off++;
  uchar program_id = data[ off ];
  if( program_id != acc_cnt-1 ) return 0;
  ulong program_acct_off = 4UL + (program_id * 32UL);
  if( memcmp( &fd_solana_vote_program_id, data+program_acct_off, 32 ) ) return 0;

  off++;
  bytes = fd_cu16_dec_sz( data+off, 3UL );
  if( bytes!=1UL ) return 0;

  /* Vote account count will always be 2.  One byte is used to list the
     account count for the transaction and 1 byte for each account. */
  if( data[ off ] != 2 ) return 0;
  off += 3UL;

  /* Instr data sz */
  bytes = fd_cu16_dec_sz( data+off, 3UL );
  off += bytes;
  if( data[off]!=14 ) return 0;

  return 1;
}

static int
fd_keyguard_authorize_gossip( fd_keyguard_authority_t const * authority,
                              uchar const *                   data,
                              ulong                           sz,
                              int                             sign_type ) {
  /* FIXME Add gossip message authorization here */
  (void)authority; (void)data; (void)sz; (void)sign_type;
  return 1;
}

static int
fd_keyguard_authorize_bundle_crank_txn( fd_keyguard_authority_t const * authority,
                                        uchar const *                   data,
                                        ulong                           sz,
                                        int                             sign_type ) {
  static const uchar disc1[ 8 ] = { FD_BUNDLE_CRANK_DISC_INIT_TIP_DISTR };
  static const uchar disc2[ 8 ] = { FD_BUNDLE_CRANK_DISC_CHANGE_TIP_RCV };
  static const uchar disc3[ 8 ] = { FD_BUNDLE_CRANK_DISC_CHANGE_BLK_BLD };

  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;

  (void)authority;
  /* TODO: we can check a lot more bytes */
  switch( sz ) {
    case (FD_BUNDLE_CRANK_2_SZ-65UL):
      return fd_memeq( data+FD_BUNDLE_CRANK_2_IX1_DISC_OFF-65UL, disc2, 8UL ) &&
             fd_memeq( data+FD_BUNDLE_CRANK_2_IX2_DISC_OFF-65UL, disc3, 8UL );
    case (FD_BUNDLE_CRANK_3_SZ-65UL):
      return fd_memeq( data+FD_BUNDLE_CRANK_3_IX1_DISC_OFF-65UL, disc1, 8UL ) &&
             fd_memeq( data+FD_BUNDLE_CRANK_3_IX2_DISC_OFF-65UL, disc2, 8UL ) &&
             fd_memeq( data+FD_BUNDLE_CRANK_3_IX3_DISC_OFF-65UL, disc3, 8UL );
    default:
      return 0;
  }
}

static int
fd_keyguard_authorize_ping( fd_keyguard_authority_t const * authority,
                            uchar const *                   data,
                            ulong                           sz,
                            int                             sign_type ) {
  (void)authority;
  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;
  if( sz != 32 ) return 0;
  if( 0!=memcmp( data, "SOLANA_PING_PONG", 16 ) ) return 0;
  return 1;
}

static int
fd_keyguard_authorize_pong( fd_keyguard_authority_t const * authority,
                            uchar const *                   data,
                            ulong                           sz,
                            int                             sign_type ) {
  (void)authority;
  if( sign_type != FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) return 0;
  if( sz != 48 ) return 0;
  if( 0!=memcmp( data, "SOLANA_PING_PONG", 16 ) ) return 0;
  return 1;
}

static int
fd_keyguard_authorize_gossip_prune( fd_keyguard_authority_t const * authority,
                                    uchar const *                   data,
                                    ulong                           sz,
                                    int                             sign_type ) {
  if( FD_UNLIKELY( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) ) return 0;
  /* Prune messages always begin with the node's pubkey */
  if( sz<40UL ) return 0;
  if( 0!=memcmp( authority->identity_pubkey, data, 32 ) ) return 0;
  return 1;
}

static int
fd_keyguard_authorize_repair( fd_keyguard_authority_t const * authority,
                              uchar const *                   data,
                              ulong                           sz,
                              int                             sign_type ) {

  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;
  if( sz<80 ) return 0;

  uint          discriminant = fd_uint_load_4( data );
  uchar const * sender       = data+4;

  if( discriminant< 8 ) return 0; /* window_index is min ID */
  if( discriminant>11 ) return 0; /* ancestor_hashes is max ID */

  if( 0!=memcmp( authority->identity_pubkey, sender, 32 ) ) return 0;

  return 1;
}

static int
fd_keyguard_authorize_tls_cv( fd_keyguard_authority_t const * authority FD_PARAM_UNUSED,
                              uchar const *                   data,
                              ulong                           sz,
                              int                             sign_type ) {
  if( FD_UNLIKELY( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) ) return 0;
  if( FD_UNLIKELY( sz != 130 ) ) return 0;

  /* validate client prefix against fd_tls */
  return fd_memeq( fd_tls13_cli_sign_prefix, data, sizeof(fd_tls13_cli_sign_prefix) );
}

int
fd_keyguard_payload_authorize( fd_keyguard_authority_t const * authority,
                               uchar const *                   data,
                               ulong                           sz,
                               int                             role,
                               int                             sign_type ) {

  if( sz > FD_KEYGUARD_SIGN_REQ_MTU ) {
    FD_LOG_WARNING(( "oversz signing request (role=%d sz=%lu)", role, sz ));
    return 0;
  }

  /* Identify payload type */

  ulong payload_mask = fd_keyguard_payload_match( data, sz, sign_type );
  int   match_cnt    = fd_ulong_popcnt( payload_mask );
  if( FD_UNLIKELY( payload_mask==0UL ) ) {
    FD_LOG_WARNING(( "unrecognized payload type (role=%#x)", (uint)role ));
  }

  int is_ambiguous = match_cnt != 1;

 /* We know that gossip, gossip prune, and repair messages are
    ambiguous, so allow mismatches here. */
  int is_gossip_repair =
    0==( payload_mask &
        (~( FD_KEYGUARD_PAYLOAD_GOSSIP |
            FD_KEYGUARD_PAYLOAD_REPAIR |
            FD_KEYGUARD_PAYLOAD_PRUNE  ) ) );
  /* Also allow ambiguities between shred and gossip ping messages
     until shred sign type is fixed... */
  int is_shred_ping =
    0==( payload_mask &
        (~( FD_KEYGUARD_PAYLOAD_SHRED |
            FD_KEYGUARD_PAYLOAD_PING  ) ) );

  if( FD_UNLIKELY( is_ambiguous && !is_gossip_repair && !is_shred_ping ) ) {
    FD_LOG_WARNING(( "ambiguous payload type (role=%#x mask=%#lx)", (uint)role, payload_mask ));
  }

  /* Authorize each role */

  switch( role ) {

  case FD_KEYGUARD_ROLE_TXSEND: {
    int txn_ok = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_TXN )) &&
                 fd_keyguard_authorize_vote_txn( authority, data, sz, sign_type );
    int tls_ok = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_TLS_CV )) &&
                 fd_keyguard_authorize_tls_cv( authority, data, sz, sign_type );
    if( FD_UNLIKELY( !txn_ok && !tls_ok ) ) {
      FD_LOG_WARNING(( "unauthorized payload type for send (mask=%#lx)", payload_mask ));
      return 0;
    }
    return 1;
  }

  case FD_KEYGUARD_ROLE_GOSSIP: {
    int ping_ok   = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_PING )) &&
                    fd_keyguard_authorize_ping( authority, data, sz, sign_type );
    int pong_ok   = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_PONG )) &&
                    fd_keyguard_authorize_pong( authority, data, sz, sign_type );
    int prune_ok  = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_PRUNE )) &&
                    fd_keyguard_authorize_gossip_prune( authority, data, sz, sign_type );
    int gossip_ok = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_GOSSIP )) &&
                    fd_keyguard_authorize_gossip( authority, data, sz, sign_type );
    if( FD_UNLIKELY( !ping_ok && !pong_ok && !prune_ok && !gossip_ok ) ) {
      FD_LOG_WARNING(( "unauthorized payload type for gossip (mask=%#lx)", payload_mask ));
      return 0;
    }
    return 1;
  }

  case FD_KEYGUARD_ROLE_REPAIR: {
    int ping_ok   = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_PING )) &&
                    fd_keyguard_authorize_ping( authority, data, sz, sign_type );
    int pong_ok   = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_PONG )) &&
                    fd_keyguard_authorize_pong( authority, data, sz, sign_type );
    int repair_ok = (!!( payload_mask & FD_KEYGUARD_PAYLOAD_REPAIR )) &&
                    fd_keyguard_authorize_repair( authority, data, sz, sign_type );
    if( FD_UNLIKELY( !ping_ok && !pong_ok && !repair_ok ) ) {
      FD_LOG_WARNING(( "unauthorized payload type for repair (mask=%#lx)", payload_mask ));
      return 0;
    }
    return 1;
  }

  case FD_KEYGUARD_ROLE_LEADER:
    if( FD_UNLIKELY( payload_mask != FD_KEYGUARD_PAYLOAD_SHRED ) ) {
      FD_LOG_WARNING(( "unauthorized payload type for leader (mask=%#lx)", payload_mask ));
      return 0;
    }
    /* no further restrictions on shred */
    return 1;

  case FD_KEYGUARD_ROLE_BUNDLE:
    if( FD_UNLIKELY( payload_mask != FD_KEYGUARD_PAYLOAD_BUNDLE ) ) {
      FD_LOG_WARNING(( "unauthorized payload type for bundle (mask=%#lx)", payload_mask ));
      return 0;
    }
    /* no further restrictions on bundle */
    return 1;

  case FD_KEYGUARD_ROLE_EVENT:
    if( FD_UNLIKELY( payload_mask != FD_KEYGUARD_PAYLOAD_EVENT ) ) {
      FD_LOG_WARNING(( "unauthorized payload type for event (mask=%#lx)", payload_mask ));
      return 0;
    }
    /* no further restrictions on event */
    return 1;

  case FD_KEYGUARD_ROLE_BUNDLE_CRANK:
    if( FD_UNLIKELY( payload_mask != FD_KEYGUARD_PAYLOAD_TXN ) ) {
      FD_LOG_WARNING(( "unauthorized payload type for event (mask=%#lx)", payload_mask ));
      return 0;
    }
    return fd_keyguard_authorize_bundle_crank_txn( authority, data, sz, sign_type );

  default:
    FD_LOG_WARNING(( "unsupported role=%#x", (uint)role ));
    return 0;
  }
}
