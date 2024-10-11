#include "fd_keyguard.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/txn/fd_compact_u16.h"

/* fd_keyguard_match fingerprints signing requests and checks them for
   ambiguity.

   Supported message types are as follows:

   - Legacy transaction messages
   - Version 0 transaction messages
   - Legacy shred signed payloads
   - Merkle shred roots
   - TLS CertificateVerify challenges
   - Gossip message signed payloads (CrdsData)

   ### Fake Signing Attacks

   The main goal of fd_keyguard_match is to defeat "fake signing"
   attacks.  These are attacks in which the keyguard signs a request for
   which the client is not authorized.  Such attacks use a combination
   of vulnerabilities:  Key reuse, and type confusion.

   Key reuse is particularly prevalent with the validator identity key,
   the hot Ed25519 key that a validator uses in almost all protocols
   that it actively participates in.

   Type confusion occurs when the message payload being signed can be
   interpreted as multiple different message types.  Usually, this is
   categorically prevented by using "signing domains".

   Such attacks are particularly dangerous to validators because their
   validator identity key holds an amount of native tokens to
   participate in Tower BFT voting.  In the worst case, an attacker
   could trick a validator into signing an innocuous message (e.g. a
   gossip message) that can also be interpreted as a transaction
   withdrawing these tokens.

   ### Code Verification

   The safety of this module is verified using a number of CBMC proofs
   composed via deductive reasoning.  These can be found in the
   verification directory of the repository.

   - fd_txn_minsz_proof verifies the constant FD_TXN_MIN_SERIALIZED_SZ.
   - fd_txn_ambiguity_gossip_proof verifies that gossip messages cannot
     be parsed as transactions.
   - fd_keyguard_match_txn_harness verifies that the txn fingerprinting
     logic is free of false negatives.
   - fd_keyguard_ambiguity_proof verifies that any input up to 2048 byte
     size are unambiguous, i.e. either detected by one or none of the
     fingerprinting functions.

   Under the hood, CBMC executes the keyguard logic with all possible
   inputs (>=2^16384 unique inputs) via symbolic execution.  The CBMC
   machine model also verifies that the code is free of common
   vulnerability classes (memory unsoundness, undefined behavior, …).

   As a result, we know with a high degree of certainty that type
   detection logic is free of false negatives.  For example, when
   fd_keyguard_match sees a transaction, it will always reliably detect
   it as one.  (fd_keyguard_match might also wrongly fingerprint
   arbitrary other inputs as, e.g. transactions.  But this is not a
   problem, as strict checks follow later on in fd_keyguard_authorize.)

   ### Deployment Context

   fd_keyguard_match is exposed to untrusted "signing request" inputs
   and implements the first line of authorization checks in the
   keyguard.  It is thus a critical component for securing the identity
   key.

   ### Implementation Approach

   This code looks awful and scary, but is carefully crafted to meet the
   aforementioned high assurance and formal verification requirements.

   Although parsers for the supported message types are available
   elsewhere in the codebase, they were not used here due to their time
   complexity exceeding the capabilities of CBMC.  The time complexity
   of all parsers in this compile unit is O(1), which allowed for
   complete CBMC coverage.

   TLDR:  The following code implements the least possible logic
          required to reliably detect types of identity key signing
          payloads without false negatives. */

FD_FN_PURE static int
fd_keyguard_payload_matches_txn_msg( uchar const * data,
                                     ulong         sz,
                                     int           sign_type ) {

  uchar const * end = data + sz;

  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;

  /* txn_msg_min_sz is the smallest valid size of a transaction msg. A
     transaction is the concatenation of (signature count, signatures,
     msg).  The smallest size of a txn is FD_TXN_MIN_SERIALIZED_SZ
     (formally proven with CBMC in fd_txn_minsz_proof.c).  We know the
     smallest sizes of "signature count" and "signatures", thus we can
     derive the smallest size of "msg". */

  ulong const txn_msg_min_sz =
      FD_TXN_MIN_SERIALIZED_SZ
    -  1UL   /* min sz of signature count (compact_u16 encoding) */
    - 64UL;  /* min sz of signature list (array of Ed25519 sigs) */
  if( sz<txn_msg_min_sz ) return 0;

  /* Message type check.

     Bit patterns of first bytes are as follows

     - 0aaaaaaa bbbbbbbb cccccccc           (Legacy txns)
     - 10000000 aaaaaaaa bbbbbbbb cccccccc  (v0     txns)

     Where 'a' are the bits that make up the 'required signature count'
       ... 'b'         ....                  'readonly signed count'
       ... 'c'         ....                  'readonly unsigned count' */

  uchar const * cursor    = data;
  uint          header_b0 = *cursor;
  cursor++;
  uint          sig_cnt;  /* sig count (ignoring compact_u16 encoding) */
  if( header_b0 & 0x80UL ) {
    /* Versioned message, only v0 recognized so far */
    if( (header_b0&0x7F)!=FD_TXN_V0 ) return 0;
    sig_cnt = *cursor;
    cursor++;
  } else {
    /* Legacy message */
    sig_cnt = header_b0;
  }

  /* There must be at least one signature. */
  if( sig_cnt==0U ) return 0;

  /* Check if signatures exceed txn size limit */
  ulong sig_sz;
  if( __builtin_umull_overflow( sig_cnt, 64UL, &sig_sz ) ) return 0;
  if( sig_sz > (FD_TXN_MTU-txn_msg_min_sz) ) return 0;

  /* Skip other fields */
  //uint ro_signed_cnt   = *cursor;
  cursor++;
  //uint ro_unsigned_cnt = *cursor;
  cursor++;

  if( cursor + 3 > end ) return 0;
  ulong addr_cnt_sz = fd_cu16_dec_sz( cursor, 3UL );
  if( !addr_cnt_sz ) return 0;
  ulong addr_cnt    = fd_cu16_dec_fixed( cursor, addr_cnt_sz );
  cursor += addr_cnt_sz;

  if( sig_cnt>addr_cnt ) return 0;

  return 1;
}

FD_FN_PURE static int
fd_keyguard_payload_matches_ping_msg( uchar const * data,
                                      ulong         sz,
                                      int           sign_type ) {
  return sign_type==FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 &&
         sz==48UL &&
         (memcmp( data, "SOLANA_PING_PONG", 16UL ) == 0);
}

FD_FN_PURE static int
fd_keyguard_payload_matches_prune_data( uchar const * data,
                                        ulong         sz,
                                        int           sign_type ) {

  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;

  ulong const static_sz = 80UL;
  if( sz < static_sz ) return 0;

  ulong prune_cnt = FD_LOAD( ulong, data+32UL );
  ulong expected_sz;
  if( __builtin_umull_overflow( prune_cnt,   32UL,      &expected_sz ) ) return 0;
  if( __builtin_uaddl_overflow( expected_sz, static_sz, &expected_sz ) ) return 0;
  if( sz != expected_sz ) return 0;

  return 1;
}

FD_FN_PURE static int
fd_keyguard_payload_matches_gossip( uchar const * data,
                                        ulong         sz,
                                        int           sign_type ) {

  /* All gossip messages except pings use raw signing */
  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;

  /* Every gossip message contains a 4 byte enum variant tag (at the
     beginning of the message) and a 32 byte public key (at an arbitrary
     location). */
  if( sz<36UL ) return 0;

  /* There probably won't ever be more than 32 different gossip message
     types. */
  if( (data[0] <0x20)
    & (data[1]==0x00)
    & (data[2]==0x00)
    & (data[3]==0x00) )
    return 1;

  return 0;
}

FD_FN_PURE static int
fd_keyguard_payload_matches_repair( uchar const * data,
                                    ulong         sz,
                                    int           sign_type ) {

  /* All repair messages except pings use raw signing */
  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;

  /* Every repair message contains a 4 byte enum variant tag (at the
     beginning of the message) and a 32 byte public key (at an arbitrary
     location). */
  if( sz<36UL ) return 0;

  /* There probably won't ever be more than 32 different repair message
     types. */
  if( (data[0] <0x20)
    & (data[1]==0x00)
    & (data[2]==0x00)
    & (data[3]==0x00) )
    return 1;

  return 0;
}

FD_FN_PURE int
fd_keyguard_payload_matches_shred( uchar const * data,
                                   ulong         sz,
                                   int           sign_type ) {
  (void)data;

  /* Note: Legacy shreds no longer relevant (drop_legacy_shreds) */

  /* FIXME: Sign Merkle shreds using SIGN_TYPE_SHA256_ED25519 (!!!) */
  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;
  if( sz != 32 ) return 0;

  return 1;
}

FD_FN_PURE int
fd_keyguard_payload_matches_tls_cv( uchar const * data,
                                    ulong         sz,
                                    int           sign_type ) {

  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;

  /* TLS CertificateVerify signing payload one of 3 sizes
     depending on hash function chosen */
  switch( sz ) {
  case 130UL: break;  /* Prefix + 32 byte hash */
  case 146UL: break;  /* Prefix + 48 byte hash */
  case 162UL: break;  /* Prefix + 64 byte hash */
  default:
    return 0;
  }

  /* Always prefixed with client or server pattern */
  static char const client_prefix[ 98 ] =
    "                                "  /* 32 spaces */
    "                                "  /* 32 spaces */
    "TLS 1.3, client CertificateVerify";

  static char const server_prefix[ 98 ] =
    "                                "  /* 32 spaces */
    "                                "  /* 32 spaces */
    "TLS 1.3, server CertificateVerify";
  int is_client = 0==memcmp( data, client_prefix, 98UL );
  int is_server = 0==memcmp( data, server_prefix, 98UL );
  return (is_client)|(is_server);
}

FD_FN_PURE int
fd_keyguard_payload_matches_bundle( uchar const * data,
                                    ulong         sz,
                                    int           sign_type ) {
  (void)data;

  if( sign_type != FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 ) return 0;
  if( sz!=9UL ) return 0;

  return 1;
}

FD_FN_PURE ulong
fd_keyguard_payload_match( uchar const * data,
                           ulong         sz,
                           int           sign_type ) {
  ulong res = 0UL;
  res |= fd_ulong_if( fd_keyguard_payload_matches_txn_msg   ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_TXN,    0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_gossip    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_GOSSIP, 0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_repair    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_REPAIR, 0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_prune_data( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_PRUNE,  0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_shred     ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_SHRED,  0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_tls_cv    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_TLS_CV, 0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_ping_msg  ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_PING,   0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_bundle    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_BUNDLE, 0 );
  return res;
}
