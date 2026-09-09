#include "fd_keyguard.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../flamenco/gossip/fd_gossip_value.h"
#include "../../discof/repair/fd_repair.h"

/* fd_keyguard_match fingerprints signing requests and checks them for
   ambiguity.

   Supported message types are as follows:

   - Legacy transaction messages
   - Version 0 transaction messages
   - Version 1 transaction messages
   - Legacy shred signed payloads
   - Merkle shred roots
   - TLS CertificateVerify challenges
   - Gossip message signed payloads (CrdsData)
   - Agave tower-file payloads

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

   The safety of this module can be verified using a number of CBMC
   proofs composed via deductive reasoning.

   - fd_txn_minsz_proof verifies the constant FD_TXN_MIN_SERIALIZED_SZ.
   - fd_txn_ambiguity_gossip_proof verifies that gossip messages cannot
     be parsed as transactions.
   - fd_keyguard_match_txn_harness verifies that the txn fingerprinting
     logic is free of false negatives.
   - fd_keyguard_ambiguity_proof verifies that bounded inputs are
     unambiguous, i.e. either detected by one or none of the
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
     - 10000001 aaaaaaaa bbbbbbbb cccccccc  (v1     txns)

     Where 'a' are the bits that make up the 'required signature count'
       ... 'b'         ....                  'readonly signed count'
       ... 'c'         ....                  'readonly unsigned count' */

  uchar const * cursor    = data;
  uint          header_b0 = *cursor;
  cursor++;
  uint          sig_cnt;  /* sig count (ignoring compact_u16 encoding) */
  if( header_b0 & 0x80UL ) {
    /* Versioned message, v0 and v1 recognized so far */
    uint version = header_b0 & 0x7F;
    if( version!=FD_TXN_V0 && version!=FD_TXN_V1 ) return 0;

    /* Check transaction V1 separately because the layout is
       different. We do the same checks for V1 and V0/legacy, just in
       a different code branch. */
    if( version==FD_TXN_V1 ) {
      sig_cnt = *cursor;
      cursor++;

      /* There must be at least one signature. */
      if( sig_cnt==0U ) return 0;

      /* Check if the signatures exceed the V1 limit */
      if( sig_cnt>FD_TXN_SIG_MAX ) return 0;

      /* Skip other fields */
      //uint ro_signed_cnt      = *cursor;
      cursor++;
      //uint ro_unsigned_cnt    = *cursor;
      cursor++;
      //uint config_mask        = fd_uint_load_4( cursor );
      cursor += 4UL;
      //uchar const * blockhash = cursor;
      cursor += FD_TXN_BLOCKHASH_SZ;

      if( cursor + 2 > end ) return 0;
      ulong instr_cnt = *cursor;
      cursor++;
      ulong addr_cnt  = *cursor;
      cursor++;

      /* Check if the instructions exceed the V1 limit */
      if( instr_cnt>FD_TXN_INSTR_MAX ) return 0;

      /* Check if the addresses exceed the V1 limit */
      if( addr_cnt>FD_TXN_ACCT_ADDR_MAX ) return 0;

      if( sig_cnt>addr_cnt ) return 0;

      return 1;
    }

    if( sz>FD_TXN_MTU_V0 ) return 0;
    sig_cnt = *cursor;
    cursor++;
  } else {
    /* Legacy message */
    if( sz>FD_TXN_MTU_V0 ) return 0;
    sig_cnt = header_b0;
  }

  /* There must be at least one signature. */
  if( sig_cnt==0U ) return 0;

  /* Check if signatures exceed txn size limit */
  ulong sig_sz;
  if( __builtin_umull_overflow( sig_cnt, 64UL, &sig_sz ) ) return 0;
  if( sig_sz > (FD_TXN_MTU_V0-txn_msg_min_sz) ) return 0;

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
  return sign_type==FD_KEYGUARD_SIGN_TYPE_ED25519 &&
         sz==32UL &&
         (memcmp( data, "SOLANA_PING_PONG", 16UL ) == 0);
}

FD_FN_PURE static int
fd_keyguard_payload_matches_pong_msg( uchar const * data,
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
  if( sz > FD_GOSSIP_MTU ) return 0;

  ulong const static_sz = 106UL;
  if( sz < static_sz ) return 0;

  if( FD_LOAD( ulong, data )!=18UL ) return 0;
  if(  memcmp( data+8UL, "\xffSOLANA_PRUNE_DATA", 18UL ) ) return 0;

  ulong prune_cnt = FD_LOAD( ulong, data+58UL );
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
  if( sz > 1188UL-64UL ) return 0;

  /* Every gossip message contains a 4 byte enum variant tag (at the
     beginning of the message) and a 32 byte public key (at an arbitrary
     location). */
  if( sz<36UL ) return 0;

  uint tag = FD_LOAD( uint, data );

  return tag<FD_GOSSIP_VALUE_CNT;
}

FD_FN_PURE static int
fd_keyguard_payload_matches_repair( uchar const * data,
                                    ulong         sz,
                                    int           sign_type ) {

  /* All repair messages except pings use raw signing */
  if( sign_type != FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;
  if( sz > FD_REPAIR_MAX_PREIMAGE_SZ ) return 0;

  /* Every repair message contains a 4 byte enum variant tag (at the
     beginning of the message) and a 32 byte public key (at an arbitrary
     location). */
  if( sz<36UL ) return 0;

  /* Ensure that the kind matches a possible repair request. */
  uint kind = FD_LOAD( uint, data );
  if( (kind==FD_REPAIR_KIND_SHRED)
    | (kind==FD_REPAIR_KIND_HIGHEST_SHRED)
    | (kind==FD_REPAIR_KIND_ORPHAN)
    | (kind==AG_REPAIR_KIND_PARENT_FEC_COUNT)
    | (kind==AG_REPAIR_KIND_FEC_ROOT)
    | (kind==AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID) )
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
fd_keyguard_payload_matches_ag_vote( uchar const * data,
                                     ulong         sz,
                                     int           sign_type ) {

  /* Alpenglow vote payload produced by ag_vote_signing_ser:

     u8  tag            (1..5, WireConsensusMessageKind vote tags)
     u64 slot
     [32 bytes block id] only for notar (1) and notar fallback (4)
     u16 shred_version */

  if( sign_type != FD_KEYGUARD_SIGN_TYPE_BLS ) return 0;
  if( sz!=11UL && sz!=43UL ) return 0;
  uchar tag = data[ 0 ];
  if( tag<1 || tag>5 ) return 0;
  int has_hash = ( tag==1 ) | ( tag==4 );
  return has_hash ? ( sz==43UL ) : ( sz==11UL );
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

FD_FN_PURE int
fd_keyguard_payload_matches_event( uchar const * data,
                                   ulong         sz,
                                   int           sign_type ) {
  static char const sign_prefix[ 100 ] =
    "                                "  /* 32 spaces */
    "                                "  /* 32 spaces */
    "Firedancer event challenge-response";

  if( sz!=sizeof(sign_prefix)+217UL ) return 0;
  if( sign_type!=FD_KEYGUARD_SIGN_TYPE_ED25519 ) return 0;
  if( 0!=memcmp( data, sign_prefix, sizeof(sign_prefix) ) ) return 0;
  return 1;
}

static int
fd_keyguard_tower_varint( uchar const * data,
                          ulong         sz,
                          ulong *       off,
                          ulong *       value ) {
  ulong out = 0UL;
  for( uint shift=0U; shift<=63U; shift+=7U ) {
    if( FD_UNLIKELY( *off>=sz ) ) return 0;
    uchar byte = data[ (*off)++ ];
    if( FD_UNLIKELY( shift==63U && byte>1U ) ) return 0;
    out |= (ulong)(byte & 0x7FU) << shift;
    if( FD_LIKELY( !(byte & 0x80U) ) ) {
      if( FD_UNLIKELY( shift && !(byte & 0x7FU) ) ) return 0;
      *value = out;
      return 1;
    }
  }
  return 0;
}

#define TOWER_PAYLOAD_MIN (1815UL) /* one vote, no root, 1-byte offset */

static int
fd_keyguard_payload_matches_tower_file( uchar const * data,
                                        ulong         sz,
                                        int           sign_type ) {
  if( FD_UNLIKELY( sign_type!=FD_KEYGUARD_SIGN_TYPE_ED25519 ) ) return 0;
  if( FD_UNLIKELY( sz<TOWER_PAYLOAD_MIN || sz>FD_KEYGUARD_SIGN_REQ_MTU ) ) return 0;

#define TOWER_REQUIRE(n) do { if( FD_UNLIKELY( (n)>sz-off ) ) return 0; } while(0)
#define TOWER_LOAD(T,v) do { TOWER_REQUIRE( sizeof(T) ); (v)=FD_LOAD( T, data+off ); off+=sizeof(T); } while(0)
#define TOWER_SKIP(n) do { TOWER_REQUIRE( (n) ); off+=(n); } while(0)

  ulong off = 0UL;
  TOWER_SKIP( 32UL );
  ulong threshold_depth; TOWER_LOAD( ulong, threshold_depth );
  if( FD_UNLIKELY( threshold_depth!=8UL ) ) return 0;
  double threshold_size = 2.0/3.0;
  ulong threshold_bits; TOWER_LOAD( ulong, threshold_bits );
  if( FD_UNLIKELY( threshold_bits!=FD_LOAD( ulong, &threshold_size ) ) ) return 0;

  TOWER_REQUIRE( 65UL );
  if( FD_UNLIKELY( !fd_mem_iszero( data+off, 65UL ) ) ) return 0;
  off += 65UL;

  ulong votes_cnt; TOWER_LOAD( ulong, votes_cnt );
  if( FD_UNLIKELY( !votes_cnt || votes_cnt>31UL ) ) return 0;
  ulong slots[ 31 ];
  uint  confs[ 31 ];
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    TOWER_LOAD( ulong, slots[ i ] );
    TOWER_LOAD( uint,  confs[ i ] );
    if( FD_UNLIKELY( slots[i]==ULONG_MAX || !confs[i] || confs[i]>31U ) ) return 0;
    if( FD_UNLIKELY( i && ( slots[i]<=slots[i-1UL] ||
                            confs[i]>=confs[i-1UL] ||
                            slots[i]-slots[i-1UL]>(1UL<<confs[i-1UL]) ) ) ) return 0;
  }
  ulong newest_slot = slots[ votes_cnt-1UL ];
  for( ulong i=0UL; i+1UL<votes_cnt; i++ ) {
    if( FD_UNLIKELY( newest_slot-slots[i]>(1UL<<confs[i]) ) ) return 0;
  }

  uchar has_root; TOWER_LOAD( uchar, has_root );
  if( FD_UNLIKELY( has_root>1U ) ) return 0;
  ulong root = ULONG_MAX;
  if( has_root ) TOWER_LOAD( ulong, root );
  if( FD_UNLIKELY( has_root && root==ULONG_MAX ) ) return 0;

  ulong authorized_voters_cnt; TOWER_LOAD( ulong, authorized_voters_cnt );
  if( FD_UNLIKELY( authorized_voters_cnt ) ) return 0;

  TOWER_REQUIRE( 32UL*48UL );
  if( FD_UNLIKELY( !fd_mem_iszero( data+off, 32UL*48UL ) ) ) return 0;
  off += 32UL*48UL;

  ulong prior_voters_idx; TOWER_LOAD( ulong, prior_voters_idx );
  uchar prior_voters_empty; TOWER_LOAD( uchar, prior_voters_empty );
  if( FD_UNLIKELY( prior_voters_idx!=31UL || prior_voters_empty!=1U ) ) return 0;

  ulong epoch_credits_cnt; TOWER_LOAD( ulong, epoch_credits_cnt );
  if( FD_UNLIKELY( epoch_credits_cnt ) ) return 0;

  TOWER_REQUIRE( 16UL );
  if( FD_UNLIKELY( !fd_mem_iszero( data+off, 16UL ) ) ) return 0;
  off += 16UL;

  uint last_vote_kind; TOWER_LOAD( uint, last_vote_kind );
  if( FD_UNLIKELY( last_vote_kind!=3U ) ) return 0;

  ulong compact_root; TOWER_LOAD( ulong, compact_root );
  if( FD_UNLIKELY( compact_root!=root ) ) return 0;

  TOWER_REQUIRE( 1UL );
  if( FD_UNLIKELY( data[off++]!=votes_cnt ) ) return 0;
  ulong slot = root==ULONG_MAX ? 0UL : root;
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    ulong offset;
    if( FD_UNLIKELY( !fd_keyguard_tower_varint( data, sz, &off, &offset ) ) ) return 0;
    int repeats_slot = !offset && (i || root!=ULONG_MAX);
    if( FD_UNLIKELY( repeats_slot || offset>ULONG_MAX-slot ) ) return 0;
    if( FD_UNLIKELY( i && offset>(1UL<<(ulong)confs[i-1UL]) ) ) return 0;
    slot += offset;
    TOWER_REQUIRE( 1UL );
    if( FD_UNLIKELY( slot!=slots[i] || data[off++]!=confs[i] ) ) return 0;
  }

  TOWER_SKIP( 32UL );
  uchar timestamp_option; TOWER_LOAD( uchar, timestamp_option );
  if( FD_UNLIKELY( timestamp_option!=1U ) ) return 0;
  long timestamp; TOWER_LOAD( long, timestamp );
  TOWER_SKIP( 32UL );

  ulong last_timestamp_slot; TOWER_LOAD( ulong, last_timestamp_slot );
  long  last_timestamp;      TOWER_LOAD( long,  last_timestamp      );
  if( FD_UNLIKELY( last_timestamp_slot!=slots[votes_cnt-1UL] || last_timestamp!=timestamp || off!=sz ) ) return 0;

#undef TOWER_REQUIRE
#undef TOWER_LOAD
#undef TOWER_SKIP

  return 1;
}

#undef TOWER_PAYLOAD_MIN

FD_FN_PURE ulong
fd_keyguard_payload_match( uchar const * data,
                           ulong         sz,
                           int           sign_type ) {
  ulong res = 0UL;
  res |= fd_ulong_if( fd_keyguard_payload_matches_txn_msg   ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_TXN,     0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_gossip    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_GOSSIP,  0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_repair    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_REPAIR,  0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_prune_data( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_PRUNE,   0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_shred     ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_SHRED,   0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_tls_cv    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_TLS_CV,  0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_ping_msg  ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_PING,    0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_pong_msg  ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_PONG,    0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_bundle    ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_BUNDLE,  0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_event     ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_EVENT,   0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_ag_vote   ( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_AG_VOTE, 0 );
  res |= fd_ulong_if( fd_keyguard_payload_matches_tower_file( data, sz, sign_type ), FD_KEYGUARD_PAYLOAD_TOWER,   0 );
  return res;
}
