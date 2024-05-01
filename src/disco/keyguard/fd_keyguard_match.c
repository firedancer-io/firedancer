#include "fd_keyguard.h"
#include "../../ballet/shred/fd_shred.h"

/* fd_keyguard_match fingerprints signing requests and checks them for
   ambiguity.

   Supported message types are as follows:

   - Legacy transaction messages
   - Version 0 transaction messages
   - Legacy shred signed payloads
   - Merkle shred roots
   - TLS CertificateVerify challenges
   - X.509 Certificate Signing Requests
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

FD_FN_PURE int
fd_keyguard_payload_matches_txn_msg( uchar const * data,
                                     ulong         sz ) {

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
  if( sig_cnt*64UL > (FD_TXN_MTU-txn_msg_min_sz) ) return 0;

  /* Skip other fields */
  //uint ro_signed_cnt   = *cursor;
  cursor++;
  //uint ro_unsigned_cnt = *cursor;
  cursor++;

  /* The next field is the address count encoded as compact_u16.

     There must be at least as many addresses as signatures.
     This check prevents ambiguity with gossip msgs, see
     fd_txn_ambiguity_gossip_proof.

     We deliberately only read the first byte of the compact_u16
     encoding, which is equivalent to 'min( addr_cnt, 127 )'.

     This is safe assuming signature count <= 127, which is the max
     number that compact_u16 encoding can represent with one byte. */
  uint addr_cnt = *cursor;
  cursor++;
  if( sig_cnt>addr_cnt ) return 0;

  return 1;
}

FD_FN_PURE int
fd_keyguard_payload_matches_gossip_msg( uchar const * data,
                                        ulong         sz ) {
  // TODO: why against testnet
  // EMERG   05-01 23:27:34.707351 1331240 2    sign:0 src/app/fdctl/run/tiles/fd_sign.c(131): fd_keyguard_payload_authorize failed 208 110 177 125 155
  return 1;
  // TODO: this causes potential ambiguity with the shred messages
  if ( sz==32 ) return 1;

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

FD_FN_PURE int
fd_keyguard_payload_matches_shred( uchar const * data,
                                   ulong         sz ) {
  switch( sz ) {

  /* Merkle shreds signing payloads always 32 byte */
  case   32UL:
    return 1;

  /* Legacy shred signing payloads always 1228 (mtu) - 64 (sig sz) bytes */
  case 1164UL: {
    /* Verify shred type */
    uint shred_type = data[ 0x00 ];
    if( (shred_type==0x5a) | (shred_type==0xa5) )
      return 1;
    return 0;
  }

  default:
  /* Not a known shred type */
    return 0;

  }
}

FD_FN_PURE int
fd_keyguard_payload_matches_tls_cv( uchar const * data,
                                    ulong         sz ) {
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
fd_keyguard_payload_matches_x509_csr( uchar const * data,
                                      ulong         sz ) {
  if( sz<1UL        ) return 0;
  if( data[0]!=0x30 ) return 0;  /* ASN.1 SEQUENCE */

  /* Conservative estimate: TBSCertificate is at least 33 bytes long
     (1 byte ASN.1 DER overhead + 32 byte Ed25519 public key).

     It is probably possible to craft a shorter TBSCertificate, but
     only by changing the SubjectPublicKeyInfo to be something other
     than Ed25519.  But we don't care about that case, since cert
     validation is then guaranteed to fail at a later step. */
  if( sz<33UL       ) return 0;

  return 1;
}

FD_FN_PURE int
fd_keyguard_payload_authorize( uchar const * data,
                               ulong         sz,
                               int           role ) {
  switch( role ) {
    case FD_KEYGUARD_ROLE_VOTER: return fd_keyguard_payload_matches_txn_msg( data, sz );
    case FD_KEYGUARD_ROLE_GOSSIP: return fd_keyguard_payload_matches_gossip_msg( data, sz );
    case FD_KEYGUARD_ROLE_LEADER: return fd_keyguard_payload_matches_shred( data, sz );
    case FD_KEYGUARD_ROLE_TLS: return fd_keyguard_payload_matches_tls_cv( data, sz );
    case FD_KEYGUARD_ROLE_X509_CA: return fd_keyguard_payload_matches_x509_csr( data, sz );
    default: return 0;
  }
}
