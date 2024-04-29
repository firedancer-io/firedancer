#ifndef HEADER_fd_src_disco_keyguard_fd_keyguard_h
#define HEADER_fd_src_disco_keyguard_fd_keyguard_h

/* fd_keyguard creates digital signatures on behalf of validator
   components. */

#include "../fd_disco_base.h"

FD_PROTOTYPES_BEGIN

/* FD_KEYGUARD_SIGN_REQ_MTU is the maximum size (inclusive) of a signing
   request payload.  The payload in this case is the message byte array
   passed to fd_ed25519_sign. */

#define FD_KEYGUARD_SIGN_REQ_MTU (2048UL)

/* Role definitions ***************************************************/

#define FD_KEYGUARD_ROLE_VOTER   (0)  /* vote transaction sender */
#define FD_KEYGUARD_ROLE_GOSSIP  (1)  /* gossip participant */
#define FD_KEYGUARD_ROLE_LEADER  (2)  /* block producer (shreds) */
#define FD_KEYGUARD_ROLE_TLS     (3)  /* TLS peer (certificate verify) */
#define FD_KEYGUARD_ROLE_X509_CA (4)  /* self-signed cert CA */

/* Type confusion/ambiguity checks ************************************/

/* fd_keyguard_payload_matches_{...} returns 1 if the byte array
   [data,data+sz) could match a signing payload of a given type (false
   positives allowed). Returns 0 if the byte array cannot possibly be a
   valid message of this type.  Any two of these functions below
   returning 1 for the same payload indicates a security issue (fake
   signing). Possible types are:

     txn_msg:     Solana transaction message (e.g. vote)
     gossip_msg:  Solana gossip over UDP message payload
     shred:       Solana legacy or merkle shred
     tls_cv:      TLS 1.3 certificate verify payload
     x509_csr:    X.509 certificate signing request */

FD_FN_PURE int fd_keyguard_payload_matches_txn_msg   ( uchar const * data, ulong sz );
FD_FN_PURE int fd_keyguard_payload_matches_gossip_msg( uchar const * data, ulong sz );
FD_FN_PURE int fd_keyguard_payload_matches_shred     ( uchar const * data, ulong sz );
FD_FN_PURE int fd_keyguard_payload_matches_tls_cv    ( uchar const * data, ulong sz );
FD_FN_PURE int fd_keyguard_payload_matches_x509_csr  ( uchar const * data, ulong sz );

/* fd_keyguard_payload_check_ambiguous returns 1 if the given byte array
   could be susceptible to fake signing (false positives allowed).  This
   happens when the payload could be interpreted as more than one type
   of message.  Otherwise, returns 0.

   For all inputs with sz<=2048UL, is guaranteed to return 0.
   This property was verified via CBMC in fd_keyguard_ambiguity_proof. */

static inline FD_FN_PURE int
fd_keyguard_payload_check_ambiguous( uchar const * data,
                                     ulong         sz ) {
  int match_cnt =
      ( !!fd_keyguard_payload_matches_txn_msg   ( data, sz ) )
    + ( !!fd_keyguard_payload_matches_gossip_msg( data, sz ) )
    + ( !!fd_keyguard_payload_matches_shred     ( data, sz ) )
    + ( !!fd_keyguard_payload_matches_tls_cv    ( data, sz ) )
    + ( !!fd_keyguard_payload_matches_x509_csr  ( data, sz ) );
  return match_cnt>1;
}

/* Authorization ******************************************************/

/* fd_keyguard_payload_authorize decides whether the keyguard accepts
   a signing request.

   [data,data+sz) is the payload of the signing request (the "message"
   in the Ed25519 signature scheme).  The data pointer and sz are
   assumed to be a valid memory region in the local address space.
   The content of this range is untrusted.

   role is one of FD_KEYGUARD_ROLE_{...}.  It is assumed that the origin
   of the request was previously authorized for the given role.

   Returns 1 if authorized, otherwise 0.

   This function is more restrictive than the respective
   fd_keyguard_payload_matches functions. */

FD_FN_PURE int
fd_keyguard_payload_authorize( uchar const * data,
                               ulong         sz,
                               int           role );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_keyguard_fd_keyguard_h */
