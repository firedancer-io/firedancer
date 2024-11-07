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
#define FD_KEYGUARD_ROLE_REPAIR  (4)  /* Repair tile */
#define FD_KEYGUARD_ROLE_BUNDLE  (5)  /* Bundle tile */
#define FD_KEYGUARD_ROLE_CNT     (6)  /* number of known roles */

/* Payload types ******************************************************/

#define FD_KEYGUARD_PAYLOAD_LG_TXN    (0)  /* Solana transaction message (e.g. vote) */
#define FD_KEYGUARD_PAYLOAD_LG_GOSSIP (1)  /* Gossip CrdsData */
#define FD_KEYGUARD_PAYLOAD_LG_PRUNE  (2)  /* Gossip PruneData */
#define FD_KEYGUARD_PAYLOAD_LG_SHRED  (3)  /* Solana legacy or merkle shred */
#define FD_KEYGUARD_PAYLOAD_LG_TLS_CV (4)  /* TLS 1.3 certificate verify payload */
#define FD_KEYGUARD_PAYLOAD_LG_REPAIR (6)  /* RepairProtocol */
#define FD_KEYGUARD_PAYLOAD_LG_PING   (7)  /* Gossip/Repair ping protocol */
#define FD_KEYGUARD_PAYLOAD_LG_BUNDLE (8)  /* Bundle block producer authentication */

#define FD_KEYGUARD_PAYLOAD_TXN    (1UL<<FD_KEYGUARD_PAYLOAD_LG_TXN   )
#define FD_KEYGUARD_PAYLOAD_GOSSIP (1UL<<FD_KEYGUARD_PAYLOAD_LG_GOSSIP)
#define FD_KEYGUARD_PAYLOAD_PRUNE  (1UL<<FD_KEYGUARD_PAYLOAD_LG_PRUNE )
#define FD_KEYGUARD_PAYLOAD_SHRED  (1UL<<FD_KEYGUARD_PAYLOAD_LG_SHRED )
#define FD_KEYGUARD_PAYLOAD_TLS_CV (1UL<<FD_KEYGUARD_PAYLOAD_LG_TLS_CV)
#define FD_KEYGUARD_PAYLOAD_REPAIR (1UL<<FD_KEYGUARD_PAYLOAD_LG_REPAIR)
#define FD_KEYGUARD_PAYLOAD_PING   (1UL<<FD_KEYGUARD_PAYLOAD_LG_PING  )
#define FD_KEYGUARD_PAYLOAD_BUNDLE (1UL<<FD_KEYGUARD_PAYLOAD_LG_BUNDLE)

/* Sign types *********************************************************/

#define FD_KEYGUARD_SIGN_TYPE_ED25519               (0)  /* ed25519_sign(input) */
#define FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519        (1)  /* ed25519_sign(sha256(data)) */
#define FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 (2)  /* ed25519_sign(pubkey-data) */

/* Type confusion/ambiguity checks ************************************/

/* fd_keyguard_payload_match returns a bitwise OR of
   FD_KEYGUARD_PAYLOAD_{...}.

   [data,data+sz) is the payload that is requested to be signed.

   sign_type is in FD_KEYGUARD_SIGN_TYPE_{...}.

   Returns 0 if none matched.  fd_ulong_popcnt(return value) is 1 if the
   payload is unambiguously of a single type. */

FD_FN_PURE ulong
fd_keyguard_payload_match( uchar const * data,
                           ulong         sz,
                           int           sign_type );

/* Authorization ******************************************************/

struct fd_keyguard_authority {
  uchar identity_pubkey[32];
};

typedef struct fd_keyguard_authority fd_keyguard_authority_t;

/* fd_keyguard_payload_authorize decides whether the keyguard accepts
   a signing request.

   [data,data+sz) is the payload that is requested to be signed.

   role is one of FD_KEYGUARD_ROLE_{...}.  It is assumed that the origin
   of the request was previously authorized for the given role.

   Returns 1 if authorized, otherwise 0.

   This function is more restrictive than the respective
   fd_keyguard_payload_matches functions. */

int
fd_keyguard_payload_authorize( fd_keyguard_authority_t const * authority,
                               uchar const *                   data,
                               ulong                           sz,
                               int                             role,
                               int                             sign_type );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_keyguard_fd_keyguard_h */
