#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_verifier_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_verifier_h

/* Signature verifiers: objects that own the SHA-512 calculators and
   the optional signer cache a tile needs to verify Ed25519 signatures,
   and that pick the verification path of the build for the batch in
   hand.

   fd_ed25519_verifier_t answers every call at once.

   fd_ed25519_batch_verifier_t delays: on builds whose fastest path is
   a fixed size SIMD group, it collects the signatures of consecutive
   transactions and verifies them once it holds a full group.  On other
   builds it behaves like fd_ed25519_verifier_t.  Its user must flush
   or clear it before switching to transactions of another block. */

#include "fd_ed25519.h"
#include "../txn/fd_txn.h"

/* FD_ED25519_VERIFIER_CACHE_{DEFAULT,OFF} are values of cache_ent_cnt
   selecting the default signer cache (2048 entries) and no cache at
   all.  Any other value is a cache entry count, a power of 2 in
   [4,2^20]. */

#define FD_ED25519_VERIFIER_CACHE_DEFAULT (0UL)
#define FD_ED25519_VERIFIER_CACHE_OFF     (ULONG_MAX)

#define FD_ED25519_VERIFIER_ALIGN (128UL)

/* FD_ED25519_VERIFIER_SIG_MAX is the most signatures a verifier
   verifies together: a run of transactions cut once it holds
   FD_ED25519_BATCH_VERIFIER_GROUP signatures, the last of which can
   bring FD_TXN_SIG_MAX.  FD_ED25519_BATCH_VERIFIER_GROUP is the
   signature count a batch verifier holds before verifying them
   together; its pending_cnt is always below it. */

#define FD_ED25519_BATCH_VERIFIER_GROUP (8UL)
#define FD_ED25519_VERIFIER_SIG_MAX     (FD_ED25519_BATCH_VERIFIER_GROUP-1UL+FD_TXN_SIG_MAX)

struct fd_ed25519_verifier;
typedef struct fd_ed25519_verifier fd_ed25519_verifier_t;

struct fd_ed25519_batch_verifier;
typedef struct fd_ed25519_batch_verifier fd_ed25519_batch_verifier_t;

FD_PROTOTYPES_BEGIN

/* fd_ed25519_verifier_{align,footprint} give the required alignment
   and footprint of a memory region for a verifier with cache_ent_cnt
   cache entries (see FD_ED25519_VERIFIER_CACHE_*).  footprint returns
   0 for an invalid cache_ent_cnt. */

FD_FN_CONST ulong
fd_ed25519_verifier_align( void );

FD_FN_CONST ulong
fd_ed25519_verifier_footprint( ulong cache_ent_cnt );

/* fd_ed25519_verifier_new formats mem as a verifier.  seed randomizes
   the cache placement.  Returns mem on success and NULL on failure
   (logs details).  join, leave and delete are the usual. */

void *
fd_ed25519_verifier_new( void * mem,
                         ulong  cache_ent_cnt,
                         ulong  seed );

fd_ed25519_verifier_t *
fd_ed25519_verifier_join( void * shverifier );

void *
fd_ed25519_verifier_leave( fd_ed25519_verifier_t * verifier );

void *
fd_ed25519_verifier_delete( void * shverifier );

/* fd_ed25519_verifier_verify returns what fd_ed25519_verify returns
   for msg, sig and public_key. */

int
fd_ed25519_verifier_verify( fd_ed25519_verifier_t * verifier,
                            uchar const             msg[], /* msg_sz */
                            ulong                   msg_sz,
                            uchar const             sig[ 64 ],
                            uchar const             public_key[ 32 ] );

/* fd_ed25519_verifier_verify_batch sets results[j] to what
   fd_ed25519_verify returns for (msgs[j], msg_szs[j], sigs[j],
   public_keys[j]), for j in [0,sig_cnt).  sig_cnt may be zero.
   Signatures are verified together in runs of at most
   FD_ED25519_VERIFIER_SIG_MAX. */

void
fd_ed25519_verifier_verify_batch( fd_ed25519_verifier_t * verifier,
                                  uchar const * const     msgs[],
                                  ulong const             msg_szs[],
                                  uchar const * const     sigs[],
                                  uchar const * const     public_keys[],
                                  int                     results[],
                                  ulong                   sig_cnt );

/* fd_ed25519_verifier_verify_txn verifies the signatures of the parsed
   transaction txn whose payload_sz byte payload is at payload.
   Returns FD_ED25519_SUCCESS if every signature verifies, else the
   first code that is neither SUCCESS nor FD_ED25519_ERR_MSG, else
   FD_ED25519_ERR_MSG. */

int
fd_ed25519_verifier_verify_txn( fd_ed25519_verifier_t * verifier,
                                fd_txn_t const *        txn,
                                uchar const *           payload,
                                ulong                   payload_sz );

/* fd_ed25519_verifier_verify_txns sets results[i] to what
   fd_ed25519_verifier_verify_txn returns for (txns[i], payloads[i],
   payload_szs[i]), for i in [0,txn_cnt), verifying consecutive
   transactions together in runs cut once they hold
   FD_ED25519_BATCH_VERIFIER_GROUP signatures. */

void
fd_ed25519_verifier_verify_txns( fd_ed25519_verifier_t * verifier,
                                 fd_txn_t const * const  txns[],
                                 uchar const * const     payloads[],
                                 ulong const             payload_szs[],
                                 int                     results[],
                                 ulong                   txn_cnt );

/* fd_ed25519_verifier_{hit,miss,insert}_cnt are the signer cache
   counters (see fd_ed25519_cache_{hit,miss,insert}_cnt), 0 without a
   cache. */

ulong fd_ed25519_verifier_hit_cnt   ( fd_ed25519_verifier_t const * verifier );
ulong fd_ed25519_verifier_miss_cnt  ( fd_ed25519_verifier_t const * verifier );
ulong fd_ed25519_verifier_insert_cnt( fd_ed25519_verifier_t const * verifier );

/* fd_ed25519_batch_verifier_{align,footprint,new,join,leave,delete}
   are as for fd_ed25519_verifier_t.  The builds that delay verify
   groups without a cache and ignore cache_ent_cnt; footprint still
   returns 0 for an invalid value. */

FD_FN_CONST ulong
fd_ed25519_batch_verifier_align( void );

FD_FN_CONST ulong
fd_ed25519_batch_verifier_footprint( ulong cache_ent_cnt );

void *
fd_ed25519_batch_verifier_new( void * mem,
                               ulong  cache_ent_cnt,
                               ulong  seed );

fd_ed25519_batch_verifier_t *
fd_ed25519_batch_verifier_join( void * shverifier );

void *
fd_ed25519_batch_verifier_leave( fd_ed25519_batch_verifier_t * verifier );

void *
fd_ed25519_batch_verifier_delete( void * shverifier );

/* fd_ed25519_batch_verifier_verify_txn adds the signatures of txn to
   the pending group, verifying the group each time it fills.  The
   signatures, public keys and message are copied, so payload need not
   outlive the call.  Returns 1 if nothing was verified (the signatures
   are pending), 0 if every signature verified in this call passed, -1
   if any failed.  A verified signature may belong to a transaction of
   an earlier call. */

int
fd_ed25519_batch_verifier_verify_txn( fd_ed25519_batch_verifier_t * verifier,
                                      fd_txn_t const *              txn,
                                      uchar const *                 payload,
                                      ulong                         payload_sz );

/* fd_ed25519_batch_verifier_flush verifies the pending signatures.
   Returns 1 if none were pending, 0 if all passed, -1 if any failed.
   Nothing is pending on return. */

int
fd_ed25519_batch_verifier_flush( fd_ed25519_batch_verifier_t * verifier );

/* fd_ed25519_batch_verifier_clear drops the pending signatures
   unverified. */

void
fd_ed25519_batch_verifier_clear( fd_ed25519_batch_verifier_t * verifier );

/* fd_ed25519_batch_verifier_pending_cnt is the number of signatures
   added and not yet verified. */

ulong
fd_ed25519_batch_verifier_pending_cnt( fd_ed25519_batch_verifier_t const * verifier );

/* fd_ed25519_batch_verifier_{hit,miss,insert}_cnt are the signer
   cache counters, 0 on the builds that delay. */

ulong fd_ed25519_batch_verifier_hit_cnt   ( fd_ed25519_batch_verifier_t const * verifier );
ulong fd_ed25519_batch_verifier_miss_cnt  ( fd_ed25519_batch_verifier_t const * verifier );
ulong fd_ed25519_batch_verifier_insert_cnt( fd_ed25519_batch_verifier_t const * verifier );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_verifier_h */
