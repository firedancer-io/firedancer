#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_verifier_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_verifier_h

/* Signature verifier: the object a tile verifies Ed25519 signatures
   with.  It owns the scratch and the optional signer cache the
   verification takes, and every result it gives is what
   fd_ed25519_verify returns for that signature.  Callers collect
   FD_ED25519_VERIFIER_GROUP signatures per
   fd_ed25519_verifier_verify_sigs call. */

#include "fd_ed25519.h"
#include "../txn/fd_txn.h"

/* FD_ED25519_VERIFIER_CACHE_{DEFAULT,OFF} are values of cache_ent_cnt
   selecting the default signer cache (2048 entries) and no cache at
   all.  Any other value is a cache entry count, a power of 2 in
   [4,2^20]. */

#define FD_ED25519_VERIFIER_CACHE_DEFAULT (0UL)
#define FD_ED25519_VERIFIER_CACHE_OFF     (ULONG_MAX)

#define FD_ED25519_VERIFIER_ALIGN (128UL)

/* FD_ED25519_VERIFIER_BATCH is the most signatures a caller is asked
   to collect per fd_ed25519_verifier_verify_sigs call, whatever the
   build; it sizes the callers' staging. */

#define FD_ED25519_VERIFIER_BATCH (8UL)

/* FD_ED25519_VERIFIER_SIG_MAX is the most signatures one
   fd_ed25519_verifier_verify_sigs call takes.  Callers collecting
   transactions add one while the total stays within a group, so a set
   of several transactions has at most FD_ED25519_VERIFIER_GROUP
   signatures and only a lone transaction can bring FD_TXN_SIG_MAX
   (the most signatures a transaction can carry). */

#define FD_ED25519_VERIFIER_SIG_MAX (FD_TXN_SIG_MAX)
FD_STATIC_ASSERT( FD_ED25519_VERIFIER_BATCH<=FD_ED25519_VERIFIER_SIG_MAX, verifier_sig_max );

/* FD_ED25519_VERIFIER_GROUP is the signature count a caller collects
   before one fd_ed25519_verifier_verify_sigs call, in
   [1,FD_ED25519_VERIFIER_BATCH].  It is the group size the Ed25519
   implementation of the build verifies fastest: a caller that has it
   calls, one that has fewer waits for more unless none can come. */

#if FD_ED25519_CRC && defined(FD_ED25519_CRC_IMPL_AVX512)
#define FD_ED25519_VERIFIER_GROUP (FD_ED25519_VERIFIER_BATCH)
#else
#define FD_ED25519_VERIFIER_GROUP (1UL)
#endif
FD_STATIC_ASSERT( 1UL<=FD_ED25519_VERIFIER_GROUP && FD_ED25519_VERIFIER_GROUP<=FD_ED25519_VERIFIER_BATCH, verifier_group );

/* A transaction verifier (the exec tiles') keeps the default cache. */

#define FD_ED25519_VERIFIER_TXN_CACHE (FD_ED25519_VERIFIER_CACHE_DEFAULT)

struct fd_ed25519_verifier;
typedef struct fd_ed25519_verifier fd_ed25519_verifier_t;

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

/* fd_ed25519_verifier_verify_sigs sets results[j] to what
   fd_ed25519_verify returns for (msgs[j], msg_szs[j], sigs[j],
   public_keys[j]), for j in [0,sig_cnt), sig_cnt in
   [1,FD_ED25519_VERIFIER_SIG_MAX] (asserted). */

void
fd_ed25519_verifier_verify_sigs( fd_ed25519_verifier_t * verifier,
                                 uchar const * const     msgs[],        /* sig_cnt */
                                 ulong const             msg_szs[],     /* sig_cnt */
                                 uchar const * const     sigs[],        /* sig_cnt */
                                 uchar const * const     public_keys[], /* sig_cnt */
                                 int                     results[],     /* sig_cnt */
                                 ulong                   sig_cnt );

/* fd_ed25519_verifier_{hit,miss,insert}_cnt are the signer cache
   counters (see fd_ed25519_cache_{hit,miss,insert}_cnt), 0 without a
   cache. */

ulong fd_ed25519_verifier_hit_cnt   ( fd_ed25519_verifier_t const * verifier );
ulong fd_ed25519_verifier_miss_cnt  ( fd_ed25519_verifier_t const * verifier );
ulong fd_ed25519_verifier_insert_cnt( fd_ed25519_verifier_t const * verifier );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_verifier_h */
