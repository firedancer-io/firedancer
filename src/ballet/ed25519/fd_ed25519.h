#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_h

/* fd_ed25519 provides APIs for ED25519 signature computations */

#include "../sha512/fd_sha512.h"

/* FD_ED25519_ERR_* gives a number of error codes used by fd_ed25519
   APIs. */

#define FD_ED25519_SUCCESS    ( 0) /* Operation was successful */
#define FD_ED25519_ERR_SIG    (-1) /* Operation failed because the signature was obviously invalid */
#define FD_ED25519_ERR_PUBKEY (-2) /* Operation failed because the public key was obviously invalid */
#define FD_ED25519_ERR_MSG    (-3) /* Operation failed because the message didn't match the signature for the given key */

/* FD_ED25519_SIG_SZ: the size of an Ed25519 signature in bytes. */
#define FD_ED25519_SIG_SZ (64UL)

/* An Ed25519 signature. */
typedef uchar fd_ed25519_sig_t[ FD_ED25519_SIG_SZ ];

FD_PROTOTYPES_BEGIN

/* fd_ed25519_public_from_private computes the public_key corresponding
   to the given private key.

   public_key is assumed to point to the first byte of a 32-byte memory
   region which will hold the public key on return.

   private_key assumed to point to first byte of a 32-byte memory region
   private key for which the public key is desired.

   sha is a handle of a local join to a sha512 calculator.

   Does no input argument checking.  The caller takes a write interest
   in public_key and sha and a read interest in public_key for the
   duration the call.  Sanitizes the sha and stack to minimize risk of
   leaking private key info before returning.  Returns public_key. */

uchar * FD_FN_SENSITIVE
fd_ed25519_public_from_private( uchar         public_key [ 32 ],
                                uchar const   private_key[ 32 ],
                                fd_sha512_t * sha );

/* fd_ed25519_sign signs a message according to the ED25519 standard.

   sig is assumed to point to the first byte of a 64-byte memory region
   which will hold the signature on return.

   msg is assumed to point to the first byte of a sz byte memory region
   which holds the message to sign (sz==0 fine, msg==NULL fine if
   sz==0).

   public_key is assumed to point to first byte of a 32-byte memory
   region that holds the public key to use to sign this message.

   private_key is assumed to point to first byte of a 32-byte memory
   region that holds the private key to use to sign this message.

   sha is a handle of a local join to a sha512 calculator.

   Does no input argument checking.  Sanitizes the sha and stack to
   minimize risk of leaking private key info after return.  The caller
   takes a write interest in sig and sha and a read interest in msg,
   public_key and private_key for the duration the call.  Returns sig. */

uchar * FD_FN_SENSITIVE
fd_ed25519_sign( uchar         sig[ 64 ],
                 uchar const   msg[], /* msg_sz */
                 ulong         msg_sz,
                 uchar const   public_key[ 32 ],
                 uchar const   private_key[ 32 ],
                 fd_sha512_t * sha );

/* FD_ED25519_SIGN_BATCH_MSG_MAX is the largest supported per-message
   size for the batched signing path below (covers the largest messages
   the validator signs; shred and transaction MTUs are ~1.2 KiB). */

#define FD_ED25519_SIGN_BATCH_MSG_MAX (2048UL)

/* fd_ed25519_sign_batch8 signs n independent messages, n in [1,8]
   (asserted).  Each signature is bit-identical to
   fd_ed25519_sign of the same (msg, key) pair, all signed with the
   single (public_key, private_key) identity.  For n>=2 the
   signatures share batched SHA-512 computations and a single field
   inversion for the point compressions, so per-signature cost is lower
   than fd_ed25519_sign.

   sig is assumed to point to the first byte of an n*64-byte memory
   region which will hold the n signatures on return (signature i at
   sig+64*i).

   msg[i] is assumed to point to the first byte of a msg_sz[i] byte
   memory region which holds message i (msg_sz[i]==0 fine, msg[i]==NULL
   fine if msg_sz[i]==0, msg_sz[i] at most
   FD_ED25519_SIGN_BATCH_MSG_MAX).

   public_key and private_key are each a single 32-byte key, shared by
   all n messages (this is a shared-identity batch signer).

   Sanitizes internal state to minimize risk of leaking private key
   info after return.  The caller takes a write interest in sig and a
   read interest in the messages and keys for the duration the call.
   Returns sig. */

uchar * FD_FN_SENSITIVE
fd_ed25519_sign_batch8( uchar               sig[],        /* n*64 */
                        uchar const * const msg[],        /* n */
                        ulong const         msg_sz[],     /* n */
                        uchar const         public_key[ 32 ],
                        uchar const         private_key[ 32 ],
                        ulong               n );

/* fd_ed25519_verify verifies message according to the ED25519 standard.

   msg is assumed to point to the first byte of a sz byte memory region
   which holds the message to verify (sz==0 fine, msg==NULL fine if
   sz==0).

   sig is assumed to point to the first byte of a 64 byte memory region
   which holds the signature of the message.

   public_key is assumed to point to first byte of a 32-byte memory
   region that holds the public key to use to verify this message.

   sha is a handle of a local join to a sha512 calculator.

   Does no input argument checking.  This function takes a write
   interest in sig and sha and a read interest in msg, public_key and
   private_key for the duration the call.  Sanitizes the sha and stack
   to minimize risk of leaking private key info after return.  Returns
   FD_ED25519_SUCCESS (0) if the message verified successfully or a
   FD_ED25519_ERR_* code indicating the failure reason otherwise. */

int
fd_ed25519_verify( uchar const   msg[], /* msg_sz */
                   ulong         msg_sz,
                   uchar const   sig[ 64 ],
                   uchar const   public_key[ 32 ],
                   fd_sha512_t * sha );

/* fd_ed25519_verify_batch_single_msg verifies a batch of signatures
   over a single message, according to the ED25519 standard.

   msg is assumed to point to the first byte of a msg_sz byte memory region
   which holds the message to verify (msg_sz==0 fine, msg==NULL fine if
   msg_sz==0).

   signatures is assumed to point to the first byte of a memory region
   which holds the signatures of the message. Each signature is 64-byte long.

   pubkeys is assumed to point to first byte of a memory region
   that holds the public keys to use to verify these signatures.
   Each public key is 64-byte long.

   shas is an array of handles of a local join to sha512 calculators.

   batch_sz is the size of signatures, pubkeys and shas.
   batch_sz must be greater than zero.

   See fd_ed25519_verify for more details. */

int
fd_ed25519_verify_batch_single_msg( uchar const   msg[], /* msg_sz */
                                    ulong const   msg_sz,
                                    uchar const   signatures[ 64 ], /* 64 * batch_sz */
                                    uchar const   pubkeys[ 32 ],    /* 32 * batch_sz */
                                    fd_sha512_t * shas[ 1 ],               /* batch_sz */
                                    uchar const   batch_sz );

/* fd_ed25519_cache_t is a bounded cache of per public key
   precomputation used to speed up verifying signatures of repeated
   public keys.  An entry holds a split table of odd multiples of -A
   (see fd_ed25519_double_scalar_mul_base_split), keyed by the full
   32-byte public key encoding.  The cache is 4-way set associative
   with LRU replacement.  A key is inserted when a signature by it
   verifies successfully for the second time within a window of recent
   misses (tracked by a small tag filter), so only valid, not small
   order keys are cached and one-time keys don't evict useful entries.
   Table builds are rate limited relative to the verify rate.

   The results (including error codes) of the cached verify APIs are
   identical to the uncached ones for all inputs and cache states; the
   cache only changes how long a verify takes.  A cache is not thread
   safe and is typically owned by a single tile.  The footprint is
   ~6.2 KiB per entry (AVX-512 build) plus ~170 KiB of fixed tables. */

struct fd_ed25519_cache;
typedef struct fd_ed25519_cache fd_ed25519_cache_t;

#define FD_ED25519_CACHE_ALIGN (128UL)

/* fd_ed25519_cache_{align,footprint} give the required alignment and
   footprint of a memory region suitable for a cache with ent_cnt
   entries.  ent_cnt must be a power of 2 in [4,2^20].  footprint
   returns 0 for an invalid ent_cnt. */

FD_FN_CONST ulong
fd_ed25519_cache_align( void );

FD_FN_CONST ulong
fd_ed25519_cache_footprint( ulong ent_cnt );

/* fd_ed25519_cache_new formats mem as a cache with ent_cnt entries,
   seeded with seed (the seed randomizes set placement).  Returns mem on
   success and NULL on failure (logs details).  fd_ed25519_cache_join
   joins the caller to the cache.  fd_ed25519_cache_leave and
   fd_ed25519_cache_delete are the usual inverses. */

void *
fd_ed25519_cache_new( void * mem,
                      ulong  ent_cnt,
                      ulong  seed );

fd_ed25519_cache_t *
fd_ed25519_cache_join( void * shcache );

void *
fd_ed25519_cache_leave( fd_ed25519_cache_t * cache );

void *
fd_ed25519_cache_delete( void * shcache );

/* fd_ed25519_cache_{hit,miss,insert}_cnt return the number of public
   key lookups that hit, the number that missed and the number of
   entries inserted, since the cache was created. */

ulong fd_ed25519_cache_hit_cnt   ( fd_ed25519_cache_t const * cache );
ulong fd_ed25519_cache_miss_cnt  ( fd_ed25519_cache_t const * cache );
ulong fd_ed25519_cache_insert_cnt( fd_ed25519_cache_t const * cache );

/* fd_ed25519_verify_cached is fd_ed25519_verify using cache.  Returns
   exactly what fd_ed25519_verify returns for the same msg, sig and
   public_key. */

int
fd_ed25519_verify_cached( uchar const          msg[], /* msg_sz */
                          ulong                msg_sz,
                          uchar const          sig[ 64 ],
                          uchar const          public_key[ 32 ],
                          fd_sha512_t *        sha,
                          fd_ed25519_cache_t * cache );

/* fd_ed25519_verify_batch_single_msg_cached is
   fd_ed25519_verify_batch_single_msg using cache.  Returns exactly what
   fd_ed25519_verify_batch_single_msg returns for the same arguments. */

int
fd_ed25519_verify_batch_single_msg_cached( uchar const          msg[], /* msg_sz */
                                           ulong const          msg_sz,
                                           uchar const          signatures[ 64 ], /* 64 * batch_sz */
                                           uchar const          pubkeys[ 32 ],    /* 32 * batch_sz */
                                           fd_sha512_t *        shas[ 1 ],        /* batch_sz */
                                           uchar const          batch_sz,
                                           fd_ed25519_cache_t * cache );

/* fd_ed25519_verify_batch_multi_msg independently verifies batch_sz
   messages.  results[j] is exactly the return code of fd_ed25519_verify
   for (msgs[j], msg_szs[j], sigs[j], public_keys[j], shas[j]), including
   error precedence.  No equations are aggregated across signatures.

   Each input array and results has batch_sz entries.  Each sigs[j]
   points to 64 readable bytes, each public_keys[j] to 32 readable bytes,
   and each msgs[j] to msg_szs[j] readable bytes (NULL is allowed when
   msg_szs[j] is zero).  Each shas[j] is a distinct joined SHA-512
   calculator used as scratch; its state on return is unspecified (it
   is left untouched when item j is hashed by the internal multi-buffer
   SHA-512, as messages of up to 1232 bytes in a group are).  The
   caller grants a read interest in the inputs and a write interest in
   results and the calculators for the call.  Writable regions must not
   overlap inputs or each other (for example, results[j] is written
   before sigs[j] is read).  Does no argument checking.  batch_sz may be
   any count, including zero, in which case nothing is dereferenced and
   all arguments may be NULL.

   On AVX-512 builds items are verified in groups of up to 8; a final
   remainder of 1 or 2 items uses fd_ed25519_verify.  Other builds call
   fd_ed25519_verify for each item. */

void
fd_ed25519_verify_batch_multi_msg( uchar const * const msgs[],
                                   ulong const         msg_szs[],
                                   uchar const * const sigs[],
                                   uchar const * const public_keys[],
                                   fd_sha512_t *       shas[],
                                   int                 results[],
                                   ulong               batch_sz );

/* fd_ed25519_verify_batch_multi_msg_cached is
   fd_ed25519_verify_batch_multi_msg with a signer cache.  On AVX-512
   builds items are verified in groups of up to 8 without consulting
   the cache, and only a final remainder of fewer than 4 items uses
   fd_ed25519_verify_cached, so cache lookups, hits and insertions
   depend on the batch shape.  Other builds call
   fd_ed25519_verify_cached for each item.  The results are identical
   either way. */

void
fd_ed25519_verify_batch_multi_msg_cached( uchar const * const  msgs[],
                                          ulong const          msg_szs[],
                                          uchar const * const  sigs[],
                                          uchar const * const  public_keys[],
                                          fd_sha512_t *        shas[],
                                          int                  results[],
                                          ulong                batch_sz,
                                          fd_ed25519_cache_t * cache );

/* fd_ed25519_strerror converts an FD_ED25519_SUCCESS / FD_ED25519_ERR_*
   code into a human readable cstr.  The lifetime of the returned
   pointer is infinite.  The returned pointer is always to a non-NULL
   cstr. */

FD_FN_CONST char const *
fd_ed25519_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_h */
