#ifndef HEADER_fd_src_flamenco_alpenglow_fd_footer_cache_h
#define HEADER_fd_src_flamenco_alpenglow_fd_footer_cache_h

/* fd_footer_cache is replay's footer verify cache, kept across footers:
   a memo of recent footer cert H(m)s keyed by the signing payload,
   evicting oldest first, and one vote lthash memo slot per rank: the
   vote account image replay last stored for that rank and its lthash. */

#include "../fd_flamenco_base.h"
#include "../../ballet/bls/fd_bls.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../choreo/votor/ag_votor_base.h"
#include "../runtime/program/vote/fd_vote_codec.h"

#define FD_FOOTER_CACHE_ALIGN   (64UL)
#define FD_FOOTER_CACHE_MAGIC   (0xf17eda2cef0c0000UL) /* firedancer footer cache ver 0 */

#define FD_FOOTER_CACHE_MSG_MAX (64UL)
#define FD_FOOTER_CACHE_MSG_CNT (64UL)

#define FD_FOOTER_CACHE_MEMO_DATA_MAX FD_VOTE_STATE_V4_SZ

struct __attribute__((aligned(64))) fd_footer_cache_memo {
  fd_lthash_value_t lthash;
  uchar             pubkey[ 32 ];
  uchar             owner [ 32 ];
  ulong             lamports; /* 0 if empty */
  ulong             data_len;
  int               executable;
  uchar             data[ FD_FOOTER_CACHE_MEMO_DATA_MAX ];

  /* blake3 cv of input bytes [2048,) for this pubkey, owner,
     executable and data_len, with data zero past offset 2040 */
  uchar             cv_pubkey[ 32 ];
  uchar             cv_owner [ 32 ];
  ulong             cv_data_len; /* 0 if none */
  int               cv_executable;
  uchar             cv[ 32 ];
};
typedef struct fd_footer_cache_memo fd_footer_cache_memo_t;

struct __attribute__((aligned(FD_FOOTER_CACHE_ALIGN))) fd_footer_cache {
  ulong magic; /* ==FD_FOOTER_CACHE_MAGIC */
  ulong next;

  struct {
    ulong sz; /* 0 if empty */
    uchar msg[ FD_FOOTER_CACHE_MSG_MAX ];
    blst_p2_affine h;
  } e[ FD_FOOTER_CACHE_MSG_CNT ];

  fd_footer_cache_memo_t memo[ AG_VAT_MAX ];
};
typedef struct fd_footer_cache fd_footer_cache_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_footer_cache_align( void );

FD_FN_CONST ulong
fd_footer_cache_footprint( void );

void *
fd_footer_cache_new( void * shmem );

fd_footer_cache_t *
fd_footer_cache_join( void * shcache );

/* fd_footer_cache_hash_msg sets h to H(msg), from the cache if there,
   otherwise computed and inserted.  msg_sz must be in
   [1,FD_FOOTER_CACHE_MSG_MAX]. */

void
fd_footer_cache_hash_msg( fd_footer_cache_t * cache,
                          uchar const *       msg,
                          ulong               msg_sz,
                          blst_p2_affine *    h );

blst_p2_affine const *
fd_footer_cache_hash_query( fd_footer_cache_t const * cache,
                            uchar const *             msg,
                            ulong                     msg_sz );

void
fd_footer_cache_hash_insert( fd_footer_cache_t *    cache,
                             uchar const *          msg,
                             ulong                  msg_sz,
                             blst_p2_affine const * h );

fd_lthash_value_t const *
fd_footer_cache_memo_query( fd_footer_cache_memo_t const * memo,
                            uchar const                    pubkey[ static FD_HASH_FOOTPRINT ],
                            uchar const                    owner[ static FD_HASH_FOOTPRINT ],
                            ulong                          lamports,
                            int                            executable,
                            uchar const *                  data,
                            ulong                          data_len );

int
fd_footer_cache_memo_insert( fd_footer_cache_memo_t * memo,
                             uchar const              pubkey[ static FD_HASH_FOOTPRINT ],
                             uchar const              owner[ static FD_HASH_FOOTPRINT ],
                             ulong                    lamports,
                             int                      executable,
                             uchar const *            data,
                             ulong                    data_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_footer_cache_h */
