#ifndef HEADER_fd_src_choreo_votor_ag_vote_h
#define HEADER_fd_src_choreo_votor_ag_vote_h

#include "ag_votor_base.h"
#include "ag_bls.h"

#define AG_VOTE_KIND_NOTAR           (0U)
#define AG_VOTE_KIND_FINAL           (1U)
#define AG_VOTE_KIND_SKIP            (2U)
#define AG_VOTE_KIND_NOTAR_FALLBACK  (3U)
#define AG_VOTE_KIND_SKIP_FALLBACK   (4U)

struct ag_vote_notar {
  ulong           slot;
  ag_block_hash_t block_hash;
  ag_bls_sig_t    sig;
  ushort          rank;
};
typedef struct ag_vote_notar ag_vote_notar_t;

struct ag_vote_notar_fallback {
  ulong           slot;
  ag_block_hash_t block_hash;
  ag_bls_sig_t    sig;
  ushort          rank;
};
typedef struct ag_vote_notar_fallback ag_vote_notar_fallback_t;

struct ag_vote_skip {
  ulong        slot;
  ag_bls_sig_t sig;
  ushort       rank;
};
typedef struct ag_vote_skip ag_vote_skip_t;

struct ag_vote_skip_fallback {
  ulong        slot;
  ag_bls_sig_t sig;
  ushort       rank;
};
typedef struct ag_vote_skip_fallback ag_vote_skip_fallback_t;

struct ag_vote_final {
  ulong        slot;
  ag_bls_sig_t sig;
  ushort       rank;
};
typedef struct ag_vote_final ag_vote_final_t;

struct ag_vote {
  uint kind;
  union {
    ag_vote_notar_t          notar;
    ag_vote_notar_fallback_t notar_fallback;
    ag_vote_skip_t           skip;
    ag_vote_skip_fallback_t  skip_fallback;
    ag_vote_final_t          final;
  };
};
typedef struct ag_vote ag_vote_t;

FD_PROTOTYPES_BEGIN


ag_vote_t
ag_vote_construct_notar( ulong                 slot,
                         ag_block_hash_t const hash,
                         ag_bls_sec_t const    sec,
                         ushort                rank,
                         ushort                shred_version );

ag_vote_t
ag_vote_construct_notar_fallback( ulong                 slot,
                                  ag_block_hash_t const hash,
                                  ag_bls_sec_t const    sec,
                                  ushort                rank,
                                  ushort                shred_version );

ag_vote_t
ag_vote_construct_skip( ulong              slot,
                        ag_bls_sec_t const sec,
                        ushort             rank,
                        ushort             shred_version );

ag_vote_t
ag_vote_construct_skip_fallback( ulong              slot,
                                 ag_bls_sec_t const sec,
                                 ushort             rank,
                                 ushort             shred_version );

ag_vote_t
ag_vote_construct_final( ulong              slot,
                         ag_bls_sec_t const sec,
                         ushort             rank,
                         ushort             shred_version );

int
ag_vote_verify( ag_vote_t const *  self,
                ag_bls_pub_t const pub,
                ushort             shred_version );

FD_FN_PURE static inline ulong
ag_vote_slot( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.slot;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.slot;
  case AG_VOTE_KIND_SKIP:           return self->skip.slot;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.slot;
  default:                          return self->final.slot;
  }
}

FD_FN_PURE static inline ushort
ag_vote_rank( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.rank;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.rank;
  case AG_VOTE_KIND_SKIP:           return self->skip.rank;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.rank;
  default:                          return self->final.rank;
  }
}

static inline void
ag_vote_set_rank( ag_vote_t * self,
                  ushort      rank ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          self->notar.rank          = rank; break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: self->notar_fallback.rank = rank; break;
  case AG_VOTE_KIND_SKIP:           self->skip.rank           = rank; break;
  case AG_VOTE_KIND_SKIP_FALLBACK:  self->skip_fallback.rank  = rank; break;
  default:                          self->final.rank          = rank; break;
  }
}

/* Only a notar and a notar fallback vote carry a block hash, so the
   accessor takes the vote that owns the 32 bytes rather than the union:
   the type states which kinds have a hash, and neither accessor has a
   NULL return for the caller to handle.  A caller holding an ag_vote_t
   has already discriminated the kind wherever it wants a hash. */

FD_FN_PURE static inline uchar const *
ag_vote_notar_block_hash( ag_vote_notar_t const * self ) {
  return self->block_hash;
}

FD_FN_PURE static inline uchar const *
ag_vote_notar_fallback_block_hash( ag_vote_notar_fallback_t const * self ) {
  return self->block_hash;
}

FD_PROTOTYPES_END

#endif
