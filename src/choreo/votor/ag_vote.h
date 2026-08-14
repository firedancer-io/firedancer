#ifndef HEADER_fd_src_choreo_votor_ag_vote_h
#define HEADER_fd_src_choreo_votor_ag_vote_h

#include "ag_votor_base.h"
#include "ag_aggsig.h"

#define AG_VOTE_TYPE_NOTAR           (0U)
#define AG_VOTE_TYPE_FINAL           (1U)
#define AG_VOTE_TYPE_SKIP            (2U)
#define AG_VOTE_TYPE_NOTAR_FALLBACK  (3U)
#define AG_VOTE_TYPE_SKIP_FALLBACK   (4U)

struct __attribute__((packed)) ag_notar_vote {
  ulong           slot;
  fd_hash_t       block_hash;
  ag_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct ag_notar_vote ag_notar_vote_t;

struct __attribute__((packed)) ag_notar_fallback_vote {
  ulong           slot;
  fd_hash_t       block_hash;
  ag_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct ag_notar_fallback_vote ag_notar_fallback_vote_t;

struct __attribute__((packed)) ag_skip_vote {
  ulong           slot;
  ag_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct ag_skip_vote ag_skip_vote_t;

struct __attribute__((packed)) ag_skip_fallback_vote {
  ulong           slot;
  ag_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct ag_skip_fallback_vote ag_skip_fallback_vote_t;

struct __attribute__((packed)) ag_final_vote {
  ulong           slot;
  ag_aggsig_sig_t sig;
  ushort          signer;
};
typedef struct ag_final_vote ag_final_vote_t;

struct __attribute__((packed)) ag_vote {
  uint kind;
  union {
    ag_notar_vote_t          notar;
    ag_notar_fallback_vote_t notar_fallback;
    ag_skip_vote_t           skip;
    ag_skip_fallback_vote_t  skip_fallback;
    ag_final_vote_t          final;
  } inner;
};
typedef struct ag_vote ag_vote_t;

#define AG_VOTE_PAYLOAD_MAX (43UL)

#define AG_VOTE_SERIALIZED_MAX (2UL + sizeof(ag_notar_vote_t) + 2UL)

FD_PROTOTYPES_BEGIN

ulong
ag_vote_payload_bytes_to_sign( uchar *           out,
                               uint              kind,
                               ulong             slot,
                               fd_hash_t const * h,
                               ushort            shred_version );

void
ag_notar_vote_new( ag_notar_vote_t *      out,
                   ulong                  slot,
                   fd_hash_t const *      h,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version );
int
ag_notar_vote_check_sig( ag_notar_vote_t const * self,
                         ag_aggsig_pk_t const *  pk,
                         ushort                  shred_version );
void
ag_notar_fallback_vote_new( ag_notar_fallback_vote_t * out,
                            ulong                      slot,
                            fd_hash_t const *          h,
                            ag_aggsig_sk_t const *     sk,
                            ushort                     signer,
                            ushort                     shred_version );
int
ag_notar_fallback_vote_check_sig( ag_notar_fallback_vote_t const * self,
                                  ag_aggsig_pk_t const *           pk,
                                  ushort                           shred_version );
void
ag_skip_vote_new( ag_skip_vote_t *       out,
                  ulong                  slot,
                  ag_aggsig_sk_t const * sk,
                  ushort                 signer,
                  ushort                 shred_version );
int
ag_skip_vote_check_sig( ag_skip_vote_t const * self,
                        ag_aggsig_pk_t const * pk,
                        ushort                 shred_version );
void
ag_skip_fallback_vote_new( ag_skip_fallback_vote_t * out,
                           ulong                     slot,
                           ag_aggsig_sk_t const *    sk,
                           ushort                    signer,
                           ushort                    shred_version );
int
ag_skip_fallback_vote_check_sig( ag_skip_fallback_vote_t const * self,
                                 ag_aggsig_pk_t const *          pk,
                                 ushort                          shred_version );
void
ag_final_vote_new( ag_final_vote_t *      out,
                   ulong                  slot,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version );
int
ag_final_vote_check_sig( ag_final_vote_t const * self,
                         ag_aggsig_pk_t const *  pk,
                         ushort                  shred_version );

void
ag_vote_new_signed( ag_vote_t *       out,
                    uint              kind,
                    ulong             slot,
                    fd_hash_t const * h,
                    ag_aggsig_sign_fn sign,
                    void *            sign_ctx,
                    ushort            signer,
                    ushort            shred_version );

void
ag_vote_new_notar( ag_vote_t *            out,
                   ulong                  slot,
                   fd_hash_t const *      h,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version );
void
ag_vote_new_notar_fallback( ag_vote_t *            out,
                            ulong                  slot,
                            fd_hash_t const *      h,
                            ag_aggsig_sk_t const * sk,
                            ushort                 signer,
                            ushort                 shred_version );
void
ag_vote_new_skip( ag_vote_t *            out,
                  ulong                  slot,
                  ag_aggsig_sk_t const * sk,
                  ushort                 signer,
                  ushort                 shred_version );
void
ag_vote_new_skip_fallback( ag_vote_t *            out,
                           ulong                  slot,
                           ag_aggsig_sk_t const * sk,
                           ushort                 signer,
                           ushort                 shred_version );
void
ag_vote_new_final( ag_vote_t *            out,
                   ulong                  slot,
                   ag_aggsig_sk_t const * sk,
                   ushort                 signer,
                   ushort                 shred_version );

int
ag_vote_check_sig( ag_vote_t const *      self,
                   ag_aggsig_pk_t const * pk,
                   ushort                 shred_version );

FD_FN_PURE static inline ulong
ag_vote_slot( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_TYPE_NOTAR:          return self->inner.notar.slot;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return self->inner.notar_fallback.slot;
  case AG_VOTE_TYPE_SKIP:           return self->inner.skip.slot;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  return self->inner.skip_fallback.slot;
  default:                          return self->inner.final.slot;
  }
}

FD_FN_PURE static inline ushort
ag_vote_signer( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_TYPE_NOTAR:          return self->inner.notar.signer;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return self->inner.notar_fallback.signer;
  case AG_VOTE_TYPE_SKIP:           return self->inner.skip.signer;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  return self->inner.skip_fallback.signer;
  default:                          return self->inner.final.signer;
  }
}

static inline void
ag_vote_set_signer( ag_vote_t * self, ushort signer ) {
  switch( self->kind ) {
  case AG_VOTE_TYPE_NOTAR:          self->inner.notar.signer          = signer; break;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: self->inner.notar_fallback.signer = signer; break;
  case AG_VOTE_TYPE_SKIP:           self->inner.skip.signer           = signer; break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  self->inner.skip_fallback.signer  = signer; break;
  default:                          self->inner.final.signer          = signer; break;
  }
}

FD_FN_PURE static inline fd_hash_t const *
ag_vote_block_hash( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_TYPE_NOTAR:          return &self->inner.notar.block_hash;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return &self->inner.notar_fallback.block_hash;
  default:                          return NULL;
  }
}

FD_PROTOTYPES_END

#endif
