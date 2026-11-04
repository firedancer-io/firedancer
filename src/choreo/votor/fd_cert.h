#ifndef HEADER_fd_src_choreo_votor_fd_cert_h
#define HEADER_fd_src_choreo_votor_fd_cert_h

#include "../../ballet/bls/fd_bls.h"
#include "fd_epoch_info.h"
#include "fd_votor_base.h"

#define FD_CERT_KIND_FINAL          (0)
#define FD_CERT_KIND_FAST_FINAL     (1)
#define FD_CERT_KIND_NOTAR          (2)
#define FD_CERT_KIND_NOTAR_FALLBACK (3)
#define FD_CERT_KIND_SKIP           (4)

#define FD_CERT_VERIFY_SUCCESS       ( 0)
#define FD_CERT_VERIFY_ERR_THRESHOLD (-1) /* the signers do not have enough stake, the signature is not checked */
#define FD_CERT_VERIFY_ERR_SIG       (-2) /* the signature does not verify */

struct fd_cert_final {
  ulong        slot;
  fd_bls_agg_t agg;
  ulong        stake;
  ushort       shred_version;
};
typedef struct fd_cert_final fd_cert_final_t;

struct fd_cert_fast_final {
  ulong           slot;
  fd_block_hash_t block_hash;
  fd_bls_agg_t    agg;
  ulong           stake;
  ushort          shred_version;
};
typedef struct fd_cert_fast_final fd_cert_fast_final_t;

struct fd_cert_notar {
  ulong           slot;
  fd_block_hash_t block_hash;
  fd_bls_agg_t    agg;
  ulong           stake;
  ushort          shred_version;
};
typedef struct fd_cert_notar fd_cert_notar_t;

struct fd_cert_notar_fallback {
  ulong           slot;
  fd_block_hash_t block_hash;
  fd_bls_agg_t    agg_notar;
  fd_bls_agg_t    agg_notar_fallback;
  ulong           stake;
  ushort          shred_version;
};
typedef struct fd_cert_notar_fallback fd_cert_notar_fallback_t;

struct fd_cert_skip {
  ulong        slot;
  fd_bls_agg_t agg_skip;
  fd_bls_agg_t agg_skip_fallback;
  ulong        stake;
  ushort       shred_version;
};
typedef struct fd_cert_skip fd_cert_skip_t;

struct fd_cert {
  uint kind;
  union {
    fd_cert_final_t          final;
    fd_cert_fast_final_t     fast_final;
    fd_cert_notar_t          notar;
    fd_cert_notar_fallback_t notar_fallback;
    fd_cert_skip_t           skip;
  };
};
typedef struct fd_cert fd_cert_t;

FD_PROTOTYPES_BEGIN

/* Definition 11. Cert::slot */

FD_FN_PURE static inline ulong
fd_cert_slot( fd_cert_t const * self ) {
  switch( self->kind ) {
  case FD_CERT_KIND_FINAL:          return self->final.slot;
  case FD_CERT_KIND_FAST_FINAL:     return self->fast_final.slot;
  case FD_CERT_KIND_NOTAR:          return self->notar.slot;
  case FD_CERT_KIND_NOTAR_FALLBACK: return self->notar_fallback.slot;
  case FD_CERT_KIND_SKIP:           return self->skip.slot;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Definition 11. Cert::block_hash */

FD_FN_PURE static inline fd_block_hash_t const *
fd_cert_block_hash( fd_cert_t const * self ) {
  switch( self->kind ) {
  case FD_CERT_KIND_FINAL:          return NULL;
  case FD_CERT_KIND_FAST_FINAL:     return &self->fast_final.block_hash;
  case FD_CERT_KIND_NOTAR:          return &self->notar.block_hash;
  case FD_CERT_KIND_NOTAR_FALLBACK: return &self->notar_fallback.block_hash;
  case FD_CERT_KIND_SKIP:           return NULL;
  default:                          FD_LOG_CRIT(( "unreachable" )); }
}

FD_FN_PURE static inline ushort
fd_cert_shred_version( fd_cert_t const * self ) {
  switch( self->kind ) {
  case FD_CERT_KIND_FINAL:          return self->final.shred_version;
  case FD_CERT_KIND_FAST_FINAL:     return self->fast_final.shred_version;
  case FD_CERT_KIND_NOTAR:          return self->notar.shred_version;
  case FD_CERT_KIND_NOTAR_FALLBACK: return self->notar_fallback.shred_version;
  case FD_CERT_KIND_SKIP:           return self->skip.shred_version;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Definition 13. ValidatedCert::try_new */

int
fd_cert_verify( fd_cert_t const *       self,
                fd_epoch_info_t const * epoch_info );

FD_PROTOTYPES_END

#endif
