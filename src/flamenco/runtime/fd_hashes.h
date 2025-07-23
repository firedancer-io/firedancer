#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "fd_runtime_public.h"

/* Forward declarations */
struct fd_stem_context;
typedef struct fd_stem_context fd_stem_context_t;

struct fd_replay_out_link;
typedef struct fd_replay_out_link fd_replay_out_link_t;

FD_PROTOTYPES_BEGIN

void
fd_hash_account_lthash_value( fd_pubkey_t const       * pubkey,
                              fd_account_meta_t const * account,
                              uchar const             * data,
                              fd_lthash_value_t *       lthash_out );

int
fd_update_hash_bank_exec_hash( fd_exec_slot_ctx_t *           slot_ctx,
                               fd_hash_t *                    hash,
                               fd_capture_ctx_t *             capture_ctx,
                               ulong                          signature_cnt,
                               fd_stem_context_t *            stem,
                               fd_replay_out_link_t *         capture_out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_hashes_h */
