#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_h

#include "../../fd_flamenco_base.h"

int
fd_sysvar_set( fd_exec_slot_ctx_t * state,
               uchar const *        owner,
               fd_pubkey_t const *  pubkey,
               uchar *              data,
               ulong                sz,
               ulong                slot,
               ulong                lamports );

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_h */
