#ifndef HEADER_fd_src_ballet_runtime_fd_sysvar_h
#define HEADER_fd_src_ballet_runtime_fd_sysvar_h

#include "../fd_executor.h"
#include "../../base58/fd_base58.h"
#include "../fd_runtime.h"

#include "fd_sysvar_clock.h"
#include "fd_sysvar_recent_hashes.h"
#include "fd_sysvar_slot_history.h"
#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar_epoch_schedule.h"
#include "fd_sysvar_fees.h"
#include "fd_sysvar_rent.h"

void fd_sysvar_set(fd_global_ctx_t *state, const unsigned char *owner, const unsigned char *pubkey, unsigned char *data, unsigned long sz, ulong slot);

#endif
