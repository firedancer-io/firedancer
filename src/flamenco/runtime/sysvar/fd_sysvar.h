#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_h

#include "../fd_executor.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../fd_runtime.h"

#include "fd_sysvar_clock.h"
#include "fd_sysvar_recent_hashes.h"
#include "fd_sysvar_slot_history.h"
#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar_epoch_schedule.h"
#include "fd_sysvar_epoch_rewards.h"
#include "fd_sysvar_fees.h"
#include "fd_sysvar_rent.h"
#include "fd_sysvar_stake_history.h"
#include "fd_sysvar_last_restart_slot.h"
#include "fd_sysvar_instructions.h"

int
fd_sysvar_set( fd_exec_slot_ctx_t * state,
               uchar const *        owner,
               fd_pubkey_t const *  pubkey,
               uchar *              data,
               ulong                sz,
               ulong                slot,
               fd_acc_lamports_t const * lamports );

#endif
