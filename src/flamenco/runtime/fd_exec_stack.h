#ifndef HEADER_fd_src_flamenco_runtime_fd_exec_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_exec_stack_h

#include "program/fd_bpf_loader_program.h"
#include "program/fd_vote_program.h"
#include "fd_runtime_const.h"

struct fd_exec_accounts {
  uchar rollback_nonce_account_mem[ FD_ACC_TOT_SZ_MAX ]                       __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  uchar rollback_fee_payer_mem[ FD_ACC_TOT_SZ_MAX ]                           __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  uchar accounts_mem[ FD_RUNTIME_WRITABLE_ACCOUNTS_MAX ][ FD_ACC_TOT_SZ_MAX ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
};
typedef struct fd_exec_accounts fd_exec_accounts_t;

struct fd_exec_stack {

  struct {
    uchar serialization_mem[ FD_MAX_INSTRUCTION_STACK_DEPTH ][ BPF_LOADER_SERIALIZATION_FOOTPRINT ] __attribute__((aligned(FD_RUNTIME_EBPF_HOST_ALIGN)));
  } bpf_loader_serialization;

  struct {
    uchar rodata        [ FD_RUNTIME_ACC_SZ_MAX ]     __attribute__((aligned(FD_SBPF_PROG_RODATA_ALIGN)));
    uchar sbpf_footprint[ FD_SBPF_PROGRAM_FOOTPRINT ] __attribute__((aligned(alignof(fd_sbpf_program_t))));
    uchar programdata   [ FD_RUNTIME_ACC_SZ_MAX ]     __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  } bpf_loader_program;

  union {
    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT ]    __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT ]        __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } authorize;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT ]    __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT ]        __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } update_validator_identity;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT ]    __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT ]        __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } update_commission;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT ]    __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem     [ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT ]        __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } withdraw;

    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_AUTHORIZED_VOTERS_FOOTPRINT ]    __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar vote_lockout_mem     [ FD_VOTE_LOCKOUTS_FOOTPRINT ]        __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
    } init_account;

    struct {
      uchar vote_state_mem             [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem      [ FD_AUTHORIZED_VOTERS_FOOTPRINT ]    __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar vote_state_landed_votes_mem[ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar tower_sync_landed_votes_mem[ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
    } tower_sync;

    struct {
      /* Deprecated instructions */
      uchar vote_state_mem            [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem     [ FD_AUTHORIZED_VOTERS_FOOTPRINT ]    __attribute__((aligned(FD_AUTHORIZED_VOTERS_ALIGN)));
      uchar landed_votes_mem          [ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
      uchar vote_lockout_mem          [ FD_VOTE_LOCKOUTS_FOOTPRINT ]        __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
      uchar compact_vs_lockout_mem    [ FD_VOTE_LOCKOUTS_FOOTPRINT ]        __attribute__((aligned(FD_VOTE_LOCKOUTS_ALIGN)));
      uchar vs_update_landed_votes_mem[ FD_LANDED_VOTES_FOOTPRINT ]         __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
    } process_vote;

  } vote_program;

  union {
    struct {
      uchar vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar authorized_voters_mem[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
      uchar landed_votes_mem     [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
    } delegate;
    struct {
      uchar delinquent_vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar delinquent_authorized_voters_mem[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
      uchar delinquent_landed_votes_mem     [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));

      uchar reference_vote_state_mem       [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
      uchar reference_authorized_voters_mem[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
      uchar reference_landed_votes_mem     [ FD_VOTE_STATE_VERSIONED_FOOTPRINT ] __attribute__((aligned(128UL)));
    } deactivate_delinquent;
  } stake_program;
};
typedef struct fd_exec_stack fd_exec_stack_t;

#endif /* HEADER_fd_src_flamenco_runtime_fd_exec_stack_h */
