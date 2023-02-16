#ifndef HEADER_fd_src_ballet_runtime_fd_global_state_h
#define HEADER_fd_src_ballet_runtime_fd_global_state_h

struct fd_global_state {
  fd_deserializable_versioned_bank_t * solana_bank;
  fd_accounts_db_fields_t *            solana_account;
};
typedef struct fd_global_state fd_global_state_t;
#define FD_GLOBAL_STATE_FOOTPRINT sizeof(fd_global_state_t)
#define FD_GLOBAL_STATE_ALIGN (8UL)

#endif
