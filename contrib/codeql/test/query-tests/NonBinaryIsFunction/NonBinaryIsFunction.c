// Add missing typedef and define
#define FD_EXECUTOR_INSTR_ERR_MISSING_ACC (-33) /* An account required by the instruction is missing */
#define FD_BANK_FLAGS_DEAD (0x00000008UL)       /* Dead.  We stopped replaying it before we could finish it (e.g. invalid block or pruned minority fork). */

typedef struct
{
    int acct_cnt;
    struct
    {
        int is_signer;
    } accounts[10];
} fd_instr_info_t;

typedef struct
{
    int flags;
} fd_bank_t;

int fd_instr_acc_is_signer_idx(fd_instr_info_t const *instr,
                               short idx)
{
    if (FD_UNLIKELY(idx >= instr->acct_cnt))
    {
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC; // $ Alert (returns -33 which is not 0 or 1)
    }

    return !!(instr->accounts[idx].is_signer);
}

static inline int
fd_banks_is_bank_dead(fd_bank_t *bank)
{
    return bank->flags & FD_BANK_FLAGS_DEAD; // $ Alert (returns value in [0, 8])
}

// inspired by the function, but heavily simplified
int fd_bn254_pairing_is_one_syscall(unsigned long in_sz)
{
    if (in_sz != 128UL)
    {
        return -1; // No alert
    }
    return 0;
}