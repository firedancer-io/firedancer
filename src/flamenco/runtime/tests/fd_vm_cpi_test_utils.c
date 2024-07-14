#include "fd_vm_cpi_test_utils.h"



/* End State
    - CPI instruction (callee id, acct metas, instr data) loaded somewhere
      in heap space
    - Account infos and Signers seeds loaded in heap space
    - Registers appropriately set ? (technically not necessary, just need
      correct arguments for syscall)
        1. Pointer to CPI instruction (vm address) 
        2. Pointer to Account infos (vm address)
        3. Number of Account infos
        4. Pointer to signer seeds (vm address) 
            - This is a pointer to an array of pointers!
        5. Number of signer seeds
    - Need to ensure all pointers are in VM addr space
        - Maybe not all? 
    - Cannot exceed heap space
    - FIXME: Is heap space the appropriate place to store these values?
*/
int
setup_c_cpi_instr(fd_vm_t *vm, fd_exec_test_cpi_instr_t const *cpi_instr)
{   
    ulong heap_end = (ulong)vm->heap + vm->heap_max;

    #define HEAP_HADDR_TO_VMADDR(haddr) \
     ((ulong)(haddr) - (ulong)vm->heap + FD_VM_MEM_MAP_HEAP_REGION_START)


    uchar *heap_cpi_start = vm->heap + vm->heap_sz;
    FD_SCRATCH_ALLOC_INIT(l, heap_cpi_start);

    #define SCRATCH_CHECK \
        do { \
            if( FD_UNLIKELY( _l >= heap_end ) ) { \
                return -1; \
            } \
        } while(0)
    ////////////// CPI Instruction 
    fd_vm_c_instruction_t instr;

    // Load callee program id
    void *program_id =  FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), sizeof(fd_pubkey_t));
    SCRATCH_CHECK;

    memcpy(program_id, cpi_instr->callee_program_id, sizeof(fd_pubkey_t));
    instr.program_id_addr = HEAP_HADDR_TO_VMADDR(program_id);

    // Account Metas
    // fact: instr.accounts_len is in fact the number of account metas
    // fact: account_meta.pubkey_addr is a pointer to the pubkey
    fd_vm_c_account_meta_t *account_metas = FD_SCRATCH_ALLOC_APPEND(l, FD_VM_C_ACCOUNT_META_ALIGN, cpi_instr->acct_metas_count * FD_VM_C_ACCOUNT_META_SIZE);
    SCRATCH_CHECK;

    for( ulong i = 0UL; i < cpi_instr->acct_metas_count; i++ ) {
        fd_exec_test_cpi_account_meta_t *account_meta = &cpi_instr->acct_metas[i];
        void *pubkey = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), sizeof(fd_pubkey_t));
        SCRATCH_CHECK;
        memcpy(pubkey, account_meta->pubkey, sizeof(fd_pubkey_t));
        fd_vm_c_account_meta_t *meta = &account_metas[i];
        meta->pubkey_addr = HEAP_HADDR_TO_VMADDR(pubkey);
        meta->is_writable = account_meta->is_writable;
        meta->is_signer = account_meta->is_signer;
    }

    // Data
    void *data = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), cpi_instr->data->size);
    SCRATCH_CHECK;
    
    memcpy(data, cpi_instr->data->bytes, cpi_instr->data->size);
    instr.data_addr = HEAP_HADDR_TO_VMADDR(data);
    instr.data_len = cpi_instr->data->size;

    // Load CPI instruction into heap
    void *instr_addr = FD_SCRATCH_ALLOC_APPEND(l, FD_VM_C_INSTRUCTION_ALIGN, FD_VM_C_INSTRUCTION_SIZE);
    SCRATCH_CHECK;
    memcpy(instr_addr, &instr, FD_VM_C_INSTRUCTION_SIZE);
    // Save to reg[1]
    vm->reg[1] = HEAP_HADDR_TO_VMADDR(instr_addr);
    //////////////// End CPI Instruction

    //////////////// Account infos
    fd_vm_c_account_info_t *account_infos = FD_SCRATCH_ALLOC_APPEND(l, FD_VM_C_ACCOUNT_INFO_ALIGN, cpi_instr->accounts_count * FD_VM_C_ACCOUNT_INFO_SIZE);
    SCRATCH_CHECK;

    for( ulong i = 0UL; i < cpi_instr->accounts_count; i++ ) {
        fd_exec_test_acct_state_t *account = &cpi_instr->accounts[i];
        fd_vm_c_account_info_t *info = &account_infos[i];
        info->is_signer = account->is_signer;
        info->is_writable = account->is_writable;
        info->executable = account->executable;
        info->rent_epoch = account->rent_epoch;
        info->data_sz = account->data->size;

        void *lamports = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), sizeof(ulong)*2); /* FIXME: verify size */
        void *data = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), account->data->size);
        void *owner = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), sizeof(fd_pubkey_t));
        void *pubkey = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), sizeof(fd_pubkey_t));

        SCRATCH_CHECK;
        memcpy(lamports, &account->lamports, sizeof(ulong)*2);
        memcpy(data, account->data->bytes, account->data->size);
        memcpy(owner, account->owner, sizeof(fd_pubkey_t));
        memcpy(pubkey, account->address, sizeof(fd_pubkey_t));

        info->lamports_addr = HEAP_HADDR_TO_VMADDR(lamports);
        info->data_addr = HEAP_HADDR_TO_VMADDR(data);
        info->owner_addr = HEAP_HADDR_TO_VMADDR(owner);
        info->pubkey_addr = HEAP_HADDR_TO_VMADDR(pubkey);
    }

    // Save to reg[2] and reg[3]
    vm->reg[2] = HEAP_HADDR_TO_VMADDR(account_infos);
    vm->reg[3] = cpi_instr->accounts_count;

    //////////////// End Account infos

    //////////////// Signers seeds
    // Pointer to C-array of fd_vm_vec_t (signer's seeds) where each
    // element is another fd_vm_vec_t (seed)
    // Note diff between signerS_seeds and signer_seeds
    fd_vm_vec_t *signers_seeds = FD_SCRATCH_ALLOC_APPEND(l, FD_VM_VEC_ALIGN, cpi_instr->signers_seeds_count * FD_VM_VEC_SIZE);
    SCRATCH_CHECK;
    for( ulong i = 0UL; i < cpi_instr->signers_seeds_count; i++ ) {
        fd_exec_test_cpi_signer_t *signer = &cpi_instr->signers_seeds[i];
        fd_vm_vec_t *seeds = FD_SCRATCH_ALLOC_APPEND(l, FD_VM_VEC_ALIGN, signer->seeds_count * FD_VM_VEC_SIZE);
        SCRATCH_CHECK;

        // fd_vec_t * seeds
        for( ulong j = 0UL; j < signer->seeds_count; j++ ) {
            // fd_vec_t seed_j points to C-array of bytes, variable length up to 32
            pb_bytes_array_t *seed_bytes = signer->seeds[j];
            void *seed = FD_SCRATCH_ALLOC_APPEND(l, sizeof(uchar), seed_bytes->size);
            SCRATCH_CHECK;
            memcpy(seed, seed_bytes->bytes, seed_bytes->size);

            fd_vm_vec_t *seed_vec = &seeds[j];
            seed_vec->addr = HEAP_HADDR_TO_VMADDR(seed);
            seed_vec->len = seed_bytes->size;
        }

        fd_vm_vec_t *signer_seeds_vec = &signers_seeds[i];
        signer_seeds_vec->addr = HEAP_HADDR_TO_VMADDR(seeds);
        signer_seeds_vec->len = signer->seeds_count;
    }

    // Save to reg[4] and reg[5]
    vm->reg[4] = HEAP_HADDR_TO_VMADDR(signers_seeds);
    vm->reg[5] = cpi_instr->signers_seeds_count;

    //////////////// End Signers seeds

    ulong heap_cpi_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    vm->heap_sz = heap_cpi_end - (ulong)vm->heap;
    
    return 0;
}