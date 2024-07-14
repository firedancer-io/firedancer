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
#define VM_CPI_TEST_SETUP FD_EXPAND_THEN_CONCAT2(setup_cpi_, VM_CPI_TEST_ABI)
int
VM_CPI_TEST_SETUP(fd_vm_t *vm, fd_exec_test_cpi_instr_t const *cpi_instr)
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
    VM_CPI_TEST_INSTR_T instr;

    // Load callee program id
    VM_CPI_TEST_INSTR_INIT_CALLEE_ID(&instr, cpi_instr->callee_program_id);

    // Account Metas
    // fact: instr.accounts_len is the number of account metas
    // fact: account_meta.pubkey_addr is a pointer to the pubkey
    VM_CPI_TEST_ACCOUNT_META_T *account_metas = FD_SCRATCH_ALLOC_APPEND(l, VM_CPI_TEST_ACCOUNT_META_ALIGN, cpi_instr->acct_metas_count * VM_CPI_TEST_ACCOUNT_META_SIZE);
    SCRATCH_CHECK;

    for( ulong i = 0UL; i < cpi_instr->acct_metas_count; i++ ) {
        fd_exec_test_cpi_account_meta_t *account_meta = &cpi_instr->acct_metas[i];
        VM_CPI_TEST_ACCOUNT_META_T *meta = &account_metas[i];

        // FIXME: Rename
        VM_CPI_TEST_INSTR_ASSIGN_ACCT_META_PUBKEY(meta, account_meta->pubkey);
        
        // FIXME: Also use templates for these?
        meta->is_writable = account_meta->is_writable;
        meta->is_signer = account_meta->is_signer;
    }
    
    VM_CPI_TEST_INSTR_ASSIGN_ACCT_META(&instr, account_metas, cpi_instr->acct_metas_count);

    // Data
    void *data = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), cpi_instr->data->size);
    SCRATCH_CHECK;    
    memcpy(data, cpi_instr->data->bytes, cpi_instr->data->size);
    VM_CPI_TEST_INSTR_ASSIGN_DATA(&instr, data, cpi_instr->data->size);


    // Load CPI instruction into heap
    void *instr_addr = FD_SCRATCH_ALLOC_APPEND(l, VM_CPI_TEST_INSTR_ALIGN, VM_CPI_TEST_INSTR_SIZE);
    SCRATCH_CHECK;
    memcpy(instr_addr, &instr, VM_CPI_TEST_INSTR_SIZE);

    // Save to reg[1]
    vm->reg[1] = HEAP_HADDR_TO_VMADDR(instr_addr);
    //////////////// End CPI Instruction

    //////////////// Account infos
    VM_CPI_TEST_ACC_INFO_T *account_infos = FD_SCRATCH_ALLOC_APPEND(l, VM_CPI_TEST_ACC_INFO_ALIGN, cpi_instr->accounts_count * VM_CPI_TEST_ACC_INFO_SIZE);
    SCRATCH_CHECK;

    for( ulong i = 0UL; i < cpi_instr->accounts_count; i++ ) {
        fd_exec_test_acct_state_t *account = &cpi_instr->accounts[i];
        VM_CPI_TEST_ACC_INFO_T *info = &account_infos[i];
        info->is_signer = account->is_signer;
        info->is_writable = account->is_writable;
        info->executable = account->executable;
        info->rent_epoch = account->rent_epoch;

        // TEMPLATIZE lamports and data, they are RefCells in rust version
        VM_CPI_TEST_ACC_INFO_LAMPORTS_SETUP(info, account->lamports);

        VM_CPI_TEST_ACC_INFO_DATA_SETUP(info, account->data);

        VM_CPI_TEST_ALLOC_AND_COPY_PUBKEY(info->pubkey_addr, account->address);
        VM_CPI_TEST_ALLOC_AND_COPY_PUBKEY(info->owner_addr, account->owner);
    }

    // Save to reg[2] and reg[3]
    vm->reg[2] = HEAP_HADDR_TO_VMADDR(account_infos);
    vm->reg[3] = cpi_instr->accounts_count;

    //////////////// End Account infos

    //////////////// Signers seeds
    // Pointer to C-array of fd_vm_vec_t (signer's seeds) where each
    // element is another fd_vm_vec_t (seed)
    // Note diff between signerS_seeds and signer_seeds
    // Thankfully no need to TEMPLATIZE this!!! (Why tho?)
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