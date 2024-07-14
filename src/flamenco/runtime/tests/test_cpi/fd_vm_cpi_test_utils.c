#include "fd_vm_cpi_test_utils.h"

/* Assumes:
  - scratch frame layout l
  - HEAP_HADDR_TO_VMADDR macro defined
  - SCRATCH_CHECK macro defined
  Super hacky, but it works for now.
*/
#define VM_CPI_TEST_ALLOC_AND_COPY_PUBKEY(dest, pubkey_addr) \
    do { \
        void *pubkey_ = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), sizeof(fd_pubkey_t)); \
        SCRATCH_CHECK; \
        memcpy(pubkey_, pubkey_addr, sizeof(fd_pubkey_t)); \
        (dest) = HEAP_HADDR_TO_VMADDR(pubkey_); \
    } while(0)

#define VM_CPI_TEST_COPY_PUBKEY(dest, pubkey_addr) \
    memcpy(dest, pubkey_addr, sizeof(fd_pubkey_t))

/* BEGIN C ABI setup */

#define VM_CPI_TEST_ABI                       c
#define VM_CPI_TEST_INSTR_T                   fd_vm_c_instruction_t
#define VM_CPI_TEST_INSTR_ALIGN               (FD_VM_C_INSTRUCTION_ALIGN)
#define VM_CPI_TEST_INSTR_SIZE                (FD_VM_C_INSTRUCTION_SIZE)
#define VM_CPI_TEST_ACCOUNT_META_T            fd_vm_c_account_meta_t
#define VM_CPI_TEST_ACCOUNT_META_ALIGN        (FD_VM_C_ACCOUNT_META_ALIGN)
#define VM_CPI_TEST_ACCOUNT_META_SIZE         (FD_VM_C_ACCOUNT_META_SIZE)
#define VM_CPI_TEST_ACC_INFO_T                fd_vm_c_account_info_t
#define VM_CPI_TEST_ACC_INFO_ALIGN            (FD_VM_C_ACCOUNT_INFO_ALIGN)
#define VM_CPI_TEST_ACC_INFO_SIZE             (FD_VM_C_ACCOUNT_INFO_SIZE)



#define VM_CPI_TEST_INSTR_INIT_CALLEE_ID(instr_ptr, program_id) \
  VM_CPI_TEST_ALLOC_AND_COPY_PUBKEY((instr_ptr)->program_id_addr, program_id)

#define VM_CPI_TEST_INSTR_ASSIGN_ACCT_META_PUBKEY(meta_ptr, program_id) \
  VM_CPI_TEST_ALLOC_AND_COPY_PUBKEY((meta_ptr)->pubkey_addr, program_id)

#define VM_CPI_TEST_INSTR_ASSIGN_ACCT_META(instr_ptr, metas_ptr, metas_count) \
    do { \
        (instr_ptr)->accounts_addr = HEAP_HADDR_TO_VMADDR(metas_ptr); \
        (instr_ptr)->accounts_len = metas_count; \
    } while(0)

#define VM_CPI_TEST_INSTR_ASSIGN_DATA(instr_ptr, data_ptr, data_length) \
    do { \
        (instr_ptr)->data_addr = HEAP_HADDR_TO_VMADDR(data_ptr); \
        (instr_ptr)->data_len = data_length; \
    } while(0)

#define VM_CPI_TEST_ACC_INFO_LAMPORTS_SETUP(acc_info_ptr, lamports_u64)\
  do { \
      ulong *lamports = FD_SCRATCH_ALLOC_APPEND(l, alignof(ulong), sizeof(ulong)); \
      SCRATCH_CHECK; \
      *lamports = lamports_u64; \
      acc_info_ptr->lamports_addr = HEAP_HADDR_TO_VMADDR(lamports); \
  } while(0)

#define VM_CPI_TEST_ACC_INFO_DATA_SETUP(acc_info_ptr, data_pb_bytes) \
  do { \
      void *data = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), data_pb_bytes->size); \
      SCRATCH_CHECK; \
      memcpy(data, data_pb_bytes->bytes, data_pb_bytes->size); \
      acc_info_ptr->data_addr = HEAP_HADDR_TO_VMADDR(data); \
      acc_info_ptr->data_sz = data_pb_bytes->size; \
  } while(0)

#include "fd_vm_cpi_test_setup_common.c"


#undef VM_CPI_TEST_ABI
#undef VM_CPI_TEST_INSTR_T
#undef VM_CPI_TEST_INSTR_ALIGN
#undef VM_CPI_TEST_INSTR_SIZE
#undef VM_CPI_TEST_ACCOUNT_META_T
#undef VM_CPI_TEST_ACCOUNT_META_ALIGN
#undef VM_CPI_TEST_ACCOUNT_META_SIZE
#undef VM_CPI_TEST_ACC_INFO_T
#undef VM_CPI_TEST_ACC_INFO_ALIGN
#undef VM_CPI_TEST_ACC_INFO_SIZE

#undef VM_CPI_TEST_INSTR_INIT_CALLEE_ID
#undef VM_CPI_TEST_INSTR_ASSIGN_ACCT_META_PUBKEY
#undef VM_CPI_TEST_INSTR_ASSIGN_ACCT_META
#undef VM_CPI_TEST_INSTR_ASSIGN_DATA
#undef VM_CPI_TEST_ACC_INFO_LAMPORTS_SETUP
#undef VM_CPI_TEST_ACC_INFO_DATA_SETUP

/* END C ABI setup */

#define VM_CPI_TEST_SETUP_RUST_VEC(vec, _addr, _cap, _len) \
    do { \
        (vec)->addr = HEAP_HADDR_TO_VMADDR(_addr); \
        (vec)->cap = _cap; \
        (vec)->len = _len; \
    } while(0)

/* BEGIN Rust ABI setup */
#define VM_CPI_TEST_ABI                         rust
#define VM_CPI_TEST_INSTR_T                     fd_vm_rust_instruction_t
#define VM_CPI_TEST_INSTR_ALIGN                 (FD_VM_RUST_INSTRUCTION_ALIGN)
#define VM_CPI_TEST_INSTR_SIZE                  (FD_VM_RUST_INSTRUCTION_SIZE)
#define VM_CPI_TEST_ACCOUNT_META_T              fd_vm_rust_account_meta_t
#define VM_CPI_TEST_ACCOUNT_META_ALIGN          (FD_VM_RUST_ACCOUNT_META_ALIGN)
#define VM_CPI_TEST_ACCOUNT_META_SIZE           (FD_VM_RUST_ACCOUNT_META_SIZE)
#define VM_CPI_TEST_ACC_INFO_T                  fd_vm_rust_account_info_t
#define VM_CPI_TEST_ACC_INFO_ALIGN              (FD_VM_RUST_ACCOUNT_INFO_ALIGN)
#define VM_CPI_TEST_ACC_INFO_SIZE               (FD_VM_RUST_ACCOUNT_INFO_SIZE)

/* Assumes scratch space for rust instr appropriately allocated */
#define VM_CPI_TEST_INSTR_INIT_CALLEE_ID(instr, program_id) \
    VM_CPI_TEST_COPY_PUBKEY((instr)->pubkey, program_id)

#define VM_CPI_TEST_INSTR_ASSIGN_ACCT_META_PUBKEY(meta_ptr, program_id) \
    VM_CPI_TEST_COPY_PUBKEY((meta_ptr)->pubkey, program_id)

/* TODO: Consolidate fd_vm_rust_vec_t assignment logic */
#define VM_CPI_TEST_INSTR_ASSIGN_ACCT_META(instr, metas_ptr, metas_count) \
    VM_CPI_TEST_SETUP_RUST_VEC(&((instr)->accounts), metas_ptr, metas_count, metas_count)

#define VM_CPI_TEST_INSTR_ASSIGN_DATA(instr, data_ptr, data_len) \
    VM_CPI_TEST_SETUP_RUST_VEC(&((instr)->data), data_ptr, data_len, data_len)

#define VM_CPI_TEST_ACC_INFO_LAMPORTS_SETUP(acc_info_ptr, lamports_u64) \
  do { \
      fd_vm_rc_refcell_t *rc_ref = FD_SCRATCH_ALLOC_APPEND(l, FD_VM_RC_REFCELL_ALIGN, sizeof(fd_vm_rc_refcell_t)); \
      SCRATCH_CHECK; \
      ulong *lamports = FD_SCRATCH_ALLOC_APPEND(l, alignof(ulong), sizeof(ulong)); \
      SCRATCH_CHECK; \
      *lamports = lamports_u64; \
      rc_ref->addr = HEAP_HADDR_TO_VMADDR(lamports); \
      acc_info_ptr->lamports_box_addr = HEAP_HADDR_TO_VMADDR(rc_ref); \
  } while(0)

#define VM_CPI_TEST_ACC_INFO_DATA_SETUP(acc_info_ptr, data_pb_bytes) \
  do { \
    fd_vm_rc_refcell_vec_t * rc_ref_vec = FD_SCRATCH_ALLOC_APPEND(l, FD_VM_RUST_VEC_ALIGN, sizeof(fd_vm_rc_refcell_vec_t)); \
    SCRATCH_CHECK; \
    uchar *data = FD_SCRATCH_ALLOC_APPEND(l, alignof(uchar), data_pb_bytes->size); \
    SCRATCH_CHECK; \
    memcpy(data, data_pb_bytes->bytes, data_pb_bytes->size); \
    rc_ref_vec->addr = HEAP_HADDR_TO_VMADDR(data); \
    rc_ref_vec->len = data_pb_bytes->size; \
    acc_info_ptr->data_box_addr = HEAP_HADDR_TO_VMADDR(rc_ref_vec); \
  } while(0)

#include "fd_vm_cpi_test_setup_common.c"

#undef VM_CPI_TEST_ABI
#undef VM_CPI_TEST_INSTR_T
#undef VM_CPI_TEST_INSTR_ALIGN
#undef VM_CPI_TEST_INSTR_SIZE
#undef VM_CPI_TEST_ACCOUNT_META_T
#undef VM_CPI_TEST_ACCOUNT_META_ALIGN
#undef VM_CPI_TEST_ACCOUNT_META_SIZE
#undef VM_CPI_TEST_ACC_INFO_T
#undef VM_CPI_TEST_ACC_INFO_ALIGN
#undef VM_CPI_TEST_ACC_INFO_SIZE

#undef VM_CPI_TEST_INSTR_INIT_CALLEE_ID
#undef VM_CPI_TEST_INSTR_ASSIGN_ACCT_META_PUBKEY
#undef VM_CPI_TEST_INSTR_ASSIGN_ACCT_META
#undef VM_CPI_TEST_INSTR_ASSIGN_DATA
#undef VM_CPI_TEST_ACC_INFO_LAMPORTS_SETUP
#undef VM_CPI_TEST_ACC_INFO_DATA_SETUP

/* END Rust ABI setup */