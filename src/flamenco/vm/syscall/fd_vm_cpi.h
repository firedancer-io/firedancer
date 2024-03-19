#ifndef HEADER_fd_src_flamenco_vm_syscall_fd_vm_cpi_h
#define HEADER_fd_src_flamenco_vm_syscall_fd_vm_cpi_h

#ifndef HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_h
#error "Do not include this directly; use fd_vm_syscall.h"
#endif

/* fd_vm_cpi contains type definitions for the cross-program-invocation
   (CPI) API.  These types are passed from the virtual machine to the
   CPI syscall handlers and are thus untrusted.  Addresses are in VM
   address space.  Struct parameter offsets and sizes match exactly.
   Structs also have alignment requirements in VM address space.  These
   alignments are provided as const macros.  Since we cannot guarantee
   that a type is aligned in host address space even when aligned in VM
   address space (FIXME: HMMM ... THAT DOESN'T SOUND RIGHT), all structs
   support unaligned access (i.e. alignof(type)==1UL).

   Unfortunately, the Solana protocol provides this API twice:
   In a C-style ABI and in Rust ABI. */

#define FD_VM_RC_REFCELL_ALIGN (8UL)

struct __attribute__((packed)) fd_vm_rc_refcell_vec {
  ulong strong;
  ulong weak;
  ulong borrow;
  ulong addr;
  ulong len;
};
typedef struct fd_vm_rc_refcell_vec fd_vm_rc_refcell_vec_t;

struct __attribute__((packed)) fd_vm_rc_refcell {
  ulong strong;
  ulong weak;
  ulong borrow;
  ulong addr;
};
typedef struct fd_vm_rc_refcell fd_vm_rc_refcell_t;

/* Structs fd_vm_c_{...}_t are part of the C ABI for the cross-program
   invocation syscall API. */

#define FD_VM_C_INSTRUCTION_ALIGN (8UL)
#define FD_VM_C_INSTRUCTION_SIZE  (40UL)

struct __attribute__((packed)) fd_vm_c_instruction {
  ulong  program_id_addr;
  ulong  accounts_addr;
  ulong  accounts_len;
  ulong  data_addr;
  ulong  data_len;
};

typedef struct fd_vm_c_instruction fd_vm_c_instruction_t;

#define FD_VM_C_ACCOUNT_META_ALIGN (8UL)
#define FD_VM_C_ACCOUNT_META_SIZE  (10UL)
struct fd_vm_c_account_meta {
  ulong pubkey_addr;
  uchar is_writable;
  uchar is_signer;
};

typedef struct fd_vm_c_account_meta fd_vm_c_account_meta_t;

/* Solana stores pubkey within account meta struct and is used to check if 
   instructions are too large. 
   https://github.com/solana-labs/solana/blob/9f6ef2fe629d59d93d227d4561d8f7d5a2fd5f2f/sdk/program/src/instruction.rs#L548 */
struct fd_vm_sol_account_meta {
  fd_pubkey_t pubkey;
  uchar is_signer;
  uchar is_writable;
};

typedef struct fd_vm_sol_account_meta fd_vm_sol_account_meta_t;

#define FD_VM_C_ACCOUNT_INFO_ALIGN (8UL)
#define FD_VM_C_ACCOUNT_INFO_SIZE  (61UL)

struct fd_vm_c_account_info {
  ulong pubkey_addr;
  ulong lamports_addr;
  ulong data_sz;
  ulong data_addr;
  ulong owner_addr;
  ulong rent_epoch;
  uchar is_signer;
  uchar is_writable;
  uchar executable;
};

typedef struct fd_vm_c_account_info fd_vm_c_account_info_t;

/* Structs fd_vm_rust_{...}_t are part of the Rust ABI for the
   cross-program-invocation syscall API. */

/* fd_vm_rust_vec_t is Rust type Vec<_> using the default allocator. */

#define FD_VM_RUST_VEC_ALIGN (8UL)
#define FD_VM_RUST_VEC_SIZE  (24UL)

struct __attribute__((packed)) fd_vm_rust_vec {
  ulong addr;
  ulong cap;
  ulong len;
};

typedef struct fd_vm_rust_vec fd_vm_rust_vec_t;

#define FD_VM_RUST_RC_ALIGN (8UL)

#define FD_VM_RUST_INSTRUCTION_ALIGN (8UL)
#define FD_VM_RUST_INSTRUCTION_SIZE  (80UL)

struct __attribute__((packed)) fd_vm_rust_instruction {
  fd_vm_rust_vec_t accounts;    /* points to fd_vm_rust_account_meta_t */
  fd_vm_rust_vec_t data;        /* points to bytes */
  uchar            pubkey[32];
};

typedef struct fd_vm_rust_instruction fd_vm_rust_instruction_t;

#define FD_VM_RUST_ACCOUNT_META_ALIGN (1UL)
#define FD_VM_RUST_ACCOUNT_META_SIZE  (34UL)

struct __attribute__((packed)) fd_vm_rust_account_meta {
  uchar pubkey[32];
  uchar is_signer;
  uchar is_writable;
};

typedef struct fd_vm_rust_account_meta fd_vm_rust_account_meta_t;

#define FD_VM_RUST_ACCOUNT_INFO_ALIGN (8UL)
#define FD_VM_RUST_ACCOUNT_INFO_SIZE  (48UL)

struct __attribute__((packed)) fd_vm_rust_account_info {
  ulong pubkey_addr;          /* points to uchar[32] */
  ulong lamports_box_addr;    /* points to Rc with embedded RefCell which points to u64 */
  ulong data_box_addr;        /* points to Rc with embedded RefCell which contains slice which points to bytes */
  ulong owner_addr;           /* points to uchar[32] */
  ulong rent_epoch;
  uchar is_signer;
  uchar is_writable;
  uchar executable;
  uchar _padding_0[5];
};

typedef struct fd_vm_rust_account_info fd_vm_rust_account_info_t;

#endif /* HEADER_fd_src_flamenco_vm_syscall_fd_vm_cpi_h */
