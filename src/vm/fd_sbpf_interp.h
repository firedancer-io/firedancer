#ifndef HEADER_fd_src_vm_fd_sbpf_interp_h
#define HEADER_fd_src_vm_fd_sbpf_interp_h

#include "fd_instr.h"
#include "fd_opcodes.h"
#include "fd_mem_map.h"
#include "fd_stack.h"
#include "fd_log_collector.h"

#define FD_VM_HEAP_SZ (32*1024)

/* sBPF instruction validation error codes */

#define FD_VM_SBPF_VALIDATE_SUCCESS               (0UL)  /* Program is valid. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_OPCODE    (1UL)  /* An invalid opcode was used. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_SRC_REG   (2UL)  /* An invalid source register was used. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_DST_REG   (3UL)  /* An invalid destination register was used. */
#define FD_VM_SBPF_VALIDATE_ERR_INF_LOOP          (4UL)  /* An infinite loop was detected. */
#define FD_VM_SBPF_VALIDATE_ERR_JMP_OUT_OF_BOUNDS (5UL)  /* An out of bounds jump was detected. */
#define FD_VM_SBPF_VALIDATE_ERR_JMP_TO_ADDL_IMM   (6UL)  /* A jump to a FD_BPF_INSTR_ADDL_IMM was detected. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_END_IMM   (7UL)  /* An invalid immediate was used for an endianness conversion instruction. */
#define FD_VM_SBPF_VALIDATE_ERR_INCOMPLETE_LDQ    (8UL)  /* The program ends with an FD_BPF_INSTR_LDQ. */
#define FD_VM_SBPF_VALIDATE_ERR_LDQ_NO_ADDL_IMM   (9UL)  /* An FD_BPF_INSTR_LDQ did not have an FD_BPF_ADDL_IMM after it. */
#define FD_VM_SBPF_VALIDATE_ERR_NO_SUCH_EXT_CALL  (10UL) /* An FD_BPF_INSTR_CALL had an immediate but no function was registered for that immediate. */

typedef uchar fd_pubkey_t[32];

/* Foward definition of fd_vm_sbpf_exec_context_t. */ 
struct fd_vm_sbpf_exec_context;
typedef struct fd_vm_sbpf_exec_context fd_vm_sbpf_exec_context_t;

/* Syscall function type for all sBPF syscall/external function calls. They take a context from 
   the VM and VM registers 1-5 as input, and return a value to VM register 0. The syscall return 
   value is a status code for the syscall. */
typedef ulong (*fd_vm_sbpf_syscall_fn_ptr_t)(fd_vm_sbpf_exec_context_t * ctx, ulong arg0, ulong arg1, ulong arg2, ulong arg3, ulong arg4, ulong * ret);

/* Definition of the map of syscalls used in sBPF programs */
struct fd_vm_sbpf_syscall_map {
  uint key;
  uint hash;

  fd_vm_sbpf_syscall_fn_ptr_t syscall_fn_ptr;
};
typedef struct fd_vm_sbpf_syscall_map fd_vm_sbpf_syscall_map_t;

#define MAP_NAME        fd_vm_sbpf_syscall_map
#define MAP_T           fd_vm_sbpf_syscall_map_t
#define MAP_LG_SLOT_CNT 6
#include "../util/tmpl/fd_map.c"

/* Definition of the map of local calls used in sBPF programs */
struct fd_vm_sbpf_local_call_map {
  uint key;
  uint hash;

  ulong offset;
};
typedef struct fd_vm_sbpf_local_call_map fd_vm_sbpf_local_call_map_t;
#define MAP_NAME        fd_vm_sbpf_local_call_map
#define MAP_T           fd_vm_sbpf_local_call_map_t
#define MAP_LG_SLOT_CNT 10
#include "../util/tmpl/fd_map.c"

/* Account specific info passed to a program as input during sBPF execution */
struct fd_vm_sbpf_exec_account_info {
  fd_pubkey_t   pubkey;         /* The pubkey for this account. */
  ulong         lamports;       /* The balance of this account. */
  ulong         data_len;       /* The length of the data in this account. */
  uchar *       data;           /* The data in this account. */
  fd_pubkey_t   owner;          /* The pubkey of the owner of this account. */
  ulong         rent_epoch;     /* The most recent rent epoch for this account. */
  uint          is_signer;      /* Is this account a signer? */
  uint          is_writable;    /* Is this account writable? */
  uint          is_executable;  /* Is this account executable? */ 
  uint          is_duplicate;
  uchar         index_of_origin;
};
typedef struct fd_vm_sbpf_exec_account_info fd_vm_sbpf_exec_account_info_t;

/* The input data passed to an sBPF program before execution. */
struct fd_vm_sbpf_exec_params {
  fd_vm_sbpf_exec_account_info_t *  accounts;     /* The account info as requested for this transaction */
  ulong                             accounts_len; /* The number of accounts requested */
  uchar *                           data;         /* Input data */
  ulong                             data_len;     /* Input data len */
  fd_pubkey_t *                     program_id;   /* The pubkey of the program we are executing */
};
typedef struct fd_vm_sbpf_exec_params fd_vm_sbpf_exec_params_t;

// FIXME: THE HEAP IS RESIZEABLE AT RUNTIME ~~ugh~~
/* The sBPF execution context. This is the primary data structure that is evolved before, during
   and after contract execution. */
struct fd_vm_sbpf_exec_context {
  /* Read-only VM parameters: */
  long                        entrypoint;     /* The initial program counter to start at */
  fd_vm_sbpf_syscall_map_t    syscall_map;    /* The map of syscalls that can be called into */
  fd_vm_sbpf_local_call_map_t local_call_map; /* The map of local calls that can be called into */
  fd_vm_sbpf_instr_t *        instrs;         /* The program instructions */
  ulong                       instrs_sz;      /* The number of program instructions */
  
  /* Writable VM parameters: */
  ulong                 register_file[11];    /* The sBPF register storage */
  ulong                 program_counter;      /* The current instruction index being executed */
  ulong                 instruction_counter;  /* The number of instructions which have been executed */
  fd_vm_log_collector_t log_collector;        /* The log collector used by `sol_log_*` syscalls */
  ulong                 compute_budget;       /* The remaining CUs left for the transaction */

  /* Memory regions: */
  uchar *       read_only;            /* The read-only memory region, typically just the relocated program binary blob */
  ulong         read_only_sz;         /* The read-only memory region size */
  uchar *       input;                /* The program input memory region */
  ulong         input_sz;             /* The program input memory region size */
  fd_vm_stack_t stack;                /* The sBPF call frame stack */
  uchar         heap[FD_VM_HEAP_SZ];  /* The heap memory allocated by the bump allocator syscall */ 
};

struct fd_vm_sbpf_trace_entry { 
  ulong pc;
  ulong ic;
  ulong register_file[11];
};
typedef struct fd_vm_sbpf_trace_entry fd_vm_sbpf_trace_entry_t;

ulong fd_vm_serialize_input_params( fd_vm_sbpf_exec_params_t * params, uchar * buf, ulong buf_sz );

/* Registers a syscall by name to an execution context. */
void fd_vm_sbpf_interp_register_syscall( fd_vm_sbpf_exec_context_t * ctx, char const * name, fd_vm_sbpf_syscall_fn_ptr_t fn_ptr ); 

/* Registers a local call by name to an execution context. */
void fd_vm_sbpf_interp_register_local_call( fd_vm_sbpf_exec_context_t * ctx, char const * name, ulong offset ); 

/* Runs the sBPF program from the context until completion or a fault occurs. Returns success
   or an error/fault code. */
ulong fd_vm_sbpf_interp_instrs( fd_vm_sbpf_exec_context_t * ctx );
ulong fd_vm_sbpf_interp_instrs_trace( fd_vm_sbpf_exec_context_t * ctx, fd_vm_sbpf_trace_entry_t * trace, ulong trace_sz, ulong * trace_used );

/* Validates the sBPF program from the given context. Returns success or an error code. */ 
ulong fd_vm_sbpf_interp_validate( fd_vm_sbpf_exec_context_t * ctx );

// FIXME: crossing region boundaries is probably bad
/* Translates an address from the VM address space to the host address space. Takes an execution 
   context, whether this is a read or write (0 for read, 1 for write), the VM addresss, the size of
   the access, and the location for storing the host address on success. Returns success or
   an error code (a fault). On success, the host_addr is set to the actual host_addr. */
ulong fd_vm_sbpf_interp_translate_vm_to_host( fd_vm_sbpf_exec_context_t * ctx,
                                              uint                        write,
                                              ulong                       vm_addr,
                                              ulong                       sz,
                                              void * *                    host_addr );

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_sbpf_interp_h */
