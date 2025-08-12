#ifndef HEADER_fd_src_flamenco_runtime_tests_harness_fd_solfuzz_h
#define HEADER_fd_src_flamenco_runtime_tests_harness_fd_solfuzz_h

/* fd_solfuzz.h provides internal/unstable APIs for executing solfuzz
   inputs.  This API is fully object-oriented and does not use globals
   (other than a fd_shmem region registration).

   Supports a number of advanced features:
   - Custom memory workspace setups
   - Multi-threaded use
   - Multi-session use */

#include "../../capture/fd_solcap_writer.h"
#include "../../../funk/fd_funk.h"

/* A fd_solfuzz_runner_t object processes solfuzz inputs.  Can be reused
   for different inputs, even of different types.  Single-thread per
   object, but multiple threads can use different objects.  Each object
   holds a shared mutable reference to a workspace throughout its
   lifetime.  Multiple solfuzz runner objects can share a workspace with
   each other (or any other allocations) just fine. */

struct fd_solfuzz_runner {
  fd_funk_t    funk[1];
  fd_wksp_t *  wksp;
  fd_spad_t *  spad;
  fd_banks_t * banks;
  fd_bank_t *  bank;

  fd_solcap_writer_t * solcap;
  void *               solcap_file; /* FILE * */
};

typedef struct fd_solfuzz_runner fd_solfuzz_runner_t;

FD_PROTOTYPES_BEGIN

/* Constructor */

/* fd_solfuzz_runner_new allocates a new solfuzz runner object, a bank
   context, and ~5 GiB of scratch memory (worst case bound for the most
   expensive input type).

   Scratch memory is lazily used/initialized, therefore plays well with
   demand paged memory. */

fd_solfuzz_runner_t *
fd_solfuzz_runner_new( fd_wksp_t * wksp,
                       ulong       wksp_tag );

/* fd_solfuzz_runner_delete frees all previously done workspace
   allocations. */

void
fd_solfuzz_runner_delete( fd_solfuzz_runner_t * runner );

/* fd_wksp_demand_paged_new attempts to create a workspace backed by
   demand-paged transparent huge page memory. */

fd_wksp_t *
fd_wksp_demand_paged_new( char const * name,
                          uint         seed,
                          ulong        part_max,
                          ulong        data_max );

/* fd_wksp_demand_paged_delete destroys a demand-paged workspace. */

void
fd_wksp_demand_paged_delete( fd_wksp_t * wksp );

/* Methods

   fd_solfuzz_<target>_run executes a Protobuf test input and returns a
   Protobuf test output.

   fd_solfuzz_<target>_fixture executes a Protobuf test fixture
   (containing both inputs and expected outputs).  Silently returns 1 if
   actual output matches expected output.  Returns 0 and logs diff if
   a mismatch occurred. */

/* SVM Instruction Execution */

ulong
fd_solfuzz_instr_run( fd_solfuzz_runner_t * runner,
                      void const *          input_,
                      void **               output_,
                      void *                output_buf,
                      ulong                 output_bufsz );

int
fd_solfuzz_instr_fixture( fd_solfuzz_runner_t * runner,
                          uchar const *         in,
                          ulong                 in_sz );

/* SVM Transaction Execution */

ulong
fd_solfuzz_txn_run( fd_solfuzz_runner_t * runner,
                    void const *          input_,
                    void **               output_,
                    void *                output_buf,
                    ulong                 output_bufsz );

int
fd_solfuzz_txn_fixture( fd_solfuzz_runner_t * runner,
                        uchar const *         in,
                        ulong                 in_sz );

/* SVM Block Execution

   - All sysvars must be provided
   - This does not test sigverify or POH
   - Epoch boundaries are tested
   - Associated entrypoint tested in Agave is `confirm_slot_entries` (except sigverify and verify_ticks are removed)
   - (idk about this yet) Recent blockhashes sysvar account must NOT be provided in the input account states.
     Instead, the sysvar is populated through the input blockhash queue.  */

ulong
fd_solfuzz_block_run( fd_solfuzz_runner_t * runner,
                      void const *          input_,
                      void **               output_,
                      void *                output_buf,
                      ulong                 output_bufsz );

int
fd_solfuzz_block_fixture( fd_solfuzz_runner_t * runner,
                          uchar const *         in,
                          ulong                 in_sz );

/* SVM Program Loading

   Loads an ELF binary (in input->elf.data()).
   output_buf points to a memory region of output_bufsz bytes where the
   result is allocated into. During execution, the contents of
   fd_sbpf_program_t are wrapped in *output (backed by output_buf).

   Returns number of bytes allocated at output_buf OR 0UL on any
   harness-specific failures. Execution failures still return number of allocated bytes,
   but output is incomplete/undefined. */

ulong
fd_solfuzz_elf_loader_run( fd_solfuzz_runner_t * runner,
                           void const *          input_,
                           void **               output_,
                           void *                output_buf,
                           ulong                 output_bufsz );

int
fd_solfuzz_elf_loader_fixture( fd_solfuzz_runner_t * runner,
                               uchar const *         in,
                               ulong                 in_sz );

/* SVM sBPF Syscall Handling */

ulong
fd_solfuzz_syscall_run( fd_solfuzz_runner_t * runner,
                        void const *          input_,
                        void **               output_,
                        void *                output_buf,
                        ulong                 output_bufsz );

int
fd_solfuzz_syscall_fixture( fd_solfuzz_runner_t * runner,
                            uchar const *         in,
                            ulong                 in_sz );

/* SVM sBPF Bytecode Execution */

ulong
fd_solfuzz_vm_interp_run( fd_solfuzz_runner_t * runner,
                          void const *          input,
                          void **               output,
                          void *                output_buf,
                          ulong                 output_bufsz );

int
fd_solfuzz_vm_interp_fixture( fd_solfuzz_runner_t * runner,
                              uchar const *         in,
                              ulong                 in_sz );

/* Bincode Encoding */

ulong
fd_solfuzz_type_run( fd_solfuzz_runner_t * runner,
                     void const *          input_,
                     void **               output_,
                     void *                output_buf,
                     ulong                 output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_harness_fd_solfuzz_h */
