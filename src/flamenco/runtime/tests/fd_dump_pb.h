#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_dump_pb_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_dump_pb_h

/* fd_dump_pb.h provides APIs for dumping instructions, transactions, and slots
   into a digestable and replayable Protobuf message. This is useful for debugging
   ledger test mismatches, collecting seed corpora, and gathering real data to test
   new harnesses. 
   
   The following arguments can be added when replaying ledger transactions: 
      COMMON:
        --dump-proto-output-dir <output_dir>
            * Defines the output directory to dump Protobuf messages to
        --dump-proto-start-slot <slot_number>
            * Defines the starting slot to dump Protobuf messages from
      
      HARNESS-SPECIFIC FILTERS:
        Instructions:
            --dump-instr-to-pb <0/1>
                * If enabled, instructions will be dumped to the specified output directory 
                * File name format is "instr-<base58_enc_sig>-<instruction_idx>.bin", where instruction_idx is 1-indexed
                * Each file represents a single instruction as a serialized InstrContext Protobuf message
            --dump-proto-sig-filter <base_58_enc_sig>
                * If enabled, only instructions with the specified signature will be dumped 

        Transactions:
            --dump-txn-to-pb <0/1>
                * If enabled, transactions will be dumped to the specified output directory
                * File name format is "txn-<base58_enc_sig>.bin" 
                * Each file represents a single transaction as a serialized TxnContext Protobuf message
            --dump-proto-sig-filter <base_58_enc_sig>
                * If enabled, only transactions with the specified signature will be dumped

        Blocks
            --dump-block-to-pb <0/1>
                * If enabled, blocks will be dumped to the specified output directory
                * File name format is "block-<slot_number>.bin"
                * Each file represents a single block as a serialized BlockContext Protobuf message

        CPI: Currently not directly invokable with a CLI argument. See details below.
                
    Other notes:
        solana-conformance (https://github.com/firedancer-io/solana-conformance)
            * Allows decoding / executing / debugging of above Protobuf messages in an isolated environment
            * Allows execution result(s) comparison between Firedancer and Solana / Agave
            * See solana-conformance/README.md for functionality and use cases */

#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "../../fd_flamenco.h"
#include "../../fd_flamenco_base.h"
#include "../fd_system_ids.h"
#include "../fd_runtime.h"
#include "../fd_executor.h"
#include "../../vm/fd_vm.h"
#include "../../../util/log/fd_log.h"
#include "../program/fd_address_lookup_table_program.h"

#include "../../nanopb/pb_encode.h"
#include "generated/elf.pb.h"
#include "generated/invoke.pb.h"
#include "generated/txn.pb.h"
#include "generated/vm.pb.h"
#include "generated/block.pb.h"

FD_PROTOTYPES_BEGIN

#define TOSTRING(x) #x
#define STRINGIFY(x) TOSTRING(x)

void
fd_dump_instr_to_protobuf( fd_exec_txn_ctx_t * txn_ctx,
                           fd_instr_info_t *   instr,
                           ushort              instruction_idx );

void
fd_dump_txn_to_protobuf( fd_exec_txn_ctx_t *txn_ctx, fd_spad_t * spad );

void
fd_dump_block_to_protobuf( fd_block_info_t const * block_info, 
                           fd_exec_slot_ctx_t const * slot_ctx,
                           fd_capture_ctx_t const * capture_ctx );

/* Captures the state of the VM (including the instruction context).
   Meant to be invoked at the start of the VM_SYSCALL_CPI_ENTRYPOINT like so:

  ```
   dump_vm_cpi_state(vm, STRINGIFY(FD_EXPAND_THEN_CONCAT2(sol_invoke_signed_, VM_SYSCALL_CPI_ABI)),
                     instruction_va, acct_infos_va, acct_info_cnt, signers_seeds_va, signers_seeds_cnt);
  ```

  Assumes that a `vm_cpi_state` directory exists in the current working directory. Generates a
  unique dump for combination of (tile_id, caller_pubkey, instr_sz). */
void
fd_dump_vm_cpi_state( fd_vm_t *    vm,
                      char const * fn_name,
                      ulong        instruction_va,
                      ulong        acct_infos_va,
                      ulong        acct_info_cnt,
                      ulong        signers_seeds_va,
                      ulong        signers_seeds_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_dump_pb_h */
