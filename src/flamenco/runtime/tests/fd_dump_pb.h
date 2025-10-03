#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_dump_pb_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_dump_pb_h

/* fd_dump_pb.h provides APIs for dumping syscalls, instructions, transactions, and blocks
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
            --dump-insn-to-pb <0/1>
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

        Syscalls:
            --dump-syscall-to-pb <0/1>
                * If enabled, syscalls will be dumped to the specified output directory
                * File name format is "syscall-<fn_name>-<base58_enc_sig>-<program_id_idx>-<instr_stack_sz>-<cus_remaining>.bin"

        ELF:
            --dump-elf-to-pb <0/1>
                * If enabled, ELF files will be dumped to the specified output directory
                * File name format is "elf-<base58_enc_sig>-<base58_enc_program_id>-<slot_number>.elfctx"

    Other notes:
        solana-conformance (https://github.com/firedancer-io/solana-conformance)
            * Allows decoding / executing / debugging of above Protobuf messages in an isolated environment
            * Allows execution result(s) comparison between Firedancer and Solana / Agave
            * See solana-conformance/README.md for functionality and use cases */

#include "../info/fd_instr_info.h"
#include "../info/fd_runtime_block_info.h"
#include "../../vm/fd_vm.h"
#include "generated/block.pb.h"
#include "generated/elf.pb.h"

FD_PROTOTYPES_BEGIN

#define TOSTRING(x) #x
#define STRINGIFY(x) TOSTRING(x)

void
fd_dump_instr_to_protobuf( fd_exec_txn_ctx_t * txn_ctx,
                           fd_instr_info_t *   instr,
                           ushort              instruction_idx );

void
fd_dump_txn_to_protobuf( fd_exec_txn_ctx_t *txn_ctx, fd_spad_t * spad );

/* Block dumping is a little bit special because the scope of the block fuzzer handles both block + new
   epoch processing. Therefore, we have to dump a decent amount of state before an epoch boundary may be
   crossed, and then dump the individual transactions within the block once the block has been fetched
   from the blockstore. Therefore, dumping is split up into two functions. `fd_dump_block_to_protobuf`
   will create an initial BlockContext type that saves some fields from the slot and epoch context, as well as any current
   builtins and sysvar accounts.

   `fd_dump_block_to_protobuf_tx_only` takes an existing block context message and a runtime block and dumps
   the transactions within the block to be replayed.

   CAVEATS: Currently, due to how spad frames are handled in the runtime, there is an edge case where block dumping will
   fail / segfault when dumping the last block of a partitioned epoch rewards distribution run. This will be fixed once the
   lifetime of the partitions can exist beyond the rewards distribution period so that we don't have to push and pop
   spad frames in disjoint sections of the runtime. */
void
fd_dump_block_to_protobuf( fd_banks_t *                   banks,
                           fd_bank_t *                    bank,
                           fd_funk_t *                    funk,
                           fd_funk_txn_xid_t const *      xid,
                           fd_capture_ctx_t const *       capture_ctx,
                           fd_spad_t *                    spad,
                           fd_exec_test_block_context_t * block_context_msg /* output */ );

void
fd_dump_block_to_protobuf_tx_only( fd_runtime_block_info_t const * block_info,
                                   fd_bank_t *                     bank,
                                   fd_funk_t *                     funk,
                                   fd_funk_txn_xid_t const *       xid,
                                   fd_capture_ctx_t const *        capture_ctx,
                                   fd_spad_t *                     spad,
                                   fd_exec_test_block_context_t *  block_context_msg );

void
fd_dump_vm_syscall_to_protobuf( fd_vm_t const * vm,
                                char const *    fn_name );

void
fd_dump_elf_to_protobuf( fd_exec_txn_ctx_t * txn_ctx,
                         fd_txn_account_t *  program_acc );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_dump_pb_h */
