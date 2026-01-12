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
#include "../../vm/fd_vm.h"
#include "generated/block.pb.h"
#include "generated/elf.pb.h"
#include "../../../disco/fd_txn_p.h"

/* The amount of memory allocated towards dumping blocks from ledgers */
#define FD_BLOCK_DUMP_CTX_SPAD_MEM_MAX (2UL<<30)
#define FD_BLOCK_DUMP_CTX_MAX_TXN_CNT  (10000UL)

FD_PROTOTYPES_BEGIN

/***** Dumping context *****/

/* Persistent context for block dumping.  Maintains state about
   in-progress block dumping, such as any dynamic memory allocations
   (which live in the spad) and the block context message. */
struct fd_block_dump_ctx {
  /* Block context message */
  fd_exec_test_block_context_t block_context;

  /* Collected transactions to dump */
  fd_txn_p_t                   txns_to_dump[FD_BLOCK_DUMP_CTX_MAX_TXN_CNT];
  ulong                        txns_to_dump_cnt;

  /* Spad for dynamic memory allocations for the block context message*/
  fd_spad_t *                  spad;
};
typedef struct fd_block_dump_ctx fd_block_dump_ctx_t;

static inline ulong
fd_block_dump_context_align( void ) {
  return alignof(fd_block_dump_ctx_t);
}

static inline ulong
fd_block_dump_context_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_block_dump_ctx_t), sizeof(fd_block_dump_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_BLOCK_DUMP_CTX_SPAD_MEM_MAX ) );
  l = FD_LAYOUT_FINI( l, fd_spad_align() );
  return l;
}

static inline void *
fd_block_dump_context_new( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_block_dump_ctx_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_dump_ctx_t), sizeof(fd_block_dump_ctx_t) );
  fd_spad_t *           spad = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(),              fd_spad_footprint( FD_BLOCK_DUMP_CTX_SPAD_MEM_MAX ) );

  ctx->spad             = fd_spad_new( spad, FD_BLOCK_DUMP_CTX_SPAD_MEM_MAX );
  ctx->txns_to_dump_cnt = 0UL;
  return ctx;
}

static inline fd_block_dump_ctx_t *
fd_block_dump_context_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_block_dump_context_align() ) ) ) {
    FD_LOG_ERR(( "misaligned mem" ));
    return NULL;
  }

  fd_block_dump_ctx_t * ctx = (fd_block_dump_ctx_t *)mem;
  ctx->spad                 = fd_spad_join( ctx->spad );
  return ctx;
}

static inline void *
fd_block_dump_context_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  return mem;
}

static inline void *
fd_block_dump_context_leave( fd_block_dump_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL ctx" ));
    return NULL;
  }
  return (void *)ctx;
}

/* Resets the block dump context to prepare for the next block. */
static inline void
fd_block_dump_context_reset( fd_block_dump_ctx_t * ctx ) {
  fd_memset( &ctx->block_context, 0, sizeof(ctx->block_context) );
  fd_spad_reset( ctx->spad );
  ctx->txns_to_dump_cnt = 0UL;
}

/****** Actual dumping functions ******/

void
fd_dump_instr_to_protobuf( fd_runtime_t *      runtime,
                           fd_bank_t *         bank,
                           fd_txn_in_t const * txn_in,
                           fd_txn_out_t *      txn_out,
                           fd_instr_info_t *   instr,
                           ushort              instruction_idx );

void
fd_dump_txn_to_protobuf( fd_runtime_t *      runtime,
                         fd_bank_t *         bank,
                         fd_txn_in_t const * txn_in,
                         fd_txn_out_t *      txn_out );

/* Block dumping is a little bit different than the other harnesses due
   to the architecture of our system.  Unlike the other dumping
   functions, blocks are dumped in two separate stages - transaction
   execution and block finalization.  Transactions are streamed into
   the exec tile as they come in from the dispatcher, so we maintain a
   running list of transaction descriptors to dump within the dumping
   context (using fd_dump_block_to_protobuf_collect_tx).  When the block
   is finalized, we take the accumulated transaction descriptors and
   convert them into Protobuf messages using
   fd_dump_block_to_protobuf, along with other fields in the slot /
   epoch context and any stake, vote, and transaction accounts.

   How it works in the replay tile:

   ...boot up backtest...
   unprivledged_init() {
     fd_block_dump_context_new()
   }

   ...start executing transactions...

   while( txns_to_execute ) {
     fd_dump_block_to_protobuf_collect_tx()
   }

   ...finalize the block...
   fd_dump_block_to_protobuf()
   fd_block_dump_context_reset() */
void
fd_dump_block_to_protobuf_collect_tx( fd_block_dump_ctx_t * dump_ctx,
                                      fd_txn_p_t const *    txn );

void
fd_dump_block_to_protobuf( fd_block_dump_ctx_t *     dump_ctx,
                           fd_banks_t *              banks,
                           fd_bank_t *               bank,
                           fd_accdb_user_t *         accdb,
                           fd_capture_ctx_t const *  capture_ctx );

void
fd_dump_vm_syscall_to_protobuf( fd_vm_t const * vm,
                                char const *    fn_name );

void
fd_dump_elf_to_protobuf( fd_runtime_t *      runtime,
                         fd_bank_t *         bank,
                         fd_txn_in_t const * txn_in,
                         fd_txn_account_t *  program_acc );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_dump_pb_h */
