#ifndef HEADER_fd_src_flamenco_txnmeta_fd_txn_meta_h
#define HEADER_fd_src_flamenco_txnmeta_fd_txn_meta_h

/* fd_txn_meta.h turns the commit record of one transaction into the
   object agave calls TransactionStatusMeta
   (transaction-status-client-types/src/lib.rs:664-677), plus the
   parsed transaction it belongs to.

   The object is serialization independent: agave computes it once in
   its transaction status service and renders it per sink
   (transaction_status_service.rs:192,213,248-260), and so does this
   module.  The renderers here are the protobuf messages of
   solana-storage.proto that the Dragon's Mouth API carries, and the
   bincode encoding of agave's TransactionError that the proto embeds
   as opaque bytes.

   Everything is a view: fd_txn_meta_t points into the record and into
   a caller owned scratch region, and nothing is allocated.  A meta
   object is valid while the record and the scratch it was built from
   are.

   The proto encoders write canonical protobuf into a caller supplied
   buffer: fields in ascending order, proto3 defaults omitted, no
   padding in a length prefix.  The same input always produces the same
   bytes, so a message can be encoded once and handed to many
   subscribers. */

#include "../fd_flamenco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../disco/events/generated/fd_event_internal_gen.h"

/* How a transaction ended.  FD_TXN_META_ERR_INSTR is agave's
   TransactionError::InstructionError, which names the instruction and
   carries an InstructionError of its own. */

#define FD_TXN_META_ERR_NONE  (0)
#define FD_TXN_META_ERR_TXN   (1)
#define FD_TXN_META_ERR_INSTR (2)

/* FD_TXN_META_ERR_SZ_MAX bounds the bincode encoding of an error: a u32
   variant, a u8 instruction index, a u32 instruction variant and a u32
   custom code. */

#define FD_TXN_META_ERR_SZ_MAX (13UL)

struct fd_txn_meta_err {
  int   kind;      /* FD_TXN_META_ERR_* */
  long  txn_err;   /* Firedancer transaction error code */
  long  instr_err; /* Firedancer instruction error code, kind INSTR only */
  uint  instr_idx; /* index of the failing instruction, kind INSTR only */
  uint  custom;    /* program error code, UINT_MAX if the error is not a custom one */
  uint  acct_idx;  /* account the error names, UINT_MAX if it names none */
};

typedef struct fd_txn_meta_err fd_txn_meta_err_t;

/* fd_txn_meta_instr_t is one instruction of the trace: the program it
   ran, the transaction accounts it was given, its data, and the depth
   of the instruction stack when it ran (1 for a top level
   instruction). */

struct fd_txn_meta_instr {
  uint          program_id_idx;
  uint          stack_height;
  uchar const * accts;
  ulong         acct_cnt;
  uchar const * data;
  ulong         data_sz;
};

typedef struct fd_txn_meta_instr fd_txn_meta_instr_t;

/* fd_txn_meta_inner_t is the inner instructions of one top level
   instruction, in the grouping agave's map_inner_instructions produces
   (transaction-status/src/lib.rs:130-146): index is the position of
   the top level instruction in the message, the entries are the
   instructions it invoked, and a top level instruction that invoked
   none has no group at all. */

struct fd_txn_meta_inner {
  uint                        index;
  fd_txn_meta_instr_t const * instr;
  ulong                       instr_cnt;
};

typedef struct fd_txn_meta_inner fd_txn_meta_inner_t;

/* fd_txn_meta_logs_t is the log messages of the transaction, held in
   the serialization the log collector produces, which is already the
   protobuf encoding of the repeated string field they go on the wire
   as (fd_log_collector.h, FD_LOG_COLLECTOR_PROTO_TAG).  cnt is how
   many messages the buffer holds; iterate them with
   fd_txn_meta_log_next. */

struct fd_txn_meta_logs {
  uchar const * buf;
  ulong         buf_sz;
  ulong         cnt;
};

typedef struct fd_txn_meta_logs fd_txn_meta_logs_t;

/* fd_txn_meta_t is one transaction and everything a consumer is told
   about it.  The fields below the error are agave's
   TransactionStatusMeta in the same order; pre_token_balances,
   post_token_balances and rewards are always empty, because no FD
   component computes token balances yet.

   The _none flags are agave's Option::None: it records logs, inner
   instructions and return data only for a transaction that executed,
   so a fees only transaction reports them as absent rather than empty
   (bank.rs:4519-4535). */

struct fd_txn_meta {
  /* The transaction */
  fd_txn_t const * txn;         /* parsed from payload, in the caller's scratch */
  uchar const *    payload;
  ulong            payload_sz;
  uchar const *    signature;   /* 64 bytes, the first signature */
  int              is_vote;
  ulong            index_in_slot;
  ulong            slot;
  ulong            bank_id;

  /* keys is every account the transaction used: the message's own
     addresses first, then the writable addresses loaded from lookup
     tables, then the readonly ones. */
  uchar const (* keys)[ 32UL ];
  ulong          key_cnt;
  ulong          static_key_cnt;
  ulong          loaded_writable_cnt;
  ulong          loaded_readonly_cnt;

  /* The meta */
  fd_txn_meta_err_t   err;
  ulong               fee;
  ulong const *       pre_balances;
  ulong const *       post_balances;
  ulong               balance_cnt;
  fd_txn_meta_inner_t const * inner;
  ulong               inner_cnt;
  int                 inner_none;
  fd_txn_meta_logs_t  logs;
  int                 logs_none;
  int                 logs_truncated;
  uchar const *       return_data;
  ulong               return_data_sz;
  uchar const *       return_data_program_id; /* 32 bytes */
  int                 return_data_none;
  ulong               compute_units_consumed;
  ulong               cost_units;
};

typedef struct fd_txn_meta fd_txn_meta_t;

/* fd_txn_meta_scratch_t is the working memory one meta object needs:
   the parsed transaction, the flattened instruction trace and the
   grouping of its inner instructions.  A caller owns one of these per
   meta object it holds at a time; nothing else is allocated. */

struct fd_txn_meta_scratch {
  uchar               txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(8)));
  fd_txn_meta_instr_t instr[ FD_EVENT_INTERNAL_COMMIT_TRACE_MAX ];
  fd_txn_meta_inner_t inner[ FD_TXN_INSTR_MAX ];
};

typedef struct fd_txn_meta_scratch fd_txn_meta_scratch_t;

FD_PROTOTYPES_BEGIN

/* fd_txn_meta_from_commit builds out from one commit record.  scratch
   holds the parts of the object that are not in the record itself and
   must stay alive as long as out is used.

   Returns 0 on success, or -1 if the record's transaction payload does
   not parse, in which case out is not usable.  The record's counts and
   indices are otherwise trusted: a caller that took the record off a
   link checks them first (fd_geyser_core_commit_record). */

int
fd_txn_meta_from_commit( fd_txn_meta_t *                          out,
                         fd_txn_meta_scratch_t *                  scratch,
                         fd_event_internal_commit_parts_t const * parts );

/* fd_txn_meta_log_next reads one log message out of the collector
   serialization.  *off is the offset to read at, advanced past the
   message; start at 0.  Returns the message and writes its length to
   *msg_sz, or returns NULL at the end of the buffer or on a malformed
   entry. */

uchar const *
fd_txn_meta_log_next( fd_txn_meta_logs_t const * logs,
                      ulong *                    off,
                      ulong *                    msg_sz );

/* fd_txn_meta_err_encode writes the bincode encoding of the error, the
   bytes that go into solana.storage.ConfirmedBlock.TransactionError.err
   (yellowstone create_transaction_error, convert_to.rs:168-177, which
   serializes agave's TransactionError with wincode; wincode's default
   enum discriminant is bincode's, a little endian u32).

   Firedancer's error codes are the negated agave variant index minus
   one, for both TransactionError (fd_runtime_err.h) and
   InstructionError (fd_executor_err.h), so the variant is -(code+1).

   out must have room for FD_TXN_META_ERR_SZ_MAX bytes.  Returns the
   number of bytes written, which is 0 for a transaction that did not
   fail and for an error that no agave variant corresponds to. */

ulong
fd_txn_meta_err_encode( fd_txn_meta_err_t const * err,
                        uchar *                   out );

/* The field numbers of the messages the encoders below write, from
   solana-storage.proto and geyser.proto.  This module does not depend
   on the vendored protobuf definitions, so test_txn_meta asserts every
   one of these against the generated headers: a renumbered field
   breaks the build rather than the wire. */

#define FD_TXN_META_F_HDR_NUM_REQUIRED_SIGNATURES    ( 1U) /* MessageHeader */
#define FD_TXN_META_F_HDR_NUM_READONLY_SIGNED        ( 2U)
#define FD_TXN_META_F_HDR_NUM_READONLY_UNSIGNED      ( 3U)

#define FD_TXN_META_F_MSG_HEADER                     ( 1U) /* Message */
#define FD_TXN_META_F_MSG_ACCOUNT_KEYS               ( 2U)
#define FD_TXN_META_F_MSG_RECENT_BLOCKHASH           ( 3U)
#define FD_TXN_META_F_MSG_INSTRUCTIONS               ( 4U)
#define FD_TXN_META_F_MSG_VERSIONED                  ( 5U)
#define FD_TXN_META_F_MSG_ADDRESS_TABLE_LOOKUPS      ( 6U)
#define FD_TXN_META_F_MSG_CONFIG                     ( 7U)

#define FD_TXN_META_F_TXN_SIGNATURES                 ( 1U) /* Transaction */
#define FD_TXN_META_F_TXN_MESSAGE                    ( 2U)

#define FD_TXN_META_F_CI_PROGRAM_ID_INDEX            ( 1U) /* CompiledInstruction */
#define FD_TXN_META_F_CI_ACCOUNTS                    ( 2U)
#define FD_TXN_META_F_CI_DATA                        ( 3U)

#define FD_TXN_META_F_LUT_ACCOUNT_KEY                ( 1U) /* MessageAddressTableLookup */
#define FD_TXN_META_F_LUT_WRITABLE_INDEXES           ( 2U)
#define FD_TXN_META_F_LUT_READONLY_INDEXES           ( 3U)

#define FD_TXN_META_F_CFG_PRIORITY_FEE               ( 1U) /* TransactionConfig */
#define FD_TXN_META_F_CFG_COMPUTE_UNIT_LIMIT         ( 2U)
#define FD_TXN_META_F_CFG_LOADED_ACCOUNTS_DATA_SIZE  ( 3U)
#define FD_TXN_META_F_CFG_HEAP_SIZE                  ( 4U)

#define FD_TXN_META_F_ERR_ERR                        ( 1U) /* TransactionError */

#define FD_TXN_META_F_II_INDEX                       ( 1U) /* InnerInstructions */
#define FD_TXN_META_F_II_INSTRUCTIONS                ( 2U)

#define FD_TXN_META_F_IN_PROGRAM_ID_INDEX            ( 1U) /* InnerInstruction */
#define FD_TXN_META_F_IN_ACCOUNTS                    ( 2U)
#define FD_TXN_META_F_IN_DATA                        ( 3U)
#define FD_TXN_META_F_IN_STACK_HEIGHT                ( 4U)

#define FD_TXN_META_F_RD_PROGRAM_ID                  ( 1U) /* ReturnData */
#define FD_TXN_META_F_RD_DATA                        ( 2U)

#define FD_TXN_META_F_META_ERR                       ( 1U) /* TransactionStatusMeta */
#define FD_TXN_META_F_META_FEE                       ( 2U)
#define FD_TXN_META_F_META_PRE_BALANCES              ( 3U)
#define FD_TXN_META_F_META_POST_BALANCES             ( 4U)
#define FD_TXN_META_F_META_INNER_INSTRUCTIONS        ( 5U)
#define FD_TXN_META_F_META_LOG_MESSAGES              ( 6U)
#define FD_TXN_META_F_META_INNER_INSTRUCTIONS_NONE   (10U)
#define FD_TXN_META_F_META_LOG_MESSAGES_NONE         (11U)
#define FD_TXN_META_F_META_LOADED_WRITABLE           (12U)
#define FD_TXN_META_F_META_LOADED_READONLY           (13U)
#define FD_TXN_META_F_META_RETURN_DATA               (14U)
#define FD_TXN_META_F_META_RETURN_DATA_NONE          (15U)
#define FD_TXN_META_F_META_COMPUTE_UNITS_CONSUMED    (16U)
#define FD_TXN_META_F_META_COST_UNITS                (17U)

#define FD_TXN_META_F_INFO_SIGNATURE                 ( 1U) /* SubscribeUpdateTransactionInfo */
#define FD_TXN_META_F_INFO_IS_VOTE                   ( 2U)
#define FD_TXN_META_F_INFO_TRANSACTION               ( 3U)
#define FD_TXN_META_F_INFO_META                      ( 4U)
#define FD_TXN_META_F_INFO_INDEX                     ( 5U)

#define FD_TXN_META_F_UPDATE_TRANSACTION             ( 1U) /* SubscribeUpdateTransaction */
#define FD_TXN_META_F_UPDATE_SLOT                    ( 2U)
#define FD_TXN_META_F_UPDATE_BANK_ID                 ( 3U)

#define FD_TXN_META_F_STATUS_SLOT                    ( 1U) /* SubscribeUpdateTransactionStatus */
#define FD_TXN_META_F_STATUS_SIGNATURE               ( 2U)
#define FD_TXN_META_F_STATUS_IS_VOTE                 ( 3U)
#define FD_TXN_META_F_STATUS_INDEX                   ( 4U)
#define FD_TXN_META_F_STATUS_ERR                     ( 5U)
#define FD_TXN_META_F_STATUS_BANK_ID                 ( 6U)

/* The proto encoders.  Each writes the body of one message (the fields,
   without a tag or a length prefix of its own) into out, and returns
   the number of bytes written, or ULONG_MAX if out_sz is too small.

   _transaction is solana.storage.ConfirmedBlock.Transaction,
   _meta is solana.storage.ConfirmedBlock.TransactionStatusMeta,
   _txn_info is geyser.SubscribeUpdateTransactionInfo,
   _txn_update is geyser.SubscribeUpdateTransaction and
   _txn_status is geyser.SubscribeUpdateTransactionStatus. */

ulong
fd_txn_meta_encode_transaction( fd_txn_meta_t const * meta,
                                uchar *               out,
                                ulong                 out_sz );

ulong
fd_txn_meta_encode_meta( fd_txn_meta_t const * meta,
                         uchar *               out,
                         ulong                 out_sz );

ulong
fd_txn_meta_encode_txn_info( fd_txn_meta_t const * meta,
                             uchar *               out,
                             ulong                 out_sz );

ulong
fd_txn_meta_encode_txn_update( fd_txn_meta_t const * meta,
                               uchar *               out,
                               ulong                 out_sz );

ulong
fd_txn_meta_encode_txn_status( fd_txn_meta_t const * meta,
                               uchar *               out,
                               ulong                 out_sz );

/* FD_TXN_META_UPDATE_SZ_MAX bounds what
   fd_txn_meta_encode_txn_update writes for any record whose counts are
   within the bounds of the commit record schema.  The terms are, in
   order: the signature, the is_vote flag, the transaction (signatures
   and message: header, account keys, blockhash, instructions with
   their accounts and data, the lookup tables and the V1 config), the
   meta (error, fee, balances, inner instructions with their accounts
   and data, logs, loaded addresses, return data, compute units and
   cost), the index, and the slot and bank id of the enclosing
   message.  Each term includes the tag and length prefix of the field
   it is written as, rounded up generously. */

#define FD_TXN_META_UPDATE_SZ_MAX                                       \
  (   80UL                                            /* signature */   \
    +  8UL                                            /* is_vote */     \
    + 16UL + FD_TXN_SIG_MAX*80UL                      /* signatures */  \
    + 16UL + 32UL                                     /* header */      \
    + FD_TXN_ACCT_ADDR_MAX*40UL                       /* account keys */\
    + 40UL                                            /* blockhash */   \
    + FD_TXN_INSTR_MAX*32UL + FD_TXN_INSTR_MAX*FD_TXN_INSTR_ACCT_MAX    \
    + FD_TXN_MTU                                      /* instructions */\
    + FD_TXN_ADDR_TABLE_LOOKUP_MAX*56UL + 2UL*FD_TXN_ACCT_ADDR_MAX      \
    + 48UL                                            /* V1 config */   \
    + 16UL + FD_TXN_META_ERR_SZ_MAX                   /* error */       \
    + 16UL                                            /* fee */         \
    + 2UL*FD_TXN_ACCT_ADDR_MAX*16UL                   /* balances */    \
    + FD_EVENT_INTERNAL_COMMIT_TRACE_MAX*48UL                           \
    + FD_EVENT_INTERNAL_COMMIT_TRACE_ACCTS_MAX                          \
    + FD_EVENT_INTERNAL_COMMIT_TRACE_DATA_MAX         /* inner instrs */\
    + 16UL + FD_EVENT_INTERNAL_COMMIT_LOGS_MAX        /* logs */        \
    + FD_TXN_ACCT_ADDR_MAX*40UL                       /* loaded addrs */\
    + 48UL + FD_EVENT_INTERNAL_COMMIT_RETURN_DATA_MAX /* return data */ \
    + 32UL                                            /* cu, cost */    \
    + 48UL                                            /* index, slot, bank id */ \
  )

/* FD_TXN_META_STATUS_SZ_MAX bounds what
   fd_txn_meta_encode_txn_status writes: a slot, a signature, a flag,
   an index, the error and a bank id. */

#define FD_TXN_META_STATUS_SZ_MAX (144UL+FD_TXN_META_ERR_SZ_MAX)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_txnmeta_fd_txn_meta_h */
