#ifndef HEADER_fd_src_disco_bank_abi_h
#define HEADER_fd_src_disco_bank_abi_h

#include "../../ballet/pack/fd_pack.h"
#include "../../ballet/blake3/fd_blake3.h"

#define FD_BANK_ABI_TXN_ALIGN     (8UL)
#define FD_BANK_ABI_TXN_FOOTPRINT (248UL)

/* A SanitizedTransaction is not just a 248 byte struct but also a bunch
   of sidecar data that's pointed to by the struct.  All of this sidecar
   data is in the form of Vec<T>'s.  Note that we only store the actual
   vector contents in the sidecar, the metadata like capacity and length
   of the vector belong to the SanitizedTransaction.  The various
   vectors are...
   
    (1) A `Vec<uchar>` of length txn->acct_addr_cnt+txn->addr_table_adtl_cnt,
        which is the precomputed `is_writable_account_cache` storing for
        each account whether it is writable (1) or readable (0).
    (2) A `Vec<CompiledInstruction>` of length txn->instr_cnt.
        Each `CompiledInstruction` is 56 bytes.
    (3) A `Vec<MessageAddressTableLookup` of length txn->addr_table_lookup_cnt.
        Each `MessageAddressTableLookup` is 80 bytes.
    (4) A `Vec<Pubkey>` of length txn->addr_table_adtl_cnt.  These are
        the loaded accounts from address lookup tables, and each pubkey
        is 32 bytes.
        
   Note that a SanitizedTransaction also have other Vec<T>'s internally,
   but we do not need a sidecar to store them because the underlying
   memory already exists in the payload somewhere, so we can reuse it.
   
   Note that the first field (the Vec<uchar>) does not need to be
   aligned, it has an alignment of 1, but we specify it as 8 here so
   that we can order the fields inside the sidecar data arbitrarily
   without overflowing the buffer. */

#define FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR(acct_addr_cnt, addr_table_adtl_cnt, instr_cnt, addr_table_lookup_cnt) \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,       \
    8UL,                   (ulong)acct_addr_cnt+(ulong)addr_table_adtl_cnt ),                                   \
    8UL,                   56UL*(ulong)instr_cnt                           ),                                   \
    8UL,                   80UL*(ulong)addr_table_lookup_cnt               ),                                   \
    8UL,                   32UL*(ulong)addr_table_adtl_cnt                 ),                                   \
    8UL )

#define FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR_MAX (FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR(FD_TXN_ACCT_ADDR_MAX, FD_TXN_ACCT_ADDR_MAX, FD_TXN_INSTR_MAX, FD_TXN_ADDR_TABLE_LOOKUP_MAX))

/* FD_BANK_ABI_TXN_INIT_{SUCCESS,ERR_{...}} are error codes.  These
   values are persisted to logs.  Entries should not be renumbered and
   numeric values should never be reused. */

#define FD_BANK_ABI_TXN_INIT_SUCCESS                          (0)
#define FD_BANK_ABI_TXN_INIT_ERR_SLOT_HASHES_SYSVAR_NOT_FOUND (1)
#define FD_BANK_ABI_TXN_INIT_ERR_ACCOUNT_NOT_FOUND            (2)
#define FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_OWNER        (3)
#define FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_DATA         (4)
#define FD_BANK_ABI_TXN_INIT_ERR_INVALID_INDEX                (5)

/* fd_bank_abi_txn_t is a struct that is ABI compatible with
   `solana_sdk::transaction::sanitized::SanitizedTransaction`.  It is an
   extremely gross hack, the type has Rust repr, so that layout is
   unspecified and unstable.  For now though, we need to do this for
   performance, as it saves us from various copies.

   The Rust `SanitizedTransaction` returned here is very special, and is
   extremely unsafe to Rust code.  In particular the internal Vec<>
   fields are not owned by the type, and are not pointing to memory
   allocated from the Rust heap, so dropping or attempting to modify
   them could crash or corrupt memory.  The type overall should never be
   modified in Rust code, and just about the only thing it can be used
   for is it will survive being passed around as a
   &SanitizedTransaction.

   The only valid way to create such a struct is to use the
   fd_bank_abi_txn_init function below.  Then it should be passed as a
   pointer to Rust, and treated only as an &SanitizedTransaction.
   
   Because the fake SanitizedTransaction does not own the underlying
   Vec objects, and they aren't actually vecs, these fields instead
   point to a sidecar buffer that is allocated by the caller.  The
   lifetime of both the transaction and the sidecar must be the same. */

struct fd_bank_abi_txn_private;
typedef struct fd_bank_abi_txn_private fd_bank_abi_txn_t;

FD_PROTOTYPES_BEGIN

/* This function takes a pointer to a buffer of at least size
   FD_BANK_ABI_TXN_FOOTPRINT where the resulting fd_bank_abi_txn_t will
   be constructed and returns FD_BANK_ABI_TXN_INIT_SUCCESS on success
   and FD_BANK_ABI_TXN_INIT_FAILURE on failure.

   Constructing a "legacy" transaction happens entirely in C and is
   extremely fast, mostly just laying out a struct.

   Constructing a "v1" transaction is slower.  In this case we need to
   load the addresses used by the transaction, which requires locking
   the "sysvar_cache" of the bank, and might contend with other bank
   threads.  It also goes and fetches the address from the related
   address lookup program in the accounts database. */

int
fd_bank_abi_txn_init( fd_bank_abi_txn_t * out_txn,       /* Memory to place the result in, must be at least FD_BANK_ABI_TXN_FOOTPRINT bytes. */
                      uchar *             out_sidecar,   /* Memory to place sidecar data in, must be at least FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR( out_txn ) bytes. */
                      void const *        bank,          /* Pointer to a Solana `Bank` object the transaction is being loaded for.  */
                      fd_blake3_t *       blake3,        /* Blake3 implementation used to create `message_hash` of the transaction. */
                      uchar *             payload,       /* Transaction raw wire payload. */
                      ulong               payload_sz,    /* Transaction raw wire size. */
                      fd_txn_t *          txn,           /* The Firedancer parsed transaction representation. */
                      int                 is_simple_vote /* If the transaction is a "simple vote" or not. */ );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bank_abi_h */
