#ifndef HEADER_fd_src_ballet_txn_fd_txn_h
#define HEADER_fd_src_ballet_txn_fd_txn_h

/* The main structure this header defines is fd_txn_t, which represents a
   Solana transaction.  A transaction, like a SQL database transaction, is the
   unit of execution atomicity in Solana, i.e. intermediate state is never
   visible to other transactions, and a failure at any point in the transaction
   causes the entire transaction to be rolled back (other than charging the
   transaction fee).

   A transaction primarily consists of a list of instructions to execute in
   sequence.  The struct fd_txn_instr_t describes one instruction.  An instruction
   specifies the invocation of a smart contract with some specified data and
   accounts.  The name 'instruction' was a poor choice, (since on-chain code is
   composed of eBPF instructions and using the same word to refer to very
   different concepts is confusing) but it's too late to change.  Thinking of a
   transaction-level instruction as a 'command' might be more useful.

   The other major component of a transaction is a list of account addresses.
   The address of any account that is referenced by any instruction in the
   transaction must appear in the list.  The address of any signer (including
   the fee payer) must appear in the list.  An account address is sometimes
   called a pubkey since it has the same format as one, though it is not always
   a public key strictly speaking (i.e. a corresponding private key may not
   exist).  Each account address in the list has associated permissions flags:
   signer/not signer and writable/readonly.  All 4 combinations are possible.
   These flags declare the transaction's intention in accessing the account,
   similar to the `mode` field of fopen( ). */

#include "../fd_ballet_base.h"

#include "../ed25519/fd_ed25519.h"

/* FD_TXN_VLEGACY: the initial, pre-V0 transaction format. */
#define FD_TXN_VLEGACY ((uchar)0xFF)
/* FD_TXN_V0: The second transaction format.  Includes a version number and
   potentially some address lookup tables */
#define FD_TXN_V0      ((uchar)0x00)

/* FD_TXN_SIGNATURE_SZ: The size (in bytes) of an Ed25519 signature. */
#define FD_TXN_SIGNATURE_SZ (64UL)
/* FD_TXN_PUBKEY_SZ: The size (in bytes) of an Ed25519 public key. */
#define FD_TXN_PUBKEY_SZ    (32UL)
/* FD_TXN_ACCT_ADDR_SZ: The size (in bytes) of a Solana account address.
   Account addresses are sometimes Ed25519 public keys, but they can also be
   the output of a SHA256 hash (program derived addresses and seeded accounts),
   or just hardcoded values (sysvars accounts).  It's important that all types
   of account addresses have this same size. */
#define FD_TXN_ACCT_ADDR_SZ (32UL)
/* FD_TXN_BLOCKHASH_SZ: The size (in bytes) of a blockhash.  A blockhash is a
   SHA256 hash, giving a size of 256 bits = 32 bytes. */
#define FD_TXN_BLOCKHASH_SZ (32UL)


/* FD_TXN_SIG_MAX: The (inclusive) maximum number of signatures a transaction
   can have.  Note: for the current MTU size of 1232 B, the maximum that a
   valid transaction can have is 12 signatures. The most I've seen in practice
   is about 7.

   From the spec: "The Solana runtime verifies that the number of signatures
   [stored as a compact-u16] matches the number in the first 8 bits of the
   message header."
   Thus this value must live in the range where compact-u16 and uint8
   representations are identical, hence a max of 127. */
#define FD_TXN_SIG_MAX               (127UL)

/* FD_TXN_ACCT_ADDR_MAX: The (inclusive) maximum number of account addresses
   that a transaction can have.  The spec only guarauntees <= 256, but the
   current MTU of 1232 B restricts this to 35 account addresses. */
#define FD_TXN_ACCT_ADDR_MAX         (256UL)

/* FD_TXN_ADDR_TABLE_LOOKUP_MAX: The (inclusive) maximum number of address
   tables that this transaction references.  The spec is pretty sloppy about
   the maximum number allowed.  Since there's a maximum of 255 total accounts
   (including the fee payer) that the transaction can reference, if you have
   more than 254 table lookups, then you must have some from which you are not
   using any account.  Realistically, the current MTU of 1232 B resticts this
   to 33. */
#define FD_TXN_ADDR_TABLE_LOOKUP_MAX (254UL)

/* FD_TXN_INSTR_MAX: The (inclusive) maximum number of instructions a transaction
   can have.  The only bound given by the spec is that it's encoded as a
   uint16.  The current max transaction size of 1232 B restricts this to 355,
   though they would be pretty useless instructions at that point. */
#define FD_TXN_INSTR_MAX             (USHORT_MAX)


/* FD_TXN_MAX_SZ: The maximum amount of memory (in bytes) that a fd_txn can
   take up, including the instruction array and any address tables.  The
   worst-case transaction is a legacy transaction with only two account addresses (a program and a fee
   payer), and tons of empty instructions (no accounts, no data). */
#define FD_TXN_MAX_SZ                (3570UL)


/* A Solana transaction instruction, i.e. one command or step to execute in a
   transaction.

   An instruction tells the runtime to execute one on-chain program (smart
   contract) with some arguments (think argc, argv).  The arguments come in the
   form of binary data and/or accounts, each of which is variable-sized and
   optional.

   Note that instructions specify accounts by giving an index into the
   transaction-level list of account addresses.  This means there are
   essentially two layers of indirection: a 1 B index to a 32 B address which
   specifies an account. */
struct fd_txn_instr {
  /* program_id: The on-chain program that this instruction invokes,
     represented as the index of the program's account address in the
     containing transaction's list of account addresses. */
  uchar   program_id;
  uchar   _padding_reserved_1; /* explicitly declare what the compiler would
                                  insert anyways */

  /* acct_cnt: The number of accounts this instruction references.
     N.B. It is possible to pass > 256 accounts to an instruction, but not more
     than 256 unique accounts. */
  ushort  acct_cnt;

  /* data_sz: The size (in bytes) of the data passed to this instruction. The
     data itself is included in the transaction, so is limited to the overall
     transaction size. */
  ushort  data_sz;

  /* acct_off: The offset (relative to the start of the transaction) in bytes
     where the account address index array starts.  This array has size
     acct_cnt.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then the array (payload+acct_off)[i]
     for i in [0, acct_cnt) gives all of the accounts passed to this
     instruction.  As with the program_id, these accounts are represented as
     indices into the transaction's list of account addresses.
     */
  ushort  acct_off;

  /* data_off: The offset (relative to the start of the transaction) in bytes
     where the instruction data array starts.  This array has size data_sz.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then the array (payload+data_off)[i]
     for i in [0, data_sz) gives the binary data passed to this instruction. */
  ushort  data_off;
};

typedef struct fd_txn_instr fd_txn_instr_t;


/* fd_txn_t: A Solana transaction. As explained above, a transaction is mostly
   a list of instructions, but there are a few other major components:
   - a list of account addresses,
   - the hash of a recent block (used as a nonce and TTL), and
   - potentially (if it's a V2 transaction) some address lookup tables. */
struct fd_txn {
  /* transaction_version: The version number of this transaction. Currently
     must be one of { FD_TXN_VLEGACY, FD_TXN_V0 }. */
  uchar       transaction_version;

  /* signature_cnt: The number of signatures in this transaction. signature_cnt
     in [1, FD_TXN_SIG_MAX]. */
  uchar       signature_cnt;

  /* signature_off: The offset (relative to the start of the transaction) in
     bytes where the signatures start.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then signature i starts at
     (payload+signature_off)[ FD_TXN_SIGNATURE_SZ*i ] for i in
     [0, signature_cnt).

     Note that signature_off is always 1 in current transaction versions. */
  ushort      signature_off;

  /* message_off: The offset (relative to the start of the transaction) in
     bytes where the 'message' starts.

     The message, which is the part of the packet covered by the signatures,
     spans from this offset to the end of the packet. */
  ushort      message_off;

  /* readonly_signed_cnt: Of the signature_cnt signatures, readonly_signed_cnt
     of them are read only. Since there must be a fee payer,
     readonly_signed_cnt in [0, signature_cnt) */
  uchar       readonly_signed_cnt;

  /* readonly_unsigned_cnt: Of the account addresses that don't have an
     accompanying signature, readonly_unsigned_cnt of them are read only.
     readonly_unsigned_cnt in [0, acct_addr_cnt-signature_cnt].  Excludes any
     accounts from address table lookups. */
  uchar       readonly_unsigned_cnt;

  /* acct_addr_cnt: The number of account addresses in this transaction.
     acct_addr_cnt in [1, FD_TXN_ACCT_ADDR_MAX].  Excludes any accounts from
     address table lookups. */
  ushort      acct_addr_cnt;

  /* acct_addr_off: The offset (relative to the start of the transaction) in
     bytes where the account addresses start.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then the array
     (payload+acct_addr_off)[ FD_TXN_ACCT_ADDR_SZ*i ] for i in [0, account_cnt)
     gives all of the account addresses in this transaction.  Since
     (payload+acct_addr_off) points inside the packet, it should be treated as
     pointing to unaligned data.

     The order of these addresses is important, because it determines the
     "permission flags" for the account in this transaction.
     Accounts ordered:
                                          Index Range                                 |   Signer?    |  Writeable?
     ---------------------------------------------------------------------------------|--------------|-------------
      [0,                                     signature_cnt - readonly_signed_cnt)    |  signer      |   writable
      [signature_cnt - readonly_signed_cnt,   signature_cnt)                          |  signer      |   readonly
      [signature_cnt,                         acct_addr_cnt - readonly_unsigned_cnt)  |  not signer  |   writable
      [acct_addr_cnt - readonly_unsigned_cnt, acct_addr_cnt)                          |  not signer  |   readonly
     */
  ushort      acct_addr_off;

  /* recent_blockhash_off: The offset (relative to the start of the
     transaction) in bytes where the recent blockhash starts.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then (payload+recent_blockhash_off) is
     a pointer to the blockhash. Since the resulting pointer points inside the
     packet, it should be treated as pointing to unaligned data. In practice,
     recent_blockhash_off is 5 or 6 (mod 32). */
  ushort      recent_blockhash_off;

  /* addr_table_lookup_cnt: The number of address lookup tables this
     transaction contains.  Must be 0 if transaction_version==FD_TXN_VLEGACY.
     addr_table_lookup_cnt in [0, FD_TXN_TABLE_LOOKUP_MAX]. */
  uchar       addr_table_lookup_cnt;

  /* addr_table_adtl_writable_cnt: The total number of writable account
     addresses across all of the address table lookups.
     addr_table_adtl_writable_cnt in [0, addr_table_adtl_cnt]. */
  uchar       addr_table_adtl_writable_cnt;

  /* addr_table_adtl_cnt: The total number of account addresses summed across
     all the address lookup tables. addr_table_adtl_cnt in
     [0, FD_TXN_ADDT_ADDR_MAX - acct_addr_cnt]. Since acct_addr_cnt > 0,
     addr_table_adtl_cnt < 256. */
  uchar      addr_table_adtl_cnt;
  uchar      _padding_reserved_1; /* explicit padding the compiler would have
                                     inserted anyways */

  /* From the address table lookups, we can add the following to the above table
                                                Index Range                                         |   Signer?    |  Writeable?
     -----------------------------------------------------------------------------------------------|--------------|-------------
     ...
      [acct_addr_cnt,                                acct_addr_cnt + addr_table_adtl_writable_cnt)  |  not signer  |   writable
      [acct_addr_cnt + addr_table_adtl_writable_cnt, acct_addr_cnt + addr_table_adtl_cnt)           |  not signer  |   readonly
      */

  /* instr_cnt: The number of instructions in this transaction.
     instr_cnt in [0, FD_TXN_INSTR_MAX]. */
  ushort      instr_cnt;

  /* instr: The array of instructions in this transaction. It's a "flexible array
     member" since C does not allow the pretty typical 0-len array at the end
     of the struct trick.
     Indexed [0, instr_cnt). */
  fd_txn_instr_t instr[ ];

  /* Logically, there's another field here:
     address_tables: The address tables this transaction imports and which
     accounts from them are selected for inclusion in this transaction's
     overall list of accounts. Indexed [0, addr_table_lookup_cnt).
  fd_txn_acct_addr_lut_t address_tables[ ];
     To access it, call fd_txn_get_address_tables( ). */

};

typedef struct fd_txn fd_txn_t;

/* fd_txn_acct_addr_lut: An on-chain address lookup table. Solana added this to
   the Transaction v2 spec in order to allow a transaction to reference more
   accounts. This struct specifies which account addresses from an on-chain
   list should be selected to include in the list of account addresses
   available to instructions in this transaction */
struct fd_txn_acct_addr_lut {
  /* addr_off: The offset (relative to the start of the transaction) in bytes
     where the address of the account containing the list of to load is stored.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then
     (fd_txn_acct_addr_t*)(payload+addr_off) is a pointer to the account
     address.  Since (payload+acct_addr_off) points inside the packet, it
     should be treated as pointing to unaligned data. */
  ushort addr_off;

  /* writable_cnt: The number of account addresses this LUT selects as writable
     from the on-chain list. */
  uchar  writable_cnt;
  /* readonly_cnt: The number of account addresses this LUT selects as read
     only from the on-chain list. */
  uchar  readonly_cnt;

  /* writable_off: The offset (relative to the start of the transaction) in
     bytes where the writable account indices begins.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then (payload+writable_off)[i] for i
     in [0, writable_cnt) gives the indices into the on-chain list that are
     selected for inclusion in this transaction's list of account addresses as
     writable accounts. */
  ushort writable_off;

  /* readonly_off: The offset (relative to the start of the transaction) in
     bytes where the read only account indices begins.

     Specifically, if uchar const * payload is a pointer to the first byte of
     the transaction data in the packet, then (payload+readonly_off)[i] for i
     in [0, readonly_cnt) gives the indices into the on-chain list that are
     selected for inclusion in this transaction's list of account addresses as
     read only accounts. */
  ushort readonly_off;
};

typedef struct fd_txn_acct_addr_lut fd_txn_acct_addr_lut_t;

#define FD_TXN_PARSE_COUNTERS_RING_SZ (32UL)

/* Counters for collecting some metrics about the outcome of parsing
   transactions */
struct fd_txn_parse_counters {
  /* success_cnt: the number of times a transaction parsed successfully */
  ulong success_cnt;
  /* failure_cnt: the number of times a transaction was ill-formed and failed
     to parse for any reason */
  ulong failure_cnt;
  /* failure_ring: some information about the causes of recent transaction
     parsing failures.  Specifically, the line of code which detected that the
     ith malformed transaction was malformed maps to
     failure_ring[ i%FD_TXN_PARSE_COUNTERS_RING_SZ ] (where i starts at 0), and the
     last instance mapping to each element of the array is the one that is
     actually present.  If fewer than FD_TXN_PARSE_COUNTERS_RING_SZ failures have
     occurred, the contents of some entries in this array are undefined. */
  ulong failure_ring[ FD_TXN_PARSE_COUNTERS_RING_SZ ];
};
typedef struct fd_txn_parse_counters fd_txn_parse_counters_t;

FD_PROTOTYPES_BEGIN
/* fd_txn_get_address_tables: Returns the array of address tables in this
   transaction.  This depends on the value of txn->instr_cnt being correct.  The
   lifetime of the returned pointer is the same as the fd_txn_t pointer passed
   as an argument, so it's not necessary to free the returned pointer
   separately.  Treat it as if this function returned a pointer to a member of
   the struct.  Suppose x=fd_txn_get_address_tables( txn ), then x[ i ] is valid
   for i in [0, txn->addr_table_lookup_cnt ). */
static inline fd_txn_acct_addr_lut_t *
fd_txn_get_address_tables( fd_txn_t * txn ) {
  return (fd_txn_acct_addr_lut_t *)(txn->instr + txn->instr_cnt);
}

/* fd_txn_get_signatures: Returns the array of Ed25519 signatures in
   `payload`, the serialization of the transaction described by `txn`.
   The number of signatures is seen in `txn->signature_cnt`.
   The lifetime of the returned signature is the lifetime of `payload`.
   Expect the returned signature to be unaligned.
   U.B. If `payload` and `txn` were not arguments to a valid
   `fd_txn_parse` call or if either was modified after the parse call. */
static inline fd_ed25519_sig_t const *
fd_txn_get_signatures( fd_txn_t const * txn,
                       void const *     payload ) {
   return (fd_ed25519_sig_t const *)((ulong)payload + (ulong)txn->signature_off);
}

/* fd_txn_footprint: Returns the total size of txn, including the
   instructions and the address tables (if any). */
static inline ulong
fd_txn_footprint( ulong instr_cnt,
                  ulong addr_table_lookup_cnt ) {
  return sizeof(fd_txn_t) + instr_cnt*sizeof(fd_txn_instr_t) + addr_table_lookup_cnt*sizeof(fd_txn_acct_addr_lut_t);
}

/* fd_txn_parse: Parses a transaction from the canonical encoding, i.e. the
   format used on the wire.  Payload points to the first byte of encoded
   transaction, e.g. the first byte of the UDP/Quic payload if the transaction
   comes from the network.  out_buf is the memory where the parsed transaction
   will be stored.  out_buf must have room for at least FD_TXN_MAX_SZ bytes.
   Returns the total size of the resulting fd_txn struct on success and 0 on
   failure.  On failure, the contents of out_buf are undefined, although
   nothing will be written beyond FD_TXN_MAX_SZ bytes.  If counters_opt is
   non-NULL, some some counters about the result of the parsing process will be
   accumulated into the struct pointed to by counters_opt. Note: The returned
   txn object is not self-contained since it refers to byte ranges inside the
   payload. */
ulong fd_txn_parse( uchar const * payload, ulong payload_sz, void * out_buf, fd_txn_parse_counters_t * counters_opt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_txn_fd_txn_h */
