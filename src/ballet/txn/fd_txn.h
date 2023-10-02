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
   current MTU of 1232 B restricts this to 35 account addresses.  An artificial
   limit of 64 is currently in place, but this is being changed to 128 in the
   near future (https://github.com/solana-labs/solana/issues/27241), so we'll
   use 128. */
#define FD_TXN_ACCT_ADDR_MAX         (128UL)

/* FD_TXN_ADDR_TABLE_LOOKUP_MAX: The (inclusive) maximum number of address
   tables that this transaction references.  The spec is pretty sloppy about
   the maximum number allowed.  Since there's a maximum of 128 total accounts
   (including the fee payer) that the transaction can reference, if you have
   more than 127 table lookups, then you must have some from which you are not
   using any account.  Realistically, the current MTU of 1232 B resticts this
   to 33. FIXME: We should petition to limit this to approx 8. */
#define FD_TXN_ADDR_TABLE_LOOKUP_MAX (127UL)

/* FD_TXN_INSTR_MAX: The (inclusive) maximum number of instructions a transaction
   can have.  As of Solana 1.15.0, this is limited to 64. */
#define FD_TXN_INSTR_MAX             (64UL)


/* FD_TXN_MAX_SZ: The maximum amount of memory (in bytes) that a fd_txn can
   take up, including the instruction array and any address tables.  The
   worst-case transaction is a V0 transaction with only two account
   addresses (a program and a fee payer), and tons of empty instructions (no
   accounts, no data) and as many address table lookups as possible. */
#define FD_TXN_MAX_SZ                (860UL)

/* FD_TXN_MTU: The maximum size (in bytes, inclusive) of a serialized
   transaction. */
#define FD_TXN_MTU                  (1232UL)


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
fd_txn_get_address_tables( fd_txn_t const * txn ) {
  return (fd_txn_acct_addr_lut_t *)(txn->instr + txn->instr_cnt);
}


/* fd_acct_addr_t: An Solana account address, which may be an Ed25519
   public key, a SHA256 hash from a program derived address, a hardcoded
   sysvar, etc.  This type does not imply any alignment. */
union fd_acct_addr {
  uchar b[FD_TXN_ACCT_ADDR_SZ];
};
typedef union fd_acct_addr fd_acct_addr_t;

/* fd_txn_get_{signatures, acct_addrs}: Returns the array of Ed25519
   signatures or account addresses (commonly, yet imprecisely called
   pubkeys), respectively, in `payload`, the serialization of the
   transaction described by `txn`.  The number of signatures is seen in
   `txn->signature_cnt` and the number of account addresses is in
   `txn->acct_addr_cnt`.

   The lifetime of the returned signature is the lifetime of `payload`.
   Expect the returned pointer to point to memory with no particular
   alignment.  U.B. If `payload` and `txn` were not arguments to a valid
   `fd_txn_parse` call or if either was modified after the parse call.
   */
static inline fd_ed25519_sig_t const *
fd_txn_get_signatures( fd_txn_t const * txn,
                       void     const * payload ) {
   return (fd_ed25519_sig_t const *)((ulong)payload + (ulong)txn->signature_off);
}

static inline fd_acct_addr_t const *
fd_txn_get_acct_addrs( fd_txn_t const * txn,
                       void     const * payload ) {
  return (fd_acct_addr_t const *)((ulong)payload + (ulong)txn->acct_addr_off);
}

static inline uchar const *
fd_txn_get_recent_blockhash( fd_txn_t const * txn,
                             void     const * payload ) {
  return (uchar const *)((ulong)payload + (ulong)txn->recent_blockhash_off);
}

/* fd_txn_align returns the alignment in bytes required of a region of
   memory to be used as a fd_txn_t.  It is the same as
   alignof(fd_txn_t). */
static inline ulong
fd_txn_align( void ) {
  return alignof(fd_txn_t);
}

/* fd_txn_footprint: Returns the total size of txn, including the
   instructions and the address tables (if any). */
static inline ulong
fd_txn_footprint( ulong instr_cnt,
                  ulong addr_table_lookup_cnt ) {
  return sizeof(fd_txn_t) + instr_cnt*sizeof(fd_txn_instr_t) + addr_table_lookup_cnt*sizeof(fd_txn_acct_addr_lut_t);
}


/* Each account address in a transaction has 3 independent binary
   properties:
   -  readonly/writable: this is enforced in the runtime, but a
       transaction fails if it tries to modify the contents of an
       account it marks as readonly
   -  signer/nonsigner: the sigverify tile ensures that the transaction
       has been validly signed by the key associated to each account
       address marked as a signer
   -  immediate/address lookup table: account addresses can come from
       the transaction itself ("immediate"), which is the only option
       for legacy transactions, or from an address lookup table

   For example, the fee payer must be writable, a signer, and immediate.

   From these properties, we can make categories of account addresses
   for counting and iterating over account addresses.  Since these
   properties can be set indepenently, it would seem to give us 2*2*2=8
   categories of accounts based on the properties, but account addresses
   that come from an address lookup table cannot be signers, giving 6
   raw categories instead of 8.

   The individual types of accounts are defined as bitflags so that
   combination categories can be created easily, e.g. all readonly
   accounts or all signers. */

/*                                                        Signer?   Writable?   Source? */
#define FD_TXN_ACCT_CAT_WRITABLE_SIGNER         0x01  /*    Yes        Yes        imm   */
#define FD_TXN_ACCT_CAT_READONLY_SIGNER         0x02  /*    Yes        No         imm   */
#define FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM  0x04  /*    No         Yes        imm   */
#define FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM  0x08  /*    No         No         imm   */
#define FD_TXN_ACCT_CAT_WRITABLE_ALT            0x10  /*    No         Yes       lookup */
#define FD_TXN_ACCT_CAT_READONLY_ALT            0x20  /*    No         No        lookup */

/* Define some groupings for convenience.  In the
   table below, "Any" means "don't care" */
#define FD_TXN_ACCT_CAT_WRITABLE                0x15  /*   Any         Yes        Any   */
#define FD_TXN_ACCT_CAT_READONLY                0x2A  /*   Any         No         Any   */
#define FD_TXN_ACCT_CAT_SIGNER                  0x03  /*   Yes         Any       Any/imm*/
#define FD_TXN_ACCT_CAT_NONSIGNER               0x3C  /*   No          Any        Any   */
#define FD_TXN_ACCT_CAT_IMM                     0x0F  /*   Any         Any        imm   */
#define FD_TXN_ACCT_CAT_ALT                     0x30  /*   No          Any       lookup */
#define FD_TXN_ACCT_CAT_NONE                    0x00  /*      --- Empty set ---         */
#define FD_TXN_ACCT_CAT_ALL                     0x3F  /*   Any         Any        Any   */

/* fd_txn_account_cnt: Returns the number of accounts referenced by this
   transaction that have the property specified by include_category.
   txn must be a pointer to a valid transaction.  include_cat must be
   one of the previously defined FD_TXN_ACCT_CAT_* values.  Ideally,
   include_cat should be a compile-time constant, in which case this
   function typically compiles to about 3 instructions. */
static inline ulong
fd_txn_account_cnt( fd_txn_t const * txn,
                    int              include_cat ) {
  ulong cnt = 0UL;
  if( include_cat & FD_TXN_ACCT_CAT_WRITABLE_SIGNER        ) cnt += (ulong)txn->signature_cnt - (ulong)txn->readonly_signed_cnt;
  if( include_cat & FD_TXN_ACCT_CAT_READONLY_SIGNER        ) cnt += (ulong)txn->readonly_signed_cnt;
  if( include_cat & FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM ) cnt += (ulong)txn->readonly_unsigned_cnt;
  if( include_cat & FD_TXN_ACCT_CAT_WRITABLE_ALT           ) cnt += (ulong)txn->addr_table_adtl_writable_cnt;
  if( include_cat & FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM )
    cnt += (ulong)txn->acct_addr_cnt - (ulong)txn->signature_cnt - (ulong)txn->readonly_unsigned_cnt;
  if( include_cat & FD_TXN_ACCT_CAT_READONLY_ALT           )
    cnt += (ulong)txn->addr_table_adtl_cnt - (ulong)txn->addr_table_adtl_writable_cnt;

  return cnt;
}

/* fd_txn_acct_iter_{init, next, end}: These functions are used for
   iterating over the accounts in a transaction that have the property
   specified by include_cat.

   Example usage:

   fd_txn_acct_addr_t const * acct = fd_txn_get_acct_addrs( txn, payload );
   fd_txn_acct_iter_t ctrl[1];
   for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE, ctrl );
         i<fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i, ctrl ) ) {
     // Do something with acct[ i ]
   }

   For fd_txn_acct_iter_init, txn must be a pointer to a valid
   transaction, include_cat must be one of the FD_TXN_ACCT_CAT_* values
   defined above (or a bitwise combination of them) and out_ctrl must
   point to a writable, potentially uninitialized fd_txn_acct_iter_t.
   Cannot fail from the caller's perspective.  On completion, returns
   the index of the first account address meeting the specified
   criteria, or fd_txn_acct_iter_end() if there aren't any.

   For fd_acct_iter_next, cur should be the current value of the
   iteration variable, and ctrl contains the control information
   produced by fd_txn_acct_iter_init, and potentially updated by calls
   to fd_acct_iter_next.  Returns the next value of the iteration
   variable, or fd_txn_acct_iter_end() if no more accounts meeting the
   criteria specified in the call to fd_txn_acct_iter_init remain.
   It is undefined behavior to call fd_acct_iter_next with values of cur
   and ctrl not returned by the same call to either fd_acct_iter_init or
   fd_acct_iter_next.  It's also U.B. to call fd_acct_iter_next after
   fd_acct_iter_end has been returned.

   fd_txn_acct_iter_t should be treated as an opaque handle and not
   modified other than by using fd_txn_acc_iter_next. It does not need
   to be destroyed, and is small enough that it should typically be
   allocated on the stack. */

typedef ulong fd_txn_acct_iter_t;

/* Account addresses are categorized into 6 categories, and all the
   account addresses for each category are stored contiguously.  This
   means that for any subset of the 6 categories that the user wants to
   iterate over, there are at most 3 disjoint ranges.

   For any iteration space I, we can choose 6 integers
   {start,end}_{0,1,2} so that
    I = [start0, end0) U [start1, end1) U [start2, end2)
   and 0<=start0<=end0<=start1<=end1<=start2<=end2<=256 with the
   additional restriction that the only empty interval we allow is
   [256, 256).
   The fact that we need to handle 0 and 256 is a bit pesky, because it
   seems like we need more than a byte to represent each number.
   However, notice that we return start0 from _init, so we don't need to
   represent it explicitly in the control word.  Furthermore, if
   start0==0, then all the remaining values are at least 1.  Thus, we
   can get away with storing each integer in one byte (an the whole
   control word in a single ulong) as long as we store one less than the
   actual value. */

static inline ulong
fd_txn_acct_iter_init( fd_txn_t const * txn,
                       int        include_cat,
                       ulong *    ctrl     ) {
  /* Our goal is to output something that looks like [end0-1, start1-1,
     end1-1, start2-1, end2-1, don't care, don't care, don't care], but
     we initially construct [255, 255, start0-1, end0-1, start1-1,
     end1-1, start2-1, end2-1].  If include_cat==0 and we don't end up
     doing anything below, then this is the right answer.  Otherwise,
     we'll immediately advance to the next interval when we compare with
     it. */
  union {
    uchar control[9]; /* The last dummy write might be to [8]. We want
                         to ignore it in that case. */
    ulong _ctrl;
  } u;
  u._ctrl = ULONG_MAX;
  ulong i = 0;

  /* One less than the start and end of the account address indices
     corresponding to the category r.  Starting these at -1 handles all
     the -1's necessary. */
  ulong start = (ulong)(-1L);
  ulong end   = (ulong)(-1L);

  /* Note: This has to be invoked in the account address index order */
# define EXTEND_REGION( r )                                                      \
  do{                                                                            \
    ulong cnt =  fd_txn_account_cnt( txn, r );                                   \
    start     =  end;                                                            \
    end       += cnt;                                                            \
    /* If cnt==0, we want to do nothing.  The easiest way to do that is          \
       to make the interval [endi, endi). */                                     \
    ulong endi   = (ulong)u.control[2*i+1];                                      \
    ulong _start = fd_ulong_if( cnt>0, start, endi );                            \
    ulong _end   = fd_ulong_if( cnt>0, end,   endi );                            \
    if( include_cat & r ) { /* Hopefully a compile-time const */                 \
      /* If the start of this sub-interval equals the end of the current         \
         interval, then we just extend the interval.  This next write is         \
         a dummy in that case (overwritten before being read) but saves          \
         a branch.  If it is not, then we write the current start and            \
         end as the next interval and advance i. */                              \
      u.control[2*i+2] = (uchar)_start;                                          \
      i = fd_ulong_if( endi==_start, i, i+1 );                                   \
      u.control[2*i+1] = (uchar)_end;                                            \
    }                                                                            \
  } while( 0 )

  EXTEND_REGION( FD_TXN_ACCT_CAT_WRITABLE_SIGNER        );
  EXTEND_REGION( FD_TXN_ACCT_CAT_READONLY_SIGNER        );
  EXTEND_REGION( FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM );
  EXTEND_REGION( FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM );
  /* FIXME: Right now we don't have a way of iterating over addresses in
     lookup tables. */
  EXTEND_REGION( FD_TXN_ACCT_CAT_WRITABLE_ALT           );
  EXTEND_REGION( FD_TXN_ACCT_CAT_READONLY_ALT           );
#undef EXTEND_REGION

  /* Undo last dummy write.  In the worst case, i==3 at this point, so
     we might write to u.control[8], but we don't care about that write
     then. */
  u.control[2*i+2] = (uchar)0xFF;

  *ctrl = (0xFFFFFFUL<<40) | (u._ctrl >> 24);
  ulong start0 = ((ulong)u.control[2] + 1UL) & 0xFFUL; /* Do the arithmetic as uchars so that 0xFF -> 0 */
  return fd_ulong_if( i==0UL, 256UL, start0 );
}

static inline ulong
fd_txn_acct_iter_next( ulong   cur,
                       ulong * _ctrl ) {
  ulong control = *_ctrl;
  ulong end = control & 0xFF; /* this is end-1, as explained above, but
                                 the interval is half-open */
  ulong next_start = ((control>>8)&0xFFUL)+1UL;
  *_ctrl = fd_ulong_if( cur==end, control>>16, control );
  return   fd_ulong_if( cur==end, next_start,  cur+1UL );
}

static inline ulong FD_FN_CONST fd_txn_acct_iter_end( void ) { return FD_TXN_ACCT_ADDR_MAX; }

/* fd_txn_parse_core: Parses a transaction from the canonical encoding, i.e.
   the format used on the wire.

   Payload points to the first byte of encoded transaction, e.g. the
   first byte of the UDP/Quic payload if the transaction comes from the
   network.  The encoded transaction must occupy exactly [payload,
   payload+payload_sz), i.e. this method will read no more than
   payload_sz bytes from payload, but it will reject the transaction if
   it contains extra padding at the end or continues past
   payload+payload_sz.  payload_sz <= FD_TXN_MTU.

   out_buf is the memory where the parsed transaction will be stored.
   out_buf must have room for at least FD_TXN_MAX_SZ bytes.

   Returns the total size of the resulting fd_txn struct on success and
   0 on failure.  On failure, the contents of out_buf are undefined,
   although nothing will be written beyond FD_TXN_MAX_SZ bytes.

   If counters_opt is non-NULL, some some counters about the result of
   the parsing process will be accumulated into the struct pointed to by
   counters_opt. Note: The returned txn object is not self-contained
   since it refers to byte ranges inside the payload.

   payload_sz_opt, if supplied, gets filled with the total bytes this txn
   uses (allowing for walking of an entry/microblock). If it is not supplied, the
   parse will return an error if the payload_sz does not exactly match.

   allow_zero_signatures tells the parser we are ok with txn that have zero signatures.
   This is only used by the test engine to pass invalid transactions into the
   native programs.
*/

ulong
fd_txn_parse_core( uchar const             * payload,
                   ulong                     payload_sz,
                   void                    * out_buf,
                   fd_txn_parse_counters_t * counters_opt,
                   ulong *                   payload_sz_opt,
                   int                       allow_zero_signatures );


/* fd_txn_parse: Convenient wrapper around fd_txn_parse_core that eliminates some optional arguments */
static inline ulong
fd_txn_parse( uchar const * payload, ulong payload_sz, void * out_buf, fd_txn_parse_counters_t * counters_opt ) {
  return fd_txn_parse_core(payload, payload_sz, out_buf, counters_opt, NULL, 0);
}

/* fd_txn_is_writable: Is the account at the supplied index writable

     Accounts ordered:
                                          Index Range                                 |   Signer?    |  Writeable?
     ---------------------------------------------------------------------------------|--------------|-------------
      [0,                                     signature_cnt - readonly_signed_cnt)    |  signer      |   writable
      [signature_cnt,                         acct_addr_cnt - readonly_unsigned_cnt)  |  not signer  |   writable
*/

static inline int
fd_txn_is_writable( fd_txn_t const * txn, int idx ) {
  if (txn->transaction_version == FD_TXN_V0 && idx >= txn->acct_addr_cnt) {
    if (idx < (txn->acct_addr_cnt + txn->addr_table_adtl_writable_cnt)) {
      return 1;
    }
    return 0;
  }

  if (idx < (txn->signature_cnt - txn->readonly_signed_cnt))
    return 1;
  if ((idx >= txn->signature_cnt) & (idx < (txn->acct_addr_cnt - txn->readonly_unsigned_cnt)))
    return 1;

  return 0;
}

/* fd_txn_is_signer: Is the account at the supplied index a signer

     Accounts ordered:
                                          Index Range                                 |   Signer?    |  Writeable?
     ---------------------------------------------------------------------------------|--------------|-------------
      [0,                                     signature_cnt - readonly_signed_cnt)    |  signer      |   writable
      [signature_cnt - readonly_signed_cnt,   signature_cnt)                          |  signer      |   readonly
*/
static inline int
fd_txn_is_signer( fd_txn_t const * txn, int idx ) {
  return idx < txn->signature_cnt;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_txn_fd_txn_h */
