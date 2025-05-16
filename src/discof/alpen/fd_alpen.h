#ifndef HEADER_fd_src_discof_alpen_fd_alpen_h
#define HEADER_fd_src_discof_alpen_fd_alpen_h

#include "../../ballet/txn/fd_txn.h"

#define FD_AG_VOTE_INITIALIZE_ACCOUNT           ( 0U)
#define FD_AG_VOTE_AUTHORIZE                    ( 1U)
#define FD_AG_VOTE_AUTHORIZE_CHECKED            ( 2U)
#define FD_AG_VOTE_AUTHORIZE_WITH_SEED          ( 3U)
#define FD_AG_VOTE_AUTHORIZE_CHECKED_WITH_SEED  ( 4U)
#define FD_AG_VOTE_WITHDRAW                     ( 5U)
#define FD_AG_VOTE_UPDATE_VALIDATOR_IDENTITY    ( 6U)
#define FD_AG_VOTE_UPDATE_COMMISSION            ( 7U)
#define FD_AG_VOTE_NOTARIZE                     ( 8U)
#define FD_AG_VOTE_FINALIZE                     ( 9U)
#define FD_AG_VOTE_SKIP                         (10U)
#define FD_AG_VOTE_NOTARIZE_FALLBACK            (11U)
#define FD_AG_VOTE_SKIP_FALLBACK                (12U)

#define FD_AG_VOTE_BLOCK_ID_SZ                  (32UL)
#define FD_AG_VOTE_BANK_HASH_SZ                 (32UL)

#define FD_AG_VOTE_SERDES_SUCCESS               ( 0)
#define FD_AG_VOTE_SERDES_FAILURE               (-1)

struct fd_ag_vote {
  uchar type;
  uchar version;
  ulong slot;
  uchar block_id[FD_AG_VOTE_BLOCK_ID_SZ];
  ulong replayed_slot;
  uchar replayed_bank_hash[FD_AG_VOTE_BANK_HASH_SZ];
};
typedef struct fd_ag_vote fd_ag_vote_t;

FD_PROTOTYPES_BEGIN
/* fd_txn_is_simple_ag_vote_transaction: Returns 1 if `txn` is a simple
   Alpenglow vote and 0 otherwise.  `txn` is a non-null pointer to a
   Solana transaction parsed by fd_txn_parse_core.  `payload` is a
   non-null pointer to serialization of `txn`, which is coupled with
   `txn` as both `txn` and `payload` are different representations of
   the same data.

   A simple vote is a transaction that meets the following criteria:
   1. has 1 or 2 signatures
   2. is legacy transaction
   3. has exactly one instruction
   4. ...which must be an Alpenglow (ag) Vote instruction
 */
int
fd_txn_is_simple_ag_vote_transaction( fd_txn_t const * txn,
                                      void     const * payload );

/* fd_ag_vote_deserialize_from_data will parse raw data as an Alpenglow
   vote.  Not all fields in fd_txn_t are populated, only those associated
   with the given allowed types:
     FD_AG_VOTE_NOTARIZE, FD_AG_VOTE_NOTARIZE_FALLBACK: version, slot,
       block_id, replayed_slot, replayed_bank_hash.
     FD_AG_VOTE_FINALIZE, FD_AG_VOTE_SKIP, FD_AG_VOTE_SKIP_FALLBACK:
       slot.
   All other types are not valid.  It returns FD_AG_VOTE_SERDES_SUCCESS /
   FD_AG_VOTE_SERDES_FAILURE accordingly.  On failure, the slot field
   will be set to ULONG_MAX. */
int
fd_ag_vote_deserialize_from_data( fd_ag_vote_t * vote,
                                  uchar const * data );

/* fd_ag_vote_serialize_into_data will serialize a valid Alpenglow vote
   into the provided data buffer.  Not all fields in fd_txn_t need to be
   populated, only those associated with the given allowed types:
     FD_AG_VOTE_NOTARIZE, FD_AG_VOTE_NOTARIZE_FALLBACK: version, slot,
       block_id, replayed_slot, replayed_bank_hash.
     FD_AG_VOTE_FINALIZE, FD_AG_VOTE_SKIP, FD_AG_VOTE_SKIP_FALLBACK:
       slot.
   All other types are not valid.  It returns FD_AG_VOTE_SERDES_SUCCESS /
   FD_AG_VOTE_SERDES_FAILURE accordingly. */
int 
fd_ag_vote_serialize_into_data( uchar * data,
                                fd_ag_vote_t const * vote );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_discof_alpen_fd_alpen_h */
