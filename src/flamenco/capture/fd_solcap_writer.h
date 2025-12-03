#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_writer_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_writer_h

#include "fd_solcap_proto.h"
#include "fd_solcap.pb.h"
#include "../types/fd_types_custom.h"

/* fd_solcap_writer_t produces pcapng dumps containing solcap packets.

    Each solcap write function is responsible for encoding and writing
    out a specific type of chunk. They provide both a header, which
    contains information about type of chunk, size, and slot number,
    and the chunk data.

    Note: The functionality is limited to the writing of solcap v2 files
    Nishk (TODO): Write docs for solcap writer
*/

FD_PROTOTYPES_BEGIN

/* Maximum fragment size for account data. Must be <= USHORT_MAX (65535)
   because fd_frag_meta_t stores sz as a ushort. */
#define SOLCAP_WRITE_ACCOUNT_DATA_MTU (65535UL)

struct fd_solcap_writer {
  int   fd;
};
typedef struct fd_solcap_writer fd_solcap_writer_t;

ulong
fd_solcap_writer_align( void );

ulong
fd_solcap_writer_footprint( void );

fd_solcap_writer_t *
fd_solcap_writer_init(  fd_solcap_writer_t * writer,
                        int                  fd );

/* fd_solcap_write_account_hdr writes an account update EPB header.
   Writes EPB + internal chunk header + account metadata. Account data
   must be written separately via fd_solcap_write_data. Returns the
   total block_len for use when writing the footer. */

uint
fd_solcap_write_account_hdr( fd_solcap_writer_t *              writer,
                              fd_solcap_buf_msg_t *            msg_hdr,
                              fd_solcap_account_update_hdr_t * account_update );

/* fd_solcap_write_data writes raw data bytes to the capture file.
   This is used for continuation fragments of any message type that
   spans multiple link fragments (e.g., large account data). */
uint
fd_solcap_write_data( fd_solcap_writer_t * writer,
                      void const *         data,
                      ulong                data_sz );

/* fd_solcap_write_bank_preimage writes a complete bank preimage EPB.
   Contains bank hash, prev hash, accounts hash, PoH hash, and sig count.
   Returns block_len for the footer. */

uint
fd_solcap_write_bank_preimage( fd_solcap_writer_t *        writer,
                               fd_solcap_buf_msg_t *       msg_hdr,
                               fd_solcap_bank_preimage_t * bank_preimage );

/* fd_solcap_write_stake_rewards_begin writes a stake rewards begin EPB.
   Marks the start of epoch rewards distribution with inflation and
   point totals. Returns block_len for the footer. */

uint
fd_solcap_write_stake_rewards_begin( fd_solcap_writer_t *              writer,
                                     fd_solcap_buf_msg_t *             msg_hdr,
                                     fd_solcap_stake_rewards_begin_t * stake_rewards_begin );

/* fd_solcap_write_stake_reward_event writes a stake reward event EPB.
   Captures individual reward calculation for a stake/vote account pair.
   Returns block_len for the footer. */

uint
fd_solcap_write_stake_reward_event( fd_solcap_writer_t *              writer,
                                     fd_solcap_buf_msg_t *            msg_hdr,
                                     fd_solcap_stake_reward_event_t * stake_reward_event );

/* fd_solcap_write_stake_account_payout writes a stake payout EPB.
   Captures stake account state changes during reward distribution.
   Returns block_len for the footer. */

uint
fd_solcap_write_stake_account_payout( fd_solcap_writer_t *               writer,
                                      fd_solcap_buf_msg_t *              msg_hdr,
                                      fd_solcap_stake_account_payout_t * stake_account_payout );

/* fd_solcap_write_ftr writes the PCapNG block footer. Adds padding to
   align to 4-byte boundary, then writes the redundant block length.
   Must be called after each message to complete the EPB. */

uint
fd_solcap_write_ftr( fd_solcap_writer_t * writer,
                     uint                 block_len_redundant );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_writer_h */
