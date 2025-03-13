#ifndef HEADER_fd_src_disco_pack_fd_pack_unwritable_h
#define HEADER_fd_src_disco_pack_fd_pack_unwritable_h

/* Table of special addresses that are not allowed to be written to.  We
   immediately reject and refuse to pack any transaction that tries to
   write to one of these accounts.  Because we reject any writes to any
   of these accounts, we actually don't need to track reads of them
   either.  This is nice, because fd_map_dynamic requires a null address
   that we promise never to insert.  The zero address is a sysvar, so
   now we meet that part of the fd_map_dynamic contract. */
#define MAP_PERFECT_NAME      fd_pack_unwritable
#define MAP_PERFECT_LG_TBL_SZ 5
#define MAP_PERFECT_T         fd_acct_addr_t
#define MAP_PERFECT_HASH_C    1073878000U
#define MAP_PERFECT_HASH_A    1039211272U
#define MAP_PERFECT_KEY       b
#define MAP_PERFECT_KEY_T     fd_acct_addr_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

/* This perfect hash table is too full for the normal hash function, but
   we can get it to fit with this function with two terms. */
#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u)+MAP_PERFECT_HASH_A)>>27)&0x1FU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a13 | (a14<<8) | (a15<<16) | (a16<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->b + 13UL ) )

/* This list is what Agave's is_maybe_writable contains as of the
   activation of 8U4skmMVnF6k2kMvrWbQuRUT3qQSiTYpSjqmhmgfthZu (Feb 14,
   2025 for mainnet). */

/* Sysvars */
#define MAP_PERFECT_0  ( SYSVAR_CLOCK_ID          ),
#define MAP_PERFECT_1  ( SYSVAR_EPOCH_REWARDS_ID  ),
#define MAP_PERFECT_2  ( SYSVAR_EPOCH_SCHED_ID    ),
#define MAP_PERFECT_3  ( SYSVAR_FEES_ID           ),
#define MAP_PERFECT_4  ( SYSVAR_INSTRUCTIONS_ID   ),
#define MAP_PERFECT_5  ( SYSVAR_LAST_RESTART_ID   ),
#define MAP_PERFECT_6  ( SYSVAR_RECENT_BLKHASH_ID ),
#define MAP_PERFECT_7  ( SYSVAR_RENT_ID           ),
#define MAP_PERFECT_8  ( SYSVAR_REWARDS_ID        ),
#define MAP_PERFECT_9  ( SYSVAR_SLOT_HASHES_ID    ),
#define MAP_PERFECT_10 ( SYSVAR_SLOT_HIST_ID      ),
#define MAP_PERFECT_11 ( SYSVAR_STAKE_HIST_ID     ),
#define MAP_PERFECT_12 ( SYSVAR_PROG_ID           ),

/* Programs */
#define MAP_PERFECT_13 ( ADDR_LUT_PROG_ID         ),
#define MAP_PERFECT_14 ( BPF_LOADER_2_PROG_ID     ),
#define MAP_PERFECT_15 ( BPF_LOADER_1_PROG_ID     ),
#define MAP_PERFECT_16 ( BPF_UPGRADEABLE_PROG_ID  ),
#define MAP_PERFECT_17 ( COMPUTE_BUDGET_PROG_ID   ),
#define MAP_PERFECT_18 ( CONFIG_PROG_ID           ),
#define MAP_PERFECT_19 ( ED25519_SV_PROG_ID       ),
#define MAP_PERFECT_20 ( FEATURE_ID               ),
#define MAP_PERFECT_21 ( LOADER_V4_PROG_ID        ),
#define MAP_PERFECT_22 ( KECCAK_SECP_PROG_ID      ),
#define MAP_PERFECT_23 ( SECP256R1_PROG_ID        ),
#define MAP_PERFECT_24 ( STAKE_CONFIG_PROG_ID     ),
#define MAP_PERFECT_25 ( STAKE_PROG_ID            ),
#define MAP_PERFECT_26 ( SYS_PROG_ID              ), /* Do not remove. See above. */
#define MAP_PERFECT_27 ( VOTE_PROG_ID             ),
#define MAP_PERFECT_28 ( ZK_EL_GAMAL_PROG_ID      ),
#define MAP_PERFECT_29 ( ZK_TOKEN_PROG_ID         ),
#define MAP_PERFECT_30 ( NATIVE_LOADER_ID         ),

#include "../../util/tmpl/fd_map_perfect.c"

#undef PERFECT_HASH

#endif /* HEADER_fd_src_disco_pack_fd_pack_unwritable_h */
