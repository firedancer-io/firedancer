#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_pcap.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../ballet/shred/fd_shred.h"
#include "../../../disco/pack/fd_microblock.h"
#include "../../../disco/fd_txn_m.h"
#include "../../../disco/pack/fd_pack.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../ballet/base64/fd_base64.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../tango/fd_tango_base.h"
#include "../../../disco/tiles.h"
#include "stdio.h"

#define MAP_PERFECT_NAME      fd_pack_unwritable
#define MAP_PERFECT_LG_TBL_SZ 5
#define MAP_PERFECT_T         fd_acct_addr_t
#define MAP_PERFECT_HASH_C    1402126759U
#define MAP_PERFECT_KEY       b
#define MAP_PERFECT_KEY_T     fd_acct_addr_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>27)&0x1FU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->b + 8UL ) )

/* This list is a superset of what Lab's is_builtin_key_or_sysvar checks. */
/* Sysvars */
#define MAP_PERFECT_0  ( SYSVAR_CLOCK_ID          ),
#define MAP_PERFECT_1  ( SYSVAR_EPOCH_SCHED_ID    ),
#define MAP_PERFECT_2  ( SYSVAR_FEES_ID           ),
#define MAP_PERFECT_3  ( SYSVAR_RECENT_BLKHASH_ID ),
#define MAP_PERFECT_4  ( SYSVAR_RENT_ID           ),
#define MAP_PERFECT_5  ( SYSVAR_REWARDS_ID        ),
#define MAP_PERFECT_6  ( SYSVAR_SLOT_HASHES_ID    ),
#define MAP_PERFECT_7  ( SYSVAR_SLOT_HIST_ID      ),
#define MAP_PERFECT_8  ( SYSVAR_STAKE_HIST_ID     ),
#define MAP_PERFECT_9  ( SYSVAR_INSTRUCTIONS_ID   ),
#define MAP_PERFECT_10 ( SYSVAR_EPOCH_REWARDS_ID  ),
#define MAP_PERFECT_11 ( SYSVAR_LAST_RESTART_ID   ),
/* Programs */
#define MAP_PERFECT_12 ( CONFIG_PROG_ID           ),
#define MAP_PERFECT_13 ( FEATURE_ID               ),
#define MAP_PERFECT_14 ( NATIVE_LOADER_ID         ),
#define MAP_PERFECT_15 ( STAKE_PROG_ID            ),
#define MAP_PERFECT_16 ( STAKE_CONFIG_PROG_ID     ),
#define MAP_PERFECT_17 ( VOTE_PROG_ID             ),
#define MAP_PERFECT_18 ( SYS_PROG_ID              ), /* Do not remove. See above. */
#define MAP_PERFECT_19 ( BPF_LOADER_1_PROG_ID     ),
#define MAP_PERFECT_20 ( BPF_LOADER_2_PROG_ID     ),
#define MAP_PERFECT_21 ( BPF_UPGRADEABLE_PROG_ID  ),
/* Extras */
#define MAP_PERFECT_22 ( ED25519_SV_PROG_ID       ),
#define MAP_PERFECT_23 ( KECCAK_SECP_PROG_ID      ),
#define MAP_PERFECT_24 ( COMPUTE_BUDGET_PROG_ID   ),
#define MAP_PERFECT_25 ( ADDR_LUT_PROG_ID         ),
#define MAP_PERFECT_26 ( NATIVE_MINT_ID           ),
#define MAP_PERFECT_27 ( TOKEN_PROG_ID            ),
#define MAP_PERFECT_28 ( SYSVAR_PROG_ID           ),

#include "../../../util/tmpl/fd_map_perfect.c"


FD_FN_PURE static inline int
fd_resolv_is_durable_nonce( fd_txn_t const * txn,
                            uchar    const * payload ) {
  if( FD_UNLIKELY( txn->instr_cnt==0 ) ) return 0;

  fd_txn_instr_t const * ix0 = &txn->instr[ 0 ];
  fd_acct_addr_t const * prog0 = fd_txn_get_acct_addrs( txn, payload ) + ix0->program_id;
  /* First instruction must be SystemProgram nonceAdvance instruction */
  fd_acct_addr_t const system_program[1] = { { { SYS_PROG_ID } } };
  if( FD_LIKELY( memcmp( prog0, system_program, sizeof(fd_acct_addr_t) ) ) )        return 0;

  /* instruction with three accounts and a four byte instruction data, a
     little-endian uint value 4 */
  if( FD_UNLIKELY( (ix0->data_sz!=4) | (ix0->acct_cnt!=3) ) ) return 0;

  return fd_uint_load_4( payload + ix0->data_off )==4U;
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  const char * path = fd_env_strip_cmdline_cstr( &argc, &argv, "--path", NULL, NULL );
  FILE * pcap_file = fopen( path, "r" );
  FD_TEST( pcap_file );

  fd_pcap_iter_t * iter = fd_pcap_iter_new( pcap_file );
  FD_TEST( iter );

  uchar pkt[ USHORT_MAX+64UL ] __attribute__((aligned(128)));
  long ts[1];
  ulong pkt_sz;


  ulong i = ULONG_MAX;
  while( 0UL!=(pkt_sz=fd_pcap_iter_next( iter, pkt, USHORT_MAX+64UL, ts ) ) ) {
    FD_TEST( pkt_sz>4UL );
    uint link_hash = FD_LOAD( uint, pkt+pkt_sz-4UL );
#define DEDUP_PACK 0x59ac4d00
#define RESOLV_PACK 0x59bd9100
    if( FD_UNLIKELY( link_hash!=RESOLV_PACK ) ) continue;

    fd_frag_meta_t const * mcache_entry = (fd_frag_meta_t const *)pkt;
    fd_txn_m_t * txnm = (fd_txn_m_t *)(mcache_entry+1);

    ulong payload_sz = txnm->payload_sz;
    (void)payload_sz;

    uchar const * payload = fd_txn_m_payload( txnm );
    fd_txn_t const * txn  = fd_txn_m_txn_t( txnm );

#define ACCT_ITER_TO_PTR( iter ) (__extension__( {                                          \
      ulong __idx = fd_txn_acct_iter_idx( iter );                                           \
      fd_ptr_if( __idx<fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM ), accts, alt_adj )+__idx; \
      }))
    fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
    fd_acct_addr_t const * alt     = fd_txn_m_alut( txnm );
    fd_acct_addr_t const * alt_adj = alt - fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

    if( FD_UNLIKELY( fd_resolv_is_durable_nonce( txn, payload ) ) ) {
      char nonce_acct[ FD_BASE58_ENCODED_32_SZ ];
      char nonce_val [ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( payload+txn->recent_blockhash_off, NULL, nonce_val );
      uchar idx = payload[ txn->instr[0].acct_off ];
      fd_acct_addr_t const * nacct = fd_ptr_if( idx<fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM ), accts, alt_adj )+idx;
      fd_base58_encode_32( nacct->b, NULL, nonce_acct );

      ulong sig_rewards = FD_PACK_FEE_PER_SIGNATURE * txn->signature_cnt; /* Easily in [5000, 635000] */

      ulong requested_execution_cus;
      ulong priority_rewards = 0UL;
      ulong precompile_sigs = 0UL;
      ulong requested_loaded_accounts_data_cost;
      uint flags = 0;
      ulong cost_estimate = fd_pack_compute_cost( txn, payload, &flags, &requested_execution_cus, &priority_rewards, &precompile_sigs, &requested_loaded_accounts_data_cost );

      /* precompile_sigs <= 16320, so after the addition,
         sig_rewards < 83,000,000 */
      sig_rewards += FD_PACK_FEE_PER_SIGNATURE * precompile_sigs;

      /* No fancy CU estimation in this version of pack
         for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) {
         uchar prog_id_idx = txn->instr[ i ].program_id;
         fd_acct_addr_t const * acct_addr = fd_txn_get_acct_addrs( txn, txnp->payload ) + (ulong)prog_id_idx;
         }
         */
      uint rewards                              = (priority_rewards < (UINT_MAX - sig_rewards)) ? (uint)(sig_rewards + priority_rewards) : UINT_MAX;
      uint compute_est                          = (uint)cost_estimate;


      printf( "nonce transaction %s has value %s. Pays %u, %u CUs\n", nonce_acct, nonce_val, rewards, compute_est );
    }

    i++;

  }


  FD_TEST( !fclose( fd_pcap_iter_delete( iter ) ) );
  fd_halt();
  return 0;
}
