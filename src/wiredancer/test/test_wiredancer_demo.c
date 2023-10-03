/* Wiredancer Unit Test.
  This test is intended to be run in AWS-F1. Its main goal is to check Wiredancer
  against x86. A "replay" tile feeds packets to a "parser" tile. The latter parses
  the transaction (it assumes 1 txn per packet for this test), and sends sigverify
  workload downstream (as many requests as needed per txn). This can be fed into
  an x86-based "verify" tile and/or Wiredancer. Due to the (substantial) difference
  in throughput, the x86-based "verify" tile will constantly try to catch up by
  skipping sequence numbers (i.e. signature verification requests). However, the
  "checker" tile will check every output from x86 against the corresponding output
  from Wiredancer (by matching the sequence numbers).

  This unit test can also be run with either Wiredancer or x86 separately (in which
  case the "checker" will just consume either output).

  General notes:
    It is assumed that all FPGAs have already been programmed with the Wiredancer
    image.

    The test replays a pcap in a loop. The packets in that pcap are expected to be
    network packets ( i.e. they must contain eth/ip4/udp headers + txn ).

    The FPGA slots in AWS-F1 need to be passed using 1-hot encoding:
      * 1x fpga in slot 0: --wd-slots 1
      * 1x fpga in slot 1: --wd-slots 2
      * 2x fpga(s) in slots 1 and 2: --wd-slots 3

    The duration of the test is set in ns. If "--duration 0" is passed, then the
    test will continue indefinitely (unit Ctrl+c).

    Transactions can be randomly corrupted (approx 50% of the time) by setting
    "--rand-txn-corrupt 1".

  Sample tests:
    # Check Wiredancer vs x86 ( 1 fpga in slot 0, with random txn corruption enabled ) #
      sudo ${BUILD_FOLDER}/linux/gcc/x86_64/unit-test/test_wiredancer_demo --replay-pcap ${PCAP_PATH} --tile-cpus 1,2,3,4,5 --duration 0 --v-x86-enabled 1 --v--wd-enabled 1 --wd-slots 1 --rand-txn-corrupt 1

    # Check Wiredancer vs x86 ( 2 fpgas in slot 0 and 1, with random txn corruption enabled ) #
      sudo ${BUILD_FOLDER}/linux/gcc/x86_64/unit-test/test_wiredancer_demo --replay-pcap ${PCAP_PATH} --tile-cpus 1,2,3,4,5 --duration 0 --v-x86-enabled 1 --v--wd-enabled 1 --wd-slots 3 --rand-txn-corrupt 1

    # Wiredancer only ( 2 fpgas in slot 0 and 1 ) #
      sudo ${BUILD_FOLDER}/linux/gcc/x86_64/unit-test/test_wiredancer_demo --replay-pcap ${PCAP_PATH} --tile-cpus 1,2,3,4,5 --duration 0 --v-x86-enabled 0 --v--wd-enabled 1 --wd-slots 3 --rand-txn-corrupt 0

    # x86 only #
      sudo ${BUILD_FOLDER}/linux/gcc/x86_64/unit-test/test_wiredancer_demo --replay-pcap ${PCAP_PATH} --tile-cpus 1,2,3,4,5 --duration 0 --v-x86-enabled 1 --v--wd-enabled 0 --wd-slots 0 --rand-txn-corrupt 0

    * x86 only (5 seconds) #
      sudo ${BUILD_FOLDER}/linux/gcc/x86_64/unit-test/test_wiredancer_demo --replay-pcap ${PCAP_PATH} --tile-cpus 1,2,3,4,5 --duration 5000000000 --v-x86-enabled 1 --v--wd-enabled 0 --wd-slots 0 --rand-txn-corrupt 0
*/


#include "fd_replay_loop.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/ed25519/fd_ed25519_private.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../c/wd_f1.h"
#include "wd_f1_mon.h"
#include <pthread.h>

/* Wiredancer unit test */

#if FD_HAS_HOSTED && FD_HAS_X86 && FD_HAS_WIREDANCER

#define DEMO_REPLAY_FSEQ_CNT_MAX 1 /* max number of replay consumers*/

#define DEMO_PARSER_CNC_PKT_CNT_IDX 0
#define DEMO_PARSER_CNC_TXN_CNT_IDX 1
#define DEMO_PARSER_CNC_SIG_CNT_IDX 2
#define DEMO_PARSER_CNC_OUT_SEQ_IDX 3
#define DEMO_PARSER_CNC_OUT_SIG_IDX 4

#define DEMO_V_X86_CNC_TXN_CNT_IDX 0
#define DEMO_V_X86_CNC_SIG_CNT_IDX 1

#define DEMO_VCHECK_CNC_SIG__X86_CNT_IDX 0
#define DEMO_VCHECK_CNC_SIG_FPGA_CNT_IDX 1
#define DEMO_VCHECK_CNC_VALIDATE_CNT_IDX 2
#define DEMO_VCHECK_CNC_SIG_PASS_CNT_IDX 3
#define DEMO_VCHECK_CNC_SIG_FAIL_CNT_IDX 4

#define DEMO_TEST_VERSION_SIGVERIFY  0
#define DEMO_TEST_VERSION_SHA512MODQ 1

FD_STATIC_ASSERT( FD_REPLAY_CNC_SIGNAL_ACK==4UL, unit_test );

FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_CHUNK_IDX    ==2UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_DONE    ==3UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT ==4UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_PUB_SZ  ==5UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_FILT_CNT==6UL, unit_test );
FD_STATIC_ASSERT( FD_REPLAY_CNC_DIAG_PCAP_FILT_SZ ==7UL, unit_test );

FD_STATIC_ASSERT( FD_REPLAY_TILE_OUT_MAX==8192UL, unit_test );

FD_STATIC_ASSERT( FD_REPLAY_TILE_SCRATCH_ALIGN==128UL, unit_test );

union parsed_txn_compressed_meta {
  ulong all;
  struct {
    ushort msg_sz;          /* msessage size */
    ushort msg_off;         /* message offset from the start of the pkt */
    ushort signature_off;   /* signature offset from the start of the pkt */
    ushort public_key_off;  /* public_key offset from the start of the pkt */
  } value;
};
typedef union parsed_txn_compressed_meta parsed_txn_compressed_meta_t;
FD_STATIC_ASSERT( sizeof(parsed_txn_compressed_meta_t) == sizeof(ulong), unit_test );


struct test_cfg {
  fd_wksp_t *  wksp;

  fd_cnc_t *        replay_cnc;
  char const *      replay_pcap;
  ulong             replay_mtu;
  ulong             replay_orig;
  fd_frag_meta_t *  replay_mcache;
  uchar *           replay_dcache;
  ulong             replay_cr_max;
  long              replay_lazy;
  uint              replay_seed;
  ulong **          replay_fseq;
  ulong             replay_fseq_cnt;

  fd_cnc_t *        parser_cnc;
  fd_frag_meta_t *  parser_mcache;
  int               parser_lazy;
  uint              parser_seed;
  int               parser_enabled;
  ulong *           parser_replay_fseq;
  int               parser_rand_txn_corrupt;

  fd_cnc_t *        v_x86_cnc;
  fd_frag_meta_t *  v_x86_mcache;
  int               v_x86_lazy;
  uint              v_x86_seed;
  int               v_x86_enabled;

  int               v__wd_enabled;
  fd_frag_meta_t *  v__wd_mcache;

  fd_cnc_t *        vcheck_cnc;
  uint              vcheck_seed;
  int               vcheck_lazy;

  int               test_version;

  /* Wiredancer */
  ulong             wd_slots;   
  int               wd_split;  
};
typedef struct test_cfg test_cfg_t;





//    SSSSSSSSSSSSSSS HHHHHHHHH     HHHHHHHHH               AAA            555555555555555555   1111111    222222222222222    
//  SS:::::::::::::::SH:::::::H     H:::::::H              A:::A           5::::::::::::::::5  1::::::1   2:::::::::::::::22  
// S:::::SSSSSS::::::SH:::::::H     H:::::::H             A:::::A          5::::::::::::::::5 1:::::::1   2::::::222222:::::2 
// S:::::S     SSSSSSSHH::::::H     H::::::HH            A:::::::A         5:::::555555555555 111:::::1   2222222     2:::::2 
// S:::::S              H:::::H     H:::::H             A:::::::::A        5:::::5               1::::1               2:::::2 
// S:::::S              H:::::H     H:::::H            A:::::A:::::A       5:::::5               1::::1               2:::::2 
//  S::::SSSS           H::::::HHHHH::::::H           A:::::A A:::::A      5:::::5555555555      1::::1            2222::::2  
//   SS::::::SSSSS      H:::::::::::::::::H          A:::::A   A:::::A     5:::::::::::::::5     1::::l       22222::::::22   
//     SSS::::::::SS    H:::::::::::::::::H         A:::::A     A:::::A    555555555555:::::5    1::::l     22::::::::222     
//        SSSSSS::::S   H::::::HHHHH::::::H        A:::::AAAAAAAAA:::::A               5:::::5   1::::l    2:::::22222        
//             S:::::S  H:::::H     H:::::H       A:::::::::::::::::::::A              5:::::5   1::::l   2:::::2             
//             S:::::S  H:::::H     H:::::H      A:::::AAAAAAAAAAAAA:::::A 5555555     5:::::5   1::::l   2:::::2             
// SSSSSSS     S:::::SHH::::::H     H::::::HH   A:::::A             A:::::A5::::::55555::::::5111::::::1112:::::2       222222
// S::::::SSSSSS:::::SH:::::::H     H:::::::H  A:::::A               A:::::A55:::::::::::::55 1::::::::::12::::::2222222:::::2
// S:::::::::::::::SS H:::::::H     H:::::::H A:::::A                 A:::::A 55:::::::::55   1::::::::::12::::::::::::::::::2
//  SSSSSSSSSSSSSSS   HHHHHHHHH     HHHHHHHHHAAAAAAA                   AAAAAAA  555555555     11111111111122222222222222222222
                                                                                                                           

int
sha512_modq_lsB(  void const *  msg,
                  ulong         sz,
                  void const *  sig,
                  void const *  public_key,
                  fd_sha512_t * sha ) {
  uchar const * r = (uchar const *)sig;

  uchar h[64];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ),
                  r, 32UL ), public_key, 32UL ), msg, sz ), h );
  fd_ed25519_sc_reduce( h, h );
  return (int)h[0];
}










// RRRRRRRRRRRRRRRRR   EEEEEEEEEEEEEEEEEEEEEEPPPPPPPPPPPPPPPPP   LLLLLLLLLLL                            AAA           YYYYYYY       YYYYYYY
// R::::::::::::::::R  E::::::::::::::::::::EP::::::::::::::::P  L:::::::::L                           A:::A          Y:::::Y       Y:::::Y
// R::::::RRRRRR:::::R E::::::::::::::::::::EP::::::PPPPPP:::::P L:::::::::L                          A:::::A         Y:::::Y       Y:::::Y
// RR:::::R     R:::::REE::::::EEEEEEEEE::::EPP:::::P     P:::::PLL:::::::LL                         A:::::::A        Y::::::Y     Y::::::Y
//   R::::R     R:::::R  E:::::E       EEEEEE  P::::P     P:::::P  L:::::L                          A:::::::::A       YYY:::::Y   Y:::::YYY
//   R::::R     R:::::R  E:::::E               P::::P     P:::::P  L:::::L                         A:::::A:::::A         Y:::::Y Y:::::Y   
//   R::::RRRRRR:::::R   E::::::EEEEEEEEEE     P::::PPPPPP:::::P   L:::::L                        A:::::A A:::::A         Y:::::Y:::::Y    
//   R:::::::::::::RR    E:::::::::::::::E     P:::::::::::::PP    L:::::L                       A:::::A   A:::::A         Y:::::::::Y     
//   R::::RRRRRR:::::R   E:::::::::::::::E     P::::PPPPPPPPP      L:::::L                      A:::::A     A:::::A         Y:::::::Y      
//   R::::R     R:::::R  E::::::EEEEEEEEEE     P::::P              L:::::L                     A:::::AAAAAAAAA:::::A         Y:::::Y       
//   R::::R     R:::::R  E:::::E               P::::P              L:::::L                    A:::::::::::::::::::::A        Y:::::Y       
//   R::::R     R:::::R  E:::::E       EEEEEE  P::::P              L:::::L         LLLLLL    A:::::AAAAAAAAAAAAA:::::A       Y:::::Y       
// RR:::::R     R:::::REE::::::EEEEEEEE:::::EPP::::::PP          LL:::::::LLLLLLLLL:::::L   A:::::A             A:::::A      Y:::::Y       
// R::::::R     R:::::RE::::::::::::::::::::EP::::::::P          L::::::::::::::::::::::L  A:::::A               A:::::A  YYYY:::::YYYY    
// R::::::R     R:::::RE::::::::::::::::::::EP::::::::P          L::::::::::::::::::::::L A:::::A                 A:::::A Y:::::::::::Y    
// RRRRRRRR     RRRRRRREEEEEEEEEEEEEEEEEEEEEEPPPPPPPPPP          LLLLLLLLLLLLLLLLLLLLLLLLAAAAAAA                   AAAAAAAYYYYYYYYYYYYY 


/* REPLAY tile ************************************************************/

static int
replay_tile_main( int     argc,
              char ** argv ) {
  (void)argc;
  test_cfg_t * cfg = (test_cfg_t *)argv;

  FD_LOG_NOTICE(( "active: replay_tile_main" ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->replay_seed, 0UL ) );

  uchar scratch[ FD_REPLAY_TILE_SCRATCH_FOOTPRINT( 1UL ) ] __attribute__((aligned( FD_REPLAY_TILE_SCRATCH_ALIGN )));

  FD_TEST( !fd_replay_tile_loop( cfg->replay_cnc, cfg->replay_pcap, cfg->replay_mtu, cfg->replay_orig, cfg->replay_mcache, cfg->replay_dcache,
                                 cfg->replay_fseq_cnt, cfg->replay_fseq, cfg->replay_cr_max, cfg->replay_lazy, rng, scratch ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}



// PPPPPPPPPPPPPPPPP        AAA               RRRRRRRRRRRRRRRRR      SSSSSSSSSSSSSSS EEEEEEEEEEEEEEEEEEEEEERRRRRRRRRRRRRRRRR   
// P::::::::::::::::P      A:::A              R::::::::::::::::R   SS:::::::::::::::SE::::::::::::::::::::ER::::::::::::::::R  
// P::::::PPPPPP:::::P    A:::::A             R::::::RRRRRR:::::R S:::::SSSSSS::::::SE::::::::::::::::::::ER::::::RRRRRR:::::R 
// PP:::::P     P:::::P  A:::::::A            RR:::::R     R:::::RS:::::S     SSSSSSSEE::::::EEEEEEEEE::::ERR:::::R     R:::::R
//   P::::P     P:::::P A:::::::::A             R::::R     R:::::RS:::::S              E:::::E       EEEEEE  R::::R     R:::::R
//   P::::P     P:::::PA:::::A:::::A            R::::R     R:::::RS:::::S              E:::::E               R::::R     R:::::R
//   P::::PPPPPP:::::PA:::::A A:::::A           R::::RRRRRR:::::R  S::::SSSS           E::::::EEEEEEEEEE     R::::RRRRRR:::::R 
//   P:::::::::::::PPA:::::A   A:::::A          R:::::::::::::RR    SS::::::SSSSS      E:::::::::::::::E     R:::::::::::::RR  
//   P::::PPPPPPPPP A:::::A     A:::::A         R::::RRRRRR:::::R     SSS::::::::SS    E:::::::::::::::E     R::::RRRRRR:::::R 
//   P::::P        A:::::AAAAAAAAA:::::A        R::::R     R:::::R       SSSSSS::::S   E::::::EEEEEEEEEE     R::::R     R:::::R
//   P::::P       A:::::::::::::::::::::A       R::::R     R:::::R            S:::::S  E:::::E               R::::R     R:::::R
//   P::::P      A:::::AAAAAAAAAAAAA:::::A      R::::R     R:::::R            S:::::S  E:::::E       EEEEEE  R::::R     R:::::R
// PP::::::PP   A:::::A             A:::::A   RR:::::R     R:::::RSSSSSSS     S:::::SEE::::::EEEEEEEE:::::ERR:::::R     R:::::R
// P::::::::P  A:::::A               A:::::A  R::::::R     R:::::RS::::::SSSSSS:::::SE::::::::::::::::::::ER::::::R     R:::::R
// P::::::::P A:::::A                 A:::::A R::::::R     R:::::RS:::::::::::::::SS E::::::::::::::::::::ER::::::R     R:::::R
// PPPPPPPPPPAAAAAAA                   AAAAAAARRRRRRRR     RRRRRRR SSSSSSSSSSSSSSS   EEEEEEEEEEEEEEEEEEEEEERRRRRRRR     RRRRRRR

/* PARSER tile ************************************************************/

static int
parser_tile_main( int     argc,
                  char ** argv ) {
  ulong    parser_idx = (ulong)argc;
  test_cfg_t * cfg    = (test_cfg_t *)argv;
  fd_wksp_t *  wksp   = cfg->wksp;
  (void)parser_idx;
  
  FD_LOG_NOTICE(( "active: parser_tile_main" ));

  /* Hook up to parser cnc */
  fd_cnc_t * cnc = cfg->parser_cnc;

  /* Command and control */
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  ulong cnc_diag_pkt_cnt = 0ULL;
  ulong cnc_diag_txn_cnt = 0ULL;
  ulong cnc_diag_sig_cnt = 0ULL;

  /* Hook up to replay mcache */
  fd_frag_meta_t const * mcache = cfg->replay_mcache;
  ulong                  depth  = fd_mcache_depth( mcache );
  ulong const *          sync   = fd_mcache_seq_laddr_const( mcache );
  ulong                  seq    = fd_mcache_seq_query( sync );

  /* Hook up to replay flow control */
  ulong * fseq = cfg->parser_replay_fseq;

  /* Hook up to the output mcache */
  fd_frag_meta_t * out_mcache = cfg->parser_mcache;
  ulong            out_depth  = fd_mcache_depth( out_mcache );
  ulong *          out_sync   = fd_mcache_seq_laddr( out_mcache );
  ulong            out_seq    = fd_mcache_seq_query( out_sync );
  ulong            out_sig    = 0UL; /* this works as a counter (in this demo) */
  cnc_diag[ DEMO_PARSER_CNC_OUT_SEQ_IDX ] = out_seq;
  cnc_diag[ DEMO_PARSER_CNC_OUT_SIG_IDX ] = out_sig;

  /* Enabled consumers */
  int v_x86_enabled = cfg->v_x86_enabled;
  int v__wd_enabled = cfg->v__wd_enabled;

  /* Hook up wd mcache */
  fd_frag_meta_t * v__wd_mcache = ( !!v__wd_enabled )? cfg->v__wd_mcache                   : NULL;
  ulong            v__wd_depth  = ( !!v__wd_enabled )? fd_mcache_depth( v__wd_mcache )     : 0UL;
  ulong *          v__wd_sync   = ( !!v__wd_enabled )? fd_mcache_seq_laddr( v__wd_mcache ) : NULL;
  ulong            v__wd_seq    = ( !!v__wd_enabled )? fd_mcache_seq_query( v__wd_sync )   : 0UL;

  /* Hook up to the random number generator */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->parser_seed, 0UL ) );

  /* Random txn corruption */
  int rand_txn_corrupt = cfg->parser_rand_txn_corrupt;

  /* Configure housekeeping */
  ulong async_min = 1UL << cfg->parser_lazy;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  /* Txn parsing counters */
  fd_txn_parse_counters_t counters_opt[1];
  
  /* Wiredancer init */
  wd_wksp_t wd;
  int wd_split = cfg->wd_split;
  uint64_t wd_slots = cfg->wd_slots;
  FD_TEST( !wd_init_pci( &wd, wd_slots ) );
  wd_ed25519_verify_init_req( &wd, 1, v__wd_depth, v__wd_mcache );
  FD_TEST( !!wd_split );

  /* Main loop */
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Wait for frag seq while doing housekeeping in the background */

    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   diff;

    ulong sig;
    ulong chunk;
    ulong sz;
    ulong ctl;
    ulong tsorig;
    ulong tspub;
    FD_MCACHE_WAIT_REG( sig, chunk, sz, ctl, tsorig, tspub, mline, seq_found, diff, async_rem, mcache, depth, seq );

    /* Housekeeping */
    if( FD_UNLIKELY( !async_rem ) ) {
      /* Send flow control credits */
      fd_fctl_rx_cr_return( fseq, seq );
      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, fd_tickcount() );
      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }
      /* Reload housekeeping timer */
      async_rem = fd_tempo_async_reload( rng, async_min );
      continue;
    }

    if( FD_UNLIKELY( diff ) ) FD_LOG_ERR(( "Overrun while polling" ));

    /* Process the received fragment */
    ulong p0 = (ulong) fd_chunk_to_laddr_const( wksp, chunk );
    uchar const * p = (uchar const *)p0;
    (void)ctl; (void)sz; (void)sig; (void)tsorig; (void)tspub;

    /* Process eth header */
    fd_eth_hdr_t * p_eth = (fd_eth_hdr_t*)p;          p = p + sizeof(fd_eth_hdr_t);
    ushort net_type = fd_ushort_bswap( p_eth->net_type );
    if( FD_UNLIKELY( net_type == FD_ETH_HDR_TYPE_VLAN ) ) {
      do {
        fd_vlan_tag_t * p_vlan = (fd_vlan_tag_t*)p;   p = p + sizeof(fd_vlan_tag_t);
        net_type = fd_ushort_bswap( p_vlan->net_type );
      } while( net_type == FD_ETH_HDR_TYPE_VLAN );
    }
    FD_TEST( net_type == FD_ETH_HDR_TYPE_IP );

    /* Process ipv4 header */
    fd_ip4_hdr_t * p_ip4 = (fd_ip4_hdr_t*)p;          p = p + p_ip4->ihl*sizeof(uint);
    FD_TEST( p_ip4->protocol == FD_IP4_HDR_PROTOCOL_UDP );
    /* FIXME remove checksum verification for performance? */
    /* FIXME assume ihl==5 and use fd_ip4_hdr_check_fast? */
    FD_TEST( !fd_ip4_hdr_check( p_ip4 ) );

    /* Process udp header */
    fd_udp_hdr_t * p_udp = (fd_udp_hdr_t*)p;          p = p + sizeof(fd_udp_hdr_t);
    uchar const * dgram = p;
    ulong dgram_sz = fd_ushort_bswap(p_udp->net_len) - sizeof(fd_udp_hdr_t);
    /* FIXME remove checksum verification for performance? */
    FD_TEST( !fd_ip4_udp_check(p_ip4->saddr, p_ip4->daddr, p_udp, dgram) );

    /* Process txn sigverify */
    unsigned char parsed[FD_TXN_MAX_SZ];
    ulong txn_sz = fd_txn_parse( dgram, dgram_sz, parsed, counters_opt );
    
    /* Count processed packets */
    cnc_diag_pkt_cnt += 1ULL;

    if( FD_LIKELY( txn_sz ) ) {

      /* count processed transactions */
      cnc_diag_txn_cnt += 1ULL;
      
      fd_txn_t * txn = (fd_txn_t*)parsed;
      /* FIXME any checks necessary here? */
      uchar const *        msg = dgram    + txn->message_off;
      ulong            msg_sz0 = dgram_sz - txn->message_off;
      uchar const * signature  = dgram    + txn->signature_off;
      uchar const * public_key = dgram    + txn->acct_addr_off;
      ulong      signature_cnt = txn->signature_cnt;

      for( ulong i=0; i<signature_cnt; i++) {
        
        ulong msg_sz = msg_sz0;
        /* randomly corrupt the txn's msg (if enabled) */
        if( FD_LIKELY( !!rand_txn_corrupt ) ) { msg_sz -= (fd_rng_uint( rng ) & 0x1); }

        /* x86 */
        if( FD_LIKELY( !!v_x86_enabled )) {

          /* prepare compressed metadata */
          parsed_txn_compressed_meta_t meta;
          ulong ul_msg_sz         = msg_sz                  ;   FD_TEST( ul_msg_sz         < (1UL<<(8*sizeof(ushort))) );
          ulong ul_msg_off        = ((ulong)msg) - p0       ;   FD_TEST( ul_msg_off        < (1UL<<(8*sizeof(ushort))) );
          ulong ul_signature_off  = ((ulong)signature) - p0 ;   FD_TEST( ul_signature_off  < (1UL<<(8*sizeof(ushort))) );
          ulong ul_public_key_off = ((ulong)public_key) - p0;   FD_TEST( ul_public_key_off < (1UL<<(8*sizeof(ushort))) );
          meta.value.msg_sz         = (ushort) ul_msg_sz        ;
          meta.value.msg_off        = (ushort) ul_msg_off       ;
          meta.value.signature_off  = (ushort) ul_signature_off ;
          meta.value.public_key_off = (ushort) ul_public_key_off;
          out_sig = meta.all;
          ulong out_chunk = chunk; /* point to replay's dcache */

          /* publish in output mcache */
          ulong out_sz      = 0UL;
          ulong out_ctl     = fd_frag_meta_ctl( parser_idx, 1 /*som*/, 1 /*eom*/, 0 /*err*/ );
          long out_now      = fd_tickcount();
          ulong out_tsorig  = fd_frag_meta_ts_comp( out_now );
          ulong out_tspub   = out_tsorig;
          fd_mcache_publish( out_mcache, out_depth, out_seq, out_sig, out_chunk, out_sz, out_ctl, out_tsorig, out_tspub );
          cnc_diag[ DEMO_PARSER_CNC_OUT_SEQ_IDX ] = out_seq;
          cnc_diag[ DEMO_PARSER_CNC_OUT_SIG_IDX ] = out_sig;
          
          /* Windup for the next iteration */
          out_seq     = fd_seq_inc( out_seq, 1UL );
        }

        /* Wiredancer */
        if( FD_LIKELY( !!v__wd_enabled )) {
          ulong do_halt = 0UL;
          ulong out_sz  = 0UL;
          ulong out_ctl = fd_frag_meta_ctl( parser_idx, 1 /*som*/, 1 /*eom*/, 0 /*err*/ );
          /* Iterate trying to send the request */
          FD_TEST( !wd_ed25519_verify_req(&wd, msg, msg_sz, signature, public_key,
                            v__wd_seq, (uint)chunk, (uint16_t)out_ctl, (uint16_t)out_sz ) );
          v__wd_seq = fd_seq_inc( v__wd_seq, 1UL );
          if( !!do_halt ) { break; }
        }

        /* windup for the next iteration */
        signature  += FD_TXN_SIGNATURE_SZ;
        public_key += FD_TXN_PUBKEY_SZ;
        cnc_diag_sig_cnt += 1ULL;
        cnc_diag[ DEMO_PARSER_CNC_SIG_CNT_IDX ] = cnc_diag_sig_cnt;
      }
    }
    cnc_diag[ DEMO_PARSER_CNC_PKT_CNT_IDX ] = cnc_diag_pkt_cnt;
    cnc_diag[ DEMO_PARSER_CNC_TXN_CNT_IDX ] = cnc_diag_txn_cnt;

    /* Check that we weren't overrun while processing */
    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) {
      FD_LOG_ERR(( "Overrun while reading" ));
      FD_TEST( 0 );
    }

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );
  }

  /* Wiredancer */
  FD_TEST( !wd_free_pci( &wd ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}






// XXXXXXX       XXXXXXX     888888888             66666666   
// X:::::X       X:::::X   88:::::::::88          6::::::6    
// X:::::X       X:::::X 88:::::::::::::88       6::::::6     
// X::::::X     X::::::X8::::::88888::::::8     6::::::6      
// XXX:::::X   X:::::XXX8:::::8     8:::::8    6::::::6       
//    X:::::X X:::::X   8:::::8     8:::::8   6::::::6        
//     X:::::X:::::X     8:::::88888:::::8   6::::::6         
//      X:::::::::X       8:::::::::::::8   6::::::::66666    
//      X:::::::::X      8:::::88888:::::8 6::::::::::::::66  
//     X:::::X:::::X    8:::::8     8:::::86::::::66666:::::6 
//    X:::::X X:::::X   8:::::8     8:::::86:::::6     6:::::6
// XXX:::::X   X:::::XXX8:::::8     8:::::86:::::6     6:::::6
// X::::::X     X::::::X8::::::88888::::::86::::::66666::::::6
// X:::::X       X:::::X 88:::::::::::::88  66:::::::::::::66 
// X:::::X       X:::::X   88:::::::::88      66:::::::::66   
// XXXXXXX       XXXXXXX     888888888          666666666                                                           
                                                                           

/* V_X86 tile ************************************************************/

static int
v_x86_tile_main( int     argc,
                  char ** argv ) {
  ulong    v_x86_idx = (ulong)argc;
  test_cfg_t * cfg    = (test_cfg_t *)argv;
  fd_wksp_t *  wksp   = cfg->wksp;
  (void)v_x86_idx;
  
  FD_LOG_NOTICE(( "active: v_x86_tile_main" ));

  /* Test version */
  int test_version = cfg->test_version;

  /* Hook up to v_x86 cnc */
  fd_cnc_t * cnc = cfg->v_x86_cnc;

  /* Hook up to parser cnc */
  fd_cnc_t * parser_cnc = cfg->parser_cnc;
  ulong * parser_cnc_diag = (ulong *)fd_cnc_app_laddr( parser_cnc );

  /* Command and control */
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  cnc_diag[ DEMO_V_X86_CNC_TXN_CNT_IDX ] = 0UL;
  cnc_diag[ DEMO_V_X86_CNC_SIG_CNT_IDX ] = 0UL;

  /* Hook up to parser mcache */
  fd_frag_meta_t const * mcache = cfg->parser_mcache;
  ulong                  depth  = fd_mcache_depth( mcache );
  ulong const *          sync   = fd_mcache_seq_laddr_const( mcache );
  ulong                  seq    = fd_mcache_seq_query( sync );

  /* Hook up to parser flow control */

  /* Hook up to the output mcache */
  fd_frag_meta_t * out_mcache = cfg->v_x86_mcache;
  ulong            out_depth  = fd_mcache_depth( out_mcache );
  ulong *          out_sync   = fd_mcache_seq_laddr( out_mcache );
  ulong            out_seq    = fd_mcache_seq_query( out_sync );
  ulong            out_sig    = 0UL; /* this works as a counter (in this demo) */

  /* There is no output flow control (in this demo) - The consumer will
      get overrun if it starts lagging behind */

  /* Hook up to the random number generator */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->v_x86_seed, 0UL ) );

  /* Debug only */
  ulong parser_seq_unavailable_cnt = 0UL;

  /* Main loop */
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  while( parser_cnc_diag[ DEMO_PARSER_CNC_OUT_SEQ_IDX ] <= seq ) { FD_SPIN_PAUSE(); }
  for(;;) {

    /* Housekeeping */
    if( 1 ) {
      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, fd_tickcount() );
      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }
    }

    /* Auto throttle */
    ulong parser_seq = parser_cnc_diag[ DEMO_PARSER_CNC_OUT_SEQ_IDX ];
    if( parser_seq < seq ) { parser_seq_unavailable_cnt += 1UL; continue; }
    ulong parser_seq_diff = parser_seq - seq;
    const ulong parser_seq_diff_max = 10UL;
    ulong seq_delta = 0UL;
    if( parser_seq_diff > parser_seq_diff_max ) { seq_delta = parser_seq_diff - parser_seq_diff_max; }
    seq += seq_delta;
    out_sig += seq_delta;

    fd_frag_meta_t const * mline = NULL;
    ulong                  seq_found = 0UL;
    long                   diff;

    ulong sig;
    ulong chunk;
    ulong sz;
    ulong ctl;
    ulong tsorig;
    ulong tspub;
    ulong async_rem = 2UL;
    FD_MCACHE_WAIT_REG( sig, chunk, sz, ctl, tsorig, tspub, mline, seq_found, diff, async_rem, mcache, depth, seq );
    FD_TEST( async_rem == 1UL );

    if( FD_UNLIKELY( diff ) ) FD_LOG_ERR(( "Overrun while polling" ));

    /* Process the received fragment */
    (void)ctl; (void)sz; (void)sig; (void)tsorig; (void)tspub;
    uchar const * p = (uchar const*)fd_chunk_to_laddr_const( wksp, chunk );
    parsed_txn_compressed_meta_t meta;
    meta.all = sig;
    uchar const *        msg = p + meta.value.msg_off;
    ulong             msg_sz = (ulong) meta.value.msg_sz;
    uchar const * signature  = p + meta.value.signature_off;
    uchar const * public_key = p + meta.value.public_key_off;

    do {
      fd_sha512_t sha[1];
      int verif = -1;
      if( test_version == DEMO_TEST_VERSION_SIGVERIFY ) {
        verif = fd_ed25519_verify(  msg,
                                    msg_sz,
                                    signature,
                                    public_key,
                                    sha );
      } else if( test_version == DEMO_TEST_VERSION_SHA512MODQ ) {
        verif = sha512_modq_lsB(  msg,
                                  msg_sz,
                                  signature,
                                  public_key,
                                  sha );
      } else {
        FD_TEST( 0 );
      }

      /* publish in output mcache */
      uint out_chunk    = (uint)(verif & 0x1);
      ulong out_sz      = 0UL;
      ulong out_ctl     = fd_frag_meta_ctl( v_x86_idx, 1 /*som*/, 1 /*eom*/, 0 /*err*/ );
      long out_now      = fd_tickcount();
      ulong out_tsorig  = fd_frag_meta_ts_comp( out_now );
      ulong out_tspub   = out_tsorig;
      fd_mcache_publish( out_mcache, out_depth, out_seq, out_sig, out_chunk, out_sz, out_ctl, out_tsorig, out_tspub );
      out_sig += 1UL;

      /* Windup for the next iteration */
      out_seq     = fd_seq_inc( out_seq, 1UL );
    } while( 0 );

    /* Check that we weren't overrun while processing */
    seq_found = fd_frag_meta_seq_query( mline );
    // seq_found = fd_frag_meta_seq_query( input_mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) {
      FD_LOG_ERR(( "Overrun while reading" ));
      FD_TEST( 0 );
    }

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );
    cnc_diag[ DEMO_V_X86_CNC_TXN_CNT_IDX ] += 1ULL;
    cnc_diag[ DEMO_V_X86_CNC_SIG_CNT_IDX ] = out_sig;
  }

  /* Debug only */
  // FD_TEST( !parser_seq_unavailable_cnt );

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}



// VVVVVVVV           VVVVVVVV      CCCCCCCCCCCCCHHHHHHHHH     HHHHHHHHHEEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCCKKKKKKKKK    KKKKKKK
// V::::::V           V::::::V   CCC::::::::::::CH:::::::H     H:::::::HE::::::::::::::::::::E    CCC::::::::::::CK:::::::K    K:::::K
// V::::::V           V::::::V CC:::::::::::::::CH:::::::H     H:::::::HE::::::::::::::::::::E  CC:::::::::::::::CK:::::::K    K:::::K
// V::::::V           V::::::VC:::::CCCCCCCC::::CHH::::::H     H::::::HHEE::::::EEEEEEEEE::::E C:::::CCCCCCCC::::CK:::::::K   K::::::K
//  V:::::V           V:::::VC:::::C       CCCCCC  H:::::H     H:::::H    E:::::E       EEEEEEC:::::C       CCCCCCKK::::::K  K:::::KKK
//   V:::::V         V:::::VC:::::C                H:::::H     H:::::H    E:::::E            C:::::C                K:::::K K:::::K   
//    V:::::V       V:::::V C:::::C                H::::::HHHHH::::::H    E::::::EEEEEEEEEE  C:::::C                K::::::K:::::K    
//     V:::::V     V:::::V  C:::::C                H:::::::::::::::::H    E:::::::::::::::E  C:::::C                K:::::::::::K     
//      V:::::V   V:::::V   C:::::C                H:::::::::::::::::H    E:::::::::::::::E  C:::::C                K:::::::::::K     
//       V:::::V V:::::V    C:::::C                H::::::HHHHH::::::H    E::::::EEEEEEEEEE  C:::::C                K::::::K:::::K    
//        V:::::V:::::V     C:::::C                H:::::H     H:::::H    E:::::E            C:::::C                K:::::K K:::::K   
//         V:::::::::V       C:::::C       CCCCCC  H:::::H     H:::::H    E:::::E       EEEEEEC:::::C       CCCCCCKK::::::K  K:::::KKK
//          V:::::::V         C:::::CCCCCCCC::::CHH::::::H     H::::::HHEE::::::EEEEEEEE:::::E C:::::CCCCCCCC::::CK:::::::K   K::::::K
//           V:::::V           CC:::::::::::::::CH:::::::H     H:::::::HE::::::::::::::::::::E  CC:::::::::::::::CK:::::::K    K:::::K
//            V:::V              CCC::::::::::::CH:::::::H     H:::::::HE::::::::::::::::::::E    CCC::::::::::::CK:::::::K    K:::::K
//             VVV                  CCCCCCCCCCCCCHHHHHHHHH     HHHHHHHHHEEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCCKKKKKKKKK    KKKKKKK

/* VCHECK tile ************************************************************/

static int
vcheck_tile_main( int     argc,
                  char ** argv ) {
  ulong           vcheck_idx = (ulong)argc;
  test_cfg_t * cfg    = (test_cfg_t *)argv;
  // fd_wksp_t *  wksp   = cfg->wksp;
  (void)vcheck_idx;

  FD_LOG_NOTICE(( "active: vcheck_tile_main" ));

  /* Hook up to consum cnc */
  fd_cnc_t * cnc = cfg->vcheck_cnc;

  /* Command and control */
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  cnc_diag[ DEMO_VCHECK_CNC_SIG__X86_CNT_IDX ] = 0UL;
  cnc_diag[ DEMO_VCHECK_CNC_SIG_FPGA_CNT_IDX ] = 0UL;
  cnc_diag[ DEMO_VCHECK_CNC_VALIDATE_CNT_IDX ] = 0UL;
  cnc_diag[ DEMO_VCHECK_CNC_SIG_PASS_CNT_IDX ] = 0UL;
  cnc_diag[ DEMO_VCHECK_CNC_SIG_FAIL_CNT_IDX ] = 0UL;

  /* Enabled producers */
  int v_x86_enabled = cfg->v_x86_enabled;
  int v__wd_enabled = cfg->v__wd_enabled;

  /* Hook up to v_x86 mcache */
  fd_frag_meta_t const * v_x86_mcache = ( !!v_x86_enabled )? cfg->v_x86_mcache                         : NULL;
  ulong                  v_x86_depth  = ( !!v_x86_enabled )? fd_mcache_depth( v_x86_mcache )           : 0UL;
  ulong const *          v_x86_sync   = ( !!v_x86_enabled )? fd_mcache_seq_laddr_const( v_x86_mcache ) : NULL;
  ulong                  v_x86_seq    = ( !!v_x86_enabled )? fd_mcache_seq_query( v_x86_sync )         : 0UL;

  /* Hook up wd mcache */
  fd_frag_meta_t * v__wd_mcache = ( !!v__wd_enabled )? cfg->v__wd_mcache                   : NULL;
  ulong            v__wd_depth  = ( !!v__wd_enabled )? fd_mcache_depth( v__wd_mcache )     : 0UL;
  ulong *          v__wd_sync   = ( !!v__wd_enabled )? fd_mcache_seq_laddr( v__wd_mcache ) : NULL;
  ulong            v__wd_seq    = ( !!v__wd_enabled )? fd_mcache_seq_query( v__wd_sync )   : 0UL;

  /* Hook up to the random number generator */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, cfg->vcheck_seed, 0UL ) );

  /* Verification */
  ulong exp_sig = 0UL;
  ulong sig_delta = 0UL;

  /* Wiredancer */
  wd_wksp_t wd;
  // int wd_split = cfg->wd_split;
  uint64_t wd_slots = cfg->wd_slots;
  FD_TEST( !wd_init_pci( &wd, wd_slots ) );
  wd_ed25519_verify_init_resp( &wd );

  /* debug */
  ulong cnt_sig_ok = 0UL;
  ulong cnt_sig_ng = 0UL;

  /* Main loop */
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Wait for frag seq while doing housekeeping in the background */
    
    fd_frag_meta_t const * v_x86_mline     = NULL;
    ulong                  v_x86_seq_found = 0UL;
    long                   v_x86_diff      = 0L;
    ulong                  v_x86_chunk     = 0UL;
    ulong                  v_x86_sig       = exp_sig; /* by default */

    ulong do_halt = 0ULL;

    /* Poll v_x86 */
    if( FD_LIKELY( !!v_x86_enabled ) ) {
      ulong sig;
      ulong chunk;
      ulong sz;
      ulong ctl;
      ulong tsorig;
      ulong tspub;
      ulong v_x86_async_rem = 0UL;
      do {
        v_x86_async_rem = 2UL;
        FD_MCACHE_WAIT_REG( sig, chunk, sz, ctl, tsorig, tspub, v_x86_mline, v_x86_seq_found, v_x86_diff, v_x86_async_rem, v_x86_mcache, v_x86_depth, v_x86_seq );
        (void)ctl; (void)sz; (void)tsorig; (void)tspub;

        if( !v_x86_async_rem ) {
          /* Send diagnostic info */
          fd_cnc_heartbeat( cnc, fd_tickcount() );
          /* Receive command-and-control signals */
          ulong s = fd_cnc_signal_query( cnc );
          if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
            if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
            do_halt = 1ULL;
            break;
          }
        } else {
          if( FD_UNLIKELY( v_x86_diff ) ) FD_LOG_ERR(( "Overrun while polling v_x86" ));
        }
      } while( (!do_halt) & (!v_x86_async_rem) );
      
      /* Extract the required values */
      sig_delta   = sig - exp_sig;
      exp_sig     = sig; /* override expected sig */
      v_x86_sig   = sig;
      v_x86_chunk = chunk;
      cnc_diag[ DEMO_VCHECK_CNC_SIG__X86_CNT_IDX ] += 1UL;
      /* halt if instructed to do so */
      if( FD_UNLIKELY( !!do_halt )) { break; }
    }

    /* Poll wiredancer */
    fd_frag_meta_t const * v__wd_mline     = NULL;
    ulong                  v__wd_seq_found = 0UL;
    long                   v__wd_diff      = 0L;
    ulong                  v__wd_chunk     = 0UL;
    ulong                  v__wd_sig       = exp_sig; /* by default */

    if( FD_LIKELY( !!v__wd_enabled ) ) {
      ulong sig;
      ulong chunk;
      ulong sz;
      ulong ctl;
      ulong tsorig;
      ulong tspub;
      ulong v__wd_async_rem = 0UL;
      /* Jump directly to where is x86 is currently at */
      v__wd_seq += sig_delta;
      do {
        v__wd_async_rem = 2UL;
        FD_MCACHE_WAIT_REG( sig, chunk, sz, ctl, tsorig, tspub, v__wd_mline, v__wd_seq_found, v__wd_diff, v__wd_async_rem, v__wd_mcache, v__wd_depth, v__wd_seq );
        (void)chunk; (void)sz; (void)tsorig; (void)tspub;
        
        if( !v__wd_async_rem ) {
          /* Send diagnostic info */
          fd_cnc_heartbeat( cnc, fd_tickcount() );
          /* Receive command-and-control signals */
          ulong s = fd_cnc_signal_query( cnc );
          if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
            if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
            do_halt = 1ULL;
            break;
          }
        }
        else {
          if( FD_UNLIKELY( v__wd_diff ) ) FD_LOG_ERR(( "Overrun while polling v__wd" ));
        }
      } while( (!do_halt) & (!v__wd_async_rem) );
      
      /* Extract the required values */
      v__wd_sig   = sig;
      v__wd_chunk = (ctl>>2)&0x1;
      /* This is essentially the latest sig that has been processed */
      cnc_diag[ DEMO_VCHECK_CNC_SIG_FPGA_CNT_IDX ] = exp_sig;
      /* halt if instructed to do so */
      if( FD_UNLIKELY( !!do_halt )) { break; }
    }


    /* Process x86 */
    if( FD_LIKELY( !!v_x86_enabled )) {
      /* Check that we weren't overrun while processing */
      v_x86_seq_found = fd_frag_meta_seq_query( v_x86_mline );
      if( FD_UNLIKELY( fd_seq_ne( v_x86_seq_found, v_x86_seq ) ) ) {
        FD_LOG_ERR(( "Overrun while processing v_x86" ));
        FD_TEST( 0 );
      }
      /* Wind up for the next iteration */
      v_x86_seq = fd_seq_inc( v_x86_seq, 1UL );
    }

    /* Process wiredancer */
    if( FD_LIKELY( !!v__wd_enabled )) {
      /* Check that we weren't overrun while processing */
      v__wd_seq_found = fd_frag_meta_seq_query( v__wd_mline );
      if( FD_UNLIKELY( fd_seq_ne( v__wd_seq_found, v__wd_seq ) ) ) {
        FD_LOG_ERR(( "Overrun while processing v__wd (exp_sig: %lu)", exp_sig ));
        ulong * p = (ulong*)v__wd_mline;
        FD_LOG_NOTICE(("mcache line %016lx_%016lx_%016lx_%016lx",*(p+0),*(p+1),*(p+2),*(p+3) ));
        FD_LOG_NOTICE(("v__wd_seq_found %016lx", v__wd_seq_found));
        FD_LOG_NOTICE(("v__wd_seq       %016lx", v__wd_seq));
        FD_TEST( 0 );
      }
      /* Wind up for the next iteration */
      v__wd_seq = fd_seq_inc( v__wd_seq, 1UL );
      /* Validate */
      // FD_TEST( v__wd_sig == exp_sig );
      cnc_diag[ DEMO_VCHECK_CNC_SIG_PASS_CNT_IDX ] += ((v__wd_chunk & 0x01U) == FD_ED25519_SUCCESS)? 1UL : 0;
      cnc_diag[ DEMO_VCHECK_CNC_SIG_FAIL_CNT_IDX ] += ((v__wd_chunk & 0x01U) != FD_ED25519_SUCCESS)? 1UL : 0;
    }

    /* Compare x86 and wiredancer (if both enabled) */
    if( FD_LIKELY( ( !!v_x86_enabled ) & ( !!v__wd_enabled ) ) ) {
      if( v_x86_chunk != v__wd_chunk ) { FD_LOG_NOTICE(( "(0x%016lx) verif x86 0x%lx vs 0x%lx wd verif (0x%016lx) - v__wd_seq 0x%016lx",
                                                          v_x86_sig, v_x86_chunk, v__wd_chunk, v__wd_sig, v__wd_seq )); }
      // FD_TEST( v_x86_sig   == v__wd_sig   );
      FD_TEST( v_x86_chunk == v__wd_chunk );
      cnc_diag[ DEMO_VCHECK_CNC_VALIDATE_CNT_IDX ] += 1UL;
      if( (v__wd_chunk & 0x01U) == FD_ED25519_SUCCESS ) {
        cnt_sig_ok +=1UL;
      } else {
        cnt_sig_ng +=1UL;
      }
    }

    /* Wind up for the next iteration */
    exp_sig += 1UL;
  }

  FD_TEST( !wd_free_pci( &wd ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  return 0;
}





// MMMMMMMM               MMMMMMMM               AAA               IIIIIIIIIINNNNNNNN        NNNNNNNN
// M:::::::M             M:::::::M              A:::A              I::::::::IN:::::::N       N::::::N
// M::::::::M           M::::::::M             A:::::A             I::::::::IN::::::::N      N::::::N
// M:::::::::M         M:::::::::M            A:::::::A            II::::::IIN:::::::::N     N::::::N
// M::::::::::M       M::::::::::M           A:::::::::A             I::::I  N::::::::::N    N::::::N
// M:::::::::::M     M:::::::::::M          A:::::A:::::A            I::::I  N:::::::::::N   N::::::N
// M:::::::M::::M   M::::M:::::::M         A:::::A A:::::A           I::::I  N:::::::N::::N  N::::::N
// M::::::M M::::M M::::M M::::::M        A:::::A   A:::::A          I::::I  N::::::N N::::N N::::::N
// M::::::M  M::::M::::M  M::::::M       A:::::A     A:::::A         I::::I  N::::::N  N::::N:::::::N
// M::::::M   M:::::::M   M::::::M      A:::::AAAAAAAAA:::::A        I::::I  N::::::N   N:::::::::::N
// M::::::M    M:::::M    M::::::M     A:::::::::::::::::::::A       I::::I  N::::::N    N::::::::::N
// M::::::M     MMMMM     M::::::M    A:::::AAAAAAAAAAAAA:::::A      I::::I  N::::::N     N:::::::::N
// M::::::M               M::::::M   A:::::A             A:::::A   II::::::IIN::::::N      N::::::::N
// M::::::M               M::::::M  A:::::A               A:::::A  I::::::::IN::::::N       N:::::::N
// M::::::M               M::::::M A:::::A                 A:::::A I::::::::IN::::::N        N::::::N
// MMMMMMMM               MMMMMMMMAAAAAAA                   AAAAAAAIIIIIIIIIINNNNNNNN         NNNNNNN


/* MAIN tile **********************************************************/

#include <stdio.h>
#include <signal.h>

ulong test_halt = 0UL;

static void
test_sigaction( int         sig,
                siginfo_t * info,
                void *      context ) {
  (void)info;
  (void)context;
  FD_LOG_NOTICE(( "received POSIX signal %i; sending halt to main", sig ));
  test_halt = 1UL;
}

static void
test_signal_trap( int sig ) {
  struct sigaction act[1];
  act->sa_sigaction = test_sigaction;
  if( FD_UNLIKELY( sigemptyset( &act->sa_mask ) ) ) FD_LOG_ERR(( "sigempty set failed" ));
  act->sa_flags = (int)(SA_SIGINFO | SA_RESETHAND);
  if( FD_UNLIKELY( sigaction( sig, act, NULL ) ) ) FD_LOG_ERR(( "unable to override signal %i", sig ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  
  uint rng_seq = 0U;
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seq++, 0UL ) );

  FD_TEST( fd_replay_tile_scratch_align()==FD_REPLAY_TILE_SCRATCH_ALIGN );
  FD_TEST( !fd_replay_tile_scratch_footprint( FD_REPLAY_TILE_OUT_MAX+1UL ) );
  for( ulong iter_rem=10000000UL; iter_rem; iter_rem-- ) {
    ulong out_cnt = fd_rng_ulong_roll( rng, FD_REPLAY_TILE_OUT_MAX+1UL );
    FD_TEST( fd_replay_tile_scratch_footprint( out_cnt )==FD_REPLAY_TILE_SCRATCH_FOOTPRINT( out_cnt ) );
  }

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",          NULL, "gigantic"                    );
  ulong        page_cnt         = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",         NULL, 1UL                           );
  ulong        numa_idx         = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",         NULL, fd_shmem_numa_idx( cpu_idx )  );
  char const * replay_pcap      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--replay-pcap",      NULL, NULL                          );
  ulong        replay_mtu       = fd_env_strip_cmdline_ulong( &argc, &argv, "--replay-mtu",       NULL, 1542UL                        );
  ulong        replay_orig      = fd_env_strip_cmdline_ulong( &argc, &argv, "--replay-orig",      NULL, 0UL                           );
  ulong        replay_depth     = fd_env_strip_cmdline_ulong( &argc, &argv, "--replay-depth",     NULL, 131072UL                      );
  ulong        replay_cr_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--replay-cr-max",    NULL, 0UL /* use default */         );
  long         replay_lazy      = fd_env_strip_cmdline_long ( &argc, &argv, "--replay-lazy",      NULL, 0L /* use default */          );
  ulong        parser_depth     = fd_env_strip_cmdline_ulong( &argc, &argv, "--parser-depth",     NULL, 131072UL                      );
  int          parser_lazy      = fd_env_strip_cmdline_int  ( &argc, &argv, "--parser-lazy",      NULL, 7                             );
  int          v_x86_enabled    = fd_env_strip_cmdline_int  ( &argc, &argv, "--v-x86-enabled",    NULL, 0                             );
  ulong        v_x86_depth      = fd_env_strip_cmdline_ulong( &argc, &argv, "--v-x86-depth",      NULL, 131072UL /* test req*/        );
  int          v_x86_lazy       = fd_env_strip_cmdline_int  ( &argc, &argv, "--v-x86-lazy",       NULL, 7                             );
  int          v__wd_enabled    = fd_env_strip_cmdline_int  ( &argc, &argv, "--v--wd-enabled",    NULL, 0                             );
  ulong        v__wd_depth      = fd_env_strip_cmdline_ulong( &argc, &argv, "--v--wd-depth",      NULL, 131072UL /* test req*/        );
  int          vcheck_lazy      = fd_env_strip_cmdline_int  ( &argc, &argv, "--vcheck-lazy",      NULL, 7                             );
  int          test_version     = fd_env_strip_cmdline_int  ( &argc, &argv, "--test-version",     NULL, DEMO_TEST_VERSION_SIGVERIFY   );
  long         duration         = fd_env_strip_cmdline_long ( &argc, &argv, "--duration",         NULL, (long)10e9                    );
  ulong        wd_slots         = fd_env_strip_cmdline_ulong( &argc, &argv, "--wd-slots",         NULL, 1UL                           );
  int          rand_txn_corrupt = fd_env_strip_cmdline_int  ( &argc, &argv, "--rand-txn-corrupt", NULL, 1UL                           );
  int          replay_enabled   = 1;
  int          parser_enabled   = 1;
  int          vcheck_enabled   = 1;

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz"  ));
  if( FD_UNLIKELY( !replay_pcap ) ) FD_LOG_ERR(( "--replay-pcap not specifed" ));

  /* Check minimum number of tiles */
  ulong req_tile_cnt = 1 /* main */ + (( !!replay_enabled )? 1UL : 0UL) +
                                      (( !!parser_enabled )? 1UL : 0UL) +
                                      (( !!v_x86_enabled )? 1UL : 0UL) +
                                      (( !!vcheck_enabled )? 1UL : 0UL);
  if( FD_UNLIKELY( fd_tile_cnt()<req_tile_cnt ) ) FD_LOG_ERR(( "this unit test requires (at least) %lu tiles", req_tile_cnt ));

  /* Counters and sequences */
  long  hb0  = fd_tickcount();
  ulong seq0 = fd_rng_ulong( rng );

  /* Config */
  test_cfg_t cfg[1];

  /* Check test_version */
  FD_TEST( test_version >= 0 );
  FD_TEST( test_version <= 1 );
  if( test_version == DEMO_TEST_VERSION_SIGVERIFY  ) { FD_LOG_NOTICE(( "TEST VERSION: full sigveriy" )); }
  if( test_version == DEMO_TEST_VERSION_SHA512MODQ ) { FD_LOG_NOTICE(( "TEST VERSION: only sha512_modq" )); }
  cfg->test_version = test_version;

  /* Workspace */
  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  cfg->wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( cfg->wksp );

  /* Configure replay fseq */
  ulong * replay_fseq[ DEMO_REPLAY_FSEQ_CNT_MAX ];
  for( int i=0; i<DEMO_REPLAY_FSEQ_CNT_MAX; i++) { 
    replay_fseq[ i ] = fd_fseq_join( fd_fseq_new( fd_wksp_alloc_laddr( cfg->wksp, fd_fseq_align(), fd_fseq_footprint(), 1UL ), seq0 ) ); 
    if( FD_UNLIKELY( !replay_fseq[ i ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  }
  ulong replay_fseq_cnt = DEMO_REPLAY_FSEQ_CNT_MAX;
  ulong parser_replay_fseq_idx = 0UL;

  /* default cnc_app_sz: 64UL minimum + 64UL extra margin (future use) */
  ulong default_cnc_app_sz = 128UL;

  /* Configure replay */
  if( 1 ) {
    FD_LOG_NOTICE(( "Creating replay cnc (app_sz 64, type 0, heartbeat0 %li)", hb0 ));
    cfg->replay_cnc = fd_cnc_join( fd_cnc_new( fd_wksp_alloc_laddr( cfg->wksp, fd_cnc_align(), fd_cnc_footprint( default_cnc_app_sz ), 1UL ),
                                               default_cnc_app_sz, 0UL, hb0 ) );
    FD_TEST( cfg->replay_cnc );

    cfg->replay_pcap = replay_pcap;
    cfg->replay_mtu  = replay_mtu;
    cfg->replay_orig = replay_orig;

    FD_LOG_NOTICE(( "Creating replay mcache (--replay-depth %lu, app_sz 0, seq0 %lu)", replay_depth, seq0 ));
    cfg->replay_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                             fd_mcache_align(), fd_mcache_footprint( replay_depth, 0UL ),
                                                                             1UL ),
                                                        replay_depth, 0UL, seq0 ) );
    FD_TEST( cfg->replay_mcache );
    FD_LOG_NOTICE(( "Creating replay dcache (--replay-mtu %lu, burst 1, compact 1, app_sz 0)", replay_mtu ));
    ulong replay_data_sz = fd_dcache_req_data_sz( replay_mtu, replay_depth, 1UL, 1 ); FD_TEST( replay_data_sz );
    cfg->replay_dcache   = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                               fd_dcache_align(), fd_dcache_footprint( replay_data_sz, 0UL ),
                                                                               1UL ),
                                                          replay_data_sz, 0UL ) );
    FD_TEST( cfg->replay_dcache );
    cfg->replay_cr_max    = replay_cr_max;
    cfg->replay_lazy      = replay_lazy;
    cfg->replay_seed      = rng_seq++;
    cfg->replay_fseq      = replay_fseq;
    FD_TEST( cfg->replay_fseq );
    cfg->replay_fseq_cnt  = replay_fseq_cnt;
  }

  /* Configure parser */
  cfg->parser_enabled = parser_enabled;
  if( !!parser_enabled ) {
    FD_LOG_NOTICE(( "Creating parser cnc (app_sz 64, type 1, heartbeat0 %li)", hb0 ));
    cfg->parser_cnc = fd_cnc_join( fd_cnc_new( fd_wksp_alloc_laddr( cfg->wksp, fd_cnc_align(), fd_cnc_footprint( default_cnc_app_sz ), 1UL ),
                                          default_cnc_app_sz, 1UL, hb0 ) );
    FD_TEST( cfg->parser_cnc );
    FD_LOG_NOTICE(( "Creating parser mcache (--replay-depth %lu, app_sz 0, seq0 %lu)", parser_depth, seq0 ));
    cfg->parser_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                        fd_mcache_align(), fd_mcache_footprint( parser_depth, 0UL ),
                                                                        1UL ),
                                                    parser_depth, 0UL, seq0 ) );
    FD_TEST( cfg->parser_mcache );
    cfg->parser_seed        = rng_seq++;
    cfg->parser_lazy        = parser_lazy;
    cfg->parser_enabled     = parser_enabled;
    cfg->parser_replay_fseq = replay_fseq[parser_replay_fseq_idx];
    cfg->parser_rand_txn_corrupt = rand_txn_corrupt;
  }

  /* Configure v_x86 */
  cfg->v_x86_enabled = v_x86_enabled;
  if( !!v_x86_enabled ) {
    FD_LOG_NOTICE(( "Creating v_x86 cnc (app_sz 64, type 1, heartbeat0 %li)", hb0 ));
    cfg->v_x86_cnc = fd_cnc_join( fd_cnc_new( fd_wksp_alloc_laddr( cfg->wksp, fd_cnc_align(), fd_cnc_footprint( default_cnc_app_sz ), 1UL ),
                                          default_cnc_app_sz, 1UL, hb0 ) );
    FD_TEST( cfg->v_x86_cnc );
    FD_LOG_NOTICE(( "Creating v_x86 mcache (--v--x86-depth %lu, app_sz 0, seq0 %lu)", v_x86_depth, seq0 ));
    cfg->v_x86_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                        fd_mcache_align(), fd_mcache_footprint( v_x86_depth, 0UL ),
                                                                        1UL ),
                                                    v_x86_depth, 0UL, seq0 ) );
    FD_TEST( cfg->v_x86_mcache );
    cfg->v_x86_seed        = rng_seq++;
    cfg->v_x86_lazy        = v_x86_lazy;
    cfg->v_x86_enabled     = v_x86_enabled;
  }

  /* v__wd */
  cfg->v__wd_enabled = v__wd_enabled;
  if (!!v__wd_enabled) {
    FD_LOG_NOTICE(( "Creating v__wd mcache (--v--x86-depth %lu, app_sz 0, seq0 %lu)", v__wd_depth, seq0 ));
    cfg->v__wd_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( cfg->wksp,
                                                                        fd_mcache_align(), fd_mcache_footprint( v__wd_depth, 0UL ),
                                                                        1UL ),
                                                    v__wd_depth, 0UL, seq0 ) );
    FD_TEST( cfg->v__wd_mcache );
  }
  cfg->wd_split       = 1UL; /* fixed */
  cfg->wd_slots       = wd_slots;

  /* consumer */
  if( 1 ) {
    FD_LOG_NOTICE(( "Creating consum cnc (app_sz 64, type 1, heartbeat0 %li)", hb0 ));
    cfg->vcheck_cnc = fd_cnc_join( fd_cnc_new( fd_wksp_alloc_laddr( cfg->wksp, fd_cnc_align(), fd_cnc_footprint( default_cnc_app_sz ), 1UL ),
                                               default_cnc_app_sz, 1UL, hb0 ) );
    FD_TEST( cfg->vcheck_cnc );
    cfg->vcheck_seed = rng_seq++;
    cfg->vcheck_lazy = vcheck_lazy;
  }

  FD_LOG_NOTICE(( "Booting" ));

  fd_tile_exec_t * v_x86_exec = ( !!v_x86_enabled )? fd_tile_exec_new( 3UL, v_x86_tile_main, 0, (char **)fd_type_pun( cfg ) ) : NULL;
  // fd_tile_exec_t * v__wd_exec = ( !!v__wd_enabled )? fd_tile_exec_new( 4UL, v__wd_tile_main, 0, (char **)fd_type_pun( cfg ) ) : NULL;
  fd_tile_exec_t * vcheck_exec = ( !!vcheck_enabled )? fd_tile_exec_new( 4UL, vcheck_tile_main, 0, (char **)fd_type_pun( cfg ) ) : NULL;
  fd_tile_exec_t * parser_exec = ( !!parser_enabled )? fd_tile_exec_new( 2UL, parser_tile_main, 0, (char **)fd_type_pun( cfg ) ) : NULL;
  fd_tile_exec_t * replay_exec = ( !!replay_enabled )? fd_tile_exec_new( 1UL, replay_tile_main, 0, (char **)fd_type_pun( cfg ) ) : NULL;

  if( !!v_x86_enabled  ) { FD_TEST( v_x86_exec ); }
  if( !!vcheck_enabled ) { FD_TEST( vcheck_exec ); }
  if( !!parser_enabled ) { FD_TEST( parser_exec ); }
  if( !!replay_enabled ) { FD_TEST( replay_exec ); }

  if( !!replay_enabled ) { FD_TEST( fd_cnc_wait( cfg->replay_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN ); }
  if( !!parser_enabled ) { FD_TEST( fd_cnc_wait( cfg->parser_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN ); }
  if( !!v_x86_enabled  ) { FD_TEST( fd_cnc_wait( cfg->v_x86_cnc,  FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN ); }
  if( !!vcheck_enabled ) { FD_TEST( fd_cnc_wait( cfg->vcheck_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN ); }

  /* FIXME improve notice */
  FD_LOG_NOTICE(( "Running (--duration %li ns, --replay-lazy %li ns, --replay-cr-max %lu, replay_seed %u, --parser-lazy %i, --v--x86-lazy %i, --vcheck-lazy %i)",
                  duration, replay_lazy, replay_cr_max, cfg->replay_seed, parser_lazy, v_x86_lazy, vcheck_lazy ));

  ulong const * replay_cnc_diag = ( !!replay_enabled )? (ulong const *)fd_cnc_app_laddr( cfg->replay_cnc ) : NULL;
  ulong const * parser_cnc_diag = ( !!parser_enabled )? (ulong const *)fd_cnc_app_laddr( cfg->parser_cnc ) : NULL;
  ulong const * vcheck_cnc_diag = ( !!vcheck_enabled )? (ulong const *)fd_cnc_app_laddr( cfg->vcheck_cnc ) : NULL;

  /* Wiredancer Monitor */
#ifdef FD_HAS_WIREDANCER 
  wd_mon_state_t wd_mon_state;
  wd_mon_state.recv_cnt[0]= 0UL;
  wd_mon_state.recv_cnt[1]= 0UL;
  wd_mon_state.send_cnt   = 0UL;
  wd_mon_state.cnt_replay = 0UL;
  wd_mon_state.cnt_parser = 0UL;
  wd_mon_state.cnt_x86    = 0UL;
  wd_mon_state.cnt__wd    = 0UL;
  wd_mon_state.rate_replay= 0UL;
  wd_mon_state.rate_parser= 0UL;
  wd_mon_state.rate_x86   = 0UL;
  wd_mon_state.rate__wd   = 0UL;
  wd_mon_state.sig_pass   = 0UL;
  wd_mon_state.sig_fail   = 0UL;
  wd_mon_state.cnt_checked= 0UL;
  wd_mon_state.running    = 1;
  FD_TEST( !wd_init_pci( &wd_mon_state.wd, wd_slots ) );
  pthread_t wd_mon_thread;
  FD_TEST( !pthread_create( &wd_mon_thread, NULL, mon_thread, &wd_mon_state)  );
#endif

  /* signal trap */
  test_signal_trap( SIGTERM );
  test_signal_trap( SIGINT  );

  /* main loop */
  long now  = fd_log_wallclock();
  long next = now;
  long done = (!!duration)? now + duration : (long)((~(ulong)0UL)>>1);
  for(;;) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( (now-done) >= 0L ) | ( !!test_halt )) {
      break;
    }
    if( FD_UNLIKELY( (now-next) >= 0L ) ) {
      FD_COMPILER_MFENCE();
      if( FD_UNLIKELY( replay_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_DONE ] ) ) {
        break;
      }
#ifdef FD_HAS_WIREDANCER
      /* compute the rates first */
      wd_mon_state.rate_replay = replay_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT  ] - wd_mon_state.cnt_replay; /* per second */
      wd_mon_state.rate_parser = parser_cnc_diag[ DEMO_PARSER_CNC_SIG_CNT_IDX      ] - wd_mon_state.cnt_parser; /* per second */
      wd_mon_state.rate_x86    = vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG__X86_CNT_IDX ] - wd_mon_state.cnt_x86; /* per second */
      wd_mon_state.rate__wd    = vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG_FPGA_CNT_IDX ] - wd_mon_state.cnt__wd; /* per second */
      /* update the counts second */
      wd_mon_state.cnt_replay  = replay_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_PUB_CNT  ];
      wd_mon_state.cnt_parser  = parser_cnc_diag[ DEMO_PARSER_CNC_SIG_CNT_IDX      ];
      wd_mon_state.cnt_x86     = vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG__X86_CNT_IDX ];
      wd_mon_state.cnt__wd     = vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG_FPGA_CNT_IDX ];
      wd_mon_state.cnt_checked = vcheck_cnc_diag[ DEMO_VCHECK_CNC_VALIDATE_CNT_IDX ];
      wd_mon_state.sig_pass    = vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG_PASS_CNT_IDX ];
      wd_mon_state.sig_fail    = vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG_FAIL_CNT_IDX ];
#endif
      /* time increment must be 1 second (for the above rates to be computed easily) */
      next += (long)1e9; /* 1 second */
    }
    FD_YIELD();
  }

  /* halt: monitor */
#ifdef FD_HAS_WIREDANCER
  wd_mon_state.running = 0;
  pthread_join( wd_mon_thread, NULL);
#endif

  /* keep pcap_done for logging purposes */
  if( FD_UNLIKELY( !replay_cnc_diag[ FD_REPLAY_CNC_DIAG_PCAP_DONE ] ) ) { FD_LOG_NOTICE(( "pcap replay finished before duration" )); }

  /* halt */
  FD_LOG_NOTICE(( "Halting" ));

  if( !!replay_enabled ) { FD_TEST( !fd_cnc_open( cfg->replay_cnc ) ); }
  if( !!parser_enabled ) { FD_TEST( !fd_cnc_open( cfg->parser_cnc ) ); }
  if( !!v_x86_enabled ) { FD_TEST( !fd_cnc_open( cfg->v_x86_cnc ) ); }
  if( !!vcheck_enabled ) { FD_TEST( !fd_cnc_open( cfg->vcheck_cnc ) ); }

  /* halt: replay */
  if( !!replay_enabled ) { fd_cnc_signal( cfg->replay_cnc, FD_CNC_SIGNAL_HALT ); }
  if( !!replay_enabled ) { FD_TEST( fd_cnc_wait( cfg->replay_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT ); }
  if( !!parser_enabled ) { FD_LOG_NOTICE(( "successfully stopped replay")); }

  /* halt: parser */
  if( !!parser_enabled ) { fd_cnc_signal( cfg->parser_cnc, FD_CNC_SIGNAL_HALT ); }
  if( !!parser_enabled ) { FD_TEST( fd_cnc_wait( cfg->parser_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT ); }
  if( !!parser_enabled ) { FD_LOG_NOTICE(( "successfully stopped parser")); }

  /* halt: vcheck (part 1) */
  if( !!vcheck_enabled ) { fd_cnc_signal( cfg->vcheck_cnc, FD_CNC_SIGNAL_HALT ); }

  /* halt: x86 */  
  if( !!v_x86_enabled ) { fd_cnc_signal( cfg->v_x86_cnc, FD_CNC_SIGNAL_HALT ); }
  if( !!v_x86_enabled ) { FD_TEST( fd_cnc_wait( cfg->v_x86_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT ); }
  if( !!v_x86_enabled ) { FD_LOG_NOTICE(( "successfully stopped x86"));  }

  /* halt: vcheck (part 2) */
  if( !!vcheck_enabled ) { FD_LOG_NOTICE(( "successfully checked wiredancer vs x86 on %lu sigverify(s) (sig_ok %lu vs sig_err %lu, --rand_txn_corrupt %s)",
    vcheck_cnc_diag[ DEMO_VCHECK_CNC_VALIDATE_CNT_IDX ], vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG_PASS_CNT_IDX ], vcheck_cnc_diag[ DEMO_VCHECK_CNC_SIG_FAIL_CNT_IDX ], rand_txn_corrupt?"enabled":"disabled" )); }

  if( !!vcheck_enabled ) { FD_TEST( fd_cnc_wait( cfg->vcheck_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT ); }
  if( !!vcheck_enabled ) { FD_LOG_NOTICE(( "successfully stopped vcheck")); }

  if( !!replay_enabled ) { fd_cnc_close( cfg->replay_cnc ); }
  if( !!parser_enabled ) { fd_cnc_close( cfg->parser_cnc ); }
  if( !!v_x86_enabled ) { fd_cnc_close( cfg->v_x86_cnc ); }
  if( !!vcheck_enabled ) { fd_cnc_close( cfg->vcheck_cnc ); }

  int ret;
  if( !!replay_enabled ) { FD_TEST( !fd_tile_exec_delete( replay_exec, &ret ) ); FD_TEST( !ret ); }
  if( !!parser_enabled ) { FD_TEST( !fd_tile_exec_delete( parser_exec, &ret ) ); FD_TEST( !ret ); }
  if( !!v_x86_enabled ) { FD_TEST( !fd_tile_exec_delete( v_x86_exec, &ret ) ); FD_TEST( !ret ); }
  if( !!vcheck_enabled ) { FD_TEST( !fd_tile_exec_delete( vcheck_exec, &ret ) ); FD_TEST( !ret ); }

  FD_LOG_NOTICE(( "Cleaning up" ));
  
  for( int i=0; i<DEMO_REPLAY_FSEQ_CNT_MAX; i++) {
  if( !!replay_enabled ) { fd_wksp_free_laddr( fd_fseq_delete  ( fd_fseq_leave  ( cfg->replay_fseq[i] ) ) ); } }
  if( !!replay_enabled ) { fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( cfg->replay_dcache  ) ) ); }
  if( !!replay_enabled ) { fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( cfg->replay_mcache  ) ) ); }
  if( !!replay_enabled ) { fd_wksp_free_laddr( fd_cnc_delete   ( fd_cnc_leave   ( cfg->replay_cnc     ) ) ); }
  if( !!parser_enabled ) { fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( cfg->parser_mcache  ) ) ); }
  if( !!parser_enabled ) { fd_wksp_free_laddr( fd_cnc_delete   ( fd_cnc_leave   ( cfg->parser_cnc     ) ) ); }
  if( !!v_x86_enabled ) { fd_wksp_free_laddr( fd_cnc_delete   ( fd_cnc_leave   ( cfg->v_x86_cnc     ) ) ); }
  if( !!v_x86_enabled ) { fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( cfg->v_x86_mcache  ) ) ); }
  if( !!v__wd_enabled ) { fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( cfg->v__wd_mcache  ) ) ); }
  if( !!vcheck_enabled ) { fd_wksp_free_laddr( fd_cnc_delete   ( fd_cnc_leave   ( cfg->vcheck_cnc     ) ) ); }
  
  fd_wksp_delete_anonymous( cfg->wksp );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#undef DEMO_SCRATCH_ALLOC

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED, FD_HAS_X86 and FD_HAS_WIREDANCER capabilities" ));
  fd_halt();
  return 0;
}

#endif
