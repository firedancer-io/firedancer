#include <stdlib.h>
#include "../../util/fd_util.h"
#include "fd_keyguard_authorize.c"
#include "fd_keyguard_match.c"

#if !defined(CBMC)
#error "Intended to only be used from CBMC"
#endif

void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {}


void
fd_log_private_2( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) __attribute__((noreturn)) {
  __CPROVER_assert( 0, "Error log used" );
}

long
fd_log_wallclock( void ) {
  long t;
  return t;
}

char const *
fd_log_private_0( char const * fmt, ... ) {
  (void)fmt;
  return "";
}

/* Formally shows how, given any input (within the size constraint),
  fd_keyguard_payload_match() will not match two payload types,
  with the exception of known ambiguity of [gossip,repair] and
  [shred,ping]. */
void
match( void ) {
  uchar data[ FD_KEYGUARD_SIGN_REQ_MTU ];
  ulong sz;

  __CPROVER_assume( sz >= 0 && sz <= FD_KEYGUARD_SIGN_REQ_MTU );

  int sign_type;
  ulong payload_mask = fd_keyguard_payload_match( data, sz, sign_type );

  int matches = fd_ulong_popcnt( payload_mask );

  /* Matches the special casing done in fd_keyguard_payload_authorize() */
  int is_gossip_repair =
    0==( payload_mask &
        (~( FD_KEYGUARD_PAYLOAD_GOSSIP |
            FD_KEYGUARD_PAYLOAD_REPAIR ) ) );
  int is_shred_ping =
    0==( payload_mask &
        (~( FD_KEYGUARD_PAYLOAD_SHRED |
            FD_KEYGUARD_PAYLOAD_PING  ) ) );

  if     ( is_gossip_repair ) __CPROVER_assert( matches <= 2, "gossip conflict");
  else if( is_shred_ping    ) __CPROVER_assert( matches <= 2, "shred conflict");
  else                        __CPROVER_assert( matches <= 1, "no conflicts" );
}

/* Shows how given any input of any size, fd_keyguard_payload_authorize() will
  have defined behaviour and return a sane result. */
void
authorize( void ) {
  ulong size;
  int sign_type;
  int role;
  uchar * data = malloc( size );
  __CPROVER_assume( data != NULL );

  fd_keyguard_authority_t authority;
  int res = fd_keyguard_payload_authorize( &authority, data, size, role, sign_type );
  __CPROVER_assert( res==0 || res==1, "authorize proof" );
}

/* Prove that any transaction that is allowed as a bundle crank only
   invokes the expected programs. */
void
bundle_txn( void ) {
  ulong size;
  uchar * payload = malloc( size );
  __CPROVER_assume( payload != NULL );
  uchar sig_cnt;
  ulong message_offset = 1 + 64*sig_cnt;
  __CPROVER_assume( size > message_offset );
  __CPROVER_assume( payload[0] == sig_cnt );

  int sign_type;
  fd_keyguard_authority_t authority;
  __CPROVER_assume( fd_keyguard_authorize_bundle_crank_txn( &authority, payload + message_offset, size - message_offset, sign_type ) );

  void * _txn = malloc( FD_TXN_MAX_SZ );
  __CPROVER_assume( _txn != NULL );
  __CPROVER_assume( sizeof(fd_txn_t)<=fd_txn_parse( payload, size, _txn, NULL ) );

  fd_txn_t const * txn = (fd_txn_t const *)_txn;
  __CPROVER_assert( txn->instr_cnt==4 || txn->instr_cnt==5, "instr_cnt" );
  fd_acct_addr_t const * addr = fd_txn_get_acct_addrs( txn, payload );

  #define MEMO_PROGRAM_ID 0x05U,0x4aU,0x53U,0x5aU,0x99U,0x29U,0x21U,0x06U,0x4dU,0x24U,0xe8U,0x71U,0x60U,0xdaU,0x38U,0x7cU, \
                          0x7cU,0x35U,0xb5U,0xddU,0xbcU,0x92U,0xbbU,0x81U,0xe4U,0x1fU,0xa8U,0x40U,0x41U,0x05U,0x44U,0x8dU
  #define COMPUTE_BUDGET_PROG_ID             0x03U,0x06U,0x46U,0x6fU,0xe5U,0x21U,0x17U,0x32U,0xffU,0xecU,0xadU,0xbaU,0x72U,0xc3U,0x9bU,0xe7U, \
                                             0xbcU,0x8cU,0xe5U,0xbbU,0xc5U,0xf7U,0x12U,0x6bU,0x2cU,0x43U,0x9bU,0x3aU,0x40U,0x00U,0x00U,0x00U
  static const uchar compute_budget_program[] = { COMPUTE_BUDGET_PROG_ID };
  static const uchar memo_program[]           = { MEMO_PROGRAM_ID        };


  __CPROVER_assert( fd_memeq( addr+16, compute_budget_program,        32UL ), "addr 16");
  __CPROVER_assert( fd_memeq( addr+17, authority.tip_payment_program, 32UL ), "addr 17");
  __CPROVER_assert( fd_memeq( addr+18, memo_program,                  32UL ), "addr 18");
  if( txn->instr_cnt==4 ) {
    __CPROVER_assert( txn->instr[0].program_id==16, "ix 0" );
    __CPROVER_assert( txn->instr[1].program_id==17, "ix 1" );
    __CPROVER_assert( txn->instr[2].program_id==17, "ix 2" );
    __CPROVER_assert( txn->instr[3].program_id==18, "ix 3" );
  } else {
    __CPROVER_assert( txn->instr[0].program_id==16, "ix 0" );
    __CPROVER_assert( txn->instr[1].program_id==20, "ix 1" );
    __CPROVER_assert( txn->instr[2].program_id==17, "ix 2" );
    __CPROVER_assert( txn->instr[3].program_id==17, "ix 3" );
    __CPROVER_assert( txn->instr[4].program_id==18, "ix 4" );
    __CPROVER_assert( fd_memeq( addr+20, authority.tip_distribution_program, 32UL ), "addr 20" );
  }
}

void
cbmc_main( void ) {
  match();
  authorize();
  /* bundle_txn calls fd_txn_parse, which is pretty tough for CBMC.  It
     finishes in about a minute with

     cbmc src/disco/keyguard/fd_keyguard_proofs.c src/ballet/txn/fd_txn_parse.c --c17 -DCBMC --function bundle_txn \
     --unwinding-assertions --unwindset fd_txn_parse_core.32:6 --unwindset fd_txn_parse_core.27:16 --unwindset fd_txn_parse_core.47:1

     but without these unwind hints, it doesn't finish in a reasonable
     amount of time, so it is excluded from the normal proof run. */
  /* bundle_txn(); */
}
