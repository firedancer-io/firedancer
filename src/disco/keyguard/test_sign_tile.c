#include "fd_sign_tile.c"
#include "../../util/sandbox/fd_sandbox_private.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>

static fd_sign_ctx_t  ctx;
static fd_topo_tile_t tile;
static fd_keyswitch_t identity_switch;
static fd_keyswitch_t voter_switch;
static uchar          junk[ 64 ];
static uchar          staked[ 64 ];
static uchar          other[ 64 ];
static char           junk_path[ 256 ];
static char           staked_path[ 256 ];

static void
write_key( char const *  path,
           uchar const * key ) {
  FILE * file = fopen( path, "w" );
  FD_TEST( file );
  FD_TEST( fputc( '[', file )!=EOF );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fprintf( file, "%s%u", i ? "," : "", (uint)key[ i ] )>0 );
  FD_TEST( fputc( ']', file )!=EOF );
  FD_TEST( !fclose( file ) );
}

/* Load the keys like privileged_init and join the rest of the ctx that
   the tests use.  We always boot with the junk key. */

static void
boot_signer( int failover ) {
  fd_memset( &ctx, 0, sizeof(ctx) );
  tile.sign.failover_enabled = failover;
  load_keys( &ctx, &tile );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  ctx.keyswitch    = fd_keyswitch_join( fd_keyswitch_new( &identity_switch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( &voter_switch,    FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch && ctx.av_keyswitch );
  FD_TEST( fd_histf_join( fd_histf_new( ctx.sign_duration, 1UL, 1000000000UL ) ) );
  derive_fields( &ctx );
  FD_TEST( fd_memeq( ctx.public_key, junk+32UL, 32UL ) );
}

/* Sign a shred root and a bundle challenge through after_frag and
   check both verify with key and not with wrong_key.  Also check the
   BLS key was derived from key. */

static void
check_signatures( uchar const * key,
                  uchar const * wrong_key ) {
  static uchar output[ 128 ] __attribute__((aligned(128)));
  static fd_frag_meta_t mcache[ 8 ];
  fd_frag_meta_t * mcaches[]    = { mcache };
  ulong            seqs[]       = { 0UL };
  ulong            depths[]     = { 8UL };
  ulong            cr_avail     = 64UL;
  ulong            min_cr_avail = 64UL;
  int              reliable     = 0;
  fd_stem_context_t stem = {
    .mcaches=mcaches, .seqs=seqs, .depths=depths,
    .cr_avail=&cr_avail, .min_cr_avail=&min_cr_avail,
    .cr_decrement_amount=1UL, .out_reliable=&reliable
  };
  ctx.out[ 0 ] = (fd_sign_out_ctx_t){ .out_mem=(fd_wksp_t *)output };

  ctx.in[ 0 ].role = FD_KEYGUARD_ROLE_LEADER;
  fd_memset( ctx._data, 0x5A, 32UL );
  after_frag_sensitive( &ctx, 0UL, 0UL, FD_KEYGUARD_SIGN_TYPE_ED25519, 32UL, 0UL, 0UL, &stem );
  FD_TEST( mcache[ 0 ].sz==64UL );
  FD_TEST( fd_ed25519_verify( ctx._data, 32UL, output, key+32UL,       ctx.sha512 )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_verify( ctx._data, 32UL, output, wrong_key+32UL, ctx.sha512 )!=FD_ED25519_SUCCESS );

  ctx.in[ 0 ].role = FD_KEYGUARD_ROLE_BUNDLE;
  fd_memcpy( ctx._data, "challenge", 9UL );
  after_frag_sensitive( &ctx, 0UL, 1UL, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519, 9UL, 0UL, 0UL, &stem );
  char  message[ FD_BASE58_ENCODED_32_SZ+10UL ];
  ulong len;
  fd_base58_encode_32( key+32UL, &len, message );
  fd_memcpy( message+len, "-challenge", 10UL );
  FD_TEST( fd_ed25519_verify( (uchar const *)message, len+10UL, output, key+32UL,       ctx.sha512 )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_verify( (uchar const *)message, len+10UL, output, wrong_key+32UL, ctx.sha512 )!=FD_ED25519_SUCCESS );

  static char const derive_msg[] = "bls-key-derive-alpenglow";
  uchar        ikm[ 64 ];
  fd_bls_sec_t bls_key[ 1 ];
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL, key+32UL, key, ctx.sha512 );
  fd_bls_sec_derive( bls_key, ikm, sizeof(ikm) );
  FD_TEST( fd_memeq( ctx.bls_private_key, bls_key, sizeof(bls_key) ) );
}

/* Request the member certificate over pubkey through after_frag and
   return the signature in sig. */

static void
member_cert( uchar const * pubkey,
             uchar *       sig ) {
  static uchar output[ 128 ] __attribute__((aligned(128)));
  static fd_frag_meta_t mcache[ 8 ];
  fd_frag_meta_t * mcaches[]    = { mcache };
  ulong            seqs[]       = { 0UL };
  ulong            depths[]     = { 8UL };
  ulong            cr_avail     = 64UL;
  ulong            min_cr_avail = 64UL;
  int              reliable     = 0;
  fd_stem_context_t stem = {
    .mcaches=mcaches, .seqs=seqs, .depths=depths,
    .cr_avail=&cr_avail, .min_cr_avail=&min_cr_avail,
    .cr_decrement_amount=1UL, .out_reliable=&reliable
  };
  ctx.out[ 0 ] = (fd_sign_out_ctx_t){ .out_mem=(fd_wksp_t *)output };

  ctx.in[ 0 ].role = FD_KEYGUARD_ROLE_FAILOV;
  fd_memcpy( ctx._data, FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( ctx._data+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, pubkey, 32UL );
  after_frag_sensitive( &ctx, 0UL, 0UL, FD_KEYGUARD_SIGN_TYPE_ED25519, FD_KEYGUARD_MEMBER_CERT_MSG_SZ, 0UL, 0UL, &stem );
  FD_TEST( mcache[ 0 ].sz==64UL );
  fd_memcpy( sig, output, 64UL );
}

static void
select_identity( uchar const * public_key ) {
  ctx.keyswitch->param = FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY;
  fd_memset( ctx.keyswitch->bytes, 0, 64UL );
  fd_memcpy( ctx.keyswitch->bytes, public_key, 32UL );
  fd_keyswitch_state( ctx.keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !ctx.keyswitch->bytes[ i ] );
}

/* test_failover_selection: under failover and the sign tile seccomp
   filter we switch between the junk and staked keys by public key and
   sign with each, without the key files. */

static void
test_failover_selection( volatile int * progress ) {
  boot_signer( 1 );
  FD_TEST( !ctx.identity_key && ctx.failover_junk_key && ctx.failover_staked_key );
  /* Switching must not read the key files. */
  FD_TEST( !unlink( junk_path ) && !unlink( staked_path ) );

  struct sock_filter filter[ 128 ];
  ulong filter_cnt = populate_allowed_seccomp( NULL, NULL, 128UL, filter );
  FD_TEST( !prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );
  fd_sandbox_private_set_seccomp_filter( (ushort)filter_cnt, filter );
  check_signatures( junk, staked );
  for( ulong i=0UL; i<3UL; i++ ) {
    select_identity( staked+32UL );
    check_signatures( staked, junk );
    select_identity( junk+32UL );
    check_signatures( junk, staked );
  }
  *progress = 1;
  /* The filter is still on, so this read kills us. */
  uchar byte;
  (void)syscall( SYS_read, -1, &byte, 1UL );
  __builtin_trap();
}

/* test_keypair_switch: without failover a switch still installs the
   keypair passed in the keyswitch. */

static void
test_keypair_switch( void ) {
  boot_signer( 0 );
  FD_TEST( ctx.identity_key && !ctx.failover_junk_key && !ctx.failover_staked_key );
  check_signatures( junk, staked );
  for( ulong i=0UL; i<3UL; i++ ) {
    uchar const * key       = i & 1UL ? junk   : staked;
    uchar const * wrong_key = i & 1UL ? staked : junk;
    ctx.keyswitch->param = FD_KEYSWITCH_PARAM_IDENTITY_KEYPAIR;
    fd_memcpy( ctx.keyswitch->bytes, key, 64UL );
    fd_keyswitch_state( ctx.keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
    during_housekeeping_sensitive( &ctx );
    FD_TEST( fd_keyswitch_state_query( ctx.keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
    for( ulong j=0UL; j<32UL; j++ ) FD_TEST( !ctx.keyswitch->bytes[ j ] );
    check_signatures( key, wrong_key );
  }
}

/* test_staked_voter_add: under failover adding the staked key as an
   authorized voter fails, and another key can still be added. */

static void
test_staked_voter_add( void ) {
  boot_signer( 1 );
  ctx.av_keyswitch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  fd_memcpy( ctx.av_keyswitch->bytes, staked, 64UL );
  fd_keyswitch_state( ctx.av_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.av_keyswitch )==FD_KEYSWITCH_STATE_FAILED );
  FD_TEST( ctx.av_keyswitch->result==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( !ctx.authorized_voters_cnt );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !ctx.av_keyswitch->bytes[ i ] );
  check_signatures( junk, staked );

  fd_memcpy( ctx.av_keyswitch->bytes, other, 64UL );
  fd_keyswitch_state( ctx.av_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.av_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx.authorized_voters_cnt==1UL );
  FD_TEST( fd_memeq( ctx.authorized_voter_pubkeys[ 0 ], other+32UL, 32UL ) );
  ctx.av_keyswitch->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
  fd_keyswitch_state( ctx.av_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( !ctx.authorized_voters_cnt );
}

/* test_member_cert: the failov role gets the staked key's signature
   over our junk pubkey, whichever key is installed. */

static void
test_member_cert( void ) {
  boot_signer( 1 );
  uchar msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_memcpy( msg, FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( msg+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, junk+32UL, 32UL );

  uchar sig[ 64 ];
  member_cert( junk+32UL, sig );
  FD_TEST( fd_ed25519_verify( msg, sizeof(msg), sig, staked+32UL, ctx.sha512 )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_verify( msg, sizeof(msg), sig, junk+32UL,   ctx.sha512 )!=FD_ED25519_SUCCESS );
  check_signatures( junk, staked );

  select_identity( staked+32UL );
  uchar switched_sig[ 64 ];
  member_cert( junk+32UL, switched_sig );
  FD_TEST( fd_memeq( switched_sig, sig, 64UL ) );
  check_signatures( staked, junk );
}

/* Each case runs in a child.  FAILOVER_SELECTION dies on the seccomp
   filter, READONLY_* die on the write, KEYPAIR_SWITCH, STAKED_VOTER_ADD
   and MEMBER_CERT exit cleanly, and the rest exit with status 1. */

enum {
  FAILOVER_SELECTION, KEYPAIR_SWITCH, STAKED_VOTER_ADD, READONLY_JUNK, READONLY_STAKED,
  SAME_KEYS, BAD_STAKED, MISSING_STAKED, BAD_JUNK, STAKED_VOTER,
  FOREIGN_SELECTION, KEYPAIR_IN_FAILOVER, SELECTION_WITHOUT_FAILOVER,
  MEMBER_CERT, FOREIGN_CERT, CASE_CNT
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_log_level_core_set( 8 );

  char dir[] = "/tmp/fd-sign-failover-XXXXXX";
  FD_TEST( mkdtemp( dir ) );
  FD_TEST( fd_cstr_printf_check( junk_path,   sizeof(junk_path),   NULL, "%s/junk.json",   dir ) );
  FD_TEST( fd_cstr_printf_check( staked_path, sizeof(staked_path), NULL, "%s/staked.json", dir ) );
  fd_cstr_ncpy( tile.sign.identity_key_path,        junk_path,   sizeof(tile.sign.identity_key_path)        );
  fd_cstr_ncpy( tile.sign.failover_staked_key_path, staked_path, sizeof(tile.sign.failover_staked_key_path) );

  fd_sha512_t sha[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  fd_memset( junk,   1, 32UL );
  fd_memset( staked, 2, 32UL );
  fd_memset( other,  3, 32UL );
  fd_ed25519_public_from_private( junk+32UL,   junk,   sha );
  fd_ed25519_public_from_private( staked+32UL, staked, sha );
  fd_ed25519_public_from_private( other+32UL,  other,  sha );

  volatile int * progress = mmap( NULL, 4096UL, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( progress!=MAP_FAILED );

  for( int test=0; test<CASE_CNT; test++ ) {
    write_key( junk_path,   junk   );
    write_key( staked_path, staked );
    *progress = 0;
    pid_t pid = fork();
    FD_TEST( pid>=0 );
    if( !pid ) {
      FD_TEST( signal( SIGILL,  SIG_DFL )!=SIG_ERR );
      FD_TEST( signal( SIGSEGV, SIG_DFL )!=SIG_ERR );
      switch( test ) {
      case FAILOVER_SELECTION: test_failover_selection( progress ); break;
      case KEYPAIR_SWITCH:     test_keypair_switch();               break;
      case STAKED_VOTER_ADD:   test_staked_voter_add();             break;
      case READONLY_JUNK:
      case READONLY_STAKED: {
        boot_signer( 1 );
        *progress = 1;
        uchar const * key = test==READONLY_JUNK ? ctx.failover_junk_key : ctx.failover_staked_key;
        FD_VOLATILE( *(uchar *)key ) = 0;
        break;
      }
      case SAME_KEYS:      write_key( staked_path, junk ); boot_signer( 1 ); break;
      case BAD_STAKED:     staked[ 32 ] ^= 1; write_key( staked_path, staked ); boot_signer( 1 ); break;
      case MISSING_STAKED: FD_TEST( !unlink( staked_path ) ); boot_signer( 1 ); break;
      case BAD_JUNK:       junk[ 32 ] ^= 1; write_key( junk_path, junk ); boot_signer( 1 ); break;
      case STAKED_VOTER:
        tile.sign.authorized_voter_paths_cnt = 1UL;
        fd_cstr_ncpy( tile.sign.authorized_voter_paths[ 0 ], staked_path, PATH_MAX );
        boot_signer( 1 );
        break;
      case FOREIGN_SELECTION: boot_signer( 1 ); select_identity( other+32UL ); break;
      case KEYPAIR_IN_FAILOVER:
        boot_signer( 1 );
        ctx.keyswitch->param = FD_KEYSWITCH_PARAM_IDENTITY_KEYPAIR;
        fd_memcpy( ctx.keyswitch->bytes, staked, 64UL );
        fd_keyswitch_state( ctx.keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
        during_housekeeping_sensitive( &ctx );
        break;
      case SELECTION_WITHOUT_FAILOVER: boot_signer( 0 ); select_identity( staked+32UL ); break;
      case MEMBER_CERT: test_member_cert(); break;
      case FOREIGN_CERT: {
        boot_signer( 1 );
        uchar sig[ 64 ];
        member_cert( other+32UL, sig );
        break;
      }
      }
      _exit( 0 );
    }
    int status;
    FD_TEST( waitpid( pid, &status, 0 )==pid );
    if( test==FAILOVER_SELECTION ) {
      FD_TEST( *progress==1 && WIFSIGNALED( status ) && WTERMSIG( status )==SIGSYS );
    } else if( test==READONLY_JUNK || test==READONLY_STAKED ) {
      FD_TEST( *progress==1 && WIFSIGNALED( status ) && WTERMSIG( status )==SIGSEGV );
    } else if( test==KEYPAIR_SWITCH || test==STAKED_VOTER_ADD || test==MEMBER_CERT ) {
      FD_TEST( WIFEXITED( status ) && !WEXITSTATUS( status ) );
    } else {
      FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
    }
  }

  FD_TEST( !munmap( (void *)progress, 4096UL ) );
  FD_TEST( !unlink( junk_path ) && !unlink( staked_path ) && !rmdir( dir ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
