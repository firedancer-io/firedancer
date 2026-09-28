#include "fd_sign_tile.c"

#include <stdio.h>
#include <unistd.h>
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

static void
boot_signer( int failover ) {
  fd_memset( &ctx, 0, sizeof(ctx) );

  ctx.failover_junk_key   = other;
  ctx.failover_staked_key = other;
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

static void
select_identity( uchar const * public_key ) {
  ctx.keyswitch->param = FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY;
  fd_memset( ctx.keyswitch->bytes, 0xA5, 64UL );
  fd_memcpy( ctx.keyswitch->bytes, public_key, 32UL );
  fd_keyswitch_state( ctx.keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !ctx.keyswitch->bytes[ i ] );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_log_level_core_set( 8 );

  char dir[ PATH_MAX ];
  char const * tmp_dir = getenv( "TMPDIR" );
  FD_TEST( fd_cstr_printf_check( dir, sizeof(dir), NULL, "%s/fd-sign-failover-XXXXXX",
                                 tmp_dir && tmp_dir[0] ? tmp_dir : "/tmp" ) );
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

  write_key( junk_path, junk );
  write_key( staked_path, staked );
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    boot_signer( 1 );
    select_identity( staked+32UL );
    check_signatures( staked, junk );
    select_identity( junk+32UL );
    check_signatures( junk, staked );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid && WIFEXITED( status ) && !WEXITSTATUS( status ) );

  pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    boot_signer( 1 );
    ctx.av_keyswitch->param = FD_KEYSWITCH_PARAM_AV_ADD;
    fd_memcpy( ctx.av_keyswitch->bytes, staked, 64UL );
    fd_keyswitch_state( ctx.av_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
    during_housekeeping_sensitive( &ctx );
    FD_TEST( fd_keyswitch_state_query( ctx.av_keyswitch )==FD_KEYSWITCH_STATE_FAILED );
    FD_TEST( ctx.av_keyswitch->result==FD_ADMINCTL_RESULT_UNSUPPORTED && !ctx.authorized_voters_cnt );
    check_signatures( junk, staked );
    _exit( 0 );
  }
  FD_TEST( waitpid( pid, &status, 0 )==pid && WIFEXITED( status ) && !WEXITSTATUS( status ) );

  FD_TEST( !unlink( junk_path ) && !unlink( staked_path ) && !rmdir( dir ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
