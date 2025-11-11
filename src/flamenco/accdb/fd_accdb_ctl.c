/* fd_accdb_ctl.c is a command-line debugging tool for interacting with
   a Firedancer account database. */

#include "../../vinyl/fd_vinyl.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/cstr/fd_cstr.h"
#include "../../util/pod/fd_pod.h"
#include <ctype.h>
#include <stddef.h> /* offsetof */
#include <stdio.h>

/* req_info contains various request metadata R/W mapped into the vinyl
   tile. */

struct req_info {
  fd_vinyl_key_t  key[1];
  ulong           val_gaddr[1];
  schar           err[1];
  fd_vinyl_comp_t comp[1];
};

typedef struct req_info req_info_t;

/* The client class contains local handles to client-related vinyl
   objects. */

struct client {
  fd_vinyl_rq_t * rq;
  fd_vinyl_cq_t * cq;
  ulong           req_id;
  ulong           link_id;

  req_info_t * req_info;
  ulong        req_info_gaddr;
  fd_wksp_t *  val_wksp;
};

typedef struct client client_t;

static char const bin2hex[ 16 ] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

static void
hexdump( uchar const * data,
         uint          sz ) {
  ulong sz_align = fd_ulong_align_dn( sz, 16UL );
  uint i;
  for( i=0U; i<sz_align; i+=16U ) {
    char line[ 80 ];
    char * p = fd_cstr_init( line );
    p = fd_cstr_append_uint_as_hex( p, '0', i, 7UL );
    p = fd_cstr_append_text( p, ":  ", 3UL );
    for( ulong j=0UL; j<16UL; j++ ) {
      p = fd_cstr_append_char( p, bin2hex[ data[ i+j ]>>4 ] );
      p = fd_cstr_append_char( p, bin2hex[ data[ i+j ]&15 ] );
      p = fd_cstr_append_char( p, ' ' );
    }
    p = fd_cstr_append_char( p, ' ' );
    for( ulong j=0UL; j<16UL; j++ ) {
      int c = data[ i+j ];
      p = fd_cstr_append_char( p, fd_char_if( fd_isalnum( c ) | fd_ispunct( c ) | (c==' '), (char)c, '.' ) );
    }
    p = fd_cstr_append_char( p, '\n' );
    ulong len = (ulong)( p-line );
    fd_cstr_fini( p );
    fwrite( line, 1UL, len, stdout );
  }
  if( sz ) {
    char line[ 80 ];
    char * p = fd_cstr_init( line );
    p = fd_cstr_append_uint_as_hex( p, '0', i, 7UL );
    p = fd_cstr_append_text( p, ":  ", 3UL );
    for( ; i<sz; i++ ) {
      p = fd_cstr_append_char( p, bin2hex[ data[ i ]>>4 ] );
      p = fd_cstr_append_char( p, bin2hex[ data[ i ]&15 ] );
      p = fd_cstr_append_char( p, ' ' );
    }
    p = fd_cstr_append_char( p, '\n' );
    ulong len = (ulong)( p-line );
    fd_cstr_fini( p );
    fwrite( line, 1UL, len, stdout );
  }
  fflush( stdout );
}

static void
client_query( client_t * client,
              char **    arg,
              ulong      arg_cnt ) {
  req_info_t * req_info = client->req_info;
  if( FD_UNLIKELY( arg_cnt!=1UL ) ) {
    puts( "ERR(query): invalid query command, usage is \"query <account address>\"" );
    return;
  }
  char const * acc_addr_b58 = arg[0];
  fd_vinyl_key_t * acc_key = req_info->key;
  if( FD_UNLIKELY( !fd_base58_decode_32( acc_addr_b58, acc_key->uc ) ) ) {
    puts( "ERR(query): invalid account address" );
    return;
  }

  /* Send an acquire request */

  req_info->comp->seq = 0UL;
  fd_vinyl_rq_send(
      client->rq,
      client->req_id++,
      client->link_id,
      FD_VINYL_REQ_TYPE_ACQUIRE, /* type */
      0UL, /* flags */
      1UL,
      FD_VINYL_VAL_MAX, /* val_max */
      /* key_gaddr       */ client->req_info_gaddr + offsetof( req_info_t, key       ),
      /* val_gaddr_gaddr */ client->req_info_gaddr + offsetof( req_info_t, val_gaddr ),
      /* err_gaddr       */ client->req_info_gaddr + offsetof( req_info_t, err       ),
      /* comp_gaddr      */ client->req_info_gaddr + offsetof( req_info_t, comp      )
  );

  /* Poll direct completion for acquire (not via CQ) */

  fd_vinyl_comp_t * comp = req_info->comp;
  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  int acquire_err = req_info->err[0];
  if( acquire_err==FD_VINYL_SUCCESS ) {
    fd_account_meta_t const * val  = fd_wksp_laddr_fast( client->val_wksp, req_info->val_gaddr[0] );
    void const *              data = (void const *)( val+1 );

    FD_BASE58_ENCODE_32_BYTES( val->owner, owner_b58 );
    printf(
        "\n"
        "Public Key: %s\n"
        "Balance: %lu.%lu SOL\n"
        "Owner: %s\n"
        "Executable: %s\n"
        "Length: %u (0x%x) bytes\n",
        acc_addr_b58,
        val->lamports / 1000000000UL,
        val->lamports % 1000000000UL,
        owner_b58,
        val->executable ? "true" : "false",
        val->dlen,
        val->dlen
    );
    hexdump( data, val->dlen );

    /* Send a release request */

    req_info->comp->seq = 0UL;
    fd_vinyl_rq_send(
        client->rq,
        client->req_id++,
        client->link_id,
        FD_VINYL_REQ_TYPE_RELEASE, /* type */
        0UL, /* flags */
        1UL,
        FD_VINYL_VAL_MAX, /* val_max */
        0UL,
        /* val_gaddr_gaddr */ client->req_info_gaddr + offsetof( req_info_t, val_gaddr ),
        /* err_gaddr       */ client->req_info_gaddr + offsetof( req_info_t, err       ),
        /* comp_gaddr      */ client->req_info_gaddr + offsetof( req_info_t, comp      )
    );

    /* Poll direct completion for release (not via CQ) */

    while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
    FD_TEST( req_info->err[0]==FD_VINYL_SUCCESS );

    puts( "" );
  } else if( acquire_err==FD_VINYL_ERR_KEY ) {
    printf(
        "\n"
        "Public Key: %s\n"
        "Account does not exist\n"
        "\n",
        acc_addr_b58
    );
  } else {
    FD_LOG_ERR(( "Vinyl acquire request failed (err %i-%s)", acquire_err, fd_vinyl_strerror( acquire_err ) ));
  }
}

static int
client_cmd( client_t * client,
            char **    tok,
            ulong      tok_cnt ) {
  if( FD_UNLIKELY( !tok_cnt ) ) return 1;
  char const * cmd = tok[0];
  if( !strcmp( cmd, "query" ) ) {
    client_query( client, tok+1, tok_cnt-1 );
  } else if( !strcmp( cmd, "quit" ) || !strcmp( cmd, "exit" ) ) {
    return 0;
  } else {
    printf( "ERR: unknown command `%s`\n", cmd );
  }
  return 1;
}

static void
repl( client_t * client ) {
  char   line[ 4096 ] = {0};
# define TOK_MAX 16
  char * tokens[ 16 ] = {0};
  for(;;) {
    fputs( "accdb> ", stdout );
    fflush( stdout );

    /* Read command */
    if( fgets( line, sizeof(line), stdin )==NULL ) {
      putc( '\n', stdout );
      break;
    }
    line[ strcspn( line, "\n" ) ] = '\0';
    line[ sizeof(line)-1        ] = '\0';

    /* Interpret command */
    ulong tok_cnt = fd_cstr_tokenize( tokens, TOK_MAX, line, ' ' );
    if( !client_cmd( client, tokens, tok_cnt ) ) break;
  }
# undef TOK_MAX
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * cfg_gaddr = fd_env_strip_cmdline_cstr( &argc, &argv, "--cfg",  NULL, NULL );
  char const * wksp_name = fd_env_strip_cmdline_cstr( &argc, &argv, "--wksp", NULL, NULL );
  if( FD_UNLIKELY( !cfg_gaddr ) ) FD_LOG_ERR(( "Missing required argument --cfg" ));
  if( FD_UNLIKELY( !wksp_name ) ) FD_LOG_ERR(( "Missing required argument --wksp" ));

  /* Join server shared memory structures */

  uchar * pod = fd_pod_join( fd_wksp_map( cfg_gaddr ) );
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "Invalid --cfg pod" ));

  void * _cnc  = fd_wksp_pod_map( pod, "cnc"  );
  void * _meta = fd_wksp_pod_map( pod, "meta" );
  void * _ele  = fd_wksp_pod_map( pod, "ele"  );
  void * _obj  = fd_wksp_pod_map( pod, "obj"  );

  fd_cnc_t * cnc = fd_cnc_join( _cnc ); FD_TEST( cnc );
  fd_vinyl_meta_t meta[1];
  FD_TEST( fd_vinyl_meta_join( meta, _meta, _ele ) );

  ulong vinyl_status = fd_cnc_signal_query( cnc );
  if( FD_UNLIKELY( vinyl_status!=FD_CNC_SIGNAL_RUN ) ) {
    char status_cstr[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
    FD_LOG_ERR(( "Vinyl tile not running (status %lu-%s)", vinyl_status, fd_cnc_signal_cstr( vinyl_status, status_cstr ) ));
  }

  /* Allocate client structures */

  fd_wksp_t * wksp = fd_wksp_attach( wksp_name );
  FD_TEST( wksp );

  ulong const rq_max = 32UL;
  ulong const cq_max = 32UL;
  void * _rq = fd_wksp_alloc_laddr( wksp, fd_vinyl_rq_align(), fd_vinyl_rq_footprint( rq_max ), 1UL );
  void * _cq = fd_wksp_alloc_laddr( wksp, fd_vinyl_cq_align(), fd_vinyl_cq_footprint( cq_max ), 1UL );
  fd_vinyl_rq_t * rq = fd_vinyl_rq_join( fd_vinyl_rq_new( _rq, rq_max ) );
  fd_vinyl_cq_t * cq = fd_vinyl_cq_join( fd_vinyl_cq_new( _cq, cq_max ) );
  if( FD_UNLIKELY( !rq || !cq ) ) {
    FD_LOG_WARNING(( "Failed to allocate request/completion queues" ));
    goto dealloc2;
  }

  ulong req_info_gaddr = fd_wksp_alloc( wksp, alignof(req_info_t), sizeof(req_info_t), 1UL );
  if( FD_UNLIKELY( !req_info_gaddr ) ) {
    FD_LOG_WARNING(( "Failed to pre-allocate request metadata" ));
    goto dealloc1;
  }
  req_info_t * req_info = fd_wksp_laddr_fast( wksp, req_info_gaddr );

  /* Run client */

  ulong const link_id   = 0UL;
  ulong const burst_max = 1UL;
  ulong const quota_max = 2UL;
  int join_err = fd_vinyl_client_join( cnc, rq, cq, wksp, link_id, burst_max, quota_max );
  if( FD_UNLIKELY( join_err ) ) FD_LOG_ERR(( "Failed to join vinyl client to server (err %i-%s)", join_err, fd_vinyl_strerror( join_err ) ));

  FD_LOG_NOTICE(( "Attached client" ));

  client_t client = {
    .rq      = rq,
    .cq      = cq,
    .req_id  = 0UL,
    .link_id = link_id,

    .req_info       = req_info,
    .req_info_gaddr = req_info_gaddr,
    .val_wksp       = fd_wksp_containing( _obj ),
  };
  repl( &client );

  FD_LOG_NOTICE(( "Detaching client" ));

  int leave_err = fd_vinyl_client_leave( cnc, link_id );
  if( FD_UNLIKELY( leave_err ) ) FD_LOG_ERR(( "Failed to leave vinyl client from server (err %i-%s)", leave_err, fd_vinyl_strerror( leave_err ) ));

dealloc1:
  fd_wksp_free( wksp, req_info_gaddr );

dealloc2:
  fd_wksp_free_laddr( fd_vinyl_rq_delete( fd_vinyl_rq_leave( rq ) ) );
  fd_wksp_free_laddr( fd_vinyl_cq_delete( fd_vinyl_cq_leave( cq ) ) );

  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_vinyl_meta_leave( meta );
  fd_wksp_unmap( _meta );
  fd_wksp_unmap( _ele );
  fd_wksp_unmap( _obj );
  fd_wksp_detach( wksp );

  fd_halt();
  return 0;
}
