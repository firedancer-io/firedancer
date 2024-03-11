#include "fddev.h"
#include "../../util/net/fd_pcap.h"
#include <stdio.h>

void
dump_cmd_args( int      * argc,
               char * * * argv,
               args_t   * args ) {
  char const * out_file = fd_env_strip_cmdline_cstr( argc, argv, "--out-file", NULL, "dump.pcap" );
  char const * link     = fd_env_strip_cmdline_cstr( argc, argv, "--link",     NULL, ""          );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->dump.pcap_path ), out_file, sizeof(args->dump.pcap_path)-1UL ) );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->dump.link_name ), link,     sizeof(args->dump.link_name)-1UL ) );
}

static void
dump_link( void           * out_file,
           fd_topo_link_t * link,
           void           * mem ) {
  fd_frag_meta_t const * mcache = link->mcache;
  ulong seq0 = fd_mcache_seq0( mcache );
  ulong seq_init = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcache ) );
  ulong depth = fd_mcache_depth( mcache );

  uint link_hash = (uint)((fd_hash( 17UL, link->name, strlen( link->name ) ) << 8) | link->kind_id);
  FD_LOG_NOTICE(( "Dumping %s %lu. Link hash: 0x%x", link->name, link->kind_id, link_hash ));
  /* We know at this point [seq0, seq_init) were published, but they may
     be long overwritten, and there may be more published than that. */

  for( ulong seq=fd_seq_dec( seq_init, 1UL ); fd_seq_ge( seq, seq0 ); seq=fd_seq_dec( seq, 1UL ) ) {
    /* It's not necessary for this to be atomic, since this is a
       post-mortem tool. */
    fd_frag_meta_t const * line = mcache+fd_mcache_line_idx( seq, depth );
    ulong read_seq = fd_frag_meta_seq_query( line );
    if( FD_UNLIKELY( read_seq!=seq ) ) break;

    ulong chunk = line->chunk;
    ulong sz    = line->sz;

    void const * buffer = fd_chunk_to_laddr_const( mem, chunk );

    fd_pcap_fwrite_pkt( (long)seq, line, sizeof(fd_frag_meta_t), buffer, sz, link_hash, out_file );
  }

  /* Now check everything after seq_init.  This could potentially loop
     forever if the producer is still going, so we cap it at one depth. */
  for( ulong off=0UL; off<depth; off++ ) {
    ulong seq = fd_seq_inc( seq_init, off );

    fd_frag_meta_t const * line = mcache+fd_mcache_line_idx( seq, depth );
    ulong read_seq = fd_frag_meta_seq_query( line );
    if( FD_UNLIKELY( read_seq!=seq ) ) break;

    ulong chunk = line->chunk;
    ulong sz    = line->sz;

    void const * buffer = fd_chunk_to_laddr_const( mem, chunk );

    fd_pcap_fwrite_pkt( (long)seq, line, sizeof(fd_frag_meta_t), buffer, sz, link_hash, out_file );
  }
}

void
dump_cmd_fn( args_t *         args,
             config_t * const config ) {

  FILE * out = fopen( args->dump.pcap_path, "w" );
  FD_TEST( fd_pcap_fwrite_hdr( out, FD_PCAP_LINK_LAYER_USER0 ) );

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( &config->topo );

  for( ulong i=0UL; i<config->topo.link_cnt; i++ ) {
    if( !strcmp( args->dump.link_name, config->topo.links[ i ].name ) || !strcmp( args->dump.link_name, "" ) ) {

      fd_topo_link_t * link = &(config->topo.links[ i ]);
      if( (link->mcache==NULL) | (link->dcache==NULL) ) {
        FD_LOG_NOTICE(( "Skipping %s %lu", link->name, link->kind_id ));
        continue;
      }
      void * mem = config->topo.workspaces[ config->topo.objs[ link->dcache_obj_id ].wksp_id ].wksp;

      dump_link( out, link, mem );
    }
  }

  fclose( out );
  fd_topo_leave_workspaces( &config->topo );
}
