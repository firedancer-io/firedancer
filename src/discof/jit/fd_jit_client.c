#include "fd_jit_client.h"
#include "../../flamenco/vm/transpile/fd_jit_proto.h"
#include "../../flamenco/vm/transpile/fd_jit_arena.h"

#include <errno.h>
#include <sys/mman.h>

void
fd_jit_client_privileged_init( fd_topo_t const * topo,
                               ulong             jit_arena_obj_id ) {
  if( jit_arena_obj_id==ULONG_MAX ) return;
  void * laddr = fd_topo_obj_laddr( topo, jit_arena_obj_id );
  fd_shmem_join_info_t info[1];
  if( FD_UNLIKELY( fd_shmem_join_query_by_addr( laddr, 1UL, info ) ) ) FD_LOG_ERR(( "jit arena is not in a joined workspace" ));
  /* mprotect on a hugetlbfs mapping needs huge page bounds, so flip the
     whole workspace.  A read-write join (single process mode, where the
     jitmap tile shares this mapping) stays writable. */
  int prot = PROT_READ|PROT_EXEC|( info->mode==FD_SHMEM_JOIN_MODE_READ_WRITE ? PROT_WRITE : 0 );
  if( FD_UNLIKELY( mprotect( info->shmem, info->page_sz*info->page_cnt, prot ) ) )
    FD_LOG_ERR(( "mprotect(jit arena,%s) failed (%i-%s)", prot&PROT_WRITE ? "rwx" : "r-x", errno, fd_io_strerror( errno ) ));
}

/* jit_req runs on the exec tile when a program with no binding is
   about to execute.  It copies the record header and value slot into
   one exec_jit frag and marks the record pending so it is sent once.
   The jit tile is a plain unreliable consumer, but we never overrun
   it: if its fseq shows the link full the request is refused and the
   record stays unmarked, so the next execution asks again.  Spill
   records have no stable index and are skipped. */

static void
jit_req( void *                _client,
         fd_progcache_rec_t *  rec,
         fd_features_t const * features ) {
  fd_jit_client_t * client = _client;
  if( FD_UNLIKELY( !rec->data_gaddr || rec<client->rec0 || (ulong)( rec-client->rec0 )>=client->rec_max ) ) return;

  ulong val_sz = fd_ulong_min( (ulong)rec->rodata_off + fd_ulong_max( (ulong)rec->rodata_sz, (ulong)rec->text_off+(ulong)rec->text_cnt*8UL ), (ulong)rec->data_max );
  ulong sz     = sizeof(fd_jit_req_t) + val_sz;
  if( FD_UNLIKELY( sz>FD_JIT_REQ_MTU ) ) {
    FD_VOLATILE( rec->transpiled_idx ) = FD_TRANSPILE_BIND_HOLD; /* never fits; stop asking */
    return;
  }
  if( FD_UNLIKELY( fd_seq_diff( client->seq, fd_fseq_query( client->fseq ) )>=(long)client->depth ) ) {
    client->refused++;
    return;
  }

  fd_jit_req_t * req = fd_chunk_to_laddr( client->mem, client->chunk );
  *req = (fd_jit_req_t) {
    .key           = rec->pair,
    .feature_slot  = rec->feature_slot,
    .deploy_slot   = rec->deploy_slot,
    .rec_idx       = (uint)( rec-client->rec0 ),
    .data_max      = rec->data_max,
    .entry_pc      = rec->entry_pc,
    .text_cnt      = rec->text_cnt,
    .text_off      = rec->text_off,
    .text_sz       = rec->text_sz,
    .rodata_sz     = rec->rodata_sz,
    .calldests_off = rec->calldests_off,
    .rodata_off    = rec->rodata_off,
    .sbpf_version  = rec->sbpf_version,
    .val_sz        = (uint)val_sz,
    .src_tile      = (uint)client->tile_idx,
    .features      = *features,
  };
  memcpy( req+1, fd_wksp_laddr_fast( client->pc_wksp, rec->data_gaddr ), val_sz );

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( client->mcache, client->depth, client->seq, 0UL, client->chunk, 0UL, 0UL, tspub, tspub );
  client->chunk = fd_dcache_compact_next( client->chunk, sz, client->chunk0, client->wmark );
  client->seq   = fd_seq_inc( client->seq, 1UL );
  client->sent++;
  FD_VOLATILE( rec->transpiled_idx ) = FD_TRANSPILE_BIND_HOLD;
}

int
fd_jit_client_init( fd_jit_client_t *      client,
                    fd_topo_t const *      topo,
                    fd_topo_tile_t const * tile,
                    ulong                  tile_idx,
                    ulong                  jit_arena_obj_id,
                    fd_progcache_t *       progcache ) {
  memset( client, 0, sizeof(*client) );
  ulong idx = fd_topo_find_tile_out_link( topo, tile, "exec_jit", tile_idx );
  if( idx==ULONG_MAX ) return 0;
  FD_TEST( jit_arena_obj_id!=ULONG_MAX );

  fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ idx ] ];
  client->mcache   = link->mcache;
  client->depth    = fd_mcache_depth( link->mcache );
  client->seq      = 0UL;
  client->mem      = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  client->chunk0   = fd_dcache_compact_chunk0( client->mem, link->dcache );
  client->wmark    = fd_dcache_compact_wmark( client->mem, link->dcache, link->mtu );
  client->chunk    = client->chunk0;
  client->pc_wksp  = (fd_wksp_t *)progcache->join->data_base;
  client->rec0     = progcache->join->rec.ele;
  client->rec_max  = progcache->join->rec.max;
  client->tile_idx = tile_idx;

  /* The jit tile's fseq for this link */
  fd_topo_tile_t const * jit_tile = &topo->tiles[ fd_topo_find_tile( topo, "jit", 0UL ) ];
  client->fseq = NULL;
  for( ulong j=0UL; j<jit_tile->in_cnt; j++ ) {
    if( jit_tile->in_link_id[ j ]==link->id ) {
      client->fseq = fd_fseq_join( fd_topo_obj_laddr( topo, jit_tile->in_link_fseq_obj_id[ j ] ) );
      break;
    }
  }
  FD_TEST( client->fseq );

  client->bind->arena   = fd_jit_arena_join( fd_topo_obj_laddr( topo, jit_arena_obj_id ) );
  FD_TEST( client->bind->arena );
  client->bind->req     = jit_req;
  client->bind->req_ctx = client;
  return 1;
}
