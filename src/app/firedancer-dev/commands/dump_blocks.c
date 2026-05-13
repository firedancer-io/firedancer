#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/shred/fd_shred_tile.h"
#include "../../../util/pod/fd_pod.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

extern action_t * ACTIONS[];

#define DUMP_BLOCKS_SLOT_HASH_CNT    (4096UL)
#define DUMP_BLOCKS_SHRED_CAP        (4UL*FD_SHRED_BLK_MAX)
#define DUMP_BLOCKS_SHRED_TMP_VALID  (1)

struct dump_blocks_shred_node;
struct dump_blocks_slot;

typedef struct dump_blocks_shred_node dump_blocks_shred_node_t;
typedef struct dump_blocks_slot       dump_blocks_slot_t;

struct dump_blocks_shred_node {
  ulong slot;
  uint  idx;
  uint  pri;
  ulong sz;
  uchar raw[ FD_SHRED_MAX_SZ ];

  dump_blocks_shred_node_t * left;
  dump_blocks_shred_node_t * right;
  dump_blocks_shred_node_t * parent;

  dump_blocks_shred_node_t * slot_next;
};

struct dump_blocks_slot {
  ulong slot;
  ulong seen_cnt;
  ulong shred_cnt;
  int   complete_seen;

  dump_blocks_shred_node_t * shreds;

  dump_blocks_slot_t * hash_next;
  dump_blocks_slot_t * lru_prev;
  dump_blocks_slot_t * lru_next;
};

struct dump_blocks_ctx {
  void const ** in_dcache;
  ulong         in_cnt;

  int           output_dirfd;

  dump_blocks_shred_node_t * shred_root;
  ulong                      shred_cnt;
  ulong                      shred_cap;

  dump_blocks_slot_t * slot_bucket[ DUMP_BLOCKS_SLOT_HASH_CNT ];
  dump_blocks_slot_t * lru_head;
  dump_blocks_slot_t * lru_tail;

  ulong * metrics_base;

  fd_shred_base_t pending_shred;
  ulong           pending_shred_sig;
  int             pending_shred_state;

  ulong raw_shred_cnt;
  ulong duplicate_cnt;
  ulong conflict_cnt;
  ulong evicted_slot_cnt;
  ulong evicted_shred_cnt;
  ulong completed_slot_cnt;
  ulong write_fail_cnt;
};
typedef struct dump_blocks_ctx dump_blocks_ctx_t;

static int dump_blocks_running = 1;

static void
dump_blocks_exit_signal( int sig FD_PARAM_UNUSED ) {
  dump_blocks_running = 0;
}

static int
dump_blocks_should_shutdown( dump_blocks_ctx_t * ctx FD_PARAM_UNUSED ) {
  return !dump_blocks_running;
}

static uint
dump_blocks_mix32( ulong x ) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdUL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53UL;
  x ^= x >> 33;
  return (uint)x | 1U;
}

static ulong
dump_blocks_slot_hash( ulong slot ) {
  return (ulong)dump_blocks_mix32( slot ) & (DUMP_BLOCKS_SLOT_HASH_CNT-1UL);
}

static int
dump_blocks_key_cmp( ulong a_slot,
                     uint  a_idx,
                     ulong b_slot,
                     uint  b_idx ) {
  if( a_slot<b_slot ) return -1;
  if( a_slot>b_slot ) return  1;
  if( a_idx <b_idx  ) return -1;
  if( a_idx >b_idx  ) return  1;
  return 0;
}

static dump_blocks_slot_t *
dump_blocks_slot_query( dump_blocks_ctx_t * ctx,
                        ulong               slot ) {
  for( dump_blocks_slot_t * s=ctx->slot_bucket[ dump_blocks_slot_hash( slot ) ]; s; s=s->hash_next )
    if( FD_LIKELY( s->slot==slot ) ) return s;
  return NULL;
}

static void
dump_blocks_lru_remove( dump_blocks_ctx_t * ctx,
                        dump_blocks_slot_t * slot ) {
  if( slot->lru_prev ) slot->lru_prev->lru_next = slot->lru_next;
  else                ctx->lru_head             = slot->lru_next;
  if( slot->lru_next ) slot->lru_next->lru_prev = slot->lru_prev;
  else                ctx->lru_tail             = slot->lru_prev;
  slot->lru_prev = NULL;
  slot->lru_next = NULL;
}

static void
dump_blocks_lru_touch( dump_blocks_ctx_t * ctx,
                       dump_blocks_slot_t * slot ) {
  if( FD_LIKELY( ctx->lru_tail==slot ) ) return;
  if( FD_LIKELY( slot->lru_prev || slot->lru_next || ctx->lru_head==slot ) ) dump_blocks_lru_remove( ctx, slot );

  slot->lru_prev = ctx->lru_tail;
  slot->lru_next = NULL;
  if( ctx->lru_tail ) ctx->lru_tail->lru_next = slot;
  else               ctx->lru_head           = slot;
  ctx->lru_tail = slot;
}

static dump_blocks_slot_t *
dump_blocks_slot_insert( dump_blocks_ctx_t * ctx,
                         ulong               slot ) {
  dump_blocks_slot_t * s = dump_blocks_slot_query( ctx, slot );
  if( FD_LIKELY( s ) ) {
    dump_blocks_lru_touch( ctx, s );
    return s;
  }

  s = (dump_blocks_slot_t *)malloc( sizeof(dump_blocks_slot_t) );
  if( FD_UNLIKELY( !s ) ) {
    FD_LOG_WARNING(( "dump_blocks failed to allocate slot metadata" ));
    return NULL;
  }
  fd_memset( s, 0, sizeof(dump_blocks_slot_t) );
  s->slot = slot;

  ulong bucket = dump_blocks_slot_hash( slot );
  s->hash_next = ctx->slot_bucket[ bucket ];
  ctx->slot_bucket[ bucket ] = s;
  dump_blocks_lru_touch( ctx, s );
  return s;
}

static dump_blocks_shred_node_t *
dump_blocks_shred_query( dump_blocks_ctx_t * ctx,
                         ulong               slot,
                         uint                idx ) {
  dump_blocks_shred_node_t * n = ctx->shred_root;
  while( n ) {
    int cmp = dump_blocks_key_cmp( slot, idx, n->slot, n->idx );
    if( FD_UNLIKELY( !cmp ) ) return n;
    n = fd_ptr_if( cmp<0, n->left, n->right );
  }
  return NULL;
}

static void
dump_blocks_treap_replace_parent_child( dump_blocks_ctx_t *       ctx,
                                        dump_blocks_shred_node_t * old_child,
                                        dump_blocks_shred_node_t * new_child ) {
  dump_blocks_shred_node_t * parent = old_child->parent;
  if( FD_UNLIKELY( !parent ) ) ctx->shred_root = new_child;
  else if( parent->left==old_child ) parent->left = new_child;
  else                              parent->right = new_child;
  if( new_child ) new_child->parent = parent;
}

static void
dump_blocks_rotate_left( dump_blocks_ctx_t *       ctx,
                         dump_blocks_shred_node_t * x ) {
  dump_blocks_shred_node_t * y = x->right;
  x->right = y->left;
  if( y->left ) y->left->parent = x;
  dump_blocks_treap_replace_parent_child( ctx, x, y );
  y->left   = x;
  x->parent = y;
}

static void
dump_blocks_rotate_right( dump_blocks_ctx_t *       ctx,
                          dump_blocks_shred_node_t * x ) {
  dump_blocks_shred_node_t * y = x->left;
  x->left = y->right;
  if( y->right ) y->right->parent = x;
  dump_blocks_treap_replace_parent_child( ctx, x, y );
  y->right  = x;
  x->parent = y;
}

static void
dump_blocks_shred_insert_node( dump_blocks_ctx_t *       ctx,
                               dump_blocks_shred_node_t * node ) {
  node->left   = NULL;
  node->right  = NULL;
  node->parent = NULL;

  if( FD_UNLIKELY( !ctx->shred_root ) ) {
    ctx->shred_root = node;
    return;
  }

  dump_blocks_shred_node_t * parent = ctx->shred_root;
  for(;;) {
    int cmp = dump_blocks_key_cmp( node->slot, node->idx, parent->slot, parent->idx );
    dump_blocks_shred_node_t ** next = fd_ptr_if( cmp<0, &parent->left, &parent->right );
    if( FD_LIKELY( *next ) ) {
      parent = *next;
      continue;
    }

    *next        = node;
    node->parent = parent;
    break;
  }

  while( node->parent && node->parent->pri<node->pri ) {
    if( node->parent->left==node ) dump_blocks_rotate_right( ctx, node->parent );
    else                          dump_blocks_rotate_left ( ctx, node->parent );
  }
}

static void
dump_blocks_shred_remove_node( dump_blocks_ctx_t *       ctx,
                               dump_blocks_shred_node_t * node ) {
  while( node->left || node->right ) {
    if( !node->left ) dump_blocks_rotate_left( ctx, node );
    else if( !node->right ) dump_blocks_rotate_right( ctx, node );
    else if( node->left->pri > node->right->pri ) dump_blocks_rotate_right( ctx, node );
    else                                         dump_blocks_rotate_left ( ctx, node );
  }

  dump_blocks_treap_replace_parent_child( ctx, node, NULL );
  ctx->shred_cnt--;
}

static void
dump_blocks_slot_remove_from_hash( dump_blocks_ctx_t * ctx,
                                   dump_blocks_slot_t * slot ) {
  dump_blocks_slot_t ** p = &ctx->slot_bucket[ dump_blocks_slot_hash( slot->slot ) ];
  while( *p ) {
    if( FD_LIKELY( *p==slot ) ) {
      *p = slot->hash_next;
      return;
    }
    p = &(*p)->hash_next;
  }
}

static void
dump_blocks_remove_slot( dump_blocks_ctx_t * ctx,
                         dump_blocks_slot_t * slot,
                         int                 count_eviction ) {
  dump_blocks_slot_remove_from_hash( ctx, slot );
  dump_blocks_lru_remove( ctx, slot );

  ulong evicted = 0UL;
  dump_blocks_shred_node_t * n = slot->shreds;
  while( n ) {
    dump_blocks_shred_node_t * next = n->slot_next;
    dump_blocks_shred_remove_node( ctx, n );
    free( n );
    evicted++;
    n = next;
  }

  if( FD_UNLIKELY( count_eviction ) ) {
    ctx->evicted_slot_cnt++;
    ctx->evicted_shred_cnt += evicted;
  }

  free( slot );
}

static int
dump_blocks_evict_lru_slot( dump_blocks_ctx_t * ctx,
                            dump_blocks_slot_t * protect ) {
  dump_blocks_slot_t * slot = ctx->lru_head;
  while( slot && slot==protect ) slot = slot->lru_next;
  if( FD_UNLIKELY( !slot ) ) return 0;
  dump_blocks_remove_slot( ctx, slot, 1 );
  return 1;
}

static int
dump_blocks_write_all( int          fd,
                       char const * path,
                       void const * buf,
                       ulong        sz ) {
  ulong wsz = 0UL;
  int err = fd_io_write( fd, buf, sz, sz, &wsz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "dump_blocks failed to write %s (%i-%s)", path, err, fd_io_strerror( err ) ));
    return -1;
  }
  return 0;
}

static int
dump_blocks_write_slot( dump_blocks_ctx_t * ctx,
                        dump_blocks_slot_t * slot ) {
  if( FD_UNLIKELY( !slot->complete_seen || slot->seen_cnt!=slot->shred_cnt ) ) return 0;

  char path[ 64 ];
  char tmp_path[ 64 ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( path,     sizeof(path),     NULL, "%lu.block",  slot->slot ) ) ) return -1;
  if( FD_UNLIKELY( !fd_cstr_printf_check( tmp_path, sizeof(tmp_path), NULL, ".%lu.block.tmp", slot->slot ) ) ) return -1;

  if( FD_LIKELY( !faccessat( ctx->output_dirfd, path, F_OK, 0 ) ) ) return 1;
  if( FD_UNLIKELY( errno!=ENOENT ) ) {
    FD_LOG_WARNING(( "dump_blocks failed to check %s (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  int fd = openat( ctx->output_dirfd, tmp_path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "dump_blocks failed to create %s (%i-%s)", tmp_path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  int failed = 0;
  static uchar const magic[ 8 ] = { 'M', 'e', ' ', '2', '6', '2', 0x19, 0x42 };
  failed = dump_blocks_write_all( fd, tmp_path, magic, sizeof(magic) );

  for( uint i=0U; !failed && i<(uint)slot->shred_cnt; i++ ) {
    dump_blocks_shred_node_t * node = dump_blocks_shred_query( ctx, slot->slot, i );
    if( FD_UNLIKELY( !node ) ) {
      FD_LOG_WARNING(( "dump_blocks slot=%lu became incomplete while writing missing shred_idx=%u", slot->slot, i ));
      failed = 1;
      break;
    }

    fd_shred_t const * parsed = fd_shred_parse( node->raw, FD_SHRED_MAX_SZ );
    if( FD_UNLIKELY( !parsed ||
                     parsed->slot!=slot->slot ||
                     parsed->idx!=i ||
                     !fd_shred_is_data( fd_shred_type( parsed->variant ) ) ||
                     fd_shred_sz( parsed )!=node->sz ) ) {
      FD_LOG_WARNING(( "dump_blocks corrupt cached raw shred slot=%lu shred_idx=%u size=%lu", slot->slot, i, node->sz ));
      failed = 1;
      break;
    }

    uchar sz_le[ 2 ] = { (uchar)(node->sz & 0xffU), (uchar)(node->sz >> 8) };
    failed = dump_blocks_write_all( fd, tmp_path, sz_le, sizeof(sz_le) );
    if( FD_UNLIKELY( failed ) ) break;
    failed = dump_blocks_write_all( fd, tmp_path, node->raw, node->sz );
  }

  if( FD_UNLIKELY( close( fd ) ) ) {
    FD_LOG_WARNING(( "dump_blocks failed to close %s (%i-%s)", tmp_path, errno, fd_io_strerror( errno ) ));
    failed = 1;
  }

  if( FD_UNLIKELY( failed ) ) {
    unlinkat( ctx->output_dirfd, tmp_path, 0 );
    ctx->write_fail_cnt++;
    return 0;
  }

  if( FD_UNLIKELY( renameat( ctx->output_dirfd, tmp_path, ctx->output_dirfd, path ) ) ) {
    FD_LOG_WARNING(( "dump_blocks failed to rename %s to %s (%i-%s)", tmp_path, path, errno, fd_io_strerror( errno ) ));
    unlinkat( ctx->output_dirfd, tmp_path, 0 );
    ctx->write_fail_cnt++;
    return -1;
  }

  FD_LOG_NOTICE(( "%s : shred_cnt=%lu", path, slot->shred_cnt ));
  ctx->completed_slot_cnt++;
  return 1;
}

static void
dump_blocks_try_complete( dump_blocks_ctx_t * ctx,
                          dump_blocks_slot_t * slot ) {
  if( FD_UNLIKELY( !slot || !slot->complete_seen || slot->seen_cnt!=slot->shred_cnt ) ) return;

  int ret = dump_blocks_write_slot( ctx, slot );
  if( FD_LIKELY( ret>0 ) ) dump_blocks_remove_slot( ctx, slot, 0 );
}

static int
dump_blocks_raw_shred_duplicate( dump_blocks_shred_node_t const * old,
                                 fd_shred_t const *               shred,
                                 uchar const *                    raw,
                                 ulong                            raw_sz ) {
  if( FD_UNLIKELY( old->sz!=raw_sz ) ) return 0;
  if( FD_LIKELY( fd_memeq( old->raw, raw, raw_sz ) ) ) return 1;

  if( FD_LIKELY( !fd_shred_is_resigned( fd_shred_type( shred->variant ) ) ) ) return 0;

  ulong sig_off = fd_shred_retransmitter_sig_off( shred );
  if( FD_UNLIKELY( sig_off>raw_sz || raw_sz-sig_off<FD_SHRED_SIGNATURE_SZ ) ) return 0;

  return fd_memeq( old->raw, raw, sig_off ) &&
         fd_memeq( old->raw+sig_off+FD_SHRED_SIGNATURE_SZ,
                   raw+sig_off+FD_SHRED_SIGNATURE_SZ,
                   raw_sz-sig_off-FD_SHRED_SIGNATURE_SZ );
}

static void
dump_blocks_process_shred( dump_blocks_ctx_t *      ctx,
                           ulong                    sig,
                           fd_shred_base_t const * shred_msg ) {
  int res = fd_shred_sig_res( sig );
  if( FD_UNLIKELY( res!=FD_FEC_RESOLVER_SHRED_OKAY      &&
                   res!=FD_FEC_RESOLVER_SHRED_COMPLETES &&
                   res!=FD_FEC_RESOLVER_SHRED_DUPLICATE ) ) return;

  uint src = fd_shred_sig_src( sig );
  if( FD_UNLIKELY( src>SHRED_SIG_SRC_HTTP_BACKFILL ) ) return;
  if( FD_UNLIKELY( src==SHRED_SIG_SRC_RECONSTRUCTED ) ) return;

  fd_shred_t const * shred = fd_shred_parse( shred_msg->shred_, FD_SHRED_MAX_SZ );
  if( FD_UNLIKELY( !shred ) ) return;

  uchar type = fd_shred_type( shred->variant );
  if( FD_UNLIKELY( !fd_shred_is_data( type ) ) ) return;
  if( FD_UNLIKELY( shred->idx>=FD_SHRED_BLK_MAX ) ) return;

  ulong shred_sz = fd_shred_sz( shred );
  if( FD_UNLIKELY( shred_sz>FD_SHRED_MAX_SZ ) ) return;

  dump_blocks_slot_t * slot = dump_blocks_slot_insert( ctx, shred->slot );
  if( FD_UNLIKELY( !slot ) ) return;

  if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
    ulong shred_cnt = (ulong)shred->idx + 1UL;
    if( FD_UNLIKELY( slot->complete_seen && slot->shred_cnt!=shred_cnt ) ) {
      FD_LOG_WARNING(( "dump_blocks conflicting slot complete metadata slot=%lu old_shred_cnt=%lu new_shred_cnt=%lu",
                       shred->slot, slot->shred_cnt, shred_cnt ));
    } else {
      slot->complete_seen = 1;
      slot->shred_cnt     = shred_cnt;
    }
  }

  dump_blocks_shred_node_t * old = dump_blocks_shred_query( ctx, shred->slot, shred->idx );
  if( FD_UNLIKELY( old ) ) {
    if( FD_LIKELY( dump_blocks_raw_shred_duplicate( old, shred, shred_msg->shred_, shred_sz ) ) ) ctx->duplicate_cnt++;
    else {
      FD_LOG_WARNING(( "dump_blocks ignoring conflicting raw data shred slot=%lu shred_idx=%u", shred->slot, shred->idx ));
      ctx->conflict_cnt++;
    }
    dump_blocks_try_complete( ctx, slot );
    return;
  }

  while( FD_UNLIKELY( ctx->shred_cnt>=ctx->shred_cap ) ) {
    if( FD_UNLIKELY( !dump_blocks_evict_lru_slot( ctx, slot ) ) ) {
      FD_LOG_WARNING(( "dump_blocks raw shred cache is full and no evictable slot exists" ));
      return;
    }
  }

  dump_blocks_shred_node_t * node = (dump_blocks_shred_node_t *)malloc( sizeof(dump_blocks_shred_node_t) );
  if( FD_UNLIKELY( !node ) ) {
    dump_blocks_evict_lru_slot( ctx, slot );
    node = (dump_blocks_shred_node_t *)malloc( sizeof(dump_blocks_shred_node_t) );
  }
  if( FD_UNLIKELY( !node ) ) {
    FD_LOG_WARNING(( "dump_blocks failed to allocate raw shred cache node" ));
    return;
  }

  fd_memset( node, 0, sizeof(dump_blocks_shred_node_t) );
  node->slot      = shred->slot;
  node->idx       = shred->idx;
  node->pri       = dump_blocks_mix32( shred->slot ^ (((ulong)shred->idx)<<32) ^ 0x9e3779b97f4a7c15UL );
  node->sz        = shred_sz;
  fd_memcpy( node->raw, shred_msg->shred_, shred_sz );

  node->slot_next = slot->shreds;
  slot->shreds    = node;
  slot->seen_cnt++;

  dump_blocks_shred_insert_node( ctx, node );
  ctx->shred_cnt++;
  ctx->raw_shred_cnt++;

  dump_blocks_try_complete( ctx, slot );
}

static void
dump_blocks_during_frag( dump_blocks_ctx_t * ctx,
                         ulong               in_idx,
                         ulong               seq FD_PARAM_UNUSED,
                         ulong               sig,
                         ulong               chunk,
                         ulong               sz,
                         ulong               ctl FD_PARAM_UNUSED ) {
  ctx->pending_shred_state = 0;

  if( FD_LIKELY( fd_shred_sig_src( sig )<=SHRED_SIG_SRC_HTTP_BACKFILL ) ) {
    if( FD_UNLIKELY( sz!=sizeof(fd_shred_base_t) ) ) {
      FD_LOG_WARNING(( "dump_blocks skipping malformed shred fragment with size %lu", sz ));
      return;
    }

    void const * src = fd_chunk_to_laddr_const( ctx->in_dcache[ in_idx ], chunk );
    fd_memcpy( &ctx->pending_shred, src, sizeof(fd_shred_base_t) );
    ctx->pending_shred_sig   = sig;
    ctx->pending_shred_state = DUMP_BLOCKS_SHRED_TMP_VALID;
  }
}

static void
dump_blocks_after_frag( dump_blocks_ctx_t * ctx,
                        ulong               in_idx FD_PARAM_UNUSED,
                        ulong               seq FD_PARAM_UNUSED,
                        ulong               sig FD_PARAM_UNUSED,
                        ulong               sz FD_PARAM_UNUSED,
                        ulong               tsorig FD_PARAM_UNUSED,
                        ulong               tspub FD_PARAM_UNUSED,
                        fd_stem_context_t * stem FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->pending_shred_state==DUMP_BLOCKS_SHRED_TMP_VALID ) ) {
    dump_blocks_process_shred( ctx, ctx->pending_shred_sig, &ctx->pending_shred );
    ctx->pending_shred_state = 0;
  }
}

#define STEM_NAME                         dump_blocks_stem
#define STEM_BURST                        (0UL)
#define STEM_CALLBACK_CONTEXT_TYPE        dump_blocks_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(dump_blocks_ctx_t)
#define STEM_CALLBACK_DURING_FRAG         dump_blocks_during_frag
#define STEM_CALLBACK_AFTER_FRAG          dump_blocks_after_frag
#define STEM_CALLBACK_SHOULD_SHUTDOWN     dump_blocks_should_shutdown
#include "../../../disco/stem/fd_stem.c"

static const char * DUMP_BLOCKS_HELP =
  "\n\n"
  "usage: dump_blocks [-h] [--topo NAME] [--output-dir PATH]\n"
  "\n"
  "Attach to a running Firedancer topology and dump completed blocks as ordered raw data shreds.\n"
  "\n"
  "optional arguments:\n"
  "  --topo NAME            use the topology from a different action (e.g. backtest)\n"
  "  --output-dir PATH     write block files to this directory (default: .)\n"
  "  -h, --help            show this help message and exit\n";

void
dump_blocks_cmd_args( int *    pargc,
                      char *** pargv,
                      args_t * args ) {
  args->dump_blocks.help = fd_env_strip_cmdline_contains( pargc, pargv, "--help" );
  args->dump_blocks.help = args->dump_blocks.help || fd_env_strip_cmdline_contains( pargc, pargv, "-h" );
  args->dump_blocks.output_dir = fd_env_strip_cmdline_cstr( pargc, pargv, "--output-dir", NULL, "." );

  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );
  ulong topo_name_len = strlen( topo_name );
  if( FD_UNLIKELY( topo_name_len > sizeof(args->dump_blocks.topo)-1 ) ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->dump_blocks.topo ), topo_name, topo_name_len ) );
}

static void
dump_blocks_reconstruct_topo( config_t *   config,
                              char const * topo_name ) {
  if( !topo_name[0] ) return;

  action_t const * selected = NULL;
  for( action_t ** a=ACTIONS; *a; a++ ) {
    action_t const * action = *a;
    if( 0==strcmp( action->name, topo_name ) ) {
      selected = action;
      break;
    }
  }

  if( !selected       ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  if( !selected->topo ) FD_LOG_ERR(( "Cannot recover topology for --topo %s", topo_name ));

  selected->topo( config );
}

void
dump_blocks_cmd_fn( args_t *   args,
                    config_t * config ) {
  if( FD_UNLIKELY( args->dump_blocks.help ) ) {
    FD_LOG_NOTICE(( "%s", DUMP_BLOCKS_HELP ));
    return;
  }

  dump_blocks_reconstruct_topo( config, args->dump_blocks.topo );

  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( topo );

  dump_blocks_ctx_t ctx = {0};
  ctx.shred_cap    = DUMP_BLOCKS_SHRED_CAP;
  ctx.output_dirfd = open( args->dump_blocks.output_dir, O_RDONLY|O_CLOEXEC|O_DIRECTORY );
  if( FD_UNLIKELY( ctx.output_dirfd<0 ) ) {
    FD_LOG_ERR(( "dump_blocks failed to open output directory %s (%i-%s)",
                 args->dump_blocks.output_dir, errno, fd_io_strerror( errno ) ));
  }

  for( ulong link_idx=0UL; link_idx<topo->link_cnt; link_idx++ ) {
    if( FD_LIKELY( strcmp( topo->links[ link_idx ].name, "shred_out" ) ) ) continue;
    ctx.in_cnt++;
  }
  if( FD_UNLIKELY( !ctx.in_cnt ) ) FD_LOG_ERR(( "shred_out links not found" ));

  fd_frag_meta_t const ** mcaches = (fd_frag_meta_t const **)fd_alloca( alignof(fd_frag_meta_t const *), sizeof(fd_frag_meta_t const *)*ctx.in_cnt );
  ctx.in_dcache = (void const **)fd_alloca( alignof(void const *), sizeof(void const *)*ctx.in_cnt );
  for( ulong link_idx=0UL, in_idx=0UL; link_idx<topo->link_cnt; link_idx++ ) {
    fd_topo_link_t const * link = &topo->links[ link_idx ];
    if( FD_LIKELY( strcmp( link->name, "shred_out" ) ) ) continue;
    if( FD_UNLIKELY( !link->mcache ) ) FD_LOG_ERR(( "shred_out:%lu mcache is null", link->kind_id ));
    if( FD_UNLIKELY( !link->mtu ) ) FD_LOG_ERR(( "shred_out:%lu has no dcache", link->kind_id ));
    void const * dcache = fd_topo_obj_wksp_base( topo, link->dcache_obj_id );
    if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "shred_out:%lu dcache is null", link->kind_id ));
    mcaches[ in_idx ]      = link->mcache;
    ctx.in_dcache[ in_idx ] = dcache;
    in_idx++;
  }

  FD_LOG_NOTICE(( "dump_blocks raw shred cache capacity=%lu slot_buckets=%lu",
                  ctx.shred_cap, DUMP_BLOCKS_SLOT_HASH_CNT ));

  struct sigaction sa = {
    .sa_handler = dump_blocks_exit_signal,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)",  errno, fd_io_strerror( errno ) ));

  uchar * fseq_mem = (uchar *)fd_alloca( FD_FSEQ_ALIGN, FD_FSEQ_FOOTPRINT*ctx.in_cnt );
  ulong ** fseqs = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*ctx.in_cnt );
  for( ulong i=0UL; i<ctx.in_cnt; i++ ) fseqs[ i ] = fd_fseq_join( fd_fseq_new( fseq_mem + i*FD_FSEQ_FOOTPRINT, 0UL ) );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount(), 0UL ) );

  uchar * scratch = fd_alloca( FD_STEM_SCRATCH_ALIGN, dump_blocks_stem_scratch_footprint( ctx.in_cnt, 0UL, 0UL ) );

  ctx.metrics_base = fd_metrics_join( fd_metrics_new( fd_alloca( FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( ctx.in_cnt ) ), ctx.in_cnt ) );
  fd_metrics_register( ctx.metrics_base );

  FD_LOG_NOTICE(( "dump_blocks attached to %lu shred_out links output_dir=%s", ctx.in_cnt, args->dump_blocks.output_dir ));

  dump_blocks_stem_run1( ctx.in_cnt, mcaches, fseqs, 0UL, NULL, 0UL, NULL, NULL, NULL, 0UL, 0UL, rng, scratch, &ctx );

  ulong consumed_frags = 0UL;
  ulong consumed_bytes = 0UL;
  for( ulong i=0UL; i<ctx.in_cnt; i++ ) {
    volatile ulong const * link_metrics = fd_metrics_link_in( ctx.metrics_base, i );
    consumed_frags += link_metrics[ FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF ];
    consumed_bytes += link_metrics[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ];
  }

  FD_LOG_NOTICE(( "dump_blocks exiting raw_shreds=%lu duplicates=%lu conflicts=%lu completed_slots=%lu write_failures=%lu evicted_slots=%lu evicted_shreds=%lu cached_shreds=%lu consumed_frags=%lu consumed_bytes=%lu",
                  ctx.raw_shred_cnt,
                  ctx.duplicate_cnt,
                  ctx.conflict_cnt,
                  ctx.completed_slot_cnt,
                  ctx.write_fail_cnt,
                  ctx.evicted_slot_cnt,
                  ctx.evicted_shred_cnt,
                  ctx.shred_cnt,
                  consumed_frags,
                  consumed_bytes ));

  fd_metrics_delete( fd_metrics_leave( ctx.metrics_base ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  for( ulong i=0UL; i<ctx.in_cnt; i++ ) fd_fseq_delete( fd_fseq_leave( fseqs[ i ] ) );

  while( ctx.lru_head ) dump_blocks_remove_slot( &ctx, ctx.lru_head, 0 );

  if( FD_UNLIKELY( close( ctx.output_dirfd ) ) ) FD_LOG_WARNING(( "dump_blocks failed to close output directory %s (%i-%s)",
                                                                  args->dump_blocks.output_dir, errno, fd_io_strerror( errno ) ));

  fd_topo_leave_workspaces( topo );
}

action_t fd_action_dump_blocks = {
  .name          = "dump-blocks",
  .args          = dump_blocks_cmd_args,
  .fn            = dump_blocks_cmd_fn,
  .perm          = NULL,
  .description   = "Dump live shred_out blocks",
  .is_diagnostic = 1
};
