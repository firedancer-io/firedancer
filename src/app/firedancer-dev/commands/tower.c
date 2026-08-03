/* The tower command prints the tower forks tree structure and leaves.
   This is a standalone application that can be run to inspect the tower
   tile's fork structure. */

#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../discof/tower/fd_tower_tile.c"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SORT_NAME        sort_blk
#define SORT_KEY_T       fd_tower_blk_t const *
#define SORT_BEFORE(a,b) ((a)->slot<(b)->slot)
#include "../../../util/tmpl/fd_sort.c"

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

extern action_t fd_action_tower;

/* fd_tower_tile_t is defined in fd_tower_tile.c, we just need to access it */

static void
tower_ctx_wksp( args_t *           args,
                config_t *         config,
                fd_tower_tile_t ** tower_ctx,
                fd_topo_wksp_t **  tower_wksp ) {
  (void)args;

  fd_topo_t * topo = &config->topo;

  ulong tile_id = fd_topo_find_tile( topo, "tower", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tower tile not found" ));

  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  /* Get the workspace that contains the tile's scratch memory */
  ulong scratch_wksp_id = topo->objs[ tile->tile_obj_id ].wksp_id;
  if( FD_UNLIKELY( scratch_wksp_id>=topo->wksp_cnt ) ) FD_LOG_ERR(( "invalid workspace id %lu for tile scratch", scratch_wksp_id ));

  fd_topo_wksp_t * _tower_wksp = &topo->workspaces[ scratch_wksp_id ];
  fd_topo_join_workspace( topo, _tower_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Access the tower tile scratch memory where tower_tile_ctx is stored */
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access tower tile scratch memory" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_tower_tile_t * _tower_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tower_tile_t), sizeof(fd_tower_tile_t) );

  *tower_ctx  = _tower_ctx;
  *tower_wksp = _tower_wksp;
}

/* tower_join copies the tower tile's tower into snapshot, rebasing the
   pointers it contains into our address space, and returns snapshot.

   fd_tower_t stores the addresses of its sub-structures rather than
   their workspace offsets (unlike eg. fd_ghost_t), and those addresses
   are local to the tower tile's address space.  Every process joins a
   workspace at a different base address, so the addresses have to be
   rebased before we can dereference them.  The whole tower lives in one
   workspace, so a single offset rebases all of them.  We join the
   workspace read-only, hence the copy.

   Only the fields the printers below use (votes, blk_pool and blk_map)
   are rebased: dereferencing any of the other pointers in snapshot is a
   bug.

   The tile keeps writing the tower while we read it, so snapshot is a
   best-effort (and potentially torn) view.  That is fine here because we
   only print it. */

static fd_tower_t *
tower_join( fd_tower_tile_t * tower_ctx,
            fd_topo_wksp_t *  tower_wksp,
            fd_tower_t *      snapshot ) {

  ulong        gaddr = fd_wksp_gaddr_fast( tower_ctx->wksp, tower_ctx->tower );
  fd_tower_t * tower = fd_wksp_laddr( tower_wksp->wksp, gaddr );
  if( FD_UNLIKELY( !tower ) ) FD_LOG_ERR(( "failed to map tower at gaddr %#lx", gaddr ));

  ulong off = (ulong)tower - (ulong)tower_ctx->tower;

  *snapshot = *tower;
  snapshot->votes    = (fd_tower_vote_t *)( (ulong)tower->votes    + off );
  snapshot->blk_pool = (fd_tower_blk_t  *)( (ulong)tower->blk_pool + off );
  snapshot->blk_map  = (void *)           ( (ulong)tower->blk_map  + off );

  return snapshot;
}

static void
print_all_forks( fd_tower_t * tower ) {
  printf( "\n[Tower Forks]\n" );
  printf( "=============\n" );
  printf( "%-15s | %-15s | %-10s | %-10s\n", "Slot", "Parent Slot", "Voted", "Confirmed" );
  printf( "%-15s-+-%-15s-+-%-10s-+-%-10s\n", "---------------", "---------------", "----------", "----------" );

  ulong slot_count = 0;
  for( ulong i = 0; i < tower->blk_max; i++ ) {
    fd_tower_blk_t * blk = tower->blk_pool + i;
    if( !blk->slot ) continue; /* unused pool element */
    fd_tower_blk_t * found = fd_tower_blocks_query( tower, blk->slot );
    if( !found ) continue;
    printf( "%-15lu | ", found->slot );
    if( found->parent_slot == ULONG_MAX ) {
      printf( "%-15s | ", "NULL" );
    } else {
      printf( "%-15lu | ", found->parent_slot );
    }
    printf( "%-10s | ", found->voted ? "Yes" : "No" );
    printf( "%-10s\n", found->confirmed ? "Yes" : "No" );
    slot_count++;
  }

  printf( "Total slots: %lu\n", slot_count );
  printf( "\n" );
}

#define SLOT_CSTR_SZ (21UL) /* 20 digits and a nul */
#define HASH_CSTR_SZ (11UL) /* 8 base58 chars, ".." and a nul */

/* fmt_slot formats slot into cstr, or returns "-" if slot is unset
   (ULONG_MAX). */

static char const *
fmt_slot( ulong slot,
          char  cstr[ static SLOT_CSTR_SZ ] ) {
  if( FD_UNLIKELY( slot==ULONG_MAX ) ) return "-";
  snprintf( cstr, SLOT_CSTR_SZ, "%lu", slot );
  return cstr;
}

/* fmt_hash formats the leading 8 base58 characters of hash into cstr, or
   returns "-" if hash is unset (all zeros). */

static char const *
fmt_hash( fd_hash_t const * hash,
          char              cstr[ static HASH_CSTR_SZ ] ) {
  if( FD_UNLIKELY( fd_hash_check_zero( hash ) ) ) return "-";
  char b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( hash->uc, NULL, b58 );
  snprintf( cstr, HASH_CSTR_SZ, "%.8s..", b58 );
  return cstr;
}

/* print_all_blocks pretty-prints the metadata the tower tracks for every
   block it currently knows about, ordered by slot.  blks is caller
   supplied scratch with room for tower->blk_max blocks. */

static void
print_all_blocks( fd_tower_t *            tower,
                  fd_tower_blk_t const ** blks ) {

  ulong blk_cnt = 0UL;
  for( ulong i=0UL; i<tower->blk_max; i++ ) {
    fd_tower_blk_t const * blk = tower->blk_pool + i;

    /* A pool element is either live, in which case the block map maps
       its slot back to it, or free, in which case slot is left over from
       whichever block previously occupied the element.  Probe the map to
       tell the two apart. */

    if( FD_UNLIKELY( fd_tower_blocks_query( tower, blk->slot )!=blk ) ) continue;
    blks[ blk_cnt++ ] = blk;
  }
  sort_blk_inplace( blks, blk_cnt );

  char root_cstr[ SLOT_CSTR_SZ ];
  printf( "\n[Tower Blocks]\n" );
  printf( "==============\n" );
  printf( "%lu block(s), root %s.  * marks the root.  Flags: R replayed, V voted, C duplicate confirmed, L our leader slot, P propagated.\n\n",
          blk_cnt, fmt_slot( tower->root, root_cstr ) );
  printf( " %11s | %11s | %5s | %5s | %11s | %-10s | %-10s | %-10s | %-10s | %s\n",
          "slot", "parent", "epoch", "RVCLP", "prev leader", "bank hash", "block hash", "replayed", "voted", "confirmed" );
  printf( "-%11s-+-%11s-+-%5s-+-%5s-+-%11s-+-%10s-+-%10s-+-%10s-+-%10s-+-%s\n",
          "-----------", "-----------", "-----", "-----", "-----------",
          "----------", "----------", "----------", "----------", "----------" );

  for( ulong i=0UL; i<blk_cnt; i++ ) {
    fd_tower_blk_t const * blk = blks[ i ];

    char slot_cstr       [ SLOT_CSTR_SZ ];
    char parent_cstr     [ SLOT_CSTR_SZ ];
    char prev_leader_cstr[ SLOT_CSTR_SZ ];
    char bank_hash_cstr  [ HASH_CSTR_SZ ];
    char block_hash_cstr [ HASH_CSTR_SZ ];
    char replayed_cstr   [ HASH_CSTR_SZ ];
    char voted_cstr      [ HASH_CSTR_SZ ];
    char confirmed_cstr  [ HASH_CSTR_SZ ];

    printf( "%c%11s | %11s | %5lu | %c%c%c%c%c | %11s | %-10s | %-10s | %-10s | %-10s | %s\n",
            blk->slot==tower->root ? '*' : ' ',
            fmt_slot( blk->slot,        slot_cstr   ),
            fmt_slot( blk->parent_slot, parent_cstr ),
            blk->epoch,
            blk->replayed   ? 'R' : '-',
            blk->voted      ? 'V' : '-',
            blk->confirmed  ? 'C' : '-',
            blk->leader     ? 'L' : '-',
            blk->propagated ? 'P' : '-',
            fmt_slot( blk->prev_leader_slot,     prev_leader_cstr ),
            fmt_hash( &blk->bank_hash,           bank_hash_cstr   ),
            fmt_hash( &blk->block_hash,          block_hash_cstr  ),
            fmt_hash( &blk->replayed_block_id,   replayed_cstr    ),
            fmt_hash( &blk->voted_block_id,      voted_cstr       ),
            fmt_hash( &blk->confirmed_block_id,  confirmed_cstr   ) );
  }

  printf( "\n" );
}

static void
tower_cmd_fn_forks( args_t *   args,
                    config_t * config ) {
  fd_tower_tile_t *          tower_ctx;
  fd_topo_wksp_t * tower_wksp;
  tower_ctx_wksp( args, config, &tower_ctx, &tower_wksp );

  fd_tower_t tower[1];
  for( ;; ) {
    print_all_forks( tower_join( tower_ctx, tower_wksp, tower ) );
    fflush( stdout );
    sleep( 1 );
  }
}

static void
tower_cmd_fn_ghost( args_t *   args,
                    config_t * config ) {
  fd_tower_tile_t *          tower_ctx;
  fd_topo_wksp_t * tower_wksp;
  tower_ctx_wksp( args, config, &tower_ctx, &tower_wksp );

  ulong ghost_gaddr = fd_wksp_gaddr_fast( tower_ctx->wksp, tower_ctx->ghost );
  fd_ghost_t * ghost = (fd_ghost_t *)fd_wksp_laddr( tower_wksp->wksp, ghost_gaddr );
  fd_ghost_root( ghost );
  FD_LOG_NOTICE(( "root slot %lu", fd_ghost_root( ghost )->slot ));

  for( ;; ) {
    char cstr[4096]; cstr[4095] = '\0'; ulong sz;
    FD_LOG_NOTICE(( "\n\n%s", fd_ghost_to_cstr( ghost, fd_ghost_root( ghost ), cstr, sizeof(cstr), &sz ) ));
    sleep( 1 );
  }
}

static void
tower_cmd_fn_tower( args_t    * args,
                     config_t * config ) {
  fd_tower_tile_t *          tower_ctx;
  fd_topo_wksp_t * tower_wksp;
  tower_ctx_wksp( args, config, &tower_ctx, &tower_wksp );

  fd_tower_t tower[1];
  tower_join( tower_ctx, tower_wksp, tower );
  if( FD_UNLIKELY( !tower->blk_max ) ) FD_LOG_ERR(( "tower tile is not initialized yet" ));

  /* Allocate the scratch print_all_blocks sorts into once up front. */

  fd_tower_blk_t const ** blks = aligned_alloc( alignof(fd_tower_blk_t const *), sizeof(fd_tower_blk_t const *)*tower->blk_max );
  if( FD_UNLIKELY( !blks ) ) FD_LOG_ERR(( "aligned_alloc failed" ));

  for( ;; ) {
    tower_join( tower_ctx, tower_wksp, tower );

    char cstr[ FD_TOWER_CSTR_MIN ];
    printf( "\n%s", fd_tower_to_cstr( tower, cstr ) );
    print_all_blocks( tower, blks );
    fflush( stdout );
    sleep( 1 );
  }
}

void
tower_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {

  /* positional arg */
  args->tower.pos_arg = (*pargv)[0];
  if( FD_UNLIKELY( !args->tower.pos_arg ) ) {
    args->tower.help = 1;
    return;
  }

  (*pargc)--;
  (*pargv)++;
}

static void
tower_cmd_fn( args_t *   args,
              config_t * config ) {

  if( args->tower.help ) {
    fd_action_help_print( &fd_action_tower );
    return;
  }

  if     ( !strcmp( args->tower.pos_arg, "forks" ) ) tower_cmd_fn_forks( args, config );
  else if( !strcmp( args->tower.pos_arg, "ghost" ) ) tower_cmd_fn_ghost( args, config );
  else if( !strcmp( args->tower.pos_arg, "tower" ) ) tower_cmd_fn_tower( args, config );
  else                                               fd_action_help_print( &fd_action_tower );
}

static void
tower_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "forks", NULL, "Print the tower forks tree structure and leaves" );
  fd_action_help_arg( help, "ghost", NULL, "Print the ghost fork choice structure" );
  fd_action_help_arg( help, "tower", NULL, "Print the local tower and every block it is tracking" );
}

action_t fd_action_tower = {
  .name        = "tower",
  .args        = tower_cmd_args,
  .fn          = tower_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Inspect a running validator's tower, ghost, and forks state",
  .detail      = "Attaches to a running validator's tower tile and continuously prints the\n"
                 "requested data structure.  Pick one of the subcommands below.",
  .usage       = "tower <forks|ghost|tower>",
  .args_help   = tower_args_help,
};
