/* force-mismatch attaches to a running validator (or backtest) and
   forces a genuine bank hash mismatch at a chosen slot, without any
   support from the validator itself.

   It works by injecting a hard fork into the bank state in shared
   memory.  A hard fork at slot T is mixed into the bank hash of the
   first block with parent_slot<T<=slot, and also moves the
   LastRestartSlot sysvar to T, so the validator computes a bank hash
   the rest of the cluster (or the ledger) disagrees with.  This is the
   same mechanism an operator's --hard-fork uses, so every downstream
   mismatch path (backtest ledger comparison, Alpenglow footer check,
   tower hard fork detection) is exercised for real.

   Hard forks are carried in bank->f and copied from parent to child
   when a bank becomes replayable, so the fork is appended to every live
   bank with slot<T.  Descendants inherit it from there.  The shred
   version is computed from the replay tile's private copy of the
   snapshot hard forks, so it is unaffected. */

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../shared/fd_bootinfo.h"
#include "../../../flamenco/runtime/fd_bank.h"
#include "../../../util/pod/fd_pod.h"
#include "../../../util/wksp/fd_wksp_private.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

extern action_t * ACTIONS[];

static void
force_mismatch_cmd_args( int *    pargc,
                         char *** pargv,
                         args_t * args ) {
  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );

  ulong topo_name_len = strlen( topo_name );
  if( FD_UNLIKELY( topo_name_len > sizeof(args->force_mismatch.topo)-1 ) ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->force_mismatch.topo ), topo_name, topo_name_len ) );

  args->force_mismatch.at_slot = fd_env_strip_cmdline_ulong( pargc, pargv, "--at-slot", NULL, 0UL );
  args->force_mismatch.after   = fd_env_strip_cmdline_ulong( pargc, pargv, "--after",   NULL, 0UL );

  if( FD_UNLIKELY( !args->force_mismatch.at_slot == !args->force_mismatch.after ) ) {
    FD_LOG_ERR(( "exactly one of --at-slot <slot> or --after <slots> must be given" ));
  }
}

static void
reconstruct_topo( config_t *   config,
                  char const * topo_name ) {
  if( !topo_name[0] ) return; /* keep default action topo */

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

static int
bank_has_fork( fd_bank_t const * bank,
               ulong             slot ) {
  ulong cnt = fd_ulong_min( FD_VOLATILE_CONST( bank->f.hard_fork_cnt ), FD_HARD_FORKS_MAX );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_VOLATILE_CONST( bank->f.hard_forks[ i ].slot )==slot ) return 1;
  }
  return 0;
}

/* bank_add_fork appends the hard fork before publishing the new count,
   so a concurrent reader sees either the old or the new list. */

static void
bank_add_fork( fd_bank_t * bank,
               ulong       slot ) {
  ulong cnt = FD_VOLATILE_CONST( bank->f.hard_fork_cnt );
  if( FD_UNLIKELY( cnt>=FD_HARD_FORKS_MAX ) ) FD_LOG_ERR(( "bank for slot %lu already has %lu hard forks", bank->f.slot, cnt ));
  bank->f.hard_forks[ cnt ].slot = slot;
  bank->f.hard_forks[ cnt ].cnt  = 1UL;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( bank->f.hard_fork_cnt ) = cnt+1UL;
}

/* max_replayed_slot returns the highest slot among replayable and
   frozen banks, or 0 if there are none yet. */

static ulong
max_replayed_slot( fd_bank_t const * pool,
                   ulong             bank_max ) {
  ulong max = 0UL;
  for( ulong i=0UL; i<bank_max; i++ ) {
    ulong state = FD_VOLATILE_CONST( pool[ i ].state );
    if( state!=FD_BANK_STATE_REPLAYABLE && state!=FD_BANK_STATE_FROZEN ) continue;
    max = fd_ulong_max( max, FD_VOLATILE_CONST( pool[ i ].f.slot ) );
  }
  return max;
}

static int
any_live_validator( void ) {
  fd_bootinfo_instance_t instances[ FD_BOOTINFO_INSTANCE_MAX ];
  ulong cnt = fd_bootinfo_discover( instances, FD_BOOTINFO_INSTANCE_MAX );
  for( ulong i=0UL; i<cnt; i++ ) if( instances[ i ].live ) return 1;
  return 0;
}

/* wksp_ready returns 1 if the workspace file exists, was created no
   earlier than min_ctime_nanos, and has been formatted. */

static int
wksp_ready( config_t const *       config,
            fd_topo_wksp_t const * wksp,
            long                   min_ctime_nanos ) {
  char const * mount_path;
  switch( wksp->page_sz ) {
    case FD_SHMEM_GIGANTIC_PAGE_SZ: mount_path = config->hugetlbfs.gigantic_page_mount_path; break;
    case FD_SHMEM_HUGE_PAGE_SZ:     mount_path = config->hugetlbfs.huge_page_mount_path;     break;
    default:                        mount_path = config->hugetlbfs.normal_page_mount_path;   break;
  }
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "%s/%s_%s.wksp", mount_path, config->name, wksp->name ) );

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) return 0;
  struct stat st;
  ulong magic = 0UL;
  int ready = !fstat( fd, &st ) &&
              (long)st.st_ctim.tv_sec*(long)1e9 + st.st_ctim.tv_nsec>=min_ctime_nanos &&
              pread( fd, &magic, sizeof(ulong), 0L )==(long)sizeof(ulong) &&
              magic==FD_WKSP_MAGIC;
  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return ready;
}

static void
force_mismatch_cmd_fn( args_t *   args,
                       config_t * config ) {
  long start_nanos = fd_log_wallclock();

  /* A short backtest can replay past the target within milliseconds of
     booting, so allow starting this before the validator. */
  if( FD_LIKELY( !config->has_user_config ) ) {
    FD_LOG_NOTICE(( "waiting for a running validator" ));
    while( !any_live_validator() ) fd_log_sleep( (long)1e6 );
  }

  fd_bootinfo_adopt( config );
  reconstruct_topo( config, args->force_mismatch.topo );
  fd_bootinfo_check_layout( config );

  fd_topo_t * topo = &config->topo;
  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  if( FD_UNLIKELY( banks_obj_id==ULONG_MAX ) ) FD_LOG_ERR(( "banks object not found in topology" ));
  fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ banks_obj_id ].wksp_id ];

  /* A backtest publishes no bootinfo and leaves its workspaces behind
     on exit, so unless a live validator was found, only attach to a
     workspace created after this command started. */
  long min_ctime_nanos = config->boot_timestamp_nanos ? 0L : start_nanos;
  if( min_ctime_nanos ) FD_LOG_NOTICE(( "waiting for %s_%s.wksp to be created", topo->app_name, wksp->name ));
  while( !wksp_ready( config, wksp, min_ctime_nanos ) ) fd_log_sleep( (long)1e6 );
  fd_topo_join_workspace( topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Banks are accessed raw rather than with fd_banks_join, which would
     also attach the file backed per-fork stores. */
  fd_banks_t * banks = fd_topo_obj_laddr( topo, banks_obj_id );
  while( FD_VOLATILE_CONST( banks->magic )!=FD_BANKS_MAGIC ) fd_log_sleep( (long)1e6 );
  fd_bank_t * pool     = fd_type_pun( (uchar *)banks + banks->pool_offset );
  ulong       bank_max = banks->max_total_banks;

  /* Wait for the snapshot to load so there is a replayed slot to count
     from, and to refuse a target that has already been replayed. */
  ulong replayed;
  while( !(replayed=max_replayed_slot( pool, bank_max )) ) FD_SPIN_PAUSE();

  ulong target = args->force_mismatch.at_slot;
  if( args->force_mismatch.after ) target = replayed + args->force_mismatch.after;
  if( FD_UNLIKELY( target<=replayed ) ) {
    FD_LOG_ERR(( "--at-slot %lu has already been replayed (highest replayed slot %lu)", target, replayed ));
  }
  FD_LOG_NOTICE(( "highest replayed slot %lu, injecting hard fork at slot %lu", replayed, target ));

  /* Keep every bank below the target carrying the fork until a block
     crossing the target is replayed.  Rescanning repairs banks that
     were cloned from a parent before it was patched (or rewritten by
     the snapshot loader). */
  ulong patched = 0UL;
  for(;;) {
    for( ulong i=0UL; i<bank_max; i++ ) {
      fd_bank_t * bank  = &pool[ i ];
      ulong       state = FD_VOLATILE_CONST( bank->state );
      if( state!=FD_BANK_STATE_REPLAYABLE && state!=FD_BANK_STATE_FROZEN && state!=FD_BANK_STATE_PRUNABLE ) continue;

      ulong slot = FD_VOLATILE_CONST( bank->f.slot );
      if( slot<target ) {
        if( !bank_has_fork( bank, target ) ) { bank_add_fork( bank, target ); patched++; }
        continue;
      }

      /* A prunable bank may never have been replayable, and banks past
         the first crossing are judged by their ancestor. */
      ulong parent_slot = FD_VOLATILE_CONST( bank->f.parent_slot );
      if( state==FD_BANK_STATE_PRUNABLE || parent_slot>=target ) continue;

      if( FD_UNLIKELY( !bank_has_fork( bank, target ) ) ) {
        if( state==FD_BANK_STATE_FROZEN ) {
          FD_LOG_ERR(( "slot %lu (parent %lu) froze before the hard fork could be injected", slot, parent_slot ));
        }
        /* Cloned from an unpatched parent but still executing.  The
           bank hash still picks up the fork when the bank freezes. */
        FD_LOG_WARNING(( "slot %lu (parent %lu) is already replaying, injecting late", slot, parent_slot ));
        bank_add_fork( bank, target );
        patched++;
      }

      ulong bank_seq = FD_VOLATILE_CONST( bank->bank_seq );
      FD_LOG_NOTICE(( "slot %lu (parent %lu) replays with the hard fork (%lu banks patched), waiting for it to complete", slot, parent_slot, patched ));
      while( FD_VOLATILE_CONST( bank->state )==FD_BANK_STATE_REPLAYABLE && FD_VOLATILE_CONST( bank->bank_seq )==bank_seq ) FD_SPIN_PAUSE();
      state = FD_VOLATILE_CONST( bank->state );
      if( FD_UNLIKELY( FD_VOLATILE_CONST( bank->bank_seq )!=bank_seq || (state!=FD_BANK_STATE_FROZEN && state!=FD_BANK_STATE_DEAD) ) ) {
        FD_LOG_WARNING(( "slot %lu was pruned before completing", slot ));
        return;
      }
      /* Under Alpenglow the footer check marks the mismatched block
         dead, otherwise it freezes and the mismatch surfaces later
         (backtest comparison, tower hard fork detection). */
      FD_BASE58_ENCODE_32_BYTES( bank->f.bank_hash.uc, bank_hash_b58 );
      FD_LOG_NOTICE(( "slot %lu %s with forced bank hash %s", slot, state==FD_BANK_STATE_DEAD ? "was marked dead" : "froze", bank_hash_b58 ));
      return;
    }
    FD_SPIN_PAUSE();
  }
}

static void
force_mismatch_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--at-slot", "<slot>",    "Force the mismatch on the first block at or after this absolute slot" );
  fd_action_help_arg( help, "--after",   "<slots>",   "Force the mismatch this many slots past the highest replayed slot" );
  fd_action_help_arg( help, "--topo",    "<command>", "Build the topology from another subcommand (e.g. `backtest`) instead of\n"
                                                      "the default validator topology" );
}

action_t fd_action_force_mismatch = {
  .name          = "force-mismatch",
  .args          = force_mismatch_cmd_args,
  .fn            = force_mismatch_cmd_fn,
  .perm          = NULL,
  .description   = "Force a bank hash mismatch in a running validator",
  .detail        = "Attaches to a running validator or backtest and injects a hard fork into\n"
                   "its bank state, so the first block at or after the target slot computes\n"
                   "a bank hash that disagrees with the cluster or ledger.  Exactly one of\n"
                   "--at-slot or --after must be given.",
  .usage         = "force-mismatch (--at-slot <slot> | --after <slots>) [--topo <command>]",
  .args_help     = force_mismatch_args_help,
  .is_immediate  = 0,
};
