#include "../firedancer/topology.h"
#include "../firedancer/config.h"
#include "../shared_dev/boot/fd_dev_boot.h"
#include "../shared/fd_action.h"
#include "../shared/commands/configure/configure.h"
#include "main.h"
#include "ledgers.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

/* Forward declarations */
void backtest_topo_initialize( config_t * config );
void backtest_set_ledger_name( char const * ledger_name );
void backtest_create_custom_config_from_args( int argc, char ** argv );
void backtest_set_custom_config( fd_ledger_config_t * config );
void backtest_clear_custom_config( void );

char const * FD_APP_NAME    = "Firedancer";
char const * FD_BINARY_NAME = "backtest";

extern fd_topo_obj_callbacks_t fd_obj_cb_mcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_dcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_fseq;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_opaque;
extern fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf;
extern fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap;
extern fd_topo_obj_callbacks_t fd_obj_cb_fib4;
extern fd_topo_obj_callbacks_t fd_obj_cb_keyswitch;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;
extern fd_topo_obj_callbacks_t fd_obj_cb_store;
extern fd_topo_obj_callbacks_t fd_obj_cb_fec_sets;
extern fd_topo_obj_callbacks_t fd_obj_cb_txncache;
extern fd_topo_obj_callbacks_t fd_obj_cb_banks;
extern fd_topo_obj_callbacks_t fd_obj_cb_funk;
extern fd_topo_obj_callbacks_t fd_obj_cb_bank_hash_cmp;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_mcache,
  &fd_obj_cb_dcache,
  &fd_obj_cb_fseq,
  &fd_obj_cb_metrics,
  &fd_obj_cb_opaque,
  &fd_obj_cb_dbl_buf,
  &fd_obj_cb_neigh4_hmap,
  &fd_obj_cb_fib4,
  &fd_obj_cb_keyswitch,
  &fd_obj_cb_tile,
  &fd_obj_cb_store,
  &fd_obj_cb_fec_sets,
  &fd_obj_cb_txncache,
  &fd_obj_cb_banks,
  &fd_obj_cb_funk,
  &fd_obj_cb_bank_hash_cmp,
  NULL,
};

configure_stage_t * STAGES[] = {
  &fd_cfg_stage_kill,
  &fd_cfg_stage_netns,
  &fd_cfg_stage_hugetlbfs,
  &fd_cfg_stage_sysctl,
  &fd_cfg_stage_ethtool_channels,
  &fd_cfg_stage_ethtool_offloads,
  &fd_cfg_stage_ethtool_loopback,
  &fd_cfg_stage_keys,
  &fd_cfg_stage_genesis,
  &fd_cfg_stage_snapshots,
  NULL,
};

extern fd_topo_run_tile_t fd_tile_net;
extern fd_topo_run_tile_t fd_tile_netlnk;
extern fd_topo_run_tile_t fd_tile_sock;
extern fd_topo_run_tile_t fd_tile_quic;
extern fd_topo_run_tile_t fd_tile_verify;
extern fd_topo_run_tile_t fd_tile_dedup;
extern fd_topo_run_tile_t fd_tile_resolv;
extern fd_topo_run_tile_t fd_tile_pack;
extern fd_topo_run_tile_t fd_tile_bank;
extern fd_topo_run_tile_t fd_tile_poh;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_metric;
extern fd_topo_run_tile_t fd_tile_cswtch;
extern fd_topo_run_tile_t fd_tile_gui;
extern fd_topo_run_tile_t fd_tile_rpc;
extern fd_topo_run_tile_t fd_tile_plugin;
extern fd_topo_run_tile_t fd_tile_bencho;
extern fd_topo_run_tile_t fd_tile_benchg;
extern fd_topo_run_tile_t fd_tile_benchs;
extern fd_topo_run_tile_t fd_tile_bundle;
extern fd_topo_run_tile_t fd_tile_pktgen;
extern fd_topo_run_tile_t fd_tile_udpecho;
extern fd_topo_run_tile_t fd_tile_genesi;
extern fd_topo_run_tile_t fd_tile_ipecho;

extern fd_topo_run_tile_t fd_tile_gossvf;
extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_repair;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_execor;
extern fd_topo_run_tile_t fd_tile_send;
extern fd_topo_run_tile_t fd_tile_tower;
extern fd_topo_run_tile_t fd_tile_backtest;
extern fd_topo_run_tile_t fd_tile_archiver_feeder;
extern fd_topo_run_tile_t fd_tile_archiver_writer;
extern fd_topo_run_tile_t fd_tile_archiver_playback;
extern fd_topo_run_tile_t fd_tile_shredcap;

extern fd_topo_run_tile_t fd_tile_snapct;
extern fd_topo_run_tile_t fd_tile_snapld;
extern fd_topo_run_tile_t fd_tile_snapdc;
extern fd_topo_run_tile_t fd_tile_snapin;

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_net,
  &fd_tile_netlnk,
  &fd_tile_sock,
  &fd_tile_quic,
  &fd_tile_verify,
  &fd_tile_dedup,
  &fd_tile_resolv,
  &fd_tile_pack,
  &fd_tile_bank,
  &fd_tile_shred,
  &fd_tile_sign,
  &fd_tile_metric,
  &fd_tile_cswtch,
  &fd_tile_gui,
  &fd_tile_rpc,
  &fd_tile_plugin,
  &fd_tile_bencho,
  &fd_tile_benchg,
  &fd_tile_benchs,
  &fd_tile_bundle,
  &fd_tile_gossvf,
  &fd_tile_gossip,
  &fd_tile_repair,
  &fd_tile_replay,
  &fd_tile_execor,
  &fd_tile_poh,
  &fd_tile_send,
  &fd_tile_tower,
  &fd_tile_archiver_feeder,
  &fd_tile_archiver_writer,
  &fd_tile_archiver_playback,
  &fd_tile_shredcap,
#if FD_HAS_ROCKSDB
  &fd_tile_backtest,
#endif
  &fd_tile_bencho,
  &fd_tile_benchg,
  &fd_tile_benchs,
  &fd_tile_pktgen,
  &fd_tile_udpecho,
  &fd_tile_snapct,
  &fd_tile_snapld,
  &fd_tile_snapdc,
  &fd_tile_snapin,
  &fd_tile_genesi,
  &fd_tile_ipecho,
  NULL,
};


extern action_t fd_action_help;
extern action_t fd_action_version;
extern action_t fd_action_backtest;

action_t * ACTIONS[] = {
  &fd_action_help,
  &fd_action_version,
  &fd_action_backtest,
  NULL,
};

int
main( int     argc,
      char ** argv ) {
  fd_config_file_t _default = fd_config_file_default();
  fd_config_file_t testnet = fd_config_file_testnet();
  fd_config_file_t devnet = fd_config_file_devnet();
  fd_config_file_t mainnet = fd_config_file_mainnet();

  fd_config_file_t * configs[] = {
    &_default,
    &testnet,
    &devnet,
    &mainnet,
    NULL
  };

  // Always insert "backtest" as the first argument since this is the backtest binary
  char ** new_argv = malloc( (ulong)(argc + 2) * sizeof(char*) );
  if( !new_argv ) {
    fprintf( stderr, "Failed to allocate memory\n" );
    return 1;
  }

  new_argv[0] = argv[0];
  new_argv[1] = "backtest";
  for( int i = 1; i < argc; i++ ) {
    new_argv[i + 1] = argv[i];
  }
  new_argv[argc + 1] = NULL;

  // Check for --ci flag
  int ci_mode = 0;
  for( int i = 1; i < argc; i++ ) {
    if( strcmp( argv[i], "--ci" ) == 0 ) {
      ci_mode = 1;
      break;
    }
  }

  // Check if we should run all ledgers or just a specific one
  if( argc > 1 && !ci_mode ) {
    // Check if the first argument is a flag (starts with --)
    if( strncmp( argv[1], "--", 2 ) == 0 ) {
      // First argument is a flag, not a ledger name
      // Don't set ledger name, let the normal flow handle it
      int result = fd_dev_main( argc + 1, new_argv, 1, configs, backtest_topo_initialize );
      free( new_argv );
      return result;
    } else if( argc > 2 && strcmp( argv[1], "backtest" ) == 0 ) {
      // Second run: ledger name is in argv[2], but check if it's a flag
      if( strncmp( argv[2], "--", 2 ) == 0 ) {
        // Don't set ledger name if it's a flag
      } else {
        backtest_set_ledger_name( argv[2] );
        // Check for custom configuration flags
        backtest_create_custom_config_from_args( argc, argv );
      }
    } else {
      // First run: ledger name is in argv[1]
      backtest_set_ledger_name( argv[1] );
      // Check for custom configuration flags
      backtest_create_custom_config_from_args( argc, argv );
    }

    // Run specific ledger - use normal flow
    int result = fd_dev_main( argc + 1, new_argv, 1, configs, backtest_topo_initialize );
    free( new_argv );
    return result;
  } else {
    // No ledger name provided or --ci flag - run ledgers by spawning child processes
    if( ci_mode ) {
      printf("Running CI ledgers one by one:\n");
    } else {
      printf("Running all available ledgers one by one:\n");
    }

    // Get the current executable path
    char exe_path[1024];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if( len == -1 ) {
      fprintf(stderr, "Failed to get executable path\n");
      free( new_argv );
      return 1;
    }
    exe_path[len] = '\0';

    // Choose which ledger set to use
    const char* ledgers[FD_LEDGER_CONFIG_COUNT];
    ulong ledger_count;
    if( ci_mode ) {
      // Use CI ledgers
      ledger_count = FD_LEDGER_CI_CONFIG_COUNT;
      for( ulong i=0; i<ledger_count && i<FD_LEDGER_CONFIG_COUNT; i++ ) {
        if( fd_ledgers_ci_configs[i] != NULL ) {
          ledgers[i] = fd_ledgers_ci_configs[i]->name;
        } else {
          ledgers[i] = "unknown";
        }
      }
    } else {
      // Use all ledgers
      ledger_count = FD_LEDGER_CONFIG_COUNT;
      for( ulong i=0; i<ledger_count; i++ ) {
        if( fd_ledger_configs[i] != NULL ) {
          ledgers[i] = fd_ledger_configs[i]->name;
        } else {
          ledgers[i] = "unknown";
        }
      }
    }

    ulong failed_count = 0;

    // Start timing for CI mode
    struct timespec ci_start_time, ci_end_time;
    clock_gettime( CLOCK_MONOTONIC, &ci_start_time );

    for( ulong i = 0; i < ledger_count; i++ ) {
      printf("Running backtest %lu/%lu: %s\n", i + 1, ledger_count, ledgers[i]);

      // Prepare arguments for the child process
      char * child_argv[4];
      child_argv[0] = exe_path;
      child_argv[1] = (char *)ledgers[i];
      child_argv[2] = "--no-watch";
      child_argv[3] = NULL;

      // Spawn child process
      pid_t pid = fork();
      if( pid == 0 ) {
        // Child process
        execv( exe_path, child_argv );
        fprintf(stderr, "Failed to exec backtest for ledger %s\n", ledgers[i]);
        exit( 1 );
      } else if( pid > 0 ) {
        // Parent process - wait for child to complete
        int status;
        waitpid( pid, &status, 0 );
        if( WIFEXITED( status ) ) {
          int exit_code = WEXITSTATUS( status );
          if( exit_code == 0 ) {
            printf("✅ Backtest completed successfully for ledger: %s\n", ledgers[i]);
          } else {
            printf("❌ Backtest failed for ledger %s with exit code %d\n", ledgers[i], exit_code);
            failed_count++;
          }
        } else {
          printf("❌ Backtest process for ledger %s was terminated abnormally\n", ledgers[i]);
          failed_count++;
        }
      } else {
        printf("❌ Failed to fork process for ledger %s\n", ledgers[i]);
        failed_count++;
      }
    }

    // End timing for CI mode and display results
    clock_gettime( CLOCK_MONOTONIC, &ci_end_time );

    long elapsed_seconds = ci_end_time.tv_sec - ci_start_time.tv_sec;
    long elapsed_nanoseconds = ci_end_time.tv_nsec - ci_start_time.tv_nsec;

    if( elapsed_nanoseconds < 0 ) {
      elapsed_seconds--;
      elapsed_nanoseconds += 1000000000L;
    }

    double elapsed_seconds_double = (double)elapsed_seconds + (double)elapsed_nanoseconds / 1000000000.0;

    printf("⏱️  Backtest suite completed in %.3f seconds (%lu ledgers)\n", elapsed_seconds_double, ledger_count );

    printf("Completed running all ledgers: %lu/%lu successful, %lu failed\n",
           ledger_count - failed_count, ledger_count, failed_count);

    free( new_argv );
    return failed_count > 0 ? 1 : 0;
  }
}

/* Function to create custom ledger configuration from command-line arguments */
void
backtest_create_custom_config_from_args( int argc, char ** argv ) {
  /* Skip custom configuration creation if this is a child process (has --no-watch) */
  for( int i = 1; i < argc; i++ ) {
    if( strcmp( argv[i], "--no-watch" ) == 0 ) {
      backtest_clear_custom_config(); /* Clear any inherited custom config */
      return; /* This is a child process, skip custom config creation */
    }
  }

  /* Check if any custom configuration flags were provided */
  int has_custom_flags = 0;
  for( int i = 1; i < argc; i++ ) {
    if( strcmp( argv[i], "--genesis" ) == 0 ||
        strcmp( argv[i], "--has-incremental" ) == 0 ||
        strcmp( argv[i], "--redownload" ) == 0 ||
        strcmp( argv[i], "--skip-checksum" ) == 0 ||
        strncmp( argv[i], "--cluster-version", 16 ) == 0 ||
        strncmp( argv[i], "--funk-pages", 12 ) == 0 ||
        strncmp( argv[i], "--index-max", 11 ) == 0 ||
        strncmp( argv[i], "--end-slot", 10 ) == 0 ||
        strncmp( argv[i], "--trash-hash", 12 ) == 0 ||
        strncmp( argv[i], "--restore-archive", 17 ) == 0 ||
        strncmp( argv[i], "--one-offs", 10 ) == 0 ) {
      has_custom_flags = 1;
      break;
    }
  }

  if( has_custom_flags ) {
    printf("NOTICE: Custom configuration flags detected. Creating custom ledger configuration.\n");

    /* Create custom configuration */
    fd_ledger_config_t custom_config = {0};

    /* Set the ledger name (should be the first non-flag argument, but skip "backtest" if present) */
    for( int i = 1; i < argc; i++ ) {
      if( strncmp( argv[i], "--", 2 ) != 0 && strcmp( argv[i], "backtest" ) != 0 ) {
        snprintf( custom_config.name, FD_LEDGER_NAME_MAX_LEN, "%s", argv[i] );
        break;
      }
    }

    /* Parse flags and set configuration */
    for( int i = 1; i < argc; i++ ) {
      if( strcmp( argv[i], "--genesis" ) == 0 ) {
        custom_config.genesis = 1;
      } else if( strcmp( argv[i], "--has-incremental" ) == 0 ) {
        custom_config.has_incremental = 1;
      } else if( strncmp( argv[i], "--cluster-version", 16 ) == 0 && i + 1 < argc ) {
        snprintf( custom_config.cluster_version, FD_LEDGER_CLUSTER_VERSION_MAX_LEN, "%s", argv[i + 1] );
        i++; /* Skip the value */
      } else if( strncmp( argv[i], "--funk-pages", 12 ) == 0 && i + 1 < argc ) {
        custom_config.funk_pages = (ulong)strtoul( argv[i + 1], NULL, 10 );
        i++; /* Skip the value */
      } else if( strncmp( argv[i], "--index-max", 11 ) == 0 && i + 1 < argc ) {
        custom_config.index_max = (ulong)strtoul( argv[i + 1], NULL, 10 );
        i++; /* Skip the value */
      } else if( strncmp( argv[i], "--end-slot", 10 ) == 0 && i + 1 < argc ) {
        custom_config.end_slot = (ulong)strtoul( argv[i + 1], NULL, 10 );
        i++; /* Skip the value */
      } else if( strncmp( argv[i], "--one-offs", 10 ) == 0 && i + 1 < argc ) {
        /* Add single one-off feature to the list */
        if( custom_config.features_cnt < FD_LEDGER_MAX_FEATURES ) {
          /* Trim whitespace */
          char * feature = argv[i + 1];
          while( *feature == ' ' || *feature == '\t' ) feature++;
          char * end = feature + strlen(feature) - 1;
          while( end > feature && (*end == ' ' || *end == '\t') ) end--;
          *(end + 1) = '\0';

          /* Copy feature name */
          snprintf( custom_config.features[custom_config.features_cnt], 64UL, "%s", feature );
          custom_config.features_cnt++;
        }
        i++; /* Skip the value */
      }
    }

    /* Set defaults for unspecified values */
    if( custom_config.cluster_version[0] == '\0' ) {
      snprintf( custom_config.cluster_version, FD_LEDGER_CLUSTER_VERSION_MAX_LEN, "mainnet" );
    }
    if( custom_config.funk_pages == 0 ) {
      custom_config.funk_pages = 1UL;
    }

    /* Set the custom configuration */
    backtest_set_custom_config( &custom_config );
  }
}
