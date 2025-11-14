#ifndef HEADER_fd_src_app_backtest_ledgers_h
#define HEADER_fd_src_app_backtest_ledgers_h

#include "../../../util/fd_util_base.h"

/* Maximum number of one-off features per ledger */
#define FD_LEDGER_MAX_FEATURES (32UL)

/* Maximum length of ledger name */
#define FD_LEDGER_NAME_MAX_LEN (64UL)

/* Maximum length of cluster version string */
#define FD_LEDGER_CLUSTER_VERSION_MAX_LEN (16UL)

/* Ledger test configuration structure */
typedef struct fd_ledger_config {
  char name[ FD_LEDGER_NAME_MAX_LEN ];                    /* Ledger name (e.g., "mainnet-257066033-v2.3.0") */
  char cluster_version[ FD_LEDGER_CLUSTER_VERSION_MAX_LEN ]; /* Cluster version (e.g., "2.3.0") */

  ulong funk_pages;                                       /* Funk heap size in pages */
  ulong index_max;                                        /* Maximum account records */
  ulong end_slot;                                         /* End slot for replay */

  int genesis;                                            /* Whether to use genesis mode (1) or entrypoints (0) */
  int has_incremental;                                    /* Whether incremental snapshots are enabled */

  /* One-off features as a null-terminated array of strings */
  char features[ FD_LEDGER_MAX_FEATURES ][ 64UL ];
  ulong features_cnt;                                     /* Number of features */

} fd_ledger_config_t;

/* Individual ledger configurations */
static const fd_ledger_config_t FD_LEDGER_TESTNET_519_V2_3_0 = {
  .name = "testnet-519-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 255312007UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257066033_V2_3_0 = {
  .name = "mainnet-257066033-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257066038UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257066844_V2_3_0 = {
  .name = "mainnet-257066844-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257066849UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257067457_V2_3_0 = {
  .name = "mainnet-257067457-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257067461UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257068890_V2_3_0 = {
  .name = "mainnet-257068890-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257068895UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257181622_V2_3_0 = {
  .name = "mainnet-257181622-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257181624UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_254462437_V2_3_0 = {
  .name = "mainnet-254462437-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 16UL,
  .index_max = 10000000UL,
  .end_slot = 254462598UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCAL_CLUSTER_V2_3_0 = {
  .name = "local-cluster-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 5010UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_262654839_V2_3_0 = {
  .name = "mainnet-262654839-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 10000000UL,
  .end_slot = 262654840UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257037451_V2_3_0 = {
  .name = "mainnet-257037451-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257037454UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257035225_V2_3_0 = {
  .name = "mainnet-257035225-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 257035233UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257465453_V2_3_0 = {
  .name = "mainnet-257465453-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 10000000UL,
  .end_slot = 257465454UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257058865_V2_3_0 = {
  .name = "mainnet-257058865-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257058870UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257059815_V2_3_0 = {
  .name = "mainnet-257059815-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257059818UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257061172_V2_3_0 = {
  .name = "mainnet-257061172-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257061175UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257222682_V2_3_0 = {
  .name = "mainnet-257222682-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257222688UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_264890264_V2_3_0 = {
  .name = "mainnet-264890264-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 264890265UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257229353_V2_3_0 = {
  .name = "mainnet-257229353-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 257229357UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257257983_V2_3_0 = {
  .name = "mainnet-257257983-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257257986UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267728520_V2_3_0 = {
  .name = "mainnet-267728520-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267728522UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267651942_V2_3_0 = {
  .name = "mainnet-267651942-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267651943UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267081197_V2_3_0 = {
  .name = "mainnet-267081197-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267081198UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267085604_V2_3_0 = {
  .name = "mainnet-267085604-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267085605UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_265688706_V2_3_0 = {
  .name = "mainnet-265688706-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 265688707UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_265330432_V2_3_0 = {
  .name = "mainnet-265330432-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 265330433UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268575190_V2_3_0 = {
  .name = "mainnet-268575190-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268575191UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268129380_V2_3_0 = {
  .name = "mainnet-268129380-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268129380UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268163043_V2_3_0 = {
  .name = "mainnet-268163043-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268163043UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_269511381_V2_3_0 = {
  .name = "mainnet-269511381-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 269511381UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_269567236_V2_3_0 = {
  .name = "mainnet-269567236-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 269567236UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_266134813_V2_3_0 = {
  .name = "mainnet-266134813-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 266134814UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_266545736_V2_3_0 = {
  .name = "mainnet-266545736-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 266545737UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267059180_V2_3_0 = {
  .name = "mainnet-267059180-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267059181UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267580466_V2_3_0 = {
  .name = "mainnet-267580466-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267580467UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268196194_V2_3_0 = {
  .name = "mainnet-268196194-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268196195UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267766641_V2_3_0 = {
  .name = "mainnet-267766641-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267766642UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_269648145_V2_3_0 = {
  .name = "mainnet-269648145-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 269648146UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_281688085_V2_3_0 = {
  .name = "testnet-281688085-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 281688086UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_277660422_V2_3_0 = {
  .name = "mainnet-277660422-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 277660423UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_277876060_V2_3_0 = {
  .name = "mainnet-277876060-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 277876061UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_277927063_V2_3_0 = {
  .name = "mainnet-277927063-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 277927065UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_281375356_V2_3_0 = {
  .name = "mainnet-281375356-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 281375359UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_251418170_V2_3_0 = {
  .name = "mainnet-251418170-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 251418233UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_282232100_V2_3_0 = {
  .name = "mainnet-282232100-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 282232101UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_282151715_V2_3_0 = {
  .name = "mainnet-282151715-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 282151717UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_286450148_V2_3_0 = {
  .name = "mainnet-286450148-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 286450151UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_EPOCH_PER_200_V2_3_0 = {
  .name = "multi-epoch-per-200-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 984UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_EPOCH_PER_300_V2_3_0 = {
  .name = "multi-epoch-per-300-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 984UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_EPOCH_PER_500_V2_3_0 = {
  .name = "multi-epoch-per-500-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 984UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_297489336_V2_3_0 = {
  .name = "testnet-297489336-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 297489363UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_300377724_V2_3_0 = {
  .name = "mainnet-300377724-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 300377728UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_300645644_V2_3_0 = {
  .name = "mainnet-300645644-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 300645644UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_300648964_V2_3_0 = {
  .name = "mainnet-300648964-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 300648964UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_301359740_V2_3_0 = {
  .name = "mainnet-301359740-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 301359740UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257181032_V2_3_0 = {
  .name = "mainnet-257181032-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257181035UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257047660_V2_3_0 = {
  .name = "mainnet-257047660-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257047662UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257047659_V2_3_0 = {
  .name = "mainnet-257047659-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257047660UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_308445707_V2_3_0 = {
  .name = "mainnet-308445707-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 308445711UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_307395181_V2_3_0 = {
  .name = "testnet-307395181-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 307395190UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_308392063_V2_3_0 = {
  .name = "mainnet-308392063-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 308392090UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_350814254_V2_3_0 = {
  .name = "devnet-350814254-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 350814284UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_311586340_V2_3_0 = {
  .name = "testnet-311586340-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 311586380UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_281546597_V2_3_0 = {
  .name = "testnet-281546597-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 281546597UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_324823213_V2_3_0 = {
  .name = "mainnet-324823213-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 324823214UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_325467935_V2_3_0 = {
  .name = "mainnet-325467935-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 325467936UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_283927487_V2_3_0 = {
  .name = "testnet-283927487-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 283927497UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_321168308_V2_3_0 = {
  .name = "testnet-321168308-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 321168308UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_327324660_V2_3_0 = {
  .name = "mainnet-327324660-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 327324660UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_370199634_V2_3_0 = {
  .name = "devnet-370199634-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 200000UL,
  .end_slot = 370199634UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_330219081_V2_3_0 = {
  .name = "mainnet-330219081-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 330219082UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_372721907_V2_3_0 = {
  .name = "devnet-372721907-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 372721910UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_331691646_V2_3_0 = {
  .name = "mainnet-331691646-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 331691647UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_378683870_V2_3_0 = {
  .name = "devnet-378683870-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 378683872UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_380592002_V2_3_0 = {
  .name = "devnet-380592002-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 380592006UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_336218682_V2_3_0 = {
  .name = "testnet-336218682-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 336218683UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_340269866_V2_3_0 = {
  .name = "testnet-340269866-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 340269872UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

// TODO: Add this ledger
static const fd_ledger_config_t FD_LEDGER_TESTNET_340272018_V2_3_0 = {
  .name = "testnet-340272018-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 340272024UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_390056400_V2_3_0 = {
  .name = "devnet-390056400-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 10UL,
  .index_max = 2000000UL,
  .end_slot = 390056406UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_346556000 = {
  .name = "testnet-346556000",
  .cluster_version = "2.3.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 346556337UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_346179946 = {
  .name = "testnet-346179946",
  .cluster_version = "2.3.0",
  .funk_pages = 30UL,
  .index_max = 90000000UL,
  .end_slot = 346179950UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_BPF_LOADER_V2_3_0 = {
  .name = "multi-bpf-loader-v2.3.0",
  .cluster_version = "2.3.0",
  .funk_pages = 1UL,
  .index_max = 1000UL,
  .end_slot = 108UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCAL_MULTI_BOUNDARY = {
  .name = "local-multi-boundary",
  .cluster_version = "2.3.0",
  .funk_pages = 1UL,
  .index_max = 1000UL,
  .end_slot = 2325UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_GENESIS_V3_0 = {
  .name = "genesis-v3.0",
  .cluster_version = "3.0.0",
  .funk_pages = 1UL,
  .index_max = 3000UL,
  .end_slot = 1280UL,
  .genesis = 1,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCALNET_STAKE_V3_0_0 = {
  .name = "localnet-stake-v3.0.0",
  .cluster_version = "3.0.0",
  .funk_pages = 1UL,
  .index_max = 3000UL,
  .end_slot = 541UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "" },
  .features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_368528500_STRICTER_ABI = {
  .name = "mainnet-368528500-stricter-abi",
  .cluster_version = "3.0.3",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 368528527UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "CxeBn9PVeeXbmjbNwLv6U4C6svNxnC4JX6mfkvgeMocM" },
  .features_cnt = 1UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_368528500_DIRECT_MAPPING = {
  .name = "mainnet-368528500-direct-mapping",
  .cluster_version = "3.0.3",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 368528527UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "CxeBn9PVeeXbmjbNwLv6U4C6svNxnC4JX6mfkvgeMocM", "9s3RKimHWS44rJcJ9P1rwCmn2TvMqtZQBmz815ZUUHqJ" },
  .features_cnt = 2UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_362107883_DIRECT_MAPPING_2 = {
  .name = "testnet-362107883-direct-mapping-2",
  .cluster_version = "3.0.3",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 362219427UL,
  .genesis = 0,
  .has_incremental = 0,
  .features = { "CxeBn9PVeeXbmjbNwLv6U4C6svNxnC4JX6mfkvgeMocM", "9s3RKimHWS44rJcJ9P1rwCmn2TvMqtZQBmz815ZUUHqJ" },
  .features_cnt = 2UL,
};

/* Array of all ledger configurations for CI testing */
#define ALL_LEDGERS \
  &FD_LEDGER_TESTNET_519_V2_3_0, \
  &FD_LEDGER_MAINNET_257066033_V2_3_0, \
  &FD_LEDGER_MAINNET_257066844_V2_3_0, \
  &FD_LEDGER_MAINNET_257067457_V2_3_0, \
  &FD_LEDGER_MAINNET_257068890_V2_3_0, \
  &FD_LEDGER_MAINNET_257181622_V2_3_0, \
  &FD_LEDGER_MAINNET_254462437_V2_3_0, \
  &FD_LEDGER_LOCAL_CLUSTER_V2_3_0, \
  &FD_LEDGER_MAINNET_262654839_V2_3_0, \
  &FD_LEDGER_MAINNET_257037451_V2_3_0, \
  &FD_LEDGER_MAINNET_257035225_V2_3_0, \
  &FD_LEDGER_MAINNET_257465453_V2_3_0, \
  &FD_LEDGER_MAINNET_257058865_V2_3_0, \
  &FD_LEDGER_MAINNET_257059815_V2_3_0, \
  &FD_LEDGER_MAINNET_257061172_V2_3_0, \
  &FD_LEDGER_MAINNET_257222682_V2_3_0, \
  &FD_LEDGER_MAINNET_264890264_V2_3_0, \
  &FD_LEDGER_MAINNET_257229353_V2_3_0, \
  &FD_LEDGER_MAINNET_257257983_V2_3_0, \
  &FD_LEDGER_MAINNET_267728520_V2_3_0, \
  &FD_LEDGER_MAINNET_267651942_V2_3_0, \
  &FD_LEDGER_MAINNET_267081197_V2_3_0, \
  &FD_LEDGER_MAINNET_267085604_V2_3_0, \
  &FD_LEDGER_MAINNET_265688706_V2_3_0, \
  &FD_LEDGER_MAINNET_265330432_V2_3_0, \
  &FD_LEDGER_MAINNET_268575190_V2_3_0, \
  &FD_LEDGER_MAINNET_268129380_V2_3_0, \
  &FD_LEDGER_MAINNET_268163043_V2_3_0, \
  &FD_LEDGER_MAINNET_269511381_V2_3_0, \
  &FD_LEDGER_MAINNET_269567236_V2_3_0, \
  &FD_LEDGER_MAINNET_266134813_V2_3_0, \
  &FD_LEDGER_MAINNET_266545736_V2_3_0, \
  &FD_LEDGER_MAINNET_267059180_V2_3_0, \
  &FD_LEDGER_MAINNET_267580466_V2_3_0, \
  &FD_LEDGER_MAINNET_268196194_V2_3_0, \
  &FD_LEDGER_MAINNET_267766641_V2_3_0, \
  &FD_LEDGER_MAINNET_269648145_V2_3_0, \
  &FD_LEDGER_TESTNET_281688085_V2_3_0, \
  &FD_LEDGER_MAINNET_277660422_V2_3_0, \
  &FD_LEDGER_MAINNET_277876060_V2_3_0, \
  &FD_LEDGER_MAINNET_277927063_V2_3_0, \
  &FD_LEDGER_MAINNET_281375356_V2_3_0, \
  &FD_LEDGER_MAINNET_251418170_V2_3_0, \
  &FD_LEDGER_MAINNET_282232100_V2_3_0, \
  &FD_LEDGER_MAINNET_282151715_V2_3_0, \
  &FD_LEDGER_MAINNET_286450148_V2_3_0, \
  &FD_LEDGER_MULTI_EPOCH_PER_200_V2_3_0, \
  &FD_LEDGER_MULTI_EPOCH_PER_300_V2_3_0, \
  &FD_LEDGER_MULTI_EPOCH_PER_500_V2_3_0, \
  &FD_LEDGER_TESTNET_297489336_V2_3_0, \
  &FD_LEDGER_MAINNET_300377724_V2_3_0, \
  &FD_LEDGER_MAINNET_300645644_V2_3_0, \
  &FD_LEDGER_MAINNET_300648964_V2_3_0, \
  &FD_LEDGER_MAINNET_301359740_V2_3_0, \
  &FD_LEDGER_MAINNET_257181032_V2_3_0, \
  &FD_LEDGER_MAINNET_257047660_V2_3_0, \
  &FD_LEDGER_MAINNET_257047659_V2_3_0, \
  &FD_LEDGER_MAINNET_308445707_V2_3_0, \
  &FD_LEDGER_TESTNET_307395181_V2_3_0, \
  &FD_LEDGER_MAINNET_308392063_V2_3_0, \
  &FD_LEDGER_DEVNET_350814254_V2_3_0, \
  &FD_LEDGER_TESTNET_311586340_V2_3_0, \
  &FD_LEDGER_TESTNET_281546597_V2_3_0, \
  &FD_LEDGER_MAINNET_324823213_V2_3_0, \
  &FD_LEDGER_MAINNET_325467935_V2_3_0, \
  &FD_LEDGER_TESTNET_283927487_V2_3_0, \
  &FD_LEDGER_TESTNET_321168308_V2_3_0, \
  &FD_LEDGER_MAINNET_327324660_V2_3_0, \
  &FD_LEDGER_DEVNET_370199634_V2_3_0, \
  &FD_LEDGER_MAINNET_330219081_V2_3_0, \
  &FD_LEDGER_DEVNET_372721907_V2_3_0, \
  &FD_LEDGER_MAINNET_331691646_V2_3_0, \
  &FD_LEDGER_DEVNET_378683870_V2_3_0, \
  &FD_LEDGER_DEVNET_380592002_V2_3_0, \
  &FD_LEDGER_TESTNET_336218682_V2_3_0, \
  &FD_LEDGER_TESTNET_340269866_V2_3_0, \
  &FD_LEDGER_DEVNET_390056400_V2_3_0, \
  &FD_LEDGER_TESTNET_346556000, \
  &FD_LEDGER_TESTNET_346179946, \
  &FD_LEDGER_MULTI_BPF_LOADER_V2_3_0, \
  &FD_LEDGER_LOCAL_MULTI_BOUNDARY, \
  &FD_LEDGER_GENESIS_V3_0, \
  &FD_LEDGER_LOCALNET_STAKE_V3_0_0, \
  &FD_LEDGER_MAINNET_368528500_STRICTER_ABI, \
  &FD_LEDGER_MAINNET_368528500_DIRECT_MAPPING, \
  &FD_LEDGER_TESTNET_362107883_DIRECT_MAPPING_2


/* Array of ledger configurations specifically for CI testing (from run_backtest_ci.sh) */
#define CI_LEDGERS \
  &FD_LEDGER_MAINNET_308392063_V2_3_0, \
  &FD_LEDGER_DEVNET_350814254_V2_3_0, \
  &FD_LEDGER_TESTNET_281546597_V2_3_0, \
  &FD_LEDGER_MAINNET_324823213_V2_3_0, \
  &FD_LEDGER_MAINNET_325467935_V2_3_0, \
  &FD_LEDGER_TESTNET_283927487_V2_3_0, \
  &FD_LEDGER_TESTNET_321168308_V2_3_0, \
  &FD_LEDGER_MAINNET_327324660_V2_3_0, \
  &FD_LEDGER_DEVNET_370199634_V2_3_0, \
  &FD_LEDGER_DEVNET_378683870_V2_3_0, \
  &FD_LEDGER_MAINNET_330219081_V2_3_0, \
  &FD_LEDGER_DEVNET_372721907_V2_3_0, \
  &FD_LEDGER_MAINNET_331691646_V2_3_0, \
  &FD_LEDGER_TESTNET_336218682_V2_3_0, \
  &FD_LEDGER_TESTNET_340269866_V2_3_0, \
  &FD_LEDGER_DEVNET_390056400_V2_3_0, \
  &FD_LEDGER_MAINNET_254462437_V2_3_0, \
  &FD_LEDGER_MULTI_EPOCH_PER_200_V2_3_0, \
  &FD_LEDGER_TESTNET_346556000, \
  &FD_LEDGER_MULTI_BPF_LOADER_V2_3_0, \
  &FD_LEDGER_DEVNET_380592002_V2_3_0, \
  &FD_LEDGER_LOCAL_MULTI_BOUNDARY, \
  &FD_LEDGER_GENESIS_V3_0, \
  &FD_LEDGER_LOCALNET_STAKE_V3_0_0, \
  &FD_LEDGER_MAINNET_368528500_STRICTER_ABI, \
  &FD_LEDGER_MAINNET_368528500_DIRECT_MAPPING, \
  &FD_LEDGER_TESTNET_362107883_DIRECT_MAPPING_2

/* Total number of ledger configurations */
#define FD_LEDGER_CONFIG_COUNT (86UL)

/* Total number of CI ledger configurations */
#define FD_LEDGER_CI_CONFIG_COUNT (27UL)

/* Array declaration for easy iteration */
static const fd_ledger_config_t * const fd_ledger_configs[ FD_LEDGER_CONFIG_COUNT + 1UL ] = {
  ALL_LEDGERS,
  NULL
};

/* Array declaration for CI ledger iteration */
static const fd_ledger_config_t * const fd_ledgers_ci_configs[ FD_LEDGER_CI_CONFIG_COUNT + 1UL ] = {
  CI_LEDGERS,
  NULL
};

/* Helper function to find a ledger configuration by name */
static inline fd_ledger_config_t const *
fd_ledger_config_find( char const * name ) {
  for( ulong i = 0UL; i < FD_LEDGER_CONFIG_COUNT; i++ ) {
    if( !strcmp( fd_ledger_configs[ i ]->name, name ) ) {
      return fd_ledger_configs[ i ];
    }
  }
  return NULL;
}

/* Helper function to get ledger configuration by index */
static inline fd_ledger_config_t const *
fd_ledger_config_get( ulong idx ) {
  if( FD_UNLIKELY( idx >= FD_LEDGER_CONFIG_COUNT ) ) return NULL;
  return fd_ledger_configs[ idx ];
}

#endif /* HEADER_fd_src_app_backtest_ledgers_h */
