#ifndef HEADER_fd_src_flamenco_runtime_tests_ledgers_h
#define HEADER_fd_src_flamenco_runtime_tests_ledgers_h

#include "../../../util/fd_util_base.h"

/* Maximum number of one-off features per ledger */
#define FD_LEDGER_MAX_FEATURES (32UL)

/* Maximum length of ledger name */
#define FD_LEDGER_NAME_MAX_LEN (64UL)

typedef struct fd_ledger_config {
  char  test_name[ FD_LEDGER_NAME_MAX_LEN ];
  char  ledger_name[ FD_LEDGER_NAME_MAX_LEN ];
  ulong funk_pages;
  ulong index_max;
  ulong end_slot;
  int   genesis;
  int   has_incremental;
  int   vinyl;
  char  enable_features[ FD_LEDGER_MAX_FEATURES ][ 64UL ];
  ulong enable_features_cnt;
} fd_ledger_config_t;

static const fd_ledger_config_t FD_LEDGER_TESTNET_519_V3_0_0 = {
  .test_name = "testnet-519-v3.0.0",
  .ledger_name = "testnet-519-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 255312007UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_519_V3_0_0_VINYL = {
  .test_name = "testnet-519-v3.0.0-vinyl",
  .ledger_name = "testnet-519-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 255312007UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257066033_V3_0_0 = {
  .test_name = "mainnet-257066033-v3.0.0",
  .ledger_name = "mainnet-257066033-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257066038UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257066844_V3_0_0 = {
  .test_name = "mainnet-257066844-v3.0.0",
  .ledger_name = "mainnet-257066844-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257066849UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257067457_V3_0_0 = {
  .test_name = "mainnet-257067457-v3.0.0",
  .ledger_name = "mainnet-257067457-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257067461UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257068890_V3_0_0 = {
  .test_name = "mainnet-257068890-v3.0.0",
  .ledger_name = "mainnet-257068890-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257068895UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257181622_V3_0_0 = {
  .test_name = "mainnet-257181622-v3.0.0",
  .ledger_name = "mainnet-257181622-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257181624UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_254462437_V3_0_0 = {
  .test_name = "mainnet-254462437-v3.0.0",
  .ledger_name = "mainnet-254462437-v3.0.0",
  .funk_pages = 16UL,
  .index_max = 10000000UL,
  .end_slot = 254462598UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_262654839_V3_0_0 = {
  .test_name = "mainnet-262654839-v3.0.0",
  .ledger_name = "mainnet-262654839-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 10000000UL,
  .end_slot = 262654840UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257037451_V3_0_0 = {
  .test_name = "mainnet-257037451-v3.0.0",
  .ledger_name = "mainnet-257037451-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257037454UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257035225_V3_0_0 = {
  .test_name = "mainnet-257035225-v3.0.0",
  .ledger_name = "mainnet-257035225-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 257035233UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257465453_V3_0_0 = {
  .test_name = "mainnet-257465453-v3.0.0",
  .ledger_name = "mainnet-257465453-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 10000000UL,
  .end_slot = 257465454UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257058865_V3_0_0 = {
  .test_name = "mainnet-257058865-v3.0.0",
  .ledger_name = "mainnet-257058865-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257058870UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257059815_V3_0_0 = {
  .test_name = "mainnet-257059815-v3.0.0",
  .ledger_name = "mainnet-257059815-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257059818UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257061172_V3_0_0 = {
  .test_name = "mainnet-257061172-v3.0.0",
  .ledger_name = "mainnet-257061172-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257061175UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257222682_V3_0_0 = {
  .test_name = "mainnet-257222682-v3.0.0",
  .ledger_name = "mainnet-257222682-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257222688UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_264890264_V3_0_0 = {
  .test_name = "mainnet-264890264-v3.0.0",
  .ledger_name = "mainnet-264890264-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 264890265UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257229353_V3_0_0 = {
  .test_name = "mainnet-257229353-v3.0.0",
  .ledger_name = "mainnet-257229353-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 257229357UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257257983_V3_0_0 = {
  .test_name = "mainnet-257257983-v3.0.0",
  .ledger_name = "mainnet-257257983-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257257986UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267728520_V3_0_0 = {
  .test_name = "mainnet-267728520-v3.0.0",
  .ledger_name = "mainnet-267728520-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267728522UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267651942_V3_0_0 = {
  .test_name = "mainnet-267651942-v3.0.0",
  .ledger_name = "mainnet-267651942-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267651943UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267081197_V3_0_0 = {
  .test_name = "mainnet-267081197-v3.0.0",
  .ledger_name = "mainnet-267081197-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267081198UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267085604_V3_0_0 = {
  .test_name = "mainnet-267085604-v3.0.0",
  .ledger_name = "mainnet-267085604-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267085605UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_265688706_V3_0_0 = {
  .test_name = "mainnet-265688706-v3.0.0",
  .ledger_name = "mainnet-265688706-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 265688707UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_265688706_V3_0_0_VINYL = {
  .test_name = "mainnet-265688706-v3.0.0-vinyl",
  .ledger_name = "mainnet-265688706-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 265688707UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_265330432_V3_0_0 = {
  .test_name = "mainnet-265330432-v3.0.0",
  .ledger_name = "mainnet-265330432-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 265330433UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268575190_V3_0_0 = {
  .test_name = "mainnet-268575190-v3.0.0",
  .ledger_name = "mainnet-268575190-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268575191UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268129380_V3_0_0 = {
  .test_name = "mainnet-268129380-v3.0.0",
  .ledger_name = "mainnet-268129380-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268129380UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268163043_V3_0_0 = {
  .test_name = "mainnet-268163043-v3.0.0",
  .ledger_name = "mainnet-268163043-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268163043UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_269511381_V3_0_0 = {
  .test_name = "mainnet-269511381-v3.0.0",
  .ledger_name = "mainnet-269511381-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 269511381UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_269567236_V3_0_0 = {
  .test_name = "mainnet-269567236-v3.0.0",
  .ledger_name = "mainnet-269567236-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 269567236UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_266134813_V3_0_0 = {
  .test_name = "mainnet-266134813-v3.0.0",
  .ledger_name = "mainnet-266134813-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 266134814UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_266545736_V3_0_0 = {
  .test_name = "mainnet-266545736-v3.0.0",
  .ledger_name = "mainnet-266545736-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 266545737UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267059180_V3_0_0 = {
  .test_name = "mainnet-267059180-v3.0.0",
  .ledger_name = "mainnet-267059180-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267059181UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267580466_V3_0_0 = {
  .test_name = "mainnet-267580466-v3.0.0",
  .ledger_name = "mainnet-267580466-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267580467UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_268196194_V3_0_0 = {
  .test_name = "mainnet-268196194-v3.0.0",
  .ledger_name = "mainnet-268196194-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 268196195UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_267766641_V3_0_0 = {
  .test_name = "mainnet-267766641-v3.0.0",
  .ledger_name = "mainnet-267766641-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 267766642UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_269648145_V3_0_0 = {
  .test_name = "mainnet-269648145-v3.0.0",
  .ledger_name = "mainnet-269648145-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 269648146UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_281688085_V3_0_0 = {
  .test_name = "testnet-281688085-v3.0.0",
  .ledger_name = "testnet-281688085-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 281688086UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_277660422_V3_0_0 = {
  .test_name = "mainnet-277660422-v3.0.0",
  .ledger_name = "mainnet-277660422-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 277660423UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_277876060_V3_0_0 = {
  .test_name = "mainnet-277876060-v3.0.0",
  .ledger_name = "mainnet-277876060-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 277876061UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_277927063_V3_0_0 = {
  .test_name = "mainnet-277927063-v3.0.0",
  .ledger_name = "mainnet-277927063-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 277927065UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_281375356_V3_0_0 = {
  .test_name = "mainnet-281375356-v3.0.0",
  .ledger_name = "mainnet-281375356-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 281375359UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_251418170_V3_0_0 = {
  .test_name = "mainnet-251418170-v3.0.0",
  .ledger_name = "mainnet-251418170-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 251418233UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_282232100_V3_0_0 = {
  .test_name = "mainnet-282232100-v3.0.0",
  .ledger_name = "mainnet-282232100-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 282232101UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_282151715_V3_0_0 = {
  .test_name = "mainnet-282151715-v3.0.0",
  .ledger_name = "mainnet-282151715-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 282151717UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_286450148_V3_0_0 = {
  .test_name = "mainnet-286450148-v3.0.0",
  .ledger_name = "mainnet-286450148-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 286450151UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_EPOCH_PER_200_V3_0_0 = {
  .test_name = "multi-epoch-per-200-v3.0.0",
  .ledger_name = "multi-epoch-per-200-v3.0.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 984UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_EPOCH_PER_300_V3_0_0 = {
  .test_name = "multi-epoch-per-300-v3.0.0",
  .ledger_name = "multi-epoch-per-300-v3.0.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 984UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_EPOCH_PER_500_V3_0_0 = {
  .test_name = "multi-epoch-per-500-v3.0.0",
  .ledger_name = "multi-epoch-per-500-v3.0.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 984UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_EPOCH_PER_500_V3_0_0_VINYL = {
  .test_name = "multi-epoch-per-500-v3.0.0-vinyl",
  .ledger_name = "multi-epoch-per-500-v3.0.0",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 984UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_297489336_V3_0_0 = {
  .test_name = "testnet-297489336-v3.0.0",
  .ledger_name = "testnet-297489336-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 297489363UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_300377724_V3_0_0 = {
  .test_name = "mainnet-300377724-v3.0.0",
  .ledger_name = "mainnet-300377724-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 300377728UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_300645644_V3_0_0 = {
  .test_name = "mainnet-300645644-v3.0.0",
  .ledger_name = "mainnet-300645644-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 300645644UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_300648964_V3_0_0 = {
  .test_name = "mainnet-300648964-v3.0.0",
  .ledger_name = "mainnet-300648964-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 300648964UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_301359740_V3_0_0 = {
  .test_name = "mainnet-301359740-v3.0.0",
  .ledger_name = "mainnet-301359740-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 301359740UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257181032_V3_0_0 = {
  .test_name = "mainnet-257181032-v3.0.0",
  .ledger_name = "mainnet-257181032-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257181035UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257047660_V3_0_0 = {
  .test_name = "mainnet-257047660-v3.0.0",
  .ledger_name = "mainnet-257047660-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257047662UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_257047659_V3_0_0 = {
  .test_name = "mainnet-257047659-v3.0.0",
  .ledger_name = "mainnet-257047659-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 257047660UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_308445707_V3_0_0 = {
  .test_name = "mainnet-308445707-v3.0.0",
  .ledger_name = "mainnet-308445707-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 308445711UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_307395181_V3_0_0 = {
  .test_name = "testnet-307395181-v3.0.0",
  .ledger_name = "testnet-307395181-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 307395190UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_308392063_V3_0_0 = {
  .test_name = "mainnet-308392063-v3.0.0",
  .ledger_name = "mainnet-308392063-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 308392090UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_308392063_V3_0_0_VINYL = {
  .test_name = "mainnet-308392063-v3.0.0-vinyl",
  .ledger_name = "mainnet-308392063-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 308392090UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_350814254_V3_0_0 = {
  .test_name = "devnet-350814254-v3.0.0",
  .ledger_name = "devnet-350814254-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 350814284UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_350814254_V3_0_0_VINYL = {
  .test_name = "devnet-350814254-v3.0.0-vinyl",
  .ledger_name = "devnet-350814254-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 350814284UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_311586340_V3_0_0 = {
  .test_name = "testnet-311586340-v3.0.0",
  .ledger_name = "testnet-311586340-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 311586380UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_281546597_V3_0_0 = {
  .test_name = "testnet-281546597-v3.0.0",
  .ledger_name = "testnet-281546597-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 281546597UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_281546597_V3_0_0_VINYL = {
  .test_name = "testnet-281546597-v3.0.0-vinyl",
  .ledger_name = "testnet-281546597-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 281546597UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_324823213_V3_0_0 = {
  .test_name = "mainnet-324823213-v3.0.0",
  .ledger_name = "mainnet-324823213-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 324823214UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_325467935_V3_0_0 = {
  .test_name = "mainnet-325467935-v3.0.0",
  .ledger_name = "mainnet-325467935-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 325467936UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_283927487_V3_0_0 = {
  .test_name = "testnet-283927487-v3.0.0",
  .ledger_name = "testnet-283927487-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 283927497UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_321168308_V3_0_0 = {
  .test_name = "testnet-321168308-v3.0.0",
  .ledger_name = "testnet-321168308-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 321168308UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_327324660_V3_0_0 = {
  .test_name = "mainnet-327324660-v3.0.0",
  .ledger_name = "mainnet-327324660-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 327324660UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_370199634_V3_0_0 = {
  .test_name = "devnet-370199634-v3.0.0",
  .ledger_name = "devnet-370199634-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 200000UL,
  .end_slot = 370199634UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_370199634_V3_0_0_VINYL = {
  .test_name = "devnet-370199634-v3.0.0-vinyl",
  .ledger_name = "devnet-370199634-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 200000UL,
  .end_slot = 370199634UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_330219081_V3_0_0 = {
  .test_name = "mainnet-330219081-v3.0.0",
  .ledger_name = "mainnet-330219081-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 330219082UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_372721907_V3_0_0 = {
  .test_name = "devnet-372721907-v3.0.0",
  .ledger_name = "devnet-372721907-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 372721910UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_331691646_V3_0_0 = {
  .test_name = "mainnet-331691646-v3.0.0",
  .ledger_name = "mainnet-331691646-v3.0.0",
  .funk_pages = 4UL,
  .index_max = 2000000UL,
  .end_slot = 331691647UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_378683870_V3_0_0 = {
  .test_name = "devnet-378683870-v3.0.0",
  .ledger_name = "devnet-378683870-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 378683872UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_380592002_V3_0_0 = {
  .test_name = "devnet-380592002-v3.0.0",
  .ledger_name = "devnet-380592002-v3.0.0",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 380592006UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_336218682_V3_0_0 = {
  .test_name = "testnet-336218682-v3.0.0",
  .ledger_name = "testnet-336218682-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 336218683UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_340269866_V3_0_0 = {
  .test_name = "testnet-340269866-v3.0.0",
  .ledger_name = "testnet-340269866-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 340269872UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_340272018_V3_0_0 = {
  .test_name = "testnet-340272018-v3.0.0",
  .ledger_name = "testnet-340272018-v3.0.0",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 340272023UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_390056400_V3_0_0 = {
  .test_name = "devnet-390056400-v3.0.0",
  .ledger_name = "devnet-390056400-v3.0.0",
  .funk_pages = 10UL,
  .index_max = 2000000UL,
  .end_slot = 390056406UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_346556000 = {
  .test_name = "testnet-346556000",
  .ledger_name = "testnet-346556000",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 346556337UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_346179946 = {
  .test_name = "testnet-346179946",
  .ledger_name = "testnet-346179946",
  .funk_pages = 30UL,
  .index_max = 90000000UL,
  .end_slot = 346179950UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MULTI_BPF_LOADER_V3_0_0 = {
  .test_name = "multi-bpf-loader-v3.0.0",
  .ledger_name = "multi-bpf-loader-v3.0.0",
  .funk_pages = 1UL,
  .index_max = 1000UL,
  .end_slot = 108UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCAL_MULTI_BOUNDARY = {
  .test_name = "local-multi-boundary",
  .ledger_name = "local-multi-boundary",
  .funk_pages = 1UL,
  .index_max = 1000UL,
  .end_slot = 2325UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCAL_MULTI_BOUNDARY_VINYL = {
  .test_name = "local-multi-boundary-vinyl",
  .ledger_name = "local-multi-boundary-vinyl",
  .funk_pages = 1UL,
  .index_max = 1000UL,
  .end_slot = 2325UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_GENESIS_V3_0 = {
  .test_name = "genesis-v3.0",
  .ledger_name = "genesis-v3.0",
  .funk_pages = 1UL,
  .index_max = 3000UL,
  .end_slot = 1280UL,
  .genesis = 1,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCALNET_STAKE_V3_0_0 = {
  .test_name = "localnet-stake-v3.0.0",
  .ledger_name = "localnet-stake-v3.0.0",
  .funk_pages = 1UL,
  .index_max = 3000UL,
  .end_slot = 541UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_368528500_STRICTER_ABI = {
  .test_name = "mainnet-368528500-stricter-abi",
  .ledger_name = "mainnet-368528500-stricter-abi",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 368528527UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "sD3uVpaavUXQRvDXrMFCQ2CqLqnbz5mK8ttWNXbtD3r" },
  .enable_features_cnt = 1UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_368528500_DIRECT_MAPPING = {
  .test_name = "mainnet-368528500-direct-mapping",
  .ledger_name = "mainnet-368528500-direct-mapping",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 368528527UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "sD3uVpaavUXQRvDXrMFCQ2CqLqnbz5mK8ttWNXbtD3r", "DFN8MyKpQqFW31qczcahgnnxcAHQc6P94wtTEX5EP1RA" },
  .enable_features_cnt = 2UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_362107883_DIRECT_MAPPING_2 = {
  .test_name = "testnet-362107883-direct-mapping-2",
  .ledger_name = "testnet-362107883-direct-mapping-2",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 362219427UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "sD3uVpaavUXQRvDXrMFCQ2CqLqnbz5mK8ttWNXbtD3r", "DFN8MyKpQqFW31qczcahgnnxcAHQc6P94wtTEX5EP1RA" },
  .enable_features_cnt = 2UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_413869565 = {
  .test_name = "devnet-413869565",
  .ledger_name = "devnet-413869565",
  .funk_pages = 40UL,
  .index_max = 100000000UL,
  .end_slot = 413869600UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_376969880 = {
  .test_name = "mainnet-376969880",
  .ledger_name = "mainnet-376969880",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 376969900UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_DEVNET_422969842 = {
  .test_name = "devnet-422969842",
  .ledger_name = "devnet-422969842",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 422969848UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_376969880_R2 = {
  .test_name = "mainnet-376969880-r2",
  .ledger_name = "mainnet-376969880-r2",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 376969900UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "5xXZc66h4UdB6Yq7FzdBxBiRAFMMScMLwHxk2QZDaNZL" },
  .enable_features_cnt = 1UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_376969880_SIMD_339 = {
  .test_name = "mainnet-376969880-simd-339",
  .ledger_name = "mainnet-376969880-simd-339",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 376969900UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "H6iVbVaDZgDphcPbcZwc5LoznMPWQfnJ1AM7L1xzqvt5" },
  .enable_features_cnt = 1UL,
};

static const fd_ledger_config_t FD_LEDGER_MAINNET_378539412 = {
  .test_name = "mainnet-378539412",
  .ledger_name = "mainnet-378539412",
  .funk_pages = 5UL,
  .index_max = 2000000UL,
  .end_slot = 378539445UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_384169347 = {
  .test_name = "testnet-384169347",
  .ledger_name = "testnet-384169347",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 384169377UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_384395810 = {
  .test_name = "testnet-384395810",
  .ledger_name = "testnet-384395810",
  .funk_pages = 3UL,
  .index_max = 2000000UL,
  .end_slot = 384395820UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_BREAKPOINT_385786458 = {
  .test_name = "breakpoint-385786458",
  .ledger_name = "breakpoint-385786458",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 385786458UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_BREAKPOINT_385786458_VINYL = {
  .test_name = "breakpoint-385786458-vinyl",
  .ledger_name = "breakpoint-385786458-vinyl",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 385786458UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 1,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCALNET_DEPRECATE_RENT_EXEMPTION_THRESHOLD = {
  .test_name = "localnet-deprecate-rent-exemption-threshold",
  .ledger_name = "localnet-deprecate-rent-exemption-threshold",
  .funk_pages = 1UL,
  .index_max = 1000UL,
  .end_slot = 260UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_LOCALNET_STATIC_INSTRUCTION_LIMIT = {
  .test_name = "localnet-static-instruction-limit",
  .ledger_name = "localnet-static-instruction-limit",
  .funk_pages = 1UL,
  .index_max = 1000UL,
  .end_slot = 191UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_VOTE_STATES_V4_LOCAL = {
  .test_name = "vote-states-v4-local",
  .ledger_name = "vote-states-v4-local",
  .funk_pages = 1UL,
  .index_max = 3000UL,
  .end_slot = 1000UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t FD_LEDGER_TESTNET_386300256 = {
  .test_name = "testnet-386300256",
  .ledger_name = "testnet-386300256",
  .funk_pages = 1UL,
  .index_max = 2000000UL,
  .end_slot = 386300289UL,
  .genesis = 0,
  .has_incremental = 0,
  .vinyl = 0,
  .enable_features = { "" },
  .enable_features_cnt = 0UL,
};

static const fd_ledger_config_t * const fd_ledger_configs[] = {
  &FD_LEDGER_TESTNET_519_V3_0_0,
  &FD_LEDGER_TESTNET_519_V3_0_0_VINYL,
  &FD_LEDGER_MAINNET_257066033_V3_0_0,
  &FD_LEDGER_MAINNET_257066844_V3_0_0,
  &FD_LEDGER_MAINNET_257067457_V3_0_0,
  &FD_LEDGER_MAINNET_257068890_V3_0_0,
  &FD_LEDGER_MAINNET_257181622_V3_0_0,
  &FD_LEDGER_MAINNET_254462437_V3_0_0,
  &FD_LEDGER_MAINNET_262654839_V3_0_0,
  &FD_LEDGER_MAINNET_257037451_V3_0_0,
  &FD_LEDGER_MAINNET_257035225_V3_0_0,
  &FD_LEDGER_MAINNET_257465453_V3_0_0,
  &FD_LEDGER_MAINNET_257058865_V3_0_0,
  &FD_LEDGER_MAINNET_257059815_V3_0_0,
  &FD_LEDGER_MAINNET_257061172_V3_0_0,
  &FD_LEDGER_MAINNET_257222682_V3_0_0,
  &FD_LEDGER_MAINNET_264890264_V3_0_0,
  &FD_LEDGER_MAINNET_257229353_V3_0_0,
  &FD_LEDGER_MAINNET_257257983_V3_0_0,
  &FD_LEDGER_MAINNET_267728520_V3_0_0,
  &FD_LEDGER_MAINNET_267651942_V3_0_0,
  &FD_LEDGER_MAINNET_267081197_V3_0_0,
  &FD_LEDGER_MAINNET_267085604_V3_0_0,
  &FD_LEDGER_MAINNET_265688706_V3_0_0,
  &FD_LEDGER_MAINNET_265688706_V3_0_0_VINYL,
  &FD_LEDGER_MAINNET_265330432_V3_0_0,
  &FD_LEDGER_MAINNET_268575190_V3_0_0,
  &FD_LEDGER_MAINNET_268129380_V3_0_0,
  &FD_LEDGER_MAINNET_268163043_V3_0_0,
  &FD_LEDGER_MAINNET_269511381_V3_0_0,
  &FD_LEDGER_MAINNET_269567236_V3_0_0,
  &FD_LEDGER_MAINNET_266134813_V3_0_0,
  &FD_LEDGER_MAINNET_266545736_V3_0_0,
  &FD_LEDGER_MAINNET_267059180_V3_0_0,
  &FD_LEDGER_MAINNET_267580466_V3_0_0,
  &FD_LEDGER_MAINNET_268196194_V3_0_0,
  &FD_LEDGER_MAINNET_267766641_V3_0_0,
  &FD_LEDGER_MAINNET_269648145_V3_0_0,
  &FD_LEDGER_TESTNET_281688085_V3_0_0,
  &FD_LEDGER_MAINNET_277660422_V3_0_0,
  &FD_LEDGER_MAINNET_277876060_V3_0_0,
  &FD_LEDGER_MAINNET_277927063_V3_0_0,
  &FD_LEDGER_MAINNET_281375356_V3_0_0,
  &FD_LEDGER_MAINNET_251418170_V3_0_0,
  &FD_LEDGER_MAINNET_282232100_V3_0_0,
  &FD_LEDGER_MAINNET_282151715_V3_0_0,
  &FD_LEDGER_MAINNET_286450148_V3_0_0,
  &FD_LEDGER_MULTI_EPOCH_PER_200_V3_0_0,
  &FD_LEDGER_MULTI_EPOCH_PER_300_V3_0_0,
  &FD_LEDGER_MULTI_EPOCH_PER_500_V3_0_0,
  &FD_LEDGER_MULTI_EPOCH_PER_500_V3_0_0_VINYL,
  &FD_LEDGER_TESTNET_297489336_V3_0_0,
  &FD_LEDGER_MAINNET_300377724_V3_0_0,
  &FD_LEDGER_MAINNET_300645644_V3_0_0,
  &FD_LEDGER_MAINNET_300648964_V3_0_0,
  &FD_LEDGER_MAINNET_301359740_V3_0_0,
  &FD_LEDGER_MAINNET_257181032_V3_0_0,
  &FD_LEDGER_MAINNET_257047660_V3_0_0,
  &FD_LEDGER_MAINNET_257047659_V3_0_0,
  &FD_LEDGER_MAINNET_308445707_V3_0_0,
  &FD_LEDGER_TESTNET_307395181_V3_0_0,
  &FD_LEDGER_MAINNET_308392063_V3_0_0,
  &FD_LEDGER_MAINNET_308392063_V3_0_0_VINYL,
  &FD_LEDGER_DEVNET_350814254_V3_0_0,
  &FD_LEDGER_DEVNET_350814254_V3_0_0_VINYL,
  &FD_LEDGER_TESTNET_311586340_V3_0_0,
  &FD_LEDGER_TESTNET_281546597_V3_0_0,
  &FD_LEDGER_TESTNET_281546597_V3_0_0_VINYL,
  &FD_LEDGER_MAINNET_324823213_V3_0_0,
  &FD_LEDGER_MAINNET_325467935_V3_0_0,
  &FD_LEDGER_TESTNET_283927487_V3_0_0,
  &FD_LEDGER_TESTNET_321168308_V3_0_0,
  &FD_LEDGER_MAINNET_327324660_V3_0_0,
  &FD_LEDGER_DEVNET_370199634_V3_0_0,
  &FD_LEDGER_DEVNET_370199634_V3_0_0_VINYL,
  &FD_LEDGER_MAINNET_330219081_V3_0_0,
  &FD_LEDGER_DEVNET_372721907_V3_0_0,
  &FD_LEDGER_MAINNET_331691646_V3_0_0,
  &FD_LEDGER_DEVNET_378683870_V3_0_0,
  &FD_LEDGER_DEVNET_380592002_V3_0_0,
  &FD_LEDGER_TESTNET_336218682_V3_0_0,
  &FD_LEDGER_TESTNET_340269866_V3_0_0,
  &FD_LEDGER_TESTNET_340272018_V3_0_0,
  &FD_LEDGER_DEVNET_390056400_V3_0_0,
  &FD_LEDGER_TESTNET_346556000,
  &FD_LEDGER_TESTNET_346179946,
  &FD_LEDGER_MULTI_BPF_LOADER_V3_0_0,
  &FD_LEDGER_LOCAL_MULTI_BOUNDARY,
  &FD_LEDGER_LOCAL_MULTI_BOUNDARY_VINYL,
  &FD_LEDGER_GENESIS_V3_0,
  &FD_LEDGER_LOCALNET_STAKE_V3_0_0,
  &FD_LEDGER_MAINNET_368528500_STRICTER_ABI,
  &FD_LEDGER_MAINNET_368528500_DIRECT_MAPPING,
  &FD_LEDGER_TESTNET_362107883_DIRECT_MAPPING_2,
  &FD_LEDGER_DEVNET_413869565,
  &FD_LEDGER_MAINNET_376969880,
  &FD_LEDGER_DEVNET_422969842,
  &FD_LEDGER_MAINNET_378539412,
  &FD_LEDGER_MAINNET_376969880_R2,
  &FD_LEDGER_MAINNET_376969880_SIMD_339,
  &FD_LEDGER_BREAKPOINT_385786458,
  &FD_LEDGER_BREAKPOINT_385786458_VINYL,
  &FD_LEDGER_LOCALNET_DEPRECATE_RENT_EXEMPTION_THRESHOLD,
  &FD_LEDGER_LOCALNET_STATIC_INSTRUCTION_LIMIT,
  &FD_LEDGER_VOTE_STATES_V4_LOCAL,
  &FD_LEDGER_TESTNET_384169347,
  &FD_LEDGER_TESTNET_384395810,
  &FD_LEDGER_TESTNET_386300256,
};
#define FD_LEDGER_CONFIG_COUNT (sizeof(fd_ledger_configs) / sizeof(fd_ledger_configs[0]))

static fd_ledger_config_t const * const fd_ledger_ci_list[] = {
  &FD_LEDGER_MAINNET_308392063_V3_0_0,
  &FD_LEDGER_MAINNET_308392063_V3_0_0_VINYL,
  &FD_LEDGER_DEVNET_350814254_V3_0_0,
  &FD_LEDGER_DEVNET_350814254_V3_0_0_VINYL,
  &FD_LEDGER_TESTNET_281546597_V3_0_0,
  &FD_LEDGER_TESTNET_281546597_V3_0_0_VINYL,
  &FD_LEDGER_MAINNET_324823213_V3_0_0,
  &FD_LEDGER_MAINNET_325467935_V3_0_0,
  &FD_LEDGER_TESTNET_283927487_V3_0_0,
  &FD_LEDGER_TESTNET_281688085_V3_0_0,
  &FD_LEDGER_TESTNET_321168308_V3_0_0,
  &FD_LEDGER_MAINNET_327324660_V3_0_0,
  &FD_LEDGER_DEVNET_370199634_V3_0_0,
  &FD_LEDGER_DEVNET_378683870_V3_0_0,
  &FD_LEDGER_MAINNET_330219081_V3_0_0,
  &FD_LEDGER_DEVNET_372721907_V3_0_0,
  &FD_LEDGER_MAINNET_331691646_V3_0_0,
  &FD_LEDGER_TESTNET_336218682_V3_0_0,
  &FD_LEDGER_TESTNET_340269866_V3_0_0,
  &FD_LEDGER_DEVNET_390056400_V3_0_0,
  &FD_LEDGER_MAINNET_254462437_V3_0_0,
  &FD_LEDGER_MULTI_EPOCH_PER_200_V3_0_0,
  &FD_LEDGER_TESTNET_346556000,
  &FD_LEDGER_MULTI_BPF_LOADER_V3_0_0,
  &FD_LEDGER_DEVNET_380592002_V3_0_0,
  &FD_LEDGER_LOCAL_MULTI_BOUNDARY,
  &FD_LEDGER_GENESIS_V3_0,
  &FD_LEDGER_LOCALNET_STAKE_V3_0_0,
  &FD_LEDGER_MAINNET_378539412,
  &FD_LEDGER_DEVNET_422969842,
  &FD_LEDGER_BREAKPOINT_385786458,
  &FD_LEDGER_BREAKPOINT_385786458_VINYL,
  &FD_LEDGER_VOTE_STATES_V4_LOCAL,
  &FD_LEDGER_TESTNET_384169347,
  &FD_LEDGER_TESTNET_384395810,
  &FD_LEDGER_TESTNET_386300256,
};
#define FD_LEDGER_CI_COUNT (sizeof(fd_ledger_ci_list) / sizeof(fd_ledger_ci_list[0]))

#endif /* HEADER_fd_src_flamenco_runtime_tests_ledgers_h */
