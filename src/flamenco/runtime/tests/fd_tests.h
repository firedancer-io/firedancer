#ifndef HEADER_src_ballet_runtime_tests_fd_tests_h
#define HEADER_src_ballet_runtime_tests_fd_tests_h

#include "../fd_runtime.h"
#include <regex.h>
#include "../../features/fd_features.h"

/* Framework for running Solana's native program tests in our runtime */

#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"

#define fd_feature_offset(x) offsetof( fd_features_t, x )

struct fd_executor_test_acc {
  fd_pubkey_t   pubkey;
  ulong         lamports;
  ulong         result_lamports;
  ulong         data_len;
  ulong         result_data_len;
  const uchar*  data;
  const uchar*  result_data;
  uchar         executable;
  uchar         result_executable;
  ulong         rent_epoch;
  ulong         result_rent_epoch;
  fd_pubkey_t   owner;
  fd_pubkey_t   result_owner;
};
typedef struct fd_executor_test_acc fd_executor_test_acc_t;
#define FD_EXECUTOR_TEST_ACC_FOOTPRINT ( sizeof(fd_executor_test_acc_t) )

struct fd_test_sysvar_cache {
  char * clock;
  char * epoch_schedule;
  char * epoch_rewards;
  char * fees;
  char * rent;
  char * slot_hashes;
  char * recent_block_hashes;
  char * stake_history;
  char * slot_history;
};
typedef struct fd_test_sysvar_cache fd_test_sysvar_cache_t;
#define FD_TEST_SYSVAR_CACHE_FOOTPRINT ( sizeof(fd_test_sysvar_cache_t) )

struct fd_executor_test {
  char*                   test_name;
  int                     test_number;
  uint                    disable_cnt;
  uchar                  *disable_feature;
  const char             *bt;
  fd_pubkey_t             program_id;
  fd_executor_test_acc_t* accs;
  ulong                   accs_len;
  const uchar*            raw_tx;
  ulong                   raw_tx_len;
  int                     expected_result;
  uint                    custom_err;
  ulong                   nonce;
  fd_test_sysvar_cache_t  sysvar_cache;
};
typedef struct fd_executor_test fd_executor_test_t;
#define FD_EXECUTOR_TEST_FOOTPRINT ( sizeof(fd_executor_test_t) )

struct fd_executor_test_suite {
  fd_wksp_t *    wksp;
  fd_funk_t *    funk;
  fd_blockstore_t * blockstore;
  fd_valloc_t    valloc;
  regex_t        filter_ex;
  const char *   filter;
  fd_features_t  features;
  char           ignore_fail[5000];
};
typedef struct fd_executor_test_suite fd_executor_test_suite_t;
#define FD_EXECUTOR_TEST_SUITE_FOOTPRINT ( sizeof(fd_executor_test_suite_t) )

typedef int (* fd_executor_test_fn)( fd_executor_test_suite_t * );

FD_PROTOTYPES_BEGIN

void fd_executor_test_suite_new( fd_executor_test_suite_t* suite );

int fd_executor_run_test(
  fd_executor_test_t*       test,
  fd_executor_test_suite_t* suite) ;

/* Tests defined by test program.  Null terminated */

extern fd_executor_test_fn tests[];
extern ulong               test_cnt;

FD_PROTOTYPES_END

#endif /* HEADER_src_ballet_runtime_tests_fd_tests_h */
