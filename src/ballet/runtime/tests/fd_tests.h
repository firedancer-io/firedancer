#ifndef HEADER_src_ballet_runtime_tests_fd_tests_h
#define HEADER_src_ballet_runtime_tests_fd_tests_h

#include "../fd_runtime.h"
#include <regex.h>
#include "../fd_features.h"

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
  ulong         rent_epoch;
  fd_pubkey_t   owner;
};
typedef struct fd_executor_test_acc fd_executor_test_acc_t;
#define FD_EXECUTOR_TEST_ACC_FOOTPRINT ( sizeof(fd_executor_test_acc_t) )

struct fd_executor_test {
  char*                   test_name;
  int                     test_number;
  int                     test_nonce;
  uint                    disable_cnt;
  uchar                  *disable_feature;
  fd_pubkey_t             program_id;
  fd_executor_test_acc_t* accs;
  ulong                   accs_len;
  const uchar*            raw_tx;
  ulong                   raw_tx_len;
  int                     expected_result;
  uint                    custom_err;
  ulong                   nonce;
};
typedef struct fd_executor_test fd_executor_test_t;
#define FD_EXECUTOR_TEST_FOOTPRINT ( sizeof(fd_executor_test_t) )

struct fd_executor_test_suite {
  fd_wksp_t*                 wksp;
  fd_funk_t*                 funk;
  fd_alloc_fun_t             allocf;
  void *                     allocf_arg;
  fd_free_fun_t              freef;
  regex_t                    filter_ex;
  const char *               filter;
  fd_features_t              features;
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

