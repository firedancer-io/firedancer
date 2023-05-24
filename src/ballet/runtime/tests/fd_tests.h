#include "../fd_runtime.h"

/* Framework for running Solana's native program tests in our runtime */

struct fd_executor_test_acc {
    fd_pubkey_t pubkey;
    ulong       lamports;
    ulong       data_len;
    uchar*      data;
    uchar       executable;
    ulong       rent_epoch;
    fd_pubkey_t owner;
};
typedef struct fd_executor_test_acc fd_executor_test_acc_t;
#define FD_EXECUTOR_TEST_ACC_FOOTPRINT ( sizeof(fd_executor_test_acc_t) )

struct fd_executor_test {
    char*                   test_name;
    fd_pubkey_t             program_id;
    fd_executor_test_acc_t* accs;
    ulong                   accs_len;
    uchar*                  raw_tx;
    ulong                   raw_tx_len;
    int                     expected_result;
};
typedef struct fd_executor_test fd_executor_test_t;
#define FD_EXECUTOR_TEST_FOOTPRINT ( sizeof(fd_executor_test_t) )

struct fd_executor_test_suite {
    fd_wksp_t* wksp;
    fd_funk_t* funk;
};
typedef struct fd_executor_test_suite fd_executor_test_suite_t;
#define FD_EXECUTOR_TEST_SUITE_FOOTPRINT ( sizeof(fd_executor_test_suite_t) )

void fd_executor_test_suite_new( fd_executor_test_suite_t* suite );
void fd_executor_run_test(
    fd_executor_test_t* test,
    fd_executor_test_suite_t* suite) ;

