#include <stdlib.h>
#include <stdio.h>
#include "fd_tests.h"
#include "../../base58/fd_base58.h"

void example_run_test() {

    /* Initialize the test suite */
    fd_executor_test_suite_t suite;
    fd_executor_test_suite_new( &suite );

    /* Data from Python */
    ulong test_accs_len = 2;

    /* The accounts needed for this test */
    fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
    fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
    fd_base58_decode_32( "CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3",  (unsigned char *) &test_accs[0].pubkey);
    test_accs[0].lamports = 55;
    test_accs[0].data_len = 10;
    uchar test_acc_0_data[] = {5, 20, 59, 23, 59, 24, 24, 89, 54, 23};
    test_accs[0].data = (uchar*)&test_acc_0_data;
    test_accs[0].executable = 1;
    test_accs[0].rent_epoch = 43;
    fd_base58_decode_32( "DpKiVBumBu2AfRp6mCqphPcp99ut1DfmX7gRXidMofjw",  (unsigned char *) &test_accs[0].owner);
    
    /* The test */
    fd_executor_test_t test;
    fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
    test.test_name = "some_name";
    fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
    uchar raw_tx[] = { 47, 53, 34, 33, 65, 34, 23 };
    test.raw_tx = (uchar*)&raw_tx;
    test.raw_tx_len = 7;
    test.expected_result = 3;

    /* How to set these up? */
    /* Next task: make these compile by calling our test suite */
    fd_executor_run_test( &test, &suite );
}

int main(int argc, char **argv) {
    fd_boot( &argc, &argv );
     example_run_test();
}
