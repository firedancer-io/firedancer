typedef unsigned long ulong;
volatile ulong *fd_metrics_tl;

#define FD_METRICS_TYPE_GAUGE (0UL)
#define FD_METRICS_TYPE_COUNTER (1UL)
#define FD_METRICS_TYPE_HISTOGRAM (2UL)

#define FD_METRICS_CONVERTER_NONE (0UL)
#define FD_METRICS_CONVERTER_SECONDS (1UL)
#define FD_METRICS_CONVERTER_NANOSECONDS (2UL)

#define DECLARE_METRIC_ENUM(MEASUREMENT, TYPE, ENUM_NAME, ENUM_VARIANT) {  \
    .name = FD_METRICS_##TYPE##_##MEASUREMENT##_NAME,                      \
    .enum_name = FD_METRICS_ENUM_##ENUM_NAME##_NAME,                       \
    .enum_variant = FD_METRICS_ENUM_##ENUM_NAME##_V_##ENUM_VARIANT##_NAME, \
    .type = FD_METRICS_TYPE_##TYPE,                                        \
    .desc = FD_METRICS_##TYPE##_##MEASUREMENT##_DESC,                      \
    .offset = FD_METRICS_##TYPE##_##MEASUREMENT##_OFF +                    \
              FD_METRICS_ENUM_##ENUM_NAME##_V_##ENUM_VARIANT##_IDX,        \
    .converter = FD_METRICS_##TYPE##_##MEASUREMENT##_CVT}

#define MIDX(type, group, measurement) (FD_METRICS_##type##_##group##_##measurement##_OFF)

#define FD_MCNT_ENUM_COPY(group, measurement, values)                                \
    do                                                                               \
    {                                                                                \
        ulong __fd_metrics_off = MIDX(COUNTER, group, measurement);                  \
        for (ulong i = 0; i < FD_METRICS_COUNTER_##group##_##measurement##_CNT; i++) \
        {                                                                            \
            fd_metrics_tl[__fd_metrics_off + i] = values[i];                         \
        }                                                                            \
    } while (0)

// Define the enum macros we need for testing
#define FD_METRICS_ENUM_TEST_CNT 3
#define FD_METRICS_ENUM_TEST_NAME "test"
#define FD_METRICS_ENUM_TEST_V_FIRST_IDX 0
#define FD_METRICS_ENUM_TEST_V_FIRST_NAME "first"
#define FD_METRICS_ENUM_TEST_V_SECOND_IDX 1
#define FD_METRICS_ENUM_TEST_V_SECOND_NAME "second"
#define FD_METRICS_ENUM_TEST_V_THIRD_IDX 2
#define FD_METRICS_ENUM_TEST_V_THIRD_NAME "third"

// Different size than TEST enum
#define FD_METRICS_ENUM_OTHER_CNT 5
#define FD_METRICS_ENUM_OTHER_NAME "other"
#define FD_METRICS_ENUM_OTHER_V_FIRST_IDX 0
#define FD_METRICS_ENUM_OTHER_V_FIRST_NAME "first"
#define FD_METRICS_ENUM_OTHER_V_SECOND_IDX 1
#define FD_METRICS_ENUM_OTHER_V_THIRD_IDX 2
#define FD_METRICS_ENUM_OTHER_V_FOURTH_IDX 3
#define FD_METRICS_ENUM_OTHER_V_FIFTH_IDX 4

#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_OFF (0UL)
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_NAME "bank_transaction_result"
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_DESC "Result of loading and executing a transaction."
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_CVT (FD_METRICS_CONVERTER_NONE)
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_CNT (4UL)

#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_SUCCESS_OFF (0UL)
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_ACCOUNT_IN_USE_OFF (1UL)
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_ACCOUNT_LOADED_TWICE_OFF (2UL)
#define FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_ACCOUNT_NOT_FOUND_OFF (3UL)

#define FD_METRICS_ENUM_TRANSACTION_ERROR_NAME "transaction_error"
#define FD_METRICS_ENUM_TRANSACTION_ERROR_CNT (4UL)
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_SUCCESS_IDX 0
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_SUCCESS_NAME "success"
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_ACCOUNT_IN_USE_IDX 1
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_ACCOUNT_IN_USE_NAME "account_in_use"
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_ACCOUNT_LOADED_TWICE_IDX 2
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_ACCOUNT_LOADED_TWICE_NAME "account_loaded_twice"
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_ACCOUNT_NOT_FOUND_IDX 3
#define FD_METRICS_ENUM_TRANSACTION_ERROR_V_ACCOUNT_NOT_FOUND_NAME "account_not_found"

typedef struct
{
    char const *name;
    char const *enum_name;
    char const *enum_variant;
    int type;
    char const *desc;
    ulong offset;

    int converter;
} fd_metrics_meta_t;

int main()
{
    // ISSUE 1: Out-of-bounds array access
    // Array size is 3, but we access index 3 (which is out of bounds)
    ulong test_array[FD_METRICS_ENUM_TEST_CNT];
    test_array[3] = 42; // $ Alert This is out of bounds

    // ISSUE 2: Mismatched count
    // Array size is 4, but the CNT macro value is 3
    ulong mismatched_count_array[4];
    for (int i = 0; i < FD_METRICS_ENUM_TEST_CNT; i++)
    {
        mismatched_count_array[i] = i; // $ Alert
    }

    // ISSUE 3: Mismatched enum name
    // Array sized by TEST enum, but accessed using OTHER enum
    ulong mismatched_enum_array[FD_METRICS_ENUM_TEST_CNT];
    mismatched_enum_array[FD_METRICS_ENUM_OTHER_V_SECOND_IDX] = 42; // $ Alert

    // ISSUE 4: Counter-based array accessed using enum index
    // Array defined with FD_METRICS_COUNTER but accessed using an enum index
    // This is the case for arrays created with DECLARE_METRIC_ENUM
    // and fine. But here we mismatch the enum name.
    volatile ulong counter_array[FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_CNT];
    counter_array[FD_METRICS_ENUM_TEST_V_FIRST_IDX] = 100; // $ Alert Mismatched enum name

    // ISSUE 5: Counter-based array accessed using enum index
    // Array defined with FD_METRICS_COUNTER but accessed using an enum index
    // This is the case for arrays created with DECLARE_METRIC_ENUM
    // and fine if the enum name matches.
    volatile ulong counter_array2[FD_METRICS_COUNTER_BANK_TRANSACTION_RESULT_CNT];
    counter_array2[FD_METRICS_ENUM_TRANSACTION_ERROR_V_SUCCESS_IDX] = 100; // OK

    ulong txn_result[2];
    FD_MCNT_ENUM_COPY(BANK, TRANSACTION_RESULT, txn_result); // $ Alert mismatched sizes, CNT (4) vs txn_result (2).

    printf("Test complete\n");
    return 0;
}

fd_metrics_meta_t ignored[] = {
    DECLARE_METRIC_ENUM(BANK_TRANSACTION_RESULT, COUNTER, TRANSACTION_ERROR, SUCCESS),
    DECLARE_METRIC_ENUM(BANK_TRANSACTION_RESULT, COUNTER, TRANSACTION_ERROR, ACCOUNT_IN_USE),
    DECLARE_METRIC_ENUM(BANK_TRANSACTION_RESULT, COUNTER, TRANSACTION_ERROR, ACCOUNT_LOADED_TWICE),
    DECLARE_METRIC_ENUM(BANK_TRANSACTION_RESULT, COUNTER, TRANSACTION_ERROR, ACCOUNT_NOT_FOUND),
};