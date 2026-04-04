char global_big[512 * 1024 + 1];

typedef struct
{
    char payload[512 * 1024 + 32];
} big_record_t;

void
large_stack_array(void)
{
    char too_big[512 * 1024 + 1]; // $ Alert
    too_big[0] = 1;
}

void
stack_size_boundary(void)
{
    char exact_limit[512 * 1024];
    char below_limit[512 * 1024 - 1];
    static char static_big[512 * 1024 + 1];

    exact_limit[0] = 1;
    below_limit[0] = exact_limit[0];
    static_big[0] = below_limit[0];
}

void
large_stack_struct(void)
{
    big_record_t record; // $ Alert
    static big_record_t cached_record;

    record.payload[0] = 2;
    cached_record.payload[0] = record.payload[0];
}

int
main(void)
{
    global_big[0] = 0;
    large_stack_array();
    stack_size_boundary();
    large_stack_struct();
    return global_big[0];
}
