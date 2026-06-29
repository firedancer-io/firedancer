typedef unsigned long long size_t;
typedef unsigned long ulong;

void *
memset(void *dst, int c, size_t n);

void *
fd_memset(void *dst, int c, ulong n);

void *
custom_memset(void *dst, int c, size_t n);

typedef struct
{
    char payload[11 * 1024 * 1024];
} huge_region_t;

typedef struct
{
    char payload[10 * 1024 * 1024];
} exact_limit_region_t;

typedef struct
{
    char payload[10 * 1024 * 1024 - 1];
} below_limit_region_t;

static char oversized_buffer[11 * 1024 * 1024];
static char exact_limit_buffer[10 * 1024 * 1024];

int
main(void)
{
    memset(oversized_buffer, 0, 11 * 1024 * 1024);           // $ Alert
    fd_memset(oversized_buffer, 0, 11 * 1024 * 1024UL);      // $ Alert
    memset(oversized_buffer, 0, sizeof(huge_region_t));      // $ Alert
    fd_memset(oversized_buffer, 0, sizeof(huge_region_t));   // $ Alert

    memset(exact_limit_buffer, 0, 10 * 1024 * 1024);         // NO Alert
    fd_memset(exact_limit_buffer, 0, 10 * 1024 * 1024UL);    // NO Alert
    memset(exact_limit_buffer, 0, sizeof(exact_limit_region_t)); // NO Alert
    fd_memset(exact_limit_buffer, 0, sizeof(below_limit_region_t)); // NO Alert
    custom_memset(oversized_buffer, 0, 11 * 1024 * 1024);    // NO Alert

    return oversized_buffer[0] + exact_limit_buffer[0];
}
