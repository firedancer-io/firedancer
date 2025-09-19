typedef unsigned long long size_t;

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

void *
memcpy(void *restrict dst, const void *restrict src, size_t n);

static inline void *
fd_memcpy(void *restrict d,
          void const *restrict s,
          ulong sz);

struct fd_txn_p
{
    // fields are irrelevant
};
typedef struct fd_txn_p fd_txn_p_t;

#define FD_HASH_FOOTPRINT (32UL)
#define FD_HASH_ALIGN (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN FD_HASH_ALIGN
union __attribute__((packed)) fd_hash
{
    uchar hash[FD_HASH_FOOTPRINT];
    uchar key[FD_HASH_FOOTPRINT]; // Making fd_hash and fd_pubkey interchangeable

    // Generic type specific accessors
    ulong ul[FD_HASH_FOOTPRINT / sizeof(ulong)];
    uint ui[FD_HASH_FOOTPRINT / sizeof(uint)];
    uchar uc[FD_HASH_FOOTPRINT];
};
typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

struct foo
{
    int a;
    long b;
};
typedef struct foo foo_t;

struct with_array
{
    int array[4];
    long b;
};
typedef struct with_array with_array_t;

int main(int argc, char **argv)
{
    foo_t first;
    foo_t second;
    memcpy(&first, &second, sizeof(foo_t));           // $ Alert
    fd_memcpy(&first, &second, sizeof(foo_t));        // $ Alert
    __builtin_memcpy(&first, &second, sizeof(foo_t)); // $ Alert

    memcpy(&first, &second, sizeof(first));           // $ Alert, same as sizeof(foo_t)
    fd_memcpy(&first, &second, sizeof(second));       // $ Alert
    __builtin_memcpy(&first, &second, sizeof(first)); // $ Alert

    with_array_t wa1;
    with_array_t wa2;
    memcpy(&wa1, &wa2, sizeof(with_array_t));           // $ Alert
    fd_memcpy(&wa1, &wa2, sizeof(with_array_t));        // $ Alert
    __builtin_memcpy(&wa1, &wa2, sizeof(with_array_t)); // $ Alert

    memcpy(&wa1, &wa2, sizeof(wa2));           // $ Alert, same as sizeof(with_array_t)
    fd_memcpy(&wa1, &wa2, sizeof(wa1));        // $ Alert
    __builtin_memcpy(&wa1, &wa2, sizeof(wa2)); // $ Alert

    memcpy(&wa1.array, &wa2.array, sizeof(wa2.array)); // NO Alert, `wa1.array = wa2.array` would be illegal C
    // we ignore pointer types like `int(*)[4]`
    fd_memcpy(&wa1.array, &wa2.array, sizeof(wa2.array));        // NO Alert
    __builtin_memcpy(&wa1.array, &wa2.array, sizeof(wa2.array)); // NO Alert

    memcpy(wa1.array, wa2.array, sizeof(wa2.array));           // NO Alert, `wa1.array`'s type is `int[4]` and we only match pointer types
    fd_memcpy(wa1.array, wa2.array, sizeof(wa2.array));        // NO Alert
    __builtin_memcpy(wa1.array, wa2.array, sizeof(wa2.array)); // NO Alert

    // strict aliasing FP example
    // Inspired by https://github.com/firedancer-io/firedancer/pull/5148#discussion_r2093565061
    foo_t normal_foo;
    char buf2[16];
    foo_t *aliased_foo = (foo_t *)buf2;              // casting pointers is fine, only dereferencing is a problem
    memcpy(&normal_foo, aliased_foo, sizeof(foo_t)); // $ Alert (False positive)
    // `normal_foo = *aliased_foo` would be a strict-aliasing violation
    // so the memcpy here is _not_ trivial, but we can't detect that easily
    fd_memcpy(&normal_foo, aliased_foo, sizeof(foo_t));        // $ Alert (False positive)
    __builtin_memcpy(&normal_foo, aliased_foo, sizeof(foo_t)); // $ Alert (False positive)

    // fd_txn_p_t example
    // Inspired by https://github.com/firedancer-io/firedancer/pull/5148#discussion_r2093566821
    fd_txn_p_t txn1;
    fd_txn_p_t txn2;
    memcpy(&txn1, &txn2, sizeof(fd_txn_p_t));           // NO Alert
    fd_memcpy(&txn1, &txn2, sizeof(fd_txn_p_t));        // NO Alert
    __builtin_memcpy(&txn1, &txn2, sizeof(fd_txn_p_t)); // NO Alert

    // fd_hash_t example
    // Inspired by FIX_ME
    fd_hash_t hash1;
    fd_hash_t hash2;
    memcpy(&hash1, &hash2, sizeof(fd_hash_t));           // NO Alert
    fd_memcpy(&hash1, &hash2, sizeof(fd_hash_t));        // NO Alert
    __builtin_memcpy(&hash1, &hash2, sizeof(fd_hash_t)); // NO Alert
}