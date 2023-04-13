#ifndef HEADER_FD_RUNTIME_TYPES_CUSTOM
#define HEADER_FD_RUNTIME_TYPES_CUSTOM

typedef char* (*fd_alloc_fun_t)(void *arg, ulong align, ulong len);
typedef void  (*fd_free_fun_t) (void *arg, void *ptr);

#define FD_HASH_FOOTPRINT (32UL)
#define FD_HASH_ALIGN (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN FD_HASH_ALIGN

union __attribute__((aligned(FD_HASH_ALIGN))) fd_hash {
  uchar hash[ FD_HASH_FOOTPRINT ];
  uchar key [ FD_HASH_FOOTPRINT ]; // Making fd_hash and fd_pubkey interchangable 
  ulong ul  [ FD_HASH_FOOTPRINT / sizeof(ulong) ];
};

typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

FD_PROTOTYPES_BEGIN

void  fd_hash_decode(fd_hash_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);
void  fd_hash_encode(fd_hash_t* self, void const** data);
void  fd_hash_destroy(fd_hash_t* self, fd_free_fun_t freef, void* freef_arg);
ulong fd_hash_size(fd_hash_t* self);

#define fd_hash_check_zero(_x)           (!(_x->ul[0] | _x->ul[1] | _x->ul[2] | _x->ul[3]))
#define fd_hash_set_zero(_x)             ((_x->ul[0] = 0) | (_x->ul[1] = 0) | (_x->ul[2] = 0) | (_x->ul[3] = 0)))

#define fd_pubkey_decode(_x,_y,_z,_a,_b) fd_hash_decode(_x, _y, _z, _a, _b)
#define fd_pubkey_encode(_x, _y)         fd_hash_encode(_x, _y)
#define fd_pubkey_destroy(_x, _y, _z)    fd_hash_destroy(_x, _y, _z)
#define fd_pubkey_size(_x)               fd_hash_size(_x)
#define fd_pubkey_check_zero(_x)         fd_hash_check_zero(_x)
#define fd_pubkey_set_zero(_x)           fd_pubkey_set_zero(_x)

FD_PROTOTYPES_END

#endif

