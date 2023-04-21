typedef char* (*fd_alloc_fun_t)(void *arg, ulong align, ulong len);
typedef void  (*fd_free_fun_t) (void *arg, void *ptr);

#define TAR_BLOCKSIZE 512

struct TarReadStream {
    fd_alloc_fun_t allocf_;
    void* allocf_arg_;
    fd_free_fun_t freef_;
    size_t cursize_;     // Current position in header/data
    size_t totalsize_;   // 0 if reading header, size of data otherwise
    size_t roundedsize_; // Rounded up to full bloxkes
    char header_[TAR_BLOCKSIZE] __attribute__((aligned(64)));
    void* buf_;
    size_t bufmax_;
};

inline size_t TarReadStream_footprint() { return sizeof(struct TarReadStream); }

extern void TarReadStream_init(struct TarReadStream* self, fd_alloc_fun_t allocf, void* allocf_arg, fd_free_fun_t freef);

typedef void (*TarReadStream_callback)(void* arg, const char* name, const void* data, size_t datalen);

// Return non-zero on end of tarball
extern int TarReadStream_moreData(struct TarReadStream* self, const void* data, size_t datalen, TarReadStream_callback cb, void* arg);

extern void TarReadStream_destroy(struct TarReadStream* self);
