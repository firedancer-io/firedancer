#define TAR_BLOCKSIZE 512

struct TarReadStream {
    size_t cursize_;     // Current position in header/data
    size_t totalsize_;   // 0 if reading header, size of data otherwise
    size_t roundedsize_; // Rounded up to full bloxkes
    char header_[TAR_BLOCKSIZE];
    void* buf_;
    size_t bufmax_;
};

inline size_t TarReadStream_footprint() { return sizeof(struct TarReadStream); }

extern void TarReadStream_init(struct TarReadStream* self);

typedef void (*TarReadStream_callback)(void* arg, const char* name, const void* data, size_t datalen);

// Return non-zero on end of tarball
extern int TarReadStream_moreData(struct TarReadStream* self, const void* data, size_t datalen, TarReadStream_callback cb, void* arg);

extern void TarReadStream_destroy(struct TarReadStream* self);
