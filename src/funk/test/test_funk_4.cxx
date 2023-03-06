#include <stdlib.h>
#include "../../util/fd_util.h"
extern "C" {
#include "../fd_funk.h"
#define FD_FUNK_NUM_DISK_SIZES 52U
uint fd_funk_disk_size(ulong rawsize, ulong* index);
}
#include <stdio.h>
#include <unistd.h>
#include <string_view>
#include <unordered_map>
#include <vector>

// A simple, fast, but not super great random number generator
class randgen {
  private:
    ulong _s1 = 0;
    ulong _s2 = 0;
    ulong _s3 = 0;

    void mix() {
      _s1 = (_s1+135075924757140979UL)*625099173779010167UL;
      _s2 = (_s2+578819778140026727UL)*115476946196358727UL;
      _s3 = (_s3+237010196533530919UL)*274199408033833319UL;
      _s1 ^= _s2>>31U;
      _s2 ^= _s3>>31U;
      _s3 ^= _s1>>31U;
    }
    
  public:
    randgen() { }
    ~randgen() { }

    void genbytes(char* data, unsigned len) {
      mix();
      while (len >= sizeof(ulong)) {
        memcpy(data, &_s1, sizeof(ulong));
        data += sizeof(ulong);
        len -= (unsigned)sizeof(ulong);
        mix();
      }
      memcpy(data, &_s1, len);
    }
};

struct recordkey {
    fd_funk_recordid _id;
    recordkey() { }
    recordkey(const recordkey& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    recordkey(recordkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    bool operator== (const recordkey& x) const {
      return memcmp(&_id, &x._id, sizeof(_id)) == 0;
    }
    operator const fd_funk_recordid* () const { return &_id; }
};

struct recordkeyhash {
    size_t operator() (const recordkey& key) const {
      std::string_view v((const char*)&key._id, sizeof(key._id));
      return std::hash<std::string_view>{}(v);
    }
};

struct xactionkey {
    fd_funk_xactionid _id;
    xactionkey() { }
    xactionkey(const xactionkey& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    xactionkey(xactionkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    xactionkey(const fd_funk_xactionid* id) { memcpy(&_id, id, sizeof(_id)); }
    bool operator== (const xactionkey& x) const {
      return memcmp(&_id, &x._id, sizeof(_id)) == 0;
    }
    operator const fd_funk_xactionid* () const { return &_id; }
    xactionkey& operator= (const xactionkey& x) { memcpy(&_id, &x._id, sizeof(_id)); return *this; }
};

struct xactionkeyhash {
    size_t operator() (const xactionkey& key) const {
      std::string_view v((const char*)&key._id, sizeof(key._id));
      return std::hash<std::string_view>{}(v);
    }
};

class databuf {
  private:
    std::vector<char> _buf;

  public:
    void write(const void* data, ulong offset, ulong datalen) {
      if (datalen == 0)
        return;
      auto oldsize = _buf.size();
      if (offset + datalen > oldsize) {
        _buf.resize(offset + datalen);
        if (offset > oldsize)
          memset(_buf.data() + oldsize, 0, offset - oldsize);
      }
      memcpy(_buf.data() + offset, data, datalen);
    }

    bool equals(const void* data, ulong datalen) const {
      return datalen == _buf.size() && memcmp(_buf.data(), data, datalen) == 0;
    }
};

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  unlink("testback");

  fd_wksp_t* wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );

  ulong index_max = 1000000;    // Maximum size (count) of master index
  ulong xactions_max = 100;     // Maximum size (count) of transaction index
  ulong cache_max = 1000;       // Maximum number of cache entries
  auto* funk = fd_funk_new("testback", wksp, 1, index_max, xactions_max, cache_max);

  fd_funk_validate(funk);
  char* scratch = (char*)malloc(FD_FUNK_MAX_ENTRY_SIZE);

  typedef std::unordered_map<recordkey,databuf,recordkeyhash> xactionstate_t;
  std::unordered_map<xactionkey,xactionstate_t,xactionkeyhash> golden;

  xactionkey rootxid(fd_funk_root(funk));

  // Copied from fd_funk_disk_size
  static const uint ALLSIZES[FD_FUNK_NUM_DISK_SIZES] = {
    128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1536, 2048,
    2688, 3584, 4736, 6272, 8192, 10752, 14080, 18304, 23808, 30976,
    40320, 52480, 68224, 88704, 115328, 150016, 195072, 253696, 329856,
    428928, 557696, 725120, 942720, 1225600, 1593344, 2071424, 2692864,
    3500800, 4551040, 5916416, 7691392, 9998848, 12998528, 16898176,
    21967744, 28558080, 37125504, 48263168, 62742144, 81564800, 106034304
  };
  for (uint rawsize = 0; ; ++rawsize) {
    ulong k;
    uint alloc = fd_funk_disk_size(rawsize, &k);
    if (alloc == 0) {
      if (rawsize <= ALLSIZES[FD_FUNK_NUM_DISK_SIZES-1])
        FD_LOG_ERR(("fd_funk_disk_size is bugged"));
      break;
    }
    if (alloc < rawsize || alloc != ALLSIZES[k] || (k > 0 && rawsize <= ALLSIZES[k-1])) {
      FD_LOG_ERR(("fd_funk_disk_size is bugged"));
      break;
    }
  }

  free(scratch);
  
  fd_funk_delete(funk);
  fd_wksp_detach(wksp);
  unlink("testback");

  FD_LOG_WARNING(("test passed!"));
  fd_log_flush();
  return 0;
}
