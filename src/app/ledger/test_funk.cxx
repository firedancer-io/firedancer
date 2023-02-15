#include "../../util/fd_util.h"
extern "C" {
#include "fd_funk.h"
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

class databuf {
  private:
    char* _buf;
    unsigned _buflen;

  public:
    databuf() {
      _buf = nullptr;
      _buflen = 0;
    }
    databuf(const databuf& x) = delete;
    databuf(databuf&& x) {
      _buf = x._buf;
      x._buf = nullptr;
      _buflen = x._buflen;
      x._buflen = 0;
    }
    databuf& operator= (const databuf& x) = delete;
    databuf& operator= (databuf&& x) = delete;
};

static const unsigned MAXRECORDSIZE = 100000;
uint random_size(randgen& rg) {
  // Simulate a crude exponential distribution of sizes
  uint s;
  rg.genbytes((char*)&s, sizeof(s));
  s = s%MAXRECORDSIZE;
  if (s < 95*MAXRECORDSIZE/100)
    // 95% are less than 1000
    s /= 100;
  else if (s < 99*MAXRECORDSIZE/100)
    // 4% are less than 10000
    s /= 10;
  return s;
}

int main() {
  unlink("testback");
  ulong footprint = fd_funk_footprint_min();
  void* mem = fd_funk_new(malloc(footprint), footprint, "testback");
  auto* funk = fd_funk_join(mem);

  fd_funk_validate(funk);

  char* scratch = (char*)malloc(MAXRECORDSIZE);

  // Generate 2000 random entries
  randgen rg;
  for (unsigned i = 0; i < 2000; ++i) {
    fd_funk_recordid id;
    rg.genbytes((char*)&id, sizeof(id));
    auto len = random_size(rg);
    rg.genbytes(scratch, len);
    fd_funk_write(funk, fd_funk_root(funk), &id, scratch, 0, len);
  }

  free(scratch);
  
  mem = fd_funk_leave(funk);
  fd_funk_delete(mem);
  free(mem);
  unlink("testback");
  
  return 0;
}
