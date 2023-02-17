#include "../../util/fd_util.h"
extern "C" {
#include "../fd_funk.h"
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string_view>
#include <unordered_map>

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
};

struct recordkeyhash {
    size_t operator() (const recordkey& key) const {
      std::string_view v((const char*)&key._id, sizeof(key._id));
      return std::hash<std::string_view>{}(v);
    }
};

class databuf {
  private:
    char* _buf;
    ulong _buflen;

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

    void write(const void* data, ulong offset, ulong datalen) {
      if (datalen == 0)
        return;
      if (_buf == nullptr) {
        _buf = (char*)malloc(offset + datalen);
        if (offset > 0)
          memset(_buf, 0, offset);
        _buflen = offset + datalen;
      } else if (offset + datalen > _buflen) {
        _buf = (char*)realloc(_buf, offset + datalen);
        if (offset > _buflen)
          memset(_buf + _buflen, 0, offset - _buflen);
        _buflen = offset + datalen;
      }
      memcpy(_buf + offset, data, datalen);
    }

    bool equals(const void* data, ulong datalen) const {
      return datalen == _buflen && memcmp(_buf, data, datalen) == 0;
    }
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
  void* mem = malloc(footprint);
  memset(mem, 0xa5, footprint);
  auto* funk = fd_funk_join(fd_funk_new(mem, footprint, "testback"));

  fd_funk_validate(funk);

  char* scratch = (char*)malloc(MAXRECORDSIZE);

  std::unordered_map<recordkey,databuf,recordkeyhash> golden;

  // Generate 2000 random entries
  randgen rg;
  for (unsigned i = 0; i < 2000; ++i) {
    recordkey key;
    rg.genbytes((char*)&key, sizeof(key));
    auto len = random_size(rg);
    rg.genbytes(scratch, len);
    if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, 0, len) != (long)len)
      FD_LOG_ERR(("write failed"));
    databuf& db = golden[key];
    db.write(scratch, 0, len);
  }

  auto validateall = [&](){
    fd_funk_validate(funk);
    if (fd_funk_num_records(funk) != golden.size())
      FD_LOG_ERR(("wrong record count"));
    for (auto& [key,db] : golden) {
      const void* res;
      auto reslen = fd_funk_read(funk, fd_funk_root(funk), &key._id, &res, 0, MAXRECORDSIZE);
      if (!db.equals(res, reslen))
        FD_LOG_ERR(("read returned wrong result"));
    }
  };
  validateall();

  auto reload = [&](){
    fd_funk_delete(fd_funk_leave(funk));
    free(mem);
    mem = malloc(footprint);
    memset(mem, 0xa5, footprint);
    funk = fd_funk_join(fd_funk_new(mem, footprint, "testback"));
  };
  reload();

  validateall();

  // Update/grow all entries
  for (auto& [key,db] : golden) {
    auto len = random_size(rg);
    ulong offset;
    if (len == 0)
      offset = 0;
    else {
      rg.genbytes((char*)&offset, sizeof(offset));
      offset %= len*2;
      if (offset >= len)
        offset = 0;
    }
    rg.genbytes(scratch, (uint)(len - offset));
    if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, offset, len - offset) != (long)(len - offset))
      FD_LOG_ERR(("write failed"));
    db.write(scratch, offset, len - offset);
  }

  validateall();
  reload();
  validateall();

  // Delete 1000 entries
  unsigned cnt = 0;
  for (auto it = golden.begin(); it != golden.end() && ++cnt < 1000; ) {
    auto& [key,_] = *it;
    fd_funk_delete_record(funk, fd_funk_root(funk), &key._id);
    it = golden.erase(it);
  }
  
  validateall();
  reload();
  validateall();

  for (unsigned i = 1; i < 100; ++i) {
    recordkey key;
    rg.genbytes((char*)&key, sizeof(key));
    auto len = random_size(rg);    
    ulong offset = i*10;
    if (offset + len > MAXRECORDSIZE)
      len = (uint)(MAXRECORDSIZE - offset);
    rg.genbytes(scratch, len);
    if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, offset, len) != (long)len)
      FD_LOG_ERR(("write failed"));
    databuf& db = golden[key];
    db.write(scratch, offset, len);
  }

  validateall();
  reload();
  validateall();

  for (auto it = golden.begin(); it != golden.end(); ) {
    auto& [key,_] = *it;
    fd_funk_delete_record(funk, fd_funk_root(funk), &key._id);
    it = golden.erase(it);
  }
  
  validateall();
  reload();
  validateall();

  {
    recordkey key;
    rg.genbytes((char*)&key, sizeof(key));
    uint len = 1;
    while (len < MAXRECORDSIZE) {
      ulong offset = 0;
      if (offset + len > MAXRECORDSIZE)
        len = (uint)(MAXRECORDSIZE - offset);
      rg.genbytes(scratch, len);
      if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, offset, len) != (long)len)
        FD_LOG_ERR(("write failed"));
      databuf& db = golden[key];
      db.write(scratch, offset, len);

      validateall();
      reload();

      len *= 3;
    }
  }

  {
    recordkey key;
    rg.genbytes((char*)&key, sizeof(key));
    uint len = 1;
    while (len < MAXRECORDSIZE) {
      uint offset = len/2;
      rg.genbytes(scratch, len - offset);
      if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, offset, len - offset) != (long)len - offset)
        FD_LOG_ERR(("write failed"));
      databuf& db = golden[key];
      db.write(scratch, offset, len - offset);

      validateall();
      reload();

      len *= 3;
    }

    fd_funk_delete_record(funk, fd_funk_root(funk), &key._id);
    fd_funk_delete_record(funk, fd_funk_root(funk), &key._id);
    fd_funk_delete_record(funk, fd_funk_root(funk), &key._id);
    const void* data;
    if (fd_funk_read(funk, fd_funk_root(funk), &key._id, &data, 0, len) != -1)
      FD_LOG_ERR(("read did not fail as expected"));
    if (fd_funk_read(funk, fd_funk_root(funk), &key._id, &data, 0, len) != -1)
      FD_LOG_ERR(("read did not fail as expected"));
    if (fd_funk_read(funk, fd_funk_root(funk), &key._id, &data, 0, len) != -1)
      FD_LOG_ERR(("read did not fail as expected"));
    golden.erase(key);
  }

  for (unsigned i = 0; i < 100; ++i) {
    recordkey key;
    rg.genbytes((char*)&key, sizeof(key));
    uint len = 10;
    rg.genbytes(scratch, len);
    if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, 0, len) != (long)len)
      FD_LOG_ERR(("write failed"));
    databuf& db = golden[key];
    db.write(scratch, 0, len);
  }

  for (unsigned j = 1; j < 200; ++j) {
    reload();
    for (auto& [key,db] : golden) {
      fd_funk_cache_hint(funk, fd_funk_root(funk), &key._id, 0, 25);
      uint len = 10;
      uint offset = 20*j;
      rg.genbytes(scratch, len);
      if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, offset, len) != (long)len)
        FD_LOG_ERR(("write failed"));
      db.write(scratch, offset, len);
    }
    validateall();
  }

  FD_LOG_INFO(("final grind... expect a warning"));
  for (;;) {
    recordkey key;
    rg.genbytes((char*)&key, sizeof(key));
    uint len = 16;
    rg.genbytes(scratch, len);
    if (fd_funk_write(funk, fd_funk_root(funk), &key._id, scratch, 0, len) != (long)len)
      break;
    databuf& db = golden[key];
    db.write(scratch, 0, len);
  }

  FD_LOG_INFO(("%u records", fd_funk_num_records(funk)));
  validateall();

  free(scratch);
  
  fd_funk_delete(fd_funk_leave(funk));
  free(mem);
  unlink("testback");

  FD_LOG_INFO(("test passed!"));
  return 0;
}
