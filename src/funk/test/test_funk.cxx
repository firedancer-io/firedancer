#include "../../util/fd_util.h"
extern "C" {
#include "../fd_funk.h"
}
#include <stdio.h>
#include <stdlib.h>
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
};

struct recordkeyhash {
    size_t operator() (const recordkey& key) const {
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

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  unlink("testback");

  fd_wksp_t* wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );

  ulong index_max = 1000000;    // Maximum size (count) of master index
  ulong xactions_max = 100;     // Maximum size (count) of transaction index
  ulong cache_max = 10000;      // Maximum number of cache entries
  auto* funk = fd_funk_new("testback", wksp, 1, index_max, xactions_max, cache_max);

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
    fd_funk_delete(funk);
    ulong       wksp_tag = 1UL;
    fd_wksp_tag_free(wksp, &wksp_tag, 1UL);
    funk = fd_funk_new("testback", wksp, 1, 100000, 100, 10000);
  };
  reload();

  validateall();

  // Use writev
  for (unsigned i = 0; i < 200; ++i) {
    recordkey key;
    rg.genbytes((char*)&key, sizeof(key));
    auto len = random_size(rg);
    rg.genbytes(scratch, len);
    struct iovec iov[3];
    iov[0].iov_base = scratch;
    iov[0].iov_len = len/3;
    iov[1].iov_base = scratch + iov[0].iov_len;
    iov[1].iov_len = len/3;
    iov[2].iov_base = scratch + (iov[0].iov_len + iov[1].iov_len);
    iov[2].iov_len = len - (iov[0].iov_len + iov[1].iov_len);
    if (fd_funk_writev(funk, fd_funk_root(funk), &key._id, iov, 3, 0) != (long)len)
      FD_LOG_ERR(("write failed"));
    databuf& db = golden[key];
    db.write(scratch, 0, len);
  }

  validateall();
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
    ulong len2 = len - offset;
    rg.genbytes(scratch, (uint)len2);
    struct iovec iov[3];
    iov[0].iov_base = scratch;
    iov[0].iov_len = len2/3;
    iov[1].iov_base = scratch + iov[0].iov_len;
    iov[1].iov_len = len2/3;
    iov[2].iov_base = scratch + (iov[0].iov_len + iov[1].iov_len);
    iov[2].iov_len = len2 - (iov[0].iov_len + iov[1].iov_len);
    if (fd_funk_writev(funk, fd_funk_root(funk), &key._id, iov, 3, offset) != (long)len2)
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

  for (unsigned j = 1; j < 100; ++j) {
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

  for (unsigned j = 1; j < 100; ++j) {
    reload();
    for (auto& [key,db] : golden) {
      fd_funk_cache_hint(funk, fd_funk_root(funk), &key._id, 0, 25);
      uint len = 10;
      uint offset = 20*j;
      rg.genbytes(scratch, len);
      struct iovec iov[3];
      iov[0].iov_base = scratch;
      iov[0].iov_len = len/3;
      iov[1].iov_base = scratch + iov[0].iov_len;
      iov[1].iov_len = len/3;
      iov[2].iov_base = scratch + (iov[0].iov_len + iov[1].iov_len);
      iov[2].iov_len = len - (iov[0].iov_len + iov[1].iov_len);
      if (fd_funk_writev(funk, fd_funk_root(funk), &key._id, iov, 3, offset) != (long)len)
        FD_LOG_ERR(("write failed"));
      db.write(scratch, offset, len);
    }
    validateall();
  }

  FD_LOG_WARNING(("final grind... expect a warning"));
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

  FD_LOG_INFO(("%lu records", fd_funk_num_records(funk)));
  validateall();

  free(scratch);
  
  fd_funk_delete(funk);
  fd_wksp_detach(wksp);
  unlink("testback");

  FD_LOG_WARNING(("test passed!"));
  fd_log_flush();
  return 0;
}
