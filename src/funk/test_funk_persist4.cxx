#include "fd_funk.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string_view>
#include <unordered_map>
#include <vector>

static ulong unique_tag = 0UL;

struct recordkey {
    fd_funk_rec_key_t id_;
    recordkey() { }
    recordkey(const recordkey& x) { memcpy(&id_, &x.id_, sizeof(id_)); }
    recordkey(recordkey&& x) { memcpy(&id_, &x.id_, sizeof(id_)); }
    bool operator== (const recordkey& x) const {
      return memcmp(&id_, &x.id_, sizeof(id_)) == 0;
    }
    void set_unique() {
      id_.ul[0] = fd_log_app_id();
      id_.ul[1] = fd_log_thread_id();
      id_.ul[2] = ++unique_tag;
# if FD_HAS_X86
      id_.ul[3] = (ulong)fd_tickcount();
# else
      id_.ul[3] = 0UL;
# endif
      id_.ul[4] = ~id_.ul[0]; id_.ul[5] = ~id_.ul[1]; id_.ul[6] = ~id_.ul[2]; id_.ul[7] = ~id_.ul[3];
    }

};

struct recordkeyhash {
    size_t operator() (const recordkey& key) const {
      std::string_view v((const char*)&key.id_, sizeof(key.id_));
      return std::hash<std::string_view>{}(v);
    }
};

struct recordvalue {
    std::vector<uchar> data_;

    void random_data(fd_rng_t * rng) {
      auto len = FD_FUNK_REC_VAL_MAX;
      data_.resize(len);
      auto* p = data_.data();
      while (len) {
        *(ulong*)p = fd_rng_ulong( rng );
        p += sizeof(ulong);
        len -= sizeof(ulong);
      }
    }

    void write_data(fd_funk_t * funk, fd_funk_txn_t * txn, const recordkey& key) {
      int err;
      auto sz = data_.size();
      assert(txn != NULL);
      auto* rec = fd_funk_rec_write_prepare(funk, txn, &key.id_, sz, &err);
      assert(rec != NULL);
      auto* wksp = fd_funk_wksp(funk);
      auto* rec2 = fd_funk_val_copy(rec, data_.data(), sz, sz, fd_funk_alloc(funk, wksp), wksp, &err);
      assert(rec2 == rec);
    }

    void erase_data(fd_funk_t * funk, fd_funk_txn_t * txn, const recordkey& key) {
      int err;
      assert(txn != NULL);
      auto* rec = fd_funk_rec_write_prepare(funk, txn, &key.id_, 0, &err);
      assert(rec != NULL);
      assert(fd_funk_rec_remove(funk, rec, 1) == FD_FUNK_SUCCESS);
    }

    void verify(fd_funk_t * funk, const recordkey& key) {
      auto* rec = fd_funk_rec_query_const(funk, NULL, &key.id_);
      assert(rec != NULL);
      assert(fd_funk_val_sz(rec) == data_.size());
      assert(memcmp(fd_funk_val(rec, fd_funk_wksp(funk)), data_.data(), data_.size()) == 0);
    }
};

struct TestHarness {
    fd_rng_t * rng_;
    fd_funk_t * funk_;
    fd_funk_txn_t * txn_;
    std::unordered_map<recordkey,recordvalue,recordkeyhash> map_;

    TestHarness(fd_rng_t * rng) : rng_(rng), funk_(NULL), txn_(NULL) { }
    ~TestHarness() { }

    void random_insert() {
      recordkey key;
      key.set_unique();
      auto& val = map_[key];
      val.random_data(rng_);
      val.write_data(funk_, txn_, key);
    }

    void random_modify() {
      auto it = map_.begin();
      auto n = fd_rng_ulong_roll(rng_, map_.size());
      for (size_t i = 0; i < n; ++i)
        ++it;
      auto& val = it->second;
      val.random_data(rng_);
      val.write_data(funk_, txn_, it->first);
    }

    void random_erase() {
      auto it = map_.begin();
      auto n = fd_rng_ulong_roll(rng_, map_.size());
      for (size_t i = 0; i < n; ++i)
        ++it;
      it->second.erase_data(funk_, txn_, it->first);
      map_.erase(it);
    }

    void verify() {
      assert(fd_funk_verify(funk_) == FD_FUNK_SUCCESS);
      assert(fd_funk_rec_size(funk_, fd_funk_wksp(funk_)) == map_.size());
      for ( auto& [key,val] : map_)
        val.verify(funk_, key);
    }
};

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  ulong wksp_tag = 1UL;
  ulong txn_max = 10UL;
  ulong rec_max = 1000UL;
  ulong seed = 1234UL;
  const char* backfile = "testback";

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_wksp_t* wksp = NULL;

  void * shmem = NULL;
  TestHarness harness(rng);
  auto buildup = [&](){
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 4UL, fd_log_cpu_id(), "wksp", 0UL );
    ulong align     = fd_funk_align();
    ulong footprint = fd_funk_footprint();
    shmem = fd_wksp_alloc_laddr( wksp, align, footprint, wksp_tag );
    void * shfunk = fd_funk_new( shmem, wksp_tag, seed, txn_max, rec_max );
    harness.funk_ = fd_funk_join( shfunk );
    assert(fd_funk_persist_open( harness.funk_, backfile, 1 ) == FD_FUNK_SUCCESS);
  };
  unlink(backfile);
  buildup();
  harness.verify();

  auto start_txn = [&](){
    fd_funk_txn_xid_t xid;
    xid.ul[0] = fd_log_app_id();
    xid.ul[1] = fd_log_thread_id();
    xid.ul[2] = ++unique_tag;
# if FD_HAS_X86
    xid.ul[3] = (ulong)fd_tickcount();
# else
    xid.ul[3] = 0UL;
# endif
    harness.txn_ = fd_funk_txn_prepare( harness.funk_, NULL, &xid, 1 );
  };
  auto end_txn = [&](){
    fd_funk_txn_publish( harness.funk_, harness.txn_, 1 );
    harness.txn_ = NULL;
  };

  start_txn();
  for (int i = 0; i < 10; ++i)
    harness.random_insert();
  end_txn();
  harness.verify();
  
  auto teardown = [&](){
    fd_funk_delete( fd_funk_leave( harness.funk_ ) );
    harness.funk_ = NULL;
    fd_wksp_free_laddr( shmem );
    fd_wksp_detach(wksp);
    wksp = NULL;
  };
  teardown();
  buildup();
  harness.verify();

  start_txn();
  for (int i = 0; i < 5; ++i)
    harness.random_erase();
  end_txn();
  harness.verify();
  teardown();
  buildup();
  harness.verify();

  start_txn();
  for (int i = 0; i < 20; ++i) {
    harness.random_insert();
    if (i%3 == 2)
      harness.random_erase();
  }
  end_txn();
  harness.verify();
  teardown();
  buildup();
  harness.verify();

  for (int j = 0; j < 20; ++j) {
    start_txn();
    for (int i = 0; i < 5; ++i)
      harness.random_erase();
    end_txn();
    harness.verify();
    teardown();
    buildup();
    harness.verify();
    
    start_txn();
    for (int i = 0; i < 3; ++i)
      harness.random_modify();
    end_txn();
    harness.verify();
    teardown();
    buildup();
    harness.verify();
    
    start_txn();
    for (int i = 0; i < 5; ++i)
      harness.random_insert();
    end_txn();
    harness.verify();
    teardown();
    buildup();
    harness.verify();
  }

  teardown();

  unlink(backfile);

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(("pass"));
  fd_log_flush();
  return 0;
}
