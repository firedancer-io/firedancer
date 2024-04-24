extern "C" {
  #include "fd_funk.h"
}
#include <map>
#include <vector>
#include <stdlib.h>
#include <assert.h>

static const long ROOT_KEY = 0;
static const ulong MAX_TXNS = 100;
static const ulong MAX_CHILDREN = 100;

struct fake_rec {
    ulong _key;
    std::vector<long> _data;
    bool _erased = false;
    bool _touched = false;

    fake_rec() = delete;
    fake_rec(ulong key) : _key(key) { }

    static fake_rec * make_random() {
      auto * rec = new fake_rec(((ulong)lrand48())%MAX_CHILDREN);
      auto len = ((ulong)lrand48())%8UL;
      rec->_data.resize(len);
      for (ulong i = 0; i < len; ++i)
        rec->_data[i] = lrand48();
      return rec;
    }

    fd_funk_rec_key_t real_id() const {
      fd_funk_rec_key_t i;
      memset(&i, 0, sizeof(i));
      i.ul[0] = _key;
      return i;
    }

    ulong size() const {
      return _data.size()*sizeof(long);
    }

    const uchar* data() const {
      return (const uchar*)_data.data();
    }
};

struct fake_txn {
    ulong _key;
    std::map<ulong,fake_rec*> _recs;
    std::map<ulong,fake_txn*> _children;
    fake_txn * _parent = NULL;
    bool _touched = false;

    fake_txn(ulong key) : _key(key) { }
    ~fake_txn() {
      for (auto i : _recs)
        delete i.second;
    }

    fd_funk_txn_xid_t real_id() const {
      fd_funk_txn_xid_t i;
      memset(&i, 0, sizeof(i));
      i.ul[0] = _key;
      return i;
    }

    void insert(fake_rec* rec) {
      auto i = _recs.find(rec->_key);
      if (i != _recs.end())
        delete i->second;
      _recs[rec->_key] = rec;
    }
};

struct fake_funk {
    fd_wksp_t * _wksp;
    fd_funk_t * _real;
    std::map<ulong,fake_txn*> _txns;
    ulong _lastxid = 0;

    fake_funk(int * argc, char *** argv) {
      fd_boot( argc, argv );
      ulong  numa_idx = fd_shmem_numa_idx( 0 );
      _wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1U, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
      void * mem = fd_wksp_alloc_laddr( _wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
      ulong txn_max = 128;
      ulong rec_max = 1<<16;
      _real = fd_funk_join( fd_funk_new( mem, 1, 1234U, txn_max, rec_max ) );

      _txns[ROOT_KEY] = new fake_txn(ROOT_KEY);
    }
    ~fake_funk() {
      for (auto i : _txns)
        delete i.second;
    }

    fake_txn * pick_unfrozen_txn() {
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_children.size() == 0)
          list[listlen++] = i.second;
      return list[((uint)lrand48())%listlen];
    }

    fd_funk_txn_t * get_real_txn(fake_txn * txn) {
      if (txn->_key == ROOT_KEY)
        return NULL;
      fd_funk_txn_t * txn_map = fd_funk_txn_map( _real, _wksp );
      auto xid = txn->real_id();
      return fd_funk_txn_query(&xid, txn_map);
    }

    void random_insert() {
      fake_txn * txn = pick_unfrozen_txn();
      fake_rec * rec = fake_rec::make_random();
      txn->insert(rec);

      fd_funk_start_write(_real);
      fd_funk_txn_t * txn2 = get_real_txn(txn);
      auto key = rec->real_id();
      fd_funk_rec_t * rec2 = fd_funk_rec_write_prepare(_real, txn2, &key, rec->size(), 1, NULL, NULL);
      if (fd_funk_val_sz(rec2) > rec->size())
        rec2 = fd_funk_val_truncate(rec2, rec->size(), fd_funk_alloc(_real, _wksp), _wksp, NULL);
      memcpy(fd_funk_val(rec2, _wksp), rec->data(), rec->size());
      fd_funk_end_write(_real);
    }

    void random_remove() {
      fake_txn * txn = pick_unfrozen_txn();
      auto& recs = txn->_recs;
      fake_rec* list[MAX_CHILDREN];
      uint listlen = 0;
      for (auto i : recs)
        if (!i.second->_erased)
          list[listlen++] = i.second;
      if (!listlen) return;
      auto* rec = list[((uint)lrand48())%listlen];

      fd_funk_start_write(_real);
      fd_funk_txn_t * txn2 = get_real_txn(txn);
      auto key = rec->real_id();
      auto* rec2 = fd_funk_rec_query(_real, txn2, &key);
      assert(rec2 != NULL);
      assert(fd_funk_rec_remove(_real, (fd_funk_rec_t *)rec2, 1) == FD_FUNK_SUCCESS);

      rec->_erased = true;
      rec->_data.clear();
      fd_funk_end_write(_real);
    }

    void random_new_txn() {
      if (_txns.size() == MAX_TXNS)
        return;

      fd_funk_start_write(_real);
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        list[listlen++] = i.second;
      auto * parent = list[((uint)lrand48())%listlen];
      
      ulong key = ++_lastxid;
      auto * txn = _txns[key] = new fake_txn(key);

      txn->_parent = parent;
      parent->_children[key] = txn;

      fd_funk_txn_t * parent2 = get_real_txn(parent);
      auto xid = txn->real_id();
      assert(fd_funk_txn_prepare(_real, parent2, &xid, 1) != NULL);
      fd_funk_end_write(_real);
    }

    void fake_cancel_family(fake_txn* txn) {
      assert(txn->_key != ROOT_KEY);
      while (!txn->_children.empty())
        fake_cancel_family(txn->_children.begin()->second);
      fd_funk_start_write(_real);
      txn->_parent->_children.erase(txn->_key);
      _txns.erase(txn->_key);
      delete txn;
      fd_funk_end_write(_real);
    }
    
    void fake_publish_to_parent(fake_txn* txn) {
      fd_funk_start_write(_real);
      // Move records into parent
      auto* parent = txn->_parent;
      for (auto i : txn->_recs)
        parent->insert(i.second);
      txn->_recs.clear();

      // Cancel siblings
      for (;;) {
        bool repeat = false;
        for (auto i : parent->_children)
          if (txn != i.second) {
            fd_funk_end_write(_real);
            fake_cancel_family(i.second);
            fd_funk_start_write(_real);
            repeat = true;
            break;
          }
        if (!repeat) break;
      }
      assert(parent->_children.size() == 1 && parent->_children[txn->_key] == txn);

      // Move children up
      parent->_children.clear();
      for (auto i : txn->_children) {
        auto* child = i.second;
        child->_parent = parent;
        parent->_children[child->_key] = child;
      }

      _txns.erase(txn->_key);
      delete txn;
      fd_funk_end_write(_real);
    }
    
    void fake_publish(fake_txn* txn) {
      assert(txn->_key != ROOT_KEY);
      if (txn->_parent->_key != ROOT_KEY)
        fake_publish(txn->_parent);
      assert(txn->_parent->_key == ROOT_KEY);
      fake_publish_to_parent(txn);
    }

    void fake_merge(fake_txn* txn) {
      fd_funk_start_write(_real);
      for (auto i : txn->_children) {
        auto* child = i.second;
        for (auto i : child->_recs)
          txn->insert(i.second);
        child->_recs.clear();
        _txns.erase(child->_key);
        delete child;
      }
      txn->_children.clear();
      fd_funk_end_write(_real);
    }
    
    void random_publish() {
      fd_funk_start_write(_real);
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_key != ROOT_KEY)
          list[listlen++] = i.second;
      if (!listlen) return;
      auto * txn = list[((uint)lrand48())%listlen];

      fd_funk_txn_t * txn2 = get_real_txn(txn);
      assert(fd_funk_txn_publish(_real, txn2, 1) > 0);
      fd_funk_end_write(_real);

      // Simulate publication
      fake_publish(txn);
    }
    
    void random_publish_into_parent() {
      fd_funk_start_write(_real);
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_key != ROOT_KEY)
          list[listlen++] = i.second;
      if (!listlen) return;
      auto * txn = list[((uint)lrand48())%listlen];

      fd_funk_txn_t * txn2 = get_real_txn(txn);
      assert(fd_funk_txn_publish_into_parent(_real, txn2, 1) == FD_FUNK_SUCCESS);
      fd_funk_end_write(_real);

      // Simulate publication
      fake_publish_to_parent(txn);
    }
    
    void random_cancel() {
      fd_funk_start_write(_real);
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_key != ROOT_KEY)
          list[listlen++] = i.second;
      if (!listlen) return;
      auto * txn = list[((uint)lrand48())%listlen];

      fd_funk_txn_t * txn2 = get_real_txn(txn);
      assert(fd_funk_txn_cancel(_real, txn2, 1) > 0);
      fd_funk_end_write(_real);

      // Simulate cancel
      fake_cancel_family(txn);
    }
    
    void random_merge() {
      fd_funk_start_write(_real);
      // Look for transactions with children but no grandchildren
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns) {
        auto* txn = i.second;
        if (txn->_children.empty()) continue;
        for (auto j : txn->_children)
          if (!j.second->_children.empty())
            goto no_good;
        list[listlen++] = i.second;
        no_good: continue;
      }
      if (!listlen) return;
      auto * txn = list[((uint)lrand48())%listlen];

      fd_funk_txn_t * txn2 = get_real_txn(txn);
      assert(fd_funk_txn_merge_all_children(_real, txn2, 1) == FD_FUNK_SUCCESS);
      fd_funk_end_write(_real);

      // Simulate merge
      fake_merge(txn);
    }

    void random_safe_read() {
      fd_funk_rec_key_t i;
      memset(&i, 0, sizeof(i));
      i.ul[0] = ((ulong)lrand48())%MAX_CHILDREN;
      ulong datalen;
      auto* data = fd_funk_rec_query_safe(_real, &i, fd_libc_alloc_virtual(), &datalen);
      if( data ) free(data);
    }
    
    void verify() {
      assert(fd_funk_verify(_real) == FD_FUNK_SUCCESS);

      for (auto i : _txns) {
        assert(i.first == i.second->_key);
        for (auto j : i.second->_recs) {
          assert(j.first == j.second->_key);
          j.second->_touched = false;
        }
      }

      fd_funk_rec_t * rec_map = fd_funk_rec_map( _real, _wksp );
      for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
           !fd_funk_rec_map_iter_done( rec_map, iter );
           iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
        fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
        auto const * xid = fd_funk_rec_xid( rec );
        auto i = _txns.find(xid->ul[0]);
        assert(i != _txns.end());
        auto const * key = fd_funk_rec_key( rec );
        auto& recs = i->second->_recs;
        auto j = recs.find(key->ul[0]);
        assert(j != recs.end());
        auto * rec2 = j->second;
        if (rec2->_erased) {
          assert(rec->flags & FD_FUNK_REC_FLAG_ERASE);
          assert(fd_funk_val_sz(rec) == 0);
        } else {
          assert(!(rec->flags & FD_FUNK_REC_FLAG_ERASE));
          assert(fd_funk_val_sz(rec) == rec2->size());
          assert(memcmp(fd_funk_val(rec, _wksp), rec2->data(), rec2->size()) == 0);
        }
        assert(!rec2->_touched);
        rec2->_touched = true;
      }

      for (auto i : _txns) {
        for (auto j : i.second->_recs) {
          assert(j.second->_touched || j.second->_erased);
        }
      }

      for (auto i : _txns) {
        auto * txn = i.second;
        assert(i.first == txn->_key);
        if (txn->_key == ROOT_KEY) {
          assert(txn->_parent == NULL);
        } else {
          assert(txn->_parent->_children.find(txn->_key)->second == txn);
        }
        txn->_touched = false;
      }

      {
        // Root transaction
        auto * txn2 = _txns[ROOT_KEY];
        assert(!txn2->_touched);
        txn2->_touched = true;

        auto& recs = txn2->_recs;
        for( auto const * rec = fd_funk_txn_first_rec(_real, NULL);
             rec;
             rec = fd_funk_txn_next_rec(_real, rec) ) {
          auto const * key = fd_funk_rec_key( rec );
          auto j = recs.find(key->ul[0]);
          assert(j != recs.end());
        }
      }

      fd_funk_txn_t * txn_map = fd_funk_txn_map( _real, _wksp );
      for( fd_funk_txn_map_iter_t iter = fd_funk_txn_map_iter_init( txn_map );
           !fd_funk_txn_map_iter_done( txn_map, iter );
           iter = fd_funk_txn_map_iter_next( txn_map, iter ) ) {
        fd_funk_txn_t * txn = fd_funk_txn_map_iter_ele( txn_map, iter );
        auto i = _txns.find(txn->xid.ul[0]);
        assert(i != _txns.end());
        auto * txn2 = i->second;
        assert(!txn2->_touched);
        txn2->_touched = true;
        
        auto * parent = fd_funk_txn_parent(txn, txn_map);
        if (parent == NULL)
          assert(ROOT_KEY == txn2->_parent->_key);
        else
          assert(parent->xid.ul[0] == txn2->_parent->_key);

        auto& recs = txn2->_recs;
        for( auto const * rec = fd_funk_txn_first_rec(_real, txn);
             rec;
             rec = fd_funk_txn_next_rec(_real, rec) ) {
          auto const * key = fd_funk_rec_key( rec );
          auto j = recs.find(key->ul[0]);
          assert(j != recs.end());
        }
      }

      for (auto i : _txns) {
        assert(i.second->_touched);
      }
    }
};
