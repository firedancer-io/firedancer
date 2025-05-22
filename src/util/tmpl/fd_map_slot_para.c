/* Generate prototypes, inlines and/or implementations for concurrent
   persistent shared maps based on linear probing with some insights
   from cuckoo hashing for improved concurrent performance.  Notably:

   - Supports an arbitrary number of concurrent operations with a
     comparable performance to a single threaded HPC linear probed map
     for non-conflicting operations (likely hardware NOC limited for
     conflicting operations).

   - Concurrent queries do not interfere with other concurrent queries.

   - All map operations can be serialized.

   - Does not require a key sentinel (but can support them useful for
     the application).

   - Does not require a guarantee there's at least one free element in
     the element store (but like a serial linear probed map, it is a
     good idea to keep utilization below the absolute theoretical
     capacity for strong algorithmic performance guarantees).

   - Insert/modify/query have a run-time configurable worst case O(1)
     cost, regardless of map fill ratio.  (Remove's worst case cost is
     not configurable due to cases involving maps filled to or near
     capacity.  For reasonable fill ratios, remove is also comparable.)

   - Stable in the sense that all keys with the same hash (or more
     generally same initial probe element) are ordered in the element
     store by insertion order.  (This allows the user to use the key
     hash to group related keys contiguously in the element store and
     then stably iterate over them with fast streaming.)

   - Query requires no atomic operations at all.  (Usual target memory
     subsystem requirements that writes to memory become visible to
     other threads in the order in which they were issued in the machine
     code.)

   - Insert/modify/remove only require atomic fetch-and-or (typically
     just one).  There's no need for an atomic compare-and-swap /
     underlying pool of free elements / etc. (Can also be used as a
     non-concurrent map on targets without FD_HAS_ATOMIC.)

   - Map concurrency metadata and the actual map element store can be
     located in separate memory regions (can also split the element
     store over multiple memory regions ... e.g. keys here / values
     there) and can back any of these memory regions by a file system to
     scale beyond billions of elements with no code change.

   - Map metadata easily fits in CPU caches with a fixed O(1) overhead
     regardless of element store capacity.  Access patterns naturally
     exploit CPU and storage caching, streaming and prefetching
     behaviors.

   - Supports asynchronous execution (e.g. issue hints for keys that
     will be accessed soon, do unrelated work while hints are
     prefetching need info into local cache in the background, then do
     key operations ... now all fast and local cache hits).

   - Supports non-plain-old-data keys and non-plain-old-data values
     (both of which are gross on real world computers but commonly done
     nevertheless).

   A map can be persisted beyond the lifetime of the creating process,
   be used inter-process, relocated in memory, be naively
   serialized/deserialized, be moved between hosts, etc.  Massive
   concurrency, high algorithmic and implementation performance for
   normal usage and friendly cache / file system streaming access
   patterns for heavily loaded / heavily concurrent usage are
   prioritized.  In particular, unlike fd_map_chain_para, this takes
   ownership of the underlying element store for the lifetime of the map
   in order to speed up operations and increase concurrency.

   Typical usage:

     struct myele {
       ulong key;  // Technically "MAP_KEY_T MAP_KEY" (default is ulong key)

       ... key can be located arbitrarily in the element.  The mapping
       ... of a key to an element in the element store is arbitrary and
       ... can move while the key is in the map.
     };

     typedef struct myele myele_t;

     #define MAP_NAME  mymap
     #define MAP_ELE_T myele_t
     #include "tmpl/fd_map_slot_para.c"

   will declare the following APIs as a header only style library in the
   compilation unit:

     // A mymap_t is a stack declaration friendly quasi-opaque local
     // object used to hold the state of a local join to a mymap.
     // Similarly, a mymap_query_t / mymap_iter_t holds the local state
     // of an ongoing operation / iteration.  E.g. it is fine to do
     // mymap_t join[1];" to allocate a mymap_t but the contents should
     // not be used directly.

     typedef struct mymap_private       mymap_t;
     typedef struct mymap_query_private mymap_query_t;
     typedef struct mymap_iter_private  mymap_iter_t;

     // mymap_lock_max returns the maximum number of version locks that
     // can be used by a mymap.  Will be a positive integer
     // power-of-two.

     ulong mymap_lock_max( void );

     // mymap_lock_cnt_est returns a reasonable number of locks to use
     // for a map backed by an ele_max capacity element store.  Assumes
     // ele_max is an integer power-of-two.  Returns an integer
     // power-of-two in [1,mymap_lock_max()].

     ulong mymap_lock_cnt_est( ulong ele_max );

     // mymap_probe_max_est returns a reasonable maximum probe sequence
     // length for a map backed by an ele_max capacity element store.
     // Assumes ele_max is an integer power-of-two.  Returns an integer
     // in [1,ele_max].

     ulong mymap_probe_max_est( ulong ele_max );

     // mymap_{align,footprint} returns the alignment and footprint
     // needed for a memory region to be used as a mymap.  align will be
     // an integer power-of-two and footprint will be a multiple of
     // align.  ele_max / lock_cnt / probe_max specify the capacity of
     // the element store / number of version locks / maximum probe
     // sequence length for the map.  footprint returns 0 for invalid
     // configurations.  In a valid configuration, ele_max is an integer
     // power-of-two, lock_cnt is an integer power-of-two, lock_cnt is
     // at most min( lock_max, ele_max ) and probe_max is in
     // [1,ele_max].
     //
     // mymap_new formats a memory region with the required alignment
     // and footprint into a mymap.  shmem points in the caller's
     // address space to the memory region to use.  Returns shmem on
     // success (mymap has ownership of the memory region) and NULL on
     // failure (no changes, logs details).  The caller is not joined on
     // return.  All map versions will be at version 0 / unlocked.  The
     // map contents will be in whatever state the backing element store
     // is in.  IMPORTANT SAFETY TIP!  THE ELEMENT STORE SHOULD BE IN A
     // CONSISTENT STATE BEFORE USING MYMAP_NEW.  For example, the
     // caller could mark all elements as free before calling this and
     // the caller could use verify immediately after creation to verify
     // integrity.
     //
     // mymap_join joins the caller to an existing mymap.  ljoin points
     // to a mymap_t compatible memory region in the caller's address
     // space, shmap points in the caller's address space to the memory
     // region containing the mymap, and shele points in the caller's
     // address space to mymap's element store.  Returns a handle to the
     // caller's local join on success (join has ownership of the ljoin
     // region) and NULL on failure (no changes, logs details).
     //
     // mymap_leave leaves a mymap join.  join points to a current local
     // join.  Returns the memory region used for the join on success
     // (caller has ownership on return and the caller is no longer
     // joined) and NULL on failure (no changes, logs details).  Use the
     // join accessors before leaving to get shmap and shele used by the
     // join if needed.
     //
     // mymap_delete unformats a memory region used as a mymap.  Assumes
     // shmap points in the caller's address space to a memory region
     // containing the mymap and that there are no joins.  Returns shmem
     // on success (caller has ownership of the memory region, any
     // remaining elements still in the mymap are released to the caller
     // implicitly) and NULL on failure (no changes, logs details).

     ulong     mymap_align    ( void );
     ulong     mymap_footprint( ulong chain_cnt );
     void *    mymap_new      ( void * shmem, ulong ele_max, ulong lock_cnt, ulong probe_max, ulong seed );
     mymap_t * mymap_join     ( void * ljoin, void * shmap, void * shele );
     void *    mymap_leave    ( mymap_t * join );
     void *    mymap_delete   ( void * shmap );

     // mymap_{ele_max,lock_cnt,probe_max,seed} return the mymap
     // configuration.  Assumes join is a current local join.  The
     // values will be valid for the mymap lifetime.

     ulong mymap_ele_max  ( mymap_t const * join );
     ulong mymap_lock_cnt ( mymap_t const * join );
     ulong mymap_probe_max( mymap_t const * join );
     ulong mymap_seed     ( mymap_t const * join );

     // mymap_{shmap,shele} return join details.  Assumes join is a
     // current local join.  The values will be valid for the join
     // lifetime.  mymap_{shmap_const,shele_const} are const correct
     // versions.

     void const * mymap_shmap_const( mymap_t const * join );
     void const * mymap_shele_const( mymap_t const * join );

     void * mymap_shmap( mymap_t * join );
     void * mymap_shele( mymap_t * join );

     // mymap_lock_{idx,ele0,ele1} specify the mapping between map
     // version lock indices and element store element indices.  Assumes
     // join is a current local join and ele_idx / lock_idx is in
     // [0,ele_max) / is in [0,lock_cnt).  mymap_lock_idx is the index
     // of the version lock that protects element store element ele_idx,
     // in [0,lock_cnt).  [mymap_lock_ele0,mymap_lock_ele1) is the
     // contiguous range of elements protected by lock lock_idx.  ele0
     // is in [0,ele_max), ele1 is in (0,ele_max], and ele0<ele1.

     ulong mymap_lock_idx ( mymap_t const * join, ulong ele_idx  );
     ulong mymap_lock_ele0( mymap_t const * join, ulong lock_idx );
     ulong mymap_lock_ele1( mymap_t const * join, ulong lock_idx );

     // mymap_key_{eq,hash} expose the provided MAP_KEY_{EQ,HASH} macros
     // as inlines with strict semantics.  They assume that the provided
     // pointers are in the caller's address space to keys that will not
     // be changed during the call.  They retain no interest in any keys
     // on return.
     //
     // mymap_key_eq returns 1 if *k0 and *k1 are equal and 0 otherwise.
     //
     // mymap_key_hash returns the hash of *key using the hash function
     // seed.  Should ideally be a random mapping from a MAP_KEY_T to a
     // ulong but this depends on what the user actually used for
     // MAP_KEY_HASH.  The seed used by a particular mymap instance can
     // be obtained above.

     int   mymap_key_eq  ( ulong * k0,  ulong * k1 );
     ulong mymap_key_hash( ulong * key, ulong seed );

     // mymap_backoff does FD_SPIN_PAUSE a random number of times.  The
     // number of pauses is an approximately uniform IID random number
     // in [0,scale/2^16] where scale is in [0,2^32).  Specifically, the
     // number of pauses is:
     //
     //   floor( scale r / 2^48 )
     //
     // where r is a non-deterministic 32-bit uniform IID random number.
     // Under the hood, r is generated by hashing the user provided seed
     // and the least significant 32-bits of the CPU tickcounter.
     // Ideally, seed is a 32-bit globally unique identifier for the
     // logical thread of execution but this is up to the application to
     // specify and rarely matters in practice.  This is a useful
     // building block for random exponential backoffs.

     void mymap_backoff( ulong scale, ulong seed );

     // mymap_query_memo returns the key_hash of the query associated
     // with the query's key to allow users to minimize potentially
     // expensive key hash computations in various operations.
     //
     // mymap_query_ele returns a pointer in the caller's address space
     // to the element store element associated with the query or a
     // sentinel value.  The sentinel value is application dependent and
     // thus arbitrary (e.g. not necessarily in the element store,
     // including NULL, a local temporary used as a bit bucket, etc).
     // Assumes query is valid.  The lifetime of the returned pointer
     // depends on the query.  mymap_query_ele_const is a const correct
     // version.

     ulong           mymap_query_memo     ( mymap_query_t const * query );
     myele_t const * mymap_query_ele_const( mymap_query_t const * query );
     myele_t *       mymap_query_ele      ( mymap_query_t *       query );

     // mymap_hint hints that the caller plans to do an operation
     // involving key soon.  Assumes join is a current local join, key
     // points to a valid key in the caller's address space for the
     // duration of the call and query points to a local scratch to hold
     // info about the hint.  Retains no interest in key.  On return,
     // the query memo will be initialized.
     //
     // flags is a bit-or of FD_MAP_FLAG flags.  If FD_MAP_FLAG_USE_HINT
     // is set, this will assume that query's memo is already
     // initialized for key (e.g. mostly useful for hashless
     // prefetching).  If FD_MAP_FLAG_PREFETCH_META /
     // FD_MAP_FLAG_PREFETCH_DATA is set, this will issue a prefetch for
     // key's mymap metadata (i.e. lock version) / the element at the
     // start of key's probe sequence (i.e. the location of key or
     // contiguously shortly before it) FD_MAP_FLAG_PREFETCH combines
     // both for convenience.  This can be used to overlap key access
     // latency with unrelated operations.  All other flags are ignored.

     void
     mymap_hint( MAP_(t) const *   join
                 MAP_KEY_T const * key
                 MAP_(query_t) *   query,
                 int               flags );

     // mymap_prepare tries to start an insert/modify/blocking query
     // operation for key.  Assumes join is a current local join, key
     // points to valid key in the caller's address space for the
     // duration of the call and query points to a local scratch to hold
     // the info about the prepare.  Retains no interest in key.
     // Returns FD_MAP_SUCCESS (0) and an FD_MAP_ERR (negative) on
     // failure.  This is a non-blocking fast O(1) (O(probe_max) worst
     // case) and supports highly concurrent operation.
     //
     // flags is a bit-or of FD_MAP_FLAG flags.  If FD_MAP_FLAG_BLOCKING
     // is set / clear in flags, this is allowed / not allowed to block
     // the caller.  If FD_MAP_FLAG_USE_HINT is set, this assumes
     // query's memo is already initialized for key.  This can be used
     // to avoid redundant expensive key hashing when prefetching.  All
     // other flags are ignored (the upper 26-bits of flags can be used
     // to provide a local seed for random backoffs but this is up to
     // the application and rarely matters in practice).
     //
     // On success, the caller is in a prepare for key, query is
     // initialized with info about prepare (including query's memo
     // initialized for key).  ele=mymap_query_ele(query) gives the
     // location in the caller's address space to an element store
     // element for the prepare that will be stable for the duration of
     // the prepare and memo=mymap_query_memo(query) gives the key hash.
     //
     // If the element is marked as free, key is not in the map and ele
     // is where key could be inserted.  If the caller is inserting key,
     // the caller should populate element's key with key, element's
     // memo (if any) with memo (avoids having to rehash the key), mark
     // ele as used and then do a mymap_publish to complete the insert.
     // If not, the caller should keep ele marked as free and do a
     // mymap_cancel to complete the prepare (doesn't matter from the
     // map's point-of-view if anything else was clobbered /
     // mymap_publish would also work here).
     //
     // If the element is marked as used, key is in the map at ele.  If
     // the caller is modifying key's value, the caller should do the
     // modification and then mymap_publish to complete the modify.  If
     // not (e.g. blocking query), the caller can inspect ele contents
     // and the mymap_cancel to complete the blocking query
     // (mymap_publish would also work here).  In both cases, the caller
     // should not modify ele's key, modify ele's memo, or mark ele as
     // free.  Note that mymap_publish must be used even if the
     // modifications were only temporary.
     //
     // On failure, the caller is not in a prepare for key, query
     // ele==sentinel and query memo will be initialized for key.
     /  Reasons for failure:
     //
     // - FD_MAP_ERR_AGAIN: A potentially conflicting operation was in
     //   progress at some point during the call.  Try again later (e.g.
     //   after a random exponential backoff).  Never returned on a
     //   blocking call.
     //
     // - FD_MAP_ERR_FULL: key was not in the map but inserting ele
     //   would require making a probe sequence longer than probe_max.
     //   Try again when the map is less full (e.g. after removing some
     //   elements).
     //
     // mymap_publish ends the prepare described by query, updating the
     // map version to reflect changes made during the prepare.  Assumes
     // query is valid and describes an active prepare.  Cannot fail and
     // will not be in the prepare will finished on return (query's memo
     // will still be intialized for key).  This is a generally safe way
     // to end a prepare even if the caller did not modify the map
     // during the prepare.
     //
     // mymap_cancel ends the prepare described by query, reverting the
     // map version to reflect that the caller did not change the map
     // during the prepare.  Assumes query is valid and describes an
     // active prepare and that the caller did not make any meaningful
     // modifications to the map during the prepare (note that temporary
     // changes during the prepare can be considered modifications as
     // per the above).  Cannot fail and will not be in the prepare will
     // finished on return (query's memo will still be initialized
     // for key).  This is a safe way to end a prepare only if the
     // caller did not modify the map during the prepare.
     //
     // IMPORTANT SAFETY TIP!  Do not nest or interleave prepares,
     // remove or queries for the same map on the same thread.
     //
     // IMPORTANT SAFETY TIP!  A successful prepare must have a matching
     // publish or cancel (and then ideally as soon as possible).
     //
     // IMPORTANT SAFETY TIP!  The order in which keys that hash to the
     // same slot were inserted into the map is preserved for the
     // lifetime of the keys.  Thus the hash function used can be
     // constructed to create ordered iterators over groups of keys.

     int  mymap_prepare( mymap_t * join, ulong const * key, myele_t * sentinel, mymap_query_t * query, int flags );
     void mymap_publish( mymap_query_t * query );
     void mymap_cancel ( mymap_query_t * query );

     // mymap_remove removes key from the mymap.  Assumes join is a
     // current local join and key is valid for the duration of the
     // call.  Retains no interest in key.  This is non-blocking fast
     // typically O(1) and supports highly concurrent operation.
     //
     // flags is a bit-or of FD_MAP_FLAG flags.  If FD_MAP_FLAG_BLOCKING
     // is set / clear in flags, this is allowed / not allowed to block
     // the caller.  If FD_MAP_FLAG_USE_HINT is set, this assumes
     // query's memo is already initialized for key.  This can be used
     // to avoid redundant expensive key hashing when prefetching.  If
     // clear, query is ignored and can be set NULL.  All other flags
     // are ignored (the upper 26-bits of flags can be used to provide a
     // local seed for random backoffs but this is up to the application
     // and rarely matters in practice).
     //
     // Returns FD_MAP_SUCCESS (0) on success and an FD_MAP_ERR
     // (negative) on failure.  On success, key's mapping was removed at
     // some point during the call.  On failure, no changes were made by
     // this call and:
     //
     // - FD_MAP_ERR_KEY: Key was not found in the mymap at some point
     //   during the call.
     //
     // - FD_MAP_ERR_AGAIN: A potentially conflicting operation was in
     //   progress at some point during the call.  Same considerations
     //   as prepare above.  Never returned on a blocking call.
     //
     // IMPORTANT SAFETY TIP!  Do not nest or interleave prepares,
     // remove or queries for the same map on the same thread.

     int mymap_remove( mymap_t * join, ulong const * key, mymap_query_t const * query, int flags );

     // mymap_query_try tries to speculatively query a mymap for key.
     // On return, query will hold information about the try (including
     // query's memo initialized for key).  sentinel gives the query
     // element pointer value (arbitrary) to pass through when it is not
     // safe to try the query.  Assumes join is a current local join and
     // key is valid for the duration of the call.  Does not modify the
     // mymap and retains no interest in key, sentinel or query.  This
     // is a non-blocking fast O(1) (O(probe_max) worst case) and
     // supports highly concurrent operation.
     //
     // flags is a bit-or of FD_MAP_FLAG flags.  If FD_MAP_FLAG_BLOCKING
     // is set / clear in flags, this is allowed / not allowed to block
     // the caller.  If FD_MAP_FLAG_USE_HINT is set, this assumes
     // query's memo is already initialized for key.  This can be used
     // to avoid redundant expensive key hashing when prefetching.  All
     // other flags are ignored (the upper 26-bits of flags can be used
     // to provide a local seed for random backoffs but this is up to
     // the application and rarely matters in practice).
     //
     // Returns FD_MAP_SUCCESS (0) on success and an FD_MAP_ERR
     // (negative) on failure.  On success, key mapped to the element
     // store element mymap_query_ele( query ) in the caller's address
     // space at some point during the call.  The mymap retains
     // ownership of this element but the caller can zero copy
     // speculatively process the element's contents.  On failure,
     // mymap_query_ele( query ) will be sentinel and returns:
     //
     // - FD_MAP_ERR_KEY: Key was not found in the mymap in some point
     //   during the call.
     //
     // - FD_MAP_ERR_AGAIN: A potentially conflicting operation was in
     //   progress at some point during the call.  Try again later (e.g.
     //   after a random exponential backoff).  Unlike prepare and
     //   remove, this call does _not_ require any locks for key's probe
     //   sequence.  As such, AGAIN can only be caused by concurrent
     //   prepare/remove operations and this will never interfere with
     //   any other concurrent operation.  Among the many implications,
     //   a query will never delay a concurrent query and AGAIN will
     //   never be returned if only concurrent speculative queries are
     //   in progress.  Never returned on a blocking call.
     //
     // IMPORTANT SAFETY TIP!  THE CALLER SHOULD BE PREPARED TO HANDLE
     // ARBITRARY AND/OR INCONSISTENT VALUES FOR ELEMENT FIELDS DURING
     // SPECULATIVE PROCESSING.  CALLERS SHOULD NOT COMMIT ANY RESULTS
     // OF SPECULATIVE PROCESSING UNTIL IT TESTS THE QUERY WAS
     // SUCCESSFUL.
     //
     // The simplest form of speculative processing is to copy the
     // element store element into a local temporary, test that the
     // speculation was valid, and then process the local temporary copy
     // at its leisure.  Zero copy, more selective copying and/or
     // writing speculative results into local temporaries are more
     // advanced examples of speculative processing.
     //
     // Use mymap_prepare to do a blocking (non-speculative) query.
     //
     // mymap_query_test tests if an in-progress query is still valid.
     // Assumes query is valid, we are still in a query try and lock
     // version numbers have not wrapped since we started the try.
     // Returns FD_MAP_SUCCESS (0) if the query is still valid and
     // FD_MAP_ERR_AGAIN (negative) if a potentially conflicting
     // operation was in progress at some point during the try.
     //
     // IMPORTANT SAFETY TIP!  Do not nest or interleave prepares,
     // remove or queries for the same map on the same thread.

     int
     mymap_query_try( mymap_t const * join,
                      ulong const *   key,
                      myele_t const * sentinel,
                      mymap_query_t * query,
                      int             flags );

     int mymap_query_test( mymap_query_t const * query );

     // mymap_lock_range tries to acquire locks lock_idx for lock_idx in
     // [range_start,range_start+range_cnt) (cyclic).
     //
     // flags is a bit-or of FD_MAP_FLAG flags.  If FD_MAP_FLAG_BLOCKING
     // is set / clear in flags, this is allowed / not allowed to block
     // the caller.  If FD_MAP_FLAG_RDONLY is set, the caller promises
     // to only read the elements covered by the range while holding the
     // locks.  All other flags are ignored (the upper 26-bits of flags
     // can be used to provide a local seed for random backoffs but this
     // is up to the application and rarely matters in practice).
     //
     // Returns FD_MAP_SUCCESS (0) on success and FD_MAP_ERR_AGAIN
     // (negative) if there was a potentially conflicting operation in
     // progress at some point during the call.  On success,
     // version[lock_idx] will hold the version to use when releasing
     // that lock.  On failure, version may have been clobbered.  AGAIN
     // is never returned if BLOCKING is set.
     //
     // mymap_unlock_range unlocks a similarly specified range.  Assumes
     // caller has the locks and version[lock_idx] is the value set when
     // locked was obtained.
     //
     // These both assume join is a current local join, range_start is
     // in [0,lock_cnt), range_cnt is in [0,lock_cnt] and version is
     // valid with space for lock_cnt entries (YES ... LOCK_CNT, NOT
     // RANGE_CNT ... this is trivial with a compile time stack
     // temporary as lock_cnt<=MAP_LOCK_MAX).

     int
     mymap_lock_range( mymap_t * join,
                       ulong     range_start,
                       ulong     range_cnt,
                       int       flags,
                       ulong *   version );

     void
     mymap_unlock_range( mymap_t *     join,
                         ulong         range_start,
                         ulong         range_cnt,
                         ulong const * version );

     // The mymap_iter_* APIs are used to iterate over all keys inserted
     // into the map with the same memo (to support grouping of keys by
     // key hash value).  The iteration order will be from the least
     // recently inserted to most recently inserted.  flags has similar
     // meaning as other APIs.  Example usage:
     //
     //   ulong memo = ... hash of keys to iterate over ...
     //
     //   mymap_iter_t iter[1];
     //   int err = mymap_iter_init( join, memo, 0, iter );
     //
     //   if( FD_UNLIKELY( err ) ) {
     //
     //     ... At this point, err is FD_MAP_ERR_AGAIN and caller has
     //     ... ownership of iter.  There was a potentially conflicting
     //     ... prepare or remove in progress at some point during the
     //     ... call.  We can try again later (e.g. after a random
     //     ... backoff or doing other non-conflicting work).
     //     ... mymap_iter_done will be 1, mymap_iter_fini will be a
     //     ... no-op.  Never returned if mymap_iter_init flags has
     //     ... FD_MAP_FLAG_BLOCKING set.
     //
     //   } else {
     //
     //     ... At this point, we are in an iteration and iteration has
     //     ... ownership of iter.
     //
     //     while( !mymap_iter_done( iter ) ) {
     //       myele_t * ele = mymap_iter_ele( iter );
     //
     //       ... At this point, mymap_key_hash( ele->key, seed ) == memo (==ele's memo if memoized)
     //
     //       ... process ele here.
     //
     //       ... IMPORTANT!  Generally speaking, it is not okay to
     //       ... insert, remove, modify, blocking read, non-blocking
     //       ... read here.  It is okay to read ele and modify any
     //       ... value fields though.  If mymap_iter_init flags had
     //       ... FD_MAP_FLAG_RDONLY set, caller promises it is only
     //       ... reading ele here.
     //
     //       mymap_iter_next( iter );
     //     }
     //
     //     mymap_iter_fini( iter );
     //
     //     ... At this point, we are not in an iteration and caller has
     //     ... ownership of iter.
     //
     //   }

     int            mymap_iter_init( mymap_t * join, ulong memo, int flags, mymap_iter_t * lmem );
     int            mymap_iter_done( mymap_iter_t * iter );
     myele_t *      mymap_iter_ele ( mymap_iter_t * iter );
     mymap_iter_t * mymap_iter_next( mymap_iter_t * iter );
     mymap_iter_t * mymap_iter_fini( mymap_iter_t * iter );

     // mymap_verify returns FD_MAP_SUCCESS (0) if the join, underlying
     // map and underlying element store give a mapping of unique keys
     // to unique elements in the element store with a bounded maximum
     // probe length.  Returns FD_MAP_ERR_INVAL (negative) otherwise (no
     // changes by this call, logs details).  Assumes that caller has
     // all the map locks and/or the map is otherwise known to be idle.

     int mymap_verify( mymap_t const * join );

     // mymap_strerror converts an FD_MAP_SUCCESS / FD_MAP_ERR code into
     // a human readable cstr.  The lifetime of the returned pointer is
     // infinite.  The returned pointer is always to a non-NULL cstr.

     char const * mymap_strerror( int err );

   Do this as often as desired in a compilation unit to get different
   types of concurrent maps.  Options exist for generating library
   header prototypes and/or library implementations for concurrent maps
   usable across multiple compilation units.  Additional options exist
   to use different hashing functions, key comparison functions, etc as
   detailed below.

   IMPORTANT SAFETY TIP!  If using a key sentinel, prepare/remove/query
   operations assume the input key is not the key sentinel (i.e. a
   sentinel is not considered a "valid key).  Sentinel keys are not
   necessary if MAP_ELE_IS_FREE, MAP_ELE_FREE and MAP_ELE_MOVE are set
   appropriately.

   To better understand prepare / publish / cancel semantics:

     mykey_t * key = ... key to insert / modify / blocking query

     mymap_query_t query[1];
     int       err  = mymap_prepare( map, key, sentinel, query, 0 );
     myele_t * ele  = mymap_query_ele ( query );
     ulong     memo = mymap_query_memo( query );

     ... At this point, memo == mymap_key_hash( key, seed )

     if( FD_UNLIKELY( err ) ) {

       ... At this point, we are not in a prepare for key and
       ... ele==sentinel.

       ... If err is FD_MAP_ERR_AGAIN, there was a potentially
       ... conflicting prepare or remove in progress at some point
       ... during the call.  We can try again later (e.g. after a
       ... random backoff or doing other non-conflicting work).
       ... Never returned for a blocking call.

       ... If err is FD_MAP_ERR_FULL, key was not in the map but
       ... inserting it would have created a key probe sequence longer
       ... than probe_max at some point during the call.  We can try
       ... again later when it is less full (e.g. after removing keys
       ... from the map).

     } else if( ... ele is marked as free ... ) ) {

       ... At this point, we are in a prepare for key, key is not in
       ... the map and ele points in the caller's address space to free
       ... element in the element store suitable for holding key.

       ... initialize ele here, including populating ele's key with key
       ... and (if memoized) populating ele's memo with memo.

       if( ... we decided not to insert key ... ) mymap_cancel( query ); // "failed insert"
       else {
         ... mark ele as used
         mymap_publish( query ); // "insert"
       }

     } else {

       ... At this point, we are in a prepare for key, key is in the map
       ... and ele points in the caller's address space to the element
       ... store element that currently contains key.  We are free to
       ... modify ele's value.  We should not modify ele's key, modify
       ... ele's memo (if memoized) or mark ele as free.

       ... process ele here

       if( ... we didn't modify ele ... ) mymap_cancel ( query ); // "blocking query"
       else                               mymap_publish( query ); // "modify"

     }

   To better understand remove semantics:

     mykey_t * key = ... key to remove

     int err = mymap_remove( map, key, NULL, 0 );

     if( FD_UNLIKELY( err ) ) {

       ... If err is FD_MAP_ERR_AGAIN, there was a potentially
       ... conflicting prepare or remove in progress at some point
       ... during the call.  We can try again later (e.g. after a random
       ... backoff or doing other non-conflicting work).
       ... Never returned for a blocking call.

       ... If err is FD_MAP_ERR_KEY, key was not in the map at some
       ... point during the call (so remove did not do anything).

     } else {

       ... key was removed from the map at some point during the call.
       ... The remove might have shuffled other keys.  This shuffling
       ... can only decrease probe sequence length for any remaining
       ... keys and preserves insertion ordering for keys with the same
       ... hash (or initial probe element more generally).

     }

   To better understand query semantics:

     mykey_t * key = ... key to query

     mymap_query_t query[1];
     int             err  = mymap_query_try( join, key, sentinel, query, 0 );
     myele_t const * ele  = mymap_query_ele_const( query );
     ulong           memo = mymap_query_memo     ( query );

     ... At this point, memo==mymap_key_hash( key, seed )

     if( FD_UNLIKELY( err ) ) {

       ... At this point, ele==sentinel
       ...
       ... If err is FD_MAP_ERR_KEY, key was not in the mymap at some
       ... point during the try.
       ...
       ... If err is FD_MAP_ERR_AGAIN, there was a potentially
       ... conflicting operation in progress during the try and we can
       ... try again later (e.g. after a random backoff or doing other
       ... non-conflicting work).

     } else {

       ... At this point, ele points in our address space to an element
       ... in the element store (non-NULL) and ele->key matched key at
       ... some point during the try.

       ... Speculatively process ele here.
       ...
       ... DO NOT TRUST ANY RESULTS OF THIS SPECULATIVE PROCESSING YET.
       ... THERE IS NO GUARANTEE YET THAT A CONCURRENT USER HASN'T
       ... CHANGED THE MYMAP IN A WAY THAT COULD YIELD ARBITRARY AND
       ... INCONSISTENT RESULTS.
       ...
       ... The simplest and most common form of speculative processing
       ... is to copy the needed portions of ele into local stack temps.
       ...
       ... Note: concurrent operations include removing key from the
       ... mymap (and maybe multiple cycles of inserting and removing it
       ... and then at potentially different element store locations) or
       ... unrelated removes potentially shuffling the location of this
       ... key.  That's not an issue practically as the ele pointer here
       ... will be to an element compatible memory region that will
       ... continue to exist regardless and we shouldn't be trusting any
       ... query reads yet (the query test will detect if these can be
       ... trusted).  See rant in fd_map_chain_para.c for more details.

       ... At this point, we are done with speculative processing (or we
       ... don't want to do any more speculative processing if the try
       ... has already failed).

       err = mymap_query_test( query );
       if( FD_UNLIKELY( err ) ) {

         ... At this point, err will be FD_MAP_ERR_AGAIN and a
         ... potentially conflicting operation in the try was detected
         ... by the test.

         ... Application specific handling here (e.g. try again after a
         ... random backoff or doing other non-conflicting work).

       } else {

         ... At this point, the results of the speculation thus far can
         ... be trusted and can be considered to have been computed at
         ... some point in time between try and test.

       }
     }

   Example use of lock_range / unlock (do a parallel snapshot of an
   entire map at a globally well defined point in time with minimal
   interference to ongoing concurrent modifications):

     ulong version[ mymap_lock_max() ];

     ulong lock_cnt = mymap_lock_cnt( join );

     mymap_lock_range( join, 0, lock_cnt, FD_MAP_FLAGS_BLOCKING | FD_MAP_FLAGS_RDONLY, version );

     for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) { ... parallelize this loop over snapshot threads as desired
       ulong ele0 = mymap_lock_ele0( join, lock_idx );
       ulong ele1 = mymap_lock_ele1( join, lock_idx );

       ... process element store elements [ele0,ele1) here

       mymap_unlock_range( join, lock_idx, 1UL, version );
     }

   Note that mymap_lock_range in this example might block the caller for
   a long time if the map is under heavy concurrent modification.  To
   prioritize the snapshotting over these operations, the same API can
   be used to prioritize the snapshot over ongoing concurrent
   modifications:

     ulong version[ mymap_lock_max() ];

     ulong lock_cnt = mymap_lock_cnt( join );

     for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ )
       mymap_lock_range( join, lock_idx, 1UL, FD_MAP_FLAGS_BLOCKING | FD_MAP_FLAGS_RDONLY, version );

     for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) { ... parallelize this loop over snapshot threads as desired
       ulong ele0 = mymap_lock_ele0( join, lock_idx );
       ulong ele1 = mymap_lock_ele1( join, lock_idx );

       ... process element store elements [ele0,ele1) here

       mymap_unlock_range( join, lock_idx, 1UL, version );
     }

   Implementation overview:

     A map is basically a persistent shared array of version numbers
     named lock.  lock[ lock_idx ] contains a version number that covers
     map slots [lock_idx(ele_max/lock_cnt),(lock_idx+1)(ele_max/lock_cnt)).

     When trying an operation that could impact probe sequences passing
     through a lock's range of slots, the version number is atomically
     incremented.  It is incremented again at completion.  It may also
     be decremented if the operation didn't end up modifying any of the
     covered slots.

     Thus, an {odd,even} version number indicates that there is {a
     potential,not any} operation in progress that could impact probe
     sequences passing through the corresponding slots.  The most
     significant bits of the version number can be used for lockfree
     style operations to detect changes to any probe sequences they use.

     When the map is not overloaded, key probe sequences are typically
     O(1) long and, in general, at most a (user configured) probe_max
     long.  Since a version number covers many slots typically, this
     implies that the typical "read" operation (e.g.
     query_try/query_test) looks like:

     - try:  observe lock version numbers covering all slots in key's
             probe sequence, fail if any locked (typically 1 normal read
             that hits L1/L2 cache, especially in the common case of
             reads more frequent than writes)
     - spec: speculatively process the element containing key
     - test: check version numbers haven't changed (typically 1 normal
             read that is an even more likely L1/L2 cache hit), fail if
             any changed

     And the typical "write" operation (e.g. prepare/publish) looks
     like:

     - prepare: increment lock version numbers covering all slots in
                key's probe sequence, fail if any locked (typically 1
                atomic fetch-and-or done test-and-test-and-set style to
                minimize hardware NOC contention)
     - exec:    (non-speculatively) process the element containing key
     - publish: increment version numbers (typically 1 normal read/write
                that hits L1/L2 cache)

     Readers never block concurrent readers or writers.  Writers can
     block other readers and other writers.  If there are many more
     version locks than concurrent writers though, writers are unlikely
     to interfere with concurrent readers or writers.  In all cases, all
     map operations are serializable.

     For maps that are loaded to their capacity, probe sequences could
     be up to probe_max long and probe_max might be quite large.  This
     implies that more than one version lock might be needed.  Since
     this range is cyclic contiguous in memory, the locking operations
     are nice compact streaming access patterns.  And similarly for the
     element store access patterns. */

#include "fd_map.h"

/* MAP_NAME gives the API prefix to use for map */

#ifndef MAP_NAME
#error "Define MAP_NAME"
#endif

/* MAP_ELE_T is the map element type */

#ifndef MAP_ELE_T
#error "Define MAP_ELE_T"
#endif

/* MAP_KEY_T is the map key type */

#ifndef MAP_KEY_T
#define MAP_KEY_T ulong
#endif

/* MAP_KEY is the MAP_ELE_T key field */

#ifndef MAP_KEY
#define MAP_KEY key
#endif

/* MAP_KEY_EQ returns 0/1 if *k0 is the same/different as *k1 */

#ifndef MAP_KEY_EQ
#define MAP_KEY_EQ(k0,k1) ((*(k0))==(*(k1)))
#endif

/* MAP_KEY_HASH returns a random mapping of *key into ulong.  The
   mapping is parameterized by the 64-bit ulong seed. */

#ifndef MAP_KEY_HASH
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( (*(key)) ^ (seed) )
#endif

/* If MAP_MEMOIZE is defined to non-zero, elements have a field that
   can be used while in the map to hold the MAP_KEY_HASH for an
   element's key.  This is useful for accelerating user code that might
   need a hash and various map operations. */

#ifndef MAP_MEMOIZE
#define MAP_MEMOIZE 0
#endif

/* If MAP_MEMOIZE is non-zero, MAP_MEMO is the memo element field.
   Should be a ulong.  Like MAP_KEY and MAP_NEXT, when an element is in
   the map, this value is managed by the map and will contain the
   MAP_KEY_HASH of the element's key and the map's seed. */

#ifndef MAP_MEMO
#define MAP_MEMO memo
#endif

/* If MAP_MEMOIZE is defined to non-zero, a non-zero MAP_KEY_EQ_IS_SLOW
   indicates the MAP_MEMO field should be used to accelerate MAP_KEY_EQ
   operations.  This is useful when MAP_KEY_EQ is non-trivial (e.g.
   variable length string compare, large buffer compares, etc). */

#ifndef MAP_KEY_EQ_IS_SLOW
#define MAP_KEY_EQ_IS_SLOW 0
#endif

/* MAP_ELE_IS_FREE returns 0/1 if the slot pointed to by ele in the
   caller's address space contains / does not contain a key-value pair.
   The implementation can assume ele is valid and that it is safe to
   speculate on ele.  The default implementation tests if key is not 0.
   If using a different key sentinel or not using a key sentinel, update
   this appropriately. */

#ifndef MAP_ELE_IS_FREE
#define MAP_ELE_IS_FREE(ctx,ele) (!((ele)->MAP_KEY))
#endif

/* MAP_ELE_FREE frees the key-value pair in the slot pointed to by ele
   in the caller's address space.  The implementation can assume ele is
   valid, ele contains a key-value pair on entry and there will be no
   concurrent operations on ele during the free.  The default
   implementation sets key to 0.  If using a different key sentinel or
   not using a key sentinel, update this appropriately.  Likewise, if
   not using plain-old-data keys and values, this should do the
   appropriate resource management.  The join ctx is provided to
   facilitate this. */

#ifndef MAP_ELE_FREE
#define MAP_ELE_FREE(ctx,ele) do (ele)->MAP_KEY = (MAP_KEY_T)0; while(0)
#endif

/* MAP_ELE_MOVE moves the key-value pair in slot src to slot dst.
   src and dst are in the caller's address space.  The implementation
   can assume src and dst are valid, dst does not contain a key-value
   pair on entry, src contains a key-value on pair on entry, and there
   will be no concurrent operations on src and dst during the move.  The
   default implementation shallow copies src to dst and sets src key to
   0.  If using a different key sentinel or not using a key sentinel,
   update this appropriately.  Likewise, if elements do not use
   plain-old-data keys and/or values, this should do the appropriate key
   and/or value resource management.  The join ctx is provided to
   facilitate this. */

#ifndef MAP_ELE_MOVE
#define MAP_ELE_MOVE(ctx,dst,src) do { MAP_ELE_T * _src = (src); (*(dst)) = *_src; _src->MAP_KEY = (MAP_KEY_T)0; } while(0)
#endif

/* MAP_CTX_MAX specifies the maximum number of bytes of user context
   for use in MAP_ELE above (e.g. custom allocators / workspaces / local
   pointers to additional value arrays / etc).  This context will be
   ulong aligned.  Default is up to 72 bytes. */

#ifndef MAP_CTX_MAX
#define MAP_CTX_MAX (72UL)
#endif

/* MAP_VERSION_T gives the map version index type.  Should be a
   primitive unsigned integer type.  The least significant bit is used
   to indicate whether or not a slot could be impacted by an in progress
   map operation.  The remaining bits indicate the version number.  The
   default is ulong, yielding effectively infinite ABA protection (e.g.
   a lockfree query operation would need to be stalled for over ~2^63
   concurrent insert/modify/remove map operations before risk of getting
   confused by version number reuse ... which would take millennia for
   modern hardware practically).  Narrow types yield less metadata
   footprint overhead for the map and lower ABA protection.  (For human
   hard real-time applications, uint is probably fine and, in for
   computer hard computer real-time applications, ushort and/or uchar
   could be fine).  */

#ifndef MAP_VERSION_T
#define MAP_VERSION_T ulong
#endif

/* MAP_LOCK_MAX gives the maximum number of version locks the map can
   support.  This should be positive and an integer power-of-two.  This
   essentially is limit on the maximum number of concurrent operations
   and thus should be much greater than the number of concurrent
   insert/modify/remove operations in expected map usage.  Default is
   1024.

   Note that this is not theoretically required for the below
   implementation.  This exists to compile time bound stack utilization
   of prepare/remove/query_try.  That is,
   sizeof(MAP_VERSION_T)*MAP_LOCK_MAX should be a L1D cache / L2D cache
   / stack allocation friendly footprint (defaults yield 8 KiB).
   MAP_LOCK_MAX could be removed by using an dynamic stack allocation
   but that would limit this to targets with FD_HAS_ALLOCA.  Could also
   be eliminated by using a dynamic footprint lock cache in the query
   structure, join structures and/or combining the query and join
   structures.  These are cumbersome for the user and the last two add
   restrictions to intra-process multithreaded usage not seen in other
   FD persistent inter-process datastructures.  (Consider using a
   massive/reasonable MAP_LOCK_MAX when FD_HAS_ALLOCA is set/clear and
   then using alloca in prepare/remove/query_try when FD_HAS_ALLOCA is
   set?  Almost the best of both worlds but does imply some subtle
   restrictions if trying to interoperate between targets compiled with
   different features ... avoiding for now.) */

#ifndef MAP_LOCK_MAX
#define MAP_LOCK_MAX (1024)
#endif

/* MAP_ALIGN gives the alignment required for the map shared memory.
   Default is 128 for double cache line alignment.  Should be at least
   ulong alignment. */

#ifndef MAP_ALIGN
#define MAP_ALIGN (128UL)
#endif

/* MAP_MAGIC gives the shared memory magic number to aid in persistent
   and/or interprocess usage. */

#ifndef MAP_MAGIC
#define MAP_MAGIC (0xf17eda2c37c5107UL) /* firedancer cslot version 0 */
#endif

/* MAP_IMPL_STYLE controls what to generate:
     0 - header only library
     1 - library header declaration
     2 - library implementation */

#ifndef MAP_IMPL_STYLE
#define MAP_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

#if MAP_IMPL_STYLE==0 /* local use only */
#define MAP_STATIC FD_FN_UNUSED static
#else /* library header and/or implementation */
#define MAP_STATIC
#endif

#define MAP_(n) FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

#if MAP_IMPL_STYLE!=2 /* need header */

#include "../bits/fd_bits.h"

struct __attribute__((aligned(MAP_ALIGN))) MAP_(shmem_private) {

  /* This point is MAP_ALIGN aligned */

  ulong magic;      /* ==MAP_MAGIC */
  ulong ele_max;    /* Element store capacity, positive and an integer power-of-two */
  ulong lock_cnt;   /* Number of locks, positive and an integer power-of-two <= min( ele_max, MAP_LOCK_MAX ) */
  ulong probe_max;  /* Maximum length probe sequence, in [1,ele_max] */
  ulong seed;       /* Key hash seed, arbitrary */
  int   lock_shift; /* log2( ele_max / lock_cnt ), non-negative */

  /* Padding to MAP_ALIGN alignment here */

  /* MAP_VERSION_T lock[ lock_cnt ] here (obligatory sigh about lagging
     C++ support for 0 sized structure array footers). */

  /* Padding to MAP_ALIGN alignment here */
};

typedef struct MAP_(shmem_private) MAP_(shmem_t);

struct MAP_(private) {
  MAP_ELE_T     * ele;                /* Location of the element store in the local address space, indexed [0,ele_max) */
  MAP_VERSION_T * lock;               /* Location of the lock versions in the local address space, indexed [0,lock_cnt) */
  ulong           ele_max;            /* ==shmem->ele_max */
  ulong           lock_cnt;           /* ==shmem->lock_cnt */
  ulong           probe_max;          /* ==shmem->probe_max */
  ulong           seed;               /* ==shmem->seed */
  int             lock_shift;         /* ==shmem->lock_shift */
  int             _pad;               /* padding to ulong alignment */
  uchar           ctx[ MAP_CTX_MAX ]; /* User context for MAP_ELE_IS_FREE/MAP_ELE_FREE/MAP_ELE_MOVE */
};

typedef struct MAP_(private) MAP_(t);

struct MAP_(query_private) {
  ulong           memo; /* Query key memo */
  MAP_ELE_T *     ele;  /* Query element in the local address space */
  MAP_VERSION_T * l;    /* Lock needed for this query in the local address space */
  MAP_VERSION_T   v;    /* Version of lock at query start */
};

typedef struct MAP_(query_private) MAP_(query_t);

struct MAP_(iter_private) {
  MAP_ELE_T     * ele;                     /* Location of the element store in the local address space, indexed [0,ele_max) */
  MAP_VERSION_T * lock;                    /* Location of the lock versions in the local address space, indexed [0,lock_cnt) */
  ulong           ele_max;                 /* ==shmem->ele_max */
  ulong           lock_cnt;                /* ==shmem->lock_cnt */
  ulong           seed;                    /* ==shmem->seed */
  ulong           memo;                    /* matching memo for iteration */
  ulong           ele_idx;                 /* If ele_rem>0, current matching element, ignored otherwise */
  ulong           ele_rem;                 /* Number of elements remaining to probe, in [0,probe_max] */
  ulong           version_lock0;           /* Index of first lock used by this iter, in [0,lock_cnt] */
  ulong           version_cnt;             /* Number of locks used by this iter, in [0,lock_cnt] (typically 1) */
  MAP_VERSION_T   version[ MAP_LOCK_MAX ]; /* Direct mapped cache of version numbers for unlock */
};

typedef struct MAP_(iter_private) MAP_(iter_t);

FD_PROTOTYPES_BEGIN

/* map_private_try returns the version of the lock observed at some
   point during the call.  Assumes lock is valid.  If the least
   significant bit of the returned value is set (i.e. is odd), an
   operation was in progress on a key whose probe sequence includes a
   map slot covered by this lock (i.e. it is not a good time to try the
   operation).  If the LSB is clear (i.e. is even), no operation was in
   progress (i.e. it is a good time to try).  This is a compiler memory
   fence. */

static inline MAP_VERSION_T
MAP_(private_try)( MAP_VERSION_T volatile const * l ) {
  MAP_VERSION_T v;
  FD_COMPILER_MFENCE();
  v = *l;
  FD_COMPILER_MFENCE();
  return v;
}

/* map_private_test tests a range of lock versions matched their locally
   cached versions at some point during the call.  Specifically, tests
   lock[lock_idx]==version[lock_idx] for all lock_idx in
   [version_lock0,version_lock0+version_cnt) (cyclic).  lock_cnt is the
   number of locks and assumed to be positive and an integer
   power-of-two.  Returns SUCCESS (zero) if all match (i.e. no probe
   sequences through slots covered by the locks between when the last
   lock in the range was observed and this was called changed) and AGAIN
   (negative) otherwise.  This is a compiler memory fence. */

static inline int
MAP_(private_test)( MAP_VERSION_T volatile const * lock,
                    ulong                          lock_cnt,
                    MAP_VERSION_T const *          version,
                    ulong                          lock_idx, /* version_lock0 */
                    ulong                          version_cnt ) {
  FD_COMPILER_MFENCE();
  for( ; version_cnt; version_cnt-- ) {
    if( FD_UNLIKELY( lock[ lock_idx ]!=version[ lock_idx ] ) ) break; /* opt for low contention */
    lock_idx = (lock_idx+1UL) & (lock_cnt-1UL);
  }
  FD_COMPILER_MFENCE();
  return version_cnt ? FD_MAP_ERR_AGAIN : FD_MAP_SUCCESS; /* cmov */
}

/* map_private_lock returns the version of the lock observed at some
   point during the call.  Assumes lock is valid.  If the least
   significant bit of the returned version is set (i.e. is odd), the
   caller did not get the lock (i.e. an operation was already in
   progress on a key whose probe sequence includes a map slot covered by
   this lock).  If the LSB is clear (i.e. is even), the caller got the
   lock (i.e. is free to do an operation involving probe sequences that
   pass through the range covered by the lock) and *lock LSB was set.
   This is a compiler memory fence.  When the target does not have
   FD_HAS_ATOMIC, this operation is emulated.  When emulated, the map
   will not be safe to use concurrently but will still work with
   comparable performance to a serial implementation. */

static inline MAP_VERSION_T
MAP_(private_lock)( MAP_VERSION_T volatile * l ) {
  MAP_VERSION_T v;
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC /* test-and-test-and-set style */
  v = *l;
  if( FD_LIKELY( !((ulong)v & 1UL) ) ) v = FD_ATOMIC_FETCH_AND_OR( l, (MAP_VERSION_T)1 ); /* opt for low contention */
# else
  v  = *l;
  *l = (MAP_VERSION_T)((ulong)v | 1UL);
# endif
  FD_COMPILER_MFENCE();
  return v;
}

/* map_private_unlock unlocks lock[lock_idx] for lock_idx in
   [version_lock0,version_lock0+version_cnt) (cyclic).  Assumes
   version[lock_idx] is the version the caller wants post unlock (which
   implies that, on entry, version[lock_idx] = lock[lock_idx] + delta
   where delta is odd and >=-1 (the -1 case corresponds "unlock with no
   changes made to the covered elements").  This cannot fail.  This is a
   compiler memory fence. */

static inline void
MAP_(private_unlock)( MAP_VERSION_T volatile * lock,
                      ulong                    lock_cnt,
                      MAP_VERSION_T const *    version,
                      ulong                    lock_idx, /* version_lock0 */
                      ulong                    version_cnt ) {
  FD_COMPILER_MFENCE();
  for( ; version_cnt; version_cnt-- ) {
    lock[ lock_idx ] = version[ lock_idx ];
    lock_idx = (lock_idx+1UL) & (lock_cnt-1UL);
  }
  FD_COMPILER_MFENCE();
}

/* map_private_ele_{is_free,free,move} expose the
   MAP_ELE_{IS_FREE,FREE,MOVE} macros as inlines with strict semantics.

   map_private_ele_is_free returns 1 if ele does not contain a key-val
   pair and 0 otherwise.  ctx will be the join's user context, ele will
   be a valid pointer to an element store element in the caller's
   address space that is safe to speculate on.  Retains no interest in
   ele.

   map_private_ele_free frees any key and/or val resources used by ele
   and marks ele as free.  ctx will be the join's user context, ele will
   be a valid pointer to an element store element in the caller's
   address space that is marked as used.  Retains no interest in ele.

   map_private_ele_move moves the key-val pair from element src to
   element dst and marks src as free.  ctx will be the join's user
   context, src/dst will be a valid pointers to an element store element
   in the caller's address space.  dst/src will be marked as free/used
   on entry and should be marked as used/free on return.  Retains no
   interest in dst or src. */

FD_FN_PURE static inline int
MAP_(private_ele_is_free)( void const *      ctx,
                           MAP_ELE_T const * ele ) {
  (void)ctx;
  return !!(MAP_ELE_IS_FREE( (ctx), (ele) ));
}

static inline void
MAP_(private_ele_free)( void *      ctx,
                        MAP_ELE_T * ele ) {
  (void)ctx;
  MAP_ELE_FREE( (ctx), (ele) );
}

static inline void
MAP_(private_ele_move)( void *      ctx,
                        MAP_ELE_T * dst,
                        MAP_ELE_T * src ) {
  (void)ctx;
  MAP_ELE_MOVE( (ctx), (dst), (src) );
}

FD_FN_CONST static inline ulong MAP_(lock_max)( void ) { return MAP_LOCK_MAX; }

FD_FN_CONST static inline ulong MAP_(lock_cnt_est) ( ulong ele_max ) { return fd_ulong_min( ele_max, MAP_LOCK_MAX ); }
FD_FN_CONST static inline ulong MAP_(probe_max_est)( ulong ele_max ) { return ele_max; }

FD_FN_CONST static inline ulong MAP_(align)( void ) { return alignof(MAP_(shmem_t)); }

FD_FN_CONST static inline ulong
MAP_(footprint)( ulong ele_max,
                 ulong lock_cnt,
                 ulong probe_max ) {
  if( !( fd_ulong_is_pow2( ele_max ) &
         fd_ulong_is_pow2( lock_cnt ) & (lock_cnt<=fd_ulong_min( ele_max, MAP_LOCK_MAX )) &
         (1UL<=probe_max) & (probe_max<=ele_max) ) ) return 0UL;
  return fd_ulong_align_up( sizeof(MAP_(shmem_t)) + lock_cnt*sizeof(MAP_VERSION_T), alignof(MAP_(shmem_t)) ); /* no overflow */
}

FD_FN_PURE static inline ulong MAP_(ele_max)  ( MAP_(t) const * join ) { return join->ele_max; }
FD_FN_PURE static inline ulong MAP_(lock_cnt) ( MAP_(t) const * join ) { return join->lock_cnt;  }
FD_FN_PURE static inline ulong MAP_(probe_max)( MAP_(t) const * join ) { return join->probe_max; }
FD_FN_PURE static inline ulong MAP_(seed)     ( MAP_(t) const * join ) { return join->seed;      }

FD_FN_PURE static inline void const * MAP_(shmap_const)( MAP_(t) const * join ) { return ((MAP_(shmem_t) const *)join->lock)-1; }
FD_FN_PURE static inline void const * MAP_(shele_const)( MAP_(t) const * join ) { return join->ele;     }

FD_FN_CONST static inline void       * MAP_(ctx)      ( MAP_(t)       * join ) { return join->ctx; }
FD_FN_CONST static inline void const * MAP_(ctx_const)( MAP_(t) const * join ) { return join->ctx; }
FD_FN_CONST static inline ulong        MAP_(ctx_max)  ( MAP_(t) const * join ) { (void)join; return MAP_CTX_MAX; }

FD_FN_PURE static inline void * MAP_(shmap)( MAP_(t) * join ) { return ((MAP_(shmem_t) *)join->lock)-1; }
FD_FN_PURE static inline void * MAP_(shele)( MAP_(t) * join ) { return join->ele; }

FD_FN_PURE static inline ulong MAP_(ele_lock) ( MAP_(t) const * join, ulong ele_idx  ) { return  ele_idx       >> join->lock_shift; }
FD_FN_PURE static inline ulong MAP_(lock_ele0)( MAP_(t) const * join, ulong lock_idx ) { return  lock_idx      << join->lock_shift; }
FD_FN_PURE static inline ulong MAP_(lock_ele1)( MAP_(t) const * join, ulong lock_idx ) { return (lock_idx+1UL) << join->lock_shift; }

FD_FN_PURE static inline int
MAP_(key_eq)( MAP_KEY_T const * k0,
              MAP_KEY_T const * k1 ) {
  return !!(MAP_KEY_EQ( (k0), (k1) ));
}

FD_FN_PURE static inline ulong
MAP_(key_hash)( MAP_KEY_T const * key,
                ulong             seed ) {
  return (MAP_KEY_HASH( (key), (seed) ));
}

static inline void
MAP_(backoff)( ulong scale,
               ulong seed ) {
  ulong r = (ulong)(uint)fd_ulong_hash( seed ^ (((ulong)fd_tickcount())<<32) );
  for( ulong rem=(scale*r)>>48; rem; rem-- ) FD_SPIN_PAUSE();
}

FD_FN_PURE static inline ulong             MAP_(query_memo     )( MAP_(query_t) const * query ) { return query->memo; }
FD_FN_PURE static inline MAP_ELE_T const * MAP_(query_ele_const)( MAP_(query_t) const * query ) { return query->ele;  }
FD_FN_PURE static inline MAP_ELE_T       * MAP_(query_ele      )( MAP_(query_t)       * query ) { return query->ele;  }

static inline void
MAP_(publish)( MAP_(query_t) * query ) {
  MAP_VERSION_T volatile * l = query->l;
  MAP_VERSION_T            v = (MAP_VERSION_T)((ulong)query->v + 2UL);
  FD_COMPILER_MFENCE();
  *l = v;
  FD_COMPILER_MFENCE();
}

static inline void
MAP_(cancel)( MAP_(query_t) * query ) {
  MAP_VERSION_T volatile * l = query->l;
  MAP_VERSION_T            v = query->v;
  FD_COMPILER_MFENCE();
  *l = v;
  FD_COMPILER_MFENCE();
}

static inline int
MAP_(query_test)( MAP_(query_t) const * query ) {
  MAP_VERSION_T volatile const * l = query->l;
  ulong                          v = query->v;
  FD_COMPILER_MFENCE();
  ulong _v = *l;
  FD_COMPILER_MFENCE();
  return _v==v ? FD_MAP_SUCCESS : FD_MAP_ERR_AGAIN;
}

static inline void
MAP_(unlock_range)( MAP_(t) *             join,
                    ulong                 range_start,
                    ulong                 range_cnt,
                    MAP_VERSION_T const * version ) {
  MAP_(private_unlock)( join->lock, join->lock_cnt, version, range_start, range_cnt );
}

FD_FN_PURE static inline int         MAP_(iter_done)( MAP_(iter_t) * iter ) { return !iter->ele_rem; }
FD_FN_PURE static inline MAP_ELE_T * MAP_(iter_ele) ( MAP_(iter_t) * iter ) { return iter->ele + iter->ele_idx; }

static inline MAP_(iter_t) *
MAP_(iter_fini)( MAP_(iter_t) * iter ) {
  MAP_(private_unlock)( iter->lock, iter->lock_cnt, iter->version, iter->version_lock0, iter->version_cnt );
  return iter;
}

MAP_STATIC void *    MAP_(new)   ( void * shmem, ulong ele_max, ulong lock_cnt, ulong probe_max, ulong seed );
MAP_STATIC MAP_(t) * MAP_(join)  ( void * ljoin, void * shmap, void * shele );
MAP_STATIC void *    MAP_(leave) ( MAP_(t) * join );
MAP_STATIC void *    MAP_(delete)( void * shmap );

MAP_STATIC void
MAP_(hint)( MAP_(t) const *   join,
            MAP_KEY_T const * key,
            MAP_(query_t) *   query,
            int               flags );

MAP_STATIC int
MAP_(prepare)( MAP_(t) *         join,
               MAP_KEY_T const * key,
               MAP_ELE_T *       sentinel,
               MAP_(query_t) *   query,
               int               flags );

MAP_STATIC int
MAP_(remove)( MAP_(t) *             join,
              MAP_KEY_T const *     key,
              MAP_(query_t) const * query,
              int                   flags );

MAP_STATIC int
MAP_(query_try)( MAP_(t) const *   join,
                 MAP_KEY_T const * key,
                 MAP_ELE_T const * sentinel,
                 MAP_(query_t) *   query,
                 int               flags );

/* FIXME: Consider adding txn API too?  Would work recording the start
   of probe sequences for keys in the transaction and then the txn_try
   would use a bitfield to lock all contiguous regions covered by the
   set of probe sequences. */

MAP_STATIC int
MAP_(lock_range)( MAP_(t) *       join,
                  ulong           range_start,
                  ulong           range_cnt,
                  int             flags,
                  MAP_VERSION_T * version );

MAP_STATIC int
MAP_(iter_init)( MAP_(t) *      join,
                 ulong          memo,
                 int            flags,
                 MAP_(iter_t) * iter );

MAP_STATIC MAP_(iter_t) *
MAP_(iter_next)( MAP_(iter_t) * iter );

MAP_STATIC int MAP_(verify)( MAP_(t) const * join );

MAP_STATIC FD_FN_CONST char const * MAP_(strerror)( int err );

FD_PROTOTYPES_END

#endif

#if MAP_IMPL_STYLE!=1 /* need implementations (assumes header already included) */

#include "../log/fd_log.h" /* Used by constructors and verify (FIXME: Consider making a compile time option) */

MAP_STATIC void *
MAP_(new)( void * shmem,
           ulong  ele_max,
           ulong  lock_cnt,
           ulong  probe_max,
           ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = MAP_(footprint)( ele_max, lock_cnt, probe_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "ele_max, lock_cnt and/or probe_max" ));
    return NULL;
  }

  /* seed arbitrary */

  /* Init the metadata */

  MAP_(shmem_t) * map = (MAP_(shmem_t) *)shmem;

  memset( map, 0, footprint );

  map->ele_max    = ele_max;
  map->lock_cnt   = lock_cnt;
  map->probe_max  = probe_max;
  map->seed       = seed;
  map->lock_shift = fd_ulong_find_msb( ele_max ) - fd_ulong_find_msb( lock_cnt );

  /* Note: memset set all the locks to version 0/unlocked */

  /* Note: caller set all elements in underlying element store set to
     free (or, more pedantically, to a key-val pair configuration
     consistent with ele_max and probe_max). */

  FD_COMPILER_MFENCE();
  map->magic = MAP_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

MAP_STATIC MAP_(t) *
MAP_(join)( void * ljoin,
            void * shmap,
            void * shele ) {
  MAP_(t)       * join = (MAP_(t)       *)ljoin;
  MAP_(shmem_t) * map  = (MAP_(shmem_t) *)shmap;
  MAP_ELE_T     * ele  = (MAP_ELE_T     *)shele;

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)join, alignof(MAP_(t)) ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( map->magic!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_WARNING(( "NULL shele" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ele, alignof(MAP_ELE_T) ) ) ) {
    FD_LOG_WARNING(( "misaligned shele" ));
    return NULL;
  }

  join->lock       = (MAP_VERSION_T *)(map+1);
  join->ele        = ele;
  join->ele_max    = map->ele_max;
  join->lock_cnt   = map->lock_cnt;
  join->probe_max  = map->probe_max;
  join->seed       = map->seed;
  join->lock_shift = map->lock_shift;

  return join;
}

MAP_STATIC void *
MAP_(leave)( MAP_(t) * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

MAP_STATIC void *
MAP_(delete)( void * shmap ) {
  MAP_(shmem_t) * map = (MAP_(shmem_t) *)shmap;

  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "NULL shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmap" ));
    return NULL;
  }

  if( FD_UNLIKELY( map->magic!=MAP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  map->magic = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)map;
}

void
MAP_(hint)( MAP_(t) const *   join,
            MAP_KEY_T const * key,
            MAP_(query_t) *   query,
            int               flags ) {
  MAP_ELE_T const *     ele0       = join->ele;
  MAP_VERSION_T const * lock       = join->lock;
  ulong                 ele_max    = join->ele_max;
  ulong                 seed       = join->seed;
  int                   lock_shift = join->lock_shift;

  ulong memo     = (flags & FD_MAP_FLAG_USE_HINT) ? query->memo : MAP_(key_hash)( key, seed );
  ulong ele_idx  = memo & (ele_max-1UL);
  ulong lock_idx = ele_idx >> lock_shift;

  /* TODO: target specific prefetch hints */
  if( FD_LIKELY( flags & FD_MAP_FLAG_PREFETCH_META ) ) FD_VOLATILE_CONST( lock[ lock_idx ] );
  if( FD_LIKELY( flags & FD_MAP_FLAG_PREFETCH_DATA ) ) FD_VOLATILE_CONST( ele0[ ele_idx  ] );

  query->memo = memo;
}

int
MAP_(prepare)( MAP_(t) *         join,
               MAP_KEY_T const * key,
               MAP_ELE_T *       sentinel,
               MAP_(query_t) *   query,
               int               flags ) {
  MAP_ELE_T *     ele0       = join->ele;
  MAP_VERSION_T * lock       = join->lock;
  ulong           ele_max    = join->ele_max;
  ulong           lock_cnt   = join->lock_cnt;
  ulong           probe_max  = join->probe_max;
  ulong           seed       = join->seed;
  int             lock_shift = join->lock_shift;
  void *          ctx        = join->ctx;

  ulong memo          = (flags & FD_MAP_FLAG_USE_HINT) ? query->memo : MAP_(key_hash)( key, seed );
  ulong start_idx     = memo & (ele_max-1UL);
  ulong version_lock0 = start_idx >> lock_shift;

  int   non_blocking = !(flags & FD_MAP_FLAG_BLOCKING);
  ulong backoff_max  = (1UL<<32);               /* in [2^32,2^48) */
  ulong backoff_seed = ((ulong)(uint)flags)>>6; /* 0 usually fine */

  for(;;) { /* Fresh try */

    int err;

    MAP_VERSION_T version[ MAP_LOCK_MAX ];
    ulong version_cnt = 0UL;
    ulong lock_idx    = version_lock0;

    /* At this point, finding any key in the map requires testing at
       most probe_max contiguous slots. */

    MAP_VERSION_T v = MAP_(private_lock)( lock + lock_idx );
    if( FD_UNLIKELY( (ulong)v & 1UL ) ) { err = FD_MAP_ERR_AGAIN; goto fail; } /* opt for low contention */
    version[ lock_idx ] = v;
    version_cnt++;

    ulong ele_idx = start_idx;

    for( ulong probe_rem=probe_max; probe_rem; probe_rem-- ) {

      /* At this point, we've acquired the locks from the start of key's
         probe sequence to ele_idx inclusive and have tested fewer than
         probe_max slots for key.

         If slot ele_idx is empty, we know that the key is currently not
         in the map and we can insert it here without creating a probe
         sequence longer than probe_max.  This does not lengthen the
         probe sequence for any currently mapped keys, preserving the
         maximum probe sequence length invariant.  Further, this is at
         the end of all keys that map to the same probe sequence start.
         So, we have preserved the key group ordering invariant.

         On return, ele will be marked as free.  To insert key into the
         map, the caller should initialize the slot's key (and memo if
         necessary), mark the slot as used, and publish to complete the
         insert.

         If the caller doesn't want to insert anything (e.g. caller only
         wants to modify an existing value), the caller should keep the
         slot marked as free (doesn't matter how the caller modified any
         other fields) and return the slot as free, and cancel to
         complete the failed insert (publish would also work ... cancel
         has theoretically lower risk of false contention).

         Likewise, if slot ele_idx contains key, we return that slot to
         the caller.  The caller can tell the difference between the
         previous case because the slot will be marked as used.

         On return, the caller can modify the slot's value arbitrarily.
         IMPORTANT SAFETY TIP!  THE CALLER MUST NOT MODIFY THE SLOT'S KEY
         OR MARK THE SLOT AS FREE.  USE REMOVE BELOW TO REMOVE KEYS.
         When done modifying the slot's value, the caller should either
         publish or cancel depending on what the caller did to the
         slot's value and how the application manages access to values
         (publish is always safe but cancel when appropriate has
         theoretically lower risk of false contention).  Note that
         cancel is not appropriate for temporary modifications to value
         (because it can confuse query ABA protection).

         In both cases, since we have the lock that covers slot ele_idx,
         we can unlock any other locks (typically the leading
         version_cnt-1 but possibly the trailing version_cnt-1 in cases
         with maps near capacity) locks already acquired to reduce
         contention with other unrelated operations.  That is, at this
         point, lock lock_idx is sufficient to prevent any operation for
         any key breaking key's probe sequence (because it would need to
         acquire the lock covering ele_idx first). */

      MAP_ELE_T * ele = ele0 + ele_idx;

      if( FD_LIKELY( MAP_(private_ele_is_free)( ctx, ele ) ) || /* opt for low collision */
          (
  #         if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
            FD_LIKELY( ele->MAP_MEMO==memo                ) &&
  #         endif
            FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) /* opt for already in map */
          ) ) {

        lock_idx = ele_idx >> lock_shift;
        version_lock0 = (version_lock0 + (ulong)(version_lock0==lock_idx)) & (lock_cnt-1UL);
        MAP_(private_unlock)( lock, lock_cnt, version, version_lock0, version_cnt-1UL );

        query->memo = memo;
        query->ele  = ele;
        query->l    = lock + lock_idx;
        query->v    = version[ lock_idx ];
        return FD_MAP_SUCCESS;
      }

      /* At this point, slot ele_idx is used by something other than
         key.  If we still have probes remaining, continue probing for
         key, locking as necessary.  If we can't acquire a lock, we
         fail. */

      ele_idx = (ele_idx+1UL) & (ele_max-1UL);

      /* FIXME: FURTHER RESTRICT TO PROBE_REM>1? */
      ulong lock_next = ele_idx >> lock_shift;
      if( FD_UNLIKELY( (lock_next!=lock_idx) & (lock_next!=version_lock0) ) ) { /* opt for locks that cover many contiguous slots */
        lock_idx = lock_next;

        MAP_VERSION_T v = MAP_(private_lock)( lock + lock_idx );
        if( FD_UNLIKELY( (ulong)v & 1UL ) ) { err = FD_MAP_ERR_AGAIN; goto fail; } /* opt for low contention */
        version[ lock_idx ] = v;
        version_cnt++;
      }
    }

    /* At this point, we've done probe_max probes without encountering
       key and we have all the locks.  So we know key is not in the map
       and that, even if we have space, inserting this key will create a
       probe sequence longer than probe_max.  That is, map is loaded
       enough that we consider it full.

       If probe_max==ele_max, this meaning of full is the traditional
       non-concurrent meaning of full (literally every slot is known to
       be used).  Even if probe_max << ele_max, it is possible to fill
       every slot (e.g. at probe_max==1, a perfect hash of ele_max keys
       to slot would fill every slot). */

    err = FD_MAP_ERR_FULL;

  fail:

    MAP_(private_unlock)( lock, lock_cnt, version, version_lock0, version_cnt );

    if( FD_UNLIKELY( non_blocking | (err!=FD_MAP_ERR_AGAIN) ) ) {
      query->memo = memo;
      query->ele  = sentinel;
      query->l    = NULL;
      query->v    = (MAP_VERSION_T)0;
      return err;
    }

    /* At this point, we hit contention and are blocking (need to try
       again).  We do a random exponential backoff (with saturation on
       wrapping) to minimize contention with other threads.  Normalizing
       out fixed point scalings baked into the below, we spin pause a
       uniform IID random number of times in [0,backoff_max) where
       backoff_max is 1 on the first hit and increases by ~30% each time
       to a maximum of 2^16 (i.e. hundreds microseconds per remaining
       lock for typical CPU speeds and spin pause delays at maximum
       backoff). */

    ulong scale = backoff_max >> 16; /* in [2^16,2^32) */
    backoff_max = fd_ulong_min( backoff_max + (backoff_max>>2) + (backoff_max>>4), (1UL<<48)-1UL ); /* in [2^32,2^48) */
    MAP_(backoff)( scale, backoff_seed );

  }

  /* never get here */

}

int
MAP_(remove)( MAP_(t) *             join,
              MAP_KEY_T const *     key,
              MAP_(query_t) const * query,
              int                   flags ) {

  MAP_VERSION_T * lock       = join->lock;
  ulong           lock_cnt   = join->lock_cnt;
  ulong           seed       = join->seed;
  ulong           probe_max  = join->probe_max;
  MAP_ELE_T *     ele0       = join->ele;
  ulong           ele_max    = join->ele_max;
  int             lock_shift = join->lock_shift;
  void *          ctx        = join->ctx;

  ulong memo          = (flags & FD_MAP_FLAG_USE_HINT) ? query->memo : MAP_(key_hash)( key, seed );
  ulong start_idx     = memo & (ele_max-1UL);
  ulong version_lock0 = start_idx >> lock_shift;

  int   non_blocking = !(flags & FD_MAP_FLAG_BLOCKING);
  ulong backoff_max  = (1UL<<32);               /* in [2^32,2^48) */
  ulong backoff_seed = ((ulong)(uint)flags)>>6; /* 0 usually fine */

  for(;;) { /* Fresh try */

    int err;

    MAP_VERSION_T version[ MAP_LOCK_MAX ];
    ulong version_cnt = 0UL;
    ulong lock_idx    = version_lock0;

    /* At this point, we need to acquire locks covering the start of the
       probe sequence through up to all contiguously used slots (and, if
       the map is not completely full, the trailing empty slot). */

    MAP_VERSION_T v = MAP_(private_lock)( lock + lock_idx );
    if( FD_UNLIKELY( (ulong)v & 1UL ) ) { err = FD_MAP_ERR_AGAIN; goto fail; } /* opt for low contention */
    version[ lock_idx ] = v;
    version_cnt++;

    ulong ele_idx  = start_idx;
    ulong hole_idx = start_idx;
    int   found    = 0;

    ulong contig_cnt;
    for( contig_cnt=0UL; contig_cnt<ele_max; contig_cnt++ ) {

      /* At this point, we've acquired the locks covering slots
         [start_idx,ele_idx] (cyclic) and have confirmed that the
         contig_cnt slots [start_idx,ele_idx) (cyclic) are used.

         If slot ele_idx is empty, we are done probing.

         Otherwise, if we haven't found key yet, we test if slot ele_idx
         contains key.

         We can optimize this further by noting that the key can only be
         in the first probe_max probes and that when we don't find the
         key, remove has nothing to do (such that we don't have to keep
         probing for contiguous slots). */

      MAP_ELE_T const * ele = ele0 + ele_idx;

      if( FD_UNLIKELY( MAP_(private_ele_is_free)( ctx, ele ) ) ) break; /* opt for first pass low collision */

      if( FD_LIKELY( !found ) ) { /* opt for first pass low collision */
        if( FD_UNLIKELY( contig_cnt>=probe_max ) ) break; /* opt for first pass low collision */
        found =
  #       if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
          FD_LIKELY( ele->MAP_MEMO==memo ) &&
  #       endif
          MAP_(key_eq)( &ele->MAP_KEY, key );
        if( found ) hole_idx = ele_idx; /* cmov */
      }

      /* Continue probing, locking as necessary.  If we can't acquire a
         lock, fail. */

      ele_idx = (ele_idx+1UL) & (ele_max-1UL);

      ulong lock_next = ele_idx >> lock_shift;
      if( FD_UNLIKELY( (lock_next!=lock_idx) & (lock_next!=version_lock0) ) ) { /* opt for locks covering many contiguous slots */
        lock_idx = lock_next;

        MAP_VERSION_T v = MAP_(private_lock)( lock + lock_idx );
        if( FD_UNLIKELY( (ulong)v & 1UL ) ) { err = FD_MAP_ERR_AGAIN; goto fail; } /* opt for low contention */
        version[ lock_idx ] = v;
        version_cnt++;
      }
    }

    /* At this point, if we haven't found the key, key did not exist in
       the map at some point during the call.  Release the locks and
       tell the user the key was already removed. */

    if( FD_UNLIKELY( !found ) ) { err = FD_MAP_ERR_KEY; goto fail; }

    /* At this point, we have locks covering the contig_cnt used slots
       starting from start_idx cyclic (and, if contig_cnt<ele_max, any
       trailing empty slot).  The key to remove is in this range at
       hole_idx.  Further, all probe sequences are intact.  Make a hole
       at hole_idx by freeing the key.  Also update the cached lock
       version to indicate "modified" when we unlock below. */

    MAP_(private_ele_free)( ctx, ele0 + hole_idx );

    lock_idx = hole_idx >> lock_shift;
    version[ lock_idx ] = (MAP_VERSION_T)((ulong)version[ lock_idx ] + 2UL);

    /* When contig_cnt<ele_max, the trailing empty slot guarantees that
       the just made hole didn't break any probe sequences for keys not
       in the contig_cnt slots and that it didn't break any probe
       sequences in [start_idx,hole_idx).  Probe sequences for keys in
       (hole_idx,start_idx+contig_cnt) (cyclic) might have been broken
       though.

       We fix the first key with a broken probe sequence by moving it to
       the hole just made.  This fills the hole but makes a new hole
       (and one closer to the empty trailing slot) in the process.  As
       this shortens the probe sequence for that key, this doesn't break
       any probe length invariants.  We are repeating this process until
       we've fixed all the contiguous slots after hole_idx.  (As an
       additional optimization to reduce remove costs when map is nearly
       full but probe_max << ele_max, we could exploit that only the
       leading probe_max-1 slots after any created hole might have
       broken probe sequences.)

       Unfortunately, when contig_cnt==ele_max, we no longer have this
       guarantee.  But we do have the entire map locked at this point.
       And we know that probe sequences are intact starting from the
       most recently created hole.  If we verify enough to eventually
       wrap back to most recently created hole, we know all probe
       sequences are intact.  Since fixing broken probe sequences in
       this fashion always shortens them and there always will be one
       hole in this process, verifying until we hit the most recently
       made hole is guaranteed to terminate.  Since there is only one
       hole, it is sufficient to just test if the next slot to verify is
       a hole.

       This test works just as well for the more common
       contig_cnt<ele_max case (it will terminate at the preexisting
       trailing empty slot instead of the most recently created hole).
       So, for code simplicity, we just do that.

       A nice side effect is this removal process is that implicitly
       improves probing for remaining keys in the map and does not
       require tombstones.

       TL;DR  It's a bad idea on many levels to fill up linearly probed
       maps to their absolute limits ... but this will still work if you
       do.

       Note also that this process preserves the ordering of keys that
       hash to the same slot (such that key group ordering is
       preserved). */

    ele_idx = hole_idx;
    for(;;) {
      ele_idx = (ele_idx+1UL) & (ele_max-1UL);

      /* At this point, slots (hole_idx,ele_idx) (cyclic) are used with
         verified probe sequences.  As per the above, we are guaranteed
         to eventually hit an empty slot (typically very quickly in
         practice) and hitting an empty slot guarantees all probe
         sequences are intact (such that we are done). */

      MAP_ELE_T * ele = ele0 + ele_idx;
      if( FD_LIKELY( MAP_(private_ele_is_free)( ctx, ele ) ) ) break;

      /* Otherwise, if ele_idx's key probe sequence doesn't start in
         (hole_idx,ele_idx] (cyclic), its probe sequence is currently
         broken by the hole at hole_idx.  We fix it by moving ele_idx to
         hole_idx.  This shortens that key's probe sequence (preserving
         the invariant) and makes a new hole at ele_idx.  We mark the
         lock version covering the new hole idx as modified for the
         unlock below.  Note that the version for the existing hole was
         already marked as modified when the hole was created so we only
         bump if ele_idx is covered by a different lock than hole_idx to
         reduce version churn to near theoretical minimum. */

  #   if MAP_MEMOIZE
      memo      = ele->MAP_MEMO;
  #   else
      memo      = MAP_(key_hash)( &ele->MAP_KEY, seed );
  #   endif
      start_idx = memo & (ele_max-1UL);

      if( !( ((hole_idx<start_idx) & (start_idx<=ele_idx)                       ) |
             ((hole_idx>ele_idx) & ((hole_idx<start_idx) | (start_idx<=ele_idx))) ) ) {

        MAP_(private_ele_move)( ctx, ele0 + hole_idx, ele );

        ulong lock_next = ele_idx >> lock_shift;
        version[ lock_next ] = (MAP_VERSION_T)((ulong)version[ lock_next ] + ((lock_next!=lock_idx) ? 2UL : 0UL) /* cmov */);
        lock_idx = lock_next;

        hole_idx = ele_idx;
      }

    }

    /* At this point, key is removed and all remaining keys have intact
       and ordered probe sequences and we have updated the necessary
       version cache entries.  Unlock and return success.  */

    MAP_(private_unlock)( lock, lock_cnt, version, version_lock0, version_cnt );
    return FD_MAP_SUCCESS;

  fail:

    MAP_(private_unlock)( lock, lock_cnt, version, version_lock0, version_cnt );

    if( FD_UNLIKELY( non_blocking | (err!=FD_MAP_ERR_AGAIN) ) ) return err;

    /* At this point, we are blocking and hit contention.  Backoff.  See
       note in prepare for how this works */

    ulong scale = backoff_max >> 16; /* in [2^16,2^32) */
    backoff_max = fd_ulong_min( backoff_max + (backoff_max>>2) + (backoff_max>>4), (1UL<<48)-1UL ); /* in [2^32,2^48) */
    MAP_(backoff)( scale, backoff_seed );
  }

  /* never get here */
}

int
MAP_(query_try)( MAP_(t) const *   join,
                 MAP_KEY_T const * key,
                 MAP_ELE_T const * sentinel,
                 MAP_(query_t) *   query,
                 int               flags ) {

  MAP_ELE_T *     ele0       = join->ele;
  MAP_VERSION_T * lock       = join->lock;
  ulong           ele_max    = join->ele_max;
  ulong           lock_cnt   = join->lock_cnt;
  ulong           probe_max  = join->probe_max;
  ulong           seed       = join->seed;
  int             lock_shift = join->lock_shift;
  void const *    ctx        = join->ctx;

  ulong memo          = (flags & FD_MAP_FLAG_USE_HINT) ? query->memo : MAP_(key_hash)( key, seed );
  ulong start_idx     = memo & (ele_max-1UL);
  ulong version_lock0 = start_idx >> lock_shift;

  int   non_blocking = !(flags & FD_MAP_FLAG_BLOCKING);
  ulong backoff_max  = (1UL<<32);               /* in [2^32,2^48) */
  ulong backoff_seed = ((ulong)(uint)flags)>>6; /* 0 usually fine */

  for(;;) { /* fresh try */

    int err;

    MAP_VERSION_T version[ MAP_LOCK_MAX ];
    ulong version_cnt = 0UL;
    ulong lock_idx    = version_lock0;

    /* At this point, finding any key in the map requires probing at
       most probe_max contiguous slots. */

    MAP_VERSION_T v = MAP_(private_try)( lock + lock_idx );
    if( FD_UNLIKELY( (ulong)v & 1UL ) ) { err = FD_MAP_ERR_AGAIN; goto fail_fast; } /* opt for low contention */
    version[ lock_idx ] = v;
    version_cnt++;

    ulong ele_idx = start_idx;

    for( ulong probe_rem=probe_max; probe_rem; probe_rem-- ) {

      /* At this point, we've observed the locks covering the start of
         key's probe sequence to ele_idx inclusive, they were unlocked
         when observed and we have done fewer than probe_max probes.

         If slot ele_idx is empty, we speculate that key was not in the
         map at some point during the call.

         If slot ele_idx holds key, we let the caller continue speculating
         about key's value.  We only need to observe the lock covering key
         after we've found it (if key gets moved or removed, the version
         of the lock covering it will change). */

      MAP_ELE_T const * ele = ele0 + ele_idx;

      if( FD_UNLIKELY( MAP_(private_ele_is_free)( ctx, ele ) ) ) { err = FD_MAP_ERR_KEY; goto fail; } /* opt for low collision */

      if(
#         if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
          FD_LIKELY( ele->MAP_MEMO==memo                ) &&
#         endif
          FD_LIKELY( MAP_(key_eq)( &ele->MAP_KEY, key ) ) /* opt for found */
        ) {

        lock_idx = ele_idx >> lock_shift;

        query->memo = memo;
        query->ele  = (MAP_ELE_T *)ele;
        query->l    = lock + lock_idx;
        query->v    = version[ lock_idx ];
        return FD_MAP_SUCCESS;
      }

      /* At this point, we speculate slot ele_idx was used by something
         other than key when observed.  Continue probing slot for key,
         observing locks as necessary. */

      ele_idx = (ele_idx+1UL) & (ele_max-1UL);

      /* FIXME: FURTHER RESTRICT TO PROBE_REM>1? */
      ulong lock_next = ele_idx >> lock_shift;
      if( FD_UNLIKELY( (lock_next!=lock_idx) & (lock_next!=version_lock0) ) ) { /* opt for locks cover many contiguous slots */
        lock_idx = lock_next;

        v = MAP_(private_try)( lock + lock_idx );
        if( FD_UNLIKELY( (ulong)v & 1UL ) ) { err = FD_MAP_ERR_AGAIN; goto fail_fast; } /* opt for low contention */
        version[ lock_idx ] = v;
        version_cnt++;
      }
    }

    /* At this point, we did probe_max probes without finding key.  We
       speculate key was not in the map at some point during the call. */

    err = FD_MAP_ERR_KEY;

  fail:

    /* If we didn't encounter any contention (i.e. no version numbers
       changed), we can trust our speculated error.  Otherwise, we tell
       the user to try again. */

    err = MAP_(private_test)( lock, lock_cnt, version, version_lock0, version_cnt ) ? FD_MAP_ERR_AGAIN : err; /* cmov */

  fail_fast: /* Used when the err is already AGAIN */

    if( FD_UNLIKELY( non_blocking | (err!=FD_MAP_ERR_AGAIN) ) ) {
      query->memo = memo;
      query->ele  = (MAP_ELE_T *)sentinel;
      query->l    = NULL;
      query->v    = (MAP_VERSION_T)0;
      return err;
    }

    /* At this point, we are blocking and hit contention.  Backoff.  See
       note in prepare for how this works */

    ulong scale = backoff_max >> 16; /* in [2^16,2^32) */
    backoff_max = fd_ulong_min( backoff_max + (backoff_max>>2) + (backoff_max>>4), (1UL<<48)-1UL ); /* in [2^32,2^48) */
    MAP_(backoff)( scale, backoff_seed );
  }
  /* never get here */
}

int
MAP_(lock_range)( MAP_(t) *       join,
                  ulong           range_start,
                  ulong           range_cnt,
                  int             flags,
                  MAP_VERSION_T * version ) {
  MAP_VERSION_T * lock     = join->lock;
  ulong           lock_cnt = join->lock_cnt;

  int   non_blocking  = !(flags & FD_MAP_FLAG_BLOCKING);
  ulong backoff_max   = (1UL<<32);               /* in [2^32,2^48) */
  ulong backoff_seed  = ((ulong)(uint)flags)>>6; /* 0 usually fine */
  ulong version_delta = (flags & FD_MAP_FLAG_RDONLY) ? 0UL : 2UL;

  for(;;) { /* fresh try */

    ulong lock_idx   = range_start;
    ulong locked_cnt = 0UL;
    for( ; locked_cnt<range_cnt; locked_cnt++ ) {
      MAP_VERSION_T v = MAP_(private_lock)( lock + lock_idx );
      if( FD_UNLIKELY( (ulong)v & 1UL ) ) goto fail; /* opt for low contention */
      version[ lock_idx ] = (MAP_VERSION_T)((ulong)v + version_delta);
      lock_idx = (lock_idx+1UL) & (lock_cnt-1UL);
    }

    return FD_MAP_SUCCESS;

  fail:

    MAP_(private_unlock)( lock, lock_cnt, version, range_start, locked_cnt );

    if( FD_UNLIKELY( non_blocking ) ) return FD_MAP_ERR_AGAIN;

    /* At this point, we are blocking and hit contention.  Backoff.  See
       note in prepare for how this works */

    ulong scale = backoff_max >> 16; /* in [2^16,2^32) */
    backoff_max = fd_ulong_min( backoff_max + (backoff_max>>2) + (backoff_max>>4), (1UL<<48)-1UL ); /* in [2^32,2^48) */
    MAP_(backoff)( scale, backoff_seed );
  }
  /* never get here */
}

int
MAP_(iter_init)( MAP_(t) *      join,
                 ulong          memo,
                 int            flags,
                 MAP_(iter_t) * iter ) {

  MAP_ELE_T *     ele0       = join->ele;
  MAP_VERSION_T * lock       = join->lock;
  ulong           ele_max    = join->ele_max;
  ulong           lock_cnt   = join->lock_cnt;
  ulong           probe_max  = join->probe_max;
  ulong           seed       = join->seed;
  int             lock_shift = join->lock_shift;
  void *          ctx        = join->ctx;

  MAP_VERSION_T * version = iter->version;

  ulong start_idx     = memo & (ele_max-1UL);
  ulong version_lock0 = start_idx >> lock_shift;
  ulong version_delta = (flags & FD_MAP_FLAG_RDONLY) ? 0UL : 2UL;

  int   non_blocking = !(flags & FD_MAP_FLAG_BLOCKING);
  ulong backoff_max  = (1UL<<32);               /* in [2^32,2^48) */
  ulong backoff_seed = ((ulong)(uint)flags)>>6; /* 0 usually fine */

  for(;;) { /* fresh try */

    ulong version_cnt = 0UL;
    ulong lock_idx    = version_lock0;

    /* At this point, finding any key-val pair that matches memo in the
       map requires probing at most probe_max contiguous slots. */

    MAP_VERSION_T v = MAP_(private_lock)( lock + lock_idx );
    if( FD_UNLIKELY( (ulong)v & 1UL ) ) goto fail; /* opt for low contention */
    version[ lock_idx ] = (MAP_VERSION_T)((ulong)v + version_delta);
    version_cnt++;

    ulong ele_idx = start_idx;
    ulong ele_rem = 0UL;

    ulong iter_cnt   = 0UL;
    ulong iter_start = start_idx;

    for( ; ele_rem<probe_max; ele_rem++ ) {

      /* At this point, we've acquired the locks covering slots
         [start_idx,ele_idx] (cyclic) and have confirmed that the
         ele_rem slots [start_idx,ele_idx) (cyclic) are used.  If slot
         ele_idx is empty, we are done probing. */

      MAP_ELE_T const * ele = ele0 + ele_idx;

      if( FD_UNLIKELY( MAP_(private_ele_is_free)( ctx, ele ) ) ) break; /* opt for first pass low collision */

      iter_start = fd_ulong_if( iter_cnt==0UL, ele_idx, iter_start );
#     if MAP_MEMOIZE
      iter_cnt += (ulong)(ele->MAP_MEMO==memo);
#     else
      iter_cnt += (ulong)(MAP_(key_hash)( &ele->MAP_KEY, seed )==memo);
#     endif

      /* Continue probing, locking as necessary.  If we can't acquire a
         lock, fail. */

      ele_idx = (ele_idx+1UL) & (ele_max-1UL);

      ulong lock_next = ele_idx >> lock_shift;
      if( FD_UNLIKELY( (lock_next!=lock_idx) & (lock_next!=version_lock0) ) ) { /* opt for locks covering many contiguous slots */
        lock_idx = lock_next;

        MAP_VERSION_T v = MAP_(private_lock)( lock + lock_idx );
        if( FD_UNLIKELY( (ulong)v & 1UL ) ) goto fail; /* opt for low contention */
        version[ lock_idx ] = (MAP_VERSION_T)((ulong)v + version_delta);
        version_cnt++;
      }
    }

    /* At this point, we've acquired the locks covering used slots
       [start_idx,start_idx+ele_rem) (cyclic) where ele_rem<=probe_max
       (and, if ele_rem<probe_max, any trailing empty slot).  iter_cnt
       is the number of slots that matched in this range and iter_start
       is the index of the first element in this range that matched
       (start_idx if no matches). */

    iter->ele           = ele0;
    iter->lock          = lock;
    iter->ele_max       = ele_max;
    iter->lock_cnt      = lock_cnt;
    iter->seed          = seed;
    iter->memo          = memo;
    iter->ele_rem       = iter_cnt;
    iter->ele_idx       = iter_start;
    iter->version_lock0 = version_lock0;
    iter->version_cnt   = version_cnt;
    /* iter->version initialized above */

    return FD_MAP_SUCCESS;

  fail:

    /* At this point, we hit contention acquiring the locks for
       iteration.  If we not blocking, tell caller to try again later.
       Otherwise, backoff.  See note in prepare for how this works. */

    MAP_(private_unlock)( lock, lock_cnt, version, version_lock0, version_cnt );

    if( FD_UNLIKELY( non_blocking ) ) {
      iter->ele_rem     = 0UL; /* make sure can't iterate */
      iter->version_cnt = 0UL; /* make sure fini is a no-op */
      return FD_MAP_ERR_AGAIN;
    }

    ulong scale = backoff_max >> 16; /* in [2^16,2^32) */
    backoff_max = fd_ulong_min( backoff_max + (backoff_max>>2) + (backoff_max>>4), (1UL<<48)-1UL ); /* in [2^32,2^48) */
    MAP_(backoff)( scale, backoff_seed );
  }
  /* never get here */
}

MAP_(iter_t) *
MAP_(iter_next)( MAP_(iter_t) * iter ) {
  ulong ele_idx = iter->ele_idx;
  ulong ele_rem = iter->ele_rem - 1UL;

  /* We just finished processing pair ele_idx and we have ele_rem
     more pairs to process.  If there is at least 1, scan for it. */

  if( ele_rem ) {
    MAP_ELE_T * ele0    = iter->ele;
    ulong       ele_max = iter->ele_max;
    ulong       seed    = iter->seed; (void)seed;
    ulong       memo    = iter->memo;

    for(;;) {
      ele_idx = (ele_idx+1UL) & (ele_max-1UL);
      MAP_ELE_T * ele = ele0 + ele_idx;
#     if MAP_MEMOIZE
      if( FD_LIKELY( ele->MAP_MEMO==memo ) ) break;
#     else
      if( FD_LIKELY( MAP_(key_hash)( &ele->MAP_KEY, seed )==memo ) ) break;
#     endif
    }
  }

  iter->ele_idx = ele_idx;
  iter->ele_rem = ele_rem;
  return iter;
}

MAP_STATIC int
MAP_(verify)( MAP_(t) const * join ) {

# define MAP_TEST(c) do {                                                                      \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_MAP_ERR_INVAL; } \
  } while(0)

  /* Validate join */

  MAP_TEST( join );
  MAP_TEST( fd_ulong_is_aligned( (ulong)join, alignof(MAP_(t)) ) );

  MAP_ELE_T const *     ele0       = join->ele;
  MAP_VERSION_T const * lock       = join->lock;
  ulong                 ele_max    = join->ele_max;
  ulong                 lock_cnt   = join->lock_cnt;
  ulong                 probe_max  = join->probe_max;
  ulong                 seed       = join->seed;
  int                   lock_shift = join->lock_shift;
  void const *          ctx        = join->ctx;

  MAP_TEST( ele0                                                   );
  MAP_TEST( fd_ulong_is_aligned( (ulong)ele0, alignof(MAP_ELE_T) ) );
  MAP_TEST( lock                                                   );
  MAP_TEST( fd_ulong_is_aligned( (ulong)lock, MAP_(align)()      ) );
  MAP_TEST( fd_ulong_is_pow2( ele_max  )                           );
  MAP_TEST( fd_ulong_is_pow2( lock_cnt )                           );
  MAP_TEST( lock_cnt <= fd_ulong_min( ele_max, MAP_LOCK_MAX )      );
  MAP_TEST( (1UL<=probe_max) & (probe_max<=ele_max)                );
  /* seed is arbitrary */
  MAP_TEST( (1UL<<lock_shift) == (ele_max/lock_cnt)                );

  /* Validate map metadata */

  MAP_(shmem_t) const * map = ((MAP_(shmem_t) const *)lock)-1;

  MAP_TEST( map                                              );
  MAP_TEST( fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) );
  MAP_TEST( map->magic      == MAP_MAGIC                     );
  MAP_TEST( map->ele_max    == ele_max                       );
  MAP_TEST( map->lock_cnt   == lock_cnt                      );
  MAP_TEST( map->probe_max  == probe_max                     );
  MAP_TEST( map->seed       == seed                          );
  MAP_TEST( map->lock_shift == lock_shift                    );

  /* Validate map elements */

  for( ulong ele_idx=0UL; ele_idx<ele_max; ele_idx++ ) {
    MAP_ELE_T const * ele = ele0 + ele_idx;
    if( FD_LIKELY( MAP_(private_ele_is_free)( ctx, ele ) ) ) continue; /* opt for sparse */

    ulong memo = MAP_(key_hash)( &ele->MAP_KEY, seed );

#   if MAP_MEMOIZE
    MAP_TEST( ele->MAP_MEMO==memo );
#   endif

    ulong probe_idx = memo & (ele_max-1UL);
    ulong probe_cnt = fd_ulong_if( ele_idx>=probe_idx, ele_idx - probe_idx, ele_max + ele_idx - probe_idx ) + 1UL;
    MAP_TEST( probe_cnt<=probe_max );

    for( ulong probe_rem=probe_cnt; probe_rem; probe_rem-- ) {
      MAP_ELE_T const * probe = ele0 + probe_idx;
      MAP_TEST( !MAP_(private_ele_is_free)( ctx, probe ) );

      int found =
#       if MAP_MEMOIZE && MAP_KEY_EQ_IS_SLOW
        FD_LIKELY( probe->MAP_MEMO == ele->MAP_MEMO ) &&
#       endif
        MAP_(key_eq)( &probe->MAP_KEY, &ele->MAP_KEY );

      MAP_TEST( (probe_rem==1UL) ? found : !found );

      probe_idx = (probe_idx+1UL) & (ele_max-1UL);
    }
  }

  /* At this point, every key in the map is reachable via it's probe
     sequence and every probe sequence is at most probe_max probes long.
     By extension, if a key is in the map, it will be found in at most
     probe_max probes. */

# undef MAP_TEST

  return FD_MAP_SUCCESS;
}

MAP_STATIC char const *
MAP_(strerror)( int err ) {
  switch( err ) {
  case FD_MAP_SUCCESS:   return "success";
  case FD_MAP_ERR_INVAL: return "bad input";
  case FD_MAP_ERR_AGAIN: return "try again later";
  case FD_MAP_ERR_FULL:  return "map too full";
  case FD_MAP_ERR_KEY:   return "key not found";
  default: break;
  }
  return "unknown";
}

#endif

#undef MAP_
#undef MAP_STATIC

#undef MAP_IMPL_STYLE
#undef MAP_MAGIC
#undef MAP_ALIGN
#undef MAP_LOCK_MAX
#undef MAP_VERSION_T
#undef MAP_CTX_MAX
#undef MAP_ELE_MOVE
#undef MAP_ELE_FREE
#undef MAP_ELE_IS_FREE
#undef MAP_KEY_EQ_IS_SLOW
#undef MAP_MEMO
#undef MAP_MEMOIZE
#undef MAP_KEY_HASH
#undef MAP_KEY_EQ
#undef MAP_KEY
#undef MAP_KEY_T
#undef MAP_ELE_T
#undef MAP_NAME
