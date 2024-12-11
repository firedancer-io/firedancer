/* Generate prototypes, inlines and/or implementations for concurrent
   persistent shared maps based on chaining.  A map can store a
   practically unbounded number of elements.  If sized on creation for
   the maximum number of mapped elements, typical map operations are a
   fast O(1) time and map element overhead is a small O(1) space.
   Further, large numbers of composite map operations can be done
   concurrently with very low risk of conflicts.

   In the current implementation, each map chain has a version number.
   Operations that require changing a chain's connectivity (e.g.
   inserting or removing an element from a chain) or modifying an
   element managed by that chain, the chain's version number is
   increased by one (atomic compare-and-swap based) such that other
   potential users of keys managed by that chain detect and react
   appropriately to a potentially concurrent conflicting operation is in
   progress.  When an operation completes, the chain version number is
   increased by one again to notify other users the operation is no
   longer in progress and that the set of keys managed by that chain
   and/or values associated with those keys has potentially changed
   since the previous version.  For example, lockfree queries can
   interoperate with this via a zero-copy
   try-speculatively-process-then-test pattern similar to that used in
   fd_tango for high throughput message processing.

   As such, there can be an arbitrary number of concurrent readers
   processing map keys.  These readers will not interfere with each
   other and will not block any concurrent insert / remove / modify
   operations.  Insert / remove / modify operations can potentially
   block each other.  Since there are typically O(1) keys per chain, the
   probability of concurrent insert / remove / modify operations
   involving different keys blocking each other is small.  Further, this
   controllable a priori by provisioning the number of chains
   appropriately.  Concurrent operations on the same key are serialized
   (as they necessarily would be any implementation).  Since the
   operations are HPC implementations, collisions are resolved as fast
   as is practical.  The upshot is that the map supports massive
   concurrency while preserving concurrent operation serializability.

   Version numbers are stored with chain head pointers such that the
   cache traffic required for managing chain versioning is covered by
   the same cache traffic required for managing chains in a
   non-concurrent implementation (e.g. fd_map_chain).  Operations do
   many internal integrity checking / bounds checking for use in high
   reliability applications.

   Lastly, fine grained versioning allows for concurrent execution of
   complex operations involving multiple keys simultaneously.  This
   allows using the map as a concurrent transactional memory and for
   serialization of all map elements at a consistent point in time while
   minimizing impact on ongoing concurrent operations (e.g. snapshotting
   all the elements in the map).

   The main drawback of chain versioning is the extra memory footprint
   required for chain metadata storage.  The current implementation
   supports indexing compression and uses atomic bit field techniques to
   minimize this overhead.

   Concurrent operation requires FD_HAS_ATOMIC.  This will still work on
   platforms without FD_HAS_ATOMIC but concurrent operations will not be
   safe.

   In short, if you need a concurrent map, this is a lot better than
   protecting a non-concurrent implementation with a global lock.  And,
   if you don't, it will be comparably performant to a non-concurrent
   implementation.

   This generator is designed for ultra tight coupling with pools,
   treaps, heaps, lists, other maps, etc.  Likewise, a map can be
   persisted beyond the lifetime of the creating process, be used
   inter-process, relocated in memory, be naively
   serialized/deserialized, be moved between hosts, use index
   compression for cache and memory bandwidth efficiency, etc.
   Concurrency and flexibility are prioritized.

   Typical usage:

     struct myele {
       ulong key;  // Technically "MAP_KEY_T MAP_KEY"  (default is ulong key),  managed by mymap when the element is in the mymap
       ulong next; // Technically "MAP_IDX_T MAP_NEXT" (default is ulong next), managed by mymap when the element is in the mymap

       ... key and next can be located arbitrarily in the element and
       ... can be reused for other purposes when the element is not in a
       ... mymap.  The mapping of a key to an element in the element
       ... store is arbitrary.  An element should not be moved /
       ... released from the element store while in the mymap.

     };

     typedef struct myele myele_t;

     #define MAP_NAME  mymap
     #define MAP_ELE_T myele_t
     #include "tmpl/fd_map_para.c"

   will declare the following APIs as a header only style library in the
   compilation unit:

     // A mymap_t is a stack declaration friendly quasi-opaque local
     // object used to hold the state of a local join to a mymap.
     // Similarly, a mymap_query_t and a mymap_iter_t hold the local
     // state of an ongoing local query and local iteration
     // respectively.  E.g. it is fine to do mymap_t join[1];" to
     // allocate a mymap_t but the contents should not be used directly.

     typedef struct mymap_private       mymap_t;
     typedef struct mymap_query_private mymap_query_t;
     typedef struct mymap_iter_private  mymap_iter_t;

     // mymap_ele_max_max returns the maximum element store capacity
     // compatible with a mymap.

     ulong mymap_ele_max_max( void );

     // mymap_chain_max returns the maximum number of chains supported
     // by a mymap.  Will be an integer power-of-two.

     ulong mymap_chain_max( void );

     // mymap_chain_cnt_est returns a reasonable number of chains to use
     // for a map that is expected to hold up to ele_max_est elements.
     // ele_max_est will be clamped to be in [1,mymap_ele_max_max()] and
     // the return value will be a integer power-of-two in
     // [1,mymap_chain_max()].

     ulong mymap_chain_cnt_est( ulong ele_max_est );

     // mymap_{align,footprint} returns the alignment and footprint
     // needed for a memory region to be used as a mymap.  align will be
     // an integer power-of-two and footprint will be a multiple of
     // align.  footprint returns 0 if chain_cnt is not an integer
     // power-of-two in [1,mymap_chain_max()].
     //
     // mymap_new formats a memory region with the required alignment
     // and footprint into a mymap.  shmem points in the caller's
     // address space to the memory region to use.  Returns shmem on
     // success (mymap has ownership of the memory region) and NULL on
     // failure (no changes, logs details).  The caller is not joined on
     // return.  The mymap will be empty with all map chains at version
     // 0 (unlocked).
     //
     // mymap_join joins the caller to an existing mymap.  ljoin points
     // to a mymap_t compatible memory region in the caller's address
     // space, shmap points in the caller's address space to the memory
     // region containing the mymap, shele points in the caller's
     // address space to mymap's element store and ele_max gives the
     // element store's capacity.  Returns a handle to the caller's
     // local join on success (join has ownership of the ljoin region)
     // and NULL on failure (no changes, logs details).
     //
     // mymap_leave leaves a mymap join.  join points to a current local
     // join.  Returns the memory region used for the join on success
     // (caller has ownership on return and the caller is no longer
     // joined) and NULL on failure (no changes, logs details).  Use the
     // join accessors before leaving to get shmap, shele and ele_max
     // used by the join if needed.
     //
     // mymap_delete unformats a memory region used as a mymap.  Assumes
     // shmap points in the caller's address space to a memory region
     // containing the mymap and that there are no joins.  Returns shmem
     // on success (caller has ownership of the memory region, any
     // remaining elements still in the mymap are released to the caller
     // implicitly) and NULL on failure (no changes, logs details).

     ulong     mymap_align    ( void );
     ulong     mymap_footprint( ulong chain_cnt );
     void *    mymap_new      ( void * shmem, ulong chain_cnt, ulong seed );
     mymap_t * mymap_join     ( void * ljoin, void * shmap, void * shele, ulong ele_max );
     void *    mymap_leave    ( mymap_t * join );
     void *    mymap_delete   ( void * shmap );

     // mymap_{chain_cnt,seed} return the mymap configuration.  Assumes
     // join is a current local join.  The values will be valid for the
     // mymap lifetime.

     ulong mymap_chain_cnt( mymap_t const * join );
     ulong mymap_seed     ( mymap_t const * join );

     // mymap_{shmap,shele,ele_max} return join details.  Assumes join
     // is a current local join.  The values will be valid for the join
     // lifetime.  mymap_{shmap_const,shele_const} are const correct
     // versions.

     void const * mymap_shmap_const( mymap_t const * join );
     void const * mymap_shele_const( mymap_t const * join );
     ulong        mymap_ele_max    ( mymap_t const * join );

     void * mymap_shmap( mymap_t * join );
     void * mymap_shele( mymap_t * join );

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
     // MAP_KEY_HASH.  The seed used by a particular mymap innstance can
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
     // Ideally, seed is a 32-bit globally unique identifer for the
     // logical thread of execution but this is up to the application to
     // specify and rarely matters in practice.  This is a useful
     // building block for random exponential backoffs.

     void mymap_backoff( ulong scale, ulong seed );

     // mymap_query_ele returns a pointer in the caller's address space
     // to the element store element associated with the query or a
     // sentinel value.  The sentinel value is application dependent and
     // thus arbitrary (e.g. not necessarily in the element store,
     // including NULL, a local temporary used as a bit bucket, etc).
     // Assumes query is valid.  The lifetime of the returned pointer
     // depends on the query.  mymap_query_ele_const is a const correct
     // version.

     myele_t const * mymap_query_ele_const( mymap_query_t const * query );
     myele_t *       mymap_query_ele      ( mymap_query_t *       query );

     // mymap_insert inserts into a mymap a mapping from a key to an
     // element store element.  ele points in the caller's address space
     // to the element and ele->key is initialized to the key.  flags is
     // a bit-or of FD_MAP_FLAG flags.  If FD_MAP_FLAG_BLOCKING is set /
     // clear in flags, this is allowed / not allowed to block the
     // caller.  Assumes join is a current local join, element is not in
     // the mymap and the key is not currently mapped to anything in the
     // mymap.  This is a non-blocking fast O(1) and supports highly
     // concurrent operation.
     //
     // Returns FD_MAP_SUCCESS (0) on success and a FD_MAP_ERR
     // (negative) on failure.  On success, ele was inserted into the
     // mymap at some point during the call (mymap took ownership of the
     // element at that time but the application is free to manage all
     // fields of the element except ele->key and ele->next).  On
     // failure, the mymap was not modified by the call, no changes of
     // ownership occurred in the call and returns:
     //
     // - FD_MAP_ERR_INVAL: ele is not a pointer to an element store
     //   element.
     //
     // - FD_MAP_ERR_AGAIN: A potentially conflicting operation was in
     //   progress at some point during the call.  Try again later (e.g.
     //   after a random exponential backoff).  Specifically, this
     //   operation requires locking the map chain associated with key.
     //   Since there are typically O(1) keys per chain, the probability
     //   of getting AGAIN due to a false conflict is negligible even
     //   under highly concurrent loads.  Since insert / remove are fast
     //   O(1) operations, any remaining conflicts, real or imagined,
     //   are typically very short lived.  Never returned for a blocking
     //   call.
     //
     // IMPORTANT SAFETY TIP!  Do not use inside a modify try/test,
     // query try/test, txn try/test or iter lock/unlock.

     int mymap_insert( mymap_t * join, myele_t * ele, int flags );

     // mymap_remove removes the mapping (if any) for key from the
     // mymap.  On return, query will contain information about the
     // removed mapping.  sentinel gives the query element pointer value
     // (arbitrary) to pass through when this did not remove a mapping
     // for any reason.  flags is a bit-or of FD_MAP_FLAG flags.  If
     // FD_MAP_FLAG_BLOCKING is set / clear in flags, this is allowed /
     // not allowed to block the caller.  Assumes join is a current
     // local join and key is valid for the duration of the call.
     // Retains no interest in key, sentinel or query.  This is a
     // non-blocking fast O(1) and supports highly concurrent operation.
     //
     // Returns FD_MAP_SUCCESS (0) on success and a FD_MAP_ERR
     // (negative) on failure.  On success, key's mapping was removed at
     // some point during the call.  mymap_query_ele( query ) will point
     // in the caller's address space to the element store element where
     // key mapped just before it was removed (element ownership
     // transferred to the caller at that time).  On failure, no changes
     // were made by this call, mymap_query_ele( query ) will be
     // sentinel and:
     //
     // - FD_MAP_ERR_KEY: Key was not found in the mymap at some point
     //   during the call.
     //
     // - FD_MAP_ERR_AGAIN: A potentially conflicting operation was in
     //   progress at some point during the call.  Same considerations
     //   as insert above.  Never returned for a blocking call.
     //
     // - FD_MAP_ERR_CORRUPT: Memory corruption was detected at some
     //   point during the call.
     //
     // IMPORTANT SAFETY TIP!  Do not use inside a modify try/test,
     // query try/test, txn try/test or iter lock/unlock.

     int
     mymap_remove( mymap_t *       join,
                   ulong const *   key,
                   myele_t const * sentinel,
                   mymap_query_t * query,
                   int             flags );

     // mymap_modify_try tries to start modification of the mymap
     // element corresponding to key.  On return, query will hold
     // information about the try.  sentinel gives the query element
     // pointer value (arbitrary) to pass through when it is not safe to
     // try.  flags is a bit-or of FD_MAP_FLAG flags.  If
     // FD_MAP_FLAG_BLOCKING is set / clear, this call is allowed / not
     // allowed to block the caller.  If FD_MAP_FLAG_ADAPTIVE is set /
     // clear, this call should / should not adapt the mymap to
     // accelerate future operations on this key.  Adaptation for a key
     // can potentially slow future operations for other keys.  The
     // marginal benefit of adaptation for a key grows linearly with the
     // number of keys managed by the key's chain.  Assumes join is a
     // current local join and key is valid for the duration of the
     // call.  Retains no interest in key, sentinel or query.  This is a
     // non-blocking fast O(1) and supports highly concurrent operation.
     //
     // Returns FD_MAP_SUCCESS (0) on success and a FD_MAP_ERR
     // (negative) on failure.  On success, mymap_query_ele( query )
     // will point in the caller's address space to the element to
     // modify and the chain that manages key will be locked.  The mymap
     // retains ownership of this element and management of the key and
     // next fields.  The caller is free to modify any other fields.  On
     // failure, the mymap was not modified by this call,
     // mymap_query_ele( query ) will be sentinel and returns:
     //
     // - FD_MAP_ERR_KEY: Key was not found in the mymap in some point
     //   during the call.
     //
     // - FD_MAP_ERR_AGAIN: A potentially conflicting operation was in
     //   progress at some point during the try.  Same considerations as
     //   insert above.  Never returned for a blocking call.
     //
     // - FD_MAP_ERR_CORRUPT: Memory corruption was detected at some
     //   point during the call.
     //
     // IMPORTANT SAFETY TIP!  Do not interleave or nest with a query
     // try/test, txn try/test or iter_lock/unlock on the same thread.

     int
     mymap_modify_try( mymap_t *       join,
                       ulong const *   key,
                       myele_t *       sentinel,
                       mymap_query_t * query,
                       int             flags );

     // mymap_modify_test finishes an in-progress modification.  Assumes
     // query is valid and the caller is in a modify try.  Returns
     // FD_MAP_SUCCESS (0).  On return, the caller will no longer be in
     // a modify try.  Guaranteed to succeed.
     //
     // IMPORTANT SAFETY TIP!  Do not interleave or nest with a query
     // try/test, txn try/test or iter_lock/unlock on the same thread.

     int mymap_modify_test( mymap_query_t * query );

     // mymap_query_try tries to speculatively query a mymap for key.
     // On return, query will hold information about the try.  sentinel
     // gives the query element pointer value (arbitrary) to pass
     // through when it is not safe to try the query.  Assumes join is a
     // current local join and key is valid for the duration of the
     // call.  Does not modify the mymap and retains no interest in key,
     // sentinel or query.  This is a non-blocking fast O(1) and
     // supports highly concurrent operation.
     //
     // Returns FD_MAP_SUCCESS (0) on success and a FD_MAP_ERR
     // (negative) on failure.  On success, key mapped to an element in
     // the element store at some point during the call.
     // mymap_query_ele( query ) will point in the caller's address
     // space to the element store element where key mapped at that
     // time.  The mymap retains ownership of this element but the
     // caller can zero copy speculatively process the element.  On
     // failure, mymap_query_ele( query ) will be sentinel and returns:
     //
     // - FD_MAP_ERR_KEY: Key was not found in the mymap in some point
     //   during the call.
     //
     // - FD_MAP_ERR_AGAIN: A potentially conflicting operation was in
     //   progress at some point during the call.  Try again later (e.g.
     //   after a random exponential backoff).  Unlike insert and
     //   remove, this call does _not_ require a lock on the chain
     //   associated with key.  As such, AGAIN can only be caused by
     //   concurrent operations that require a lock on the chain that
     //   manages key (with similar considerations as insert and remove)
     //   and this will never interfere with any other concurrent
     //   operation.  Among the many implications, a query will never
     //   delay a concurrent query and AGAIN will never be returned if
     //   only concurrent queries are in progress.
     //
     // - FD_MAP_ERR_CORRUPT: Memory corruption was detected at some
     //   point during the call.
     //
     // IMPORTANT SAFETY TIP!  THE CALLER SHOULD BE PREPARED TO HANDLE
     // ARBITRARY AND/OR INCONSISTENT VALUES FOR ELEMENT FIELDS DURING
     // SPECULATIVE PROCESSING.  CALLERS SHOULD NOT COMMIT ANY RESULTS
     // OF SPECULATIVE PROCESSING UNTIL IT TESTS THE QUERY WAS
     // SUCCESSFUL.
     //
     // The simplest form of speculative processing is to copy the
     // element from the element store into a local temporary, test that
     // the speculation was valid, and then process the local temporary
     // copy at its leisure.  Zero copy, more selective copying and/or
     // writing speculative results into local tempoaries are more
     // advanced examples of speculative processing.
     //
     // Use mymap_modify to do a blocking (non-speculative) and/or
     // adaptive query (just don't actually modify the element).
     //
     // IMPORTANT SAFETY TIP!  Do not interleave or nest with a modify
     // try/test, txn try/test or iter_lock/unlock on the same thread.

     int
     mymap_query_try( mymap_t const * join,
                      ulong const *   key,
                      myele_t const * sentinel,
                      mymap_query_t * query );

     // mymap_query_test tests if an in-progress query is still valid.
     // Assumes query is valid, we are still in a query try and chain
     // version numbers have not wrapped since we started the try.
     // Returns FD_MAP_SUCCESS (0) if the query is still valid and
     // FD_MAP_ERR_AGAIN (negative) if a potentially conflicting
     // operation was in progress at some point during the try.
     //
     // IMPORTANT SAFETY TIP!  Do not interleave or nest with a modify
     // try/test, txn try/test or iter_lock/unlock on the same thread.

     int mymap_query_test( mymap_query_t const * query );

     // mymap_txn_key_max_max() returns the theoretical maximum number
     // of keys that can be in a transaction.  (Practically unbounded.)

     ulong mymap_txn_key_max_max( void );

     // mymap_txn_{align,footprint} return the alignment and footprint
     // required for a mymap_txn_t that can support at least key_max
     // keys.  align will be an integer power of two.  footprint will be
     // a multiple of align.  Returns 0 if key_max > key_max_max.
     //
     // mymap_txn_init formats a memory region with the required
     // alignment and footprint as a txn_t that can support at least
     // key_max keys.  ltxn points in the caller's address space to the
     // memory region to use.  Assumes join is a current local join.
     // On success, returns ltxn (txn will have ownership of the memory
     // region, txn will be valid with empty speculative and locked key
     // sets).  The lifetime of the join should be at least the lifetime
     // of the txn.  On failure (obviously bad inputs), returns NULL (no
     // changes).
     //
     // mymap_txn_fini unformats a memory region as a txn_t and returns
     // a pointer to the underlying memory.  On success, returns ltxn.
     // The caller has ownership of the memory region on return.  On
     // failure (e.g. NULL input), returns NULL (no changes).

     ulong         mymap_txn_align    ( void );
     ulong         mymap_txn_footprint( ulong key_max );
     mymap_txn_t * mymap_txn_init     ( void * ltxn, mymap_t * join, ulong key_max );
     void *        mymap_txn_fini     ( mymap_txn_t * txn );

     // mymap_txn_add indicates that key may be used in a txn.  Assumes
     // txn is valid and not in a try and key is valid for duration of
     // the call.  Retains no interest in key.  A zero value for lock
     // indicates the key will be operated on speculatively.  A non-zero
     // value indicates the key will potentially be inserted / removed /
     // modified by the transaction.  It is okay to have a mixture of
     // speculative and locked keys in a transaction.  Further, it is
     // okay to add the same key multiple times (though not particularly
     // efficient), including as a mixture of speculative and locked (if
     // _any_ adds of same key are locked, it will be treated as a
     // locked key for the txn overall).  Returns FD_MAP_SUCCESS (zero)
     // on success (txn is valid and not in a try) and FD_MAP_ERR_INVAL
     // (negative) on failure (txn is valid and not in a try but key was
     // not added).  INVAL is only possible when more than key_max adds
     // have been done since init.

     int mymap_txn_add( mymap_txn_t * txn, mymap_key_t const * key, int lock );

     // mymap_txn_try returns FD_MAP_SUCCESS (zero) if it is safe to try
     // the transaction and FD_MAP_ERR_AGAIN (negative) if the user
     // should try again later (e.g. after a random exponential
     // backoff).  flags is a bit-of of FD_MAP_FLAG flags.  If
     // FD_MAP_FLAG_BLOCKING is set / clear, this call is allowed / not
     // allowed to block the caller.  Assumes txn is valid and not in a
     // try.  On success, txn will be valid and in a try.  On an
     // failure, txn will be valid and not in a try.
     //
     // IMPORTANT SAFETY TIP!  Do not interleave or nest with modify
     // try/test, query try/test or iter_lock/unlock on the same thread.
     //
     // To better under the restrictions on nesting and interleaving,
     // mymap_{insert,remove,query_try,modify_try,query_try} will fail
     // with FD_MAP_ERR_AGAIN for any key managed by a chain locked by
     // the txn but can succeed for keys on managed by other chains.
     // This behavior is unpredictable as it depends on the keys in the
     // txn, keys not in the transaction, map seed, map chain count and
     // user provided key hash function.  Interleaving a query_test,
     // modify_test, iter_unlock can be similarly unpredictable.  Worse,
     // an interleaved modify_test or iter_unlock can muck up the chain
     // locks and used by the txn try.  Similarly for other cases.
     //
     // IMPORTANT SAFETY TIP!  If some txn keys were speculative, the
     // caller should not rely on any reads from the corresponding
     // element until the transaction tests successfully.  Similar
     // considerations as mymap_query_try.

     int mymap_txn_try( mymap_txn_t * txn, int flags );

     // mymap_txn_{insert,remove} behave _identically_ to
     // mymap_{insert,remove} from the caller's point of view but
     // assumes we are in a txn try and key was added to the txn as
     // locked.  These will never return FD_MAP_ERR_AGAIN.
     //
     // Similarly, mymap_txn_query behaves _identically_ to
     // mymap_query_try from the caller's point of view but assumes we
     // are in a txn try and key was added to txn as either speculative
     // or locked.  Will never return FD_MAP_ERR_AGAIN.
     //
     // Likewise, mymap_txn_modify behaves _identically_ to
     // mymap_modify_try from the caller's point of view but assumes we
     // are in a txn try and key was added to txn as locked.  It will
     // never return FD_MAP_ERR_AGAIN.
     //
     // There is no mymap_query_test or mymap_modify_test because these
     // are part of the overall txn test.
     //
     // IMPORTANT SAFETY TIP!
     //
     // These never should be used outside a txn try.
     //
     // IMPORTANT SAFETY TIP!
     //
     // For a speculative txn key, mymap_query can return FD_MAP_ERR_KEY
     // and/or FD_MAP_ERR_CORRUPT if there are locked concurrent
     // operations on the chain managing key (e.g a concurrent remove of
     // a key that happens to be on the same chain).  When such
     // operations are possible, these errors can be canaries that the
     // transaction has already failed (testing the txn is still
     // necessary to it "official").  CORRUPT in this situation is most
     // likely an "unofficial" failure than memory corruption.
     // Similarly, while mymap_txn_query is guaranteed give a pointer to
     // an element store element on success, there is no guarantee it
     // will be to the correct element, a well formed element (or even
     // to the same location if used multiple times in the try).  When
     // such concurrent operations are not possible (e.g. single
     // threaded operation), SUCCESS, KEY, CORRUPT and the element
     // pointer returned have their usual interpretations.
     //
     // TL;DR speculative txn keys are best used for commmon stable
     // constant-ish read-only data to minimize concurrent complex
     // transactions using these common keys from unnecessarily blocking
     // each other.
     //
     // TL;DR resolve all speculative txn keys to elements at
     // transaction start exactly once for sanity.
     //
     // TL;DR avoid using speculative txn keys at all unless very well
     // versed in lockfree programming idioms and gotchas.

     int mymap_txn_insert( mymap_t *       join, myele_t * ele );
     int mymap_txn_remove( mymap_t *       join, ulong const * key, myele_t const * sentinel, mymap_query_t * query );
     int mymap_txn_modify( mymap_t *       join, ulong const * key, myele_t *       sentinel, mymap_query_t * query, int flags );
     int mymap_txn_query ( mymap_t const * join, ulong const * key, myele_t const * sentinel, mymap_query_t * query );

     // mymap_txn_test returns FD_MAP_SUCCESS (zero) if the txn try
     // succeeded and FD_MAP_AGAIN (negative) if it failed (e.g. the
     // test detected a potentially conflicting concurrent operation
     // during the try).  On success, any results from processing of
     // keys marked as speculative can be trusted.  On failure, the
     // mymap was not changed by the try.  Regardless of return value,
     // txn will _not_ be in a try on return _but_ will still be valid.
     // As such, if a transaction fails, it can be retried (e.g. after a
     // random exponential backoff) without needing to recreate it (e.g.
     // no need to fini then init/add again).  Assumes txn is in a try
     // and, for any txn speculative keys, no wrapping of txn version
     // numbers has occurred since the try started..
     //
     // IMPORTANT SAFETY TIP!  This is guaranteed to succeed if no keys
     // were added to the transaction as speculative.
     //
     // IMPORTANT SAFETY TIP!  Do not interleave or nest with modify
     // try/test, query try/test or iter_lock/unlock on the same thread.

     int mymap_txn_test( mymap_txn_t * txn );

     // mymap_iter_lock locks zero or more map chains.  Assumes join is
     // a current local join.  On input, lock_seq[i] for i in
     // [0,lock_cnt) gives the set of chains to lock.  flags is a bit-or
     // of FD_MAP_FLAG flags.  If FD_MAP_FLAG_BLOCKING is set / not set,
     // this call is allowed / not allowed to block the caller.  Assumes
     // join, lock_seq and lock_cnt are valid and the caller does not
     // already have any of these locks.  In particular, lock_seq should
     // contain unique values in [0,chain_cnt), which also implies
     // lock_cnt is at most chain_cnt.  Retains no interest in lock_seq.
     // Returns FD_MAP_SUCCESS (zero) on success and FD_MAP_ERR_AGAIN
     // (negative) on failure.  On return:
     //
     //   FD_MAP_SUCCESS: lock_seq will be a permutation of the input
     //   giving the actual order (from oldest to newest) in which the
     //   locks were acquired.  This can be used, for example, to unlock
     //   in the same order and can be used by the caller to optimize
     //   the order for iterating over keys to reduce the amount of
     //   contention with other concurrent operations.  If there were no
     //   potentially conflicting concurrent operations during the call,
     //   lock_seq will be in the input order.
     //
     //   FD_MAP_ERR_AGAIN: a potentially conflicting operation was in
     //   progress at some point during the call.  lock_seq might have
     //   been changed (but will still be a permutation of the input).
     //   The mymap itself wasn't changed by the call.
     // 
     // Guaranteed to succeed if blocking (but will not return to the
     // caller until all the requested chains are locked).
     //
     // IMPORTANT SAFETY TIP!  Do not use interleave or nest with modify
     // try/test, query try/test or txn try/test on the same thread.

     int
     mymap_iter_lock( mymap_t * join,
                      ulong *   lock_seq,
                      ulong     lock_cnt,
                      int       flags );

     // mymap_iter_unlock unlocks chains lock_seq[i] for i in
     // [0,lock_cnt) in that order.  Assumes join is a current local
     // join, lock_seq and lock_cnt are valid (same requirements as
     // mymap_iter_lock) and the caller has a lock on those chains.
     // Retains no interest in lock_seq.  Guaranteed to succeed.
     //
     // IMPORTANT SAFETY TIP!  Do not use interleave or nest with modify
     // try/test, query try/test or txn try/test on the same thread.

     void
     mymap_iter_unlock( mymap_t *     join,
                        ulong const * lock_seq,
                        ulong         lock_cnt );

     // mymap_iter_chain_idx returns the index of the map chain that
     // manages key.  Useful for iterating over groups of related keys
     // when the map hash function is designed to group all related keys
     // onto the same chain.

     ulong
     mymap_iter_chain_idx( mymap_t const * join,
                           ulong const *   key );

     // mymap_{iter,iter_done,iter_next,iter_ele,iter_ele_const} iterate
     // over a single map chain.  Assumes join is a current local join,
     // chain_idx is in [0,mymap_chain_cnt(join)) and the caller lock on
     // chain idx or the chain is otherwise known to be idle.
     //
     // These are building blocks for concurrent parallel iteration.  As
     // the locking and ordering requirements for such an iterator are
     // very application specific, no default global iterators are
     // provided (i.e. a generic global iterator will need to be so
     // conservative on locking than typical application requirements,
     // it is practically more mischievious than useful).  E.g. a mymap
     // snapshot might lock all chains to get the state of the entire
     // mymap at a consistent point in time.  For each chain (in the
     // order given by the lock acquisition), the snapshot would
     // serialize all keys on that chain and then unlock it
     // incrementally.

     mymap_iter_t    mymap_iter          ( mymap_t const * join, ulong chain_idx );
     mymap_iter_t    mymap_iter_done     ( mymap_iter_t iter );
     mymap_iter_t    mymap_iter_next     ( mymap_iter_t iter );
     myele_t const * mymap_iter_ele_const( mymap_iter_t iter );
     myele_t *       mymap_iter_ele      ( mymap_iter_t iter );

     // mymap_reset removes all elements from the mymap.  Caller has
     // ownership of all items removed on return.  Assumes that join is
     // a current local join and the caller has a lock on all map chains
     // or the map is otherwise known to be idle.

     void mymap_reset( mymap_t * join );

     // mymap_verify returns FD_MAP_SUCCESS (0) if the join, underlying
     // map and underlying element store give a valid mapping of unique
     // keys to unique elements in the element store.  Assumes that
     // caller has a lock on all map chains or the map is otherwise
     // known to be idle.  Returns FD_MAP_ERR_CORRUPT (negative)
     // otherwise (no changes by this call, logs details).

     int mymap_verify( mymap_t const * join );

   Do this as often as desired in a compilation unit to get different
   types of concurrent maps.  Options exist for generating library
   header prototypes and/or library implementations for concurrent maps
   usable across multiple compilation units.  Additional options exist
   to use index compression, different hashing functions, key comparison
   functions, etc as detailed below.

   To better understand the insert/remove/{modify,query}_{try,test}
   APIs:

     ... basic insert

     myele_t * ele = ... acquire an unused element from the element store

     ... populate ele appropriately, including

     ele->key = ... key associated with this element

     int err = mymap_insert( join, err, FD_MAP_FLAG_BLOCKING );

     if( FD_UNLIKELY( err ) ) { // Not possible in this example

       ... If err is FD_MAP_ERR_INVAL, ele did not point at an element
       ... store element.
       ...
       ... If err is FD_MAP_ERR_AGAIN, there was a potentially
       ... conflicting operation in progress on the mymap during the
       ... call.  We can try again later (e.g. after a random backoff or
       ... doing other non-conflicting work).

     } else {

       ... At this point, a mapping from key to the element store
       ... element pointed to by ele in our address space was added
       ... during the call.  ele->key will be stable while in the mymap.
       ... Neither ele->key nor ele->next should be modified by the
       ... application while in the mymap.  The application is free to
       ... manage all other fields of the element as desired.

     }

     ... basic remove

     ulong key = ... key to remove

     mymap_query_t query[1];
     int err = mymap_remove( join, &key, NULL, query, FD_MAP_FLAG_BLOCKING );
     mymap_ele_t * ele = mymap_query_ele( query );

     if( FD_UNLIKELY( err ) ) {
    
       ... At this point, ele==sentinel==NULL.
       ... 
       ... If err is FD_MAP_ERR_KEY, key was not in the mymap at some
       ... point during the remove.
       ... 
       ... If err is FD_MAP_ERR_AGAIN, there was a potentially
       ... conflicting operation in progress during the remove.  We can
       ... try again later (e.g. after a random backoff or doing other
       ... non-conflicting work).  (Not possible in this example.)
       ... 
       ... If err is FD_MAP_ERR_CORRUPT, memory corruption was detected
       ... at some point during the call.  (Usually abortive.)
    
     } else {
    
       ... At this point, ele points into the element store (non-NULL),
       ... ele->key matches key, key mapped to that element before the
       ... remove, and we have ownership of that element.

       ... release ele to the element store
       
     }

     ... basic modify

     ulong key = ... key to modify

     mymap_query_t query[1];
     int err = mymap_modify_try( join, &key, NULL, query, FD_MAP_FLAG_BLOCKING );
     mymap_ele_t * ele = mymap_query_ele( query );

     if( FD_UNLIKELY( err ) ) {
    
       ... At this point, ele==sentinel==NULL.
       ... 
       ... If err is FD_MAP_ERR_KEY, key was not in the mymap at some
       ... point during the try.
       ... 
       ... If err is FD_MAP_ERR_AGAIN, there was a potentially
       ... conflicting operation in progress during the try.  We can try
       ... again later (e.g. after a random backoff or doing other
       ... non-conflicting work).  (Not possible in this example.)
       ... 
       ... If err is FD_MAP_ERR_CORRUPT, memory corruption was detected
       ... at some point during the call.  (Usually abortive.)
    
     } else {
    
       ... At this point, ele points in our address space to an element
       ... store element, ele->key matches key and we are in a modify try
       ... such that it is safe to modify fields ele not managed by the
       ... mymap.

       ... Modify application managed fields of ele here.

       ... IMPORTANT SAFETY TIP!  IF THE USER WANTS TO SUPPORT ROLLING
       ... BACK A MODIFICATION AT THIS POINT, THEY CAN DO SO BY SAVING
       ... THE ORIGINAL VALUE OF ELE BEFORE MODIFYING ANY FIELDS AND
       ... THEN RESTORING IT HERE.
    
       ... Finish the modification (guaranteed to succeed)

       mymap_modify_test( query );

       ... At this point, the modification is done and we are no
       ... longer in a try.

     }

     ... basic speculative query

     ulong key = ... key to query

     mymap_query_t query[1];
     int err = mymap_query_try( join, &key, NULL, query );
     mymap_ele_t const * ele = mymap_query_ele_const( query );

     if( FD_UNLIKELY( err ) ) {
    
       ... At this point, ele==sentinel==NULL.
       ... 
       ... If err is FD_MAP_ERR_KEY, key was not in the mymap at some
       ... point during the try.
       ... 
       ... If err is FD_MAP_ERR_AGAIN, there was a potentially
       ... conflicting operation in progress during the try and we can
       ... try again later (e.g. after a random backoff or doing other
       ... non-conflicting work).
       ... 
       ... If err is FD_MAP_ERR_CORRUPT, memory corruption was detected
       ... during the call.  (Usually abortive.)
    
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
       ... is to copy the needed portions of ele into a local stack
       ... temp.
       ...
       ... Note: concurrent operations could include removing key from
       ... the mymap (and maybe multiple cycles of inserting and
       ... removing it and then at potentially different element store
       ... locations).  That's not an issue practically as the ele
       ... pointer here will be to an element compatible memory region
       ... that will continue to exist regardless and we shouldn't be
       ... trusting any query reads yet (the query test will detect if
       ... if these can be trusted).
       ...
       ... Rant: If ele is more complex than plain-old-data, so long ele
       ... is using allocators like fd_alloc and fd_wksp for dynamically
       ... allocated fields (e.g. not using the giant steaming pile of
       ... page based memory virtual memory, operating system, language
       ... and standard library fail that is heap based allocation ala
       ... malloc/free), concurrent removes are _still_ fine for the
       ... exact same reason.  That is, the memory that actually backed
       ... dynamically allocated fields will still continue to exist
       ... post remove ... you know ... just like reality (turns out,
       ... surprise, "free" doesn't actually uninstall any DIMMs and
       ... malloc/free are the worst possible abstraction for resource
       ... management).
       ... 
       ... The concurrent remove case actually demonstrates why fd_alloc
       ... / fd_wksp / fd_shmem / etc exist in the first place.  Beyond
       ... being faster, simpler, more concurrent and more reliable
       ... (especially in cases like this), they are more flexible (e.g.
       ... sharing and persisting the data structure asynchronously
       ... across multiple processes in different address spaces) and
       ... more secure (e.g. can easily bounds check memory accesses
       ... and then use the memory subsystem to sandbox different
       ... components from touching memory they shouldn't, actually
       ... using a modern virtual memory subsystem for something useful
       ... for a change instead of bending over backwards to provide
       ... exactly the wrong abstraction of the real world).  Common
       ... hardware and software practices have turned computers into an
       ... unreliable and insecure Tower of Babel.  Had virtual memory
       ... been better abstracted and better implemented all levels of
       ... the stack, life would be much easier (and things like fast
       ... persistent memories might have seen a lot more commerical
       ... success).  In the meantime, dispelling the magical thinking
       ... encourged by the conventional abstractions, the key lessons
       ... are:
       ... 
       ... * Friends don't let friends malloc.
       ... * Lockfree is not a synonym for garbage collection.
       ... * Real world computers aren't infinite tape Turing machines.
       ... * Real world memory doesn't magically disappear.

       ... At this point, we are done with speculative processing (or we
       ... don't want to do any more speculative processing if the try
       ... has already failed).
    
       err = mymap_query_test( query );
       if( FD_UNLKELY( err ) ) {
    
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

   To better understand the txn API:

     ... allocate a txn

     ulong         align     = mymap_txn_align();
     ulong         footprint = mymap_txn_footprint( key_max );
     void *        ltxn      = ... allocate align/footprint local scratch memory
     mymap_txn_t * txn       = mymap_txn_init( ltxn, join, key_max );

     ... add at most key_max keys to the transaction as locked

     for( ... all keys involved in the transaction ... ) mymap_txn_add( txn, key, 1 ); // guaranteed to succeed for this example

     ... try to do the transaction

     int err = mymap_txn_try( txn, FD_MAP_FLAG_BLOCKING );

     if( FD_UNLIKELY( err ) ) { // Not possible in this example

       ... At this point, err is FD_MAP_ERR_AGAIN and there was a
       ... potentially conflicting operation in progress during the try.
       ... We can should try again later (e.g. after a random backoff or
       ... doing other non-conflicting work).  We are no longer in a try
       ... but we could reuse the txn as-is to retry.

     } else {

       ... At this point, it is safe to try the transaction.
 
       ... Do the transaction here.  Since all keys are locked in this
       ... example, we don't need to worry about any changing behind our
       ... back (i.e. the try is guaranteed to succeed).

       ... Like modify, if we wants to rollback the transaction at this
       ... point, we should save the state of all locked keys involved
       ... to local temporaries before we do the transaction and then
       ... restore the state here.

       ... Finish the try (guaranteed to succeed for this example)

       mymap_txn_test( txn );

       ... At this point, we are no longer in a txn try but the txn is
       ... valid such that we could reuse the txn as-is for another
       ... transaction involving the same keys.

       mymap_txn_fini( txn );

       ... At this point, txn is no longer valid and we have ownership of
       ... the ltxn memory region

       ... free ltxn

     }

   To better understand the iter API:
     
     ... basic mymap element snapshot (i.e. iterate over all elements in
     ... the mymap at a globally consistent point in time while
     ... minimizing contension with other concurrent operations)
     
     ulong lock_cnt = mymap_chain_cnt( join );

     ulong * lock_seq = ... allocate lock_cnt ulong scratch ...

     for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) lock_seq[ lock_idx ] = lock_idx;
     
     mymap_iter_lock( join, lock_seq, lock_cnt, FD_MAP_FLAG_BLOCKING );
     
     for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) {
       ulong chain_idx = lock_seq[ lock_idx ]; // process chains in the order they were locked
     
       for( mymap_iter_t iter = mymap_iter( join, chain_idx ); !mymap_iter_done( iter ); iter = mymap_iter_next( iter ) ) {
         myele_t const * ele = mymap_iter_ele_const( iter );
     
         ... append ele to snapshot here (ele will be appended in
         ... no particular order for this example).  Note that, as
         ... the caller has a lock on the chain that manages ele,
         ... the caller is free to modify the fields of ele it
         ... manages.
     
       }
     
       mymap_iter_unlock( lock_seq + lock_idx, 1UL ); // unlock incrementally
     }
     
     ... free lock_seq here
*/

/* FIXME: consider adding a parallel verify that operates on a
   locked/idle subset of the chains. */

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

/* MAP_IDX_T is the map next index type.  Should be a primitive unsigned
   integer type large enough to represent the largest capacity element
   store of interest.  (E.g. if ushort, the maximum element store
   capacity compatible with the map will be 65535 elements.) */

#ifndef MAP_IDX_T
#define MAP_IDX_T ulong
#endif

/* MAP_NEXT is the MAP_ELE_T next field */

#ifndef MAP_NEXT
#define MAP_NEXT next
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

/* MAP_CNT_WIDTH gives the number of bits in a ulong to reserve for
   encoding the count in a versioned count.  Element store capacity
   should be representable in this width.  Default is 43 bits (e.g.
   enough to support a ~1 PiB element store of 128 byte elements).  The
   versioning width will be 64-MAP_CNT_WIDTH.  Since the least
   significant bit of the version is used to indicate locked, versioning
   width should be at least 2 and ideally as large as possible.  With
   the 43 default, a chain's version number will not be reused until
   2^20 individual operations on a chain have been done.  Version
   numbers only impact speculative operations.  If not using speculative
   operations, version width can be reduced to the minimum. */

#ifndef MAP_CNT_WIDTH
#define MAP_CNT_WIDTH (43)
#endif

/* MAP_ALIGN gives the alignment required for the map shared memory.
   Default is 128 for double cache line alignment.  Should be at least
   ulong alignment. */

#ifndef MAP_ALIGN
#define MAP_ALIGN (128UL)
#endif

/* MAP_MAGIC is the shared memory magic number to aid in persistent
   and/or interprocess usage. */

#ifndef MAP_MAGIC
#define MAP_MAGIC (0xf17eda2c37c3a900UL) /* firedancer cmap version 0 */
#endif

/* MAP_IMPL_STYLE controls what to generate:
     0 - header only library
     1 - library header declaration
     2 - library implementation */

#ifndef MAP_IMPL_STYLE
#define MAP_IMPL_STYLE 0
#endif

/* Commom map error codes (FIXME: probably should get around to making
   unified error codes, error strings and/or flags across util at least
   so we don't have to do this in the generator itself) */

#define FD_MAP_SUCCESS     (0)
#define FD_MAP_ERR_INVAL   (-1)
#define FD_MAP_ERR_AGAIN   (-2)
#define FD_MAP_ERR_CORRUPT (-3)
#define FD_MAP_ERR_KEY     (-4)

#define FD_MAP_FLAG_BLOCKING (1)
#define FD_MAP_FLAG_ADAPTIVE (2)

/* Implementation *****************************************************/

#define MAP_VER_WIDTH (64-MAP_CNT_WIDTH)

#if MAP_IMPL_STYLE==0 /* local use only */
#define MAP_STATIC FD_FN_UNUSED static
#else /* library header and/or implementation */
#define MAP_STATIC
#endif

#define MAP_(n) FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

#if MAP_IMPL_STYLE!=2 /* need header */

#include "../bits/fd_bits.h"

/* Note: we don't overalign chain metadata to reduce on map metadata
   footprint requirements.  Though this can cause cache false sharing
   for concurrent operations on different keys that are managed
   different chains that share a cache line, this risk can be controlled
   by overprovisioning chain_cnt.  That is, for a fixed map metadata
   footprint, this false sharing seems preferable to using fewer chains
   as that would lead to an equivalent increase in the amount of locking
   necessary to avoid potential conflicts for keys managed by the same
   chain (i.e. the former makes good use of the padding that would be
   otherwise wasted if overaligning this). */

struct MAP_(shmem_private_chain) {
  ulong     ver_cnt;   /* versioned count, cnt is in [0,ele_max] in lsb, ver in msb, odd: chain locked, even: chain unlocked */
  MAP_IDX_T head_cidx; /* compressed index of the first element on the chain */
};

typedef struct MAP_(shmem_private_chain) MAP_(shmem_private_chain_t);

struct __attribute__((aligned(MAP_ALIGN))) MAP_(shmem_private) {

  /* FIXME: consider having a memo of the chain in which an element is
     stored and/or using doubly linked list chains (maybe with the xor
     trick)?  We could do faster variants of remove and maybe amortize
     some hash calcs. */

  ulong magic;     /* == MAP_MAGIC */
  ulong seed;      /* Hash seed, arbitrary */
  ulong chain_cnt; /* Number of chains, positive integer power-of-two */

  /* Padding to MAP_ALIGN alignment here */

  /* MAP_(shmem_private_chain_t) chain[ chain_cnt ] here */
};

typedef struct MAP_(shmem_private) MAP_(shmem_t);

struct MAP_(private) {
  MAP_(shmem_t) * map;     /* Location of the map in the local address space */
  MAP_ELE_T *     ele;     /* Location of the element store in the local address space */
  ulong           ele_max; /* Capacity of the element store, in [0,ele_max_max] */
};

typedef struct MAP_(private) MAP_(t);

struct MAP_(query_private) {
  MAP_ELE_T *                   ele;     /* Points to the operation element in the local address space (or a sentinel) */
  MAP_(shmem_private_chain_t) * chain;   /* Points to the chain that manages element in the local address space */
  ulong                         ver_cnt; /* Versioned count of the chain at operation try */
};

typedef struct MAP_(query_private) MAP_(query_t);

struct MAP_(txn_private_info) {
  MAP_(shmem_private_chain_t) * chain;   /* Points to the chain that manages one or more txn keys (set by txn_add) */
  ulong                         ver_cnt; /* Versioned count of the chain at the transaction start (set by txn_try) */
};

typedef struct MAP_(txn_private_info) MAP_(txn_private_info_t);

struct MAP_(txn_private) {
  MAP_(shmem_t) * map;      /* Map used by this transaction */
  ulong           info_max; /* Number of chains possible for this transaction */
  ulong           lock_cnt; /* Number of chains in the locked set,      in [0,info_max] */
  ulong           spec_cnt; /* Number of chains in the speculative set, in [0,info_max], lock_cnt + spec_cnt <= info_max */

  /* MAP_(txn_private_info_t) info[ info_max ] here (obligatory sigh
     about lagging C++ support for 0 sized structure array footers).

     The locked      set is at indices [0,lock_cnt),                 lock_cnt                              infos.
     The free        set is at indices [lock_cnt,info_max-spec_cnt), free_cnt = info_max-spec_cnt-lock_cnt infos.
     The speculative set is at indices [info_max-spec_cnt,info_max), spec_cnt                              infos.

     A chain will appear at most once in a set.  A chain will not appear
     in both sets.

     Note that it would be trivial to make this shared memory persistent
     though not obvious if that would be useful.  (A precomputed
     template for a common transaction done by multiple threads is a
     possibility but the versions would still need to be local.) */

};

typedef struct MAP_(txn_private) MAP_(txn_t);

struct MAP_(iter_private) {
  MAP_ELE_T const * ele;     /* Pointer to the element store in the caller's address space */
  ulong             ele_idx; /* Current iteration element store index (or the null index) */
};

typedef struct MAP_(iter_private) MAP_(iter_t);

FD_PROTOTYPES_BEGIN

/* map_private_vcnt pack ver and cnt into a versioned cnt.  ver is
   masked to fit into MAP_VER_WIDTH bits.  cnt is assumed in
   [0,ele_max_max].

   map_private_vcnt_{ver,cnt} extract the {version,index} from a
   versioned index.  Return will fit into {MAP_VER_WIDTH,MAP_CNT_WIDTH}
   bits. */

FD_FN_CONST static inline ulong MAP_(private_vcnt)( ulong ver, ulong cnt ) { return (ver<<MAP_CNT_WIDTH) | cnt; }

FD_FN_CONST static inline ulong MAP_(private_vcnt_ver)( ulong ver_cnt ) { return  ver_cnt >> MAP_CNT_WIDTH;  }
FD_FN_CONST static inline ulong MAP_(private_vcnt_cnt)( ulong ver_cnt ) { return (ver_cnt << MAP_VER_WIDTH) >> MAP_VER_WIDTH; }

/* map_shmem_private_chain returns the location in the caller's address
   space of the map chain metadata.  Assumes map is valid.
   map_shmem_private_chain_const is a const correct version. */

FD_FN_CONST static inline MAP_(shmem_private_chain_t) *
MAP_(shmem_private_chain)( MAP_(shmem_t) * map ) {
  return (MAP_(shmem_private_chain_t) *)(map+1);
}

FD_FN_CONST static inline MAP_(shmem_private_chain_t) const *
MAP_(shmem_private_chain_const)( MAP_(shmem_t) const * map ) {
  return (MAP_(shmem_private_chain_t) const *)(map+1);
}

/* map_txn_private_info returns the location in the caller's address
   space of the txn info.  Assumes txn is valid. */

FD_FN_CONST static inline MAP_(txn_private_info_t) *
MAP_(txn_private_info)( MAP_(txn_t) * txn ) {
  return (MAP_(txn_private_info_t) *)(txn+1);
}

/* map_private_chain_idx returns the index of the chain, in
   [0,chain_cnt), that manages key for a map with chain_cnt chains and
   the given seed.  Assumes chain_cnt is an integer power-of-two.
   Assumes key is stable for the duration of the call.  Retains no
   interest in key on return. */

FD_FN_PURE static inline ulong
MAP_(private_chain_idx)( MAP_KEY_T const * key,
                         ulong             seed,
                         ulong             chain_cnt ) {
  return (MAP_KEY_HASH( (key), (seed) )) & (chain_cnt-1UL);
}

/* map_private_{cidx,idx} compress / decompress 64-bit in-register
   indices to/from their in-memory representations. */

FD_FN_CONST static inline MAP_IDX_T MAP_(private_cidx)( ulong     idx  ) { return (MAP_IDX_T)idx;  }
FD_FN_CONST static inline ulong     MAP_(private_idx) ( MAP_IDX_T cidx ) { return (ulong)    cidx; }

/* map_private_idx_null returns the element storage index that
   represents NULL. */

FD_FN_CONST static inline ulong MAP_(private_idx_null)( void ) { return (ulong)(MAP_IDX_T)(~0UL); }

/* map_private_idx_is_null returns 1 if idx is the NULL map index and 0
   otherwise. */

FD_FN_CONST static inline int MAP_(private_idx_is_null)( ulong idx ) { return idx==(ulong)(MAP_IDX_T)(~0UL); }

/* map_private_cas does a ulong FD_ATOMIC_CAS when the target has
   FD_HAS_ATOMIC and emulates it when not.  When emulated, the map will
   not be safe to use concurrently but will still work. */

static inline ulong
MAP_(private_cas)( ulong volatile * p,
                   ulong            c,
                   ulong            s ) {
  ulong o;
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  o = FD_ATOMIC_CAS( p, c, s );
# else
  o = *p;
  *p = fd_ulong_if( o==c, s, c );
# endif
  FD_COMPILER_MFENCE();
  return o;
}

FD_FN_CONST static inline ulong MAP_(ele_max_max)( void ) { return (ulong)(MAP_IDX_T)(ULONG_MAX >> MAP_VER_WIDTH); }

FD_FN_CONST static inline ulong
MAP_(chain_max)( void ) {
  return fd_ulong_pow2_dn( (ULONG_MAX - sizeof(MAP_(shmem_t)) - alignof(MAP_(shmem_t)) + 1UL) /
                           sizeof(MAP_(shmem_private_chain_t)) );
}

FD_FN_CONST static inline ulong
MAP_(chain_cnt_est)( ulong ele_max_est ) {

  /* Clamp to be in [1,ele_max_max] (as ele_max_est 0 is degenerate and
     as the map is guaranteed to hold at most ele_max_max keys). */

  ele_max_est = fd_ulong_min( fd_ulong_max( ele_max_est, 1UL ), MAP_(ele_max_max)() );

  /* Compute the number of chains as the power of 2 that makes the
     average chain length between ~1 and ~2 when ele_max_est are stored
     in the map and then clamp to the chain max. */

  ulong chain_min = (ele_max_est>>1) + (ele_max_est&1UL); /* chain_min = ceil(ele_max_est/2), in [1,2^63], computed w/o overflow */
  ulong chain_cnt = fd_ulong_pow2_up( chain_min );        /* Power of 2 in [1,2^63] */

  return fd_ulong_min( chain_cnt, MAP_(chain_max)() );
}

FD_FN_CONST static inline ulong MAP_(align)( void ) { return alignof(MAP_(shmem_t)); }

FD_FN_CONST static inline ulong
MAP_(footprint)( ulong chain_cnt ) {
  if( !(fd_ulong_is_pow2( chain_cnt ) & (chain_cnt<=MAP_(chain_max)())) ) return 0UL;
  /* Note: assumes shmem_t and shmem_private_chain_t have compatible alignments */
  return fd_ulong_align_up( sizeof(MAP_(shmem_t)) + chain_cnt*sizeof(MAP_(shmem_private_chain_t)),
                            alignof(MAP_(shmem_t)) ); /* no overflow */
}

FD_FN_PURE static inline ulong MAP_(seed)     ( MAP_(t) const * join ) { return join->map->seed;      }
FD_FN_PURE static inline ulong MAP_(chain_cnt)( MAP_(t) const * join ) { return join->map->chain_cnt; }

FD_FN_PURE static inline void const * MAP_(shmap_const)( MAP_(t) const * join ) { return join->map;     }
FD_FN_PURE static inline void const * MAP_(shele_const)( MAP_(t) const * join ) { return join->ele;     }
FD_FN_PURE static inline ulong        MAP_(ele_max)    ( MAP_(t) const * join ) { return join->ele_max; }

FD_FN_PURE static inline void * MAP_(shmap)( MAP_(t) * join ) { return join->map; }
FD_FN_PURE static inline void * MAP_(shele)( MAP_(t) * join ) { return join->ele; }

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

FD_FN_PURE static inline MAP_ELE_T const * MAP_(query_ele_const)( MAP_(query_t) const * query ) { return query->ele; }
FD_FN_PURE static inline MAP_ELE_T       * MAP_(query_ele      )( MAP_(query_t)       * query ) { return query->ele; }

static inline int
MAP_(modify_test)( MAP_(query_t) * query ) {
  MAP_(shmem_private_chain_t) * chain   = query->chain;
  ulong                         ver_cnt = query->ver_cnt;
  FD_COMPILER_MFENCE();
  chain->ver_cnt = ver_cnt + (2UL<<MAP_CNT_WIDTH);
  FD_COMPILER_MFENCE();
  return FD_MAP_SUCCESS;
}

static inline int
MAP_(query_test)( MAP_(query_t) const * query ) {
  MAP_(shmem_private_chain_t) const * chain   = query->chain;
  ulong                               ver_cnt = query->ver_cnt;
  FD_COMPILER_MFENCE();
  ulong _ver_cnt = chain->ver_cnt;
  FD_COMPILER_MFENCE();
  return fd_int_if( ver_cnt==_ver_cnt, FD_MAP_SUCCESS, FD_MAP_ERR_AGAIN );
}

FD_FN_CONST static inline ulong
MAP_(txn_key_max_max)( void ) {
  return (ULONG_MAX - sizeof(MAP_(txn_t)) - alignof(MAP_(txn_t)) + 1UL) / sizeof( MAP_(txn_private_info_t) );
}

FD_FN_CONST static inline ulong MAP_(txn_align)( void ) { return alignof(MAP_(txn_t)); }

FD_FN_CONST static inline ulong
MAP_(txn_footprint)( ulong key_max ) {
  if( key_max > MAP_(txn_key_max_max)() ) return 0UL;
  return sizeof(MAP_(txn_t)) + key_max*sizeof(MAP_(txn_private_info_t)); /* no overflow */
}

static inline MAP_(txn_t) *
MAP_(txn_init)( void *    mem,
                MAP_(t) * join,
                ulong     key_max ) {
  MAP_(txn_t) * txn = (MAP_(txn_t) *)mem;
  if( FD_UNLIKELY( (!mem                                                 ) |
                   (!fd_ulong_is_aligned( (ulong)mem, MAP_(txn_align)() )) |
                   (!join                                                ) |
                   (key_max > MAP_(txn_key_max_max)()                    ) ) ) return NULL;
  txn->map      = join->map;
  txn->info_max = key_max;               /* Worst case number of chains impacted by this transaction */
  txn->lock_cnt = 0UL;
  txn->spec_cnt = 0UL;
  return txn;
}

FD_FN_CONST static inline void * MAP_(txn_fini)( MAP_(txn_t) * txn ) { return (void *)txn; }

FD_FN_PURE static inline ulong
MAP_(iter_chain_idx)( MAP_(t) const *   join,
                      MAP_KEY_T const * key ) {
  MAP_(shmem_t) const * map = join->map;
  return MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );
}

FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter)( MAP_(t) const * join,
            ulong           chain_idx ) {
  /* FIXME: consider iter = {NULL,NULL} if chain_idx >= join->map->chain_cnt? */
  MAP_(shmem_private_chain_t) const * chain = MAP_(shmem_private_chain_const)( join->map ) + chain_idx;
  MAP_(iter_t) iter;
  iter.ele     = join->ele;
  iter.ele_idx = MAP_(private_idx)( chain->head_cidx );
  return iter;
}

FD_FN_CONST static inline int MAP_(iter_done)( MAP_(iter_t) iter ) { return MAP_(private_idx_is_null)( iter.ele_idx ); }

FD_FN_PURE static inline MAP_(iter_t)
MAP_(iter_next)( MAP_(iter_t) iter ) {
  MAP_ELE_T const * ele = iter.ele + iter.ele_idx;
  iter.ele_idx = MAP_(private_idx)( ele->MAP_NEXT );
  return iter;
}

FD_FN_CONST static inline MAP_ELE_T *
MAP_(iter_ele)( MAP_(iter_t) iter ) {
  return (MAP_ELE_T *)(iter.ele + iter.ele_idx);
}

FD_FN_CONST static inline MAP_ELE_T const *
MAP_(iter_ele_const)( MAP_(iter_t) iter ) {
  return iter.ele + iter.ele_idx;
}

MAP_STATIC void *    MAP_(new)   ( void * shmem, ulong chain_cnt, ulong seed );
MAP_STATIC MAP_(t) * MAP_(join)  ( void * ljoin, void * shmap, void * shele, ulong ele_max );
MAP_STATIC void *    MAP_(leave) ( MAP_(t) * join );
MAP_STATIC void *    MAP_(delete)( void * map );

MAP_STATIC int MAP_(insert)( MAP_(t) * join, MAP_ELE_T * ele, int flags );

MAP_STATIC int
MAP_(remove)( MAP_(t) *         join,
              MAP_KEY_T const * key,
              MAP_ELE_T const * sentinel,
              MAP_(query_t) *   query,
              int               flags );

MAP_STATIC int
MAP_(modify_try)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  MAP_ELE_T *       sentinel,
                  MAP_(query_t) *   query,
                  int               flags );

MAP_STATIC int
MAP_(query_try)( MAP_(t) const *   join,
                 MAP_KEY_T const * key,
                 MAP_ELE_T const * sentinel,
                 MAP_(query_t) *   query );

MAP_STATIC int MAP_(txn_add)( MAP_(txn_t) * txn, MAP_KEY_T const * key, int lock );

MAP_STATIC int MAP_(txn_try)( MAP_(txn_t) * txn, int flags );

MAP_STATIC int
MAP_(txn_modify)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  MAP_ELE_T *       sentinel,
                  MAP_(query_t) *   query,
                  int               flags );

static inline int
MAP_(txn_query)( MAP_(t) const *   join,
                 MAP_KEY_T const * key,
                 MAP_ELE_T const * sentinel,
                 MAP_(query_t) *   query ) {
  return MAP_(txn_modify)( (MAP_(t) *)join, key, (MAP_ELE_T *)sentinel, query, 0 );
}

MAP_STATIC int MAP_(txn_test)( MAP_(txn_t) * txn );

MAP_STATIC int
MAP_(iter_lock)( MAP_(t) * join,
                 ulong *   lock_seq,
                 ulong     lock_cnt,
                 int       flags );

MAP_STATIC void
MAP_(iter_unlock)( MAP_(t) *     join,
                   ulong const * lock_seq,
                   ulong         lock_cnt );

MAP_STATIC void MAP_(reset)( MAP_(t) * join );

MAP_STATIC FD_FN_PURE int MAP_(verify)( MAP_(t) const * join );

MAP_STATIC FD_FN_CONST char const * MAP_(strerror)( int err );

FD_PROTOTYPES_END

#endif

#if MAP_IMPL_STYLE!=1 /* need implementations (assumes header already included) */

#include "../log/fd_log.h" /* Used by constructors and verify (FIXME: Consider making a compile time option) */

/* MAP_CRIT_{BEGIN,BLOCKED,END} handle virtually all atomic boilerplate
   for operations that require modifying a map chain's structure or
   elements managed by that chain.  Usage:

     MAP_CRIT( chain, blocking ) {

       ... At this point, we have a lock on the chain and the "ulong"
       ... ver_cnt contains the chain's versioned count just before we
       ... took the lock.  The "int" retain_lock is zero.
       ...
       ... Do locked operations on the map chain here
       ...
       ... On exiting this block, if retain_lock is non-zero, we resume
       ... execution immediately after MAP_CRIT_END.  This is used for
       ... "try" style operations where a "test" operation is done to
       ... unlock the chain after the caller does their try/test work.
       ... Otherwise, we will update the version number, unlock the
       ... chain and then resume execution after MAP_CRIT_END.
       ...
       ... Because compiler memory fences are done just before entering
       ... and after exiting this block, there is typically no need to
       ... use any atomics / volatile / fencing here.  That is, we can
       ... just write "normal" code on platforms where writes to memory
       ... become visible to other threads in the order in which they
       ... were issued in the machine code (e.g. x86) as the version
       ... update and unlock writes are after the changes done here
       ... and others will not proceed until they see the new version
       ... and unlock.  YMMV for non-x86 platforms (probably need
       ... additional hardware store fences in these macros).
       ...
       ... It is safe to use "break" and/or "continue" within this
       ... block.  The overall MAP_CRIT will exit with the appropriate
       ... compiler fencing, version update and unlocking and then
       ... execution will resume immediately after MAP_CRIT_END.
       ...
       ... IMPORTANT SAFETY TIP!  DO NOT RETURN FROM THIS BLOCK.
       ...
       ... IMPORTANT SAFETY TIP!  OPERATIONS THAT CHANGE THE CHAIN
       ... ELEMENT COUNT SHOULD UPDATE VER_CNT's COUNT WHILE HOLDING
       ... THE VERSION CONSTANT.

     } MAP_CRIT_BLOCKED {

       ... At this point, somebody else had a lock on the chain when we
       ... tried to take the lock.
       ...
       ... Handle blocked here.
       ...
       ... On exiting this block, if blocking was zero in MAP_CRIT, we
       ... will resume execution immediately after MAP_CRIT_END.  If
       ... blocking was non-zero, we will resume execution immediately
       ... before MAP_CRIT (e.g. we will retry again after a short spin
       ... pause).  Similar considerations to the above for compiler
       ... memory fences, "break" and "continue".  As we do not have the
       ... lock here, retain_lock is neither relevant nor available.
       ...
       ... IMPORTANT SAFETY TIP!  DO NOT RETURN FROM THIS BLOCK.
       
     } MAP_CRIT_END; */

#define MAP_CRIT(c,b) do {                                                                                                       \
    ulong volatile * _vc         = (ulong volatile *)&(c)->ver_cnt;                                                              \
    int              _b          = (b);                                                                                          \
    int              retain_lock = 0;                                                                                            \
    FD_COMPILER_MFENCE();                                                                                                        \
    for(;;) {                                                                                                                    \
      ulong ver_cnt = *_vc;                                                                                                      \
      if( FD_LIKELY( !(ver_cnt & (1UL<<MAP_CNT_WIDTH))                                        ) &&  /* opt for low contention */ \
          FD_LIKELY( MAP_(private_cas)( _vc, ver_cnt, ver_cnt+(1UL<<MAP_CNT_WIDTH) )==ver_cnt ) ) { /* opt for low contention */ \
        FD_COMPILER_MFENCE();                                                                                                    \
        do

#define MAP_CRIT_BLOCKED                                                                  \
        while(0);                                                                         \
        FD_COMPILER_MFENCE();                                                             \
        if( !retain_lock ) *_vc = ver_cnt+(2UL<<MAP_CNT_WIDTH); /* likely compile time */ \
        FD_COMPILER_MFENCE();                                                             \
        break;                                                                            \
      } else {                                                                            \
        FD_COMPILER_MFENCE();                                                             \
        do

#define MAP_CRIT_END                               \
        while(0);                                  \
        FD_COMPILER_MFENCE();                      \
        if( !_b ) break; /* likely compile time */ \
        FD_SPIN_PAUSE();                           \
      }                                            \
    }                                              \
    FD_COMPILER_MFENCE();                          \
  } while(0)

MAP_STATIC void *
MAP_(new)( void * shmem,
           ulong  chain_cnt,
           ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, MAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = MAP_(footprint)( chain_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }

  /* seed is arbitrary */

  /* Init the metadata */

  MAP_(shmem_t) * map = (MAP_(shmem_t) *)shmem;

  map->seed      = seed;
  map->chain_cnt = chain_cnt;

  /* Set all the chains to version 0 and empty */

  MAP_(shmem_private_chain_t) * chain = MAP_(shmem_private_chain)( map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    chain[ chain_idx ].ver_cnt   = MAP_(private_vcnt)( 0UL, 0UL );
    chain[ chain_idx ].head_cidx = MAP_(private_cidx)( MAP_(private_idx_null)() );
  }

  FD_COMPILER_MFENCE();
  map->magic = MAP_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

MAP_STATIC MAP_(t) *
MAP_(join)( void * ljoin,
            void * shmap,
            void * shele,
            ulong  ele_max ) {
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

  if( FD_UNLIKELY( (!ele) & (!!ele_max) ) ) {
    FD_LOG_WARNING(( "NULL shele" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ele, alignof(MAP_ELE_T) ) ) ) {
    FD_LOG_WARNING(( "misaligned shele" ));
    return NULL;
  }

  join->map     = map;
  join->ele     = ele;
  join->ele_max = ele_max;

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

MAP_STATIC int
MAP_(insert)( MAP_(t) *   join,
              MAP_ELE_T * ele,
              int         flags ) {

  /* Determine the element index (fastest if ele are power-of-two) and
     the chain that should hold ele */

  ulong ele_idx = (ulong)(ele - join->ele);
  if( FD_UNLIKELY( ele_idx>=join->ele_max ) ) return FD_MAP_ERR_INVAL;

  MAP_(shmem_t) * map = join->map;
  MAP_(shmem_private_chain_t) * chain =
    MAP_(shmem_private_chain)( map ) + MAP_(private_chain_idx)( &ele->MAP_KEY, map->seed, map->chain_cnt );

  /* Insert element at the head of chain.  If chain is already locked,
     signal to try again later. */

  int err;

  MAP_CRIT( chain, flags & FD_MAP_FLAG_BLOCKING ) {
    ulong version = MAP_(private_vcnt_ver)( ver_cnt );
    ulong ele_cnt = MAP_(private_vcnt_cnt)( ver_cnt );

    ele->MAP_NEXT    = chain->head_cidx;
    chain->head_cidx = MAP_(private_cidx)( ele_idx );
    ver_cnt          = MAP_(private_vcnt)( version, ele_cnt+1UL ); /* version updated on exit */
    err              = FD_MAP_SUCCESS;

  } MAP_CRIT_BLOCKED {

    err = FD_MAP_ERR_AGAIN;

  } MAP_CRIT_END;

  return err;
}

MAP_STATIC int
MAP_(remove)( MAP_(t) *         join,
              MAP_KEY_T const * key,
              MAP_ELE_T const * sentinel,
              MAP_(query_t) *   query,
              int               flags ) {

  /* Determine the chain that should hold key */

  MAP_(shmem_t) * map     = join->map;
  MAP_ELE_T *     ele     = join->ele;
  ulong           ele_max = join->ele_max;

  MAP_(shmem_private_chain_t) * chain =
    MAP_(shmem_private_chain)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );

  /* Find the key on the chain.  If found, remove it.  If not found,
     corrupt or blocked, fail the operation. */

  query->ele   = (MAP_ELE_T *)sentinel;
  query->chain = chain;

  int err;

  MAP_CRIT( chain, flags & FD_MAP_FLAG_BLOCKING ) {
    ulong version = MAP_(private_vcnt_ver)( ver_cnt );
    ulong ele_cnt = MAP_(private_vcnt_cnt)( ver_cnt );

    query->ver_cnt = ver_cnt;

    if( FD_UNLIKELY( ele_cnt>ele_max ) ) { /* optimize for not corrupt */
      err = FD_MAP_ERR_CORRUPT;
      goto done;
    }

    MAP_IDX_T * cur = &chain->head_cidx;
    for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) { /* guarantee bounded exec under corruption */
      ulong ele_idx = MAP_(private_idx)( *cur );
      if( FD_UNLIKELY( ele_idx>=ele_max ) ) { /* optimize for not corrupt */
        err = FD_MAP_ERR_CORRUPT;
        goto done;
      }

      if( FD_LIKELY( MAP_(key_eq)( key, &ele[ ele_idx ].MAP_KEY ) ) ) { /* optimize for found */
        *cur       = ele[ ele_idx ].MAP_NEXT;
        ver_cnt    = MAP_(private_vcnt)( version, ele_cnt-1UL ); /* version updated on exit */
        query->ele = &ele[ ele_idx ];
        err        = FD_MAP_SUCCESS;
        goto done;
      }

      cur = &ele[ ele_idx ].MAP_NEXT; /* Retain the pointer to next so we can rewrite it on found */
    }

    /* Key was not found */

    ulong ele_idx = MAP_(private_idx)( *cur );
    if( FD_UNLIKELY( !MAP_(private_idx_is_null( ele_idx ) ) ) ) { /* optimize for not corrupt */
      err = FD_MAP_ERR_CORRUPT;
      goto done;
    }

    err = FD_MAP_ERR_KEY;

  done: /* silly language restriction */;

  } MAP_CRIT_BLOCKED {

    query->ver_cnt = ver_cnt;
    err            = FD_MAP_ERR_AGAIN;

  } MAP_CRIT_END;

  return err;
}

MAP_STATIC int
MAP_(modify_try)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  MAP_ELE_T *       sentinel,
                  MAP_(query_t) *   query,
                  int               flags ) {

  /* Determine which chain might hold key */

  MAP_(shmem_t) * map     = join->map;
  MAP_ELE_T *     ele     = join->ele;
  ulong           ele_max = join->ele_max;

  MAP_(shmem_private_chain_t) * chain =
    MAP_(shmem_private_chain)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );

  /* Search for the key on chain.  If found, retain the chain lock
     and return the found element.  If not found, corrupt or blocked,
     fail. */

  query->ele   = (MAP_ELE_T *)sentinel;
  query->chain = chain;

  int err;

  MAP_CRIT( chain, flags & FD_MAP_FLAG_BLOCKING ) {

    query->ver_cnt = ver_cnt;

    ulong ele_cnt = MAP_(private_vcnt_cnt)( ver_cnt );
    if( FD_UNLIKELY( ele_cnt>ele_max ) ) { /* optimize for not corrupt */
      err = FD_MAP_ERR_CORRUPT;
      goto done;
    }

    MAP_IDX_T * cur = &chain->head_cidx;
    for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) { /* guarantee bounded exec under corruption */
      ulong ele_idx = MAP_(private_idx)( *cur );
      if( FD_UNLIKELY( ele_idx>=ele_max ) ) { /* optimize for not corrupt */
        err = FD_MAP_ERR_CORRUPT;
        goto done;
      }

      if( FD_LIKELY( MAP_(key_eq)( key, &ele[ ele_idx ].MAP_KEY ) ) ) { /* optimize for found */
        if( flags & FD_MAP_FLAG_ADAPTIVE ) {
          *cur                    = ele[ ele_idx ].MAP_NEXT;
          ele[ ele_idx ].MAP_NEXT = chain->head_cidx;
          chain->head_cidx        = MAP_(private_cidx)( ele_idx );
        }
        query->ele  = &ele[ ele_idx ];
        err         = FD_MAP_SUCCESS;
        retain_lock = 1;
        goto done;
      }

      cur = &ele[ ele_idx ].MAP_NEXT; /* Retain the pointer to next so we can rewrite it on found */
    }

    ulong ele_idx = MAP_(private_idx)( *cur );
    if( FD_UNLIKELY( !MAP_(private_idx_is_null( ele_idx ) ) ) ) { /* optimize for not corrupt */
      err = FD_MAP_ERR_CORRUPT;
      goto done;
    }

    err = FD_MAP_ERR_KEY;

  done: /* silly language restriction */;

  } MAP_CRIT_BLOCKED {

    query->ver_cnt = ver_cnt;
    err            = FD_MAP_ERR_AGAIN;

  } MAP_CRIT_END;

  return err;
}

MAP_STATIC int
MAP_(query_try)( MAP_(t) const *   join,
                 MAP_KEY_T const * key,
                 MAP_ELE_T const * sentinel,
                 MAP_(query_t) *   query ) {

  /* Determine which chain might hold key */

  MAP_(shmem_t) const * map     = join->map;
  MAP_ELE_T const *     ele     = join->ele;
  ulong                 ele_max = join->ele_max;

  MAP_(shmem_private_chain_t) const * chain =
    MAP_(shmem_private_chain_const)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );

  /* Determine the version of the chain we are querying.  Then
     speculatively read and validate the number of elements on the chain
     at that version.  If the chain is locked, tell the user to try
     again later.  If the number of elements in the chain is invalid,
     tell user the map is corrupt. */

  ulong volatile const * _vc = &chain->ver_cnt;

  FD_COMPILER_MFENCE();
  ulong then = *_vc;
  FD_COMPILER_MFENCE();

  ulong ele_cnt = MAP_(private_vcnt_cnt)( then );

  FD_COMPILER_MFENCE();
  ulong now  = *_vc;
  FD_COMPILER_MFENCE();

  query->ele     = (MAP_ELE_T *)                  sentinel;
  query->chain   = (MAP_(shmem_private_chain_t) *)chain;
  query->ver_cnt = then;

  if( FD_UNLIKELY( (now!=then) | (!!(then & (1UL<<MAP_CNT_WIDTH))) ) ) return FD_MAP_ERR_AGAIN;
  if( FD_UNLIKELY( ele_cnt>ele_max                                 ) ) return FD_MAP_ERR_CORRUPT;

  /* Search the chain for key.  Since we know the numer of elements on
     the chain, we can bound this search to avoid corruption causing out
     of bound reads, infinite loops and such. */

  MAP_IDX_T const * cur = &chain->head_cidx;
  for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) {

    /* Speculatively read the index of the chain, speculate if a valid
       index and, if so, speculate if the chain element matches the
       query.  Note that this assumes element keys have a lifetime of at
       least that of the element.  A sufficient (but not a necessary,
       see rant) condition for this is that key is a plain-old-data
       fields in the element. */

    FD_COMPILER_MFENCE();
    ulong ele_idx = MAP_(private_idx)( *cur );
    FD_COMPILER_MFENCE();

    int corrupt = (ele_idx>=ele_max);
    int found   = !corrupt ? MAP_(key_eq)( key, &ele[ ele_idx ].MAP_KEY ) : 0;

    /* Validate the speculation.  If validation fails (e.g. the chain
       was modified behind our back), tell the user to try again later.
       If the element index was not valid, tell the user the map has
       been corrupted.  If key was found at element, tell the user they
       can speculate element ele_idx contains key. */

    FD_COMPILER_MFENCE();
    now = *_vc;
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( now!=then ) ) return FD_MAP_ERR_AGAIN;
    if( FD_UNLIKELY( corrupt   ) ) return FD_MAP_ERR_CORRUPT;

    if( FD_LIKELY( found ) ) { /* Optimize for found */
      query->ele = (MAP_ELE_T *)&ele[ ele_idx ];
      return FD_MAP_SUCCESS;
    }

    /* The chain element didn't hold the key ... move to next element */

    cur = &ele[ ele_idx ].MAP_NEXT;
  }

  /* At this point, the chain didn't hold the key.  We could probably
     return immediately but we speculative read the tail pointer,
     validate it as an additional integrity check.  If these checks
     pass, we are confident the whole chain looked valid and did not
     hold key between now and then. */

  ulong ele_idx = MAP_(private_idx)( *cur );

  FD_COMPILER_MFENCE();
  now = *_vc;
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( now!=then                              ) ) return FD_MAP_ERR_AGAIN;
  if( FD_UNLIKELY( !MAP_(private_idx_is_null( ele_idx ) ) ) ) return FD_MAP_ERR_CORRUPT;

  return FD_MAP_ERR_KEY;
}

/* Note: txn_add is currently optimized for reasonably small number
   of keys per transaction.  For a huge number of transaction keys (e.g.
   an iterator over all keys for all keys), probably should use the
   iterator API.  For a moderate number of transaction keys, probably
   should consider data structures where set insert/remove/test are
   sublinear time.  Similarly, if MAP_HASH is costly, might be useful to
   stash the key hashes in the transaction, memoize it in the elements,
   etc. */

MAP_STATIC int
MAP_(txn_add)( MAP_(txn_t) *     txn,
               MAP_KEY_T const * key,
               int               lock ) {

  /* Unpack txn fields */

  MAP_(shmem_t) * map      = txn->map;
  ulong           info_max = txn->info_max;
  ulong           lock_cnt = txn->lock_cnt;
  ulong           spec_cnt = txn->spec_cnt;

  MAP_(txn_private_info_t) * lock_info = MAP_(txn_private_info)( txn );
  MAP_(txn_private_info_t) * spec_info = lock_info + (info_max - spec_cnt);

  /* Determine which chain manages this key */

  MAP_(shmem_private_chain_t) * chain = MAP_(shmem_private_chain)( map )
                                      + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );

  /* If this chain already needs to be locked for this transaction,
     nothing to do. */

  for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ )
    if( FD_UNLIKELY( chain==lock_info[ lock_idx ].chain ) ) return FD_MAP_SUCCESS;

  if( FD_UNLIKELY( !lock ) ) { /* optimize for locked key, possible compile time */

    /* At this point, key is used speculatively by the transaction and
       its managing chain isn't in the locked set.  If this chain is
       already in the speculative set, nothing to do. */

    for( ulong spec_idx=0UL; spec_idx<spec_cnt; spec_idx++ )
      if( FD_UNLIKELY( chain==spec_info[ spec_idx ].chain ) ) return FD_MAP_SUCCESS;

    /* Add the chain to the speculative set.  If we don't have any room,
       fail. */

    ulong free_cnt = info_max - lock_cnt - spec_cnt;
    if( FD_UNLIKELY( !free_cnt ) ) return FD_MAP_ERR_INVAL; /* Impossible if less than key_max keys added */
    spec_info[-1].chain = chain;
    txn->spec_cnt = spec_cnt + 1UL;

  } else {

    /* At this point, key is used locked by the transaction and its
       managing chain isn't in the locked set.  If this chain is
       currently in the speculative set, move it to the locked
       set. */

    for( ulong spec_idx=0UL; spec_idx<spec_cnt; spec_idx++ )
      if( FD_UNLIKELY( chain==spec_info[ spec_idx ].chain ) ) {
        spec_info[ spec_idx ].chain = spec_info[ 0 ].chain; /* Fill the hole at spec_idx, making a hole at 0 */
        lock_info[ lock_cnt ].chain = chain;                /* Either uses unused entry or fills hole at 0 */
        txn->spec_cnt = spec_cnt - 1UL;
        txn->lock_cnt = lock_cnt + 1UL;
        return FD_MAP_SUCCESS;
      }

    /* Add the chain to the locked set.  If we don't have any room,
       fail. */

    ulong free_cnt = info_max - lock_cnt - spec_cnt;
    if( FD_UNLIKELY( !free_cnt ) ) return FD_MAP_ERR_INVAL; /* Impossible if less than key_max keys added */
    lock_info[lock_cnt].chain = chain;
    txn->lock_cnt = lock_cnt + 1UL;

  }

  return FD_MAP_SUCCESS;
}

MAP_STATIC int
MAP_(txn_try)( MAP_(txn_t) * txn,
               int           flags ) {
  int non_blocking = !(flags & FD_MAP_FLAG_BLOCKING);

  /* Unpack txn fields */

  ulong info_max = txn->info_max;
  ulong lock_cnt = txn->lock_cnt;
  ulong spec_cnt = txn->spec_cnt;

  MAP_(txn_private_info_t) * lock_info = MAP_(txn_private_info)( txn );
  MAP_(txn_private_info_t) * spec_info = lock_info + info_max - spec_cnt;

  ulong backoff_exp = (1UL<<32); /* See iter_lock for details */

  int err;

  for(;; ) {

    err = FD_MAP_SUCCESS;

    FD_COMPILER_MFENCE();

    /* Get the chain versions for all keys in the speculative set.
       If any are locked, set AGAIN if any are locked. */

    for( ulong spec_idx=0UL; spec_idx<spec_cnt; spec_idx++ ) {
      ulong ver_cnt = spec_info[ spec_idx ].chain->ver_cnt;
      if( FD_UNLIKELY( ver_cnt & (1UL<<MAP_CNT_WIDTH) ) ) { /* Already locked */
        err = FD_MAP_ERR_AGAIN;
        break;
      }
      spec_info[ spec_idx ].ver_cnt = ver_cnt;
    }

    if( FD_LIKELY( !err ) ) {

      /* At this point, all the chains we are speculating on were 
         unlocked and we have have recorded their versions.  Try to lock
         all the chains for the locked key. */
      /* FIXME: consider reordering like iter_lock? */

      for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) {

        MAP_CRIT( lock_info[ lock_idx ].chain, 0 ) { /* non-blocking */

          /* Got the lock ... save the version and retain the lock for
             test. */

          lock_info[ lock_idx ].ver_cnt = ver_cnt;
          retain_lock = 1;

        } MAP_CRIT_BLOCKED {

          /* We hit contention for this lock.  Unlock the any chains
             we already locked to prevent possible deadlock (see
             iter_lock) */

          for( ulong unlock_idx=0UL; unlock_idx<lock_idx; unlock_idx++ )
            lock_info[ unlock_idx ].chain->ver_cnt = lock_info[ unlock_idx ].ver_cnt + (2UL<<MAP_CNT_WIDTH);

          err = FD_MAP_ERR_AGAIN;

        } MAP_CRIT_END;

        if( FD_UNLIKELY( err ) ) break;

      }

    }

    FD_COMPILER_MFENCE();

    if( FD_LIKELY( (!err) | non_blocking ) ) break;

    /* At this point, we hit contention and are blocking (need to try
       again).  Do a random backoff (see iter_lock for details). */

    ulong scale = fd_ulong_min( (fd_ulong_min( lock_cnt+spec_cnt, (1UL<<16)-1UL )*backoff_exp) >> 16, (1UL<<32)-1UL );
    backoff_exp = fd_ulong_min( backoff_exp + (backoff_exp>>2) + (backoff_exp>>4), (1UL<<48)-1UL );
    mymap_backoff( scale, 0UL );
  }

  /* At this point, if we don't have an error, we have the chain
     versions for txn keys used speculatively and they were unlocked and
     we have locks on the chains for txn keys used locked.  Otherwise,
     this is a non-blocking call and we return AGAIN. */

  return err;
}

MAP_STATIC int
MAP_(txn_test)( MAP_(txn_t) * txn ) {

  /* Unpack txn fields */

  ulong info_max = txn->info_max;
  ulong lock_cnt = txn->lock_cnt;
  ulong spec_cnt = txn->spec_cnt;

  MAP_(txn_private_info_t) * lock_info = MAP_(txn_private_info)( txn );
  MAP_(txn_private_info_t) * spec_info = lock_info + info_max - spec_cnt;

  /* Unlock all chains locked for this transaction.  Then test if any
     keys used speculatively could have changed in locking / trying /
     unlocking.  If so, tell user to retry later. */

  int err = FD_MAP_SUCCESS;

  FD_COMPILER_MFENCE();

  for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) lock_info[ lock_idx ].chain->ver_cnt += (1UL<<MAP_CNT_WIDTH);

  for( ulong spec_idx=0UL; spec_idx<spec_cnt; spec_idx++ ) {
    MAP_(shmem_private_chain_t) const * chain   = spec_info[ spec_idx ].chain;
    ulong                               ver_cnt = spec_info[ spec_idx ].ver_cnt;
    if( FD_UNLIKELY( chain->ver_cnt!=ver_cnt ) ) {
      err = FD_MAP_ERR_AGAIN;
      break;
    }
  }

  FD_COMPILER_MFENCE();

  return err;
}

MAP_STATIC int
MAP_(txn_insert)( MAP_(t) *   join,
                  MAP_ELE_T * ele ) {

  /* Determine the element index (fastest if ele are power-of-two) and
     the chain that should hold ele */

  MAP_(shmem_t) * map     = join->map;
  ulong           ele_max = join->ele_max;

  ulong ele_idx = (ulong)(ele - join->ele);
  if( FD_UNLIKELY( ele_idx>=ele_max ) ) return FD_MAP_ERR_INVAL;

  MAP_(shmem_private_chain_t) * chain =
    MAP_(shmem_private_chain)( map ) + MAP_(private_chain_idx)( &ele->MAP_KEY, map->seed, map->chain_cnt );

  /* Insert ele_idx at head of chain. */

  ulong ver_cnt = chain->ver_cnt;
  ulong version = MAP_(private_vcnt_ver)( ver_cnt );
  ulong ele_cnt = MAP_(private_vcnt_cnt)( ver_cnt );

  ele->MAP_NEXT    = chain->head_cidx;
  chain->head_cidx = MAP_(private_cidx)( ele_idx );
  chain->ver_cnt   = MAP_(private_vcnt)( version, ele_cnt+1UL );

  return FD_MAP_SUCCESS;
}

MAP_STATIC int
MAP_(txn_remove)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  MAP_ELE_T const * sentinel,
                  MAP_(query_t) *   query ) {

  /* Determine the chain that should hold key */

  MAP_(shmem_t) * map     = join->map;
  MAP_ELE_T *     ele     = join->ele;
  ulong           ele_max = join->ele_max;

  MAP_(shmem_private_chain_t) * chain =
    MAP_(shmem_private_chain)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );

  /* Find the key on the chain and remove it */

  ulong ver_cnt = chain->ver_cnt;
  ulong version = MAP_(private_vcnt_ver)( ver_cnt );
  ulong ele_cnt = MAP_(private_vcnt_cnt)( ver_cnt );

  query->ele     = (MAP_ELE_T *)sentinel;
  query->chain   = chain;
  query->ver_cnt = ver_cnt;

  if( FD_UNLIKELY( ele_cnt>ele_max ) ) return FD_MAP_ERR_CORRUPT; /* optimize for not corrupt */

  MAP_IDX_T * cur = &chain->head_cidx;
  for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) { /* guarantee bounded exec under corruption */
    ulong ele_idx = MAP_(private_idx)( *cur );
    if( FD_UNLIKELY( ele_idx>=ele_max ) ) return FD_MAP_ERR_CORRUPT; /* optimize for not corrupt */

    if( FD_LIKELY( MAP_(key_eq)( key, &ele[ ele_idx ].MAP_KEY ) ) ) { /* optimize for found */
      *cur           = ele[ ele_idx ].MAP_NEXT;
      chain->ver_cnt = MAP_(private_vcnt)( version, ele_cnt-1UL );
      query->ele     = &ele[ ele_idx ];
      return FD_MAP_SUCCESS;
    }

    cur = &ele[ ele_idx ].MAP_NEXT; /* Retain the pointer to next so we can rewrite it on found */
  }

  ulong ele_idx = MAP_(private_idx)( *cur );
  if( FD_UNLIKELY( !MAP_(private_idx_is_null( ele_idx ) ) ) ) return FD_MAP_ERR_CORRUPT; /* optimize for not found */
  return FD_MAP_ERR_KEY;
}

MAP_STATIC int
MAP_(txn_modify)( MAP_(t) *         join,
                  MAP_KEY_T const * key,
                  MAP_ELE_T *       sentinel,
                  MAP_(query_t) *   query,
                  int               flags ) {

  /* Determine which chain might hold key */

  MAP_(shmem_t) * map     = join->map;
  MAP_ELE_T *     ele     = join->ele;
  ulong           ele_max = join->ele_max;

  MAP_(shmem_private_chain_t) * chain =
    MAP_(shmem_private_chain)( map ) + MAP_(private_chain_idx)( key, map->seed, map->chain_cnt );

  /* Search the chain for key */

  ulong ver_cnt = chain->ver_cnt;
  ulong ele_cnt = MAP_(private_vcnt_cnt)( ver_cnt );

  query->ele     = sentinel;
  query->chain   = chain;
  query->ver_cnt = ver_cnt;

  if( FD_UNLIKELY( ele_cnt>ele_max ) ) return FD_MAP_ERR_CORRUPT; /* optimize for not corrupt */

  MAP_IDX_T * cur = &chain->head_cidx;
  for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) {
    ulong ele_idx = MAP_(private_idx)( *cur );

    if( FD_UNLIKELY( ele_idx>=ele_max ) ) return FD_MAP_ERR_CORRUPT; /* optimize for not corrupt */

    if( FD_LIKELY( MAP_(key_eq)( key, &ele[ ele_idx ].MAP_KEY ) ) ) { /* optimize for found */
      if( flags & FD_MAP_FLAG_ADAPTIVE ) {
        *cur                    = ele[ ele_idx ].MAP_NEXT;
        ele[ ele_idx ].MAP_NEXT = chain->head_cidx;
        chain->head_cidx        = MAP_(private_cidx)( ele_idx );
      }
      query->ele = &ele[ ele_idx ];
      return FD_MAP_SUCCESS;
    }

    cur = &ele[ ele_idx ].MAP_NEXT;
  }

  ulong ele_idx = MAP_(private_idx)( *cur );
  if( FD_UNLIKELY( !MAP_(private_idx_is_null( ele_idx ) ) ) ) return FD_MAP_ERR_CORRUPT; /* optimize for not corrupt */

  return FD_MAP_ERR_KEY;
}

MAP_STATIC int
MAP_(iter_lock)( MAP_(t) * join,
                 ulong *   lock_seq,
                 ulong     lock_cnt,
                 int       flags ) {
  if( FD_UNLIKELY( !lock_cnt ) ) return FD_MAP_SUCCESS; /* nothing to do */

  int non_blocking = !(flags & FD_MAP_FLAG_BLOCKING);

  MAP_(shmem_private_chain_t) * chain = MAP_(shmem_private_chain)( join->map );

  int err;

  ulong backoff    = 1UL<<32; /* in [1,2^16)*2^32 */
  ulong lock_idx   = 0UL;
  ulong locked_cnt = 0UL;
  for(;;) {

    err = FD_MAP_SUCCESS;

    /* At this point, we've acquired locks [0,locked_cnt), we need to
       acquire locks [locked_cnt,lock_cnt), [locked_cnt,lock_cnt) is non
       empty and i is in [locked_cnt,lock_cnt).  Try to acquire lock
       lock_idx this iteration. */

    ulong chain_idx = lock_seq[ lock_idx ];

    MAP_CRIT( chain + chain_idx, 0 ) {

      /* At this point, we got the lock.  Swap lock at locked_cnt and
         lock_idx and increment locked_cnt to move lock_idx to the
         locked set as the most recently acquired lock.  Since we
         increment lock_idx below, when locked_cnt<lock_idx (i.e. we had
         contention for lock locked_cnt recently), this will move the
         next attempt to lock locked_cnt as far as possible from now of
         the remaining locks to acquire.  When locked_cnt==lock_idx,
         this is a branchless no-op (and the increment of lock_idx below
         will guarantee lock_idx will be at least locked_cnt next
         iteration, preserving the invariant that lock_idx is in
         [locked_cnt,lock_cnt) on the next iteration if there is one. */

      ulong chain_idx_tmp = lock_seq[ locked_cnt ];
      lock_seq[ lock_idx   ] = chain_idx_tmp;
      lock_seq[ locked_cnt ] = chain_idx;
      locked_cnt++;

      retain_lock = 1;

    } MAP_CRIT_BLOCKED {

      /* We failed to get lock lock_idx.  To avoid deadlock with the
         thread that has this lock and is trying get a lock we already
         have, we unlock the chains we've already locked (note that we
         need to unlock here in non-blocking operation too).  Quick
         experiments in extreme contention scenarios found more
         incremental approaches in blocking operation could take an
         excessively long time to resolve so we bulk unlock. */

      for( ulong unlock_idx=0UL; unlock_idx<locked_cnt; unlock_idx++ )
        chain[ lock_seq[ unlock_idx ] ].ver_cnt += (1UL<<MAP_CNT_WIDTH);
      locked_cnt = 0UL;

      err = FD_MAP_ERR_AGAIN;

    } MAP_CRIT_END;

    if( FD_UNLIKELY( (locked_cnt==lock_cnt  ) |          /* all locks acquired */
                     ((!!err) & non_blocking) ) ) break; /* or hit contention and are non-blocking */

    /* Move to the next lock.  Everytime we wrap around, we hit
       contention since the last wrap / iter start.  We do a random
       exponential backoff with saturation on wrapping to minimize
       contention with other threads hitting these locks.  Normalizing
       out fixed point scalings baked into the below, we spin pause a
       uniform IID random number of times in [0,unlocked_cnt*backoff]
       where backoff is 1 on the first wrap and increases by ~30% each
       time to a maximum of 2^16 (i.e. hundreds microseconds per
       remaining lock for typical CPU speeds and spin pause delays at
       maximum backoff). */

    lock_idx++;
    if( FD_UNLIKELY( lock_idx==lock_cnt ) ) { /* optimize for lots of locks */
      lock_idx = locked_cnt;
      ulong scale = fd_ulong_min( (fd_ulong_min( lock_cnt-locked_cnt, (1UL<<16)-1UL )*backoff) >> 16, (1UL<<32)-1UL );
      backoff = fd_ulong_min( backoff + (backoff>>2) + (backoff>>4), (1UL<<48)-1UL );
      mymap_backoff( scale, 0UL );
    }
  }

  return err;
}

MAP_STATIC void
MAP_(iter_unlock)( MAP_(t) *     join,
                   ulong const * lock_seq,
                   ulong         lock_cnt ) {
  MAP_(shmem_private_chain_t) * chain = MAP_(shmem_private_chain)( join->map );

  FD_COMPILER_MFENCE();
  for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ )
    chain[ lock_seq[ lock_idx ] ].ver_cnt += (1UL<<MAP_CNT_WIDTH);
  FD_COMPILER_MFENCE();
}

MAP_STATIC void
MAP_(reset)( MAP_(t) * join ) {
  MAP_(shmem_t) * map = join->map;

  ulong                         chain_cnt = map->chain_cnt;
  MAP_(shmem_private_chain_t) * chain     = MAP_(shmem_private_chain)( map );

  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    ulong ver_cnt = chain[ chain_idx ].ver_cnt;
    ulong version = MAP_(private_vcnt_ver)( ver_cnt );
    chain[ chain_idx ].ver_cnt   = MAP_(private_vcnt)( version+2UL, 0UL );
    chain[ chain_idx ].head_cidx = MAP_(private_cidx)( MAP_(private_idx_null)() );
  }
}

MAP_STATIC int
MAP_(verify)( MAP_(t) const * join ) {

# define MAP_TEST(c) do {                                                                        \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_MAP_ERR_CORRUPT; } \
  } while(0)

  /* Validate join */

  MAP_TEST( join );
  MAP_TEST( fd_ulong_is_aligned( (ulong)join, alignof(MAP_(t)) ) );

  MAP_(shmem_t) const * map     = join->map;
  MAP_ELE_T const *     ele     = join->ele;
  ulong                 ele_max = join->ele_max;

  MAP_TEST( map );
  MAP_TEST( fd_ulong_is_aligned( (ulong)map, MAP_(align)() ) );

  MAP_TEST( (!!ele) | (!ele_max) );
  MAP_TEST( fd_ulong_is_aligned( (ulong)ele, alignof(MAP_ELE_T) ) );

  MAP_TEST( ele_max<=MAP_(ele_max_max)() );

  /* Validate map metadata */

  ulong magic     = map->magic;
  ulong seed      = map->seed;
  ulong chain_cnt = map->chain_cnt;

  MAP_TEST( magic==MAP_MAGIC );
  /* seed is arbitrary */
  MAP_TEST( fd_ulong_is_pow2( chain_cnt ) );
  MAP_TEST( chain_cnt<=MAP_(chain_max)()  );

  MAP_(shmem_private_chain_t) const * chain = MAP_(shmem_private_chain_const)( map );

  /* Validate the map chains */

  ulong unmapped_ele_cnt = ele_max;
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {

    /* Validate the chain length */

    ulong ver_cnt = chain[ chain_idx ].ver_cnt;

    ulong ele_cnt = MAP_(private_vcnt_cnt)( ver_cnt );
    MAP_TEST( ele_cnt<=unmapped_ele_cnt );
    unmapped_ele_cnt -= ele_cnt;

    /* Validate chain linkage, element membership and element uniqueness */

    ulong head_idx = MAP_(private_idx)( chain[ chain_idx ].head_cidx );
    ulong cur_idx  = head_idx;
    for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) {
      MAP_TEST( cur_idx<ele_max );                                           /* In element store */

      MAP_KEY_T const * key = &ele[ cur_idx ].MAP_KEY;
      ulong ele_chain_idx = MAP_(private_chain_idx)( key, seed, chain_cnt );
      MAP_TEST( ele_chain_idx==chain_idx );                                  /* On correct chain */

      /* Note that we've already validated linkage from head_idx to
         cur_idx so pointer chasing here is safe. */

      ulong prv_idx = head_idx;
      while( prv_idx!=cur_idx ) {
        MAP_TEST( !MAP_(key_eq)( &ele[ prv_idx ].MAP_KEY, key ) );           /* Unique */
        prv_idx = MAP_(private_idx)( ele[ prv_idx ].MAP_NEXT );
      }

      cur_idx = MAP_(private_idx)( ele[ cur_idx ].MAP_NEXT );
    }

    MAP_TEST( MAP_(private_idx_is_null)( cur_idx ) );
  }

  /* At this point, we know the sum of the chain lengths do not exceed
     the size of the element store, each chain is of their stated
     length, each chain element is in element store, and that every
     element on a chain belongs on that chain (which precludes the
     possibility of two chains merging into one) and that every element
     on a chain is unique (which implies unique among all chains since
     elements with each key maps to a single chain).

     That is, join is a current local join to a valid shared mapping of
     unique keys to unique elements in the element store.

     We don't know anything about unmapped elements in the element store
     and cannot do any verification of them (here be dragons).  But
     that's kinda the point ... what's in the unmapped elements depends
     on how the application is managing those. */

# undef MAP_TEST

  return FD_MAP_SUCCESS;
}

MAP_STATIC char const *
MAP_(strerror)( int err ) {
  switch( err ) {
  case FD_MAP_SUCCESS:     return "success";
  case FD_MAP_ERR_INVAL:   return "bad input";
  case FD_MAP_ERR_AGAIN:   return "try again";
  case FD_MAP_ERR_CORRUPT: return "corruption detected";
  case FD_MAP_ERR_KEY:     return "key not found";
  default: break;
  }
  return "unknown";
}

#undef MAP_CRIT_END
#undef MAP_CRIT_BLOCKED
#undef MAP_CRIT

#endif

#undef MAP_
#undef MAP_STATIC
#undef MAP_VER_WIDTH

#undef MAP_IMPL_STYLE
#undef MAP_MAGIC
#undef MAP_ALIGN
#undef MAP_CNT_WIDTH
#undef MAP_KEY_HASH
#undef MAP_KEY_EQ
#undef MAP_NEXT
#undef MAP_IDX_T
#undef MAP_KEY
#undef MAP_KEY_T
#undef MAP_ELE_T
#undef MAP_NAME
