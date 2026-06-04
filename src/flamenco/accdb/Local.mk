# Admin API
$(call add-hdrs,fd_accdb_admin.h)

# Low-level user API
$(call add-hdrs,fd_accdb_user.h)
$(call add-hdrs,fd_accdb_ref.h)

# Synchronous user API
$(call add-hdrs,fd_accdb_sync.h)

# Pipeline user API
$(call add-hdrs,fd_accdb_pipe.h)
$(call add-objs,fd_accdb_pipe,fd_flamenco)

# Mock database
$(call add-hdrs,fd_accdb_impl_v0.h)
$(call add-objs,fd_accdb_impl_v0,fd_flamenco)
$(call make-unit-test,test_accdb_v0,test_accdb_v0,fd_flamenco fd_ballet fd_util)

# In-memory only database
$(call add-hdrs,fd_accdb_funk.h)
$(call add-objs,fd_accdb_funk,fd_flamenco)
$(call add-hdrs,fd_accdb_lineage.h)
$(call add-objs,fd_accdb_lineage,fd_flamenco)
$(call add-hdrs,fd_accdb_admin_v1.h fd_accdb_impl_v1.h)
$(call add-objs,fd_accdb_admin_v1   fd_accdb_impl_v1,fd_flamenco)

# Debug APIs
$(call add-hdrs,fd_accdb_fsck.h)
$(call add-objs,fd_accdb_fsck_funk,fd_flamenco)

ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_accdb_v1,test_accdb_v1,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_accdb_v1)
ifdef FD_HAS_RACESAN
$(call make-unit-test,test_accdb_v1_racesan,test_accdb_v1_racesan,fd_flamenco fd_funk fd_ballet fd_util)
endif
endif

# New accounts database (accdb v4) core library
ifdef FD_HAS_ATOMIC
ifdef FD_HAS_ALLOCA

$(call add-hdrs,fd_accdb.h fd_accdb_cache.h fd_accdb_shmem.h)
$(call add-objs,fd_accdb fd_accdb_cache fd_accdb_shmem,fd_flamenco)

$(call make-unit-test,test_accdb,test_accdb,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_accdb)

$(call make-unit-test,test_accdb_cache,test_accdb_cache,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_accdb_cache)

$(call make-unit-test,bench_accdb,bench_accdb,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,bench_accdb_hotread,bench_accdb_hotread,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,bench_accdb_txn,bench_accdb_txn,fd_flamenco fd_ballet fd_util)

ifdef FD_HAS_RACESAN
$(call make-unit-test,test_accdb_racesan,test_accdb_racesan,fd_flamenco fd_ballet fd_util)
endif

endif
endif
