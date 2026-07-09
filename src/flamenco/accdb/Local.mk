ifdef FD_HAS_ATOMIC
ifdef FD_HAS_ALLOCA

$(call add-hdrs,fd_accdb.h fd_accdb_cache.h fd_accdb_shmem.h)
$(call add-objs,fd_accdb fd_accdb_cache fd_accdb_shmem,fd_flamenco)
$(call add-objs,fd_accdb_tile,fd_disco) # TODO: MOVE TO DISCOF

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
