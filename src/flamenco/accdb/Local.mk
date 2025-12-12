# Admin API
$(call add-hdrs,fd_accdb_admin.h)
$(call add-objs,fd_accdb_admin,fd_flamenco)

# User API
$(call add-hdrs,fd_accdb_user.h fd_accdb_sync.h)

# Funk-based database
$(call add-hdrs,fd_accdb_impl_v1.h)
$(call add-objs,fd_accdb_impl_v1,fd_flamenco)

# Vinyl/funk prototype
$(call add-hdrs,fd_accdb_impl_v2.h)
$(call add-objs,fd_accdb_impl_v2,fd_flamenco)

# Internals
$(call add-hdrs,fd_vinyl_req_pool.h)
$(call add-objs,fd_vinyl_req_pool,fd_flamenco)

# Debug APIs
$(call add-hdrs,fd_accdb_fsck.h)
$(call add-objs,fd_accdb_fsck_funk fd_accdb_fsck_vinyl,fd_flamenco)
ifdef FD_HAS_LZ4
$(call make-bin,fd_accdb_ctl,fd_accdb_ctl,fd_vinyl fd_tango fd_ballet fd_util)
endif

ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_accdb_v1,test_accdb_v1,fd_flamenco fd_funk fd_util)
$(call run-unit-test,test_accdb_v1)
ifdef FD_HAS_LZ4
$(call make-unit-test,test_accdb_v2,test_accdb_v2,fd_flamenco fd_vinyl fd_funk fd_tango fd_util)
endif
endif
