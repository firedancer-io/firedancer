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

# Production database
ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_accdb_admin_v2.h fd_accdb_impl_v2.h)
$(call add-objs,fd_accdb_admin_v2   fd_accdb_impl_v2,fd_flamenco)
$(call add-hdrs,fd_vinyl_req_pool.h)
$(call add-objs,fd_vinyl_req_pool,fd_flamenco)
endif

# Debug APIs
$(call add-hdrs,fd_accdb_fsck.h)
$(call add-objs,fd_accdb_fsck_funk fd_accdb_fsck_vinyl,fd_flamenco)
ifdef FD_HAS_LZ4
$(call make-bin,fd_accdb_ctl,fd_accdb_ctl,fd_vinyl fd_tango fd_ballet fd_util)
endif

ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_accdb_v1,test_accdb_v1,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_accdb_v1)
ifdef FD_HAS_LZ4
$(call make-unit-test,test_accdb_v2,test_accdb_v2,fd_flamenco fd_vinyl fd_funk fd_tango fd_ballet fd_util)
endif
endif
