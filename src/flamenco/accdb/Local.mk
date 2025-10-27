# Admin API
$(call add-hdrs,fd_accdb_admin.h)
$(call add-objs,fd_accdb_admin,fd_flamenco)

# User API
$(call add-hdrs,fd_accdb_user.h fd_accdb_sync.h)
$(call add-objs,fd_accdb_user,fd_flamenco)

ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_accdb,test_accdb,fd_flamenco fd_funk fd_util)
$(call run-unit-test,test_accdb)
endif
