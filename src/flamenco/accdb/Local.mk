# Admin API
$(call add-hdrs,fd_accdb_admin.h)
$(call add-objs,fd_accdb_admin,fd_flamenco)

# User API
$(call add-hdrs,fd_accdb_user.h fd_accdb_sync.h)
$(call add-objs,fd_accdb_user,fd_flamenco)
