$(call add-hdrs,fd_accdb.h fd_accdb_tile.h)
$(call add-objs,fd_accdb_tile,fd_discof)
$(call add-objs,fd_accdb,fd_discof)

$(call make-unit-test,test_accdb,test_accdb,fd_discof fd_ballet fd_util)
$(call run-unit-test,test_accdb)
