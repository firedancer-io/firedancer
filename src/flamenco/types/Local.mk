$(call add-hdrs,fd_bincode.h fd_types.h fd_types_custom.h)
$(call add-objs,fd_types,fd_flamenco)
$(call make-unit-test,test_types,test_types,fd_flamenco fd_util)
$(call run-unit-test,test_types)
