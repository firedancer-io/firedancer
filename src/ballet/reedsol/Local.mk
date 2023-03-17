$(call add-hdrs,fd_reedsol.h)
ifdef FD_HAS_GFNI
$(call add-asms,fd_reedsol_gfni_32,fd_ballet)
endif
$(call add-objs,fd_reedsol,fd_ballet)
$(call add-objs,fd_reedsol_internal,fd_ballet)
$(call make-unit-test,test_reedsol,test_reedsol,fd_ballet fd_util)
