$(call add-hdrs,fd_crds.h)
$(call add-objs,fd_crds,fd_flamenco)

$(call make-unit-test,test_crds,test_crds,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_crds)
