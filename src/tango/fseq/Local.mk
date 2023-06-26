$(call add-hdrs,fd_fseq.h)
$(call add-objs,fd_fseq,fd_tango)
$(call make-unit-test,test_fseq,test_fseq,fd_tango fd_util)
$(call run-unit-test,test_fseq,)

