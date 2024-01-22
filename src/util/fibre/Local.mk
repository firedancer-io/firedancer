$(call make-lib,fd_fibre)
$(call add-objs,fd_fibre,fd_fibre)

$(call make-unit-test,test_fibre,test_fibre,fd_fibre fd_util)

