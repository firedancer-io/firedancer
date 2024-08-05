$(call add-hdrs,fd_trusted_slots.h)
$(call add-objs,fd_trusted_slots,fd_choreo)
$(call make-unit-test,test_trusted_slots,test_trusted_slots,fd_choreo fd_util)
