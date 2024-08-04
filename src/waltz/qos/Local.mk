$(call make-lib,fd_qos)
$(call add-objs,fd_qos fd_qos_local fd_qos_entry,fd_qos)
$(call make-unit-test,test_qos,test_qos,fd_qos fd_tls fd_ballet fd_waltz fd_util)
$(call make-unit-test,test_qos_vm,test_qos_vm,fd_qos fd_tls fd_ballet fd_waltz fd_util)
