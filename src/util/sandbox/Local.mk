$(call add-hdrs,fd_sandbox.h fd_sandbox_util_private.h)

# Linux Sandbox
ifeq "$(FD_HAS_SANDBOX_LINUX)" "1"
  $(call add-objs,fd_sandbox_linux,fd_util)
  $(call make-unit-test,test_sandbox_linux,test_sandbox_linux,fd_util)
  $(call run-unit-test,test_sandbox_linux,)
else ifeq "$(FD_HAS_SANDBOX_UNSUPPORTED)" "1"
  $(call add-objs,fd_sandbox_unsupported,fd_util)
else
  $(error There is noo sandbox specified for your target. Ensure your configuration includes the appropriate `with-sandbox-*`)
endif 
