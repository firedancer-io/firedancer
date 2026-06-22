# QUIC core library
$(call add-hdrs,fd_slow_base.h)

# QUIC cryptography
$(call add-hdrs,fd_slow_crypto.h fd_slow_key.h)
$(call add-objs,fd_slow_crypto fd_slow_key,fd_waltz)

# timer wheel
$(call add-hdrs,fd_wheel.h)
$(call add-objs,fd_wheel,fd_waltz)
$(call make-unit-test,test_wheel,test_wheel,fd_waltz fd_util)
$(call run-unit-test,test_wheel)
