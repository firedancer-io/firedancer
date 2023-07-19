ifneq ($(FD_HAS_SECP256K1),)

$(call add-hdrs,fd_secp256k1.h)
$(call add-objs,fd_secp256k1,fd_ballet)

else

$(warning secp256k1 disabled due to lack of libsecp256k1)

endif
