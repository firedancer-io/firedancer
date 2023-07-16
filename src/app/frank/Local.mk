ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_X86
$(call add-hdrs,fd_frank.h)
$(call add-objs,fd_frank_run fd_frank_mon fd_frank_verify fd_frank_mon fd_frank_dedup fd_frank_quic fd_frank_pack,fd_frank)
endif
endif
endif
