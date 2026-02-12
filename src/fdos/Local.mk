ifdef FD_HAS_LINUX
ifneq ($(wildcard $(BASEDIR)/fdos/kern/x86_64/bin/fdos_kern.elf),)

$(call make-lib,fdos_host)
$(call add-objs,host/fdos_env host/fdos_kern_img host/fdos_kvm,fdos_host)
ifdef FD_HAS_LIBLLVM
$(call add-objs,x86/fd_x86_disasm,fdos_host)
endif
$(call make-bin,test_fdos,test_fdos,fdos_host fd_util)

$(OBJDIR)/obj/fdos/test_fdos.o: $(BASEDIR)/fdos/kern/x86_64/bin/fdos_kern.elf
.PHONY: $(BASEDIR)/fdos/kern/x86_64/bin/fdos_kern.elf
$(BASEDIR)/fdos/kern/x86_64/bin/fdos_kern.elf:
	$(MAKE) MACHINE=fdos_kern_x86 $@

endif
endif
