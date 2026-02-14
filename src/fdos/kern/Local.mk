ifdef FD_FDOS_KERN
$(OBJDIR)/bin/fdos_kern.elf: src/fdos/kern/fdos_kern.ld $(OBJDIR)/obj/fdos/kern/fdos_kern.o $(OBJDIR)/lib/libfd_util.a
	mkdir -p $(dir $@) && \
    ld.lld \
	--no-undefined \
	--no-dynamic-linker \
	--static \
	-T src/fdos/kern/fdos_kern.ld \
	-o $@ \
	$(OBJDIR)/obj/fdos/kern/fdos_kern.o \
	$(OBJDIR)/lib/libfd_util.a \
	$(OPT)/cross/x86/lib/libc.a \
	$(OPT)/cross/x86/lib/libnosys.a
endif
