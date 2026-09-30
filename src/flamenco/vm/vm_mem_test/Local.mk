
$(call add-objs,fd_vm_mem_test,)


$(OBJDIR)/lib/libfd_vm_mem_test.a: $(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)fd_vm_mem_test_rewritten.o)

$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)fd_vm_mem_test_rewritten.o): $(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)fd_vm_mem_test.o)
	python3 $(abspath $(patsubst $(OBJDIR)/obj/%,src/%,$<)/..)/patch_vm_test.py $< $@

