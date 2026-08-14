$(call add-asms,fd_gdb_scripts,fdctl_shared)
$(OBJDIR)/obj/app/shared/gdb/fd_gdb_scripts.o: src/app/shared/gdb/fd_base58_gdb.py

$(call make-unit-test,test_gdb_base58,test_gdb_base58 fd_gdb_scripts,fd_util)
$(call add-test-scripts,test_gdb_base58.sh)
