$(call add-hdrs,fd_txn_generate.h)
$(call add-objs,fd_txn_generate,fd_txn_generate)
.PHONY: fd_txn_generate

fd_txn_generate: $(OBJDIR)/bin/fd_txn_generate
