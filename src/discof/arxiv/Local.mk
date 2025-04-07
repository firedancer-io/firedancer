ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_shred_arxiv fd_arxiv_tile,fd_discof)
$(call make-unit-test,test_arxiv,test_arxiv,fd_discof fd_flamenco fd_ballet fd_util)
endif
endif
