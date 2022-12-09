$(call add-hdrs,fd_bmtree.h)
$(call add-objs,fd_bmtree,fd_ballet)

$(call make-unit-test,test_bmtree20,test_bmtree20,fd_ballet fd_util)
$(call make-unit-test,test_bmtree32,test_bmtree32,fd_ballet fd_util)
