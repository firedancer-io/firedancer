
$(call make-lib,fd_sol_tests)
$(call add-objs,$(patsubst src/runtime-tests/%.c,%,$(wildcard src/runtime-tests/1/2/generated/*.c)),fd_sol_tests)
