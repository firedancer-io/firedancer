.PHONY: all
all:
	@make -C ../../..

.PHONY: clean
clean:
	@make -C ../../.. clean

.PHONY: stubs
stubs: fd_types.json
	python3 gen_stubs.py fd_types.h fd_types.c fd_type_names.c
