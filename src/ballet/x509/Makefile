SESSION:=frama-c-rte-eva-then-wp.session
JOBS:=$(shell nproc)
TIMEOUT:=30

.PHONY:
frama-c:
	frama-c \
		fd_x509_common.c \
		fd_x509_cert_parser.c \
		fd_x509_framac.c \
		-machdep x86_64 \
		-pp-annot \
		-warn-left-shift-negative \
		-warn-right-shift-negative \
		-warn-signed-downcast \
		-warn-signed-overflow \
		-warn-unsigned-downcast \
		-warn-unsigned-overflow \
		-rte \
		-then \
		-eva \
		-wp-dynamic -eva-slevel 1 \
		-eva-warn-undefined-pointer-comparison none \
		-then -wp -wp-steps 100000 \
		-wp-dynamic \
		-wp-no-init-const \
		-wp-par $(JOBS) \
		-wp-timeout $(TIMEOUT) -save $(SESSION)
