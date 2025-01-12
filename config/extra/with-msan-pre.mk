# MemorySanitizer requires all dependencies to be recompiled with
# -fsanitize=memory.  Run ./deps.sh +msan to create opt-msan.
OPT:=opt-msan
LIBCXX:=$(OPT)
