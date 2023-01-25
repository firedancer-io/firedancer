# Note: This probably needs to after machine specific targets otherwise
# the -fomit-frame-pointer that occurs there will be silently override
# the -fno-omit-frame-pointer here.
#
# FIXME: CONSIDER MANUALLY SETTING FD_HAS_ASAN IN BOTH THE CPPFLAGS AND
# IN THE MAKE ENVIRONMENT?

CPPFLAGS+=-fsanitize=address -fno-omit-frame-pointer
LDFLAGS+=-fsanitize=address
