# Note: This needs to happen after machine specific targets otherwise
# the -fomit-frame-pointer that occurs there will be silently override
# the -fno-omit-frame-pointer here.
CPPFLAGS+=-fsanitize=address -fno-omit-frame-pointer
LDFLAGS+=-fsanitize=address
