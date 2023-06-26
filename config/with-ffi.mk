# -Wno-pedantic is needed because bindgen::wrap_static_fns spits out code that
# triggers a warning.
CPPFLAGS+=-DFD_HAS_FFI=1 -fPIC -flto=thin -Wno-pedantic
