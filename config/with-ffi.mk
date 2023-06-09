# -Wno-pedantic is needed because bindgen::wrap_static_fns spits out code that
# triggers a warning.
CPPFLAGS+=-fPIC -flto=thin -Wno-pedantic
