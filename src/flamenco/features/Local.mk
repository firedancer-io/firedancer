$(call add-hdrs,fd_features.h fd_features_generated.h)
$(call add-objs,fd_features fd_features_generated,fd_flamenco)
$(call make-unit-test,test_features,test_features,fd_flamenco fd_funk fd_ballet fd_util)
