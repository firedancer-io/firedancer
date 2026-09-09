$(call add-hdrs,fd_alpenglow.h fd_block_marker.h fd_block_marker_serde.h)
$(call add-objs,fd_alpenglow fd_block_marker fd_block_marker_serde,fd_flamenco)
$(call make-unit-test,test_block_marker,test_block_marker,fd_flamenco fd_choreo fd_ballet fd_util)
$(call run-unit-test,test_block_marker)
