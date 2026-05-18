$(call add-hdrs,fd_vote_codec.h)
$(call add-objs,fd_vote_codec,fd_flamenco)

$(call add-hdrs,fd_authorized_voters.h)
$(call add-objs,fd_authorized_voters,fd_flamenco)

$(call add-hdrs,fd_vote_utils.h)
$(call add-objs,fd_vote_utils,fd_flamenco)

$(call add-hdrs,fd_vote_state_versioned.h)
$(call add-objs,fd_vote_state_versioned,fd_flamenco)

$(call add-hdrs,fd_vote_state_v3.h)
$(call add-objs,fd_vote_state_v3,fd_flamenco)

$(call add-hdrs,fd_vote_state_v4.h)
$(call add-objs,fd_vote_state_v4,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_vote_codec,fuzz_vote_codec,fd_flamenco fd_ballet fd_util)
$(call run-fuzz-test,fuzz_vote_codec)
endif
