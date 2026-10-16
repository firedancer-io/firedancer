$(call add-hdrs,fd_validator_location.h)
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

$(call add-hdrs,fd_vote_state_v5.h)
$(call add-objs,fd_vote_state_v5,fd_flamenco)

$(call make-unit-test,test_vote_codec,test_vote_codec,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_vote_codec)

$(call make-unit-test,test_vote_state_v5,test_vote_state_v5,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_vote_state_v5)

$(call make-unit-test,test_validator_location,test_validator_location,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_validator_location)
