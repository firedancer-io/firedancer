$(call add-hdrs,fd_stakes.h)
$(call add-objs,fd_stakes,fd_flamenco)

$(call add-hdrs,fd_stake_delegations.h)
$(call add-objs,fd_stake_delegations,fd_flamenco)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_stake_delegations,test_stake_delegations,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_stake_delegations)
endif
endif

$(call add-hdrs,fd_vote_states.h)
$(call add-objs,fd_vote_states,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_vote_states,test_vote_states,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_vote_states)
endif
