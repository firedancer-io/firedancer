ifdef FD_HAS_INT128
$(call add-hdrs,fd_stakes.h)
$(call add-objs,fd_stakes,fd_flamenco)

$(call add-hdrs,fd_stake_delegations.h)
$(call add-objs,fd_stake_delegations,fd_flamenco)
$(call make-unit-test,test_stake_delegations,test_stake_delegations,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_stake_delegations)

# TODO this should not depend on fd_funk
ifdef FD_HAS_HOSTED
$(call make-bin,fd_stakes_from_snapshot,fd_stakes_from_snapshot,fd_flamenco fd_funk fd_ballet fd_util)
endif
endif
