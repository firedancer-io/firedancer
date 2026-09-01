$(call add-hdrs,fd_stake_types.h)
ifdef FD_HAS_DOUBLE
$(call add-hdrs,fd_stakes.h)
$(call add-objs,fd_stakes,fd_flamenco)
endif

$(call add-hdrs,fd_vote_stakes.h)
$(call add-objs,fd_vote_stakes,fd_flamenco)

$(call add-hdrs,fd_epoch_stakes_digest.h)
$(call add-objs,fd_epoch_stakes_digest,fd_flamenco)

$(call add-hdrs,fd_stake_delegations.h)
$(call add-objs,fd_stake_delegations,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_stake_delegations,test_stake_delegations,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_stake_delegations)
ifdef FD_HAS_DOUBLE
$(call make-unit-test,test_warmup_cooldown_allowance,test_warmup_cooldown_allowance,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_warmup_cooldown_allowance)
endif
endif

$(call add-hdrs,fd_collector_overrides.h)
$(call add-objs,fd_collector_overrides,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_vote_stakes,test_vote_stakes,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_vote_stakes)
$(call make-unit-test,test_epoch_stakes_digest,test_epoch_stakes_digest,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_epoch_stakes_digest)
$(call make-unit-test,test_collector_overrides,test_collector_overrides,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_collector_overrides)
endif
