ifdef FD_HAS_INT128
$(call add-hdrs,fd_stakes.h fd_stake_program.h)
$(call add-objs,fd_stakes fd_stake_program,fd_flamenco)
# TODO this should not depend on fd_funk
$(call make-bin,fd_stakes_from_snapshot,fd_stakes_from_snapshot,fd_flamenco fd_funk fd_ballet fd_util)
endif
