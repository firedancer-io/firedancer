$(call add-hdrs,fd_authorized_voters.h)
$(call add-objs,fd_authorized_voters,fd_flamenco)

$(call add-hdrs,fd_vote_common.h)
$(call add-objs,fd_vote_common,fd_flamenco)

$(call add-hdrs,fd_vote_lockout.h)
$(call add-objs,fd_vote_lockout,fd_flamenco)

$(call add-hdrs,fd_vote_state_versioned.h)
$(call add-objs,fd_vote_state_versioned,fd_flamenco)

$(call add-hdrs,fd_vote_state_v3.h)
$(call add-objs,fd_vote_state_v3,fd_flamenco)

$(call add-hdrs,fd_vote_state_v4.h)
$(call add-objs,fd_vote_state_v4,fd_flamenco)
