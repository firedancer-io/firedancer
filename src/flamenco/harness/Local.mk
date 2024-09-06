$(call add-hdrs,../runtime/tests/generated/exec_v2.pb.h,t../runtime/ests/generated/slot_v2.pb.h,../runtime/tests/generated/txn_v2.pb.h,../runtime/tests/generated/instr_v2.pb.h)
$(call add-objs,../runtime/tests/generated/exec_v2.pb ../runtime/tests/generated/slot_v2.pb ../runtime/tests/generated/txn_v2.pb ../runtime/tests/generated/instr_v2.pb,fd_flamenco)

$(call add-hdrs,fd_harness.h)
$(call add-objs,fd_harness_instr,fd_flamenco)
$(call add-objs,fd_harness_txn,fd_flamenco)
$(call add-objs,fd_harness_slot,fd_flamenco)
$(call add-objs,fd_harness_runtime,fd_flamenco)
$(call make-bin,fd_harness_tool,fd_harness_tool,fd_flamenco fd_ballet fd_util fd_funk)
