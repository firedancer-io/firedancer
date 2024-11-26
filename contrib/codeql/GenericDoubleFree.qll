import cpp
import semmle.code.cpp.dataflow.new.DataFlow

bindingset[x]
signature string regcap(string x);

class CandidateCall extends Call {
  CandidateCall() {
    not (
      this.getLocation().getFile().getBaseName().matches("test%") or
      this.getLocation().getFile().getBaseName().matches("%_ci.%") or
      this.getLocation().getFile().getBaseName() = "main.c" /* annoying mismatch with funk_init */
    )
  }
}

module DoubleFreeConfig<regcap/1 doubleMatch, regcap/1 barrierMatch> implements
  DataFlow::StateConfigSig
{
  class FlowState = string;

  predicate isSource(DataFlow::Node source, DataFlow::FlowState state) {
    exists(CandidateCall call |
      source.asIndirectArgument() = call.getArgument(0) and
      state = doubleMatch(call.getTarget().getName())
    )
  }

  predicate isBarrier(DataFlow::Node barrier, DataFlow::FlowState state) {
    exists(CandidateCall call |
      barrier.asIndirectArgument() = call.getArgument(0) and
      state = barrierMatch(call.getTarget().getName())
    )
  }

  predicate isSink(DataFlow::Node sink, DataFlow::FlowState state) {
    exists(CandidateCall call |
      sink.asIndirectArgument() = call.getArgument(0) and
      state = doubleMatch(call.getTarget().getName())
    )
  }
}
