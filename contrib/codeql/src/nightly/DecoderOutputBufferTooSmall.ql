/**
 * @name Decoder output buffer too small
 * @description Finds decoder calls where the output argument is a
 *              fixed-size array smaller than the decoder's maximum
 *              documented write size.
 * @kind problem
 * @id asymmetric-research/decoder-output-buffer-too-small
 * @problem.severity warning
 * @precision high
 * @tags reliability
 *       security
 *       external/cwe/cwe-121
 */

import cpp
import filter

private predicate constantIntegralValue(Expr e, int value) {
  value = e.getValue().toInt()
}

private predicate fdBase64DecodedMax(Expr encodedSz, int decodedMax) {
  exists(int n |
    constantIntegralValue(encodedSz, n) and
    n >= 0 and
    decodedMax = ((n + 3) / 4) * 3
  )
}

private predicate arrayByteSize(ArrayType arrayType, int bytes) {
  bytes = arrayType.getArraySize() * arrayType.getBaseType().getSize()
}

private predicate outputBufferByteSize(Expr output, int bytes) {
  exists(ArrayType arrayType |
    arrayType = output.getType().getUnspecifiedType() and
    arrayByteSize(arrayType, bytes)
  )
  or
  exists(AddressOfExpr addressOf, ArrayType arrayType |
    output = addressOf and
    arrayType = addressOf.getOperand().getType().getUnspecifiedType() and
    arrayByteSize(arrayType, bytes)
  )
}

abstract class DecoderCall extends FunctionCall {
  abstract Expr getOutputArgument();
  abstract int getRequiredOutputBytes();
}

class Base64DecoderCall extends DecoderCall {
  Base64DecoderCall() {
    this.getTarget().hasName("fd_base64_decode") and
    this.getNumberOfArguments() = 3
  }

  override Expr getOutputArgument() { result = this.getArgument(0) }

  override int getRequiredOutputBytes() {
    fdBase64DecodedMax(this.getArgument(2), result)
  }
}

class FixedSizeBase58DecoderCall extends DecoderCall {
  FixedSizeBase58DecoderCall() {
    this.getTarget().hasName(["fd_base58_decode_32", "fd_base58_decode_64"]) and
    this.getNumberOfArguments() = 2
  }

  override Expr getOutputArgument() { result = this.getArgument(1) }

  override int getRequiredOutputBytes() {
    (
      this.getTarget().hasName("fd_base58_decode_32") and result = 32
    )
    or
    (
      this.getTarget().hasName("fd_base58_decode_64") and result = 64
    )
  }
}

from DecoderCall call, int outputBytes, int requiredBytes
where
  outputBufferByteSize(call.getOutputArgument(), outputBytes) and
  requiredBytes = call.getRequiredOutputBytes() and
  outputBytes < requiredBytes and
  included(call.getLocation())
select call.getOutputArgument(),
  "The output buffer is " + outputBytes + " bytes, but $@ can write up to " +
    requiredBytes + " bytes.",
  call.getTarget(), call.getTarget().getName()
