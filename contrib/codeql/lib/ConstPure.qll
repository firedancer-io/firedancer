import cpp

/**
 * Holds if `f` is attributed with `const`.
 */
predicate isConstFunction(Function f) {
  f.getAnAttribute().getName() = "const"
}

/**
 * Holds if `f` is attributed with `pure`.
 */
predicate isPureFunction(Function f) {
  f.getAnAttribute().getName() = "pure"
}

/**
 * Holds if `f` is attributed with either `const` or `pure`.
 */
predicate isConstOrPureFunction(Function f) {
  isConstFunction(f) or
  isPureFunction(f)
}

/**
 * A function attributed with `const`.
 */
class ConstFunction extends Function {
  ConstFunction() { isConstFunction(this) }
}

/**
 * A function attributed with `pure`.
 */
class PureFunction extends Function {
  PureFunction() { isPureFunction(this) }
}

/**
 * A function attributed with either `const` or `pure`.
 */
class ConstOrPureFunction extends Function {
  ConstOrPureFunction() {
    this instanceof ConstFunction or
    this instanceof PureFunction
  }
}
