import cpp

/**
 * An object-like macro that can stand in for a named constant.
 */
class ConstantMacro extends Macro {
  ConstantMacro() { not this.getHead().matches("%(%") }
}

/**
 * A return statement that yields a literal value.
 */
class LiteralReturn extends ReturnStmt {
  LiteralReturn() { this.hasExpr() and this.getExpr().getUnconverted() instanceof Literal }
}

/**
 * A return statement that yields a named constant macro.
 */
class MacroReturn extends ReturnStmt {
  MacroReturn() {
    this.hasExpr() and
    this.getExpr().getUnconverted().findRootCause() instanceof ConstantMacro
  }
}

/**
 * A return statement that yields a simple constant value, either as a literal
 * or through a constant-like macro.
 */
class ConstantReturn extends ReturnStmt {
  ConstantReturn() { this instanceof LiteralReturn or this instanceof MacroReturn }
}
