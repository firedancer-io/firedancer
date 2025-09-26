/**
 * @name Metrics Enum Access Issue
 * @id asymmetric-research/metrics-enum-access
 * @description Finds issues with FD_METRICS_ENUM_%_CNT and FD_METRICS_ENUM_%_IDX macros used for array accesses.
 * @kind problem
 * @severity warning
 * @precision high
 */

import cpp


bindingset[s]
int getValue(string s) {
    result = s.regexpCapture(".*?([0-9]+).*", 1).toInt()
}

predicate defMacro(Variable f, MacroAccess m) {
    m.getMacroName().matches("FD_METRICS_ENUM_%_CNT") and
    f.getLocation().getStartLine() = m.getLocation().getStartLine() and
    f.getLocation().getFile() = m.getLocation().getFile()
}

class MetricsEnumArray extends Variable {
    MetricsEnumArray() {
        this.getType() instanceof ArrayType and
        defMacro(this, _)
    }

    MacroAccess getMacroAccess() {
        defMacro(this, result)
    }

    ArrayExpr getAUsage() {
        this.getAnAccess() = result.getAChild()
    }
}

predicate accMacro(ArrayExpr a, MacroAccess m) {
    m.getMacroName().matches("FD_METRICS_ENUM_%_IDX") and
    inmacroexpansion(a.getArrayOffset(), m)
}

class MetricsEnumAccess extends ArrayExpr {
    MetricsEnumAccess() {
        accMacro(this, _)
    }

    MacroAccess getMacroAccess() {
        accMacro(this, result)
    }
}

Macro idxToCnt(Macro idxMacro) {
    result.hasName(idxMacro.getName().regexpReplaceAll("_V_.*", "_CNT"))
}

predicate matchLiteralDef(MetricsEnumAccess a) {
    getValue(idxToCnt(a.getMacroAccess().getMacro()).getBody()) != a.getArrayBase().getType().(ArrayType).getArraySize()
}

ArrayExpr matchLiteralAccess(MetricsEnumArray e) {
    result = e.getAUsage() and
    getValue(e.getMacroAccess().getMacro().getBody()) <= getValue(result.getArrayOffset().getValue())
}

predicate matchMetricType(MetricsEnumAccess a, MetricsEnumArray e) {
    e.getAUsage() = a and
    idxToCnt(a.getMacroAccess().getMacro()) != e.getMacroAccess().getMacro()
}


from Element res, MetricsEnumAccess a, MetricsEnumArray e, string des
where
    res = matchLiteralAccess(e) and des = "literal access greater than the arrays size" or
    res = a and matchLiteralDef(a) and des = "literal array definition size differing from the metrics cnt" or
    res = e and matchMetricType(a, e) and des = "metrics idx and count types do not match"
select res, des

