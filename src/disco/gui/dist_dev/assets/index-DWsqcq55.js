import { r as os, a as m, v as Ht, b as Fi, u as as, R as ss, y as Xe, I as ls, p as us, t as ds, g as cs, c as fs, j as d, i as hs, L as on, k as Ue, d as Pe, e as ee, _ as Di, f as Hi, h as cr, l as fr, P as Gt, m as x, s as et, n as tt, o as nt, q as rt, w as it, x as ot, z as at, A as st, B as lt, C as ut, D as dt, E as ct, F as ft, G as ht, H as pt, J as gt, K as vt, M as mt, N as bt, O as yt, Q as xt, S as _t, T as wt, U as Ct, V as kt, W as zt, X as jt, Y as Ot, Z as gn, $ as hr, a0 as pr, a1 as gr, a2 as vr, a3 as mr, a4 as br, a5 as yr, a6 as xr, a7 as _r, a8 as wr, a9 as Cr, aa as kr, ab as zr, ac as jr, ad as $r, ae as Lr, af as Rr, ag as Mr, ah as Sr, ai as On, aj as Gi, ak as Ui, al as Yi, am as qi, an as Vi, ao as Xi, ap as Ki, aq as Zi, ar as Ji, as as Qi, at as eo, au as to, av as no, aw as ro, ax as io, ay as oo, az as ao, aA as so, aB as lo, aC as uo, aD as co, aE as fo, aF as ho, aG as po, aH as go, aI as vo, aJ as mo, aK as bo, aL as yo, aM as xo, aN as _o, aO as wo, aP as Co, aQ as ko, aR as zo, aS as jo, aT as $o, aU as Lo, aV as Ro, aW as Mo, aX as So, aY as Oo, aZ as Eo, a_ as Wo, a$ as To, b0 as No, b1 as Po, b2 as Ao, b3 as ps, b4 as Io, b5 as gs, b6 as vs, b7 as Bo, b8 as ms, b9 as Fo, ba as Or, bb as bs, bc as ys, bd as Do, be as xs, bf as Ho, bg as En, bh as _s, bi as ws, bj as Cs, bk as Go, bl as ks, bm as zs, bn as js, bo as $s, bp as Ls, bq as Rs, br as Ms, bs as Ss, bt as Ke, bu as Er, bv as Je, bw as vn, bx as Os, by as Es, bz as _n, bA as He, bB as De, bC as Uo, bD as Ws, bE as Ts, bF as Wr, bG as Ns, bH as Ps, bI as As, bJ as Is, bK as Bs, bL as Fs, bM as Ds, bN as Hs, bO as Gs, bP as Us, bQ as Ys, bR as qs } from "./index-9FuZN4Z6.js";
const Vs = ["1", "2", "3"], Xs = ["surface", "classic"], Ks = { disabled: { type: "boolean", className: "disabled", default: false }, size: { type: "enum", className: "rt-r-size", values: Vs, default: "2", responsive: true }, variant: { type: "enum", className: "rt-variant", values: Xs, default: "surface" }, ...os }, Yo = m.forwardRef((e2, t) => {
  const { className: n, children: r, radius: i, value: a, defaultValue: o, onValueChange: s, ...c } = Ht(e2, Ks, Fi), [u, p] = as({ prop: a, onChange: s, defaultProp: o });
  return m.createElement(ss, { "data-disabled": e2.disabled || void 0, "data-radius": i, ref: t, className: Xe("rt-SegmentedControlRoot", n), onValueChange: (f) => {
    f && p(f);
  }, ...c, type: "single", value: u, asChild: false, disabled: !!e2.disabled }, r, m.createElement("div", { className: "rt-SegmentedControlIndicator" }));
});
Yo.displayName = "SegmentedControl.Root";
const wn = m.forwardRef(({ children: e2, className: t, ...n }, r) => m.createElement(ls, { ref: r, className: Xe("rt-reset", "rt-SegmentedControlItem", t), ...n, disabled: false, asChild: false }, m.createElement("span", { className: "rt-SegmentedControlItemSeparator" }), m.createElement("span", { className: "rt-SegmentedControlItemLabel" }, m.createElement("span", { className: "rt-SegmentedControlItemLabelActive" }, e2), m.createElement("span", { className: "rt-SegmentedControlItemLabelInactive", "aria-hidden": true }, e2))));
wn.displayName = "SegmentedControl.Item";
const Zs = ["1", "2", "3"], Js = ["surface", "ghost"], Qs = ["auto", "fixed"], Pn = { size: { type: "enum", className: "rt-r-size", values: Zs, default: "2", responsive: true }, variant: { type: "enum", className: "rt-variant", values: Js, default: "ghost" }, layout: { type: "enum", className: "rt-r-tl", values: Qs, responsive: true } }, el = ["start", "center", "end", "baseline"], tl = { align: { type: "enum", className: "rt-r-va", values: el, parseValue: nl, responsive: true } };
function nl(e2) {
  return { baseline: "baseline", start: "top", center: "middle", end: "bottom" }[e2];
}
const rl = ["start", "center", "end"], Tr = { justify: { type: "enum", className: "rt-r-ta", values: rl, parseValue: il, responsive: true }, ...ds, ...us };
function il(e2) {
  return { start: "left", center: "center", end: "right" }[e2];
}
const Nr = m.forwardRef((e2, t) => {
  const { layout: n, ...r } = Pn, { className: i, children: a, layout: o, ...s } = Ht(e2, r, Fi), c = cs({ value: o, className: Pn.layout.className, propValues: Pn.layout.values });
  return m.createElement("div", { ref: t, className: Xe("rt-TableRoot", i), ...s }, m.createElement(fs, null, m.createElement("table", { className: Xe("rt-TableRootTable", c) }, a)));
});
Nr.displayName = "Table.Root";
const Pr = m.forwardRef(({ className: e2, ...t }, n) => m.createElement("thead", { ...t, ref: n, className: Xe("rt-TableHeader", e2) }));
Pr.displayName = "Table.Header";
const Ar = m.forwardRef(({ className: e2, ...t }, n) => m.createElement("tbody", { ...t, ref: n, className: Xe("rt-TableBody", e2) }));
Ar.displayName = "Table.Body";
const dn = m.forwardRef((e2, t) => {
  const { className: n, ...r } = Ht(e2, tl);
  return m.createElement("tr", { ...r, ref: t, className: Xe("rt-TableRow", n) });
});
dn.displayName = "Table.Row";
const Ir = m.forwardRef((e2, t) => {
  const { className: n, ...r } = Ht(e2, Tr);
  return m.createElement("td", { className: Xe("rt-TableCell", n), ref: t, ...r });
});
Ir.displayName = "Table.Cell";
const qe = m.forwardRef((e2, t) => {
  const { className: n, ...r } = Ht(e2, Tr);
  return m.createElement("th", { className: Xe("rt-TableCell", "rt-TableColumnHeaderCell", n), scope: "col", ref: t, ...r });
});
qe.displayName = "Table.ColumnHeaderCell";
const Br = m.forwardRef((e2, t) => {
  const { className: n, ...r } = Ht(e2, Tr);
  return m.createElement("th", { className: Xe("rt-TableCell", "rt-TableRowHeaderCell", n), scope: "row", ref: t, ...r });
});
Br.displayName = "Table.RowHeaderCell";
function ol() {
  var e2 = m.useRef(true);
  return e2.current ? (e2.current = false, true) : e2.current;
}
var al = function(e2, t) {
  return e2 === t;
};
function sl(e2, t) {
  t === void 0 && (t = al);
  var n = m.useRef(), r = m.useRef(e2), i = ol();
  return !i && !t(r.current, e2) && (n.current = r.current, r.current = e2), n.current;
}
function Yn() {
  return Yn = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Yn.apply(null, arguments);
}
function ll(e2, t) {
  if (e2 == null) return {};
  var n = {};
  for (var r in e2) if ({}.hasOwnProperty.call(e2, r)) {
    if (t.indexOf(r) !== -1) continue;
    n[r] = e2[r];
  }
  return n;
}
var ul = ["outlineWidth", "outlineColor", "outlineOpacity"], Fr = function(e2) {
  return e2.outlineWidth, e2.outlineColor, e2.outlineOpacity, ll(e2, ul);
}, dl = ["axis.ticks.text", "axis.legend.text", "legends.title.text", "legends.text", "legends.ticks.text", "legends.title.text", "labels.text", "dots.text", "markers.text", "annotations.text"], cl = function(e2, t) {
  return Yn({}, t, e2);
}, fl = function(e2, t) {
  var n = hs({}, e2, t);
  return dl.forEach(function(r) {
    on(n, r, cl(Ue(n, r), n.text));
  }), n;
}, hl = { background: "transparent", text: { fontFamily: "sans-serif", fontSize: 11, fill: "#333333", outlineWidth: 0, outlineColor: "#ffffff", outlineOpacity: 1 }, axis: { domain: { line: { stroke: "transparent", strokeWidth: 1 } }, ticks: { line: { stroke: "#777777", strokeWidth: 1 }, text: {} }, legend: { text: { fontSize: 12 } } }, grid: { line: { stroke: "#dddddd", strokeWidth: 1 } }, legends: { hidden: { symbol: { fill: "#333333", opacity: 0.6 }, text: { fill: "#333333", opacity: 0.6 } }, text: {}, ticks: { line: { stroke: "#777777", strokeWidth: 1 }, text: { fontSize: 10 } }, title: { text: {} } }, labels: { text: {} }, markers: { lineColor: "#000000", lineStrokeWidth: 1, text: {} }, dots: { text: {} }, tooltip: { container: { background: "white", color: "inherit", fontSize: "inherit", borderRadius: "2px", boxShadow: "0 1px 2px rgba(0, 0, 0, 0.25)", padding: "5px 9px" }, basic: { whiteSpace: "pre", display: "flex", alignItems: "center" }, chip: { marginRight: 7 }, table: {}, tableCell: { padding: "3px 5px" }, tableCellValue: { fontWeight: "bold" } }, crosshair: { line: { stroke: "#000000", strokeWidth: 1, strokeOpacity: 0.75, strokeDasharray: "6 6" } }, annotations: { text: { fontSize: 13, outlineWidth: 2, outlineColor: "#ffffff", outlineOpacity: 1 }, link: { stroke: "#000000", strokeWidth: 1, outlineWidth: 2, outlineColor: "#ffffff", outlineOpacity: 1 }, outline: { fill: "none", stroke: "#000000", strokeWidth: 2, outlineWidth: 2, outlineColor: "#ffffff", outlineOpacity: 1 }, symbol: { fill: "#000000", outlineWidth: 2, outlineColor: "#ffffff", outlineOpacity: 1 } } }, pl = function(e2) {
  return m.useMemo(function() {
    return fl(hl, e2);
  }, [e2]);
}, qo = m.createContext(null), gl = {}, Vo = function(e2) {
  var t = e2.theme, n = t === void 0 ? gl : t, r = e2.children, i = pl(n);
  return d.jsx(qo.Provider, { value: i, children: r });
}, X = function() {
  var e2 = m.useContext(qo);
  if (e2 === null) throw new Error("Unable to find the theme, did you forget to wrap your component with ThemeProvider?");
  return e2;
};
function Et() {
  return Et = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Et.apply(null, arguments);
}
var vl = ["basic", "chip", "container", "table", "tableCell", "tableCellValue"], ml = { pointerEvents: "none", position: "absolute", zIndex: 10, top: 0, left: 0 }, ti = function(e2, t) {
  return "translate(" + e2 + "px, " + t + "px)";
}, Xo = m.memo(function(e2) {
  var t, n = e2.position, r = e2.anchor, i = e2.children, a = X(), o = mn(), s = o.animate, c = o.config, u = Xl(), p = u[0], f = u[1], l = m.useRef(false), g = void 0, y = false, v = f.width > 0 && f.height > 0, h = Math.round(n[0]), b = Math.round(n[1]);
  v && (r === "top" ? (h -= f.width / 2, b -= f.height + 14) : r === "right" ? (h += 14, b -= f.height / 2) : r === "bottom" ? (h -= f.width / 2, b += 14) : r === "left" ? (h -= f.width + 14, b -= f.height / 2) : r === "center" && (h -= f.width / 2, b -= f.height / 2), g = { transform: ti(h, b) }, l.current || (y = true), l.current = [h, b]);
  var _ = Pe({ to: g, config: c, immediate: !s || y }), w = a.tooltip;
  w.basic, w.chip, w.container, w.table, w.tableCell, w.tableCellValue;
  var C = function($, R) {
    if ($ == null) return {};
    var k = {};
    for (var j in $) if ({}.hasOwnProperty.call($, j)) {
      if (R.indexOf(j) !== -1) continue;
      k[j] = $[j];
    }
    return k;
  }(w, vl), z = Et({}, ml, C, { transform: (t = _.transform) != null ? t : ti(h, b), opacity: _.transform ? 1 : 0 });
  return d.jsx(ee.div, { ref: p, style: z, children: i });
});
Xo.displayName = "TooltipWrapper";
var bl = m.memo(function(e2) {
  var t = e2.size, n = t === void 0 ? 12 : t, r = e2.color, i = e2.style;
  return d.jsx("span", { style: Et({ display: "block", width: n, height: n, background: r }, i === void 0 ? {} : i) });
}), yl = m.memo(function(e2) {
  var t, n = e2.id, r = e2.value, i = e2.format, a = e2.enableChip, o = a !== void 0 && a, s = e2.color, c = e2.renderContent, u = X(), p = Zl(i);
  if (typeof c == "function") t = c();
  else {
    var f = r;
    p !== void 0 && f !== void 0 && (f = p(f)), t = d.jsxs("div", { style: u.tooltip.basic, children: [o && d.jsx(bl, { color: s, style: u.tooltip.chip }), f !== void 0 ? d.jsxs("span", { children: [n, ": ", d.jsx("strong", { children: "" + f })] }) : n] });
  }
  return d.jsx("div", { style: u.tooltip.container, role: "tooltip", children: t });
}), xl = { width: "100%", borderCollapse: "collapse" }, _l = m.memo(function(e2) {
  var t, n = e2.title, r = e2.rows, i = r === void 0 ? [] : r, a = e2.renderContent, o = X();
  return i.length ? (t = typeof a == "function" ? a() : d.jsxs("div", { children: [n && n, d.jsx("table", { style: Et({}, xl, o.tooltip.table), children: d.jsx("tbody", { children: i.map(function(s, c) {
    return d.jsx("tr", { children: s.map(function(u, p) {
      return d.jsx("td", { style: o.tooltip.tableCell, children: u }, p);
    }) }, c);
  }) }) })] }), d.jsx("div", { style: o.tooltip.container, children: t })) : null;
});
_l.displayName = "TableTooltip";
var qn = m.memo(function(e2) {
  var t = e2.x0, n = e2.x1, r = e2.y0, i = e2.y1, a = X(), o = mn(), s = o.animate, c = o.config, u = m.useMemo(function() {
    return Et({}, a.crosshair.line, { pointerEvents: "none" });
  }, [a.crosshair.line]), p = Pe({ x1: t, x2: n, y1: r, y2: i, config: c, immediate: !s });
  return d.jsx(ee.line, Et({}, p, { fill: "none", style: u }));
});
qn.displayName = "CrosshairLine";
var wl = m.memo(function(e2) {
  var t, n, r = e2.width, i = e2.height, a = e2.type, o = e2.x, s = e2.y;
  return a === "cross" ? (t = { x0: o, x1: o, y0: 0, y1: i }, n = { x0: 0, x1: r, y0: s, y1: s }) : a === "top-left" ? (t = { x0: o, x1: o, y0: 0, y1: s }, n = { x0: 0, x1: o, y0: s, y1: s }) : a === "top" ? t = { x0: o, x1: o, y0: 0, y1: s } : a === "top-right" ? (t = { x0: o, x1: o, y0: 0, y1: s }, n = { x0: o, x1: r, y0: s, y1: s }) : a === "right" ? n = { x0: o, x1: r, y0: s, y1: s } : a === "bottom-right" ? (t = { x0: o, x1: o, y0: s, y1: i }, n = { x0: o, x1: r, y0: s, y1: s }) : a === "bottom" ? t = { x0: o, x1: o, y0: s, y1: i } : a === "bottom-left" ? (t = { x0: o, x1: o, y0: s, y1: i }, n = { x0: 0, x1: o, y0: s, y1: s }) : a === "left" ? n = { x0: 0, x1: o, y0: s, y1: s } : a === "x" ? t = { x0: o, x1: o, y0: 0, y1: i } : a === "y" && (n = { x0: 0, x1: r, y0: s, y1: s }), d.jsxs(d.Fragment, { children: [t && d.jsx(qn, { x0: t.x0, x1: t.x1, y0: t.y0, y1: t.y1 }), n && d.jsx(qn, { x0: n.x0, x1: n.x1, y0: n.y0, y1: n.y1 })] });
});
wl.displayName = "Crosshair";
var Ko = m.createContext({ showTooltipAt: function() {
}, showTooltipFromEvent: function() {
}, hideTooltip: function() {
} }), Vn = { isVisible: false, position: [null, null], content: null, anchor: null }, Zo = m.createContext(Vn), Cl = function(e2) {
  var t = m.useState(Vn), n = t[0], r = t[1], i = m.useCallback(function(s, c, u) {
    var p = c[0], f = c[1];
    u === void 0 && (u = "top"), r({ isVisible: true, position: [p, f], anchor: u, content: s });
  }, [r]), a = m.useCallback(function(s, c, u) {
    u === void 0 && (u = "top");
    var p = e2.current.getBoundingClientRect(), f = e2.current.offsetWidth, l = f === p.width ? 1 : f / p.width, g = "touches" in c ? c.touches[0] : c, y = g.clientX, v = g.clientY, h = (y - p.left) * l, b = (v - p.top) * l;
    u !== "left" && u !== "right" || (u = h < p.width / 2 ? "right" : "left"), r({ isVisible: true, position: [h, b], anchor: u, content: s });
  }, [e2, r]), o = m.useCallback(function() {
    r(Vn);
  }, [r]);
  return { actions: m.useMemo(function() {
    return { showTooltipAt: i, showTooltipFromEvent: a, hideTooltip: o };
  }, [i, a, o]), state: n };
}, Jo = function() {
  var e2 = m.useContext(Ko);
  if (e2 === void 0) throw new Error("useTooltip must be used within a TooltipProvider");
  return e2;
}, kl = function() {
  var e2 = m.useContext(Zo);
  if (e2 === void 0) throw new Error("useTooltipState must be used within a TooltipProvider");
  return e2;
}, zl = function(e2) {
  return e2.isVisible;
}, jl = function() {
  var e2 = kl();
  return zl(e2) ? d.jsx(Xo, { position: e2.position, anchor: e2.anchor, children: e2.content }) : null;
}, $l = function(e2) {
  var t = e2.container, n = e2.children, r = Cl(t), i = r.actions, a = r.state;
  return d.jsx(Ko.Provider, { value: i, children: d.jsx(Zo.Provider, { value: a, children: n }) });
};
let Ie;
typeof window < "u" ? Ie = window : typeof self < "u" ? Ie = self : Ie = global;
let Xn = null, Kn = null;
const ni = 20, An = Ie.clearTimeout, ri = Ie.setTimeout, In = Ie.cancelAnimationFrame || Ie.mozCancelAnimationFrame || Ie.webkitCancelAnimationFrame, ii = Ie.requestAnimationFrame || Ie.mozRequestAnimationFrame || Ie.webkitRequestAnimationFrame;
In == null || ii == null ? (Xn = An, Kn = function(t) {
  return ri(t, ni);
}) : (Xn = function([t, n]) {
  In(t), An(n);
}, Kn = function(t) {
  const n = ii(function() {
    An(r), t();
  }), r = ri(function() {
    In(n), t();
  }, ni);
  return [n, r];
});
function Ll(e2) {
  let t, n, r, i, a, o, s;
  const c = typeof document < "u" && document.attachEvent;
  if (!c) {
    o = function(b) {
      const _ = b.__resizeTriggers__, w = _.firstElementChild, C = _.lastElementChild, z = w.firstElementChild;
      C.scrollLeft = C.scrollWidth, C.scrollTop = C.scrollHeight, z.style.width = w.offsetWidth + 1 + "px", z.style.height = w.offsetHeight + 1 + "px", w.scrollLeft = w.scrollWidth, w.scrollTop = w.scrollHeight;
    }, a = function(b) {
      return b.offsetWidth !== b.__resizeLast__.width || b.offsetHeight !== b.__resizeLast__.height;
    }, s = function(b) {
      if (b.target.className && typeof b.target.className.indexOf == "function" && b.target.className.indexOf("contract-trigger") < 0 && b.target.className.indexOf("expand-trigger") < 0) return;
      const _ = this;
      o(this), this.__resizeRAF__ && Xn(this.__resizeRAF__), this.__resizeRAF__ = Kn(function() {
        a(_) && (_.__resizeLast__.width = _.offsetWidth, _.__resizeLast__.height = _.offsetHeight, _.__resizeListeners__.forEach(function(z) {
          z.call(_, b);
        }));
      });
    };
    let l = false, g = "";
    r = "animationstart";
    const y = "Webkit Moz O ms".split(" ");
    let v = "webkitAnimationStart animationstart oAnimationStart MSAnimationStart".split(" "), h = "";
    {
      const b = document.createElement("fakeelement");
      if (b.style.animationName !== void 0 && (l = true), l === false) {
        for (let _ = 0; _ < y.length; _++) if (b.style[y[_] + "AnimationName"] !== void 0) {
          h = y[_], g = "-" + h.toLowerCase() + "-", r = v[_], l = true;
          break;
        }
      }
    }
    n = "resizeanim", t = "@" + g + "keyframes " + n + " { from { opacity: 0; } to { opacity: 0; } } ", i = g + "animation: 1ms " + n + "; ";
  }
  const u = function(l) {
    if (!l.getElementById("detectElementResize")) {
      const g = (t || "") + ".resize-triggers { " + (i || "") + 'visibility: hidden; opacity: 0; } .resize-triggers, .resize-triggers > div, .contract-trigger:before { content: " "; display: block; position: absolute; top: 0; left: 0; height: 100%; width: 100%; overflow: hidden; z-index: -1; } .resize-triggers > div { background: #eee; overflow: auto; } .contract-trigger:before { width: 200%; height: 200%; }', y = l.head || l.getElementsByTagName("head")[0], v = l.createElement("style");
      v.id = "detectElementResize", v.type = "text/css", e2 != null && v.setAttribute("nonce", e2), v.styleSheet ? v.styleSheet.cssText = g : v.appendChild(l.createTextNode(g)), y.appendChild(v);
    }
  };
  return { addResizeListener: function(l, g) {
    if (c) l.attachEvent("onresize", g);
    else {
      if (!l.__resizeTriggers__) {
        const y = l.ownerDocument, v = Ie.getComputedStyle(l);
        v && v.position === "static" && (l.style.position = "relative"), u(y), l.__resizeLast__ = {}, l.__resizeListeners__ = [], (l.__resizeTriggers__ = y.createElement("div")).className = "resize-triggers";
        const h = y.createElement("div");
        h.className = "expand-trigger", h.appendChild(y.createElement("div"));
        const b = y.createElement("div");
        b.className = "contract-trigger", l.__resizeTriggers__.appendChild(h), l.__resizeTriggers__.appendChild(b), l.appendChild(l.__resizeTriggers__), o(l), l.addEventListener("scroll", s, true), r && (l.__resizeTriggers__.__animationListener__ = function(w) {
          w.animationName === n && o(l);
        }, l.__resizeTriggers__.addEventListener(r, l.__resizeTriggers__.__animationListener__));
      }
      l.__resizeListeners__.push(g);
    }
  }, removeResizeListener: function(l, g) {
    if (c) l.detachEvent("onresize", g);
    else if (l.__resizeListeners__.splice(l.__resizeListeners__.indexOf(g), 1), !l.__resizeListeners__.length) {
      l.removeEventListener("scroll", s, true), l.__resizeTriggers__.__animationListener__ && (l.__resizeTriggers__.removeEventListener(r, l.__resizeTriggers__.__animationListener__), l.__resizeTriggers__.__animationListener__ = null);
      try {
        l.__resizeTriggers__ = !l.removeChild(l.__resizeTriggers__);
      } catch {
      }
    }
  } };
}
let Rl = class extends m.Component {
  constructor(...t) {
    super(...t), this.state = { height: this.props.defaultHeight || 0, width: this.props.defaultWidth || 0 }, this._autoSizer = null, this._detectElementResize = null, this._didLogDeprecationWarning = false, this._parentNode = null, this._resizeObserver = null, this._timeoutId = null, this._onResize = () => {
      this._timeoutId = null;
      const { disableHeight: n, disableWidth: r, onResize: i } = this.props;
      if (this._parentNode) {
        const a = window.getComputedStyle(this._parentNode) || {}, o = parseFloat(a.paddingLeft || "0"), s = parseFloat(a.paddingRight || "0"), c = parseFloat(a.paddingTop || "0"), u = parseFloat(a.paddingBottom || "0"), p = this._parentNode.getBoundingClientRect(), f = p.height - c - u, l = p.width - o - s;
        if (!n && this.state.height !== f || !r && this.state.width !== l) {
          this.setState({ height: f, width: l });
          const g = () => {
            this._didLogDeprecationWarning || (this._didLogDeprecationWarning = true, console.warn("scaledWidth and scaledHeight parameters have been deprecated; use width and height instead"));
          };
          typeof i == "function" && i({ height: f, width: l, get scaledHeight() {
            return g(), f;
          }, get scaledWidth() {
            return g(), l;
          } });
        }
      }
    }, this._setRef = (n) => {
      this._autoSizer = n;
    };
  }
  componentDidMount() {
    const { nonce: t } = this.props, n = this._autoSizer ? this._autoSizer.parentNode : null;
    if (n != null && n.ownerDocument && n.ownerDocument.defaultView && n instanceof n.ownerDocument.defaultView.HTMLElement) {
      this._parentNode = n;
      const r = n.ownerDocument.defaultView.ResizeObserver;
      r != null ? (this._resizeObserver = new r(() => {
        this._timeoutId = setTimeout(this._onResize, 0);
      }), this._resizeObserver.observe(n)) : (this._detectElementResize = Ll(t), this._detectElementResize.addResizeListener(n, this._onResize)), this._onResize();
    }
  }
  componentWillUnmount() {
    this._parentNode && (this._detectElementResize && this._detectElementResize.removeResizeListener(this._parentNode, this._onResize), this._timeoutId !== null && clearTimeout(this._timeoutId), this._resizeObserver && this._resizeObserver.disconnect());
  }
  render() {
    const { children: t, defaultHeight: n, defaultWidth: r, disableHeight: i = false, disableWidth: a = false, doNotBailOutOnEmptyChildren: o = false, nonce: s, onResize: c, style: u = {}, tagName: p = "div", ...f } = this.props, { height: l, width: g } = this.state, y = { overflow: "visible" }, v = {};
    let h = false;
    return i || (l === 0 && (h = true), y.height = 0, v.height = l, v.scaledHeight = l), a || (g === 0 && (h = true), y.width = 0, v.width = g, v.scaledWidth = g), o && (h = false), m.createElement(p, { ref: this._setRef, style: { ...y, ...u }, ...f }, !h && t(v));
  }
};
var Qo = m.createContext(), Ml = function(e2) {
  var t = e2.children, n = e2.animate, r = n === void 0 || n, i = e2.config, a = i === void 0 ? "default" : i, o = m.useMemo(function() {
    var s = Di(a) ? Hi[a] : a;
    return { animate: r, config: s };
  }, [r, a]);
  return d.jsx(Qo.Provider, { value: o, children: t });
}, mn = function() {
  return m.useContext(Qo);
}, Sl = function(e2) {
  var t = e2.children, n = e2.condition, r = e2.wrapper;
  return n ? m.cloneElement(r, {}, t) : t;
}, Ol = { position: "relative" }, ea = function(e2) {
  var t = e2.children, n = e2.theme, r = e2.renderWrapper, i = r === void 0 || r, a = e2.isInteractive, o = a === void 0 || a, s = e2.animate, c = e2.motionConfig, u = m.useRef(null);
  return d.jsx(Vo, { theme: n, children: d.jsx(Ml, { animate: s, config: c, children: d.jsx($l, { container: u, children: d.jsxs(Sl, { condition: i, wrapper: d.jsx("div", { style: Ol, ref: u }), children: [t, o && d.jsx(jl, {})] }) }) }) });
}, El = function(e2, t) {
  return e2.width === t.width && e2.height === t.height;
}, Wl = function(e2) {
  var t = e2.children, n = e2.width, r = e2.height, i = e2.onResize, a = e2.debounceResize, o = Sr({ width: n, height: r }, a, { equalityFn: El })[0];
  return m.useEffect(function() {
    i == null ? void 0 : i(o);
  }, [o, i]), d.jsx(d.Fragment, { children: t(o) });
}, ta = function(e2) {
  var t = e2.children, n = e2.defaultWidth, r = e2.defaultHeight, i = e2.onResize, a = e2.debounceResize, o = a === void 0 ? 0 : a;
  return d.jsx(Rl, { defaultWidth: n, defaultHeight: r, children: function(s) {
    var c = s.width, u = s.height;
    return d.jsx(Wl, { width: c, height: u, onResize: i, debounceResize: o, children: t });
  } });
};
function Wt() {
  return Wt = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Wt.apply(null, arguments);
}
function na(e2, t) {
  if (e2 == null) return {};
  var n = {};
  for (var r in e2) if ({}.hasOwnProperty.call(e2, r)) {
    if (t.indexOf(r) !== -1) continue;
    n[r] = e2[r];
  }
  return n;
}
var Tl = ["id", "colors"], Nl = function(e2) {
  var t = e2.id, n = e2.colors, r = na(e2, Tl);
  return d.jsx("linearGradient", Wt({ id: t, x1: 0, x2: 0, y1: 0, y2: 1 }, r, { children: n.map(function(i) {
    var a = i.offset, o = i.color, s = i.opacity;
    return d.jsx("stop", { offset: a + "%", stopColor: o, stopOpacity: s !== void 0 ? s : 1 }, a);
  }) }));
}, Pl = { linearGradient: Nl }, Yt = { color: "#000000", background: "#ffffff", size: 4, padding: 4, stagger: false }, Al = m.memo(function(e2) {
  var t = e2.id, n = e2.background, r = n === void 0 ? Yt.background : n, i = e2.color, a = i === void 0 ? Yt.color : i, o = e2.size, s = o === void 0 ? Yt.size : o, c = e2.padding, u = c === void 0 ? Yt.padding : c, p = e2.stagger, f = p === void 0 ? Yt.stagger : p, l = s + u, g = s / 2, y = u / 2;
  return f === true && (l = 2 * s + 2 * u), d.jsxs("pattern", { id: t, width: l, height: l, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: l, height: l, fill: r }), d.jsx("circle", { cx: y + g, cy: y + g, r: g, fill: a }), f && d.jsx("circle", { cx: 1.5 * u + s + g, cy: 1.5 * u + s + g, r: g, fill: a })] });
}), oi = function(e2) {
  return e2 * Math.PI / 180;
}, qt = { spacing: 5, rotation: 0, background: "#000000", color: "#ffffff", lineWidth: 2 }, Il = m.memo(function(e2) {
  var t = e2.id, n = e2.spacing, r = n === void 0 ? qt.spacing : n, i = e2.rotation, a = i === void 0 ? qt.rotation : i, o = e2.background, s = o === void 0 ? qt.background : o, c = e2.color, u = c === void 0 ? qt.color : c, p = e2.lineWidth, f = p === void 0 ? qt.lineWidth : p, l = Math.round(a) % 360, g = Math.abs(r);
  l > 180 ? l -= 360 : l > 90 ? l -= 180 : l < -180 ? l += 360 : l < -90 && (l += 180);
  var y, v = g, h = g;
  return l === 0 ? y = `
                M 0 0 L ` + v + ` 0
                M 0 ` + h + " L " + v + " " + h + `
            ` : l === 90 ? y = `
                M 0 0 L 0 ` + h + `
                M ` + v + " 0 L " + v + " " + h + `
            ` : (v = Math.abs(g / Math.sin(oi(l))), h = g / Math.sin(oi(90 - l)), y = l > 0 ? `
                    M 0 ` + -h + " L " + 2 * v + " " + h + `
                    M ` + -v + " " + -h + " L " + v + " " + h + `
                    M ` + -v + " 0 L " + v + " " + 2 * h + `
                ` : `
                    M ` + -v + " " + h + " L " + v + " " + -h + `
                    M ` + -v + " " + 2 * h + " L " + 2 * v + " " + -h + `
                    M 0 ` + 2 * h + " L " + 2 * v + ` 0
                `), d.jsxs("pattern", { id: t, width: v, height: h, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: v, height: h, fill: s, stroke: "rgba(255, 0, 0, 0.1)", strokeWidth: 0 }), d.jsx("path", { d: y, strokeWidth: f, stroke: u, strokeLinecap: "square" })] });
}), Vt = { color: "#000000", background: "#ffffff", size: 4, padding: 4, stagger: false }, Bl = m.memo(function(e2) {
  var t = e2.id, n = e2.color, r = n === void 0 ? Vt.color : n, i = e2.background, a = i === void 0 ? Vt.background : i, o = e2.size, s = o === void 0 ? Vt.size : o, c = e2.padding, u = c === void 0 ? Vt.padding : c, p = e2.stagger, f = p === void 0 ? Vt.stagger : p, l = s + u, g = u / 2;
  return f === true && (l = 2 * s + 2 * u), d.jsxs("pattern", { id: t, width: l, height: l, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: l, height: l, fill: a }), d.jsx("rect", { x: g, y: g, width: s, height: s, fill: r }), f && d.jsx("rect", { x: 1.5 * u + s, y: 1.5 * u + s, width: s, height: s, fill: r })] });
}), Fl = { patternDots: Al, patternLines: Il, patternSquares: Bl }, Dl = ["type"], ai = Wt({}, Pl, Fl), Hl = m.memo(function(e2) {
  var t = e2.defs;
  return !t || t.length < 1 ? null : d.jsx("defs", { "aria-hidden": true, children: t.map(function(n) {
    var r = n.type, i = na(n, Dl);
    return ai[r] ? m.createElement(ai[r], Wt({ key: i.id }, i)) : null;
  }) });
}), Gl = m.forwardRef(function(e2, t) {
  var n = e2.width, r = e2.height, i = e2.margin, a = e2.defs, o = e2.children, s = e2.role, c = e2.ariaLabel, u = e2.ariaLabelledBy, p = e2.ariaDescribedBy, f = e2.isFocusable, l = X();
  return d.jsxs("svg", { xmlns: "http://www.w3.org/2000/svg", width: n, height: r, role: s, "aria-label": c, "aria-labelledby": u, "aria-describedby": p, focusable: f, tabIndex: f ? 0 : void 0, ref: t, children: [d.jsx(Hl, { defs: a }), d.jsx("rect", { width: n, height: r, fill: l.background }), d.jsx("g", { transform: "translate(" + i.left + "," + i.top + ")", children: o })] });
}), Ul = m.memo(function(e2) {
  var t = e2.size, n = e2.color, r = e2.borderWidth, i = e2.borderColor;
  return d.jsx("circle", { r: t / 2, fill: n, stroke: i, strokeWidth: r, style: { pointerEvents: "none" } });
});
m.memo(function(e2) {
  var t = e2.x, n = e2.y, r = e2.symbol, i = r === void 0 ? Ul : r, a = e2.size, o = e2.datum, s = e2.color, c = e2.borderWidth, u = e2.borderColor, p = e2.label, f = e2.labelTextAnchor, l = f === void 0 ? "middle" : f, g = e2.labelYOffset, y = g === void 0 ? -12 : g, v = e2.ariaLabel, h = e2.ariaLabelledBy, b = e2.ariaDescribedBy, _ = e2.ariaHidden, w = e2.ariaDisabled, C = e2.isFocusable, z = C !== void 0 && C, $ = e2.tabIndex, R = $ === void 0 ? 0 : $, k = e2.onFocus, j = e2.onBlur, T = e2.testId, P = X(), N = mn(), L = N.animate, E = N.config, W = Pe({ transform: "translate(" + t + ", " + n + ")", config: E, immediate: !L }), S = m.useCallback(function(Y) {
    k == null ? void 0 : k(o, Y);
  }, [k, o]), O = m.useCallback(function(Y) {
    j == null ? void 0 : j(o, Y);
  }, [j, o]);
  return d.jsxs(ee.g, { transform: W.transform, style: { pointerEvents: "none" }, focusable: z, tabIndex: z ? R : void 0, "aria-label": v, "aria-labelledby": h, "aria-describedby": b, "aria-disabled": w, "aria-hidden": _, onFocus: z && k ? S : void 0, onBlur: z && j ? O : void 0, "data-testid": T, children: [m.createElement(i, { size: a, color: s, datum: o, borderWidth: c, borderColor: u }), p && d.jsx("text", { textAnchor: l, y, style: Fr(P.dots.text), children: p })] });
});
var Yl = m.memo(function(e2) {
  var t = e2.width, n = e2.height, r = e2.axis, i = e2.scale, a = e2.value, o = e2.lineStyle, s = e2.textStyle, c = e2.legend, u = e2.legendNode, p = e2.legendPosition, f = p === void 0 ? "top-right" : p, l = e2.legendOffsetX, g = l === void 0 ? 14 : l, y = e2.legendOffsetY, v = y === void 0 ? 14 : y, h = e2.legendOrientation, b = h === void 0 ? "horizontal" : h, _ = X(), w = 0, C = 0, z = 0, $ = 0;
  if (r === "y" ? (z = i(a), C = t) : (w = i(a), $ = n), c && !u) {
    var R = function(k) {
      var j = k.axis, T = k.width, P = k.height, N = k.position, L = k.offsetX, E = k.offsetY, W = k.orientation, S = 0, O = 0, Y = W === "vertical" ? -90 : 0, M = "start";
      if (j === "x") switch (N) {
        case "top-left":
          S = -L, O = E, M = "end";
          break;
        case "top":
          O = -E, M = W === "horizontal" ? "middle" : "start";
          break;
        case "top-right":
          S = L, O = E, M = W === "horizontal" ? "start" : "end";
          break;
        case "right":
          S = L, O = P / 2, M = W === "horizontal" ? "start" : "middle";
          break;
        case "bottom-right":
          S = L, O = P - E, M = "start";
          break;
        case "bottom":
          O = P + E, M = W === "horizontal" ? "middle" : "end";
          break;
        case "bottom-left":
          O = P - E, S = -L, M = W === "horizontal" ? "end" : "start";
          break;
        case "left":
          S = -L, O = P / 2, M = W === "horizontal" ? "end" : "middle";
      }
      else switch (N) {
        case "top-left":
          S = L, O = -E, M = "start";
          break;
        case "top":
          S = T / 2, O = -E, M = W === "horizontal" ? "middle" : "start";
          break;
        case "top-right":
          S = T - L, O = -E, M = W === "horizontal" ? "end" : "start";
          break;
        case "right":
          S = T + L, M = W === "horizontal" ? "start" : "middle";
          break;
        case "bottom-right":
          S = T - L, O = E, M = "end";
          break;
        case "bottom":
          S = T / 2, O = E, M = W === "horizontal" ? "middle" : "end";
          break;
        case "bottom-left":
          S = L, O = E, M = W === "horizontal" ? "start" : "end";
          break;
        case "left":
          S = -L, M = W === "horizontal" ? "end" : "middle";
      }
      return { x: S, y: O, rotation: Y, textAnchor: M };
    }({ axis: r, width: t, height: n, position: f, offsetX: g, offsetY: v, orientation: b });
    u = d.jsx("text", { transform: "translate(" + R.x + ", " + R.y + ") rotate(" + R.rotation + ")", textAnchor: R.textAnchor, dominantBaseline: "central", style: s, children: c });
  }
  return d.jsxs("g", { transform: "translate(" + w + ", " + z + ")", children: [d.jsx("line", { x1: 0, x2: C, y1: 0, y2: $, stroke: _.markers.lineColor, strokeWidth: _.markers.lineStrokeWidth, style: o }), u] });
});
m.memo(function(e2) {
  var t = e2.markers, n = e2.width, r = e2.height, i = e2.xScale, a = e2.yScale;
  return t && t.length !== 0 ? t.map(function(o, s) {
    return d.jsx(Yl, Wt({}, o, { width: n, height: r, scale: o.axis === "y" ? a : i }), s);
  }) : null;
});
m.createContext(void 0);
var ql = { basis: Mr, basisClosed: Rr, basisOpen: Lr, bundle: $r, cardinal: jr, cardinalClosed: zr, cardinalOpen: kr, catmullRom: Cr, catmullRomClosed: wr, catmullRomOpen: _r, linear: xr, linearClosed: yr, monotoneX: br, monotoneY: mr, natural: vr, step: gr, stepAfter: pr, stepBefore: hr }, Dr = Object.keys(ql);
Dr.filter(function(e2) {
  return e2.endsWith("Closed");
});
Gt(Dr, "bundle", "basisClosed", "basisOpen", "cardinalClosed", "cardinalOpen", "catmullRomClosed", "catmullRomOpen", "linearClosed");
Gt(Dr, "bundle", "basisClosed", "basisOpen", "cardinalClosed", "cardinalOpen", "catmullRomClosed", "catmullRomOpen", "linearClosed");
x(jt), x(zt), x(kt), x(Ct), x(wt), x(_t), x(xt), x(yt), x(bt), x(mt), x(vt), x(gt), x(pt), x(ht), x(ft), x(ct), x(dt), x(ut), x(lt), x(st), x(at), x(ot), x(it), x(rt), x(nt), x(tt), x(et);
x(jt), x(zt), x(kt), x(Ct), x(wt), x(_t), x(xt), x(yt), x(bt), x(mt), x(vt), x(gt), x(pt), x(ht), x(ft), x(ct), x(dt), x(ut), x(lt), x(st), x(at), x(ot), x(it), x(rt), x(nt), x(tt), x(et);
Ot(gn);
var Vl = { top: 0, right: 0, bottom: 0, left: 0 }, ra = function(e2, t, n) {
  return n === void 0 && (n = {}), m.useMemo(function() {
    var r = Wt({}, Vl, n);
    return { margin: r, innerWidth: e2 - r.left - r.right, innerHeight: t - r.top - r.bottom, outerWidth: e2, outerHeight: t };
  }, [e2, t, n]);
}, Xl = function() {
  var e2 = m.useRef(null), t = m.useState({ left: 0, top: 0, width: 0, height: 0 }), n = t[0], r = t[1], i = m.useState(function() {
    return typeof ResizeObserver > "u" ? null : new ResizeObserver(function(a) {
      var o = a[0];
      return r(o.contentRect);
    });
  })[0];
  return m.useEffect(function() {
    return e2.current && i !== null && i.observe(e2.current), function() {
      i !== null && i.disconnect();
    };
  }, [i]), [e2, n];
}, Kl = function(e2) {
  return typeof e2 == "function" ? e2 : typeof e2 == "string" ? e2.indexOf("time:") === 0 ? cr(e2.slice("5")) : fr(e2) : function(t) {
    return "" + t;
  };
}, Zl = function(e2) {
  return m.useMemo(function() {
    return Kl(e2);
  }, [e2]);
}, Jl = function(e2, t, n, r) {
  return Math.sqrt(Math.pow(n - e2, 2) + Math.pow(r - t, 2));
}, Ql = function(e2, t) {
  var n, r = "touches" in t ? t.touches[0] : t, i = r.clientX, a = r.clientY, o = e2.getBoundingClientRect(), s = (n = e2.getBBox !== void 0 ? e2.getBBox() : { width: e2.offsetWidth || 0, height: e2.offsetHeight || 0 }).width === o.width ? 1 : n.width / o.width;
  return [(i - o.left) * s, (a - o.top) * s];
};
function eu() {
  for (var e2 = arguments.length, t = new Array(e2), n = 0; n < e2; n++) t[n] = arguments[n];
  return function(r) {
    for (var i = 0, a = t; i < a.length; i++) {
      var o = a[i];
      typeof o == "function" ? o(r) : o != null && (o.current = r);
    }
  };
}
function tu(e2, t) {
  var n, r = 1;
  e2 == null && (e2 = 0), t == null && (t = 0);
  function i() {
    var a, o = n.length, s, c = 0, u = 0;
    for (a = 0; a < o; ++a) s = n[a], c += s.x, u += s.y;
    for (c = (c / o - e2) * r, u = (u / o - t) * r, a = 0; a < o; ++a) s = n[a], s.x -= c, s.y -= u;
  }
  return i.initialize = function(a) {
    n = a;
  }, i.x = function(a) {
    return arguments.length ? (e2 = +a, i) : e2;
  }, i.y = function(a) {
    return arguments.length ? (t = +a, i) : t;
  }, i.strength = function(a) {
    return arguments.length ? (r = +a, i) : r;
  }, i;
}
function nu(e2) {
  const t = +this._x.call(null, e2), n = +this._y.call(null, e2);
  return ia(this.cover(t, n), t, n, e2);
}
function ia(e2, t, n, r) {
  if (isNaN(t) || isNaN(n)) return e2;
  var i, a = e2._root, o = { data: r }, s = e2._x0, c = e2._y0, u = e2._x1, p = e2._y1, f, l, g, y, v, h, b, _;
  if (!a) return e2._root = o, e2;
  for (; a.length; ) if ((v = t >= (f = (s + u) / 2)) ? s = f : u = f, (h = n >= (l = (c + p) / 2)) ? c = l : p = l, i = a, !(a = a[b = h << 1 | v])) return i[b] = o, e2;
  if (g = +e2._x.call(null, a.data), y = +e2._y.call(null, a.data), t === g && n === y) return o.next = a, i ? i[b] = o : e2._root = o, e2;
  do
    i = i ? i[b] = new Array(4) : e2._root = new Array(4), (v = t >= (f = (s + u) / 2)) ? s = f : u = f, (h = n >= (l = (c + p) / 2)) ? c = l : p = l;
  while ((b = h << 1 | v) === (_ = (y >= l) << 1 | g >= f));
  return i[_] = a, i[b] = o, e2;
}
function ru(e2) {
  var t, n, r = e2.length, i, a, o = new Array(r), s = new Array(r), c = 1 / 0, u = 1 / 0, p = -1 / 0, f = -1 / 0;
  for (n = 0; n < r; ++n) isNaN(i = +this._x.call(null, t = e2[n])) || isNaN(a = +this._y.call(null, t)) || (o[n] = i, s[n] = a, i < c && (c = i), i > p && (p = i), a < u && (u = a), a > f && (f = a));
  if (c > p || u > f) return this;
  for (this.cover(c, u).cover(p, f), n = 0; n < r; ++n) ia(this, o[n], s[n], e2[n]);
  return this;
}
function iu(e2, t) {
  if (isNaN(e2 = +e2) || isNaN(t = +t)) return this;
  var n = this._x0, r = this._y0, i = this._x1, a = this._y1;
  if (isNaN(n)) i = (n = Math.floor(e2)) + 1, a = (r = Math.floor(t)) + 1;
  else {
    for (var o = i - n || 1, s = this._root, c, u; n > e2 || e2 >= i || r > t || t >= a; ) switch (u = (t < r) << 1 | e2 < n, c = new Array(4), c[u] = s, s = c, o *= 2, u) {
      case 0:
        i = n + o, a = r + o;
        break;
      case 1:
        n = i - o, a = r + o;
        break;
      case 2:
        i = n + o, r = a - o;
        break;
      case 3:
        n = i - o, r = a - o;
        break;
    }
    this._root && this._root.length && (this._root = s);
  }
  return this._x0 = n, this._y0 = r, this._x1 = i, this._y1 = a, this;
}
function ou() {
  var e2 = [];
  return this.visit(function(t) {
    if (!t.length) do
      e2.push(t.data);
    while (t = t.next);
  }), e2;
}
function au(e2) {
  return arguments.length ? this.cover(+e2[0][0], +e2[0][1]).cover(+e2[1][0], +e2[1][1]) : isNaN(this._x0) ? void 0 : [[this._x0, this._y0], [this._x1, this._y1]];
}
function Te(e2, t, n, r, i) {
  this.node = e2, this.x0 = t, this.y0 = n, this.x1 = r, this.y1 = i;
}
function su(e2, t, n) {
  var r, i = this._x0, a = this._y0, o, s, c, u, p = this._x1, f = this._y1, l = [], g = this._root, y, v;
  for (g && l.push(new Te(g, i, a, p, f)), n == null ? n = 1 / 0 : (i = e2 - n, a = t - n, p = e2 + n, f = t + n, n *= n); y = l.pop(); ) if (!(!(g = y.node) || (o = y.x0) > p || (s = y.y0) > f || (c = y.x1) < i || (u = y.y1) < a)) if (g.length) {
    var h = (o + c) / 2, b = (s + u) / 2;
    l.push(new Te(g[3], h, b, c, u), new Te(g[2], o, b, h, u), new Te(g[1], h, s, c, b), new Te(g[0], o, s, h, b)), (v = (t >= b) << 1 | e2 >= h) && (y = l[l.length - 1], l[l.length - 1] = l[l.length - 1 - v], l[l.length - 1 - v] = y);
  } else {
    var _ = e2 - +this._x.call(null, g.data), w = t - +this._y.call(null, g.data), C = _ * _ + w * w;
    if (C < n) {
      var z = Math.sqrt(n = C);
      i = e2 - z, a = t - z, p = e2 + z, f = t + z, r = g.data;
    }
  }
  return r;
}
function lu(e2) {
  if (isNaN(p = +this._x.call(null, e2)) || isNaN(f = +this._y.call(null, e2))) return this;
  var t, n = this._root, r, i, a, o = this._x0, s = this._y0, c = this._x1, u = this._y1, p, f, l, g, y, v, h, b;
  if (!n) return this;
  if (n.length) for (; ; ) {
    if ((y = p >= (l = (o + c) / 2)) ? o = l : c = l, (v = f >= (g = (s + u) / 2)) ? s = g : u = g, t = n, !(n = n[h = v << 1 | y])) return this;
    if (!n.length) break;
    (t[h + 1 & 3] || t[h + 2 & 3] || t[h + 3 & 3]) && (r = t, b = h);
  }
  for (; n.data !== e2; ) if (i = n, !(n = n.next)) return this;
  return (a = n.next) && delete n.next, i ? (a ? i.next = a : delete i.next, this) : t ? (a ? t[h] = a : delete t[h], (n = t[0] || t[1] || t[2] || t[3]) && n === (t[3] || t[2] || t[1] || t[0]) && !n.length && (r ? r[b] = n : this._root = n), this) : (this._root = a, this);
}
function uu(e2) {
  for (var t = 0, n = e2.length; t < n; ++t) this.remove(e2[t]);
  return this;
}
function du() {
  return this._root;
}
function cu() {
  var e2 = 0;
  return this.visit(function(t) {
    if (!t.length) do
      ++e2;
    while (t = t.next);
  }), e2;
}
function fu(e2) {
  var t = [], n, r = this._root, i, a, o, s, c;
  for (r && t.push(new Te(r, this._x0, this._y0, this._x1, this._y1)); n = t.pop(); ) if (!e2(r = n.node, a = n.x0, o = n.y0, s = n.x1, c = n.y1) && r.length) {
    var u = (a + s) / 2, p = (o + c) / 2;
    (i = r[3]) && t.push(new Te(i, u, p, s, c)), (i = r[2]) && t.push(new Te(i, a, p, u, c)), (i = r[1]) && t.push(new Te(i, u, o, s, p)), (i = r[0]) && t.push(new Te(i, a, o, u, p));
  }
  return this;
}
function hu(e2) {
  var t = [], n = [], r;
  for (this._root && t.push(new Te(this._root, this._x0, this._y0, this._x1, this._y1)); r = t.pop(); ) {
    var i = r.node;
    if (i.length) {
      var a, o = r.x0, s = r.y0, c = r.x1, u = r.y1, p = (o + c) / 2, f = (s + u) / 2;
      (a = i[0]) && t.push(new Te(a, o, s, p, f)), (a = i[1]) && t.push(new Te(a, p, s, c, f)), (a = i[2]) && t.push(new Te(a, o, f, p, u)), (a = i[3]) && t.push(new Te(a, p, f, c, u));
    }
    n.push(r);
  }
  for (; r = n.pop(); ) e2(r.node, r.x0, r.y0, r.x1, r.y1);
  return this;
}
function pu(e2) {
  return e2[0];
}
function gu(e2) {
  return arguments.length ? (this._x = e2, this) : this._x;
}
function vu(e2) {
  return e2[1];
}
function mu(e2) {
  return arguments.length ? (this._y = e2, this) : this._y;
}
function oa(e2, t, n) {
  var r = new Hr(t ?? pu, n ?? vu, NaN, NaN, NaN, NaN);
  return e2 == null ? r : r.addAll(e2);
}
function Hr(e2, t, n, r, i, a) {
  this._x = e2, this._y = t, this._x0 = n, this._y0 = r, this._x1 = i, this._y1 = a, this._root = void 0;
}
function si(e2) {
  for (var t = { data: e2.data }, n = t; e2 = e2.next; ) n = n.next = { data: e2.data };
  return t;
}
var Ne = oa.prototype = Hr.prototype;
Ne.copy = function() {
  var e2 = new Hr(this._x, this._y, this._x0, this._y0, this._x1, this._y1), t = this._root, n, r;
  if (!t) return e2;
  if (!t.length) return e2._root = si(t), e2;
  for (n = [{ source: t, target: e2._root = new Array(4) }]; t = n.pop(); ) for (var i = 0; i < 4; ++i) (r = t.source[i]) && (r.length ? n.push({ source: r, target: t.target[i] = new Array(4) }) : t.target[i] = si(r));
  return e2;
};
Ne.add = nu;
Ne.addAll = ru;
Ne.cover = iu;
Ne.data = ou;
Ne.extent = au;
Ne.find = su;
Ne.remove = lu;
Ne.removeAll = uu;
Ne.root = du;
Ne.size = cu;
Ne.visit = fu;
Ne.visitAfter = hu;
Ne.x = gu;
Ne.y = mu;
function ln(e2) {
  return function() {
    return e2;
  };
}
function It(e2) {
  return (e2() - 0.5) * 1e-6;
}
function bu(e2) {
  return e2.index;
}
function li(e2, t) {
  var n = e2.get(t);
  if (!n) throw new Error("node not found: " + t);
  return n;
}
function yu(e2) {
  var t = bu, n = f, r, i = ln(30), a, o, s, c, u, p = 1;
  e2 == null && (e2 = []);
  function f(h) {
    return 1 / Math.min(s[h.source.index], s[h.target.index]);
  }
  function l(h) {
    for (var b = 0, _ = e2.length; b < p; ++b) for (var w = 0, C, z, $, R, k, j, T; w < _; ++w) C = e2[w], z = C.source, $ = C.target, R = $.x + $.vx - z.x - z.vx || It(u), k = $.y + $.vy - z.y - z.vy || It(u), j = Math.sqrt(R * R + k * k), j = (j - a[w]) / j * h * r[w], R *= j, k *= j, $.vx -= R * (T = c[w]), $.vy -= k * T, z.vx += R * (T = 1 - T), z.vy += k * T;
  }
  function g() {
    if (o) {
      var h, b = o.length, _ = e2.length, w = new Map(o.map((z, $) => [t(z, $, o), z])), C;
      for (h = 0, s = new Array(b); h < _; ++h) C = e2[h], C.index = h, typeof C.source != "object" && (C.source = li(w, C.source)), typeof C.target != "object" && (C.target = li(w, C.target)), s[C.source.index] = (s[C.source.index] || 0) + 1, s[C.target.index] = (s[C.target.index] || 0) + 1;
      for (h = 0, c = new Array(_); h < _; ++h) C = e2[h], c[h] = s[C.source.index] / (s[C.source.index] + s[C.target.index]);
      r = new Array(_), y(), a = new Array(_), v();
    }
  }
  function y() {
    if (o) for (var h = 0, b = e2.length; h < b; ++h) r[h] = +n(e2[h], h, e2);
  }
  function v() {
    if (o) for (var h = 0, b = e2.length; h < b; ++h) a[h] = +i(e2[h], h, e2);
  }
  return l.initialize = function(h, b) {
    o = h, u = b, g();
  }, l.links = function(h) {
    return arguments.length ? (e2 = h, g(), l) : e2;
  }, l.id = function(h) {
    return arguments.length ? (t = h, l) : t;
  }, l.iterations = function(h) {
    return arguments.length ? (p = +h, l) : p;
  }, l.strength = function(h) {
    return arguments.length ? (n = typeof h == "function" ? h : ln(+h), y(), l) : n;
  }, l.distance = function(h) {
    return arguments.length ? (i = typeof h == "function" ? h : ln(+h), v(), l) : i;
  }, l;
}
var xu = { value: () => {
} };
function aa() {
  for (var e2 = 0, t = arguments.length, n = {}, r; e2 < t; ++e2) {
    if (!(r = arguments[e2] + "") || r in n || /[\s.]/.test(r)) throw new Error("illegal type: " + r);
    n[r] = [];
  }
  return new Cn(n);
}
function Cn(e2) {
  this._ = e2;
}
function _u(e2, t) {
  return e2.trim().split(/^|\s+/).map(function(n) {
    var r = "", i = n.indexOf(".");
    if (i >= 0 && (r = n.slice(i + 1), n = n.slice(0, i)), n && !t.hasOwnProperty(n)) throw new Error("unknown type: " + n);
    return { type: n, name: r };
  });
}
Cn.prototype = aa.prototype = { constructor: Cn, on: function(e2, t) {
  var n = this._, r = _u(e2 + "", n), i, a = -1, o = r.length;
  if (arguments.length < 2) {
    for (; ++a < o; ) if ((i = (e2 = r[a]).type) && (i = wu(n[i], e2.name))) return i;
    return;
  }
  if (t != null && typeof t != "function") throw new Error("invalid callback: " + t);
  for (; ++a < o; ) if (i = (e2 = r[a]).type) n[i] = ui(n[i], e2.name, t);
  else if (t == null) for (i in n) n[i] = ui(n[i], e2.name, null);
  return this;
}, copy: function() {
  var e2 = {}, t = this._;
  for (var n in t) e2[n] = t[n].slice();
  return new Cn(e2);
}, call: function(e2, t) {
  if ((i = arguments.length - 2) > 0) for (var n = new Array(i), r = 0, i, a; r < i; ++r) n[r] = arguments[r + 2];
  if (!this._.hasOwnProperty(e2)) throw new Error("unknown type: " + e2);
  for (a = this._[e2], r = 0, i = a.length; r < i; ++r) a[r].value.apply(t, n);
}, apply: function(e2, t, n) {
  if (!this._.hasOwnProperty(e2)) throw new Error("unknown type: " + e2);
  for (var r = this._[e2], i = 0, a = r.length; i < a; ++i) r[i].value.apply(t, n);
} };
function wu(e2, t) {
  for (var n = 0, r = e2.length, i; n < r; ++n) if ((i = e2[n]).name === t) return i.value;
}
function ui(e2, t, n) {
  for (var r = 0, i = e2.length; r < i; ++r) if (e2[r].name === t) {
    e2[r] = xu, e2 = e2.slice(0, r).concat(e2.slice(r + 1));
    break;
  }
  return n != null && e2.push({ name: t, value: n }), e2;
}
var Ft = 0, an = 0, Xt = 0, sa = 1e3, kn, sn, zn = 0, Tt = 0, Wn = 0, cn = typeof performance == "object" && performance.now ? performance : Date, la = typeof window == "object" && window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : function(e2) {
  setTimeout(e2, 17);
};
function ua() {
  return Tt || (la(Cu), Tt = cn.now() + Wn);
}
function Cu() {
  Tt = 0;
}
function Zn() {
  this._call = this._time = this._next = null;
}
Zn.prototype = da.prototype = { constructor: Zn, restart: function(e2, t, n) {
  if (typeof e2 != "function") throw new TypeError("callback is not a function");
  n = (n == null ? ua() : +n) + (t == null ? 0 : +t), !this._next && sn !== this && (sn ? sn._next = this : kn = this, sn = this), this._call = e2, this._time = n, Jn();
}, stop: function() {
  this._call && (this._call = null, this._time = 1 / 0, Jn());
} };
function da(e2, t, n) {
  var r = new Zn();
  return r.restart(e2, t, n), r;
}
function ku() {
  ua(), ++Ft;
  for (var e2 = kn, t; e2; ) (t = Tt - e2._time) >= 0 && e2._call.call(null, t), e2 = e2._next;
  --Ft;
}
function di() {
  Tt = (zn = cn.now()) + Wn, Ft = an = 0;
  try {
    ku();
  } finally {
    Ft = 0, ju(), Tt = 0;
  }
}
function zu() {
  var e2 = cn.now(), t = e2 - zn;
  t > sa && (Wn -= t, zn = e2);
}
function ju() {
  for (var e2, t = kn, n, r = 1 / 0; t; ) t._call ? (r > t._time && (r = t._time), e2 = t, t = t._next) : (n = t._next, t._next = null, t = e2 ? e2._next = n : kn = n);
  sn = e2, Jn(r);
}
function Jn(e2) {
  if (!Ft) {
    an && (an = clearTimeout(an));
    var t = e2 - Tt;
    t > 24 ? (e2 < 1 / 0 && (an = setTimeout(di, e2 - cn.now() - Wn)), Xt && (Xt = clearInterval(Xt))) : (Xt || (zn = cn.now(), Xt = setInterval(zu, sa)), Ft = 1, la(di));
  }
}
const $u = 1664525, Lu = 1013904223, ci = 4294967296;
function Ru() {
  let e2 = 1;
  return () => (e2 = ($u * e2 + Lu) % ci) / ci;
}
function Mu(e2) {
  return e2.x;
}
function Su(e2) {
  return e2.y;
}
var Ou = 10, Eu = Math.PI * (3 - Math.sqrt(5));
function Wu(e2) {
  var t, n = 1, r = 1e-3, i = 1 - Math.pow(r, 1 / 300), a = 0, o = 0.6, s = /* @__PURE__ */ new Map(), c = da(f), u = aa("tick", "end"), p = Ru();
  e2 == null && (e2 = []);
  function f() {
    l(), u.call("tick", t), n < r && (c.stop(), u.call("end", t));
  }
  function l(v) {
    var h, b = e2.length, _;
    v === void 0 && (v = 1);
    for (var w = 0; w < v; ++w) for (n += (a - n) * i, s.forEach(function(C) {
      C(n);
    }), h = 0; h < b; ++h) _ = e2[h], _.fx == null ? _.x += _.vx *= o : (_.x = _.fx, _.vx = 0), _.fy == null ? _.y += _.vy *= o : (_.y = _.fy, _.vy = 0);
    return t;
  }
  function g() {
    for (var v = 0, h = e2.length, b; v < h; ++v) {
      if (b = e2[v], b.index = v, b.fx != null && (b.x = b.fx), b.fy != null && (b.y = b.fy), isNaN(b.x) || isNaN(b.y)) {
        var _ = Ou * Math.sqrt(0.5 + v), w = v * Eu;
        b.x = _ * Math.cos(w), b.y = _ * Math.sin(w);
      }
      (isNaN(b.vx) || isNaN(b.vy)) && (b.vx = b.vy = 0);
    }
  }
  function y(v) {
    return v.initialize && v.initialize(e2, p), v;
  }
  return g(), t = { tick: l, restart: function() {
    return c.restart(f), t;
  }, stop: function() {
    return c.stop(), t;
  }, nodes: function(v) {
    return arguments.length ? (e2 = v, g(), s.forEach(y), t) : e2;
  }, alpha: function(v) {
    return arguments.length ? (n = +v, t) : n;
  }, alphaMin: function(v) {
    return arguments.length ? (r = +v, t) : r;
  }, alphaDecay: function(v) {
    return arguments.length ? (i = +v, t) : +i;
  }, alphaTarget: function(v) {
    return arguments.length ? (a = +v, t) : a;
  }, velocityDecay: function(v) {
    return arguments.length ? (o = 1 - v, t) : 1 - o;
  }, randomSource: function(v) {
    return arguments.length ? (p = v, s.forEach(y), t) : p;
  }, force: function(v, h) {
    return arguments.length > 1 ? (h == null ? s.delete(v) : s.set(v, y(h)), t) : s.get(v);
  }, find: function(v, h, b) {
    var _ = 0, w = e2.length, C, z, $, R, k;
    for (b == null ? b = 1 / 0 : b *= b, _ = 0; _ < w; ++_) R = e2[_], C = v - R.x, z = h - R.y, $ = C * C + z * z, $ < b && (k = R, b = $);
    return k;
  }, on: function(v, h) {
    return arguments.length > 1 ? (u.on(v, h), t) : u.on(v);
  } };
}
function Tu() {
  var e2, t, n, r, i = ln(-30), a, o = 1, s = 1 / 0, c = 0.81;
  function u(g) {
    var y, v = e2.length, h = oa(e2, Mu, Su).visitAfter(f);
    for (r = g, y = 0; y < v; ++y) t = e2[y], h.visit(l);
  }
  function p() {
    if (e2) {
      var g, y = e2.length, v;
      for (a = new Array(y), g = 0; g < y; ++g) v = e2[g], a[v.index] = +i(v, g, e2);
    }
  }
  function f(g) {
    var y = 0, v, h, b = 0, _, w, C;
    if (g.length) {
      for (_ = w = C = 0; C < 4; ++C) (v = g[C]) && (h = Math.abs(v.value)) && (y += v.value, b += h, _ += h * v.x, w += h * v.y);
      g.x = _ / b, g.y = w / b;
    } else {
      v = g, v.x = v.data.x, v.y = v.data.y;
      do
        y += a[v.data.index];
      while (v = v.next);
    }
    g.value = y;
  }
  function l(g, y, v, h) {
    if (!g.value) return true;
    var b = g.x - t.x, _ = g.y - t.y, w = h - y, C = b * b + _ * _;
    if (w * w / c < C) return C < s && (b === 0 && (b = It(n), C += b * b), _ === 0 && (_ = It(n), C += _ * _), C < o && (C = Math.sqrt(o * C)), t.vx += b * g.value * r / C, t.vy += _ * g.value * r / C), true;
    if (g.length || C >= s) return;
    (g.data !== t || g.next) && (b === 0 && (b = It(n), C += b * b), _ === 0 && (_ = It(n), C += _ * _), C < o && (C = Math.sqrt(o * C)));
    do
      g.data !== t && (w = a[g.data.index] * r / C, t.vx += b * w, t.vy += _ * w);
    while (g = g.next);
  }
  return u.initialize = function(g, y) {
    e2 = g, n = y, p();
  }, u.strength = function(g) {
    return arguments.length ? (i = typeof g == "function" ? g : ln(+g), p(), u) : i;
  }, u.distanceMin = function(g) {
    return arguments.length ? (o = g * g, u) : Math.sqrt(o);
  }, u.distanceMax = function(g) {
    return arguments.length ? (s = g * g, u) : Math.sqrt(s);
  }, u.theta = function(g) {
    return arguments.length ? (c = g * g, u) : Math.sqrt(c);
  }, u;
}
function fi(e2, t) {
  (t == null || t > e2.length) && (t = e2.length);
  for (var n = 0, r = Array(t); n < t; n++) r[n] = e2[n];
  return r;
}
function Nu(e2, t) {
  var n = typeof Symbol < "u" && e2[Symbol.iterator] || e2["@@iterator"];
  if (n) return (n = n.call(e2)).next.bind(n);
  if (Array.isArray(e2) || (n = function(i, a) {
    if (i) {
      if (typeof i == "string") return fi(i, a);
      var o = {}.toString.call(i).slice(8, -1);
      return o === "Object" && i.constructor && (o = i.constructor.name), o === "Map" || o === "Set" ? Array.from(i) : o === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(o) ? fi(i, a) : void 0;
    }
  }(e2)) || t) {
    n && (e2 = n);
    var r = 0;
    return function() {
      return r >= e2.length ? { done: true } : { done: false, value: e2[r++] };
    };
  }
  throw new TypeError(`Invalid attempt to iterate non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`);
}
function jn() {
  return jn = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, jn.apply(null, arguments);
}
var Pu = { nivo: ["#e8c1a0", "#f47560", "#f1e15b", "#e8a838", "#61cdbb", "#97e3d5"], category10: Qi, accent: Ji, dark2: Zi, paired: Ki, pastel1: Xi, pastel2: Vi, set1: qi, set2: Yi, set3: gn, tableau10: Ui }, Au = { brown_blueGreen: jt, purpleRed_green: zt, pink_yellowGreen: kt, purple_orange: Ct, red_blue: wt, red_grey: _t, red_yellow_blue: xt, red_yellow_green: yt, spectral: bt }, Iu = { brown_blueGreen: lo, purpleRed_green: so, pink_yellowGreen: ao, purple_orange: oo, red_blue: io, red_grey: ro, red_yellow_blue: no, red_yellow_green: to, spectral: eo }, Bu = { blues: mt, greens: vt, greys: gt, oranges: pt, purples: ht, reds: ft, blue_green: ct, blue_purple: dt, green_blue: ut, orange_red: lt, purple_blue_green: st, purple_blue: at, purple_red: ot, red_purple: it, yellow_green_blue: rt, yellow_green: nt, yellow_orange_brown: tt, yellow_orange_red: et }, Fu = { blues: No, greens: To, greys: Wo, oranges: Eo, purples: Oo, reds: So, turbo: Mo, viridis: Ro, inferno: Lo, magma: $o, plasma: jo, cividis: zo, warm: ko, cool: Co, cubehelixDefault: wo, blue_green: _o, blue_purple: xo, green_blue: yo, orange_red: bo, purple_blue_green: mo, purple_blue: vo, purple_red: go, red_purple: po, yellow_green_blue: ho, yellow_green: fo, yellow_orange_brown: co, yellow_orange_red: uo };
jn({}, Pu, Au, Bu);
var Du = { rainbow: Ao, sinebow: Po };
jn({}, Iu, Fu, Du);
var Hu = function(e2) {
  return e2.theme !== void 0;
}, Gu = function(e2) {
  return e2.from !== void 0;
}, Uu = function(e2, t) {
  if (typeof e2 == "function") return e2;
  if (On(e2)) {
    if (Hu(e2)) {
      if (t === void 0) throw new Error("Unable to use color from theme as no theme was provided");
      var n = Ue(t, e2.theme);
      if (n === void 0) throw new Error("Color from theme is undefined at path: '" + e2.theme + "'");
      return function() {
        return n;
      };
    }
    if (Gu(e2)) {
      var r = function(c) {
        return Ue(c, e2.from);
      };
      if (Array.isArray(e2.modifiers)) {
        for (var i, a = [], o = function() {
          var c = i.value, u = c[0], p = c[1];
          if (u === "brighter") a.push(function(f) {
            return f.brighter(p);
          });
          else if (u === "darker") a.push(function(f) {
            return f.darker(p);
          });
          else {
            if (u !== "opacity") throw new Error("Invalid color modifier: '" + u + "', must be one of: 'brighter', 'darker', 'opacity'");
            a.push(function(f) {
              return f.opacity = p, f;
            });
          }
        }, s = Nu(e2.modifiers); !(i = s()).done; ) o();
        return a.length === 0 ? r : function(c) {
          return a.reduce(function(u, p) {
            return p(u);
          }, Gi(r(c))).toString();
        };
      }
      return r;
    }
    throw new Error("Invalid color spec, you should either specify 'theme' or 'from' when using a config object");
  }
  return function() {
    return e2;
  };
}, hi = function(e2, t) {
  return m.useMemo(function() {
    return Uu(e2, t);
  }, [e2, t]);
}, Yu = ps, qu = Io;
function Vu(e2, t) {
  return e2 && Yu(e2, t, qu);
}
var Xu = Vu, Ku = gs;
function Zu(e2, t) {
  return function(n, r) {
    if (n == null) return n;
    if (!Ku(n)) return e2(n, r);
    for (var i = n.length, a = t ? i : -1, o = Object(n); (t ? a-- : ++a < i) && r(o[a], a, o) !== false; ) ;
    return n;
  };
}
var Ju = Zu, Qu = Xu, ed = Ju, td = ed(Qu), nd = td, rd = nd;
function id(e2, t) {
  var n = [];
  return rd(e2, function(r, i, a) {
    t(r, i, a) && n.push(r);
  }), n;
}
var od = id, ad = vs, sd = Bo, ld = 1, ud = 2;
function dd(e2, t, n, r) {
  var i = n.length, a = i, o = !r;
  if (e2 == null) return !a;
  for (e2 = Object(e2); i--; ) {
    var s = n[i];
    if (o && s[2] ? s[1] !== e2[s[0]] : !(s[0] in e2)) return false;
  }
  for (; ++i < a; ) {
    s = n[i];
    var c = s[0], u = e2[c], p = s[1];
    if (o && s[2]) {
      if (u === void 0 && !(c in e2)) return false;
    } else {
      var f = new ad();
      if (r) var l = r(u, p, c, e2, t, f);
      if (!(l === void 0 ? sd(p, u, ld | ud, r, f) : l)) return false;
    }
  }
  return true;
}
var cd = dd, fd = ms;
function hd(e2) {
  return e2 === e2 && !fd(e2);
}
var ca = hd, pd = ca, gd = Io;
function vd(e2) {
  for (var t = gd(e2), n = t.length; n--; ) {
    var r = t[n], i = e2[r];
    t[n] = [r, i, pd(i)];
  }
  return t;
}
var md = vd;
function bd(e2, t) {
  return function(n) {
    return n == null ? false : n[e2] === t && (t !== void 0 || e2 in Object(n));
  };
}
var fa = bd, yd = cd, xd = md, _d = fa;
function wd(e2) {
  var t = xd(e2);
  return t.length == 1 && t[0][2] ? _d(t[0][0], t[0][1]) : function(n) {
    return n === e2 || yd(n, e2, t);
  };
}
var Cd = wd, kd = Bo, zd = bs, jd = ys, $d = Fo, Ld = ca, Rd = fa, Md = Or, Sd = 1, Od = 2;
function Ed(e2, t) {
  return $d(e2) && Ld(t) ? Rd(Md(e2), t) : function(n) {
    var r = zd(n, e2);
    return r === void 0 && r === t ? jd(n, e2) : kd(t, r, Sd | Od);
  };
}
var Wd = Ed;
function Td(e2) {
  return function(t) {
    return t == null ? void 0 : t[e2];
  };
}
var Nd = Td, Pd = Do;
function Ad(e2) {
  return function(t) {
    return Pd(t, e2);
  };
}
var Id = Ad, Bd = Nd, Fd = Id, Dd = Fo, Hd = Or;
function Gd(e2) {
  return Dd(e2) ? Bd(Hd(e2)) : Fd(e2);
}
var Ud = Gd, Yd = Cd, qd = Wd, Vd = xs, Xd = Ho, Kd = Ud;
function Zd(e2) {
  return typeof e2 == "function" ? e2 : e2 == null ? Vd : typeof e2 == "object" ? Xd(e2) ? qd(e2[0], e2[1]) : Yd(e2) : Kd(e2);
}
var Jd = Zd, Qd = _s, ec = od, tc = Jd, nc = Ho;
function rc(e2, t) {
  var n = nc(e2) ? Qd : ec;
  return n(e2, tc(t));
}
var ic = rc;
const oc = En(ic);
var ac = Cs, sc = ws, lc = "[object Number]";
function uc(e2) {
  return typeof e2 == "number" || sc(e2) && ac(e2) == lc;
}
var dc = uc;
const pi = En(dc);
function cc(e2, t, n) {
  var r = -1, i = e2.length;
  t < 0 && (t = -t > i ? 0 : i + t), n = n > i ? i : n, n < 0 && (n += i), i = t > n ? 0 : n - t >>> 0, t >>>= 0;
  for (var a = Array(i); ++r < i; ) a[r] = e2[r + t];
  return a;
}
var ha = cc, fc = Do, hc = ha;
function pc(e2, t) {
  return t.length < 2 ? e2 : fc(e2, hc(t, 0, -1));
}
var gc = pc, vc = Go, mc = ks, bc = gc, yc = Or;
function xc(e2, t) {
  return t = vc(t, e2), e2 = bc(e2, t), e2 == null || delete e2[yc(mc(t))];
}
var _c = xc, wc = zs;
function Cc(e2) {
  return wc(e2) ? void 0 : e2;
}
var kc = Cc, zc = $s, jc = Ms, $c = _c, Lc = Go, Rc = Ls, Mc = kc, Sc = js, Oc = Rs, Ec = 1, Wc = 2, Tc = 4, Nc = Sc(function(e2, t) {
  var n = {};
  if (e2 == null) return n;
  var r = false;
  t = zc(t, function(a) {
    return a = Lc(a, e2), r || (r = a.length > 1), a;
  }), Rc(e2, Oc(e2), n), r && (n = jc(n, Ec | Wc | Tc, Mc));
  for (var i = t.length; i--; ) $c(n, t[i]);
  return n;
}), Pc = Nc;
const Gr = En(Pc);
function Nt() {
  return Nt = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Nt.apply(null, arguments);
}
var Ac = ["basic", "chip", "container", "table", "tableCell", "tableCellValue"], Ic = { pointerEvents: "none", position: "absolute", zIndex: 10, top: 0, left: 0 }, gi = function(e2, t) {
  return "translate(" + e2 + "px, " + t + "px)";
}, Bc = m.memo(function(e2) {
  var t, n = e2.position, r = e2.anchor, i = e2.children, a = X(), o = $t(), s = o.animate, c = o.config, u = df(), p = u[0], f = u[1], l = m.useRef(false), g = void 0, y = false, v = f.width > 0 && f.height > 0, h = Math.round(n[0]), b = Math.round(n[1]);
  v && (r === "top" ? (h -= f.width / 2, b -= f.height + 14) : r === "right" ? (h += 14, b -= f.height / 2) : r === "bottom" ? (h -= f.width / 2, b += 14) : r === "left" ? (h -= f.width + 14, b -= f.height / 2) : r === "center" && (h -= f.width / 2, b -= f.height / 2), g = { transform: gi(h, b) }, l.current || (y = true), l.current = [h, b]);
  var _ = Pe({ to: g, config: c, immediate: !s || y }), w = a.tooltip;
  w.basic, w.chip, w.container, w.table, w.tableCell, w.tableCellValue;
  var C = function($, R) {
    if ($ == null) return {};
    var k = {};
    for (var j in $) if ({}.hasOwnProperty.call($, j)) {
      if (R.indexOf(j) !== -1) continue;
      k[j] = $[j];
    }
    return k;
  }(w, Ac), z = Nt({}, Ic, C, { transform: (t = _.transform) != null ? t : gi(h, b), opacity: _.transform ? 1 : 0 });
  return d.jsx(ee.div, { ref: p, style: z, children: i });
});
Bc.displayName = "TooltipWrapper";
var Fc = m.memo(function(e2) {
  var t = e2.size, n = t === void 0 ? 12 : t, r = e2.color, i = e2.style;
  return d.jsx("span", { style: Nt({ display: "block", width: n, height: n, background: r }, i === void 0 ? {} : i) });
});
m.memo(function(e2) {
  var t, n = e2.id, r = e2.value, i = e2.format, a = e2.enableChip, o = a !== void 0 && a, s = e2.color, c = e2.renderContent, u = X(), p = ff(i);
  if (typeof c == "function") t = c();
  else {
    var f = r;
    p !== void 0 && f !== void 0 && (f = p(f)), t = d.jsxs("div", { style: u.tooltip.basic, children: [o && d.jsx(Fc, { color: s, style: u.tooltip.chip }), f !== void 0 ? d.jsxs("span", { children: [n, ": ", d.jsx("strong", { children: "" + f })] }) : n] });
  }
  return d.jsx("div", { style: u.tooltip.container, role: "tooltip", children: t });
});
var Dc = { width: "100%", borderCollapse: "collapse" }, Hc = m.memo(function(e2) {
  var t, n = e2.title, r = e2.rows, i = r === void 0 ? [] : r, a = e2.renderContent, o = X();
  return i.length ? (t = typeof a == "function" ? a() : d.jsxs("div", { children: [n && n, d.jsx("table", { style: Nt({}, Dc, o.tooltip.table), children: d.jsx("tbody", { children: i.map(function(s, c) {
    return d.jsx("tr", { children: s.map(function(u, p) {
      return d.jsx("td", { style: o.tooltip.tableCell, children: u }, p);
    }) }, c);
  }) }) })] }), d.jsx("div", { style: o.tooltip.container, children: t })) : null;
});
Hc.displayName = "TableTooltip";
var Qn = m.memo(function(e2) {
  var t = e2.x0, n = e2.x1, r = e2.y0, i = e2.y1, a = X(), o = $t(), s = o.animate, c = o.config, u = m.useMemo(function() {
    return Nt({}, a.crosshair.line, { pointerEvents: "none" });
  }, [a.crosshair.line]), p = Pe({ x1: t, x2: n, y1: r, y2: i, config: c, immediate: !s });
  return d.jsx(ee.line, Nt({}, p, { fill: "none", style: u }));
});
Qn.displayName = "CrosshairLine";
var Gc = m.memo(function(e2) {
  var t, n, r = e2.width, i = e2.height, a = e2.type, o = e2.x, s = e2.y;
  return a === "cross" ? (t = { x0: o, x1: o, y0: 0, y1: i }, n = { x0: 0, x1: r, y0: s, y1: s }) : a === "top-left" ? (t = { x0: o, x1: o, y0: 0, y1: s }, n = { x0: 0, x1: o, y0: s, y1: s }) : a === "top" ? t = { x0: o, x1: o, y0: 0, y1: s } : a === "top-right" ? (t = { x0: o, x1: o, y0: 0, y1: s }, n = { x0: o, x1: r, y0: s, y1: s }) : a === "right" ? n = { x0: o, x1: r, y0: s, y1: s } : a === "bottom-right" ? (t = { x0: o, x1: o, y0: s, y1: i }, n = { x0: o, x1: r, y0: s, y1: s }) : a === "bottom" ? t = { x0: o, x1: o, y0: s, y1: i } : a === "bottom-left" ? (t = { x0: o, x1: o, y0: s, y1: i }, n = { x0: 0, x1: o, y0: s, y1: s }) : a === "left" ? n = { x0: 0, x1: o, y0: s, y1: s } : a === "x" ? t = { x0: o, x1: o, y0: 0, y1: i } : a === "y" && (n = { x0: 0, x1: r, y0: s, y1: s }), d.jsxs(d.Fragment, { children: [t && d.jsx(Qn, { x0: t.x0, x1: t.x1, y0: t.y0, y1: t.y1 }), n && d.jsx(Qn, { x0: n.x0, x1: n.x1, y0: n.y0, y1: n.y1 })] });
});
Gc.displayName = "Crosshair";
m.createContext({ showTooltipAt: function() {
}, showTooltipFromEvent: function() {
}, hideTooltip: function() {
} });
var Uc = { isVisible: false, position: [null, null], content: null, anchor: null };
m.createContext(Uc);
let Ge;
typeof window < "u" ? Ge = window : typeof self < "u" ? Ge = self : Ge = global;
Ge.clearTimeout;
Ge.setTimeout;
Ge.cancelAnimationFrame || Ge.mozCancelAnimationFrame || Ge.webkitCancelAnimationFrame;
Ge.requestAnimationFrame || Ge.mozRequestAnimationFrame || Ge.webkitRequestAnimationFrame;
var Yc = m.createContext(), $t = function() {
  return m.useContext(Yc);
};
function Dt() {
  return Dt = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Dt.apply(null, arguments);
}
function pa(e2, t) {
  if (e2 == null) return {};
  var n = {};
  for (var r in e2) if ({}.hasOwnProperty.call(e2, r)) {
    if (t.indexOf(r) !== -1) continue;
    n[r] = e2[r];
  }
  return n;
}
var qc = ["id", "colors"], Vc = function(e2) {
  var t = e2.id, n = e2.colors, r = pa(e2, qc);
  return d.jsx("linearGradient", Dt({ id: t, x1: 0, x2: 0, y1: 0, y2: 1 }, r, { children: n.map(function(i) {
    var a = i.offset, o = i.color, s = i.opacity;
    return d.jsx("stop", { offset: a + "%", stopColor: o, stopOpacity: s !== void 0 ? s : 1 }, a);
  }) }));
}, Xc = { linearGradient: Vc }, Kt = { color: "#000000", background: "#ffffff", size: 4, padding: 4, stagger: false }, Kc = m.memo(function(e2) {
  var t = e2.id, n = e2.background, r = n === void 0 ? Kt.background : n, i = e2.color, a = i === void 0 ? Kt.color : i, o = e2.size, s = o === void 0 ? Kt.size : o, c = e2.padding, u = c === void 0 ? Kt.padding : c, p = e2.stagger, f = p === void 0 ? Kt.stagger : p, l = s + u, g = s / 2, y = u / 2;
  return f === true && (l = 2 * s + 2 * u), d.jsxs("pattern", { id: t, width: l, height: l, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: l, height: l, fill: r }), d.jsx("circle", { cx: y + g, cy: y + g, r: g, fill: a }), f && d.jsx("circle", { cx: 1.5 * u + s + g, cy: 1.5 * u + s + g, r: g, fill: a })] });
}), er = function(e2) {
  return e2 * Math.PI / 180;
}, Zc = function(e2) {
  return 180 * e2 / Math.PI;
}, Jc = function(e2, t) {
  return { x: Math.cos(e2) * t, y: Math.sin(e2) * t };
}, Qc = function(e2) {
  var t = e2 % 360;
  return t < 0 && (t += 360), t;
}, Zt = { spacing: 5, rotation: 0, background: "#000000", color: "#ffffff", lineWidth: 2 }, ef = m.memo(function(e2) {
  var t = e2.id, n = e2.spacing, r = n === void 0 ? Zt.spacing : n, i = e2.rotation, a = i === void 0 ? Zt.rotation : i, o = e2.background, s = o === void 0 ? Zt.background : o, c = e2.color, u = c === void 0 ? Zt.color : c, p = e2.lineWidth, f = p === void 0 ? Zt.lineWidth : p, l = Math.round(a) % 360, g = Math.abs(r);
  l > 180 ? l -= 360 : l > 90 ? l -= 180 : l < -180 ? l += 360 : l < -90 && (l += 180);
  var y, v = g, h = g;
  return l === 0 ? y = `
                M 0 0 L ` + v + ` 0
                M 0 ` + h + " L " + v + " " + h + `
            ` : l === 90 ? y = `
                M 0 0 L 0 ` + h + `
                M ` + v + " 0 L " + v + " " + h + `
            ` : (v = Math.abs(g / Math.sin(er(l))), h = g / Math.sin(er(90 - l)), y = l > 0 ? `
                    M 0 ` + -h + " L " + 2 * v + " " + h + `
                    M ` + -v + " " + -h + " L " + v + " " + h + `
                    M ` + -v + " 0 L " + v + " " + 2 * h + `
                ` : `
                    M ` + -v + " " + h + " L " + v + " " + -h + `
                    M ` + -v + " " + 2 * h + " L " + 2 * v + " " + -h + `
                    M 0 ` + 2 * h + " L " + 2 * v + ` 0
                `), d.jsxs("pattern", { id: t, width: v, height: h, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: v, height: h, fill: s, stroke: "rgba(255, 0, 0, 0.1)", strokeWidth: 0 }), d.jsx("path", { d: y, strokeWidth: f, stroke: u, strokeLinecap: "square" })] });
}), Jt = { color: "#000000", background: "#ffffff", size: 4, padding: 4, stagger: false }, tf = m.memo(function(e2) {
  var t = e2.id, n = e2.color, r = n === void 0 ? Jt.color : n, i = e2.background, a = i === void 0 ? Jt.background : i, o = e2.size, s = o === void 0 ? Jt.size : o, c = e2.padding, u = c === void 0 ? Jt.padding : c, p = e2.stagger, f = p === void 0 ? Jt.stagger : p, l = s + u, g = u / 2;
  return f === true && (l = 2 * s + 2 * u), d.jsxs("pattern", { id: t, width: l, height: l, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: l, height: l, fill: a }), d.jsx("rect", { x: g, y: g, width: s, height: s, fill: r }), f && d.jsx("rect", { x: 1.5 * u + s, y: 1.5 * u + s, width: s, height: s, fill: r })] });
}), nf = { patternDots: Kc, patternLines: ef, patternSquares: tf }, rf = ["type"], vi = Dt({}, Xc, nf), of = m.memo(function(e2) {
  var t = e2.defs;
  return !t || t.length < 1 ? null : d.jsx("defs", { "aria-hidden": true, children: t.map(function(n) {
    var r = n.type, i = pa(n, rf);
    return vi[r] ? m.createElement(vi[r], Dt({ key: i.id }, i)) : null;
  }) });
});
m.forwardRef(function(e2, t) {
  var n = e2.width, r = e2.height, i = e2.margin, a = e2.defs, o = e2.children, s = e2.role, c = e2.ariaLabel, u = e2.ariaLabelledBy, p = e2.ariaDescribedBy, f = e2.isFocusable, l = X();
  return d.jsxs("svg", { xmlns: "http://www.w3.org/2000/svg", width: n, height: r, role: s, "aria-label": c, "aria-labelledby": u, "aria-describedby": p, focusable: f, tabIndex: f ? 0 : void 0, ref: t, children: [d.jsx(of, { defs: a }), d.jsx("rect", { width: n, height: r, fill: l.background }), d.jsx("g", { transform: "translate(" + i.left + "," + i.top + ")", children: o })] });
});
var af = m.memo(function(e2) {
  var t = e2.size, n = e2.color, r = e2.borderWidth, i = e2.borderColor;
  return d.jsx("circle", { r: t / 2, fill: n, stroke: i, strokeWidth: r, style: { pointerEvents: "none" } });
});
m.memo(function(e2) {
  var t = e2.x, n = e2.y, r = e2.symbol, i = r === void 0 ? af : r, a = e2.size, o = e2.datum, s = e2.color, c = e2.borderWidth, u = e2.borderColor, p = e2.label, f = e2.labelTextAnchor, l = f === void 0 ? "middle" : f, g = e2.labelYOffset, y = g === void 0 ? -12 : g, v = e2.ariaLabel, h = e2.ariaLabelledBy, b = e2.ariaDescribedBy, _ = e2.ariaHidden, w = e2.ariaDisabled, C = e2.isFocusable, z = C !== void 0 && C, $ = e2.tabIndex, R = $ === void 0 ? 0 : $, k = e2.onFocus, j = e2.onBlur, T = e2.testId, P = X(), N = $t(), L = N.animate, E = N.config, W = Pe({ transform: "translate(" + t + ", " + n + ")", config: E, immediate: !L }), S = m.useCallback(function(Y) {
    k == null ? void 0 : k(o, Y);
  }, [k, o]), O = m.useCallback(function(Y) {
    j == null ? void 0 : j(o, Y);
  }, [j, o]);
  return d.jsxs(ee.g, { transform: W.transform, style: { pointerEvents: "none" }, focusable: z, tabIndex: z ? R : void 0, "aria-label": v, "aria-labelledby": h, "aria-describedby": b, "aria-disabled": w, "aria-hidden": _, onFocus: z && k ? S : void 0, onBlur: z && j ? O : void 0, "data-testid": T, children: [m.createElement(i, { size: a, color: s, datum: o, borderWidth: c, borderColor: u }), p && d.jsx("text", { textAnchor: l, y, style: Fr(P.dots.text), children: p })] });
});
var sf = m.memo(function(e2) {
  var t = e2.width, n = e2.height, r = e2.axis, i = e2.scale, a = e2.value, o = e2.lineStyle, s = e2.textStyle, c = e2.legend, u = e2.legendNode, p = e2.legendPosition, f = p === void 0 ? "top-right" : p, l = e2.legendOffsetX, g = l === void 0 ? 14 : l, y = e2.legendOffsetY, v = y === void 0 ? 14 : y, h = e2.legendOrientation, b = h === void 0 ? "horizontal" : h, _ = X(), w = 0, C = 0, z = 0, $ = 0;
  if (r === "y" ? (z = i(a), C = t) : (w = i(a), $ = n), c && !u) {
    var R = function(k) {
      var j = k.axis, T = k.width, P = k.height, N = k.position, L = k.offsetX, E = k.offsetY, W = k.orientation, S = 0, O = 0, Y = W === "vertical" ? -90 : 0, M = "start";
      if (j === "x") switch (N) {
        case "top-left":
          S = -L, O = E, M = "end";
          break;
        case "top":
          O = -E, M = W === "horizontal" ? "middle" : "start";
          break;
        case "top-right":
          S = L, O = E, M = W === "horizontal" ? "start" : "end";
          break;
        case "right":
          S = L, O = P / 2, M = W === "horizontal" ? "start" : "middle";
          break;
        case "bottom-right":
          S = L, O = P - E, M = "start";
          break;
        case "bottom":
          O = P + E, M = W === "horizontal" ? "middle" : "end";
          break;
        case "bottom-left":
          O = P - E, S = -L, M = W === "horizontal" ? "end" : "start";
          break;
        case "left":
          S = -L, O = P / 2, M = W === "horizontal" ? "end" : "middle";
      }
      else switch (N) {
        case "top-left":
          S = L, O = -E, M = "start";
          break;
        case "top":
          S = T / 2, O = -E, M = W === "horizontal" ? "middle" : "start";
          break;
        case "top-right":
          S = T - L, O = -E, M = W === "horizontal" ? "end" : "start";
          break;
        case "right":
          S = T + L, M = W === "horizontal" ? "start" : "middle";
          break;
        case "bottom-right":
          S = T - L, O = E, M = "end";
          break;
        case "bottom":
          S = T / 2, O = E, M = W === "horizontal" ? "middle" : "end";
          break;
        case "bottom-left":
          S = L, O = E, M = W === "horizontal" ? "start" : "end";
          break;
        case "left":
          S = -L, M = W === "horizontal" ? "end" : "middle";
      }
      return { x: S, y: O, rotation: Y, textAnchor: M };
    }({ axis: r, width: t, height: n, position: f, offsetX: g, offsetY: v, orientation: b });
    u = d.jsx("text", { transform: "translate(" + R.x + ", " + R.y + ") rotate(" + R.rotation + ")", textAnchor: R.textAnchor, dominantBaseline: "central", style: s, children: c });
  }
  return d.jsxs("g", { transform: "translate(" + w + ", " + z + ")", children: [d.jsx("line", { x1: 0, x2: C, y1: 0, y2: $, stroke: _.markers.lineColor, strokeWidth: _.markers.lineStrokeWidth, style: o }), u] });
});
m.memo(function(e2) {
  var t = e2.markers, n = e2.width, r = e2.height, i = e2.xScale, a = e2.yScale;
  return t && t.length !== 0 ? t.map(function(o, s) {
    return d.jsx(sf, Dt({}, o, { width: n, height: r, scale: o.axis === "y" ? a : i }), s);
  }) : null;
});
var lf = function(e2) {
  var t = $t(), n = t.animate, r = t.config, i = function(s) {
    var c = m.useRef();
    return m.useEffect(function() {
      c.current = s;
    }, [s]), c.current;
  }(e2), a = m.useMemo(function() {
    return Ss(i, e2);
  }, [i, e2]), o = Pe({ from: { value: 0 }, to: { value: 1 }, reset: true, config: r, immediate: !n }).value;
  return Ke(o, a);
};
m.createContext(void 0);
var uf = { basis: Mr, basisClosed: Rr, basisOpen: Lr, bundle: $r, cardinal: jr, cardinalClosed: zr, cardinalOpen: kr, catmullRom: Cr, catmullRomClosed: wr, catmullRomOpen: _r, linear: xr, linearClosed: yr, monotoneX: br, monotoneY: mr, natural: vr, step: gr, stepAfter: pr, stepBefore: hr }, Ur = Object.keys(uf);
Ur.filter(function(e2) {
  return e2.endsWith("Closed");
});
Gt(Ur, "bundle", "basisClosed", "basisOpen", "cardinalClosed", "cardinalOpen", "catmullRomClosed", "catmullRomOpen", "linearClosed");
Gt(Ur, "bundle", "basisClosed", "basisOpen", "cardinalClosed", "cardinalOpen", "catmullRomClosed", "catmullRomOpen", "linearClosed");
x(jt), x(zt), x(kt), x(Ct), x(wt), x(_t), x(xt), x(yt), x(bt), x(mt), x(vt), x(gt), x(pt), x(ht), x(ft), x(ct), x(dt), x(ut), x(lt), x(st), x(at), x(ot), x(it), x(rt), x(nt), x(tt), x(et);
x(jt), x(zt), x(kt), x(Ct), x(wt), x(_t), x(xt), x(yt), x(bt), x(mt), x(vt), x(gt), x(pt), x(ht), x(ft), x(ct), x(dt), x(ut), x(lt), x(st), x(at), x(ot), x(it), x(rt), x(nt), x(tt), x(et);
Ot(gn);
var df = function() {
  var e2 = m.useRef(null), t = m.useState({ left: 0, top: 0, width: 0, height: 0 }), n = t[0], r = t[1], i = m.useState(function() {
    return typeof ResizeObserver > "u" ? null : new ResizeObserver(function(a) {
      var o = a[0];
      return r(o.contentRect);
    });
  })[0];
  return m.useEffect(function() {
    return e2.current && i !== null && i.observe(e2.current), function() {
      i !== null && i.disconnect();
    };
  }, [i]), [e2, n];
}, cf = function(e2) {
  return typeof e2 == "function" ? e2 : typeof e2 == "string" ? e2.indexOf("time:") === 0 ? cr(e2.slice("5")) : fr(e2) : function(t) {
    return "" + t;
  };
}, ff = function(e2) {
  return m.useMemo(function() {
    return cf(e2);
  }, [e2]);
};
function Ze() {
  return Ze = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Ze.apply(null, arguments);
}
var tr = { dotSize: 4, noteWidth: 120, noteTextOffset: 8 }, hf = function(e2) {
  var t = typeof e2;
  return m.isValidElement(e2) || t === "string" || t === "function" || t === "object";
}, pf = function(e2) {
  var t = typeof e2;
  return t === "string" || t === "function";
}, fn = function(e2) {
  return e2.type === "circle";
}, nr = function(e2) {
  return e2.type === "dot";
}, hn = function(e2) {
  return e2.type === "rect";
}, gf = function(e2) {
  var t = e2.data, n = e2.annotations, r = e2.getPosition, i = e2.getDimensions;
  return n.reduce(function(a, o) {
    var s = o.offset || 0;
    return [].concat(a, oc(t, o.match).map(function(c) {
      var u = r(c), p = i(c);
      return (fn(o) || hn(o)) && (p.size = p.size + 2 * s, p.width = p.width + 2 * s, p.height = p.height + 2 * s), Ze({}, Gr(o, ["match", "offset"]), u, p, { size: o.size || p.size, datum: c });
    }));
  }, []);
}, vf = function(e2, t, n, r) {
  var i = Math.atan2(r - t, n - e2);
  return Qc(Zc(i));
}, ga = function(e2) {
  var t, n, r = e2.x, i = e2.y, a = e2.noteX, o = e2.noteY, s = e2.noteWidth, c = s === void 0 ? tr.noteWidth : s, u = e2.noteTextOffset, p = u === void 0 ? tr.noteTextOffset : u;
  if (pi(a)) t = r + a;
  else {
    if (a.abs === void 0) throw new Error("noteX should be either a number or an object containing an 'abs' property");
    t = a.abs;
  }
  if (pi(o)) n = i + o;
  else {
    if (o.abs === void 0) throw new Error("noteY should be either a number or an object containing an 'abs' property");
    n = o.abs;
  }
  var f = r, l = i, g = vf(r, i, t, n);
  if (fn(e2)) {
    var y = Jc(er(g), e2.size / 2);
    f += y.x, l += y.y;
  }
  if (hn(e2)) {
    var v = Math.round((g + 90) / 45) % 8;
    v === 0 && (l -= e2.height / 2), v === 1 && (f += e2.width / 2, l -= e2.height / 2), v === 2 && (f += e2.width / 2), v === 3 && (f += e2.width / 2, l += e2.height / 2), v === 4 && (l += e2.height / 2), v === 5 && (f -= e2.width / 2, l += e2.height / 2), v === 6 && (f -= e2.width / 2), v === 7 && (f -= e2.width / 2, l -= e2.height / 2);
  }
  var h = t, b = t;
  return (g + 90) % 360 > 180 ? (h -= c, b -= c) : b += c, { points: [[f, l], [t, n], [b, n]], text: [h, n - p], angle: g + 90 };
}, mf = function(e2) {
  var t = e2.data, n = e2.annotations, r = e2.getPosition, i = e2.getDimensions;
  return m.useMemo(function() {
    return gf({ data: t, annotations: n, getPosition: r, getDimensions: i });
  }, [t, n, r, i]);
}, bf = function(e2) {
  var t = e2.annotations;
  return m.useMemo(function() {
    return t.map(function(n) {
      return Ze({}, n, { computed: ga(Ze({}, n)) });
    });
  }, [t]);
}, yf = function(e2) {
  return m.useMemo(function() {
    return ga(e2);
  }, [e2]);
}, xf = function(e2) {
  var t = e2.datum, n = e2.x, r = e2.y, i = e2.note, a = X(), o = $t(), s = o.animate, c = o.config, u = Pe({ x: n, y: r, config: c, immediate: !s });
  return typeof i == "function" ? m.createElement(i, { x: n, y: r, datum: t }) : d.jsxs(d.Fragment, { children: [a.annotations.text.outlineWidth > 0 && d.jsx(ee.text, { x: u.x, y: u.y, style: Ze({}, a.annotations.text, { strokeLinejoin: "round", strokeWidth: 2 * a.annotations.text.outlineWidth, stroke: a.annotations.text.outlineColor }), children: i }), d.jsx(ee.text, { x: u.x, y: u.y, style: Gr(a.annotations.text, ["outlineWidth", "outlineColor"]), children: i })] });
}, mi = function(e2) {
  var t = e2.points, n = e2.isOutline, r = n !== void 0 && n, i = X(), a = m.useMemo(function() {
    var c = t[0];
    return t.slice(1).reduce(function(u, p) {
      return u + " L" + p[0] + "," + p[1];
    }, "M" + c[0] + "," + c[1]);
  }, [t]), o = lf(a);
  if (r && i.annotations.link.outlineWidth <= 0) return null;
  var s = Ze({}, i.annotations.link);
  return r && (s.strokeLinecap = "square", s.strokeWidth = i.annotations.link.strokeWidth + 2 * i.annotations.link.outlineWidth, s.stroke = i.annotations.link.outlineColor, s.opacity = i.annotations.link.outlineOpacity), d.jsx(ee.path, { fill: "none", d: o, style: s });
}, _f = function(e2) {
  var t = e2.x, n = e2.y, r = e2.size, i = X(), a = $t(), o = a.animate, s = a.config, c = Pe({ x: t, y: n, radius: r / 2, config: s, immediate: !o });
  return d.jsxs(d.Fragment, { children: [i.annotations.outline.outlineWidth > 0 && d.jsx(ee.circle, { cx: c.x, cy: c.y, r: c.radius, style: Ze({}, i.annotations.outline, { fill: "none", strokeWidth: i.annotations.outline.strokeWidth + 2 * i.annotations.outline.outlineWidth, stroke: i.annotations.outline.outlineColor, opacity: i.annotations.outline.outlineOpacity }) }), d.jsx(ee.circle, { cx: c.x, cy: c.y, r: c.radius, style: i.annotations.outline })] });
}, wf = function(e2) {
  var t = e2.x, n = e2.y, r = e2.size, i = r === void 0 ? tr.dotSize : r, a = X(), o = $t(), s = o.animate, c = o.config, u = Pe({ x: t, y: n, radius: i / 2, config: c, immediate: !s });
  return d.jsxs(d.Fragment, { children: [a.annotations.outline.outlineWidth > 0 && d.jsx(ee.circle, { cx: u.x, cy: u.y, r: u.radius, style: Ze({}, a.annotations.outline, { fill: "none", strokeWidth: 2 * a.annotations.outline.outlineWidth, stroke: a.annotations.outline.outlineColor, opacity: a.annotations.outline.outlineOpacity }) }), d.jsx(ee.circle, { cx: u.x, cy: u.y, r: u.radius, style: a.annotations.symbol })] });
}, Cf = function(e2) {
  var t = e2.x, n = e2.y, r = e2.width, i = e2.height, a = e2.borderRadius, o = a === void 0 ? 6 : a, s = X(), c = $t(), u = c.animate, p = c.config, f = Pe({ x: t - r / 2, y: n - i / 2, width: r, height: i, config: p, immediate: !u });
  return d.jsxs(d.Fragment, { children: [s.annotations.outline.outlineWidth > 0 && d.jsx(ee.rect, { x: f.x, y: f.y, rx: o, ry: o, width: f.width, height: f.height, style: Ze({}, s.annotations.outline, { fill: "none", strokeWidth: s.annotations.outline.strokeWidth + 2 * s.annotations.outline.outlineWidth, stroke: s.annotations.outline.outlineColor, opacity: s.annotations.outline.outlineOpacity }) }), d.jsx(ee.rect, { x: f.x, y: f.y, rx: o, ry: o, width: f.width, height: f.height, style: s.annotations.outline })] });
}, kf = function(e2) {
  var t = e2.datum, n = e2.x, r = e2.y, i = e2.note, a = yf(e2);
  if (!hf(i)) throw new Error("note should be a valid react element");
  return d.jsxs(d.Fragment, { children: [d.jsx(mi, { points: a.points, isOutline: true }), fn(e2) && d.jsx(_f, { x: n, y: r, size: e2.size }), nr(e2) && d.jsx(wf, { x: n, y: r, size: e2.size }), hn(e2) && d.jsx(Cf, { x: n, y: r, width: e2.width, height: e2.height, borderRadius: e2.borderRadius }), d.jsx(mi, { points: a.points }), d.jsx(xf, { datum: t, x: a.text[0], y: a.text[1], note: i })] });
}, bi = function(e2, t) {
  t.forEach(function(n, r) {
    var i = n[0], a = n[1];
    r === 0 ? e2.moveTo(i, a) : e2.lineTo(i, a);
  });
}, zf = function(e2, t) {
  var n = t.annotations, r = t.theme;
  n.length !== 0 && (e2.save(), n.forEach(function(i) {
    if (!pf(i.note)) throw new Error("note is invalid for canvas implementation");
    r.annotations.link.outlineWidth > 0 && (e2.lineCap = "square", e2.strokeStyle = r.annotations.link.outlineColor, e2.lineWidth = r.annotations.link.strokeWidth + 2 * r.annotations.link.outlineWidth, e2.beginPath(), bi(e2, i.computed.points), e2.stroke(), e2.lineCap = "butt"), fn(i) && r.annotations.outline.outlineWidth > 0 && (e2.strokeStyle = r.annotations.outline.outlineColor, e2.lineWidth = r.annotations.outline.strokeWidth + 2 * r.annotations.outline.outlineWidth, e2.beginPath(), e2.arc(i.x, i.y, i.size / 2, 0, 2 * Math.PI), e2.stroke()), nr(i) && r.annotations.symbol.outlineWidth > 0 && (e2.strokeStyle = r.annotations.symbol.outlineColor, e2.lineWidth = 2 * r.annotations.symbol.outlineWidth, e2.beginPath(), e2.arc(i.x, i.y, i.size / 2, 0, 2 * Math.PI), e2.stroke()), hn(i) && r.annotations.outline.outlineWidth > 0 && (e2.strokeStyle = r.annotations.outline.outlineColor, e2.lineWidth = r.annotations.outline.strokeWidth + 2 * r.annotations.outline.outlineWidth, e2.beginPath(), e2.rect(i.x - i.width / 2, i.y - i.height / 2, i.width, i.height), e2.stroke()), e2.strokeStyle = r.annotations.link.stroke, e2.lineWidth = r.annotations.link.strokeWidth, e2.beginPath(), bi(e2, i.computed.points), e2.stroke(), fn(i) && (e2.strokeStyle = r.annotations.outline.stroke, e2.lineWidth = r.annotations.outline.strokeWidth, e2.beginPath(), e2.arc(i.x, i.y, i.size / 2, 0, 2 * Math.PI), e2.stroke()), nr(i) && (e2.fillStyle = r.annotations.symbol.fill, e2.beginPath(), e2.arc(i.x, i.y, i.size / 2, 0, 2 * Math.PI), e2.fill()), hn(i) && (e2.strokeStyle = r.annotations.outline.stroke, e2.lineWidth = r.annotations.outline.strokeWidth, e2.beginPath(), e2.rect(i.x - i.width / 2, i.y - i.height / 2, i.width, i.height), e2.stroke()), typeof i.note == "function" ? i.note(e2, { datum: i.datum, x: i.computed.text[0], y: i.computed.text[1], theme: r }) : (e2.font = r.annotations.text.fontSize + "px " + r.annotations.text.fontFamily, e2.textAlign = "left", e2.textBaseline = "alphabetic", e2.fillStyle = r.annotations.text.fill, e2.strokeStyle = r.annotations.text.outlineColor, e2.lineWidth = 2 * r.annotations.text.outlineWidth, r.annotations.text.outlineWidth > 0 && (e2.lineJoin = "round", e2.strokeText(i.note, i.computed.text[0], i.computed.text[1]), e2.lineJoin = "miter"), e2.fillText(i.note, i.computed.text[0], i.computed.text[1]));
  }), e2.restore());
};
function We() {
  return We = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, We.apply(null, arguments);
}
function bn(e2, t) {
  if (e2 == null) return {};
  var n = {};
  for (var r in e2) if ({}.hasOwnProperty.call(e2, r)) {
    if (t.indexOf(r) !== -1) continue;
    n[r] = e2[r];
  }
  return n;
}
var jf = m.memo(function(e2) {
  var t = e2.node, n = e2.animated, r = e2.onClick, i = e2.onMouseEnter, a = e2.onMouseMove, o = e2.onMouseLeave;
  return d.jsx(ee.circle, { "data-testid": "node." + t.id, transform: Ke([n.x, n.y, n.scale], function(s, c, u) {
    return "translate(" + s + "," + c + ") scale(" + u + ")";
  }), r: Ke([n.size], function(s) {
    return s / 2;
  }), fill: n.color, strokeWidth: n.borderWidth, stroke: n.borderColor, opacity: n.opacity, onClick: r ? function(s) {
    return r(t, s);
  } : void 0, onMouseEnter: i ? function(s) {
    return i(t, s);
  } : void 0, onMouseMove: a ? function(s) {
    return a(t, s);
  } : void 0, onMouseLeave: o ? function(s) {
    return o(t, s);
  } : void 0 });
}), $f = m.memo(function(e2) {
  var t = e2.link, n = e2.animated, r = e2.blendMode;
  return d.jsx(ee.line, { "data-testid": "link." + t.id, stroke: n.color, style: { mixBlendMode: r }, strokeWidth: t.thickness, strokeLinecap: "round", opacity: n.opacity, x1: n.x1, y1: n.y1, x2: n.x2, y2: n.y2 });
}), Me = { layers: ["links", "nodes", "annotations"], linkDistance: 30, centeringStrength: 1, repulsivity: 10, distanceMin: 1, distanceMax: 1 / 0, iterations: 120, nodeSize: 12, activeNodeSize: 18, inactiveNodeSize: 8, nodeColor: "#000000", nodeBorderWidth: 0, nodeBorderColor: { from: "color" }, linkThickness: 1, linkColor: { from: "source.color" }, isInteractive: true, defaultActiveNodeIds: [], nodeTooltip: function(e2) {
  var t = e2.node;
  return d.jsx(yl, { id: t.id, enableChip: true, color: t.color });
}, annotations: [], animate: true, motionConfig: "gentle", role: "img" }, ae = We({}, Me, { nodeComponent: jf, linkComponent: $f, linkBlendMode: "normal" }), se = We({}, Me, { renderNode: function(e2, t) {
  e2.fillStyle = t.color, e2.beginPath(), e2.arc(t.x, t.y, t.size / 2, 0, 2 * Math.PI), e2.fill(), t.borderWidth > 0 && (e2.strokeStyle = t.borderColor, e2.lineWidth = t.borderWidth, e2.stroke());
}, renderLink: function(e2, t) {
  e2.strokeStyle = t.color, e2.lineWidth = t.thickness, e2.beginPath(), e2.moveTo(t.source.x, t.source.y), e2.lineTo(t.target.x, t.target.y), e2.stroke();
}, pixelRatio: typeof window < "u" && window.devicePixelRatio || 1 }), Lf = ["index"], St = function(e2) {
  return m.useMemo(function() {
    return typeof e2 == "function" ? e2 : function() {
      return e2;
    };
  }, [e2]);
}, va = function(e2) {
  var t = e2.center, n = e2.nodes, r = e2.links, i = e2.linkDistance, a = i === void 0 ? Me.linkDistance : i, o = e2.centeringStrength, s = o === void 0 ? Me.centeringStrength : o, c = e2.repulsivity, u = c === void 0 ? Me.repulsivity : c, p = e2.distanceMin, f = p === void 0 ? Me.distanceMin : p, l = e2.distanceMax, g = l === void 0 ? Me.distanceMax : l, y = e2.iterations, v = y === void 0 ? Me.iterations : y, h = e2.nodeSize, b = h === void 0 ? Me.nodeSize : h, _ = e2.activeNodeSize, w = _ === void 0 ? Me.activeNodeSize : _, C = e2.inactiveNodeSize, z = C === void 0 ? Me.inactiveNodeSize : C, $ = e2.nodeColor, R = $ === void 0 ? Me.nodeColor : $, k = e2.nodeBorderWidth, j = k === void 0 ? Me.nodeBorderWidth : k, T = e2.nodeBorderColor, P = T === void 0 ? Me.nodeBorderColor : T, N = e2.linkThickness, L = N === void 0 ? Me.linkThickness : N, E = e2.linkColor, W = E === void 0 ? Me.linkColor : E, S = e2.isInteractive, O = S === void 0 ? Me.isInteractive : S, Y = e2.defaultActiveNodeIds, M = Y === void 0 ? Me.defaultActiveNodeIds : Y, je = m.useState(null), ye = je[0], $e = je[1], xe = m.useState(null), Ce = xe[0], ke = xe[1], ze = function(F) {
    var ne = F.linkDistance, H = F.centeringStrength, q = F.repulsivity, G = F.distanceMin, we = F.distanceMax, A = F.center, U = St(ne), re = A[0], ie = A[1];
    return m.useMemo(function() {
      return { link: yu().distance(function(I) {
        return U(I.data);
      }).strength(H), charge: Tu().strength(-q).distanceMin(G).distanceMax(we), center: tu(re, ie) };
    }, [U, H, q, G, we, re, ie]);
  }({ linkDistance: a, centeringStrength: s, repulsivity: u, distanceMin: f, distanceMax: g, center: t });
  m.useEffect(function() {
    var F = n.map(function(q) {
      return { id: q.id, data: We({}, q), index: 0, x: 0, y: 0, vx: 0, vy: 0 };
    }), ne = r.map(function(q) {
      return { data: We({}, q), index: 0, source: F.find(function(G) {
        return G.id === q.source;
      }), target: F.find(function(G) {
        return G.id === q.target;
      }) };
    }), H = Wu(F).force("link", ze.link.links(ne)).force("charge", ze.charge).force("center", ze.center).stop();
    return H.tick(v), $e(F), ke(ne), function() {
      H.stop();
    };
  }, [n, r, ze, v, $e, ke]);
  var _e = m.useState(M), Oe = _e[0], de = _e[1], le = function(F) {
    var ne = F.size, H = F.activeSize, q = F.inactiveSize, G = F.color, we = F.borderWidth, A = F.borderColor, U = F.isInteractive, re = F.activeNodeIds, ie = X(), I = St(ne), Z = St(G), ue = St(we), J = hi(A, ie), D = m.useCallback(function(V) {
      var be = Z(V.data);
      return { size: I(V.data), color: be, borderWidth: ue(V.data), borderColor: J(We({}, V, { color: be })) };
    }, [I, Z, ue, J]), B = St(H), oe = m.useCallback(function(V) {
      var be = Z(V.data);
      return { size: B(V.data), color: be, borderWidth: ue(V.data), borderColor: J(We({}, V, { color: be })) };
    }, [B, Z, ue, J]), ve = St(q), me = m.useCallback(function(V) {
      var be = Z(V.data);
      return { size: ve(V.data), color: be, borderWidth: ue(V.data), borderColor: J(We({}, V, { color: be })) };
    }, [ve, Z, ue, J]);
    return m.useCallback(function(V) {
      return U && re.length !== 0 ? re.includes(V.id) ? oe(V) : me(V) : D(V);
    }, [D, oe, me, U, re]);
  }({ size: b, activeSize: w, inactiveSize: z, color: R, borderWidth: j, borderColor: P, isInteractive: O, activeNodeIds: Oe }), ge = m.useMemo(function() {
    return ye === null ? null : ye.map(function(F) {
      return We({}, F, le(F));
    });
  }, [ye, le]), Ee = X(), Le = St(L), Re = hi(W, Ee), te = m.useMemo(function() {
    return Ce === null || ge === null ? null : Ce.map(function(F) {
      var ne = F.index, H = bn(F, Lf), q = { id: H.source.id + "." + H.target.id, data: H.data, index: ne, source: ge.find(function(G) {
        return G.id === H.source.id;
      }), target: ge.find(function(G) {
        return G.id === H.target.id;
      }) };
      return We({}, q, { thickness: Le(q), color: Re(q) });
    });
  }, [Ce, ge, Le, Re]);
  return { nodes: ge, links: te, activeNodeIds: Oe, setActiveNodeIds: de };
}, Rf = function(e2) {
  return { x: e2.x, y: e2.y };
}, Mf = function(e2) {
  return { size: e2.size, width: e2.size, height: e2.size };
}, ma = function(e2, t) {
  return mf({ data: e2, annotations: t, getPosition: Rf, getDimensions: Mf });
}, Sf = function(e2) {
  var t = e2.links, n = e2.linkComponent, r = e2.blendMode, i = mn(), a = i.animate, o = i.config, s = m.useMemo(function() {
    return [function(f) {
      return { x1: f.source.x, y1: f.source.y, x2: f.source.x, y2: f.source.y, color: f.color, opacity: 0 };
    }, function(f) {
      return { x1: f.source.x, y1: f.source.y, x2: f.target.x, y2: f.target.y, color: f.color, opacity: 1 };
    }];
  }, []), c = s[0], u = s[1], p = Er(t, { keys: function(f) {
    return f.id;
  }, initial: u, from: c, enter: u, update: u, expires: true, config: o, immediate: !a });
  return d.jsx(d.Fragment, { children: p(function(f, l) {
    return m.createElement(n, { key: l.id, link: l, animated: f, blendMode: r });
  }) });
}, Of = function(e2) {
  var t = e2.nodes, n = e2.nodeComponent, r = e2.onMouseEnter, i = e2.onMouseMove, a = e2.onMouseLeave, o = e2.onClick, s = e2.tooltip, c = e2.setActiveNodeIds, u = e2.isInteractive, p = mn(), f = p.animate, l = p.config, g = m.useMemo(function() {
    return [function(k) {
      return { x: k.x, y: k.y, size: k.size, color: k.color, borderWidth: k.borderWidth, borderColor: k.borderColor, scale: 0, opacity: 0 };
    }, function(k) {
      return { x: k.x, y: k.y, size: k.size, color: k.color, borderWidth: k.borderWidth, borderColor: k.borderColor, scale: 1, opacity: 1 };
    }, function(k) {
      return { x: k.x, y: k.y, size: k.size, color: k.color, borderWidth: k.borderWidth, borderColor: k.borderColor, scale: 0, opacity: 0 };
    }];
  }, []), y = g[0], v = g[1], h = g[2], b = Er(t, { keys: function(k) {
    return k.id;
  }, initial: v, from: y, enter: v, update: v, leave: h, config: l, immediate: !f }), _ = Jo(), w = _.showTooltipFromEvent, C = _.hideTooltip, z = m.useCallback(function(k, j) {
    w(m.createElement(s, { node: k }), j), c([k.id]), r == null ? void 0 : r(k, j);
  }, [w, s, c, r]), $ = m.useCallback(function(k, j) {
    w(m.createElement(s, { node: k }), j), i == null ? void 0 : i(k, j);
  }, [w, s, i]), R = m.useCallback(function(k, j) {
    C(), c([]), a == null ? void 0 : a(k, j);
  }, [C, c, a]);
  return d.jsx(d.Fragment, { children: b(function(k, j) {
    return m.createElement(n, { key: j.id, node: j, animated: k, onMouseEnter: u ? z : void 0, onMouseMove: u ? $ : void 0, onMouseLeave: u ? R : void 0, onClick: u ? o : void 0 });
  }) });
}, Ef = function(e2) {
  var t = e2.nodes, n = e2.annotations, r = ma(t, n);
  return d.jsx(d.Fragment, { children: r.map(function(i, a) {
    return d.jsx(kf, We({}, i), a);
  }) });
}, Wf = ["isInteractive", "animate", "motionConfig", "theme", "renderWrapper"], Tf = function(e2) {
  var t = e2.width, n = e2.height, r = e2.margin, i = e2.data, a = i.nodes, o = i.links, s = e2.linkDistance, c = s === void 0 ? ae.linkDistance : s, u = e2.centeringStrength, p = u === void 0 ? ae.centeringStrength : u, f = e2.repulsivity, l = f === void 0 ? ae.repulsivity : f, g = e2.distanceMin, y = g === void 0 ? ae.distanceMin : g, v = e2.distanceMax, h = v === void 0 ? ae.distanceMax : v, b = e2.iterations, _ = b === void 0 ? ae.iterations : b, w = e2.layers, C = w === void 0 ? ae.layers : w, z = e2.nodeComponent, $ = z === void 0 ? ae.nodeComponent : z, R = e2.nodeSize, k = R === void 0 ? ae.nodeSize : R, j = e2.activeNodeSize, T = j === void 0 ? ae.activeNodeSize : j, P = e2.inactiveNodeSize, N = P === void 0 ? ae.inactiveNodeSize : P, L = e2.nodeColor, E = L === void 0 ? ae.nodeColor : L, W = e2.nodeBorderWidth, S = W === void 0 ? ae.nodeBorderWidth : W, O = e2.nodeBorderColor, Y = O === void 0 ? ae.nodeBorderColor : O, M = e2.linkComponent, je = M === void 0 ? ae.linkComponent : M, ye = e2.linkThickness, $e = ye === void 0 ? ae.linkThickness : ye, xe = e2.linkColor, Ce = xe === void 0 ? ae.linkColor : xe, ke = e2.linkBlendMode, ze = ke === void 0 ? ae.linkBlendMode : ke, _e = e2.annotations, Oe = _e === void 0 ? ae.annotations : _e, de = e2.isInteractive, le = de === void 0 ? ae.isInteractive : de, ge = e2.defaultActiveNodeIds, Ee = ge === void 0 ? ae.defaultActiveNodeIds : ge, Le = e2.nodeTooltip, Re = Le === void 0 ? ae.nodeTooltip : Le, te = e2.onMouseEnter, F = e2.onMouseMove, ne = e2.onMouseLeave, H = e2.onClick, q = e2.role, G = q === void 0 ? ae.role : q, we = e2.ariaLabel, A = e2.ariaLabelledBy, U = e2.ariaDescribedBy, re = e2.forwardedRef, ie = ra(t, n, r), I = ie.margin, Z = ie.innerWidth, ue = ie.innerHeight, J = ie.outerWidth, D = ie.outerHeight, B = va({ center: [Z / 2, ue / 2], nodes: a, links: o, linkDistance: c, centeringStrength: p, repulsivity: l, distanceMin: y, distanceMax: h, iterations: _, nodeSize: k, activeNodeSize: T, inactiveNodeSize: N, nodeColor: E, nodeBorderWidth: S, nodeBorderColor: Y, linkThickness: $e, linkColor: Ce, isInteractive: le, defaultActiveNodeIds: Ee }), oe = B.nodes, ve = B.links, me = B.activeNodeIds, V = B.setActiveNodeIds, be = { links: null, nodes: null, annotations: null };
  C.includes("links") && ve !== null && (be.links = d.jsx(Sf, { links: ve, linkComponent: je, blendMode: ze }, "links")), C.includes("nodes") && oe !== null && (be.nodes = d.jsx(Of, { nodes: oe, nodeComponent: $, onMouseEnter: te, onMouseMove: F, onMouseLeave: ne, onClick: H, tooltip: Re, setActiveNodeIds: V, isInteractive: le }, "nodes")), C.includes("annotations") && oe !== null && (be.annotations = d.jsx(Ef, { nodes: oe, annotations: Oe }, "annotations"));
  var Fe = m.useMemo(function() {
    return { nodes: oe || [], links: ve || [], activeNodeIds: me, setActiveNodeIds: V };
  }, [oe, ve, me, V]);
  return d.jsx(Gl, { width: J, height: D, margin: I, role: G, ariaLabel: we, ariaLabelledBy: A, ariaDescribedBy: U, ref: re, children: C.map(function(Ae, Lt) {
    var Ye;
    return typeof Ae == "function" ? d.jsx(m.Fragment, { children: m.createElement(Ae, Fe) }, Lt) : (Ye = be == null ? void 0 : be[Ae]) != null ? Ye : null;
  }) });
}, ba = m.forwardRef(function(e2, t) {
  var n = e2.isInteractive, r = n === void 0 ? ae.isInteractive : n, i = e2.animate, a = i === void 0 ? ae.animate : i, o = e2.motionConfig, s = o === void 0 ? ae.motionConfig : o, c = e2.theme, u = e2.renderWrapper, p = bn(e2, Wf);
  return d.jsx(ea, { animate: a, isInteractive: r, motionConfig: s, renderWrapper: u, theme: c, children: d.jsx(Tf, We({}, p, { isInteractive: r, forwardedRef: t })) });
}), Nf = ["defaultWidth", "defaultHeight", "onResize", "debounceResize"];
m.forwardRef(function(e2, t) {
  var n = e2.defaultWidth, r = e2.defaultHeight, i = e2.onResize, a = e2.debounceResize, o = bn(e2, Nf);
  return d.jsx(ta, { defaultWidth: n, defaultHeight: r, onResize: i, debounceResize: a, children: function(s) {
    var c = s.width, u = s.height;
    return d.jsx(ba, We({}, o, { width: c, height: u, ref: t }));
  } });
});
var Pf = ["theme", "isInteractive", "animate", "motionConfig", "renderWrapper"], Af = function(e2) {
  var t = e2.width, n = e2.height, r = e2.margin, i = e2.pixelRatio, a = i === void 0 ? se.pixelRatio : i, o = e2.data, s = o.nodes, c = o.links, u = e2.linkDistance, p = u === void 0 ? se.linkDistance : u, f = e2.centeringStrength, l = f === void 0 ? se.centeringStrength : f, g = e2.repulsivity, y = g === void 0 ? se.repulsivity : g, v = e2.distanceMin, h = v === void 0 ? se.distanceMin : v, b = e2.distanceMax, _ = b === void 0 ? se.distanceMax : b, w = e2.iterations, C = w === void 0 ? se.iterations : w, z = e2.layers, $ = z === void 0 ? se.layers : z, R = e2.renderNode, k = R === void 0 ? se.renderNode : R, j = e2.nodeSize, T = j === void 0 ? se.nodeSize : j, P = e2.activeNodeSize, N = P === void 0 ? se.activeNodeSize : P, L = e2.inactiveNodeSize, E = L === void 0 ? se.inactiveNodeSize : L, W = e2.nodeColor, S = W === void 0 ? se.nodeColor : W, O = e2.nodeBorderWidth, Y = O === void 0 ? se.nodeBorderWidth : O, M = e2.nodeBorderColor, je = M === void 0 ? se.nodeBorderColor : M, ye = e2.renderLink, $e = ye === void 0 ? se.renderLink : ye, xe = e2.linkThickness, Ce = xe === void 0 ? se.linkThickness : xe, ke = e2.linkColor, ze = ke === void 0 ? se.linkColor : ke, _e = e2.annotations, Oe = _e === void 0 ? se.annotations : _e, de = e2.isInteractive, le = de === void 0 ? se.isInteractive : de, ge = e2.defaultActiveNodeIds, Ee = ge === void 0 ? se.defaultActiveNodeIds : ge, Le = e2.nodeTooltip, Re = Le === void 0 ? se.nodeTooltip : Le, te = e2.onClick, F = e2.role, ne = e2.forwardedRef, H = m.useRef(null), q = ra(t, n, r), G = q.margin, we = q.innerWidth, A = q.innerHeight, U = q.outerWidth, re = q.outerHeight, ie = va({ center: [we / 2, A / 2], nodes: s, links: c, linkDistance: p, centeringStrength: l, repulsivity: y, distanceMin: h, distanceMax: _, iterations: C, nodeSize: T, activeNodeSize: N, inactiveNodeSize: E, nodeColor: S, nodeBorderWidth: Y, nodeBorderColor: je, linkThickness: Ce, linkColor: ze, isInteractive: le, defaultActiveNodeIds: Ee }), I = ie.nodes, Z = ie.links, ue = ie.activeNodeIds, J = ie.setActiveNodeIds, D = ma(I, Oe), B = bf({ annotations: D }), oe = m.useMemo(function() {
    return { nodes: I || [], links: Z || [], activeNodeIds: ue, setActiveNodeIds: J };
  }, [I, Z, ue, J]), ve = X();
  m.useEffect(function() {
    if (H.current !== null) {
      H.current.width = U * a, H.current.height = re * a;
      var ce = H.current.getContext("2d");
      ce.scale(a, a), ce.fillStyle = ve.background, ce.fillRect(0, 0, U, re), ce.translate(G.left, G.top), $.forEach(function(fe) {
        fe === "links" && Z !== null ? Z.forEach(function(Rt) {
          return $e(ce, Rt);
        }) : fe === "nodes" && I !== null ? I.forEach(function(Rt) {
          return k(ce, Rt);
        }) : fe === "annotations" ? zf(ce, { annotations: B, theme: ve }) : typeof fe == "function" && I !== null && Z !== null && fe(ce, oe);
      });
    }
  }, [H, U, re, G.left, G.top, a, $, ve, I, Z, k, $e, B, oe]);
  var me = m.useCallback(function(ce) {
    if (H.current && I !== null) {
      var fe = Ql(H.current, ce), Rt = fe[0], Nn = fe[1];
      return I.find(function(Mt) {
        return Jl(Mt.x, Mt.y, Rt - G.left, Nn - G.top) <= Mt.size / 2;
      });
    }
  }, [H, G, I]), V = Jo(), be = V.showTooltipFromEvent, Fe = V.hideTooltip, Ae = m.useCallback(function(ce) {
    var fe = me(ce);
    fe ? (be(m.createElement(Re, { node: fe }), ce), J([fe.id])) : (Fe(), J([]));
  }, [me, be, Re, Fe, J]), Lt = m.useCallback(function() {
    Fe(), J([]);
  }, [Fe, J]), Ye = m.useCallback(function(ce) {
    if (te) {
      var fe = me(ce);
      fe && te(fe, ce);
    }
  }, [me, te]);
  return d.jsx("canvas", { ref: eu(H, ne), width: U * a, height: re * a, style: { width: U, height: re, cursor: le ? "auto" : "normal" }, onClick: le ? Ye : void 0, onMouseEnter: le ? Ae : void 0, onMouseLeave: le ? Lt : void 0, onMouseMove: le ? Ae : void 0, role: F });
}, If = m.forwardRef(function(e2, t) {
  var n = e2.theme, r = e2.isInteractive, i = r === void 0 ? se.isInteractive : r, a = e2.animate, o = a === void 0 ? se.animate : a, s = e2.motionConfig, c = s === void 0 ? se.motionConfig : s, u = e2.renderWrapper, p = bn(e2, Pf);
  return d.jsx(ea, { isInteractive: i, animate: o, motionConfig: c, theme: n, renderWrapper: u, children: d.jsx(Af, We({}, p, { isInteractive: i, forwardedRef: t })) });
}), Bf = ["defaultWidth", "defaultHeight", "onResize", "debounceResize"];
m.forwardRef(function(e2, t) {
  var n = e2.defaultWidth, r = e2.defaultHeight, i = e2.onResize, a = e2.debounceResize, o = bn(e2, Bf);
  return d.jsx(ta, { defaultWidth: n, defaultHeight: r, onResize: i, debounceResize: a, children: function(s) {
    var c = s.width, u = s.height;
    return d.jsx(If, We({}, o, { width: c, height: u, ref: t }));
  } });
});
const pn = "default", $n = 600, Qe = $n / 2, rr = 150;
let Ln = "sqrt", ya = 0.5, xa = false, Rn = true;
function Ff(e2) {
  return Number.isNaN(e2) ? NaN : e2 < 0 ? 0 : e2 > 1 ? 1 : e2;
}
function Df(e2) {
  return Math.sqrt(Math.sqrt(Ff(e2)));
}
function Hf(e2, t = 0.4, n = 0.5, r = 1e-6) {
  const i = (l) => Math.min(1 - r, Math.max(r, l)), a = i(e2), o = i(n), s = (l) => Math.log(l / (1 - l)), c = (l) => {
    if (l >= 0) return 1 / (1 + Math.exp(-l));
    {
      const g = Math.exp(l);
      return g / (1 + g);
    }
  }, u = s(o), p = t * (s(a) - u) + u, f = c(p);
  return f <= 0 ? 0 : f >= 1 ? 1 : f;
}
function _a(e2, t) {
  return e2 ?? (e2 = 0), Ln === "sqrt" ? e2 = Df(e2) : Ln === "log" && (e2 = Hf(e2, ya)), t ? `rgba(196, 107, 240, ${e2})` : `rgba(28, 231, 194, ${e2})`;
}
function yi(e2, t) {
  var _a2;
  const { peer_identities: n, peer_names: r, peer_throughput: i, total_throughput: a } = e2;
  if (!n || !r || !i || a == null) return;
  const o = [], s = t ? t.filter(({ id: u }) => u !== pn).slice(xa ? 1 : 0) : new Array(64).fill(null);
  for (let u = 0; u < s.length; u++) {
    const p = (_a2 = s[u]) == null ? void 0 : _a2.peerIdentity;
    p && (n.includes(p) || (s[u] = null));
  }
  let c = 0;
  for (let u = 0; u < n.length; u++) {
    const p = n[u];
    let f = s.find((l) => (l == null ? void 0 : l.peerIdentity) === n[u]);
    if (!f) {
      for (f = { id: p, peerIdentity: n[u] }; c < s.length && s[c] !== null; ) c++;
      s[c] = f, c++;
    }
    f.name = r == null ? void 0 : r[u], f.throughput = i == null ? void 0 : i[u], f.pct = (f.throughput ?? 0) / (a || 1), o.push({ source: p, target: pn });
  }
  return { nodes: s.filter((u) => !!u), links: o };
}
function xi(e2, t, n) {
  if (Rn) {
    const r = e2.isEgress ? 1.5 : 1, i = 2 * Math.PI * t / n;
    e2.x = Math.cos(i) * rr * r, e2.y = Math.sin(i) * rr * r;
  } else {
    const r = $n * 0.8;
    e2.isEgress ? e2.x = r / 2 : e2.x = -480 / 2, e2.y = t / n * r - r / 2;
  }
}
function Gf() {
  var _a2, _b;
  const e2 = Je(vn);
  sl(e2);
  const [t, n] = m.useState(false), [r, i] = m.useState(false), a = Je(Os), o = m.useRef(), s = m.useRef(), c = m.useMemo(() => {
    var _a3;
    if (!(e2 == null ? void 0 : e2.ingress)) return;
    const g = yi(e2.ingress, (_a3 = o.current) == null ? void 0 : _a3.nodes);
    if (!g) return;
    const { nodes: y, links: v } = g;
    return y.forEach((h, b) => {
      xi(h, b, y.length);
    }), performance.now(), { nodes: [{ id: pn }, ...y], links: v };
  }, [e2]);
  o.current = c;
  const u = m.useMemo(() => {
    var _a3;
    if (!(e2 == null ? void 0 : e2.egress)) return;
    const g = yi(e2.egress, (_a3 = s.current) == null ? void 0 : _a3.nodes);
    if (!g) return;
    const { nodes: y, links: v } = g;
    return y.forEach((h, b) => {
      h.isEgress = true, xi(h, b, y.length), h.id.indexOf("egress") < 0 && (h.id += "egress");
    }), v.forEach((h, b) => {
      h.source.indexOf("egress") < 0 && (h.source += "egress");
    }), { nodes: y, links: v };
  }, [e2]);
  s.current = u;
  const p = 13, f = m.useMemo(() => {
    if (!c) return;
    const l = { ...c, nodes: [...c.nodes], links: [...c.links] };
    return u && l.nodes && r && (l.nodes = [...l.nodes, ...u.nodes], Rn || (l.links = [...l.links, ...u.links])), l;
  }, [c, u, r]);
  return f ? d.jsxs("div", { children: [d.jsxs(Yo, { defaultValue: "sqrt", onValueChange: (l) => Ln = l, children: [d.jsx(wn, { value: "linear", children: "linear" }), d.jsx(wn, { value: "sqrt", children: "sqrt" }), d.jsx(wn, { value: "log", children: "log" })] }), d.jsx("div", { style: { width: "300px", padding: "8px 0" }, children: d.jsx(Es, { defaultValue: [0.5], onValueChange: (l) => {
    ya = l[0];
  }, min: 0, max: 1, step: 0.05, disabled: Ln !== "log" }) }), "Spin ", d.jsx(_n, { onCheckedChange: (l) => xa = l }), "Egress", " ", d.jsx(_n, { checked: r, onCheckedChange: i }), "Circular", " ", d.jsx(_n, { defaultChecked: true, onCheckedChange: (l) => Rn = l }), d.jsxs(He, { direction: "column", children: [d.jsxs(De, { children: ["Total throughput ingress:", " ", (_a2 = e2 == null ? void 0 : e2.ingress.total_throughput) == null ? void 0 : _a2.toLocaleString()] }), d.jsxs(De, { children: ["Total throughput egress:", " ", (_b = e2 == null ? void 0 : e2.egress.total_throughput) == null ? void 0 : _b.toLocaleString()] })] }), d.jsx(ba, { animate: t, height: $n, width: $n, data: f, linkDistance: (l) => rr, nodeSize: (l) => l.id === pn ? 70 : p, activeNodeSize: (l) => 2 * p, inactiveNodeSize: 0, margin: { top: 0, right: 0, bottom: 0, left: 0 }, centeringStrength: 2, repulsivity: 100, linkThickness: (l) => 2, nodeTooltip: ({ node: l }) => {
    var _a3, _b2;
    const g = a[l.data.peerIdentity ?? ""];
    return d.jsxs("div", { children: [d.jsx("div", { children: l.data.peerIdentity }), d.jsx("div", { children: l.data.name ?? ((_a3 = g.info) == null ? void 0 : _a3.name) }), d.jsxs("div", { children: [(_b2 = l.data.throughput) == null ? void 0 : _b2.toLocaleString(), " bytes/s"] })] });
  }, nodeComponent: Uf, linkComponent: Yf })] }) : null;
}
const Uf = ({ node: e2, animated: t, onClick: n, onMouseEnter: r, onMouseMove: i, onMouseLeave: a }) => {
  if (e2.data.id === pn) return d.jsx("circle", { cx: Qe, cy: Qe, r: "11", fill: "#1CE7C2" });
  const o = _a(e2.data.pct, e2.data.isEgress);
  return d.jsx("circle", { cx: (e2.data.x ?? 0) + Qe, cy: (e2.data.y ?? 0) + Qe, r: "7", fill: o, onClick: n ? (s) => n(e2, s) : void 0, onMouseEnter: r ? (s) => r(e2, s) : void 0, onMouseMove: i ? (s) => i(e2, s) : void 0, onMouseLeave: a ? (s) => a(e2, s) : void 0 });
}, Yf = ({ link: e2 }) => e2.source.data.isEgress && Rn ? null : d.jsx("line", { x1: Qe, y1: Qe, x2: (e2.source.data.x ?? 0) + Qe, y2: (e2.source.data.y ?? 0) + Qe, stroke: _a(e2.source.data.pct, e2.source.data.isEgress), strokeWidth: e2.thickness, strokeLinecap: "round" });
function Pt() {
  return Pt = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Pt.apply(null, arguments);
}
var qf = ["basic", "chip", "container", "table", "tableCell", "tableCellValue"], Vf = { pointerEvents: "none", position: "absolute", zIndex: 10, top: 0, left: 0 }, _i = function(e2, t) {
  return "translate(" + e2 + "px, " + t + "px)";
}, wa = m.memo(function(e2) {
  var t, n = e2.position, r = e2.anchor, i = e2.children, a = X(), o = Tn(), s = o.animate, c = o.config, u = zh(), p = u[0], f = u[1], l = m.useRef(false), g = void 0, y = false, v = f.width > 0 && f.height > 0, h = Math.round(n[0]), b = Math.round(n[1]);
  v && (r === "top" ? (h -= f.width / 2, b -= f.height + 14) : r === "right" ? (h += 14, b -= f.height / 2) : r === "bottom" ? (h -= f.width / 2, b += 14) : r === "left" ? (h -= f.width + 14, b -= f.height / 2) : r === "center" && (h -= f.width / 2, b -= f.height / 2), g = { transform: _i(h, b) }, l.current || (y = true), l.current = [h, b]);
  var _ = Pe({ to: g, config: c, immediate: !s || y }), w = a.tooltip;
  w.basic, w.chip, w.container, w.table, w.tableCell, w.tableCellValue;
  var C = function($, R) {
    if ($ == null) return {};
    var k = {};
    for (var j in $) if ({}.hasOwnProperty.call($, j)) {
      if (R.indexOf(j) !== -1) continue;
      k[j] = $[j];
    }
    return k;
  }(w, qf), z = Pt({}, Vf, C, { transform: (t = _.transform) != null ? t : _i(h, b), opacity: _.transform ? 1 : 0 });
  return d.jsx(ee.div, { ref: p, style: z, children: i });
});
wa.displayName = "TooltipWrapper";
var Xf = m.memo(function(e2) {
  var t = e2.size, n = t === void 0 ? 12 : t, r = e2.color, i = e2.style;
  return d.jsx("span", { style: Pt({ display: "block", width: n, height: n, background: r }, i === void 0 ? {} : i) });
}), Kf = m.memo(function(e2) {
  var t, n = e2.id, r = e2.value, i = e2.format, a = e2.enableChip, o = a !== void 0 && a, s = e2.color, c = e2.renderContent, u = X(), p = Ma(i);
  if (typeof c == "function") t = c();
  else {
    var f = r;
    p !== void 0 && f !== void 0 && (f = p(f)), t = d.jsxs("div", { style: u.tooltip.basic, children: [o && d.jsx(Xf, { color: s, style: u.tooltip.chip }), f !== void 0 ? d.jsxs("span", { children: [n, ": ", d.jsx("strong", { children: "" + f })] }) : n] });
  }
  return d.jsx("div", { style: u.tooltip.container, role: "tooltip", children: t });
}), Zf = { width: "100%", borderCollapse: "collapse" }, Jf = m.memo(function(e2) {
  var t, n = e2.title, r = e2.rows, i = r === void 0 ? [] : r, a = e2.renderContent, o = X();
  return i.length ? (t = typeof a == "function" ? a() : d.jsxs("div", { children: [n && n, d.jsx("table", { style: Pt({}, Zf, o.tooltip.table), children: d.jsx("tbody", { children: i.map(function(s, c) {
    return d.jsx("tr", { children: s.map(function(u, p) {
      return d.jsx("td", { style: o.tooltip.tableCell, children: u }, p);
    }) }, c);
  }) }) })] }), d.jsx("div", { style: o.tooltip.container, children: t })) : null;
});
Jf.displayName = "TableTooltip";
var ir = m.memo(function(e2) {
  var t = e2.x0, n = e2.x1, r = e2.y0, i = e2.y1, a = X(), o = Tn(), s = o.animate, c = o.config, u = m.useMemo(function() {
    return Pt({}, a.crosshair.line, { pointerEvents: "none" });
  }, [a.crosshair.line]), p = Pe({ x1: t, x2: n, y1: r, y2: i, config: c, immediate: !s });
  return d.jsx(ee.line, Pt({}, p, { fill: "none", style: u }));
});
ir.displayName = "CrosshairLine";
var Qf = m.memo(function(e2) {
  var t, n, r = e2.width, i = e2.height, a = e2.type, o = e2.x, s = e2.y;
  return a === "cross" ? (t = { x0: o, x1: o, y0: 0, y1: i }, n = { x0: 0, x1: r, y0: s, y1: s }) : a === "top-left" ? (t = { x0: o, x1: o, y0: 0, y1: s }, n = { x0: 0, x1: o, y0: s, y1: s }) : a === "top" ? t = { x0: o, x1: o, y0: 0, y1: s } : a === "top-right" ? (t = { x0: o, x1: o, y0: 0, y1: s }, n = { x0: o, x1: r, y0: s, y1: s }) : a === "right" ? n = { x0: o, x1: r, y0: s, y1: s } : a === "bottom-right" ? (t = { x0: o, x1: o, y0: s, y1: i }, n = { x0: o, x1: r, y0: s, y1: s }) : a === "bottom" ? t = { x0: o, x1: o, y0: s, y1: i } : a === "bottom-left" ? (t = { x0: o, x1: o, y0: s, y1: i }, n = { x0: 0, x1: o, y0: s, y1: s }) : a === "left" ? n = { x0: 0, x1: o, y0: s, y1: s } : a === "x" ? t = { x0: o, x1: o, y0: 0, y1: i } : a === "y" && (n = { x0: 0, x1: r, y0: s, y1: s }), d.jsxs(d.Fragment, { children: [t && d.jsx(ir, { x0: t.x0, x1: t.x1, y0: t.y0, y1: t.y1 }), n && d.jsx(ir, { x0: n.x0, x1: n.x1, y0: n.y0, y1: n.y1 })] });
});
Qf.displayName = "Crosshair";
var Ca = m.createContext({ showTooltipAt: function() {
}, showTooltipFromEvent: function() {
}, hideTooltip: function() {
} }), or = { isVisible: false, position: [null, null], content: null, anchor: null }, ka = m.createContext(or), eh = function(e2) {
  var t = m.useState(or), n = t[0], r = t[1], i = m.useCallback(function(s, c, u) {
    var p = c[0], f = c[1];
    u === void 0 && (u = "top"), r({ isVisible: true, position: [p, f], anchor: u, content: s });
  }, [r]), a = m.useCallback(function(s, c, u) {
    u === void 0 && (u = "top");
    var p = e2.current.getBoundingClientRect(), f = e2.current.offsetWidth, l = f === p.width ? 1 : f / p.width, g = "touches" in c ? c.touches[0] : c, y = g.clientX, v = g.clientY, h = (y - p.left) * l, b = (v - p.top) * l;
    u !== "left" && u !== "right" || (u = h < p.width / 2 ? "right" : "left"), r({ isVisible: true, position: [h, b], anchor: u, content: s });
  }, [e2, r]), o = m.useCallback(function() {
    r(or);
  }, [r]);
  return { actions: m.useMemo(function() {
    return { showTooltipAt: i, showTooltipFromEvent: a, hideTooltip: o };
  }, [i, a, o]), state: n };
}, za = function() {
  var e2 = m.useContext(Ca);
  if (e2 === void 0) throw new Error("useTooltip must be used within a TooltipProvider");
  return e2;
}, th = function() {
  var e2 = m.useContext(ka);
  if (e2 === void 0) throw new Error("useTooltipState must be used within a TooltipProvider");
  return e2;
}, nh = function(e2) {
  return e2.isVisible;
}, rh = function() {
  var e2 = th();
  return nh(e2) ? d.jsx(wa, { position: e2.position, anchor: e2.anchor, children: e2.content }) : null;
}, ih = function(e2) {
  var t = e2.container, n = e2.children, r = eh(t), i = r.actions, a = r.state;
  return d.jsx(Ca.Provider, { value: i, children: d.jsx(ka.Provider, { value: a, children: n }) });
};
let Be;
typeof window < "u" ? Be = window : typeof self < "u" ? Be = self : Be = global;
let ar = null, sr = null;
const wi = 20, Bn = Be.clearTimeout, Ci = Be.setTimeout, Fn = Be.cancelAnimationFrame || Be.mozCancelAnimationFrame || Be.webkitCancelAnimationFrame, ki = Be.requestAnimationFrame || Be.mozRequestAnimationFrame || Be.webkitRequestAnimationFrame;
Fn == null || ki == null ? (ar = Bn, sr = function(t) {
  return Ci(t, wi);
}) : (ar = function([t, n]) {
  Fn(t), Bn(n);
}, sr = function(t) {
  const n = ki(function() {
    Bn(r), t();
  }), r = Ci(function() {
    Fn(n), t();
  }, wi);
  return [n, r];
});
function oh(e2) {
  let t, n, r, i, a, o, s;
  const c = typeof document < "u" && document.attachEvent;
  if (!c) {
    o = function(b) {
      const _ = b.__resizeTriggers__, w = _.firstElementChild, C = _.lastElementChild, z = w.firstElementChild;
      C.scrollLeft = C.scrollWidth, C.scrollTop = C.scrollHeight, z.style.width = w.offsetWidth + 1 + "px", z.style.height = w.offsetHeight + 1 + "px", w.scrollLeft = w.scrollWidth, w.scrollTop = w.scrollHeight;
    }, a = function(b) {
      return b.offsetWidth !== b.__resizeLast__.width || b.offsetHeight !== b.__resizeLast__.height;
    }, s = function(b) {
      if (b.target.className && typeof b.target.className.indexOf == "function" && b.target.className.indexOf("contract-trigger") < 0 && b.target.className.indexOf("expand-trigger") < 0) return;
      const _ = this;
      o(this), this.__resizeRAF__ && ar(this.__resizeRAF__), this.__resizeRAF__ = sr(function() {
        a(_) && (_.__resizeLast__.width = _.offsetWidth, _.__resizeLast__.height = _.offsetHeight, _.__resizeListeners__.forEach(function(z) {
          z.call(_, b);
        }));
      });
    };
    let l = false, g = "";
    r = "animationstart";
    const y = "Webkit Moz O ms".split(" ");
    let v = "webkitAnimationStart animationstart oAnimationStart MSAnimationStart".split(" "), h = "";
    {
      const b = document.createElement("fakeelement");
      if (b.style.animationName !== void 0 && (l = true), l === false) {
        for (let _ = 0; _ < y.length; _++) if (b.style[y[_] + "AnimationName"] !== void 0) {
          h = y[_], g = "-" + h.toLowerCase() + "-", r = v[_], l = true;
          break;
        }
      }
    }
    n = "resizeanim", t = "@" + g + "keyframes " + n + " { from { opacity: 0; } to { opacity: 0; } } ", i = g + "animation: 1ms " + n + "; ";
  }
  const u = function(l) {
    if (!l.getElementById("detectElementResize")) {
      const g = (t || "") + ".resize-triggers { " + (i || "") + 'visibility: hidden; opacity: 0; } .resize-triggers, .resize-triggers > div, .contract-trigger:before { content: " "; display: block; position: absolute; top: 0; left: 0; height: 100%; width: 100%; overflow: hidden; z-index: -1; } .resize-triggers > div { background: #eee; overflow: auto; } .contract-trigger:before { width: 200%; height: 200%; }', y = l.head || l.getElementsByTagName("head")[0], v = l.createElement("style");
      v.id = "detectElementResize", v.type = "text/css", e2 != null && v.setAttribute("nonce", e2), v.styleSheet ? v.styleSheet.cssText = g : v.appendChild(l.createTextNode(g)), y.appendChild(v);
    }
  };
  return { addResizeListener: function(l, g) {
    if (c) l.attachEvent("onresize", g);
    else {
      if (!l.__resizeTriggers__) {
        const y = l.ownerDocument, v = Be.getComputedStyle(l);
        v && v.position === "static" && (l.style.position = "relative"), u(y), l.__resizeLast__ = {}, l.__resizeListeners__ = [], (l.__resizeTriggers__ = y.createElement("div")).className = "resize-triggers";
        const h = y.createElement("div");
        h.className = "expand-trigger", h.appendChild(y.createElement("div"));
        const b = y.createElement("div");
        b.className = "contract-trigger", l.__resizeTriggers__.appendChild(h), l.__resizeTriggers__.appendChild(b), l.appendChild(l.__resizeTriggers__), o(l), l.addEventListener("scroll", s, true), r && (l.__resizeTriggers__.__animationListener__ = function(w) {
          w.animationName === n && o(l);
        }, l.__resizeTriggers__.addEventListener(r, l.__resizeTriggers__.__animationListener__));
      }
      l.__resizeListeners__.push(g);
    }
  }, removeResizeListener: function(l, g) {
    if (c) l.detachEvent("onresize", g);
    else if (l.__resizeListeners__.splice(l.__resizeListeners__.indexOf(g), 1), !l.__resizeListeners__.length) {
      l.removeEventListener("scroll", s, true), l.__resizeTriggers__.__animationListener__ && (l.__resizeTriggers__.removeEventListener(r, l.__resizeTriggers__.__animationListener__), l.__resizeTriggers__.__animationListener__ = null);
      try {
        l.__resizeTriggers__ = !l.removeChild(l.__resizeTriggers__);
      } catch {
      }
    }
  } };
}
class ah extends m.Component {
  constructor(...t) {
    super(...t), this.state = { height: this.props.defaultHeight || 0, width: this.props.defaultWidth || 0 }, this._autoSizer = null, this._detectElementResize = null, this._didLogDeprecationWarning = false, this._parentNode = null, this._resizeObserver = null, this._timeoutId = null, this._onResize = () => {
      this._timeoutId = null;
      const { disableHeight: n, disableWidth: r, onResize: i } = this.props;
      if (this._parentNode) {
        const a = window.getComputedStyle(this._parentNode) || {}, o = parseFloat(a.paddingLeft || "0"), s = parseFloat(a.paddingRight || "0"), c = parseFloat(a.paddingTop || "0"), u = parseFloat(a.paddingBottom || "0"), p = this._parentNode.getBoundingClientRect(), f = p.height - c - u, l = p.width - o - s;
        if (!n && this.state.height !== f || !r && this.state.width !== l) {
          this.setState({ height: f, width: l });
          const g = () => {
            this._didLogDeprecationWarning || (this._didLogDeprecationWarning = true, console.warn("scaledWidth and scaledHeight parameters have been deprecated; use width and height instead"));
          };
          typeof i == "function" && i({ height: f, width: l, get scaledHeight() {
            return g(), f;
          }, get scaledWidth() {
            return g(), l;
          } });
        }
      }
    }, this._setRef = (n) => {
      this._autoSizer = n;
    };
  }
  componentDidMount() {
    const { nonce: t } = this.props, n = this._autoSizer ? this._autoSizer.parentNode : null;
    if (n != null && n.ownerDocument && n.ownerDocument.defaultView && n instanceof n.ownerDocument.defaultView.HTMLElement) {
      this._parentNode = n;
      const r = n.ownerDocument.defaultView.ResizeObserver;
      r != null ? (this._resizeObserver = new r(() => {
        this._timeoutId = setTimeout(this._onResize, 0);
      }), this._resizeObserver.observe(n)) : (this._detectElementResize = oh(t), this._detectElementResize.addResizeListener(n, this._onResize)), this._onResize();
    }
  }
  componentWillUnmount() {
    this._parentNode && (this._detectElementResize && this._detectElementResize.removeResizeListener(this._parentNode, this._onResize), this._timeoutId !== null && clearTimeout(this._timeoutId), this._resizeObserver && this._resizeObserver.disconnect());
  }
  render() {
    const { children: t, defaultHeight: n, defaultWidth: r, disableHeight: i = false, disableWidth: a = false, doNotBailOutOnEmptyChildren: o = false, nonce: s, onResize: c, style: u = {}, tagName: p = "div", ...f } = this.props, { height: l, width: g } = this.state, y = { overflow: "visible" }, v = {};
    let h = false;
    return i || (l === 0 && (h = true), y.height = 0, v.height = l, v.scaledHeight = l), a || (g === 0 && (h = true), y.width = 0, v.width = g, v.scaledWidth = g), o && (h = false), m.createElement(p, { ref: this._setRef, style: { ...y, ...u }, ...f }, !h && t(v));
  }
}
var ja = m.createContext(), sh = function(e2) {
  var t = e2.children, n = e2.animate, r = n === void 0 || n, i = e2.config, a = i === void 0 ? "default" : i, o = m.useMemo(function() {
    var s = Di(a) ? Hi[a] : a;
    return { animate: r, config: s };
  }, [r, a]);
  return d.jsx(ja.Provider, { value: o, children: t });
}, Tn = function() {
  return m.useContext(ja);
}, lh = function(e2) {
  var t = e2.children, n = e2.condition, r = e2.wrapper;
  return n ? m.cloneElement(r, {}, t) : t;
}, uh = { position: "relative" }, Yr = function(e2) {
  var t = e2.children, n = e2.theme, r = e2.renderWrapper, i = r === void 0 || r, a = e2.isInteractive, o = a === void 0 || a, s = e2.animate, c = e2.motionConfig, u = m.useRef(null);
  return d.jsx(Vo, { theme: n, children: d.jsx(sh, { animate: s, config: c, children: d.jsx(ih, { container: u, children: d.jsxs(lh, { condition: i, wrapper: d.jsx("div", { style: uh, ref: u }), children: [t, o && d.jsx(rh, {})] }) }) }) });
}, dh = function(e2, t) {
  return e2.width === t.width && e2.height === t.height;
}, ch = function(e2) {
  var t = e2.children, n = e2.width, r = e2.height, i = e2.onResize, a = e2.debounceResize, o = Sr({ width: n, height: r }, a, { equalityFn: dh })[0];
  return m.useEffect(function() {
    i == null ? void 0 : i(o);
  }, [o, i]), d.jsx(d.Fragment, { children: t(o) });
}, qr = function(e2) {
  var t = e2.children, n = e2.defaultWidth, r = e2.defaultHeight, i = e2.onResize, a = e2.debounceResize, o = a === void 0 ? 0 : a;
  return d.jsx(ah, { defaultWidth: n, defaultHeight: r, children: function(s) {
    var c = s.width, u = s.height;
    return d.jsx(ch, { width: c, height: u, onResize: i, debounceResize: o, children: t });
  } });
};
function zi(e2, t) {
  (t == null || t > e2.length) && (t = e2.length);
  for (var n = 0, r = Array(t); n < t; n++) r[n] = e2[n];
  return r;
}
function fh(e2, t) {
  var n = typeof Symbol < "u" && e2[Symbol.iterator] || e2["@@iterator"];
  if (n) return (n = n.call(e2)).next.bind(n);
  if (Array.isArray(e2) || (n = function(i, a) {
    if (i) {
      if (typeof i == "string") return zi(i, a);
      var o = {}.toString.call(i).slice(8, -1);
      return o === "Object" && i.constructor && (o = i.constructor.name), o === "Map" || o === "Set" ? Array.from(i) : o === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(o) ? zi(i, a) : void 0;
    }
  }(e2)) || t) {
    n && (e2 = n);
    var r = 0;
    return function() {
      return r >= e2.length ? { done: true } : { done: false, value: e2[r++] };
    };
  }
  throw new TypeError(`Invalid attempt to iterate non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`);
}
function Ve() {
  return Ve = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Ve.apply(null, arguments);
}
function $a(e2, t) {
  if (e2 == null) return {};
  var n = {};
  for (var r in e2) if ({}.hasOwnProperty.call(e2, r)) {
    if (t.indexOf(r) !== -1) continue;
    n[r] = e2[r];
  }
  return n;
}
var hh = ["id", "colors"], ph = function(e2) {
  var t = e2.id, n = e2.colors, r = $a(e2, hh);
  return d.jsx("linearGradient", Ve({ id: t, x1: 0, x2: 0, y1: 0, y2: 1 }, r, { children: n.map(function(i) {
    var a = i.offset, o = i.color, s = i.opacity;
    return d.jsx("stop", { offset: a + "%", stopColor: o, stopOpacity: s !== void 0 ? s : 1 }, a);
  }) }));
}, La = { linearGradient: ph }, Qt = { color: "#000000", background: "#ffffff", size: 4, padding: 4, stagger: false }, gh = m.memo(function(e2) {
  var t = e2.id, n = e2.background, r = n === void 0 ? Qt.background : n, i = e2.color, a = i === void 0 ? Qt.color : i, o = e2.size, s = o === void 0 ? Qt.size : o, c = e2.padding, u = c === void 0 ? Qt.padding : c, p = e2.stagger, f = p === void 0 ? Qt.stagger : p, l = s + u, g = s / 2, y = u / 2;
  return f === true && (l = 2 * s + 2 * u), d.jsxs("pattern", { id: t, width: l, height: l, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: l, height: l, fill: r }), d.jsx("circle", { cx: y + g, cy: y + g, r: g, fill: a }), f && d.jsx("circle", { cx: 1.5 * u + s + g, cy: 1.5 * u + s + g, r: g, fill: a })] });
}), lr = function(e2) {
  return e2 * Math.PI / 180;
}, en = { spacing: 5, rotation: 0, background: "#000000", color: "#ffffff", lineWidth: 2 }, vh = m.memo(function(e2) {
  var t = e2.id, n = e2.spacing, r = n === void 0 ? en.spacing : n, i = e2.rotation, a = i === void 0 ? en.rotation : i, o = e2.background, s = o === void 0 ? en.background : o, c = e2.color, u = c === void 0 ? en.color : c, p = e2.lineWidth, f = p === void 0 ? en.lineWidth : p, l = Math.round(a) % 360, g = Math.abs(r);
  l > 180 ? l -= 360 : l > 90 ? l -= 180 : l < -180 ? l += 360 : l < -90 && (l += 180);
  var y, v = g, h = g;
  return l === 0 ? y = `
                M 0 0 L ` + v + ` 0
                M 0 ` + h + " L " + v + " " + h + `
            ` : l === 90 ? y = `
                M 0 0 L 0 ` + h + `
                M ` + v + " 0 L " + v + " " + h + `
            ` : (v = Math.abs(g / Math.sin(lr(l))), h = g / Math.sin(lr(90 - l)), y = l > 0 ? `
                    M 0 ` + -h + " L " + 2 * v + " " + h + `
                    M ` + -v + " " + -h + " L " + v + " " + h + `
                    M ` + -v + " 0 L " + v + " " + 2 * h + `
                ` : `
                    M ` + -v + " " + h + " L " + v + " " + -h + `
                    M ` + -v + " " + 2 * h + " L " + 2 * v + " " + -h + `
                    M 0 ` + 2 * h + " L " + 2 * v + ` 0
                `), d.jsxs("pattern", { id: t, width: v, height: h, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: v, height: h, fill: s, stroke: "rgba(255, 0, 0, 0.1)", strokeWidth: 0 }), d.jsx("path", { d: y, strokeWidth: f, stroke: u, strokeLinecap: "square" })] });
}), tn = { color: "#000000", background: "#ffffff", size: 4, padding: 4, stagger: false }, mh = m.memo(function(e2) {
  var t = e2.id, n = e2.color, r = n === void 0 ? tn.color : n, i = e2.background, a = i === void 0 ? tn.background : i, o = e2.size, s = o === void 0 ? tn.size : o, c = e2.padding, u = c === void 0 ? tn.padding : c, p = e2.stagger, f = p === void 0 ? tn.stagger : p, l = s + u, g = u / 2;
  return f === true && (l = 2 * s + 2 * u), d.jsxs("pattern", { id: t, width: l, height: l, patternUnits: "userSpaceOnUse", children: [d.jsx("rect", { width: l, height: l, fill: a }), d.jsx("rect", { x: g, y: g, width: s, height: s, fill: r }), f && d.jsx("rect", { x: 1.5 * u + s, y: 1.5 * u + s, width: s, height: s, fill: r })] });
}), Ra = { patternDots: gh, patternLines: vh, patternSquares: mh }, bh = ["type"], ji = Ve({}, La, Ra), yh = m.memo(function(e2) {
  var t = e2.defs;
  return !t || t.length < 1 ? null : d.jsx("defs", { "aria-hidden": true, children: t.map(function(n) {
    var r = n.type, i = $a(n, bh);
    return ji[r] ? m.createElement(ji[r], Ve({ key: i.id }, i)) : null;
  }) });
}), xh = m.forwardRef(function(e2, t) {
  var n = e2.width, r = e2.height, i = e2.margin, a = e2.defs, o = e2.children, s = e2.role, c = e2.ariaLabel, u = e2.ariaLabelledBy, p = e2.ariaDescribedBy, f = e2.isFocusable, l = X();
  return d.jsxs("svg", { xmlns: "http://www.w3.org/2000/svg", width: n, height: r, role: s, "aria-label": c, "aria-labelledby": u, "aria-describedby": p, focusable: f, tabIndex: f ? 0 : void 0, ref: t, children: [d.jsx(yh, { defs: a }), d.jsx("rect", { width: n, height: r, fill: l.background }), d.jsx("g", { transform: "translate(" + i.left + "," + i.top + ")", children: o })] });
}), _h = m.memo(function(e2) {
  var t = e2.size, n = e2.color, r = e2.borderWidth, i = e2.borderColor;
  return d.jsx("circle", { r: t / 2, fill: n, stroke: i, strokeWidth: r, style: { pointerEvents: "none" } });
});
m.memo(function(e2) {
  var t = e2.x, n = e2.y, r = e2.symbol, i = r === void 0 ? _h : r, a = e2.size, o = e2.datum, s = e2.color, c = e2.borderWidth, u = e2.borderColor, p = e2.label, f = e2.labelTextAnchor, l = f === void 0 ? "middle" : f, g = e2.labelYOffset, y = g === void 0 ? -12 : g, v = e2.ariaLabel, h = e2.ariaLabelledBy, b = e2.ariaDescribedBy, _ = e2.ariaHidden, w = e2.ariaDisabled, C = e2.isFocusable, z = C !== void 0 && C, $ = e2.tabIndex, R = $ === void 0 ? 0 : $, k = e2.onFocus, j = e2.onBlur, T = e2.testId, P = X(), N = Tn(), L = N.animate, E = N.config, W = Pe({ transform: "translate(" + t + ", " + n + ")", config: E, immediate: !L }), S = m.useCallback(function(Y) {
    k == null ? void 0 : k(o, Y);
  }, [k, o]), O = m.useCallback(function(Y) {
    j == null ? void 0 : j(o, Y);
  }, [j, o]);
  return d.jsxs(ee.g, { transform: W.transform, style: { pointerEvents: "none" }, focusable: z, tabIndex: z ? R : void 0, "aria-label": v, "aria-labelledby": h, "aria-describedby": b, "aria-disabled": w, "aria-hidden": _, onFocus: z && k ? S : void 0, onBlur: z && j ? O : void 0, "data-testid": T, children: [m.createElement(i, { size: a, color: s, datum: o, borderWidth: c, borderColor: u }), p && d.jsx("text", { textAnchor: l, y, style: Fr(P.dots.text), children: p })] });
});
var wh = m.memo(function(e2) {
  var t = e2.width, n = e2.height, r = e2.axis, i = e2.scale, a = e2.value, o = e2.lineStyle, s = e2.textStyle, c = e2.legend, u = e2.legendNode, p = e2.legendPosition, f = p === void 0 ? "top-right" : p, l = e2.legendOffsetX, g = l === void 0 ? 14 : l, y = e2.legendOffsetY, v = y === void 0 ? 14 : y, h = e2.legendOrientation, b = h === void 0 ? "horizontal" : h, _ = X(), w = 0, C = 0, z = 0, $ = 0;
  if (r === "y" ? (z = i(a), C = t) : (w = i(a), $ = n), c && !u) {
    var R = function(k) {
      var j = k.axis, T = k.width, P = k.height, N = k.position, L = k.offsetX, E = k.offsetY, W = k.orientation, S = 0, O = 0, Y = W === "vertical" ? -90 : 0, M = "start";
      if (j === "x") switch (N) {
        case "top-left":
          S = -L, O = E, M = "end";
          break;
        case "top":
          O = -E, M = W === "horizontal" ? "middle" : "start";
          break;
        case "top-right":
          S = L, O = E, M = W === "horizontal" ? "start" : "end";
          break;
        case "right":
          S = L, O = P / 2, M = W === "horizontal" ? "start" : "middle";
          break;
        case "bottom-right":
          S = L, O = P - E, M = "start";
          break;
        case "bottom":
          O = P + E, M = W === "horizontal" ? "middle" : "end";
          break;
        case "bottom-left":
          O = P - E, S = -L, M = W === "horizontal" ? "end" : "start";
          break;
        case "left":
          S = -L, O = P / 2, M = W === "horizontal" ? "end" : "middle";
      }
      else switch (N) {
        case "top-left":
          S = L, O = -E, M = "start";
          break;
        case "top":
          S = T / 2, O = -E, M = W === "horizontal" ? "middle" : "start";
          break;
        case "top-right":
          S = T - L, O = -E, M = W === "horizontal" ? "end" : "start";
          break;
        case "right":
          S = T + L, M = W === "horizontal" ? "start" : "middle";
          break;
        case "bottom-right":
          S = T - L, O = E, M = "end";
          break;
        case "bottom":
          S = T / 2, O = E, M = W === "horizontal" ? "middle" : "end";
          break;
        case "bottom-left":
          S = L, O = E, M = W === "horizontal" ? "start" : "end";
          break;
        case "left":
          S = -L, M = W === "horizontal" ? "end" : "middle";
      }
      return { x: S, y: O, rotation: Y, textAnchor: M };
    }({ axis: r, width: t, height: n, position: f, offsetX: g, offsetY: v, orientation: b });
    u = d.jsx("text", { transform: "translate(" + R.x + ", " + R.y + ") rotate(" + R.rotation + ")", textAnchor: R.textAnchor, dominantBaseline: "central", style: s, children: c });
  }
  return d.jsxs("g", { transform: "translate(" + w + ", " + z + ")", children: [d.jsx("line", { x1: 0, x2: C, y1: 0, y2: $, stroke: _.markers.lineColor, strokeWidth: _.markers.lineStrokeWidth, style: o }), u] });
});
m.memo(function(e2) {
  var t = e2.markers, n = e2.width, r = e2.height, i = e2.xScale, a = e2.yScale;
  return t && t.length !== 0 ? t.map(function(o, s) {
    return d.jsx(wh, Ve({}, o, { width: n, height: r, scale: o.axis === "y" ? a : i }), s);
  }) : null;
});
m.createContext(void 0);
var Ch = { basis: Mr, basisClosed: Rr, basisOpen: Lr, bundle: $r, cardinal: jr, cardinalClosed: zr, cardinalOpen: kr, catmullRom: Cr, catmullRomClosed: wr, catmullRomOpen: _r, linear: xr, linearClosed: yr, monotoneX: br, monotoneY: mr, natural: vr, step: gr, stepAfter: pr, stepBefore: hr }, Vr = Object.keys(Ch);
Vr.filter(function(e2) {
  return e2.endsWith("Closed");
});
Gt(Vr, "bundle", "basisClosed", "basisOpen", "cardinalClosed", "cardinalOpen", "catmullRomClosed", "catmullRomOpen", "linearClosed");
Gt(Vr, "bundle", "basisClosed", "basisOpen", "cardinalClosed", "cardinalOpen", "catmullRomClosed", "catmullRomOpen", "linearClosed");
x(jt), x(zt), x(kt), x(Ct), x(wt), x(_t), x(xt), x(yt), x(bt), x(mt), x(vt), x(gt), x(pt), x(ht), x(ft), x(ct), x(dt), x(ut), x(lt), x(st), x(at), x(ot), x(it), x(rt), x(nt), x(tt), x(et);
x(jt), x(zt), x(kt), x(Ct), x(wt), x(_t), x(xt), x(yt), x(bt), x(mt), x(vt), x(gt), x(pt), x(ht), x(ft), x(ct), x(dt), x(ut), x(lt), x(st), x(at), x(ot), x(it), x(rt), x(nt), x(tt), x(et);
Ot(gn);
var kh = { top: 0, right: 0, bottom: 0, left: 0 }, Xr = function(e2, t, n) {
  return n === void 0 && (n = {}), m.useMemo(function() {
    var r = Ve({}, kh, n);
    return { margin: r, innerWidth: e2 - r.left - r.right, innerHeight: t - r.top - r.bottom, outerWidth: e2, outerHeight: t };
  }, [e2, t, n]);
}, zh = function() {
  var e2 = m.useRef(null), t = m.useState({ left: 0, top: 0, width: 0, height: 0 }), n = t[0], r = t[1], i = m.useState(function() {
    return typeof ResizeObserver > "u" ? null : new ResizeObserver(function(a) {
      var o = a[0];
      return r(o.contentRect);
    });
  })[0];
  return m.useEffect(function() {
    return e2.current && i !== null && i.observe(e2.current), function() {
      i !== null && i.disconnect();
    };
  }, [i]), [e2, n];
}, jh = function(e2) {
  return typeof e2 == "function" ? e2 : typeof e2 == "string" ? e2.indexOf("time:") === 0 ? cr(e2.slice("5")) : fr(e2) : function(t) {
    return "" + t;
  };
}, Ma = function(e2) {
  return m.useMemo(function() {
    return jh(e2);
  }, [e2]);
}, $h = function(e2) {
  return Uo(e2) ? e2 : function(t) {
    return Ue(t, e2);
  };
}, yn = function(e2) {
  return m.useMemo(function() {
    return $h(e2);
  }, [e2]);
}, Lh = function(e2, t, n, r, i, a) {
  return e2 <= i && i <= e2 + n && t <= a && a <= t + r;
}, $i = function(e2, t) {
  var n, r = "touches" in t ? t.touches[0] : t, i = r.clientX, a = r.clientY, o = e2.getBoundingClientRect(), s = (n = e2.getBBox !== void 0 ? e2.getBBox() : { width: e2.offsetWidth || 0, height: e2.offsetHeight || 0 }).width === o.width ? 1 : n.width / o.width;
  return [(i - o.left) * s, (a - o.top) * s];
}, Rh = Object.keys(La), Mh = Object.keys(Ra), Sh = function(e2, t, n) {
  if (e2 === "*") return true;
  if (Uo(e2)) return e2(t);
  if (On(e2)) {
    var r = n ? Ue(t, n) : t;
    return Ws(Ts(r, Object.keys(e2)), e2);
  }
  return false;
}, Oh = function(e2, t, n, r) {
  var i = {}, a = i.dataKey, o = i.colorKey, s = o === void 0 ? "color" : o, c = i.targetKey, u = c === void 0 ? "fill" : c, p = [], f = {};
  return e2.length && t.length && (p = [].concat(e2), t.forEach(function(l) {
    for (var g, y = function() {
      var h = g.value, b = h.id, _ = h.match;
      if (Sh(_, l, a)) {
        var w = e2.find(function(P) {
          return P.id === b;
        });
        if (w) {
          if (Mh.includes(w.type)) if (w.background === "inherit" || w.color === "inherit") {
            var C = Ue(l, s), z = w.background, $ = w.color, R = b;
            w.background === "inherit" && (R = R + ".bg." + C, z = C), w.color === "inherit" && (R = R + ".fg." + C, $ = C), on(l, u, "url(#" + R + ")"), f[R] || (p.push(Ve({}, w, { id: R, background: z, color: $ })), f[R] = 1);
          } else on(l, u, "url(#" + b + ")");
          else if (Rh.includes(w.type)) if (w.colors.map(function(P) {
            return P.color;
          }).includes("inherit")) {
            var k = Ue(l, s), j = b, T = Ve({}, w, { colors: w.colors.map(function(P, N) {
              return P.color !== "inherit" ? P : (j = j + "." + N + "." + k, Ve({}, P, { color: P.color === "inherit" ? k : P.color }));
            }) });
            T.id = j, on(l, u, "url(#" + j + ")"), f[j] || (p.push(T), f[j] = 1);
          } else on(l, u, "url(#" + b + ")");
        }
        return 1;
      }
    }, v = fh(n); !(g = v()).done && !y(); ) ;
  })), p;
};
function Eh() {
  for (var e2 = arguments.length, t = new Array(e2), n = 0; n < e2; n++) t[n] = arguments[n];
  return function(r) {
    for (var i = 0, a = t; i < a.length; i++) {
      var o = a[i];
      typeof o == "function" ? o(r) : o != null && (o.current = r);
    }
  };
}
function Wh(e2, t, n, r) {
  var i = -1, a = e2 == null ? 0 : e2.length;
  for (r && a && (n = e2[++i]); ++i < a; ) n = t(n, e2[i], i, e2);
  return n;
}
var Th = Wh;
function Nh(e2) {
  return function(t) {
    return e2 == null ? void 0 : e2[t];
  };
}
var Ph = Nh, Ah = Ph, Ih = { \u00C0: "A", \u00C1: "A", \u00C2: "A", \u00C3: "A", \u00C4: "A", \u00C5: "A", \u00E0: "a", \u00E1: "a", \u00E2: "a", \u00E3: "a", \u00E4: "a", \u00E5: "a", \u00C7: "C", \u00E7: "c", \u00D0: "D", \u00F0: "d", \u00C8: "E", \u00C9: "E", \u00CA: "E", \u00CB: "E", \u00E8: "e", \u00E9: "e", \u00EA: "e", \u00EB: "e", \u00CC: "I", \u00CD: "I", \u00CE: "I", \u00CF: "I", \u00EC: "i", \u00ED: "i", \u00EE: "i", \u00EF: "i", \u00D1: "N", \u00F1: "n", \u00D2: "O", \u00D3: "O", \u00D4: "O", \u00D5: "O", \u00D6: "O", \u00D8: "O", \u00F2: "o", \u00F3: "o", \u00F4: "o", \u00F5: "o", \u00F6: "o", \u00F8: "o", \u00D9: "U", \u00DA: "U", \u00DB: "U", \u00DC: "U", \u00F9: "u", \u00FA: "u", \u00FB: "u", \u00FC: "u", \u00DD: "Y", \u00FD: "y", \u00FF: "y", \u00C6: "Ae", \u00E6: "ae", \u00DE: "Th", \u00FE: "th", \u00DF: "ss", \u0100: "A", \u0102: "A", \u0104: "A", \u0101: "a", \u0103: "a", \u0105: "a", \u0106: "C", \u0108: "C", \u010A: "C", \u010C: "C", \u0107: "c", \u0109: "c", \u010B: "c", \u010D: "c", \u010E: "D", \u0110: "D", \u010F: "d", \u0111: "d", \u0112: "E", \u0114: "E", \u0116: "E", \u0118: "E", \u011A: "E", \u0113: "e", \u0115: "e", \u0117: "e", \u0119: "e", \u011B: "e", \u011C: "G", \u011E: "G", \u0120: "G", \u0122: "G", \u011D: "g", \u011F: "g", \u0121: "g", \u0123: "g", \u0124: "H", \u0126: "H", \u0125: "h", \u0127: "h", \u0128: "I", \u012A: "I", \u012C: "I", \u012E: "I", \u0130: "I", \u0129: "i", \u012B: "i", \u012D: "i", \u012F: "i", \u0131: "i", \u0134: "J", \u0135: "j", \u0136: "K", \u0137: "k", \u0138: "k", \u0139: "L", \u013B: "L", \u013D: "L", \u013F: "L", \u0141: "L", \u013A: "l", \u013C: "l", \u013E: "l", \u0140: "l", \u0142: "l", \u0143: "N", \u0145: "N", \u0147: "N", \u014A: "N", \u0144: "n", \u0146: "n", \u0148: "n", \u014B: "n", \u014C: "O", \u014E: "O", \u0150: "O", \u014D: "o", \u014F: "o", \u0151: "o", \u0154: "R", \u0156: "R", \u0158: "R", \u0155: "r", \u0157: "r", \u0159: "r", \u015A: "S", \u015C: "S", \u015E: "S", \u0160: "S", \u015B: "s", \u015D: "s", \u015F: "s", \u0161: "s", \u0162: "T", \u0164: "T", \u0166: "T", \u0163: "t", \u0165: "t", \u0167: "t", \u0168: "U", \u016A: "U", \u016C: "U", \u016E: "U", \u0170: "U", \u0172: "U", \u0169: "u", \u016B: "u", \u016D: "u", \u016F: "u", \u0171: "u", \u0173: "u", \u0174: "W", \u0175: "w", \u0176: "Y", \u0177: "y", \u0178: "Y", \u0179: "Z", \u017B: "Z", \u017D: "Z", \u017A: "z", \u017C: "z", \u017E: "z", \u0132: "IJ", \u0133: "ij", \u0152: "Oe", \u0153: "oe", \u0149: "'n", \u017F: "s" }, Bh = Ah(Ih), Fh = Bh, Dh = Fh, Hh = Wr, Gh = /[\xc0-\xd6\xd8-\xf6\xf8-\xff\u0100-\u017f]/g, Uh = "\\u0300-\\u036f", Yh = "\\ufe20-\\ufe2f", qh = "\\u20d0-\\u20ff", Vh = Uh + Yh + qh, Xh = "[" + Vh + "]", Kh = RegExp(Xh, "g");
function Zh(e2) {
  return e2 = Hh(e2), e2 && e2.replace(Gh, Dh).replace(Kh, "");
}
var Jh = Zh, Qh = /[^\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]+/g;
function ep(e2) {
  return e2.match(Qh) || [];
}
var tp = ep, np = /[a-z][A-Z]|[A-Z]{2}[a-z]|[0-9][a-zA-Z]|[a-zA-Z][0-9]|[^a-zA-Z0-9 ]/;
function rp(e2) {
  return np.test(e2);
}
var ip = rp, Sa = "\\ud800-\\udfff", op = "\\u0300-\\u036f", ap = "\\ufe20-\\ufe2f", sp = "\\u20d0-\\u20ff", lp = op + ap + sp, Oa = "\\u2700-\\u27bf", Ea = "a-z\\xdf-\\xf6\\xf8-\\xff", up = "\\xac\\xb1\\xd7\\xf7", dp = "\\x00-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\xbf", cp = "\\u2000-\\u206f", fp = " \\t\\x0b\\f\\xa0\\ufeff\\n\\r\\u2028\\u2029\\u1680\\u180e\\u2000\\u2001\\u2002\\u2003\\u2004\\u2005\\u2006\\u2007\\u2008\\u2009\\u200a\\u202f\\u205f\\u3000", Wa = "A-Z\\xc0-\\xd6\\xd8-\\xde", hp = "\\ufe0e\\ufe0f", Ta = up + dp + cp + fp, Na = "['\u2019]", Li = "[" + Ta + "]", pp = "[" + lp + "]", Pa = "\\d+", gp = "[" + Oa + "]", Aa = "[" + Ea + "]", Ia = "[^" + Sa + Ta + Pa + Oa + Ea + Wa + "]", vp = "\\ud83c[\\udffb-\\udfff]", mp = "(?:" + pp + "|" + vp + ")", bp = "[^" + Sa + "]", Ba = "(?:\\ud83c[\\udde6-\\uddff]){2}", Fa = "[\\ud800-\\udbff][\\udc00-\\udfff]", At = "[" + Wa + "]", yp = "\\u200d", Ri = "(?:" + Aa + "|" + Ia + ")", xp = "(?:" + At + "|" + Ia + ")", Mi = "(?:" + Na + "(?:d|ll|m|re|s|t|ve))?", Si = "(?:" + Na + "(?:D|LL|M|RE|S|T|VE))?", Da = mp + "?", Ha = "[" + hp + "]?", _p = "(?:" + yp + "(?:" + [bp, Ba, Fa].join("|") + ")" + Ha + Da + ")*", wp = "\\d*(?:1st|2nd|3rd|(?![123])\\dth)(?=\\b|[A-Z_])", Cp = "\\d*(?:1ST|2ND|3RD|(?![123])\\dTH)(?=\\b|[a-z_])", kp = Ha + Da + _p, zp = "(?:" + [gp, Ba, Fa].join("|") + ")" + kp, jp = RegExp([At + "?" + Aa + "+" + Mi + "(?=" + [Li, At, "$"].join("|") + ")", xp + "+" + Si + "(?=" + [Li, At + Ri, "$"].join("|") + ")", At + "?" + Ri + "+" + Mi, At + "+" + Si, Cp, wp, Pa, zp].join("|"), "g");
function $p(e2) {
  return e2.match(jp) || [];
}
var Lp = $p, Rp = tp, Mp = ip, Sp = Wr, Op = Lp;
function Ep(e2, t, n) {
  return e2 = Sp(e2), t = n ? void 0 : t, t === void 0 ? Mp(e2) ? Op(e2) : Rp(e2) : e2.match(t) || [];
}
var Wp = Ep, Tp = Th, Np = Jh, Pp = Wp, Ap = "['\u2019]", Ip = RegExp(Ap, "g");
function Bp(e2) {
  return function(t) {
    return Tp(Pp(Np(t).replace(Ip, "")), e2, "");
  };
}
var Fp = Bp, Dp = ha;
function Hp(e2, t, n) {
  var r = e2.length;
  return n = n === void 0 ? r : n, !t && n >= r ? e2 : Dp(e2, t, n);
}
var Gp = Hp, Up = "\\ud800-\\udfff", Yp = "\\u0300-\\u036f", qp = "\\ufe20-\\ufe2f", Vp = "\\u20d0-\\u20ff", Xp = Yp + qp + Vp, Kp = "\\ufe0e\\ufe0f", Zp = "\\u200d", Jp = RegExp("[" + Zp + Up + Xp + Kp + "]");
function Qp(e2) {
  return Jp.test(e2);
}
var Ga = Qp;
function eg(e2) {
  return e2.split("");
}
var tg = eg, Ua = "\\ud800-\\udfff", ng = "\\u0300-\\u036f", rg = "\\ufe20-\\ufe2f", ig = "\\u20d0-\\u20ff", og = ng + rg + ig, ag = "\\ufe0e\\ufe0f", sg = "[" + Ua + "]", ur = "[" + og + "]", dr = "\\ud83c[\\udffb-\\udfff]", lg = "(?:" + ur + "|" + dr + ")", Ya = "[^" + Ua + "]", qa = "(?:\\ud83c[\\udde6-\\uddff]){2}", Va = "[\\ud800-\\udbff][\\udc00-\\udfff]", ug = "\\u200d", Xa = lg + "?", Ka = "[" + ag + "]?", dg = "(?:" + ug + "(?:" + [Ya, qa, Va].join("|") + ")" + Ka + Xa + ")*", cg = Ka + Xa + dg, fg = "(?:" + [Ya + ur + "?", ur, qa, Va, sg].join("|") + ")", hg = RegExp(dr + "(?=" + dr + ")|" + fg + cg, "g");
function pg(e2) {
  return e2.match(hg) || [];
}
var gg = pg, vg = tg, mg = Ga, bg = gg;
function yg(e2) {
  return mg(e2) ? bg(e2) : vg(e2);
}
var xg = yg, _g = Gp, wg = Ga, Cg = xg, kg = Wr;
function zg(e2) {
  return function(t) {
    t = kg(t);
    var n = wg(t) ? Cg(t) : void 0, r = n ? n[0] : t.charAt(0), i = n ? _g(n, 1).join("") : t.slice(1);
    return r[e2]() + i;
  };
}
var jg = zg, $g = jg, Lg = $g("toUpperCase"), Rg = Lg, Mg = Fp, Sg = Rg, Og = Mg(function(e2, t, n) {
  return e2 + (n ? " " : "") + Sg(t);
}), Eg = Og;
const Wg = En(Eg);
function Tg(e2) {
  var t = 0, n = e2.children, r = n && n.length;
  if (!r) t = 1;
  else for (; --r >= 0; ) t += n[r].value;
  e2.value = t;
}
function Ng() {
  return this.eachAfter(Tg);
}
function Pg(e2, t) {
  let n = -1;
  for (const r of this) e2.call(t, r, ++n, this);
  return this;
}
function Ag(e2, t) {
  for (var n = this, r = [n], i, a, o = -1; n = r.pop(); ) if (e2.call(t, n, ++o, this), i = n.children) for (a = i.length - 1; a >= 0; --a) r.push(i[a]);
  return this;
}
function Ig(e2, t) {
  for (var n = this, r = [n], i = [], a, o, s, c = -1; n = r.pop(); ) if (i.push(n), a = n.children) for (o = 0, s = a.length; o < s; ++o) r.push(a[o]);
  for (; n = i.pop(); ) e2.call(t, n, ++c, this);
  return this;
}
function Bg(e2, t) {
  let n = -1;
  for (const r of this) if (e2.call(t, r, ++n, this)) return r;
}
function Fg(e2) {
  return this.eachAfter(function(t) {
    for (var n = +e2(t.data) || 0, r = t.children, i = r && r.length; --i >= 0; ) n += r[i].value;
    t.value = n;
  });
}
function Dg(e2) {
  return this.eachBefore(function(t) {
    t.children && t.children.sort(e2);
  });
}
function Hg(e2) {
  for (var t = this, n = Gg(t, e2), r = [t]; t !== n; ) t = t.parent, r.push(t);
  for (var i = r.length; e2 !== n; ) r.splice(i, 0, e2), e2 = e2.parent;
  return r;
}
function Gg(e2, t) {
  if (e2 === t) return e2;
  var n = e2.ancestors(), r = t.ancestors(), i = null;
  for (e2 = n.pop(), t = r.pop(); e2 === t; ) i = e2, e2 = n.pop(), t = r.pop();
  return i;
}
function Ug() {
  for (var e2 = this, t = [e2]; e2 = e2.parent; ) t.push(e2);
  return t;
}
function Yg() {
  return Array.from(this);
}
function qg() {
  var e2 = [];
  return this.eachBefore(function(t) {
    t.children || e2.push(t);
  }), e2;
}
function Vg() {
  var e2 = this, t = [];
  return e2.each(function(n) {
    n !== e2 && t.push({ source: n.parent, target: n });
  }), t;
}
function* Xg() {
  var e2 = this, t, n = [e2], r, i, a;
  do
    for (t = n.reverse(), n = []; e2 = t.pop(); ) if (yield e2, r = e2.children) for (i = 0, a = r.length; i < a; ++i) n.push(r[i]);
  while (n.length);
}
function Kr(e2, t) {
  e2 instanceof Map ? (e2 = [void 0, e2], t === void 0 && (t = Jg)) : t === void 0 && (t = Zg);
  for (var n = new Mn(e2), r, i = [n], a, o, s, c; r = i.pop(); ) if ((o = t(r.data)) && (c = (o = Array.from(o)).length)) for (r.children = o, s = c - 1; s >= 0; --s) i.push(a = o[s] = new Mn(o[s])), a.parent = r, a.depth = r.depth + 1;
  return n.eachBefore(e0);
}
function Kg() {
  return Kr(this).eachBefore(Qg);
}
function Zg(e2) {
  return e2.children;
}
function Jg(e2) {
  return Array.isArray(e2) ? e2[1] : null;
}
function Qg(e2) {
  e2.data.value !== void 0 && (e2.value = e2.data.value), e2.data = e2.data.data;
}
function e0(e2) {
  var t = 0;
  do
    e2.height = t;
  while ((e2 = e2.parent) && e2.height < ++t);
}
function Mn(e2) {
  this.data = e2, this.depth = this.height = 0, this.parent = null;
}
Mn.prototype = Kr.prototype = { constructor: Mn, count: Ng, each: Pg, eachAfter: Ig, eachBefore: Ag, find: Bg, sum: Fg, sort: Dg, path: Hg, ancestors: Ug, descendants: Yg, leaves: qg, links: Vg, copy: Kg, [Symbol.iterator]: Xg };
function t0(e2) {
  if (typeof e2 != "function") throw new Error();
  return e2;
}
function nn() {
  return 0;
}
function rn(e2) {
  return function() {
    return e2;
  };
}
function n0(e2) {
  e2.x0 = Math.round(e2.x0), e2.y0 = Math.round(e2.y0), e2.x1 = Math.round(e2.x1), e2.y1 = Math.round(e2.y1);
}
function Zr(e2, t, n, r, i) {
  for (var a = e2.children, o, s = -1, c = a.length, u = e2.value && (r - t) / e2.value; ++s < c; ) o = a[s], o.y0 = n, o.y1 = i, o.x0 = t, o.x1 = t += o.value * u;
}
function Jr(e2, t, n, r, i) {
  for (var a = e2.children, o, s = -1, c = a.length, u = e2.value && (i - n) / e2.value; ++s < c; ) o = a[s], o.x0 = t, o.x1 = r, o.y0 = n, o.y1 = n += o.value * u;
}
var r0 = (1 + Math.sqrt(5)) / 2;
function i0(e2, t, n, r, i, a) {
  for (var o = [], s = t.children, c, u, p = 0, f = 0, l = s.length, g, y, v = t.value, h, b, _, w, C, z, $; p < l; ) {
    g = i - n, y = a - r;
    do
      h = s[f++].value;
    while (!h && f < l);
    for (b = _ = h, z = Math.max(y / g, g / y) / (v * e2), $ = h * h * z, C = Math.max(_ / $, $ / b); f < l; ++f) {
      if (h += u = s[f].value, u < b && (b = u), u > _ && (_ = u), $ = h * h * z, w = Math.max(_ / $, $ / b), w > C) {
        h -= u;
        break;
      }
      C = w;
    }
    o.push(c = { value: h, dice: g < y, children: s.slice(p, f) }), c.dice ? Zr(c, n, r, i, v ? r += y * h / v : a) : Jr(c, n, r, v ? n += g * h / v : i, a), v -= h, p = f;
  }
  return o;
}
const Za = function e(t) {
  function n(r, i, a, o, s) {
    i0(t, r, i, a, o, s);
  }
  return n.ratio = function(r) {
    return e((r = +r) > 1 ? r : 1);
  }, n;
}(r0);
function o0() {
  var e2 = Za, t = false, n = 1, r = 1, i = [0], a = nn, o = nn, s = nn, c = nn, u = nn;
  function p(l) {
    return l.x0 = l.y0 = 0, l.x1 = n, l.y1 = r, l.eachBefore(f), i = [0], t && l.eachBefore(n0), l;
  }
  function f(l) {
    var g = i[l.depth], y = l.x0 + g, v = l.y0 + g, h = l.x1 - g, b = l.y1 - g;
    h < y && (y = h = (y + h) / 2), b < v && (v = b = (v + b) / 2), l.x0 = y, l.y0 = v, l.x1 = h, l.y1 = b, l.children && (g = i[l.depth + 1] = a(l) / 2, y += u(l) - g, v += o(l) - g, h -= s(l) - g, b -= c(l) - g, h < y && (y = h = (y + h) / 2), b < v && (v = b = (v + b) / 2), e2(l, y, v, h, b));
  }
  return p.round = function(l) {
    return arguments.length ? (t = !!l, p) : t;
  }, p.size = function(l) {
    return arguments.length ? (n = +l[0], r = +l[1], p) : [n, r];
  }, p.tile = function(l) {
    return arguments.length ? (e2 = t0(l), p) : e2;
  }, p.padding = function(l) {
    return arguments.length ? p.paddingInner(l).paddingOuter(l) : p.paddingInner();
  }, p.paddingInner = function(l) {
    return arguments.length ? (a = typeof l == "function" ? l : rn(+l), p) : a;
  }, p.paddingOuter = function(l) {
    return arguments.length ? p.paddingTop(l).paddingRight(l).paddingBottom(l).paddingLeft(l) : p.paddingTop();
  }, p.paddingTop = function(l) {
    return arguments.length ? (o = typeof l == "function" ? l : rn(+l), p) : o;
  }, p.paddingRight = function(l) {
    return arguments.length ? (s = typeof l == "function" ? l : rn(+l), p) : s;
  }, p.paddingBottom = function(l) {
    return arguments.length ? (c = typeof l == "function" ? l : rn(+l), p) : c;
  }, p.paddingLeft = function(l) {
    return arguments.length ? (u = typeof l == "function" ? l : rn(+l), p) : u;
  }, p;
}
function a0(e2, t, n, r, i) {
  var a = e2.children, o, s = a.length, c, u = new Array(s + 1);
  for (u[0] = c = o = 0; o < s; ++o) u[o + 1] = c += a[o].value;
  p(0, s, e2.value, t, n, r, i);
  function p(f, l, g, y, v, h, b) {
    if (f >= l - 1) {
      var _ = a[f];
      _.x0 = y, _.y0 = v, _.x1 = h, _.y1 = b;
      return;
    }
    for (var w = u[f], C = g / 2 + w, z = f + 1, $ = l - 1; z < $; ) {
      var R = z + $ >>> 1;
      u[R] < C ? z = R + 1 : $ = R;
    }
    C - u[z - 1] < u[z] - C && f + 1 < z && --z;
    var k = u[z] - w, j = g - k;
    if (h - y > b - v) {
      var T = g ? (y * j + h * k) / g : h;
      p(f, z, k, y, v, T, b), p(z, l, j, T, v, h, b);
    } else {
      var P = g ? (v * j + b * k) / g : b;
      p(f, z, k, y, v, h, P), p(z, l, j, y, P, h, b);
    }
  }
}
function s0(e2, t, n, r, i) {
  (e2.depth & 1 ? Jr : Zr)(e2, t, n, r, i);
}
function Oi(e2, t) {
  (t == null || t > e2.length) && (t = e2.length);
  for (var n = 0, r = Array(t); n < t; n++) r[n] = e2[n];
  return r;
}
function l0(e2, t) {
  var n = typeof Symbol < "u" && e2[Symbol.iterator] || e2["@@iterator"];
  if (n) return (n = n.call(e2)).next.bind(n);
  if (Array.isArray(e2) || (n = function(i, a) {
    if (i) {
      if (typeof i == "string") return Oi(i, a);
      var o = {}.toString.call(i).slice(8, -1);
      return o === "Object" && i.constructor && (o = i.constructor.name), o === "Map" || o === "Set" ? Array.from(i) : o === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(o) ? Oi(i, a) : void 0;
    }
  }(e2)) || t) {
    n && (e2 = n);
    var r = 0;
    return function() {
      return r >= e2.length ? { done: true } : { done: false, value: e2[r++] };
    };
  }
  throw new TypeError(`Invalid attempt to iterate non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`);
}
function Sn() {
  return Sn = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Sn.apply(null, arguments);
}
var Ja = { nivo: ["#e8c1a0", "#f47560", "#f1e15b", "#e8a838", "#61cdbb", "#97e3d5"], category10: Qi, accent: Ji, dark2: Zi, paired: Ki, pastel1: Xi, pastel2: Vi, set1: qi, set2: Yi, set3: gn, tableau10: Ui }, u0 = Object.keys(Ja), Qa = { brown_blueGreen: jt, purpleRed_green: zt, pink_yellowGreen: kt, purple_orange: Ct, red_blue: wt, red_grey: _t, red_yellow_blue: xt, red_yellow_green: yt, spectral: bt }, d0 = Object.keys(Qa), c0 = { brown_blueGreen: lo, purpleRed_green: so, pink_yellowGreen: ao, purple_orange: oo, red_blue: io, red_grey: ro, red_yellow_blue: no, red_yellow_green: to, spectral: eo }, es = { blues: mt, greens: vt, greys: gt, oranges: pt, purples: ht, reds: ft, blue_green: ct, blue_purple: dt, green_blue: ut, orange_red: lt, purple_blue_green: st, purple_blue: at, purple_red: ot, red_purple: it, yellow_green_blue: rt, yellow_green: nt, yellow_orange_brown: tt, yellow_orange_red: et }, f0 = Object.keys(es), h0 = { blues: No, greens: To, greys: Wo, oranges: Eo, purples: Oo, reds: So, turbo: Mo, viridis: Ro, inferno: Lo, magma: $o, plasma: jo, cividis: zo, warm: ko, cool: Co, cubehelixDefault: wo, blue_green: _o, blue_purple: xo, green_blue: yo, orange_red: bo, purple_blue_green: mo, purple_blue: vo, purple_red: go, red_purple: po, yellow_green_blue: ho, yellow_green: fo, yellow_orange_brown: co, yellow_orange_red: uo }, Dn = Sn({}, Ja, Qa, es), p0 = function(e2) {
  return u0.includes(e2);
}, g0 = function(e2) {
  return d0.includes(e2);
}, v0 = function(e2) {
  return f0.includes(e2);
}, m0 = { rainbow: Ao, sinebow: Po };
Sn({}, c0, h0, m0);
var b0 = function(e2) {
  return e2.theme !== void 0;
}, y0 = function(e2) {
  return e2.from !== void 0;
}, x0 = function(e2, t) {
  if (typeof e2 == "function") return e2;
  if (On(e2)) {
    if (b0(e2)) {
      if (t === void 0) throw new Error("Unable to use color from theme as no theme was provided");
      var n = Ue(t, e2.theme);
      if (n === void 0) throw new Error("Color from theme is undefined at path: '" + e2.theme + "'");
      return function() {
        return n;
      };
    }
    if (y0(e2)) {
      var r = function(c) {
        return Ue(c, e2.from);
      };
      if (Array.isArray(e2.modifiers)) {
        for (var i, a = [], o = function() {
          var c = i.value, u = c[0], p = c[1];
          if (u === "brighter") a.push(function(f) {
            return f.brighter(p);
          });
          else if (u === "darker") a.push(function(f) {
            return f.darker(p);
          });
          else {
            if (u !== "opacity") throw new Error("Invalid color modifier: '" + u + "', must be one of: 'brighter', 'darker', 'opacity'");
            a.push(function(f) {
              return f.opacity = p, f;
            });
          }
        }, s = l0(e2.modifiers); !(i = s()).done; ) o();
        return a.length === 0 ? r : function(c) {
          return a.reduce(function(u, p) {
            return p(u);
          }, Gi(r(c))).toString();
        };
      }
      return r;
    }
    throw new Error("Invalid color spec, you should either specify 'theme' or 'from' when using a config object");
  }
  return function() {
    return e2;
  };
}, Hn = function(e2, t) {
  return m.useMemo(function() {
    return x0(e2, t);
  }, [e2, t]);
}, _0 = function(e2, t) {
  if (typeof e2 == "function") return e2;
  var n = typeof t == "function" ? t : function(f) {
    return Ue(f, t);
  };
  if (Array.isArray(e2)) {
    var r = Ot(e2), i = function(f) {
      return r(n(f));
    };
    return i.scale = r, i;
  }
  if (On(e2)) {
    if (function(f) {
      return f.datum !== void 0;
    }(e2)) return function(f) {
      return Ue(f, e2.datum);
    };
    if (function(f) {
      return f.scheme !== void 0;
    }(e2)) {
      if (p0(e2.scheme)) {
        var a = Ot(Dn[e2.scheme]), o = function(f) {
          return a(n(f));
        };
        return o.scale = a, o;
      }
      if (g0(e2.scheme)) {
        if (e2.size !== void 0 && (e2.size < 3 || e2.size > 11)) throw new Error("Invalid size '" + e2.size + "' for diverging color scheme '" + e2.scheme + "', must be between 3~11");
        var s = Ot(Dn[e2.scheme][e2.size || 11]), c = function(f) {
          return s(n(f));
        };
        return c.scale = s, c;
      }
      if (v0(e2.scheme)) {
        if (e2.size !== void 0 && (e2.size < 3 || e2.size > 9)) throw new Error("Invalid size '" + e2.size + "' for sequential color scheme '" + e2.scheme + "', must be between 3~9");
        var u = Ot(Dn[e2.scheme][e2.size || 9]), p = function(f) {
          return u(n(f));
        };
        return p.scale = u, p;
      }
    }
    throw new Error("Invalid colors, when using an object, you should either pass a 'datum' or a 'scheme' property");
  }
  return function() {
    return e2;
  };
}, w0 = function(e2, t) {
  return m.useMemo(function() {
    return _0(e2, t);
  }, [e2, t]);
}, C0 = function(e2, t) {
  e2.font = (t.fontWeight ? t.fontWeight + " " : "") + t.fontSize + "px " + t.fontFamily;
}, k0 = function(e2, t, n, r, i) {
  r === void 0 && (r = 0), i === void 0 && (i = 0), t.outlineWidth > 0 && (e2.strokeStyle = t.outlineColor, e2.lineWidth = 2 * t.outlineWidth, e2.lineJoin = "round", e2.strokeText(n, r, i)), e2.fillStyle = t.fill, e2.fillText(n, r, i);
};
function un() {
  return un = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, un.apply(null, arguments);
}
function Ei(e2, t) {
  if (e2 == null) return {};
  var n = {};
  for (var r in e2) if ({}.hasOwnProperty.call(e2, r)) {
    if (t.indexOf(r) !== -1) continue;
    n[r] = e2[r];
  }
  return n;
}
var z0 = ["style", "children"], j0 = ["outlineWidth", "outlineColor", "outlineOpacity"], Wi = function(e2) {
  var t = e2.style, n = e2.children, r = Ei(e2, z0), i = t.outlineWidth, a = t.outlineColor, o = t.outlineOpacity, s = Ei(t, j0);
  return d.jsxs(d.Fragment, { children: [i > 0 && d.jsx(ee.text, un({}, r, { style: un({}, s, { strokeWidth: 2 * i, stroke: a, strokeOpacity: o, strokeLinejoin: "round" }), children: n })), d.jsx(ee.text, un({}, r, { style: s, children: n }))] });
};
function Se() {
  return Se = Object.assign ? Object.assign.bind() : function(e2) {
    for (var t = 1; t < arguments.length; t++) {
      var n = arguments[t];
      for (var r in n) ({}).hasOwnProperty.call(n, r) && (e2[r] = n[r]);
    }
    return e2;
  }, Se.apply(null, arguments);
}
function Ut(e2, t) {
  if (e2 == null) return {};
  var n = {};
  for (var r in e2) if ({}.hasOwnProperty.call(e2, r)) {
    if (t.indexOf(r) !== -1) continue;
    n[r] = e2[r];
  }
  return n;
}
var $0 = function(e2, t) {
  return Ke([e2, t], function(n, r) {
    return "translate(" + n + "," + r + ")";
  });
}, L0 = function(e2, t) {
  return Ke([e2, t], function(n, r) {
    return "translate(" + n + "px, " + r + "px)";
  });
}, Ti = function(e2, t, n) {
  return Ke([e2, t, n], function(r, i, a) {
    return "translate(" + r + "," + i + ") rotate(" + a + ")";
  });
}, R0 = function(e2, t, n) {
  return Ke([e2, t, n], function(r, i, a) {
    return "translate(" + r + "px," + i + "px) rotate(" + a + "deg)";
  });
}, M0 = function(e2, t, n) {
  return Ke([e2, t, n], function(r, i, a) {
    return "translate(" + (r - (a === 0 ? 0 : 5)) + "px," + (i - (a === 0 ? 5 : 0)) + "px) rotate(" + a + "deg)";
  });
}, S0 = m.memo(function(e2) {
  var t = e2.node, n = e2.animatedProps, r = e2.borderWidth, i = e2.enableLabel, a = e2.enableParentLabel, o = e2.labelSkipSize, s = X(), c = i && t.isLeaf && (o === 0 || Math.min(t.width, t.height) > o), u = a && t.isParent;
  return d.jsxs(ee.g, { transform: $0(n.x, n.y), children: [d.jsx(ee.rect, { "data-testid": "node." + t.id, width: Ke(n.width, function(p) {
    return Math.max(p, 0);
  }), height: Ke(n.height, function(p) {
    return Math.max(p, 0);
  }), fill: t.fill ? t.fill : n.color, strokeWidth: r, stroke: t.borderColor, fillOpacity: t.opacity, onMouseEnter: t.onMouseEnter, onMouseMove: t.onMouseMove, onMouseLeave: t.onMouseLeave, onClick: t.onClick }), c && d.jsx(Wi, { "data-testid": "label." + t.id, textAnchor: "middle", dominantBaseline: "central", style: Se({}, s.labels.text, { fill: t.labelTextColor, pointerEvents: "none" }), fillOpacity: n.labelOpacity, transform: Ti(n.labelX, n.labelY, n.labelRotation), children: t.label }), u && d.jsx(Wi, { "data-testid": "parentLabel." + t.id, dominantBaseline: "central", style: Se({}, s.labels.text, { fill: t.parentLabelTextColor, pointerEvents: "none" }), fillOpacity: n.parentLabelOpacity, transform: Ti(n.parentLabelX, n.parentLabelY, n.parentLabelRotation), children: t.parentLabel })] });
}), O0 = m.memo(function(e2) {
  var t = e2.node;
  return d.jsx(Kf, { id: t.id, value: t.formattedValue, enableChip: true, color: t.color });
}), E0 = m.memo(function(e2) {
  var t = e2.node, n = e2.animatedProps, r = e2.borderWidth, i = e2.enableLabel, a = e2.enableParentLabel, o = e2.labelSkipSize, s = X(), c = i && t.isLeaf && (o === 0 || Math.min(t.width, t.height) > o), u = a && t.isParent;
  return d.jsxs(ee.div, { "data-testid": "node." + t.id, id: t.path.replace(/[^\w]/gi, "-"), style: { boxSizing: "border-box", position: "absolute", top: 0, left: 0, transform: L0(n.x, n.y), width: n.width, height: n.height, borderWidth: r, borderStyle: "solid", borderColor: t.borderColor, overflow: "hidden" }, children: [d.jsx(ee.div, { style: { boxSizing: "border-box", position: "absolute", top: 0, left: 0, opacity: t.opacity, width: n.width, height: n.height, background: n.color }, onMouseEnter: t.onMouseEnter, onMouseMove: t.onMouseMove, onMouseLeave: t.onMouseLeave, onClick: t.onClick }), c && d.jsx(ee.span, { "data-testid": "label." + t.id, style: Se({}, s.labels.text, { position: "absolute", display: "flex", top: -5, left: -5, width: 10, height: 10, justifyContent: "center", alignItems: "center", whiteSpace: "nowrap", color: t.labelTextColor, transformOrigin: "center center", transform: R0(n.labelX, n.labelY, n.labelRotation), opacity: n.labelOpacity, pointerEvents: "none" }), children: t.label }), u && d.jsx(ee.span, { "data-testid": "parentLabel." + t.id, style: Se({}, s.labels.text, { position: "absolute", display: "flex", justifyContent: "flex-start", alignItems: "center", whiteSpace: "nowrap", width: 10, height: 10, color: t.parentLabelTextColor, transformOrigin: "top left", transform: M0(n.parentLabelX, n.parentLabelY, n.parentLabelRotation), opacity: n.parentLabelOpacity, pointerEvents: "none" }), children: t.parentLabel })] });
}), he = { layers: ["nodes"], identity: "id", value: "value", tile: "squarify", leavesOnly: false, innerPadding: 0, outerPadding: 0, colors: { scheme: "nivo" }, colorBy: "pathComponents.1", nodeOpacity: 0.33, enableLabel: true, label: "formattedValue", labelSkipSize: 0, labelTextColor: { from: "color", modifiers: [["darker", 1]] }, orientLabel: true, enableParentLabel: true, parentLabel: "id", parentLabelSize: 20, parentLabelPosition: "top", parentLabelPadding: 6, parentLabelTextColor: { from: "color", modifiers: [["darker", 1]] }, borderWidth: 1, borderColor: { from: "color", modifiers: [["darker", 1]] }, isInteractive: true, tooltip: O0, role: "img", animate: true, motionConfig: "gentle" }, K = Se({}, he, { nodeComponent: S0, defs: [], fill: [] }), Q = Se({}, he, { nodeComponent: E0 }), pe = Se({}, he, { pixelRatio: typeof window < "u" && window.devicePixelRatio || 1 }), W0 = { binary: a0, dice: Zr, slice: Jr, sliceDice: s0, squarify: Za }, T0 = function(e2) {
  var t = e2.root, n = e2.getValue;
  return m.useMemo(function() {
    return Kr(t).sum(n);
  }, [t, n]);
}, Qr = function(e2) {
  var t = e2.data, n = e2.width, r = e2.height, i = e2.identity, a = i === void 0 ? he.identity : i, o = e2.value, s = o === void 0 ? he.value : o, c = e2.valueFormat, u = e2.leavesOnly, p = u === void 0 ? he.leavesOnly : u, f = e2.tile, l = f === void 0 ? he.tile : f, g = e2.innerPadding, y = g === void 0 ? he.innerPadding : g, v = e2.outerPadding, h = v === void 0 ? he.outerPadding : v, b = e2.label, _ = b === void 0 ? he.label : b, w = e2.orientLabel, C = w === void 0 ? he.orientLabel : w, z = e2.enableParentLabel, $ = z === void 0 ? he.enableParentLabel : z, R = e2.parentLabel, k = R === void 0 ? he.parentLabel : R, j = e2.parentLabelSize, T = j === void 0 ? he.parentLabelSize : j, P = e2.parentLabelPosition, N = P === void 0 ? he.parentLabelPosition : P, L = e2.parentLabelPadding, E = L === void 0 ? he.parentLabelPadding : L, W = e2.colors, S = W === void 0 ? he.colors : W, O = e2.colorBy, Y = O === void 0 ? he.colorBy : O, M = e2.nodeOpacity, je = M === void 0 ? he.nodeOpacity : M, ye = e2.borderColor, $e = ye === void 0 ? he.borderColor : ye, xe = e2.labelTextColor, Ce = xe === void 0 ? he.labelTextColor : xe, ke = e2.parentLabelTextColor, ze = ke === void 0 ? he.parentLabelTextColor : ke, _e = yn(a), Oe = yn(s), de = Ma(c), le = yn(_), ge = yn(k), Ee = function(A) {
    var U = A.width, re = A.height, ie = A.tile, I = A.innerPadding, Z = A.outerPadding, ue = A.enableParentLabel, J = A.parentLabelSize, D = A.parentLabelPosition, B = A.leavesOnly;
    return m.useMemo(function() {
      var oe = o0().size([U, re]).tile(W0[ie]).round(true).paddingInner(I).paddingOuter(Z);
      if (ue && !B) {
        var ve = J + 2 * Z;
        oe["padding" + Wg(D)](ve);
      }
      return oe;
    }, [U, re, ie, I, Z, ue, J, D, B]);
  }({ width: n, height: r, tile: l, innerPadding: y, outerPadding: h, enableParentLabel: $, parentLabelSize: T, parentLabelPosition: N, leavesOnly: p }), Le = T0({ root: t, getValue: Oe }), Re = m.useMemo(function() {
    var A = Ns(Le);
    return Ee(A), p ? A.leaves() : A.descendants();
  }, [Le, Ee, p]), te = m.useMemo(function() {
    return Re.map(function(A) {
      var U = function(Z, ue) {
        var J = Z.ancestors().map(function(D) {
          return ue(D.data);
        }).reverse();
        return { path: J.join("."), pathComponents: J };
      }(A, _e), re = U.path, ie = U.pathComponents, I = { id: _e(A.data), path: re, pathComponents: ie, data: Gr(A.data, "children"), x: A.x0, y: A.y0, width: A.x1 - A.x0, height: A.y1 - A.y0, value: A.value, formattedValue: de(A.value), treeDepth: A.depth, treeHeight: A.height, isParent: A.height > 0, isLeaf: A.height === 0, parentLabelX: 0, parentLabelY: 0, parentLabelRotation: 0 };
      return I.labelRotation = C && I.height > I.width ? -90 : 0, N === "top" && (I.parentLabelX = h + E, I.parentLabelY = h + T / 2), N === "right" && (I.parentLabelX = I.width - h - T / 2, I.parentLabelY = I.height - h - E, I.parentLabelRotation = -90), N === "bottom" && (I.parentLabelX = h + E, I.parentLabelY = I.height - h - T / 2), N === "left" && (I.parentLabelX = h + T / 2, I.parentLabelY = I.height - h - E, I.parentLabelRotation = -90), I.label = le(I), I.parentLabel = ge(I), I;
    });
  }, [Re, _e, de, le, C, ge, T, N, E, h]), F = X(), ne = w0(S, Y), H = Hn($e, F), q = Hn(Ce, F), G = Hn(ze, F), we = m.useMemo(function() {
    return te.map(function(A) {
      var U = Se({}, A, { color: ne(A), opacity: je });
      return U.borderColor = H(U), U.labelTextColor = q(U), U.parentLabelTextColor = G(U), U;
    });
  }, [te, ne, je, H, q, G]);
  return { hierarchy: Le, nodes: we, layout: Ee };
}, ts = function(e2) {
  var t = e2.nodes;
  return m.useMemo(function() {
    return { nodes: t };
  }, [t]);
}, Gn = function(e2) {
  return { x: e2.x, y: e2.y, width: e2.width, height: e2.height, color: e2.color, labelX: e2.width / 2, labelY: e2.height / 2, labelRotation: e2.labelRotation, labelOpacity: 1, parentLabelX: e2.parentLabelX, parentLabelY: e2.parentLabelY, parentLabelRotation: e2.parentLabelRotation, parentLabelOpacity: 1 };
}, Ni = function(e2) {
  return { x: e2.x + e2.width / 2, y: e2.y + e2.height / 2, width: 0, height: 0, color: e2.color, labelX: 0, labelY: 0, labelRotation: e2.labelRotation, labelOpacity: 0, parentLabelX: 0, parentLabelY: 0, parentLabelRotation: e2.parentLabelRotation, parentLabelOpacity: 0 };
}, ns = m.memo(function(e2) {
  var t = e2.nodes, n = e2.nodeComponent, r = e2.borderWidth, i = e2.enableLabel, a = e2.labelSkipSize, o = e2.enableParentLabel, s = function(l, g) {
    var y = g.isInteractive, v = g.onMouseEnter, h = g.onMouseMove, b = g.onMouseLeave, _ = g.onClick, w = g.tooltip, C = za(), z = C.showTooltipFromEvent, $ = C.hideTooltip, R = m.useCallback(function(N, L) {
      z(m.createElement(w, { node: N }), L, "left");
    }, [z, w]), k = m.useCallback(function(N, L) {
      R(N, L), v == null ? void 0 : v(N, L);
    }, [v, R]), j = m.useCallback(function(N, L) {
      R(N, L), h == null ? void 0 : h(N, L);
    }, [h, R]), T = m.useCallback(function(N, L) {
      $(), b == null ? void 0 : b(N, L);
    }, [b, $]), P = m.useCallback(function(N, L) {
      _ == null ? void 0 : _(N, L);
    }, [_]);
    return m.useMemo(function() {
      return l.map(function(N) {
        return y ? Se({}, N, { onMouseEnter: function(L) {
          return k(N, L);
        }, onMouseMove: function(L) {
          return j(N, L);
        }, onMouseLeave: function(L) {
          return T(N, L);
        }, onClick: function(L) {
          return P(N, L);
        } }) : N;
      });
    }, [y, l, k, j, T, P]);
  }(t, { isInteractive: e2.isInteractive, onMouseEnter: e2.onMouseEnter, onMouseMove: e2.onMouseMove, onMouseLeave: e2.onMouseLeave, onClick: e2.onClick, tooltip: e2.tooltip }), c = Tn(), u = c.animate, p = c.config, f = Er(s, { keys: function(l) {
    return l.path;
  }, initial: Gn, from: Ni, enter: Gn, update: Gn, leave: Ni, config: p, immediate: !u });
  return d.jsx(d.Fragment, { children: f(function(l, g) {
    return m.createElement(n, { key: g.path, node: g, animatedProps: l, borderWidth: r, enableLabel: i, labelSkipSize: a, enableParentLabel: o });
  }) });
}), N0 = ["isInteractive", "animate", "motionConfig", "theme", "renderWrapper"], P0 = function(e2) {
  var t = e2.data, n = e2.identity, r = n === void 0 ? K.identity : n, i = e2.value, a = i === void 0 ? K.value : i, o = e2.valueFormat, s = e2.tile, c = s === void 0 ? K.tile : s, u = e2.nodeComponent, p = u === void 0 ? K.nodeComponent : u, f = e2.innerPadding, l = f === void 0 ? K.innerPadding : f, g = e2.outerPadding, y = g === void 0 ? K.outerPadding : g, v = e2.leavesOnly, h = v === void 0 ? K.leavesOnly : v, b = e2.width, _ = e2.height, w = e2.margin, C = e2.layers, z = C === void 0 ? K.layers : C, $ = e2.colors, R = $ === void 0 ? K.colors : $, k = e2.colorBy, j = k === void 0 ? K.colorBy : k, T = e2.nodeOpacity, P = T === void 0 ? K.nodeOpacity : T, N = e2.borderWidth, L = N === void 0 ? K.borderWidth : N, E = e2.borderColor, W = E === void 0 ? K.borderColor : E, S = e2.defs, O = S === void 0 ? K.defs : S, Y = e2.fill, M = Y === void 0 ? K.fill : Y, je = e2.enableLabel, ye = je === void 0 ? K.enableLabel : je, $e = e2.label, xe = $e === void 0 ? K.label : $e, Ce = e2.labelTextColor, ke = Ce === void 0 ? K.labelTextColor : Ce, ze = e2.orientLabel, _e = ze === void 0 ? K.orientLabel : ze, Oe = e2.labelSkipSize, de = Oe === void 0 ? K.labelSkipSize : Oe, le = e2.enableParentLabel, ge = le === void 0 ? K.enableParentLabel : le, Ee = e2.parentLabel, Le = Ee === void 0 ? K.parentLabel : Ee, Re = e2.parentLabelSize, te = Re === void 0 ? K.parentLabelSize : Re, F = e2.parentLabelPosition, ne = F === void 0 ? K.parentLabelPosition : F, H = e2.parentLabelPadding, q = H === void 0 ? K.parentLabelPadding : H, G = e2.parentLabelTextColor, we = G === void 0 ? K.parentLabelTextColor : G, A = e2.isInteractive, U = A === void 0 ? K.isInteractive : A, re = e2.onMouseEnter, ie = e2.onMouseMove, I = e2.onMouseLeave, Z = e2.onClick, ue = e2.tooltip, J = ue === void 0 ? K.tooltip : ue, D = e2.role, B = e2.ariaLabel, oe = e2.ariaLabelledBy, ve = e2.ariaDescribedBy, me = e2.forwardedRef, V = Xr(b, _, w), be = V.margin, Fe = V.innerWidth, Ae = V.innerHeight, Lt = V.outerWidth, Ye = V.outerHeight, ce = Qr({ data: t, identity: r, value: a, valueFormat: o, leavesOnly: h, width: Fe, height: Ae, tile: c, innerPadding: l, outerPadding: y, colors: R, colorBy: j, nodeOpacity: P, borderColor: W, label: xe, labelTextColor: ke, orientLabel: _e, enableParentLabel: ge, parentLabel: Le, parentLabelSize: te, parentLabelPosition: ne, parentLabelPadding: q, parentLabelTextColor: we }).nodes, fe = { nodes: null };
  z.includes("nodes") && (fe.nodes = d.jsx(ns, { nodes: ce, nodeComponent: p, borderWidth: L, enableLabel: ye, labelSkipSize: de, enableParentLabel: ge, isInteractive: U, onMouseEnter: re, onMouseMove: ie, onMouseLeave: I, onClick: Z, tooltip: J }, "nodes"));
  var Rt = ts({ nodes: ce }), Nn = Oh(O, ce, M);
  return d.jsx(xh, { width: Lt, height: Ye, margin: be, defs: Nn, role: D, ariaLabel: B, ariaLabelledBy: oe, ariaDescribedBy: ve, ref: me, children: z.map(function(Mt, is) {
    var ei;
    return typeof Mt == "function" ? d.jsx(m.Fragment, { children: m.createElement(Mt, Rt) }, is) : (ei = fe == null ? void 0 : fe[Mt]) != null ? ei : null;
  }) });
}, rs = m.forwardRef(function(e2, t) {
  var n = e2.isInteractive, r = n === void 0 ? K.isInteractive : n, i = e2.animate, a = i === void 0 ? K.animate : i, o = e2.motionConfig, s = o === void 0 ? K.motionConfig : o, c = e2.theme, u = e2.renderWrapper, p = Ut(e2, N0);
  return d.jsx(Yr, { animate: a, isInteractive: r, motionConfig: s, renderWrapper: u, theme: c, children: d.jsx(P0, Se({}, p, { isInteractive: r, forwardedRef: t })) });
}), A0 = ["defaultWidth", "defaultHeight", "onResize", "debounceResize"];
m.forwardRef(function(e2, t) {
  var n = e2.defaultWidth, r = e2.defaultHeight, i = e2.onResize, a = e2.debounceResize, o = Ut(e2, A0);
  return d.jsx(qr, { defaultWidth: n, defaultHeight: r, onResize: i, debounceResize: a, children: function(s) {
    var c = s.width, u = s.height;
    return d.jsx(rs, Se({}, o, { width: c, height: u, ref: t }));
  } });
});
var I0 = ["isInteractive", "animate", "motionConfig", "theme", "renderWrapper"], B0 = function(e2) {
  var t = e2.data, n = e2.identity, r = n === void 0 ? Q.identity : n, i = e2.value, a = i === void 0 ? Q.value : i, o = e2.tile, s = o === void 0 ? Q.tile : o, c = e2.nodeComponent, u = c === void 0 ? Q.nodeComponent : c, p = e2.valueFormat, f = e2.innerPadding, l = f === void 0 ? Q.innerPadding : f, g = e2.outerPadding, y = g === void 0 ? Q.outerPadding : g, v = e2.leavesOnly, h = v === void 0 ? Q.leavesOnly : v, b = e2.width, _ = e2.height, w = e2.margin, C = e2.layers, z = C === void 0 ? K.layers : C, $ = e2.colors, R = $ === void 0 ? Q.colors : $, k = e2.colorBy, j = k === void 0 ? Q.colorBy : k, T = e2.nodeOpacity, P = T === void 0 ? Q.nodeOpacity : T, N = e2.borderWidth, L = N === void 0 ? Q.borderWidth : N, E = e2.borderColor, W = E === void 0 ? Q.borderColor : E, S = e2.enableLabel, O = S === void 0 ? Q.enableLabel : S, Y = e2.label, M = Y === void 0 ? Q.label : Y, je = e2.labelTextColor, ye = je === void 0 ? Q.labelTextColor : je, $e = e2.orientLabel, xe = $e === void 0 ? Q.orientLabel : $e, Ce = e2.labelSkipSize, ke = Ce === void 0 ? Q.labelSkipSize : Ce, ze = e2.enableParentLabel, _e = ze === void 0 ? Q.enableParentLabel : ze, Oe = e2.parentLabel, de = Oe === void 0 ? Q.parentLabel : Oe, le = e2.parentLabelSize, ge = le === void 0 ? Q.parentLabelSize : le, Ee = e2.parentLabelPosition, Le = Ee === void 0 ? Q.parentLabelPosition : Ee, Re = e2.parentLabelPadding, te = Re === void 0 ? Q.parentLabelPadding : Re, F = e2.parentLabelTextColor, ne = F === void 0 ? Q.parentLabelTextColor : F, H = e2.isInteractive, q = H === void 0 ? Q.isInteractive : H, G = e2.onMouseEnter, we = e2.onMouseMove, A = e2.onMouseLeave, U = e2.onClick, re = e2.tooltip, ie = re === void 0 ? Q.tooltip : re, I = e2.role, Z = e2.ariaLabel, ue = e2.ariaLabelledBy, J = e2.ariaDescribedBy, D = e2.forwardedRef, B = Xr(b, _, w), oe = B.margin, ve = B.innerWidth, me = B.innerHeight, V = B.outerWidth, be = B.outerHeight, Fe = Qr({ data: t, identity: r, value: a, valueFormat: p, leavesOnly: h, width: ve, height: me, tile: s, innerPadding: l, outerPadding: y, colors: R, colorBy: j, nodeOpacity: P, borderColor: W, label: M, labelTextColor: ye, orientLabel: xe, enableParentLabel: _e, parentLabel: de, parentLabelSize: ge, parentLabelPosition: Le, parentLabelPadding: te, parentLabelTextColor: ne }).nodes, Ae = { nodes: null };
  z.includes("nodes") && (Ae.nodes = d.jsx(ns, { nodes: Fe, nodeComponent: u, borderWidth: L, enableLabel: O, labelSkipSize: ke, enableParentLabel: _e, isInteractive: q, onMouseEnter: G, onMouseMove: we, onMouseLeave: A, onClick: U, tooltip: ie }, "nodes"));
  var Lt = ts({ nodes: Fe });
  return d.jsx("div", { role: I, "aria-label": Z, "aria-labelledby": ue, "aria-describedby": J, style: { position: "relative", width: V, height: be }, ref: D, children: d.jsx("div", { style: { position: "absolute", top: oe.top, left: oe.left }, children: z.map(function(Ye, ce) {
    var fe;
    return typeof Ye == "function" ? d.jsx(m.Fragment, { children: m.createElement(Ye, Lt) }, ce) : (fe = Ae == null ? void 0 : Ae[Ye]) != null ? fe : null;
  }) }) });
}, F0 = m.forwardRef(function(e2, t) {
  var n = e2.isInteractive, r = n === void 0 ? Q.isInteractive : n, i = e2.animate, a = i === void 0 ? Q.animate : i, o = e2.motionConfig, s = o === void 0 ? Q.motionConfig : o, c = e2.theme, u = e2.renderWrapper, p = Ut(e2, I0);
  return d.jsx(Yr, { animate: a, isInteractive: r, motionConfig: s, renderWrapper: u, theme: c, children: d.jsx(B0, Se({}, p, { isInteractive: r, forwardedRef: t })) });
}), D0 = ["defaultWidth", "defaultHeight", "onResize", "debounceResize"];
m.forwardRef(function(e2, t) {
  var n = e2.defaultWidth, r = e2.defaultHeight, i = e2.onResize, a = e2.debounceResize, o = Ut(e2, D0);
  return d.jsx(qr, { defaultWidth: n, defaultHeight: r, onResize: i, debounceResize: a, children: function(s) {
    var c = s.width, u = s.height;
    return d.jsx(F0, Se({}, o, { width: c, height: u, ref: t }));
  } });
});
var H0 = ["theme", "isInteractive", "animate", "motionConfig", "renderWrapper"], Pi = function(e2, t, n, r) {
  return e2.find(function(i) {
    return Lh(i.x + t.left, i.y + t.top, i.width, i.height, n, r);
  });
}, G0 = function(e2) {
  var t = e2.data, n = e2.identity, r = n === void 0 ? pe.identity : n, i = e2.value, a = i === void 0 ? pe.identity : i, o = e2.tile, s = o === void 0 ? pe.tile : o, c = e2.valueFormat, u = e2.innerPadding, p = u === void 0 ? pe.innerPadding : u, f = e2.outerPadding, l = f === void 0 ? pe.outerPadding : f, g = e2.leavesOnly, y = g === void 0 ? pe.leavesOnly : g, v = e2.width, h = e2.height, b = e2.margin, _ = e2.colors, w = _ === void 0 ? pe.colors : _, C = e2.colorBy, z = C === void 0 ? pe.colorBy : C, $ = e2.nodeOpacity, R = $ === void 0 ? pe.nodeOpacity : $, k = e2.borderWidth, j = k === void 0 ? pe.borderWidth : k, T = e2.borderColor, P = T === void 0 ? pe.borderColor : T, N = e2.enableLabel, L = N === void 0 ? pe.enableLabel : N, E = e2.label, W = E === void 0 ? pe.label : E, S = e2.labelTextColor, O = S === void 0 ? pe.labelTextColor : S, Y = e2.orientLabel, M = Y === void 0 ? pe.orientLabel : Y, je = e2.labelSkipSize, ye = je === void 0 ? pe.labelSkipSize : je, $e = e2.isInteractive, xe = $e === void 0 ? pe.isInteractive : $e, Ce = e2.onMouseMove, ke = e2.onClick, ze = e2.tooltip, _e = ze === void 0 ? pe.tooltip : ze, Oe = e2.pixelRatio, de = Oe === void 0 ? pe.pixelRatio : Oe, le = e2.role, ge = e2.ariaLabel, Ee = e2.ariaLabelledBy, Le = e2.ariaDescribedBy, Re = e2.forwardedRef, te = m.useRef(null), F = Xr(v, h, b), ne = F.margin, H = F.innerWidth, q = F.innerHeight, G = F.outerWidth, we = F.outerHeight, A = Qr({ data: t, identity: r, value: a, valueFormat: c, leavesOnly: y, width: H, height: q, tile: s, innerPadding: p, outerPadding: l, colors: w, colorBy: z, nodeOpacity: R, borderColor: P, label: W, labelTextColor: O, orientLabel: M, enableParentLabel: false }).nodes, U = X();
  m.useEffect(function() {
    if (te.current !== null) {
      var D = te.current.getContext("2d");
      D !== null && (te.current.width = G * de, te.current.height = we * de, D.scale(de, de), D.fillStyle = U.background, D.fillRect(0, 0, G, we), D.translate(ne.left, ne.top), A.forEach(function(B) {
        D.fillStyle = B.color, D.fillRect(B.x, B.y, B.width, B.height), j > 0 && (D.strokeStyle = B.borderColor, D.lineWidth = j, D.strokeRect(B.x, B.y, B.width, B.height));
      }), L && (D.textAlign = "center", D.textBaseline = "middle", C0(D, U.labels.text), A.forEach(function(B) {
        if (B.isLeaf && (ye === 0 || Math.min(B.width, B.height) > ye)) {
          var oe = M && B.height > B.width;
          D.save(), D.translate(B.x + B.width / 2, B.y + B.height / 2), D.rotate(lr(oe ? -90 : 0)), k0(D, Se({}, U.labels.text, { fill: B.labelTextColor }), String(B.label)), D.restore();
        }
      })));
    }
  }, [te, A, G, we, H, q, ne, j, L, M, ye, U, de]);
  var re = za(), ie = re.showTooltipFromEvent, I = re.hideTooltip, Z = m.useCallback(function(D) {
    if (te.current !== null) {
      var B = $i(te.current, D), oe = B[0], ve = B[1], me = Pi(A, ne, oe, ve);
      me !== void 0 ? (ie(m.createElement(_e, { node: me }), D, "left"), Ce == null ? void 0 : Ce(me, D)) : I();
    }
  }, [te, A, ne, ie, I, _e, Ce]), ue = m.useCallback(function() {
    I();
  }, [I]), J = m.useCallback(function(D) {
    if (te.current !== null) {
      var B = $i(te.current, D), oe = B[0], ve = B[1], me = Pi(A, ne, oe, ve);
      me !== void 0 && (ke == null ? void 0 : ke(me, D));
    }
  }, [te, A, ne, ke]);
  return d.jsx("canvas", { ref: Eh(te, Re), width: G * de, height: we * de, style: { width: G, height: we }, onMouseEnter: xe ? Z : void 0, onMouseMove: xe ? Z : void 0, onMouseLeave: xe ? ue : void 0, onClick: xe ? J : void 0, role: le, "aria-label": ge, "aria-labelledby": Ee, "aria-describedby": Le });
}, U0 = m.forwardRef(function(e2, t) {
  var n = e2.theme, r = e2.isInteractive, i = r === void 0 ? pe.isInteractive : r, a = e2.animate, o = a === void 0 ? pe.animate : a, s = e2.motionConfig, c = s === void 0 ? pe.motionConfig : s, u = e2.renderWrapper, p = Ut(e2, H0);
  return d.jsx(Yr, { isInteractive: i, animate: o, motionConfig: c, theme: n, renderWrapper: u, children: d.jsx(G0, Se({}, p, { isInteractive: i, forwardedRef: t })) });
}), Y0 = ["defaultWidth", "defaultHeight", "onResize", "debounceResize"];
m.forwardRef(function(e2, t) {
  var n = e2.defaultWidth, r = e2.defaultHeight, i = e2.onResize, a = e2.debounceResize, o = Ut(e2, Y0);
  return d.jsx(qr, { defaultWidth: n, defaultHeight: r, onResize: i, debounceResize: a, children: function(s) {
    var c = s.width, u = s.height;
    return d.jsx(U0, Se({}, o, { width: c, height: u, ref: t }));
  } });
});
const Ai = ["#00F0FF", "#00B5FF", "#5BFFFF", "#00FFD1", "#0EEAD5", "#D9F8FF"], Ii = 300;
function q0() {
  const e2 = Je(vn), [t] = Sr(e2, 5e3, { maxWait: 5e3 }), [n, r] = m.useState(false);
  if (t) return d.jsxs("div", { children: [d.jsxs("span", { children: ["Include all (outside top 64)\xA0", d.jsx(_n, { checked: n, onCheckedChange: r })] }), d.jsxs(He, { style: { paddingTop: "50px" }, children: [d.jsx(Bi, { networkTraffic: t.ingress, label: "ingress", includeAll: n }), d.jsx(Bi, { networkTraffic: t.egress, label: "egress", includeAll: n })] })] });
}
function Bi({ networkTraffic: e2, label: t, includeAll: n }) {
  const r = m.useMemo(() => {
    var _a2, _b;
    if (!e2.peer_throughput) return;
    const i = 0.7;
    let a = 0, o = 0;
    const s = [];
    for (; o < e2.peer_throughput.length && a * i < (e2.total_throughput ?? 0); ) {
      const u = ((_a2 = e2.peer_names) == null ? void 0 : _a2[o]) || ((_b = e2.peer_identities) == null ? void 0 : _b[o]) || "";
      let p = Ai[Math.trunc(Math.random() * Ai.length)];
      s.push({ name: u, loc: e2.peer_throughput[o], color: p }), a += e2.peer_throughput[o], o++;
    }
    let c = 0;
    for (o; o < e2.peer_throughput.length; o++) c += e2.peer_throughput[o];
    return s.push({ name: "rest", loc: n ? (e2.total_throughput ?? 0) - a : c, color: "#1CE7C2" }), { name: "peers", children: s, color: void 0 };
  }, [n, e2]);
  if (r) return d.jsxs(He, { direction: "column", align: "center", children: [d.jsx(De, { children: t }), d.jsx(rs, { theme: { labels: { text: { fontSize: 14 } }, tooltip: { container: { background: "black" } } }, animate: false, height: Ii, width: Ii, data: r, identity: "name", value: "loc", valueFormat: ".02s", margin: { top: 10, right: 10, bottom: 10, left: 10 }, labelSkipSize: 16, labelTextColor: "black", enableParentLabel: false, borderColor: { from: "color", modifiers: [["darker", 1]] }, colors: (i) => i.data.color ?? "orange" })] });
}
function Bt({ inBytes: e2, value: t }) {
  const n = Ps(t, 5e3) ?? 0, r = e2 ? As(n.valuePerSecond ?? 0).toString() : Math.trunc(n.valuePerSecond ?? 0).toLocaleString();
  return d.jsxs(Ir, { children: [r, " /s"] });
}
const V0 = ["pull_request", "pull_response", "push", "ping", "pong", "prune"];
function X0() {
  var _a2;
  const e2 = (_a2 = Je(vn)) == null ? void 0 : _a2.messages, t = m.useMemo(() => {
    if (e2 == null ? void 0 : e2.num_bytes_rx) return e2.num_bytes_rx.map((n, r) => {
      var _a3, _b, _c2, _d2;
      return { type: V0[r], ingressBytes: (_a3 = e2.num_bytes_rx) == null ? void 0 : _a3[r], egressBytes: (_b = e2.num_bytes_tx) == null ? void 0 : _b[r], ingressMessages: (_c2 = e2.num_messages_rx) == null ? void 0 : _c2[r], egressMessages: (_d2 = e2.num_messages_tx) == null ? void 0 : _d2[r] };
    });
  }, [e2]);
  if (t) return d.jsxs("div", { style: { minWidth: "500px" }, children: [d.jsx(De, { children: "Messages" }), d.jsxs(Nr, { children: [d.jsx(Pr, { children: d.jsxs(dn, { children: [d.jsx(qe, { children: "Type" }), d.jsx(qe, { children: "Ingress" }), d.jsx(qe, { children: "Egress" }), d.jsx(qe, { children: "PPS in" }), d.jsx(qe, { children: "PPS out" })] }) }), d.jsx(Ar, { children: t == null ? void 0 : t.map((n, r) => d.jsxs(dn, { children: [d.jsx(Br, { children: n.type }), d.jsx(Bt, { value: n.ingressBytes ?? 0, inBytes: true }), d.jsx(Bt, { value: n.egressBytes ?? 0, inBytes: true }), d.jsx(Bt, { value: n.ingressMessages ?? 0 }), d.jsx(Bt, { value: n.egressMessages ?? 0 })] }, n.type)) })] })] });
}
const K0 = ["ContactInfoV1", "Vote", "LowestSlot", "SnapshotHashes", "AccountsHashes", "EpochSlots", "VersionV1", "VersionV2", "NodeInstance", "DuplicateShred", "IncrementalSnapshotHashes", "ContactInfoV2", "RestartLastVotedForkSlots", "RestartHeaviestFork"];
function Z0() {
  var _a2, _b, _c2, _d2;
  const t = (_a2 = Je(vn)) == null ? void 0 : _a2.storage, n = m.useMemo(() => {
    if (t == null ? void 0 : t.count) return t.count.map((r, i) => {
      var _a3, _b2, _c3;
      return { type: K0[i], activeEntries: (_a3 = t.count) == null ? void 0 : _a3[i], egressCount: (_b2 = t.count_tx) == null ? void 0 : _b2[i], egressBytes: (_c3 = t.bytes_tx) == null ? void 0 : _c3[i] };
    });
  }, [t]);
  if (n) return d.jsxs("div", { children: [d.jsx(De, { children: "Storage Stats" }), d.jsxs(He, { gap: "2", children: [d.jsxs(De, { children: ["Evicted: ", (_b = t == null ? void 0 : t.evicted_count) == null ? void 0 : _b.toLocaleString()] }), d.jsxs(De, { children: ["Expired: ", (_c2 = t == null ? void 0 : t.expired_count) == null ? void 0 : _c2.toLocaleString()] }), d.jsxs(De, { children: ["Capacity: ", (_d2 = t == null ? void 0 : t.capacity) == null ? void 0 : _d2.toLocaleString()] })] }), d.jsxs(Nr, { children: [d.jsx(Pr, { children: d.jsxs(dn, { children: [d.jsx(qe, { children: "Type" }), d.jsx(qe, { children: "Active Entries" }), d.jsx(qe, { children: "Egress Entries" }), d.jsx(qe, { children: "Egress Bytes" })] }) }), d.jsx(Ar, { children: n == null ? void 0 : n.map((r) => d.jsxs(dn, { children: [d.jsx(Br, { children: r.type }), d.jsx(Ir, { children: r.activeEntries }), d.jsx(Bt, { value: r.egressCount ?? 0 }), d.jsx(Bt, { value: r.egressBytes ?? 0, inBytes: true })] }, r.type)) })] })] });
}
function J0() {
  var _a2;
  const t = (_a2 = Je(vn)) == null ? void 0 : _a2.health;
  return t ? d.jsxs(He, { children: [d.jsxs(He, { direction: "column", children: [d.jsxs(De, { children: ["Connected stake: ", Is(t.connected_stake), " SOL"] }), d.jsxs(De, { children: ["Staked (", t.connected_staked_peers, ") vs unstaked (", t.connected_unstaked_peers, ")"] }), d.jsx(Q0, { health: t })] }), d.jsxs(He, { direction: "column", gap: "1", children: [d.jsx(xn, { label: "Pull Response entries", values: [t.num_pull_response_entries_rx_success, t.num_pull_response_entries_rx_failure, t.num_pull_response_entries_rx_duplicate] }), d.jsx(xn, { label: "Pull Response messages", values: [t.num_pull_response_messages_rx_success, t.num_pull_response_messages_rx_failure, 0] }), d.jsx(xn, { label: "Push Entries rx", values: [t.num_push_entries_rx_success, t.num_push_entries_rx_failure, t.num_push_entries_rx_duplicate] }), d.jsx(xn, { label: "Push messages rx", values: [t.num_push_messages_rx_success, t.num_push_messages_rx_failure, 0] })] })] }) : null;
}
function xn({ label: e2, values: t }) {
  const n = m.useMemo(() => {
    const r = Fs.sum(t);
    return t.map((i) => i / r * 100);
  }, [t]);
  return d.jsxs(He, { direction: "column", children: [d.jsx(De, { children: e2 }), d.jsxs("svg", { height: "8", width: "100%", fill: "none", xmlns: "http://www.w3.org/2000/svg", style: { alignSelf: "center" }, children: [d.jsx("rect", { height: "8", width: `${n[0]}%`, opacity: 0.6, fill: "green" }), d.jsx("rect", { height: "8", width: `${n[1]}%`, x: `${n[0]}%`, opacity: 0.6, fill: "red" }), d.jsx("rect", { height: "8", width: `${n[2]}%`, x: `${n[0] + n[1]}%`, opacity: 0.6, fill: "blue" })] })] });
}
function Q0({ health: e2 }) {
  const t = m.useMemo(() => [{ id: "staked", label: "staked", value: Number(e2.connected_staked_peers) }, { id: "unstaked", label: "unstaked", value: Number(e2.connected_unstaked_peers) }], [e2]);
  return d.jsx(Bs, { height: 300, width: 300, data: t, enableArcLabels: true, enableArcLinkLabels: true, layers: ["arcs"], animate: false, innerRadius: 0.7 });
}
function ev() {
  return d.jsxs(d.Fragment, { children: [d.jsxs(He, { align: "center", justify: "center", children: [d.jsx(Gf, {}), d.jsx(q0, {})] }), d.jsx(J0, {}), d.jsxs(He, { gap: "9", children: [d.jsx(X0, {}), d.jsx(Z0, {})] })] });
}
function tv() {
  const e2 = Ds(), t = Je(Hs), n = Je(Gs), r = m.useRef(/* @__PURE__ */ new Map()), [i, a] = m.useState([]), [o, s] = m.useState([]);
  m.useEffect(() => {
    var _a2;
    if (!t) return;
    const p = Object.entries(t);
    if (!i.length && ((_a2 = p[0]) == null ? void 0 : _a2[1])) {
      const f = Object.keys(p[0][1]);
      a(f), s(Array.from({ length: f.length }).map(() => -1));
    }
    p.forEach(([f, l]) => {
      r.current.set(f, l);
    });
  }, [i, t]), m.useEffect(() => {
    if (n) for (const p of n.changes) {
      const f = r.current.get(p.row_index.toString());
      f && (f[p.column_name] = p.new_value);
    }
  }, [n]);
  const c = m.useCallback((p, f) => {
    if (f < p || p < 0) return;
    const l = { start_row: p, row_cnt: f - p };
    e2({ topic: "gossip", key: "query_scroll", id: 16, params: l });
  }, [e2]), u = m.useCallback((p) => {
    const f = i == null ? void 0 : i.indexOf(p);
    f !== void 0 && s((l) => {
      const g = l[f] * -1, y = [...l];
      y[f] = g;
      const v = i.filter((_) => _ !== p), h = new Array(v.length).fill(0), b = { col: [p, ...v], dir: [g, ...h] };
      return e2({ topic: "gossip", key: "query_sort", id: 32, params: b }), y;
    });
  }, [i, e2]);
  return { query: c, sort: u, cols: i, rowsCacheRef: r };
}
const nv = 1e3, Un = 0, rv = { Pubkey: 400, "IP Addr": 160 };
function iv() {
  const e2 = Je(Us) ?? nv, { query: t, sort: n, cols: r, rowsCacheRef: i } = tv(), a = m.useCallback(({ startIndex: o, endIndex: s }) => {
    const c = Math.max(0, o - Un), u = Math.min(s + Un, e2 > 0 ? e2 - 1 : s + Un);
    t(c, u);
  }, [t, e2]);
  return d.jsx(d.Fragment, { children: d.jsx(Ys, { totalCount: e2, increaseViewportBy: 100, rangeChanged: a, itemContent: (o) => {
    var _a2;
    const s = (_a2 = i.current) == null ? void 0 : _a2.get(o.toString());
    if (!s) return d.jsx(d.Fragment, { children: d.jsx("td", { colSpan: 5, children: "Loading\u2026" }) });
    const c = Object.entries(s);
    return d.jsx(d.Fragment, { children: c.map(([u, p]) => d.jsx("td", { children: p }, u)) });
  }, fixedHeaderContent: () => d.jsx("tr", { style: { background: qs }, children: r == null ? void 0 : r.map((o) => {
    const s = rv[o];
    return d.jsx("th", { onClick: () => n(o), style: { minWidth: s, padding: "0 8px" }, children: o }, o);
  }) }), style: { height: 300 } }) });
}
function sv() {
  return d.jsxs(He, { direction: "column", gap: "4", flexGrow: "1", flexShrink: "1", height: "100%", children: [d.jsx(iv, {}), d.jsx(ev, {})] });
}
export {
  sv as default
};
