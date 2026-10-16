"""Unit tests for AnalysisView.collect_effective_callsites.

Build a minimal stubbed view (no real ADG/IDA needed) and verify:
 - thunk frames are skipped
 - deduplication by (binary, function)
 - lex-sort deterministic output
 - total_count reflects full set before K-cap
 - empty result on unknown target
"""
from dotenv import load_dotenv
load_dotenv()

from types import SimpleNamespace

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import (
    AnalysisView,
    EffectiveCallsite,
)
from fmst_analyzer.nodes.common import FunctionAttr


class _Bin:
    def __init__(self, name): self.name = name


class _Fn:
    def __init__(self, module, name, attrs=FunctionAttr(0)):
        self.module = module
        self.decompiled_name = name
        self.name = name
        self.artifact_stem = name
        self.attrs = attrs

    def has_attr(self, attr):
        return bool(self.attrs & attr)


def _build_view():
    """Fixture topology (edges = caller → callee):
        httpd::handler_a ──► httpd::__imp_foo ──► libfoo::foo
        httpd::handler_b ──► httpd::__imp_foo ──► libfoo::foo
        httpd::handler_c ──► httpd::wrapper ──► httpd::__imp_foo ──► libfoo::foo

    handler_a / handler_b / handler_c are real httpd functions.
    __imp_foo and wrapper are thunks (wrapper's body is
    `return __imp_foo(a)`).
    After thunk pruning, 3 distinct non-thunk callers reach libfoo::foo.
    """
    foo = _Fn("libfoo.so", "foo")
    imp_foo = _Fn("httpd", "__imp_foo", FunctionAttr.PLT)
    wrapper = _Fn("httpd", "wrapper", FunctionAttr.THUNK)
    a = _Fn("httpd", "handler_a")
    b = _Fn("httpd", "handler_b")
    c = _Fn("httpd", "handler_c")

    callers = {
        id(foo): [imp_foo],
        id(imp_foo): [a, b, wrapper],
        id(wrapper): [c],
        id(a): [],
        id(b): [],
        id(c): [],
    }
    callsite_lines = {
        (id(a), id(imp_foo)): 100,
        (id(b), id(imp_foo)): 200,
        (id(wrapper), id(imp_foo)): 42,
        (id(c), id(wrapper)): 50,
        (id(imp_foo), id(foo)): 3,
    }

    code = {
        ("httpd", "__imp_foo"): (
            "int __imp_foo(const char *a)\n"
            "{\n"
            "  return ___ext_foo(a);\n"
            "}\n"
        ),
        ("httpd", "wrapper"): (
            "int wrapper(const char *a)\n"
            "{\n"
            "  return __imp_foo(a);\n"
            "}\n"
        ),
        ("httpd", "handler_a"): (
            "int handler_a(int x) {\n"
            "  if (x < 0) return -1;\n"
            "  return __imp_foo(\"key\");\n"
            "}\n"
        ),
        ("httpd", "handler_b"): (
            "int handler_b(int x) {\n"
            "  do_setup();\n"
            "  return __imp_foo(\"key\");\n"
            "}\n"
        ),
        ("httpd", "handler_c"): (
            "int handler_c(int x) {\n"
            "  log(\"before\");\n"
            "  return wrapper(\"key\");\n"
            "}\n"
        ),
    }

    class FakeCG:
        def has_node_by_name(self, name):
            return name in {"foo", "__imp_foo", "wrapper",
                            "handler_a", "handler_b", "handler_c"}
        def get_node_by_name(self, name):
            return {"foo": foo, "__imp_foo": imp_foo, "wrapper": wrapper,
                    "handler_a": a, "handler_b": b, "handler_c": c}[name]
        def get_callers_of(self, fn):
            return callers.get(id(fn), [])

    cg = FakeCG()
    httpd_bin = _Bin("httpd")
    libfoo_bin = _Bin("libfoo.so")

    class FakeADG:
        scope = {httpd_bin, libfoo_bin}
        def is_reachable(self, fn): return True
        def get_binary_callgraphs(self):
            return {httpd_bin: cg, libfoo_bin: cg}
        def get_predecessors_by_type(self, fn, edge_type):
            if fn is foo: return [imp_foo]
            return []

    adg = FakeADG()

    class FakeLDG:
        def get_node_by_name(self, name):
            return {"httpd": httpd_bin, "libfoo.so": libfoo_bin}.get(name)

    def _get_full_code(binary, function):
        return code.get((binary, function), "")

    class _CS:
        def __init__(self, callee_name, line):
            self.callee_name = callee_name
            self.line_number = line

    def _attach_callsites(fn, outbound):
        def gc():
            out = {}
            for (caller_id, callee_id), line in callsite_lines.items():
                if caller_id != id(fn):
                    continue
                callee = next(
                    f for f in [foo, imp_foo, wrapper, a, b, c]
                    if id(f) == callee_id
                )
                out[(callee.decompiled_name, line)] = _CS(
                    callee.decompiled_name, line,
                )
            return out
        fn.get_callsites = gc

    for fn in [foo, imp_foo, wrapper, a, b, c]:
        _attach_callsites(fn, callers.get(id(fn), []))

    view = SimpleNamespace(
        adg=adg, root=httpd_bin, lib_dep_graph=FakeLDG(),
        get_full_code=_get_full_code,
    )
    return AnalysisView.collect_effective_callsites.__get__(
        view, type(view)
    )


def test_collect_skips_thunks_and_dedups_by_function():
    collect = _build_view()
    sites, total = collect("libfoo.so", "foo")
    fns = sorted((s.binary, s.function) for s in sites)
    assert fns == [
        ("httpd", "handler_a"),
        ("httpd", "handler_b"),
        ("httpd", "handler_c"),
    ]
    assert total == 3
    assert len(sites) == 3


def test_external_import_without_thunk_name_or_source_is_traversed():
    collect = _build_view()
    view = collect.__self__
    graph = next(iter(view.adg.get_binary_callgraphs().values()))
    external = graph.get_node_by_name("__imp_foo")
    external.name = external.decompiled_name = external.artifact_stem = "vendor_import"
    external.attrs = FunctionAttr.EXTERNAL
    original = view.get_full_code

    def source(binary, function):
        if function == "vendor_import":
            raise AssertionError("An external import has no C body to query")
        return original(binary, function)

    view.get_full_code = source
    sites, total = collect("libfoo.so", "foo")
    assert total == 3
    assert {site.function for site in sites} == {"handler_a", "handler_b", "handler_c"}


def test_collect_lex_sorted_output():
    collect = _build_view()
    sites, _ = collect("libfoo.so", "foo")
    keys = [(s.binary, s.function, s.representative_line) for s in sites]
    assert keys == sorted(keys)


def test_collect_representative_line_points_at_thunk_call():
    collect = _build_view()
    sites, _ = collect("libfoo.so", "foo")
    by_fn = {s.function: s for s in sites}
    assert by_fn["handler_a"].representative_line == 100
    assert by_fn["handler_b"].representative_line == 200
    assert by_fn["handler_c"].representative_line == 50


def test_collect_reached_via_omits_thunk_frames():
    collect = _build_view()
    sites, _ = collect("libfoo.so", "foo")
    by_fn = {s.function: s for s in sites}
    for s in sites:
        assert "__imp_foo" not in s.reached_via
        assert "wrapper" not in s.reached_via


def test_collect_context_snippet_has_line_prefix():
    collect = _build_view()
    sites, _ = collect("libfoo.so", "foo")
    for s in sites:
        assert str(s.representative_line) in s.context_snippet


def test_collect_empty_on_unknown_target():
    collect = _build_view()
    sites, total = collect("libfoo.so", "nonexistent_fn")
    assert sites == []
    assert total == 0


def test_collect_uses_structural_thunk_attribute_without_code_artifact():
    """A PLT thunk has no CTree snapshot by design and must not be read as C."""
    target = _Fn("libfoo.so", "foo")
    plt = _Fn("httpd", "foo_plt", FunctionAttr.THUNK | FunctionAttr.PLT)
    handler = _Fn("httpd", "handler")

    callers = {id(target): [plt], id(plt): [handler], id(handler): []}

    class FakeCG:
        def has_node_by_name(self, name):
            return name in {"foo", "foo_plt", "handler"}

        def get_node_by_name(self, name):
            return {"foo": target, "foo_plt": plt, "handler": handler}[name]

        def get_callers_of(self, fn):
            return callers.get(id(fn), [])

    cg = FakeCG()
    httpd_bin = _Bin("httpd")
    libfoo_bin = _Bin("libfoo.so")

    class FakeADG:
        scope = {httpd_bin, libfoo_bin}

        def is_reachable(self, fn):
            return True

        def get_binary_callgraphs(self):
            return {httpd_bin: cg, libfoo_bin: cg}

        def get_predecessors_by_type(self, fn, edge_type):
            return [plt] if fn is target else []

    class FakeLDG:
        def get_node_by_name(self, name):
            return {"httpd": httpd_bin, "libfoo.so": libfoo_bin}.get(name)

    class _CS:
        def __init__(self, callee_name, line):
            self.callee_name = callee_name
            self.line_number = line

    target.get_callsites = lambda: {}
    plt.get_callsites = lambda: {"foo": _CS("foo", 1)}
    handler.get_callsites = lambda: {"foo_plt": _CS("foo_plt", 3)}

    def _get_full_code(binary, function):
        if function == "foo_plt":
            raise AssertionError("structural thunk must not request decompiled C")
        return "int handler(void) {\n  prepare();\n  return foo_plt();\n}\n"

    view = SimpleNamespace(
        adg=FakeADG(),
        root=httpd_bin,
        lib_dep_graph=FakeLDG(),
        get_full_code=_get_full_code,
    )
    collect = AnalysisView.collect_effective_callsites.__get__(view, type(view))

    sites, total = collect("libfoo.so", "foo")

    assert total == 1
    assert [(site.binary, site.function) for site in sites] == [
        ("httpd", "handler"),
    ]
    assert sites[0].reached_via == "foo"


def test_collect_respects_max_sites_cap():
    collect = _build_view()
    sites, total = collect("libfoo.so", "foo", max_sites=2)
    assert len(sites) == 2
    assert total == 3


def test_collect_stops_at_first_non_thunk_caller_per_path():
    """A non-thunk function reaches the target through a non-thunk
    caller. Only the frame closest to the target should emit — the
    grandparent reaches the resource via the handler's own decision
    point, which is a different analysis (what does handler's caller
    do with handler's return value).

    Topology:
        grandparent  ──►  handler  ──►  __imp_foo  ──►  libfoo::foo
        (non-thunk)       (non-thunk)   (thunk)         (target)

    Expected: only `handler` is emitted. `grandparent` is not.
    """
    target = _Fn("libfoo.so", "foo")
    imp = _Fn("httpd", "__imp_foo", FunctionAttr.PLT)
    handler = _Fn("httpd", "handler")
    gp = _Fn("httpd", "grandparent")

    callers = {
        id(target): [imp],
        id(imp): [handler],
        id(handler): [gp],
        id(gp): [],
    }
    lines = {
        (id(handler), id(imp)): 42,
        (id(gp), id(handler)): 77,
        (id(imp), id(target)): 3,
    }
    code = {
        ("httpd", "__imp_foo"): "int __imp_foo(const char *a) {\n  return ext_foo(a);\n}\n",
        ("httpd", "handler"): (
            "int handler(int x) {\n"
            "  do_setup();\n"
            "  return __imp_foo(\"key\");\n"
            "}\n"
        ),
        ("httpd", "grandparent"): (
            "int grandparent(void) {\n"
            "  int r = handler(0);\n"
            "  if (r != 0) return -1;\n"
            "  return 0;\n"
            "}\n"
        ),
    }

    class FakeCG:
        def has_node_by_name(self, name):
            return name in {"foo", "__imp_foo", "handler", "grandparent"}
        def get_node_by_name(self, name):
            return {"foo": target, "__imp_foo": imp,
                    "handler": handler, "grandparent": gp}[name]
        def get_callers_of(self, fn):
            return callers.get(id(fn), [])

    cg = FakeCG()
    httpd_bin = _Bin("httpd")
    libfoo_bin = _Bin("libfoo.so")

    class FakeADG:
        scope = {httpd_bin, libfoo_bin}
        def is_reachable(self, fn): return True
        def get_binary_callgraphs(self):
            return {httpd_bin: cg, libfoo_bin: cg}
        def get_predecessors_by_type(self, fn, edge_type):
            if fn is target:
                return [imp]
            return []

    adg = FakeADG()

    class FakeLDG:
        def get_node_by_name(self, name):
            return {"httpd": httpd_bin, "libfoo.so": libfoo_bin}.get(name)

    def _get_full_code(binary, function):
        return code.get((binary, function), "")

    class _CS:
        def __init__(self, callee_name, line):
            self.callee_name = callee_name
            self.line_number = line

    def _attach_callsites(fn):
        def gc():
            out = {}
            for (caller_id, callee_id), line in lines.items():
                if caller_id != id(fn):
                    continue
                callee = next(
                    f for f in [target, imp, handler, gp]
                    if id(f) == callee_id
                )
                out[(callee.decompiled_name, line)] = _CS(
                    callee.decompiled_name, line,
                )
            return out
        fn.get_callsites = gc

    for fn in [target, imp, handler, gp]:
        _attach_callsites(fn)

    view = SimpleNamespace(
        adg=adg, root=httpd_bin, lib_dep_graph=FakeLDG(),
        get_full_code=_get_full_code,
    )
    collect = AnalysisView.collect_effective_callsites.__get__(
        view, type(view)
    )
    sites, total = collect("libfoo.so", "foo")

    # Only handler emitted; grandparent is NOT a decision point for
    # this resource (grandparent checks handler's return, which is a
    # separate analysis).
    fns = [(s.binary, s.function) for s in sites]
    assert fns == [("httpd", "handler")], (
        f"Expected only 'handler' emitted; got {fns}. "
        "grandparent reaches target through handler's own decision "
        "point and should NOT emit."
    )
    assert total == 1


def test_collect_walks_through_library_internal_non_thunk_wrappers():
    """Library-internal non-thunk wrappers (e.g., libnvram::nvram_get
    with ``if (j_nvram_init()) return 0;``) are NOT decision points
    for view.root's system-level violation_effect — they only
    propagate failure signals. BFS should walk through them, just
    like thunks, and emit only view.root non-thunk frames.

    Topology mirrors the R6700v3 nvram case:
        httpd::handler  ──►  httpd::__imp_wrap  ──►  lib::wrap  ──►  lib::target
        (non-thunk       (thunk: return           (non-thunk:        (target)
         in view.root)    __imp_wrap(a))           has branching
                                                   error check)

    Expected: only `httpd::handler` is emitted. The library-internal
    `lib::wrap` is walked through because it's not in view.root.
    """
    target = _Fn("libnvram.so", "target")
    wrap = _Fn("libnvram.so", "wrap")
    imp = _Fn("httpd", "__imp_wrap", FunctionAttr.PLT)
    handler = _Fn("httpd", "handler")

    callers = {
        id(target): [wrap],
        id(wrap): [imp],
        id(imp): [handler],
        id(handler): [],
    }
    lines = {
        (id(wrap), id(target)): 5,
        (id(imp), id(wrap)): 3,
        (id(handler), id(imp)): 42,
    }
    code = {
        # Library wrapper with branching error check — NON-thunk
        # structurally but still just propagates the failure signal.
        ("libnvram.so", "wrap"): (
            "int wrap(const char *a) {\n"
            "  if (target_init()) return 0;\n"
            "  return target(a);\n"
            "}\n"
        ),
        ("httpd", "__imp_wrap"): (
            "int __imp_wrap(const char *a) {\n"
            "  return ext_wrap(a);\n"
            "}\n"
        ),
        # The real httpd-layer decision point
        ("httpd", "handler"): (
            "int handler(int x) {\n"
            "  value = wrap(\"key\");\n"
            "  if (!value) return render_error_page();\n"
            "}\n"
        ),
    }

    class FakeCG:
        def has_node_by_name(self, name):
            return name in {"target", "wrap", "__imp_wrap", "handler"}
        def get_node_by_name(self, name):
            return {"target": target, "wrap": wrap,
                    "__imp_wrap": imp, "handler": handler}[name]
        def get_callers_of(self, fn):
            return callers.get(id(fn), [])

    cg = FakeCG()
    httpd_bin = _Bin("httpd")
    libnvram_bin = _Bin("libnvram.so")

    class FakeADG:
        scope = {httpd_bin, libnvram_bin}
        def is_reachable(self, fn): return True
        def get_binary_callgraphs(self):
            return {httpd_bin: cg, libnvram_bin: cg}
        def get_predecessors_by_type(self, fn, edge_type):
            if fn is wrap: return [imp]  # cross-binary IMPL edge
            return []

    adg = FakeADG()

    class FakeLDG:
        def get_node_by_name(self, name):
            return {"httpd": httpd_bin, "libnvram.so": libnvram_bin}.get(name)

    def _get_full_code(binary, function):
        return code.get((binary, function), "")

    class _CS:
        def __init__(self, callee_name, line):
            self.callee_name = callee_name
            self.line_number = line

    def _attach_callsites(fn):
        def gc():
            out = {}
            for (caller_id, callee_id), line in lines.items():
                if caller_id != id(fn):
                    continue
                callee = next(
                    f for f in [target, wrap, imp, handler]
                    if id(f) == callee_id
                )
                out[(callee.decompiled_name, line)] = _CS(
                    callee.decompiled_name, line,
                )
            return out
        fn.get_callsites = gc

    for fn in [target, wrap, imp, handler]:
        _attach_callsites(fn)

    view = SimpleNamespace(
        adg=adg, root=httpd_bin, lib_dep_graph=FakeLDG(),
        get_full_code=_get_full_code,
    )
    collect = AnalysisView.collect_effective_callsites.__get__(
        view, type(view)
    )
    sites, total = collect("libnvram.so", "target")

    # Only the view.root handler is emitted; lib::wrap is walked
    # through (not emitted) even though it's technically non-thunk
    # per _is_thunk's rule.
    fns = [(s.binary, s.function) for s in sites]
    assert fns == [("httpd", "handler")], (
        f"Expected only view.root handler; got {fns}. "
        "Library-internal non-thunk wrappers should be walked "
        "through, not emitted, per Fix A design."
    )
    assert total == 1


def test_source_name_and_trivial_body_do_not_skip_a_real_caller():
    collect = _build_view()
    view = collect.__self__
    cg = next(iter(view.adg.get_binary_callgraphs().values()))
    cg.get_node_by_name("__imp_foo").attrs = FunctionAttr(0)
    sites, _ = collect("libfoo.so", "foo")
    assert [site.function for site in sites] == ["__imp_foo"]
