"""Source contexts distinguish shared callsites without hashing coverage."""
import pytest

from fmst_analyzer.analysis.network_analyzer.analyzer_schema import NetworkResourceAgentResult
from fmst_analyzer.analysis.network_analyzer.controller import (
    finalize_resource_result, stable_interaction_id, validate_resource_result,
)
from test_network_analyzer_controller import _View, _fact, _listener


def _context(line):
    return dict(binary_name="httpd", function_name="main", line_number=line, column_number=0)


def test_shared_bind_preserves_three_source_contexts():
    class View(_View):
        def get_full_code(self, *_):
            return "main() {\nif (family == 1) {}\nbind(fd);\nif (family == 2) {}\nif (family == 10) {}\n}"

    drafts = []
    for line, family in [(2, "AF_UNIX"), (4, "AF_INET"), (5, "AF_INET6")]:
        data = _listener(["bind"]).model_dump()
        data.update(context_anchor=_context(line), applicability=f"family == {family}")
        data["identity"]["family"] = family
        if family == "AF_UNIX":
            data.update(disposition="internal_ipc", interaction_kind=None)
        drafts.append(type(_listener(["bind"])).model_validate(data))
    output = NetworkResourceAgentResult(analyses=drafts)
    validate_resource_result(output, "bind", [_fact("bind", "bind", 3)], View())
    final = finalize_resource_result("httpd", "bind", output)
    assert len({item.analysis.interaction_id for item in final}) == 3
    assert {item.analysis.identity.family for item in final} == {"AF_UNIX", "AF_INET", "AF_INET6"}


def test_added_coverage_and_prose_do_not_rename_context():
    data = _listener(["bind"]).model_dump()
    data.update(context_anchor=_context(2), applicability="The socket constructor is reached.")
    draft = type(_listener(["bind"])).model_validate(data)
    richer = draft.model_copy(update={"callsite_ids": ["listen", "bind"], "summary": "More evidence"})
    assert stable_interaction_id("httpd", "bind", draft) == stable_interaction_id("httpd", "bind", richer)


@pytest.mark.parametrize("column", [0, 1, 3])
def test_context_locator_cannot_use_whitespace_or_middle_of_source_token(column):
    class View(_View):
        def get_full_code(self, *_):
            return "main() {\n  socket(fd);\n  bind(fd);\n}"

    draft = _listener(["bind"])
    draft.context_anchor = type(draft.context_anchor)(
        binary_name="httpd", function_name="main", line_number=3, column_number=column)
    validate_resource_result(NetworkResourceAgentResult(analyses=[draft]),
                             "bind", [_fact("bind", "bind", 3)], View())


def test_same_context_conflict_cannot_hide_in_different_coverage():
    data = _listener(["bind"]).model_dump()
    data.update(context_anchor=_context(2), applicability="The socket constructor is reached.")
    draft = type(_listener(["bind"])).model_validate(data)
    conflicting = draft.model_copy(update={"callsite_ids": ["listen"], "summary": "Conflicting conclusion"})
    with pytest.raises(ValueError, match="must belong to the interaction"):
        validate_resource_result(NetworkResourceAgentResult(analyses=[draft, conflicting]),
                                 "bind", [_fact("bind", "bind", 3), _fact("listen", "listen", 4)], _View())


def test_persisted_conflict_cannot_hide_behind_different_ids():
    from test_network_analyzer_schema import _result, _network_analysis
    first = _network_analysis(["bind"])
    second = first.model_copy(update={"interaction_id": "different-arbitrary-id"})
    _result(phase="full", root_binary="httpd", callsites={"bind": _fact("bind", "bind", 3)},
            analyses=[first, second])
