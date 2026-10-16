"""Line citations distinguish imports from unavailable real function bodies."""
from types import SimpleNamespace
import pytest
from fmst_analyzer.analysis.base.output_validation import OutputValidationError, validate_code_reference


def view(*, external):
    def unavailable(*args):
        raise FileNotFoundError("source body not available")
    return SimpleNamespace(
        lib_dep_graph=SimpleNamespace(get_node_by_name=lambda name: object()),
        get_function_ea=lambda *args: 0x1000,
        get_full_code=unavailable,
        is_external_function=lambda *args, **kwargs: external,
    )


def test_import_line_receives_source_correction():
    with pytest.raises(OutputValidationError, match="line_number=9") as error:
        validate_code_reference(view(external=True), binary_name="library", function_name="import_name", line_number=9)
    assert "external/import" in str(error.value)
    assert "caller" in str(error.value)


def test_missing_regular_body_remains_tool_failure():
    with pytest.raises(FileNotFoundError):
        validate_code_reference(view(external=False), binary_name="library", function_name="real_function", line_number=9)


def test_existing_source_is_used_even_if_external_attribute_is_present():
    source_view = view(external=True)
    source_view.get_full_code = lambda *args: "source line\n"
    assert validate_code_reference(source_view, binary_name="library", function_name="alias", line_number=1) == "source line\n"


def test_native_import_thunk_gets_the_same_locator_feedback():
    source_view = view(external=False)
    source_view.is_external_function = lambda binary, name, *, resolve_thunk=False: resolve_thunk
    with pytest.raises(OutputValidationError, match="native linkage thunk"):
        validate_code_reference(source_view, binary_name="library", function_name="plt_entry", line_number=9)
