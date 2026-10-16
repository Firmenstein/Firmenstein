"""Small provider-neutral tool abstraction for task-scoped agents."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from functools import update_wrapper
from typing import Any, Callable, get_type_hints

from pydantic import BaseModel, ConfigDict, Field, create_model


def _argument_descriptions(docstring: str) -> dict[str, str]:
    """Extract one-line descriptions from a conventional ``Args:`` block."""
    descriptions: dict[str, str] = {}
    in_args = False
    current: str | None = None
    for raw_line in docstring.splitlines():
        line = raw_line.strip()
        if line == "Args:":
            in_args = True
            current = None
            continue
        if not in_args:
            continue
        if not raw_line.startswith((" ", "\t")) and line:
            break
        if ":" in line and not line.startswith(("-", "*")):
            candidate, description = line.split(":", 1)
            if candidate.isidentifier():
                current = candidate
                descriptions[current] = description.strip()
                continue
        if current and line:
            descriptions[current] = f"{descriptions[current]} {line}".strip()
    return descriptions


def _input_model(func: Callable[..., Any], name: str) -> type[BaseModel]:
    signature = inspect.signature(func)
    hints = get_type_hints(func)
    descriptions = _argument_descriptions(inspect.getdoc(func) or "")
    fields: dict[str, tuple[Any, Any]] = {}
    for parameter in signature.parameters.values():
        if parameter.kind in {
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        }:
            continue
        annotation = hints.get(parameter.name, Any)
        default = ... if parameter.default is inspect.Parameter.empty else parameter.default
        fields[parameter.name] = (
            annotation,
            Field(default=default, description=descriptions.get(parameter.name)),
        )
    return create_model(
        f"{name}Input",
        __config__=ConfigDict(extra="forbid"),
        **fields,
    )


@dataclass
class AgentTool:
    """A validated callable that an Agent SDK adapter can expose."""

    name: str
    description: str
    args_schema: type[BaseModel]
    func: Callable[..., Any] | None = None
    coroutine: Callable[..., Any] | None = None
    timeout_seconds: float | None = None
    error_context: Callable[[Any, Exception], str] | None = None

    def __post_init__(self) -> None:
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        wrapped = self.coroutine or self.func
        if wrapped is not None:
            update_wrapper(self, wrapped)

    def get_input_schema(self) -> type[BaseModel]:
        return self.args_schema

    def error_feedback(self, arguments: Any, error: Exception) -> str:
        """Format an adapter failure, optionally retaining the original request.

        Called at the adapter boundary, including failures before schema
        validation. Context does not change success or retry policy.
        """
        message = f"{type(error).__name__}: {error}"
        if self.error_context is not None:
            try:
                message += "\n" + self.error_context(arguments, error)
            except Exception as context_error:  # retain the original failure
                message += f"\nError context could not be saved: {type(context_error).__name__}: {context_error}"
        return message

    def _validated_kwargs(self, arguments: dict[str, Any] | None) -> dict[str, Any]:
        # Codex App Server may encode an empty dynamic-tool input as
        # ``{"args": {}}`` even when the advertised JSON schema has no
        # properties.  Normalize that wire representation only for genuinely
        # parameterless tools; non-empty schemas must retain strict validation.
        if not self.args_schema.model_fields and arguments == {"args": {}}:
            arguments = {}
        parsed = self.args_schema.model_validate(arguments or {})
        return parsed.model_dump()

    def invoke(self, arguments: dict[str, Any] | None = None) -> Any:
        kwargs = self._validated_kwargs(arguments)
        if self.func is not None:
            return self.func(**kwargs)
        if self.coroutine is None:
            raise RuntimeError(f"Tool {self.name!r} has no implementation")
        return asyncio.run(self.coroutine(**kwargs))

    async def ainvoke(
        self,
        arguments: dict[str, Any] | None = None,
        *,
        default_timeout_seconds: float | None = None,
    ) -> Any:
        kwargs = self._validated_kwargs(arguments)
        timeout_seconds = self.timeout_seconds or default_timeout_seconds

        async def invoke_async() -> Any:
            if self.coroutine is not None:
                return await self.coroutine(**kwargs)
            if self.func is None:
                raise RuntimeError(f"Tool {self.name!r} has no implementation")
            # Keep synchronous analysis tools on the owning event loop. IDA
            # APIs require that identity; asyncio's timeout remains a useful
            # boundary for tools implemented as coroutines.
            return self.func(**kwargs)

        if timeout_seconds is None:
            return await invoke_async()
        if timeout_seconds <= 0:
            raise ValueError("tool timeout_seconds must be positive")
        async with asyncio.timeout(timeout_seconds):
            return await invoke_async()


def tool(
    func_or_name: Callable[..., Any] | str | None = None,
    *,
    description: str | None = None,
    timeout_seconds: float | None = None,
):
    """Decorate a sync or async function as an :class:`AgentTool`."""

    def decorate(func: Callable[..., Any], explicit_name: str | None = None) -> AgentTool:
        name = explicit_name or func.__name__
        return AgentTool(
            name=name,
            description=description or inspect.getdoc(func) or name,
            args_schema=_input_model(func, name),
            coroutine=func if inspect.iscoroutinefunction(func) else None,
            func=None if inspect.iscoroutinefunction(func) else func,
            timeout_seconds=timeout_seconds,
        )

    if callable(func_or_name):
        return decorate(func_or_name)
    if isinstance(func_or_name, str):
        return lambda func: decorate(func, func_or_name)
    return decorate


__all__ = ["AgentTool", "tool"]
