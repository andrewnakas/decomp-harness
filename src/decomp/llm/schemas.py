"""What the model is allowed to answer.

Structured output serves two purposes here. It removes the tokens a prose answer
would spend on boilerplate the harness can generate itself, and it makes a
malformed answer a parse error rather than a plausible-looking mistake that
reaches a build.

The model never writes a file, never writes the macro scaffolding, and never
writes a note longer than a packet header. It supplies the body, the write set,
and what it learned.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class Window(BaseModel):
    """One span of guest memory the body writes.

    The oracle rewinds exactly these bytes before running the candidate. A write
    outside them is never rewound and reaches the live program, so an incomplete
    window is not a smaller answer, it is a wrong one.
    """

    base: str = Field(description="Entry register the address derives from, e.g. 'r3'")
    deref: list[int] = Field(
        default_factory=list,
        description="Offsets to follow from the base before applying `offset`, "
                    "for a pointer that must be read before the call",
    )
    offset: int = Field(default=0, description="Byte offset from the resolved base")
    length: int = Field(description="Bytes written at that address")
    why: str = Field(default="", max_length=120, description="What lives there")


class FieldFinding(BaseModel):
    """A struct field the body revealed."""

    struct: str
    offset: int
    size: int = 4
    ctype: str = "u32"
    name: str
    access: Literal["load", "store", "both"] = "both"
    evidence: str = Field(default="", max_length=160,
                          description="The line or expression that shows it")


class NameFinding(BaseModel):
    addr: str = Field(description="Hex address, e.g. '82B28A00'")
    name: str
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    why: str = Field(default="", max_length=120)


class PortAnswer(BaseModel):
    """One ported function."""

    addr: str = Field(description="The address from the packet header, hex")
    code: str = Field(
        description="The body only: statements that go inside Native(). No "
                    "includes, no namespace, no function signature, no macro "
                    "scaffolding - the harness generates all of that."
    )
    windows: list[Window] = Field(
        default_factory=list,
        description="Every span the body writes, including writes made by any "
                    "callee it invokes. Exclude the function's own stack frame.",
    )
    result_registers: list[str] = Field(
        default_factory=list,
        description="Registers the caller reads, e.g. ['r3'] or ['v1']. Compare "
                    "what the caller uses; scratch registers are noise.",
    )
    signature: str = Field(default="", max_length=200)
    name: str = Field(default="", max_length=80,
                      description="A name for this function, if the body makes one clear")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    fields: list[FieldFinding] = Field(default_factory=list)
    names: list[NameFinding] = Field(default_factory=list)
    note: str = Field(default="", max_length=300,
                      description="What it does and why the window set is complete. "
                                  "Facts only; this is the whole note.")
    blocked: Literal["", "gate1", "gate2", "gate3", "gate4"] = Field(
        default="",
        description="Set only if the function cannot be verified: it reaches "
                    "something unreplayable, its write set is not knowable from "
                    "entry state, it reads the clock, or nothing it produces is "
                    "observable. Explain in `note`.",
    )
    needs: list[Literal["assembly", "callee_body", "xrefs", "struct", "probe"]] = Field(
        default_factory=list,
        description="Ask for more context instead of guessing. The harness will "
                    "supply it and re-ask.",
    )
    needs_arg: list[str] = Field(default_factory=list,
                                 description="What to fetch, e.g. a callee address")


class BatchAnswer(BaseModel):
    """Several small functions answered in one call."""

    ports: list[PortAnswer]


class TriageAnswer(BaseModel):
    """A cheap classification pass, used for naming and routing."""

    addr: str
    name: str = ""
    role: str = Field(default="", max_length=160)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


def json_schema(model: type[BaseModel]) -> dict[str, Any]:
    """The JSON Schema both providers accept for structured output."""
    return model.model_json_schema()


def parse_port_answer(payload: Any) -> PortAnswer:
    """Validate a model answer, raising with a message worth sending back."""
    from pydantic import ValidationError

    if payload is None:
        raise ValueError("no structured output in the response")
    try:
        return PortAnswer.model_validate(payload)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:4]
        )
        raise ValueError(f"answer does not match the schema: {problems}") from exc


def parse_batch_answer(payload: Any) -> list[PortAnswer]:
    if isinstance(payload, dict) and "ports" in payload:
        return BatchAnswer.model_validate(payload).ports
    if isinstance(payload, list):
        return [parse_port_answer(item) for item in payload]
    return [parse_port_answer(payload)]
