"""Lossless string framing for a separate Qwen transport profile.

The pinned template writes `<parameter=name>\n` + value + `\n</parameter>`.
Framed values lose exactly one LF at each edge. Additional whitespace belongs
to the value. Inline values with no boundary LF retain every character. A
one-sided LF, including CRLF framing, is rejected rather than repaired. Typed
decoding, exact nullable null/None reservation, duplicate checks and supported
schema constraints come from the unchanged pinned schema parser.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from . import local_qwen35_schema_parser as schema

SCHEMA_HELPER_SHA256 = "c98b49f8b8cc716f000d97b8a6f91dea694a0ffcb45baa14f0d1f3e1d2e5de31"
TEMPLATE_SHA256 = "a4aee8afcf2e0711942cf848899be66016f8d14a889ff9ede07bca099c28f715"
ToolParseError = schema.ToolParseError
AmbiguousToolParseError = schema.AmbiguousToolParseError
check_schema = schema.check_schema

if hashlib.sha256(Path(schema.__file__).read_bytes()).hexdigest() != SCHEMA_HELPER_SHA256:
    raise ValueError("Frozen schema helper changed")


def parameter_value(raw):
    """Remove only the two LFs emitted by the exact frozen template."""
    first, last = raw.startswith("\n"), raw.endswith("\n")
    if first or last:
        if not (first and last and len(raw) >= 2):
            raise ToolParseError("Asymmetric parameter LF framing; no whitespace repair applied")
        return raw[1:-1]
    return raw


def parse_qwen_tools(text, tools):
    schemas = {}
    for tool in tools or []:
        name = tool["function"]["name"]
        if name in schemas: raise ToolParseError("Duplicate function schema")
        schemas[name] = tool["function"]["parameters"]
    if "<tool_call>" not in text:
        if "<function=" in text or "</tool_call>" in text: raise ToolParseError("Incomplete tool-call envelope")
        return [], text.strip()
    blocks = list(re.finditer(r"<tool_call>\s*(.*?)\s*</tool_call>", text, re.DOTALL))
    if text.count("<tool_call>") != len(blocks) or text.count("</tool_call>") != len(blocks):
        raise ToolParseError("Unbalanced tool-call envelope")
    calls = []
    for block in blocks:
        matched = re.fullmatch(r"<function=([A-Za-z_][A-Za-z0-9_]*)>\s*(.*?)\s*</function>", block.group(1), re.DOTALL)
        if not matched: raise ToolParseError("Malformed function block")
        name, body = matched.groups()
        if name not in schemas: raise ToolParseError("Unknown function name")
        specification = schemas[name]; check_schema(specification); arguments = {}; position = 0
        # No whitespace matcher may consume any part of a parameter's value.
        for parameter in re.finditer(r"<parameter=([A-Za-z_][A-Za-z0-9_]*)>(.*?)</parameter>", body, re.DOTALL):
            if body[position:parameter.start()].strip(): raise ToolParseError("Unexpected text between parameters")
            key, raw = parameter.groups()
            if key in arguments: raise ToolParseError("Duplicate parameter")
            field = specification.get("properties", {}).get(key)
            if field is None: raise ToolParseError("Unknown parameter")
            arguments[key] = schema._decode(parameter_value(raw), field, specification)
            position = parameter.end()
        if body[position:].strip(): raise ToolParseError("Unexpected function-body text")
        schema._validate(arguments, specification, specification)
        calls.append({"id": "local-call-" + str(len(calls)), "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False)}})
    remainder = text
    for block in reversed(blocks): remainder = remainder[:block.start()] + remainder[block.end():]
    return calls, remainder.strip()


def parse_qwen_completion(raw, tools):
    text = raw.rstrip()
    for ending in ("<|im_end|>", "<|endoftext|>"):
        if text.endswith(ending): text = text[:-len(ending)].rstrip()
    reasoning = None
    if text.lstrip().startswith("<think>"):
        matched = re.match(r"^\s*<think>(.*?)</think>\s*", text, re.DOTALL)
        if not matched: raise ToolParseError("Unclosed reasoning block")
        reasoning = matched.group(1).strip(); text = text[matched.end():]
    calls, content = parse_qwen_tools(text, tools)
    return calls, content, reasoning
