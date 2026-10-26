"""Remove transport credentials and opaque continuation state before persistence."""
from __future__ import annotations

import base64
import binascii
import json
import re


_DROP = object()
_OPAQUE = {"xcodexturnstate", "encryptedcontent"}
_HEADER = re.compile(r"(?im)^(x-codex-turn-state[ \t]*:)[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*")


def _opaque(name):
    return isinstance(name, str) and re.sub(r"[^a-z0-9]", "", name.lower()) in _OPAQUE


def sanitize_transport(value, *, secret=""):
    """Return a new public value and removal counts, retaining ordinary messages.

    JSON strings and explicitly named base64 JSON bodies are inspected too.
    Original response hashes can be retained separately; sanitized bytes must
    never be described as byte-identical to the original transport response.
    """
    counts = {"opaque_fields_removed": 0, "credential_values_redacted": 0}

    def visit(item, field="", depth=0, semantic=False):
        if depth > 100:
            raise ValueError("Transport response nesting exceeds the privacy filter limit")
        if isinstance(item, dict):
            header_name = item.get("name", item.get("key"))
            if (not semantic and isinstance(header_name, str)
                    and re.sub(r"[^a-z0-9]", "", header_name.lower()) == "xcodexturnstate"
                    and ("value" in item or "values" in item)):
                counts["opaque_fields_removed"] += 1
                return _DROP
            result = {}
            for key, entry in item.items():
                if not semantic and _opaque(key):
                    counts["opaque_fields_removed"] += 1
                    continue
                public_key = key.replace(secret, "[REDACTED]") if secret and isinstance(key, str) else key
                if public_key != key:
                    counts["credential_values_redacted"] += 1
                task_data = (semantic or (key == "content" and (
                    item.get("role") in ("assistant", "user", "system", "developer", "tool")
                    or field in {"message", "delta"}))
                    or (key == "arguments" and (field == "function" or item.get("type") == "function_call"))
                    or (key == "text" and item.get("type") in ("input_text", "output_text")))
                public_entry = visit(entry, str(key), depth + 1, semantic=task_data)
                if public_entry is not _DROP:
                    result[public_key] = public_entry
            return result
        if isinstance(item, (list, tuple)):
            if not semantic and len(item) == 2 and _opaque(item[0]):
                counts["opaque_fields_removed"] += 1
                return _DROP
            result = []
            for entry in item:
                public = visit(entry, field, depth + 1, semantic=semantic)
                if public is not _DROP:
                    result.append(public)
            return result
        if not isinstance(item, str):
            return item
        public = item
        if secret and secret in public:
            counts["credential_values_redacted"] += public.count(secret)
            public = public.replace(secret, "[REDACTED]")
        # Answer text and tool arguments are task data, even if they happen to
        # contain JSON fields with the same names as transport metadata.
        if semantic:
            return public
        public, removed = _HEADER.subn(r"\1 [REMOVED]", public)
        counts["opaque_fields_removed"] += removed
        text = public.strip()
        if text.startswith(("{", "[")):
            try:
                parsed = json.loads(public)
            except (ValueError, TypeError):
                pass
            else:
                changed = visit(parsed, field, depth + 1)
                if changed is _DROP:
                    return "null"
                if changed != parsed:
                    return json.dumps(changed, ensure_ascii=False, separators=(",", ":"))
        if (field.lower().endswith(("_base64", "_b64"))
                or field.lower() in {"body", "raw_body", "request_body", "response_body"}):
            try:
                decoded = base64.b64decode(public + "=" * (-len(public) % 4),
                                           altchars=b"-_", validate=True).decode("utf-8")
            except (ValueError, UnicodeError, binascii.Error):
                pass
            else:
                if decoded.lstrip().startswith(("{", "[")):
                    changed = visit(decoded, "", depth + 1)
                    if changed != decoded:
                        encoder = base64.urlsafe_b64encode if "-" in public or "_" in public else base64.b64encode
                        encoded = encoder(changed.encode()).decode("ascii")
                        return encoded
        return public

    result = visit(value)
    return (None if result is _DROP else result), counts
