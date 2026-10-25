"""Environment-configured OpenAI-compatible transport.

Only request/response bodies and nonsecret status metadata are persisted by the
harness. Authorization and response headers are never copied into receipts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


class EnvironmentClient:
    def __init__(self, *, timeout=180):
        base = os.environ.get("SKILLLIFEBENCH_BASE_URL", "").rstrip("/")
        key = os.environ.get("SKILLLIFEBENCH_API_KEY", "")
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Set SKILLLIFEBENCH_BASE_URL to an OpenAI-compatible API base URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("API base URL must not contain credentials, query parameters or fragments")
        if key and key in base:
            raise ValueError("API key must be supplied only through SKILLLIFEBENCH_API_KEY")
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not local:
            raise ValueError("Remote API endpoints require HTTPS")
        if not key and not local:
            raise ValueError("Set SKILLLIFEBENCH_API_KEY for the remote endpoint")
        self.base_url, self._key, self.timeout = base, key, timeout

    def _safe(self, value):
        if isinstance(value, dict):
            return {self._safe(key): self._safe(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._safe(item) for item in value]
        if isinstance(value, str) and self._key:
            return value.replace(self._key, "[REDACTED]")
        return value

    def complete(self, model, messages, tools=None, max_tokens=2048, tool_choice=None):
        payload = {"model": model, "messages": messages, "max_tokens": max_tokens}
        if tools:
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        body = json.dumps(payload, ensure_ascii=False).encode()
        endpoint = self.base_url + "/chat/completions"
        receipt = {"requested_model": model, "endpoint": endpoint,
                   "timestamp": datetime.now(timezone.utc).isoformat(),
                   "request_sha256": hashlib.sha256(body).hexdigest(), "status": "pending"}
        headers = {"Content-Type": "application/json"}
        request = urllib.request.Request(endpoint, data=body, headers=headers)
        if self._key:
            # urllib excludes unredirected headers from redirected requests.
            # An endpoint redirect must never forward the API credential.
            request.add_unredirected_header("Authorization", "Bearer " + self._key)
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                receipt["http_status"] = response.status
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError("API response exceeds 8 MiB")
            data = json.loads(raw)
            safe = self._safe(data)
            receipt.update(status="ok", served_model=safe.get("model"), usage=safe.get("usage"),
                           response_sha256=hashlib.sha256(raw).hexdigest(), response=safe,
                           credential_redaction_applied=safe != data)
        except urllib.error.HTTPError as error:
            detail = error.read(8192).decode(errors="replace")
            receipt.update(status="http_error", http_status=error.code, error=self._safe(detail))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, AttributeError) as error:
            receipt.update(status="transport_error", error=self._safe(str(error)))
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 6)
        return receipt
