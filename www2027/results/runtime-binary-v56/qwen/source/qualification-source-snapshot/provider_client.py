"""Credential-separated gateway client with bounded, immutable call receipts.

Never import the legacy entrypoint or load the repository .env.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


class GatewayClient:
    def __init__(self, config_path=None, timeout=90):
        path = Path(config_path or Path.home()/'.config/skilllifebench-research/provider.json')
        config = json.loads(path.read_text())
        self._key = config.get('api_key') or config.get('key')
        self.base_url = config['base_url'].rstrip('/')
        if not self.base_url.endswith('/v1'):
            self.base_url += '/v1'
        if not self._key:
            raise ValueError('private provider configuration lacks API key')
        self.timeout = timeout

    def complete(self, model, messages, tools=None, max_tokens=1024, tool_choice=None):
        payload = dict(model=model, messages=messages, max_tokens=max_tokens)
        if tools:
            payload['tools'] = tools
        if tool_choice is not None:
            payload['tool_choice'] = tool_choice
        body = json.dumps(payload, ensure_ascii=False).encode()
        started = time.monotonic()
        receipt = dict(requested_model=model, endpoint=self.base_url+'/chat/completions',
                       timestamp=datetime.now(timezone.utc).isoformat(),
                       request_sha256=hashlib.sha256(body).hexdigest(), status='pending')
        request = urllib.request.Request(receipt['endpoint'], data=body,
                   headers={'Authorization': 'Bearer '+self._key, 'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(8*1024*1024)
                receipt['http_status'] = response.status
            data = json.loads(raw)
            receipt.update(status='ok', served_model=data.get('model'), usage=data.get('usage'),
                           response_sha256=hashlib.sha256(raw).hexdigest(), response=data)
        except urllib.error.HTTPError as exc:
            error = exc.read(8192).decode(errors='replace').replace(self._key, '[REDACTED]')
            receipt.update(status='http_error', http_status=exc.code, error=error)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            receipt.update(status='transport_error', error=str(exc).replace(self._key, '[REDACTED]'))
        receipt['elapsed_seconds'] = round(time.monotonic()-started, 3)
        return receipt


def save_receipt(path, receipt):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
