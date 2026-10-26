import base64
from copy import deepcopy
import json
import hashlib
import os
import unittest
from unittest.mock import MagicMock, patch

from skilllifebench.client import EnvironmentClient
from skilllifebench.privacy import sanitize_transport


class TransportPrivacyTests(unittest.TestCase):
    def test_removes_plain_nested_and_encoded_session_state(self):
        token = "synthetic-continuation-state-for-test"
        cipher = "synthetic-encrypted-reasoning-for-test"
        body = {"output": [{"type": "reasoning", "encrypted_content": cipher}],
                "choices": [{"message": {"content": "Final answer", "tool_calls": []}}]}
        original = {"headers": [["X-Codex-Turn-State", token], ["Content-Type", "application/json"]],
                    "response": body, "response_body": json.dumps(body),
                    "response_body_base64": base64.b64encode(json.dumps(body).encode()).decode()}
        before = deepcopy(original)
        public, counts = sanitize_transport(original)
        self.assertEqual(original, before)
        self.assertNotIn(token, json.dumps(public))
        self.assertNotIn(cipher, json.dumps(public))
        self.assertNotIn(cipher, base64.b64decode(public["response_body_base64"]).decode())
        self.assertEqual(public["response"]["choices"], body["choices"])
        self.assertEqual(public["headers"], [["Content-Type", "application/json"]])
        self.assertEqual(counts["opaque_fields_removed"], 4)

    def test_case_variants_and_error_headers(self):
        data = {"X_CODEX_TURN_STATE": "synthetic-state", "encryptedContent": "synthetic-cipher",
                "error": "X-Codex-Turn-State: synthetic-state\nordinary failure"}
        public, counts = sanitize_transport(data)
        self.assertNotIn("synthetic-state", json.dumps(public))
        self.assertNotIn("synthetic-cipher", json.dumps(public))
        self.assertIn("ordinary failure", public["error"])
        self.assertEqual(counts["opaque_fields_removed"], 3)

    def test_ordinary_task_and_usage_data_are_preserved(self):
        data = {"model": "test-model", "usage": {"output_tokens": 17},
                "choices": [{"message": {"content": "A value at /home/user/report.txt", "tool_calls": []}}],
                "file_base64": base64.b64encode(b"ordinary binary\x00payload").decode()}
        public, counts = sanitize_transport(data)
        self.assertEqual(public, data)
        self.assertEqual(counts, {"opaque_fields_removed": 0, "credential_values_redacted": 0})

    def test_redacts_key_echo_inside_encoded_json(self):
        secret = "synthetic-api-secret-for-test"
        data = {"body_base64": base64.b64encode(json.dumps({"error": secret}).encode()).decode()}
        public, counts = sanitize_transport(data, secret=secret)
        self.assertNotIn(secret, base64.b64decode(public["body_base64"]).decode())
        self.assertEqual(counts["credential_values_redacted"], 1)

    def test_header_pair_and_unlabelled_encoded_body(self):
        opaque = "synthetic-hidden-state"
        data = {"header": ["X-Codex-Turn-State", opaque],
                "body": base64.b64encode(json.dumps({"encrypted_content": opaque}).encode()).decode()}
        public, counts = sanitize_transport(data)
        self.assertNotIn("header", public)
        self.assertEqual(json.loads(base64.b64decode(public["body"])), {})
        self.assertEqual(counts["opaque_fields_removed"], 2)

    def test_semantic_answer_and_tool_arguments_are_unchanged(self):
        answer = json.dumps({"encrypted_content": "legitimate task field", "answer": 42})
        arguments = json.dumps({"path": "result.json", "content": answer})
        data = {"choices": [{"message": {"role": "assistant", "content": answer,
                "tool_calls": [{"function": {"name": "write_file", "arguments": arguments}}]}}],
                "output": [{"type": "message", "content": [{"type": "output_text", "text": answer}]},
                           {"type": "function_call", "arguments": arguments}]}
        public, counts = sanitize_transport(data)
        self.assertEqual(public, data)
        self.assertEqual(counts["opaque_fields_removed"], 0)

    def test_header_objects_continuations_and_unpadded_body(self):
        data = {"headers": [{"name": "X-Codex-Turn-State", "value": "synthetic-state"}],
                "error": "X-Codex-Turn-State: first-fragment\r\n second-fragment\nordinary failure",
                "response_body_base64": base64.urlsafe_b64encode(
                    json.dumps({"encrypted_content": "synthetic-cipher"}).encode()).decode().rstrip("=")}
        public, counts = sanitize_transport(data)
        self.assertEqual(public["headers"], [])
        self.assertNotIn("fragment", public["error"])
        encoded = public["response_body_base64"]
        self.assertEqual(json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))), {})
        self.assertEqual(counts["opaque_fields_removed"], 3)

    def test_malformed_role_or_type_does_not_escape_filter(self):
        value = {"role": [], "type": {}, "content": "answer", "encrypted_content": "synthetic-state"}
        public, counts = sanitize_transport(value)
        self.assertEqual(public["content"], "answer")
        self.assertEqual(counts["opaque_fields_removed"], 1)

    def test_client_keeps_separate_source_and_public_response_hashes(self):
        body = {"model": "test-model", "output": [{"type": "reasoning", "encrypted_content": "synthetic-state"}],
                "choices": [{"message": {"role": "assistant", "content": "42"}}]}
        raw = json.dumps(body).encode()
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = raw
        with patch.dict(os.environ, {"SKILLLIFEBENCH_BASE_URL": "https://example.invalid/v1",
                                     "SKILLLIFEBENCH_API_KEY": "synthetic-test-key"}), \
                patch("urllib.request.urlopen", return_value=response):
            receipt = EnvironmentClient().complete("test-model", [])
        self.assertEqual(receipt["status"], "ok")
        self.assertNotIn("synthetic-state", json.dumps(receipt))
        self.assertEqual(receipt["response_sha256"], hashlib.sha256(raw).hexdigest())
        public = json.dumps(receipt["response"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(receipt["published_response_sha256"], hashlib.sha256(public).hexdigest())
        self.assertEqual(receipt["response"]["choices"], body["choices"])


if __name__ == "__main__":
    unittest.main()
