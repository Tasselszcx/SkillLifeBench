"""Public-runner tests never make live model requests."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from skilllifebench.catalog import DEFAULT_MANIFEST, load_tasks, select_tasks
from skilllifebench.client import EnvironmentClient
from skilllifebench.__main__ import main
from skilllifebench.tasks.backend import LifecycleBackend, grade_task
from skilllifebench.runtime.harness_matrix_session import FilesystemBackend, HarnessLimits, HarnessSession, run_native


class TransportTests(unittest.TestCase):
    def test_env_configuration_does_not_load_dotenv(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "SKILLLIFEBENCH_BASE_URL"):
                EnvironmentClient()

    def test_credentials_rejected_in_url(self):
        with patch.dict(os.environ, {"SKILLLIFEBENCH_BASE_URL": "https://user:password@example.invalid/v1"}, clear=True):
            with self.assertRaisesRegex(ValueError, "credentials"):
                EnvironmentClient()

    def test_transport_receipt_omits_secret_and_headers(self):
        secret = "test-secret-never-persist"
        data = {"model": "test-model", "choices": [{"message": {"role": "assistant", "content": "hello"}}]}
        response = io.BytesIO(json.dumps(data).encode())
        response.status = 200
        environment = {"SKILLLIFEBENCH_BASE_URL": "https://endpoint.invalid/v1", "SKILLLIFEBENCH_API_KEY": secret}
        with patch.dict(os.environ, environment, clear=True), patch("urllib.request.urlopen", return_value=response) as open_url:
            client = EnvironmentClient()
            receipt = client.complete("test-model", [{"role": "user", "content": "task"}])
        request = open_url.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer " + secret)
        redirected = urllib.request.HTTPRedirectHandler().redirect_request(
            request, None, 302, "redirect", {}, "https://other.invalid/v1")
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertNotIn(secret, json.dumps(receipt))
        self.assertNotIn("headers", receipt)
        self.assertEqual(receipt["request_sha256"], hashlib.sha256(request.data).hexdigest())
        self.assertEqual(receipt["status"], "ok")

    def test_server_error_redacts_echoed_key(self):
        secret = "test-secret-never-persist"
        error = urllib.error.HTTPError("https://endpoint.invalid/v1", 401, "unauthorized", {}, io.BytesIO(secret.encode()))
        environment = {"SKILLLIFEBENCH_BASE_URL": "https://endpoint.invalid/v1", "SKILLLIFEBENCH_API_KEY": secret}
        with patch.dict(os.environ, environment, clear=True), patch("urllib.request.urlopen", side_effect=error):
            receipt = EnvironmentClient().complete("model", [])
        self.assertEqual(receipt["error"], "[REDACTED]")


@unittest.skipUnless(DEFAULT_MANIFEST.exists(), "Frozen public manifest has not been staged")
class CatalogTests(unittest.TestCase):
    def test_public_manifest_has_60_instances_and_12_templates(self):
        tasks, binding = load_tasks()
        self.assertEqual((len(tasks), binding["templates"]), (60, 12))
        self.assertEqual({task["class"] for task in tasks}, {"B", "D", "E"})
        self.assertEqual(len(select_tasks(tasks, [tasks[0]["id"]])), 1)
        with self.assertRaisesRegex(ValueError, "Unknown task"):
            select_tasks(tasks, ["not-a-case"])

    def test_list_is_offline_and_structured(self):
        output = io.StringIO()
        with patch("urllib.request.urlopen", side_effect=AssertionError("No network allowed")), redirect_stdout(output):
            status = main(["list", "--json"])
        self.assertEqual(status, 0)
        self.assertEqual(len(json.loads(output.getvalue())["tasks"]), 60)

    def test_path_traversal_rejected_before_execution(self):
        document = json.loads(DEFAULT_MANIFEST.read_text())
        document["tasks"][0]["conditions"]["clean"]["../escape"] = "bad"
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "manifest.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "Unsafe task fixture"):
                load_tasks(path)

    def test_backend_exposes_observations_not_hidden_oracles(self):
        tasks, _ = load_tasks()
        for task in tasks:
            with tempfile.TemporaryDirectory() as root:
                # Construction creates public inputs but executes no skill code.
                backend = LifecycleBackend(task, "attack", Path(root) / "backend", None)
                for public in backend.public_tools:
                    self.assertNotIn("code", public["function"])
                self.assertEqual(backend.initial_messages[0]["role"], "system")
                self.assertEqual(len(backend.initial_messages), 2)
                self.assertTrue(all(type(value) is str for value in backend.ids.values()))


class HarnessTests(unittest.TestCase):
    def test_unsupported_case_rejected_before_creating_output_or_running_tools(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "backend"
            with self.assertRaisesRegex(ValueError, "Summary-contract cases are not supported"):
                FilesystemBackend({"summary_contract": {}}, "clean", output, None)
            self.assertFalse(output.exists())

    def test_incomplete_replay_is_not_reported_as_success(self):
        report = {"complete": False, "planned": 1680, "matched": 1679,
                  "aggregate_counts_match": False, "prefixes_regraded": 8000, "model_calls": 0}
        with patch("skilllifebench.verification.lifecycle_replay.run", return_value=report), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(["replay", "--output", "/tmp/unused-replay-test"]), 2)

    def test_refusal_remains_a_task_failure_and_does_not_retry_for_success(self):
        class Backend:
            initial_messages = [{"role": "user", "content": "task"}]
            public_tools = []
            provenance = {}
            def finalize(self, final, reason):
                return {"task_success": False, "goal_success": False, "joint_success": False,
                        "valid_measurement": True, "stop_reason": reason}
        class Client:
            timeout = 180
            calls = 0
            def complete(self, model, messages, tools, max_tokens, tool_choice):
                self.calls += 1
                payload = {"model": model, "messages": messages, "max_tokens": max_tokens}
                return {"status": "ok", "served_model": model,
                        "request_sha256": hashlib.sha256(json.dumps(payload, ensure_ascii=False).encode()).hexdigest(),
                        "response": {"choices": [{"message": {"role": "assistant", "refusal": "no"}, "finish_reason": "stop"}]}}
        with tempfile.TemporaryDirectory() as root:
            client = Client()
            session = HarnessSession(Backend(), client, "test-model", Path(root) / "session")
            outcome = session.finalize(run_native(session), "test")
        self.assertEqual(client.calls, 1)
        self.assertEqual(outcome["stop_reason"], "model_refusal")
        self.assertIs(outcome["joint_success"], False)


if __name__ == "__main__":
    unittest.main()
