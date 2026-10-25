"""Expose the five frozen AgentDojo runtimes to a common harness session.

Only initialize/step/score operations enter the existing isolated executor.
Opaque native state never becomes a host object. Model policy, budgets, identity
qualification and amended scientific analysis belong to the matrix controller.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import importlib
import json
from pathlib import Path
import sys


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class SourceBackendError(ValueError):
    """An original source binding or runtime transition could not be verified."""


@dataclass(frozen=True)
class SourceGroup:
    name: str
    plan: str
    plan_sha256: str
    cases: int
    module: str
    runtime_class: str
    prepare: str | None = None
    controller: str = "agentdojo_episode_runner"


SOURCE_GROUPS = {
    "agentdojo_fixed_source_state_runtime_v1": SourceGroup(
        "agentdojo4", "experiments/agentdojo-four-model-plan.json",
        "ea748fadc61f624e84c1814438428e28c22bcd2fb4e8a3dbb1aea570d1016385", 4,
        "agentdojo_fixed_runtime", "AgentDojoFixedRuntime"),
    "agentdojo_original_registry_fixed_source_runtime_v2": SourceGroup(
        "agentdojo18", "experiments/agentdojo-candidate18-model-plan.json",
        "20e50e521631532991339bfdf23371c72f045c8cf07b233c6f6773f75f76e07f", 18,
        "agentdojo_candidate_fixed_runtime", "AgentDojoCandidateFixedRuntime",
        "agentdojo_candidate_fixed_prepare"),
    "agentdojo_original_registry_banking_fixed_source_runtime_v1": SourceGroup(
        "agentdojo_banking15", "experiments/agentdojo-banking15-model-plan.json",
        "0fd0e9601b0d45f350481825d908c7b86bf55508b10edffe67eff1f6418df337", 15,
        "agentdojo_banking_fixed_runtime", "AgentDojoBankingFixedRuntime",
        "agentdojo_banking_fixed_prepare"),
    "agentdojo_original_registry_next40_fixed_source_runtime_v1": SourceGroup(
        "agentdojo_next40", "experiments/agentdojo-next40-model-plan.json",
        "370af1827c5cebf2c7c081eb2c2a64e069faa6b047fc301a4ef81c594a9ec482", 40,
        "agentdojo_next40_fixed_runtime", "AgentDojoNext40FixedRuntime",
        "agentdojo_next40_fixed_prepare"),
    "agentdojo_original_registry_next51_fixed_source_runtime_v1": SourceGroup(
        "agentdojo_next51", "experiments/agentdojo-next51-model-plan02.json",
        "62b19677ff1761bb95b5007a8c46e8a15772362b15e3c72584ebb9da94a3d334", 51,
        "agentdojo_next51_fixed_runtime", "AgentDojoNext51FixedRuntime",
        "agentdojo_next51_fixed_prepare", "agentdojo_next51_episode_runner"),
}


def _bound_file(root, relative, expected):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise SourceBackendError("Source input must be relative to source_root")
    path = root / path
    if not path.is_file() or _sha(path.read_bytes()) != expected:
        raise SourceBackendError("Frozen source input differs: " + str(path))
    return path


def source_backend_spec(case, source_root):
    """Authenticate source plans/inputs/code without constructing a runtime.

    This function is safe for plan preparation: it performs file reads only.
    Constructors and native initialization run only when the returned backend's
    context is entered after the matrix controller freezes its plan.
    """
    try:
        group = SOURCE_GROUPS[case["execution_backend"]]
    except (KeyError, TypeError) as error:
        raise SourceBackendError("Unsupported AgentDojo execution_backend") from error
    root = Path(source_root).absolute()
    plan_path = _bound_file(root, group.plan, group.plan_sha256)
    plan = json.loads(plan_path.read_bytes())
    cases = plan["cases"]
    if len(cases) != group.cases or len({row["id"] for row in cases}) != len(cases):
        raise SourceBackendError("Frozen source population differs")
    original = next((row for row in cases if row["id"] == case.get("id")), None)
    if original is None or _canonical(case) != _canonical(original):
        raise SourceBackendError("Case differs from the original frozen source plan")
    content = {key: value for key, value in case.items() if key != "case_sha256"}
    if _sha(_canonical(content).encode()) != case.get("case_sha256"):
        raise SourceBackendError("Frozen source case hash differs")

    code = Path(__file__).parent
    names = {group.module + ".py", "agentdojo_runtime_prototype.py", "isolated_executor.py",
             "_sandbox_worker.py", group.controller + ".py", "episode_runner.py",
             "effect_oracle.py", "provider_client.py"}
    if group.prepare:
        names.update({group.prepare + ".py", "agentdojo_candidate_prepare.py", "agentdojo_candidate_fixed_worker.py"})
    else:
        names.add("agentdojo_fixed_worker.py")
    execution_hashes = {}
    for name in sorted(names):
        expected = plan["implementation_sha256"].get(name)
        if expected is None or _sha((code / name).read_bytes()) != expected:
            raise SourceBackendError("Frozen execution implementation differs: " + name)
        execution_hashes[name] = expected

    if group.prepare:
        paths = {name: _bound_file(root, plan["prerequisite_paths"][name], plan["prerequisite_sha256"][name])
                 for name in ("assembly_manifest", "contexts", "source_receipt", "selection_plan")}
        kwargs = {"assembly_dir": paths["assembly_manifest"].parent, "contexts_file": paths["contexts"],
                  "source_receipt": paths["source_receipt"], "selection_plan": paths["selection_plan"]}
    else:
        paths = {
            "prototype_manifest": _bound_file(root, "authenticity/agentdojo-runtime-prototype/preparation_manifest.json",
                                              plan["prototype_manifest_sha256"]),
            "source_receipt": _bound_file(root, "dataset/agentdojo-four-pilot-fixed-sources-20261014b/source_receipt.json",
                                          plan["runtime_source_receipt_sha256"]),
        }
        kwargs = {"prototype_dir": paths["prototype_manifest"].parent, "source_receipt": paths["source_receipt"]}
    return {
        "group": group, "runtime_kwargs": kwargs,
        "provenance": {
            "source_group": group.name, "execution_backend": case["execution_backend"],
            "source_plan_path": str(plan_path), "source_plan_sha256": group.plan_sha256,
            "source_case_sha256": case["case_sha256"],
            "source_inputs": {name: {"path": str(path), "sha256": _sha(path.read_bytes())} for name, path in paths.items()},
            "execution_implementation_sha256": execution_hashes,
            "state_handling": "Opaque native state is decoded only by the existing isolated worker.",
        },
    }


def _runtime_factory(group, **kwargs):
    module = importlib.import_module("www2027." + group.module)
    return getattr(module, group.runtime_class)(**kwargs)


class AgentDojoBackend:
    """One bounded original source session; model/tool budgets are external."""

    def __init__(self, case, condition, output_dir, spec):
        if condition not in ("clean", "injected") or condition not in case.get("conditions", {}):
            raise SourceBackendError("Condition must be the original clean or injected condition")
        self.case, self.condition = copy.deepcopy(case), condition
        self.output_dir, self.spec = Path(output_dir), spec
        self.provenance = copy.deepcopy(spec["provenance"])
        self.initial_messages, self.public_tools = [], []
        self.events, self.transitions = [], []
        self.handle = self.last_verified_handle = None
        self.runtime = None
        self._entered = self._closed = self._finalized = False
        self._outcome = None
        self.error = None

    def _transition(self, transition, operation):
        record = {"operation": operation, "receipt_path": str(transition.receipt_path),
                  "receipt_sha256": _sha(Path(transition.receipt_path).read_bytes())}
        self.transitions.append(record)
        self.handle = transition.handle
        if self.handle is not None:
            self.last_verified_handle = self.handle
        return record

    def __enter__(self):
        if self._entered or self._closed:
            raise SourceBackendError("Source session cannot be entered twice")
        self._entered = True
        self.runtime = _runtime_factory(self.spec["group"], output_dir=self.output_dir, **self.spec["runtime_kwargs"])
        try:
            self.runtime.__enter__()
            initial = self.runtime.initialize(self.case["id"], self.condition)
            self._transition(initial, "initialize")
            helpers = importlib.import_module("www2027." + self.spec["group"].controller)
            prompt, catalog, tools = helpers.public_input(initial)
            if _sha(prompt.encode()) != self.case["normal_prompt_sha256"]:
                raise SourceBackendError("Runtime public prompt differs from the frozen source")
            if _sha(_canonical(catalog).encode()) != self.case["catalog_sha256"]:
                raise SourceBackendError("Runtime catalog differs from the frozen source")
            value = initial.result.get("worker_result") or {}
            binding, artifacts = value.get("binding") or {}, value.get("artifacts") or {}
            observed = {"initial_state_sha256": (artifacts.get("before") or {}).get("uncompressed_sha256"),
                        "source_map_sha256": binding.get("source_map_sha256"),
                        "effective_map_sha256": binding.get("effective_map_sha256")}
            expected = self.case["conditions"][self.condition]
            if binding.get("condition") != self.condition or any(expected.get(key) != actual or actual is None
                                                                   for key, actual in observed.items()):
                raise SourceBackendError("Initial condition state/map differs from the frozen source")
            self.provenance["initial_binding"] = {"expected": {key: expected[key] for key in observed},
                                                  "observed": observed, "verified_before_model_request": True}
            self.initial_messages = [{"role": "system", "content": helpers.SYSTEM}, {"role": "user", "content": prompt}]
            self.public_tools = copy.deepcopy(tools)
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, exc_type, exc, traceback):
        if not self._closed:
            self._closed = True
            if self.runtime is not None:
                self.runtime.__exit__(exc_type, exc, traceback)
        return False

    def execute(self, name, args, call_id=None):
        if not self._entered or self._closed or self._finalized or self.handle is None:
            raise SourceBackendError("No active verified native state")
        if name not in {tool["function"]["name"] for tool in self.public_tools}:
            raise SourceBackendError("Unknown original public tool")
        if not isinstance(args, dict):
            raise SourceBackendError("Tool arguments must be a JSON object")
        if call_id is not None and (not isinstance(call_id, str) or not call_id):
            raise SourceBackendError("Tool call ID must be a nonempty string")
        arguments = json.loads(_canonical(args))
        try:
            transition = self.runtime.step(self.handle, name, arguments)
            evidence = self._transition(transition, "step")
            value = transition.result.get("worker_result") or {}
            event = {"step": len(self.events), "tool_call_id": call_id, "name": name,
                     "raw_arguments": arguments, "runtime_receipt": evidence,
                     "verified_handle_returned": transition.handle is not None,
                     "tool_outcome": value.get("tool_outcome"),
                     "source_exposure": (value.get("tool_outcome") or {}).get("source_exposure"),
                     "operation_status": value.get("operation_status")}
            self.events.append(copy.deepcopy(event))
            if self.handle is None:
                raise SourceBackendError("Tool state cannot be verified for the next step")
            helpers = importlib.import_module("www2027." + self.spec["group"].controller)
            return helpers.tool_feedback(value)
        except Exception as error:
            self.error = type(error).__name__ + ": " + str(error)
            raise

    def finalize(self, final_output, stop_reason):
        if self._outcome is not None:
            return copy.deepcopy(self._outcome)
        if not self._entered or self._closed:
            raise SourceBackendError("Source session is not active")
        if final_output is not None and not isinstance(final_output, str):
            raise SourceBackendError("Final output must be text or None")
        if not isinstance(stop_reason, str) or not stop_reason:
            raise SourceBackendError("Stop reason must be a nonempty string")
        self._finalized = True
        scores = None
        if self.handle is not None:
            try:
                scored = self.runtime.score(self.handle, final_output if isinstance(final_output, str) else "")
                self._transition(scored, "score")
                scores = (scored.result.get("worker_result") or {}).get("scores")
                if scored.handle is None:
                    scores = scored.result.get("scores")
            except Exception as error:
                scores = {key: {"status": "unknown", "value": None,
                                "error": type(error).__name__ + ": " + str(error)} for key in ("utility", "goal_success")}
        self._outcome = {
            "case_id": self.case["id"], "case_sha256": self.case["case_sha256"], "condition": self.condition,
            "complete": stop_reason == "completed", "stop_reason": stop_reason, "error": self.error,
            "events": copy.deepcopy(self.events), "runtime_transitions": copy.deepcopy(self.transitions),
            "final_output": final_output, "original_source_final_scores": copy.deepcopy(scores),
            "source_backend": copy.deepcopy(self.provenance),
            "measurement_scope": "Original final-state scores retained separately; original analyzers must independently qualify per-step effects, normal-v3 and registered end goals.",
        }
        return copy.deepcopy(self._outcome)


def create_agentdojo_backend(case, condition, output_dir, source_root):
    """Return a context manager; entering it performs original native init.

    ``output_dir`` must be fresh and is passed unchanged to the original runtime.
    ``source_backend_spec`` can authenticate all inputs before plan freeze.
    """
    return AgentDojoBackend(case, condition, output_dir, source_backend_spec(case, source_root))
