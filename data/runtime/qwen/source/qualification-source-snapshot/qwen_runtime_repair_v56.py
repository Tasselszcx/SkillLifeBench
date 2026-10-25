"""Recorded local Qwen Default/Check runs on the frozen 89 runtime cases.

The controller never reads gateway credentials, executes filesystem skill cases,
or changes source case bytes. Server launch, protocol pilot and full execution
are separate root-reviewed operations. Preflight is read-only and generates no
model output. Task scoring runs separately from these immutable raw receipts.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import urllib.request

VERSION = "qwen-runtime-recorded-policy-controller-v56.2"
SOURCE_BACKENDS = {
    "agentdojo_original_registry_next40_fixed_source_runtime_v1",
    "agentdojo_original_registry_next51_fixed_source_runtime_v1",
}
VALID_STOPS = {"completed", "model_output_truncated", "model_refusal", "invalid_tool_call",
               "model_tool_format_error", "round_limit", "tool_step_limit", "wall_limit",
               "invalid_final_message", "model_context_limit", "model_output_incomplete"}
INFRA_STOPS = {"api_error", "model_identity_error", "request_identity_error", "invalid_model_response",
               "controller_or_backend_error", "framework_error", "harness_protocol_error",
               "harness_schema_error", "runtime_error", "execution_limit"}
PINNED_CONTEXT_ERRORS = {
    "c4a73f9c8f3ccbf277b5af8db9a25d3dcb427de426abd487282092bdd66cf5be":
        "ValueError: Declared local context budget exceeded; no truncation applied",
    "53c753a156359b5eaec9fd498e0e64274e45e1a46d9374534be0c590a54b2c7e":
        "ValueError: Declared context budget exceeded; no truncation applied",
}
MODEL_PARSE_ERRORS = {
    "Asymmetric parameter LF framing; no whitespace repair applied",
    "Incomplete tool-call envelope", "Unbalanced tool-call envelope", "Malformed function block",
    "Unknown function name", "Unexpected text between parameters", "Duplicate parameter",
    "Unknown parameter", "Unexpected function-body text", "Unclosed reasoning block",
    "Nonfinite JSON number", "Duplicate JSON object key", "Nonfinite JSON literal",
    "Non-JSON scalar/object parameter", "Value nesting exceeds bound", "Value rejected by false schema",
    "Parameter matches no anyOf branch", "Parameter type mismatch", "Parameter outside enum",
    "Missing required object field", "Unknown object field", "Parameter matches no anyOf decoding",
    "Ambiguous anyOf parameter decoding", "Tool call produced with tool_choice=none",
    "tool call produced with tool_choice=none", "Forced tool request not fulfilled",
    "forced tool request not fulfilled",
}
INCOMPLETE_GENERATION_ERRORS = {
    "Generation reached output token cap before EOS":"model_output_truncated",
    "Generation stopped before EOS; time limit or incomplete output":"model_output_incomplete",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda:stream.read(8*1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def classify_local_terminal(raw_stop, receipt, model, identity_contract=None):
    """Derive a narrow stop category without changing the raw receipt/outcome.

    Only exact errors from the two source-pinned local servers are recognized.
    A generic HTTP500 remains infrastructure failure. Generated syntax errors
    require HTTP200, raw generated text and the expected served identity.
    """
    result={"raw_stop_reason":raw_stop,"derived_stop_reason":raw_stop,
            "classification":"unchanged","raw_record_modified":False}
    if not receipt:
        return result
    server_hash=model["server_source"]["sha256"]
    bound_request=(receipt.get("requested_model")==model["model_id"] and
                   receipt.get("endpoint")==model["base_url"]+"/chat/completions")
    if raw_stop=="api_error" and bound_request and server_hash in PINNED_CONTEXT_ERRORS and receipt.get("status")=="http_error" and receipt.get("http_status")==500:
        try:
            error=json.loads(receipt["error"])
        except (KeyError,TypeError,ValueError):
            error={}
        if error=={"error":PINNED_CONTEXT_ERRORS[server_hash]}:
            result.update(derived_stop_reason="model_context_limit",classification="exact_pinned_context_budget_error",
                pinned_server_sha256=server_hash,exact_error=error["error"],fresh_episode_retry_allowed=False,
                response_identity_scope="Local endpoint/source identity verified at episode start; HTTP error has no generated model output.")
    if raw_stop=="model_tool_format_error":
        data=receipt.get("response")or{}
        contract=identity_contract or model.get("expected_identity",{})
        identity_ok=(bound_request and receipt.get("http_status")==200 and receipt.get("status")=="tool_parse_error"
            and receipt.get("served_model")==model["model_id"] and data.get("model")==model["model_id"]
            and isinstance(data.get("raw_completion"),str) and bool(contract)
            and all((data.get("local_identity")or{}).get(k)==v for k,v in contract.items())
            and server_hash in PINNED_CONTEXT_ERRORS)
        if not identity_ok:
            result.update(derived_stop_reason="model_identity_error",classification="parse_error_lacks_bound_generated_output")
            return result
        error=data.get("tool_parse_error")
        result["raw_completion_sha256"]=hashlib.sha256(data["raw_completion"].encode()).hexdigest()
        result["raw_completion_preserved_in_api_response"]=True
        if error in MODEL_PARSE_ERRORS:
            result.update(classification="pinned_model_generated_syntax_failure",exact_error=error,fresh_episode_retry_allowed=False)
        elif error in INCOMPLETE_GENERATION_ERRORS:
            result.update(derived_stop_reason=INCOMPLETE_GENERATION_ERRORS[error],classification="pinned_incomplete_generation",
                          exact_error=error,fresh_episode_retry_allowed=False)
        else:
            # Unsupported schema/history handling is not model misbehavior.
            # Do not guess its origin or obtain a success-seeking fresh sample.
            result.update(derived_stop_reason="unclassified_local_parser_error",classification="requires_adapter_review",
                          exact_error=error,fresh_episode_retry_allowed=False)
    return result


def verify(binding):
    path=Path(binding["path"])
    if path.name in {".env","legacy_a_cases.py","auth.json","credentials.json"}:
        raise ValueError("forbidden_input")
    if not path.is_file() or sha(path)!=binding["sha256"]:
        raise ValueError("input_binding_differs:"+str(path))
    return path


def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2,allow_nan=False)
        stream.write("\n");stream.flush();os.fsync(stream.fileno())


def atomic(path,value):
    path=Path(path);temp=path.with_suffix(path.suffix+".tmp")
    with temp.open("w") as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2,allow_nan=False)
        stream.write("\n");stream.flush();os.fsync(stream.fileno())
    temp.replace(path)


class PolicyBackend:
    """Instance-local, append-only policy view over the unchanged native backend."""
    def __init__(self, backend, policy, default_system, check_block):
        if policy not in {"Default","Check"}:
            raise ValueError("unsupported_policy")
        messages=copy.deepcopy(backend.initial_messages)
        if len(messages)!=2 or messages[0]!={"role":"system","content":default_system} or messages[1].get("role")!="user":
            raise ValueError("canonical_initial_roles_or_system_differ")
        self._backend=backend
        self.initial_messages=messages
        if policy=="Check":
            self.initial_messages[0]["content"] += "\n\n"+check_block
        self.policy=policy

    def __getattr__(self,name):
        return getattr(self._backend,name)


def selected_jobs(manifest,phase,model_key=None):
    if phase not in {"pilot","full"}:
        raise ValueError("unknown_phase")
    with verify(manifest["schedule"]).open() as stream:
        jobs=[json.loads(line) for line in stream]
    if len(jobs)!=534 or len({j["job_id"]for j in jobs})!=534:
        raise ValueError("full_schedule_must_have_534_unique_jobs")
    permitted={m["key"]for m in manifest["models"]}
    if model_key is not None and model_key not in permitted:
        raise ValueError("unknown_model_key")
    if phase=="pilot":
        jobs=[j for j in jobs if j["case_id"]in manifest["pilot_case_ids"]]
    if model_key is not None:
        jobs=[j for j in jobs if j["model_key"]==model_key]
    return jobs


def read_health(model):
    base=model["base_url"]
    if base!=f"http://127.0.0.1:{model['port']}/v1":
        raise ValueError("local_loopback_only")
    with urllib.request.urlopen(base.removesuffix("/v1")+"/health",timeout=10) as response:
        data=json.loads(response.read(1024*1024))
    if data.get("status")!="ready" or data.get("model")!=model["model_id"]:
        raise ValueError("model_server_not_ready")
    identity=data["identity"]
    for key,value in model["expected_identity"].items():
        if identity.get(key)!=value:
            raise ValueError("server_identity_differs:"+key)
    if type(identity.get("pid"))is not int:
        raise ValueError("server_pid_missing")
    return identity


def preflight(path,expected_sha,check_health=False,model_key=None):
    path=Path(path)
    if sha(path)!=expected_sha:
        raise ValueError("manifest_hash_differs")
    manifest=json.loads(path.read_text())
    if manifest["controller_version"]!=VERSION or manifest["scheduled_episodes"]!=534:
        raise ValueError("manifest_version_or_population_differs")
    for binding in manifest["implementation_bindings"]:
        verify(binding)
    for key in ("parent_protocol","cases","schedule","system_default","check_append_only","system_check"):
        verify(manifest[key])
    default=Path(manifest["system_default"]["path"]).read_text()
    block=Path(manifest["check_append_only"]["path"]).read_text()
    if Path(manifest["system_check"]["path"]).read_text()!=default+"\n\n"+block:
        raise ValueError("check_is_not_exact_append_only")
    cases={c["id"]:c for c in json.loads(Path(manifest["cases"]["path"]).read_text())["cases"]}
    if len(cases)!=89 or any(c["class"]!="C" or c["execution_backend"]not in SOURCE_BACKENDS for c in cases.values()):
        raise ValueError("runtime89_only")
    from .harness_matrix_sources import source_backend_spec
    specs={case_id:source_backend_spec(case,Path(manifest["source_root"])) for case_id,case in cases.items()}
    jobs=selected_jobs(manifest,"full")
    expected=Counter((model["key"],policy,condition)for model in manifest["models"]
                     for policy,condition in [("Default","clean"),("Default","injected"),("Check","injected")]
                     for _ in range(89))
    if Counter((j["model_key"],j["policy"],j["condition"])for j in jobs)!=expected:
        raise ValueError("unbalanced_policy_schedule")
    for job in jobs:
        case=cases[job["case_id"]]
        if job["case_sha256"]!=case["case_sha256"] or job["task_sha256"]!=case["normal_prompt_sha256"] or job["catalog_sha256"]!=case["catalog_sha256"]:
            raise ValueError("scheduled_case_binding_differs")
        if canonical(job["source_binding"])!=canonical(specs[job["case_id"]]["provenance"]):
            raise ValueError("canonical_native_source_binding_differs")
        content=default if job["policy"]=="Default"else default+"\n\n"+block
        if hashlib.sha256(content.encode()).hexdigest()!=job["system_sha256"]:
            raise ValueError("scheduled_policy_hash_differs")
    identities={}
    for model in manifest["models"]:
        if model_key and model["key"]!=model_key:
            continue
        verify(model["pinned_manifest"]);verify(model["server_source"])
        if check_health:
            identities[model["key"]]=read_health(model)
    return manifest,cases,identities


def require_approval(path,manifest_sha,operation):
    approval=json.loads(Path(path).read_text())
    if approval.get("approved")is not True or approval.get("manifest_sha256")!=manifest_sha or operation not in approval.get("operations",[]):
        raise ValueError("root_review_does_not_cover_this_operation")
    return approval


def launch_server(manifest,model_key,manifest_sha,approval_path):
    require_approval(approval_path,manifest_sha,"launch_servers")
    model=next(m for m in manifest["models"]if m["key"]==model_key)
    root=Path(model["instance_root"])
    if root.exists():
        raise ValueError("server_instance_root_already_exists")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
        if probe.connect_ex(("127.0.0.1",model["port"]))==0:
            raise ValueError("model_port_occupied")
    gpu=str(model["physical_gpu"])
    query=subprocess.run(["nvidia-smi","-i",gpu,"--query-compute-apps=pid","--format=csv,noheader,nounits"],capture_output=True,text=True,check=True)
    active=[line.strip() for line in query.stdout.splitlines() if line.strip().isdigit()]
    if active:
        raise ValueError("gpu_has_existing_compute_processes:"+",".join(active))
    if shutil.disk_usage(root.parent).free<512*1024**2:
        raise ValueError("insufficient_server_metadata_disk")
    root.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy();env["PYTHONPATH"]=manifest["code_root"]
    with (root/"controller-server.log").open("xb") as log:
        process=subprocess.Popen(model["serve_command"],cwd=manifest["code_root"],env=env,
                                 stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                 start_new_session=True,close_fds=True)
    record={"model_key":model_key,"pid":process.pid,"started_at":now(),"manifest_sha256":manifest_sha,
            "argv":model["serve_command"],"model_generation_requests":0,"instance_root":str(root)}
    save(root/"controller-launch.json",record)
    return record


def execute(manifest_path,manifest_sha,approval_path,output,phase,model_key=None):
    require_approval(approval_path,manifest_sha,phase)
    manifest,cases,identities=preflight(manifest_path,manifest_sha,True,model_key)
    output=Path(output).absolute()
    if not output.is_relative_to(Path("/tmp/skilllife-qwen-runtime-v56")) or output.exists():
        raise ValueError("fresh_tmp_output_required")
    output.parent.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(output.parent).free<manifest["minimum_raw_disk_bytes"]:
        raise ValueError("insufficient_raw_evidence_disk")
    jobs=selected_jobs(manifest,phase,model_key)
    output.mkdir(exist_ok=False)
    save(output/"protocol.json",{"manifest_path":str(manifest_path),"manifest_sha256":manifest_sha,
        "frozen_manifest":manifest,"phase":phase,"selected_jobs":len(jobs),"started_at":now(),
        "pid":os.getpid(),"observed_servers":identities,"is_ranked_full_cohort":phase=="full"})
    with (output/"planned-index.jsonl").open("x") as stream:
        for job in jobs:stream.write(canonical(job)+"\n")
    from .harness_matrix_sources import create_agentdojo_backend
    from .harness_matrix_session import HarnessLimits,HarnessSession,run_native
    from .local_client import LocalModelClient
    limits=HarnessLimits(**manifest["harness_limits"])
    default=Path(manifest["system_default"]["path"]).read_text()
    block=Path(manifest["check_append_only"]["path"]).read_text()
    lock=threading.Lock();stop=threading.Event();terminals=[]

    def worker(model):
        expected_identity={**model["expected_identity"],"pid":identities[model["key"]]["pid"]}
        for job in jobs:
            if job["model_key"]!=model["key"]:continue
            if stop.is_set():break
            if shutil.disk_usage(output).free<manifest["minimum_raw_disk_bytes"]:
                stop.set();raise RuntimeError("raw_disk_floor_reached")
            current=read_health(model)
            if any(current.get(k)!=v for k,v in expected_identity.items()):
                stop.set();raise RuntimeError("server_instance_changed")
            attempts=[];selected=None
            for attempt in range(1,manifest["max_fresh_episode_attempts"]+1):
                cell=output/f"attempt-{attempt:02d}"/"episodes"/job["job_id"]
                cell.mkdir(parents=True,exist_ok=False)
                session=None
                try:
                    with ExitStack() as stack:
                        backend=stack.enter_context(create_agentdojo_backend(copy.deepcopy(cases[job["case_id"]]),job["condition"],cell/"backend",Path(manifest["source_root"])))
                        view=PolicyBackend(backend,job["policy"],default,block)
                        save(cell/"policy-binding.json",{"job":job,"policy":job["policy"],
                            "default_system_sha256":hashlib.sha256(default.encode()).hexdigest(),
                            "check_append_sha256":hashlib.sha256(block.encode()).hexdigest(),
                            "actual_system_sha256":hashlib.sha256(view.initial_messages[0]["content"].encode()).hexdigest(),
                            "user_message_unchanged":view.initial_messages[1]==backend.initial_messages[1],
                            "public_tools_unchanged":view.public_tools==backend.public_tools})
                        client=LocalModelClient(base_url=model["base_url"],timeout=manifest["request_timeout_seconds"])
                        session=HarnessSession(view,client,model["model_id"],cell/"session",limits=limits,identity_contract=expected_identity)
                        result=run_native(session)
                        record=session.finalize(result,"native")
                except OSError as error:
                    if error.errno==28:
                        stop.set();raise
                    record={"stop_reason":"controller_or_backend_error","error_type":type(error).__name__,"error":str(error)}
                    save(cell/"failure.json",record)
                except Exception as error:
                    record={"stop_reason":"controller_or_backend_error","error_type":type(error).__name__,"error":str(error),
                            "model_rounds":session.model_rounds if session else 0,
                            "tool_actions":session.tool_actions if session else 0,
                            "model_turns":copy.deepcopy(session.model_turns)if session else [],
                            "partial_backend_events":copy.deepcopy(session.backend.events)if session else []}
                    save(cell/"failure.json",record)
                raw_reason=record["stop_reason"]
                api_paths=sorted((cell/"session").glob("api-*.json"))
                last_api=json.loads(api_paths[-1].read_text())if api_paths else None
                classification=classify_local_terminal(raw_reason,last_api,model,expected_identity)
                if api_paths:
                    classification["raw_api_path"]=str(api_paths[-1])
                    classification["raw_api_sha256"]=sha(api_paths[-1])
                save(cell/"terminal-classification.json",classification)
                reason=classification["derived_stop_reason"];valid=reason in VALID_STOPS
                outcome=cell/"session/outcome.json"
                item={"attempt":attempt,"stop_reason":reason,"valid_execution_candidate":valid,
                      "raw_stop_reason":raw_reason,"terminal_classification":classification,
                      "outcome_path":str(outcome)if outcome.is_file()else None,
                      "outcome_sha256":sha(outcome)if outcome.is_file()else None,
                      "cell":str(cell),"finished_at":now(),"model_rounds":record.get("model_rounds"),
                      "tool_actions":record.get("tool_actions"),"elapsed_seconds":record.get("harness_elapsed_seconds")}
                save(cell/"execution-terminal.json",item);attempts.append(item)
                with lock:
                    with (output/"progress.jsonl").open("a") as stream:
                        stream.write(canonical({"job_id":job["job_id"],**item})+"\n");stream.flush();os.fsync(stream.fileno())
                if valid:selected=attempt;break
                if reason not in INFRA_STOPS:break
            terminal={**job,"selected_attempt":selected,"attempts":attempts}
            with lock:
                terminals.append(terminal)
                atomic(output/"selection.json",terminals)
                atomic(output/"status.json",{"planned":len(jobs),"terminal":len(terminals),
                    "execution_valid_candidates":sum(t["selected_attempt"]is not None for t in terminals),
                    "stops":dict(Counter(a["stop_reason"]for t in terminals for a in t["attempts"])),"updated_at":now()})
    chosen=[m for m in manifest["models"]if any(j["model_key"]==m["key"]for j in jobs)]
    def guarded_worker(model):
        try:
            return worker(model)
        except BaseException:
            stop.set()
            raise
    try:
        with ThreadPoolExecutor(max_workers=len(chosen))as pool:
            list(pool.map(guarded_worker,chosen))
    except BaseException as error:
        stop.set()
        save(output/"controller-abort.json",{"type":type(error).__name__,"reason":str(error),"time":now(),"terminal_jobs":len(terminals)})
        raise
    summary={"planned":len(jobs),"terminal":len(terminals),"valid_execution_candidates":sum(t["selected_attempt"]is not None for t in terminals),
             "attempts":sum(len(t["attempts"])for t in terminals),"finished_at":now(),
             "task_scoring_performed":False,"all_raw_records_retained":True}
    save(output/"complete.json",summary)
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("preflight","launch-server","run"))
    parser.add_argument("--manifest",type=Path,required=True)
    parser.add_argument("--manifest-sha256",required=True)
    parser.add_argument("--approval",type=Path)
    parser.add_argument("--check-health",action="store_true")
    parser.add_argument("--model-key",choices=("local9b","local4b"))
    parser.add_argument("--phase",choices=("pilot","full"),default="pilot")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.command=="preflight":
        manifest,cases,identities=preflight(args.manifest,args.manifest_sha256,args.check_health,args.model_key)
        print(json.dumps({"verified":True,"cases":len(cases),"jobs":534,"servers_checked":list(identities),"model_calls":0,"native_executions":0}));return
    if args.approval is None:parser.error("--approval root-review file is required")
    if args.command=="launch-server":
        if not args.model_key:parser.error("--model-key is required")
        manifest,_,_=preflight(args.manifest,args.manifest_sha256)
        print(json.dumps(launch_server(manifest,args.model_key,args.manifest_sha256,args.approval)));return
    if args.output is None:parser.error("--output is required")
    print(json.dumps(execute(args.manifest,args.manifest_sha256,args.approval,args.output,args.phase,args.model_key)))


if __name__=="__main__":main()
