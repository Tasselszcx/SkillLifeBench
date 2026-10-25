"""Protocol-only tests: no model calls or source runtime execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from .qwen_runtime_repair_v56 import (PolicyBackend,require_approval,selected_jobs,VALID_STOPS,INFRA_STOPS,
                                    classify_local_terminal,PINNED_CONTEXT_ERRORS)


class DummyBackend:
    initial_messages=[{"role":"system","content":"canonical main"},{"role":"user","content":"unaltered task"}]
    public_tools=[{"type":"function","function":{"name":"read","parameters":{"type":"object"}}}]
    provenance={"source_case_sha256":"case"}
    events=[]


class PolicyProtocolTests(unittest.TestCase):
    def pinned_model(self,server_hash=None):
        server_hash=server_hash or next(iter(PINNED_CONTEXT_ERRORS))
        return {"model_id":"pinned-qwen","base_url":"http://127.0.0.1:8767/v1",
                "server_source":{"sha256":server_hash},"expected_identity":{"server_sha256":server_hash,"pid":123}}

    def context_receipt(self,model,error):
        return {"status":"http_error","http_status":500,"requested_model":model["model_id"],
                "endpoint":model["base_url"]+"/chat/completions","error":json.dumps({"error":error})}

    def syntax_receipt(self,model,error):
        return {"status":"tool_parse_error","http_status":200,"requested_model":model["model_id"],
                "served_model":model["model_id"],"endpoint":model["base_url"]+"/chat/completions",
                "response":{"model":model["model_id"],"local_identity":model["expected_identity"],
                            "raw_completion":"<tool_call><function=broken>","tool_parse_error":error}}

    def test_check_is_exact_append_with_no_backend_mutation(self):
        backend=DummyBackend();before=copy.deepcopy(backend.initial_messages)
        check=PolicyBackend(backend,"Check","canonical main","authorization block")
        self.assertEqual(check.initial_messages,[{"role":"system","content":"canonical main\n\nauthorization block"},before[1]])
        self.assertEqual(backend.initial_messages,before)
        self.assertIs(check.public_tools,backend.public_tools)
        self.assertIs(check.provenance,backend.provenance)

    def test_default_remains_byte_equivalent(self):
        backend=DummyBackend();default=PolicyBackend(backend,"Default","canonical main","block")
        self.assertEqual(default.initial_messages,backend.initial_messages)
        default.initial_messages[1]["content"]="independent copy"
        self.assertEqual(backend.initial_messages[1]["content"],"unaltered task")

    def test_policy_or_original_prompt_mismatch_stops(self):
        with self.assertRaises(ValueError):PolicyBackend(DummyBackend(),"other","canonical main","block")
        with self.assertRaises(ValueError):PolicyBackend(DummyBackend(),"Check","different main","block")

    def test_valid_failures_are_not_retry_eligible(self):
        self.assertFalse(VALID_STOPS&INFRA_STOPS)
        for reason in ["model_refusal","round_limit","model_tool_format_error","invalid_tool_call"]:
            self.assertIn(reason,VALID_STOPS);self.assertNotIn(reason,INFRA_STOPS)

    def test_only_exact_pinned_context_errors_become_valid_budget_stops(self):
        for server_hash,error in PINNED_CONTEXT_ERRORS.items():
            model=self.pinned_model(server_hash);receipt=self.context_receipt(model,error);before=copy.deepcopy(receipt)
            result=classify_local_terminal("api_error",receipt,model)
            self.assertEqual(result["raw_stop_reason"],"api_error")
            self.assertEqual(result["derived_stop_reason"],"model_context_limit")
            self.assertFalse(result["fresh_episode_retry_allowed"]);self.assertEqual(receipt,before)

    def test_generic500_or_unpinned_server_is_not_a_model_failure(self):
        model=self.pinned_model()
        for error in ["RuntimeError: CUDA out of memory","ToolParseError: Malformed function block",
                      "ValueError: context budget exceeded",next(iter(PINNED_CONTEXT_ERRORS.values()))+" extra"]:
            result=classify_local_terminal("api_error",self.context_receipt(model,error),model)
            self.assertEqual(result["derived_stop_reason"],"api_error")
        model=self.pinned_model("unknown")
        result=classify_local_terminal("api_error",self.context_receipt(model,next(iter(PINNED_CONTEXT_ERRORS.values()))),model)
        self.assertEqual(result["derived_stop_reason"],"api_error")

    def test_generated_syntax_error_keeps_raw_text_and_does_not_resample(self):
        model=self.pinned_model();receipt=self.syntax_receipt(model,"Malformed function block");before=copy.deepcopy(receipt)
        result=classify_local_terminal("model_tool_format_error",receipt,model)
        self.assertEqual(result["derived_stop_reason"],"model_tool_format_error")
        self.assertEqual(result["classification"],"pinned_model_generated_syntax_failure")
        self.assertFalse(result["fresh_episode_retry_allowed"]);self.assertEqual(receipt,before)
        self.assertTrue(result["raw_completion_preserved_in_api_response"])

    def test_schema_error_or_identity_mismatch_is_not_a_model_syntax_failure(self):
        model=self.pinned_model();receipt=self.syntax_receipt(model,"Unsupported schema keywords: format")
        result=classify_local_terminal("model_tool_format_error",receipt,model)
        self.assertEqual(result["derived_stop_reason"],"unclassified_local_parser_error")
        self.assertFalse(result["fresh_episode_retry_allowed"])
        receipt=self.syntax_receipt(model,"Malformed function block");receipt["response"]["local_identity"]={}
        self.assertEqual(classify_local_terminal("model_tool_format_error",receipt,model)["derived_stop_reason"],"model_identity_error")

    def test_output_cap_is_a_valid_budget_failure(self):
        model=self.pinned_model();receipt=self.syntax_receipt(model,"Generation reached output token cap before EOS")
        result=classify_local_terminal("model_tool_format_error",receipt,model)
        self.assertEqual(result["derived_stop_reason"],"model_output_truncated")
        self.assertFalse(result["fresh_episode_retry_allowed"])

    def test_approval_covers_exact_manifest_and_operation(self):
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp)/"root-review.json";path.write_text(json.dumps({"approved":True,"manifest_sha256":"abc","operations":["pilot"]}))
            self.assertTrue(require_approval(path,"abc","pilot")["approved"])
            with self.assertRaises(ValueError):require_approval(path,"abc","full")
            with self.assertRaises(ValueError):require_approval(path,"different","pilot")

    def test_pilot_and_full_preserve_uniform_case_schedule(self):
        with tempfile.TemporaryDirectory()as temp:
            jobs=[{"job_id":f"{model}/{policy}/{case}/{condition}","model_key":model,"case_id":str(case),"policy":policy,"condition":condition}
                  for model in ["local9b","local4b"]for case in range(89)
                  for policy,condition in [("Default","clean"),("Default","injected"),("Check","injected")]]
            path=Path(temp)/"schedule.jsonl";path.write_text(''.join(json.dumps(j)+'\n'for j in jobs))
            manifest={"schedule":{"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()},"models":[{"key":"local9b"},{"key":"local4b"}],"pilot_case_ids":["0","1"]}
            self.assertEqual(len(selected_jobs(manifest,"full")),534)
            self.assertEqual(len(selected_jobs(manifest,"pilot")),12)
            self.assertEqual(len(selected_jobs(manifest,"pilot","local9b")),6)
            self.assertEqual(len(selected_jobs(manifest,"full","local4b")),267)


if __name__=="__main__":unittest.main()
