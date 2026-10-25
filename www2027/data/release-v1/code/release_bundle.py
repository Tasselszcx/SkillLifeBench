"""Portable index of unchanged scenario objects and original measurement tables.

No measurement is rescored, qualified retrospectively, or pooled into one ASR.
Final builds require the388-case index and both terminal next51 run inventories.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import shutil

SOURCES = {"new194": (1164, "nested_json"), "legacy66": (435, "nested_json"),
    "legacy_c2": (8, "episodes_json"), "agentdojo4": (16, "episodes_json"),
    "agentdojo18": (72, "csv"), "agentdojo_banking15": (60, "csv"),
    "agentdojo_next40": (160, "csv"), "agentdojo_next51": (204, "csv")}
HOLDS = frozenset(("agentdojo-travel-user6-goal6", "agentdojo-travel-user12-goal6"))
STATUS_FIELDS = frozenset(("complete", "execution_complete", "outcome_present", "evidence_complete", "qualified_model_identity",
    "original_scores_bound", "security_admission_eligible", "planned_cell_execution_order_verified", "record_status", "stop_reason",
    "coverage", "effect_measurement_status", "analysis_role", "same_target_set", "served_model_strings", "requested_output_format_status"))
JSON_METRICS = {
    "new194": ("harm", "artifact_utility", "non_exposure", "incomplete_no_action_observed", "d_endpoint_verified",
        "d_source_exposed_sink_effect", "d_full_chain_verified", "harm_recorded_in_partial_execution"),
    "legacy66": ("harm", "artifact_utility", "non_exposure", "incomplete_no_action_observed", "d_endpoint_verified",
        "d_source_exposed_sink_effect", "d_full_chain_verified", "harm_recorded_in_partial_execution"),
    "legacy_c2": ("local_mail_effect", "task_complete", "source_preceded_mail_effect", "source_exposed_mail_effect",
        "source_return_verified", "summary_facts_correct"),
    "agentdojo4": ("original_utility", "original_goal_success", "independent_ever_target_effect", "injected_source_returned",
        "injected_feedback_in_later_model_request")}
KNOWN_BOOLEAN_METRICS = frozenset(("ever_actual_effect", "final_target_present", "effect_then_restored", "qualified_cell_actual_effect",
    "normal_result_correct", "joint_safe_success", "original_goal_value", "original_utility_value", "primary_record_effect",
    "qualified_primary_record_effect", "full_modeled_goal_effect", "qualified_full_modeled_goal_effect", "final_full_modeled_goal_present",
    "qualified_final_primary", "qualified_final_full_modeled", "normal_result_v1", "normal_result_v2", "normal_result_v3",
    "normal_with_requested_format", "joint_semantic_safe", "joint_with_requested_format", "requested_output_format_value",
    "source_feedback_in_later_successful_request", "retrieval_feedback_in_later_successful_request",
    "registered_target_attainment", "registered_full_goal_completion", "qualified_registered_target_attainment",
    "qualified_registered_full_goal_completion", "registered_unauthorized_target_effect", "qualified_unauthorized_target_effect",
    "any_established_out_of_request_native_consequence", "qualified_any_established_out_of_request_native_consequence",
    "joint_registered_target_safe", "joint_registered_target_with_requested_format", "qualified_normal_result_correct",
    "qualified_normal_with_requested_format", "joint_security_safe", "final_output_primary", "final_output_full",
    "qualified_final_output_primary", "qualified_final_output_full", "full_goal_completed_by_terminal", "qualified_full_goal_completed_by_terminal"))


def require(valid, reason):
    if not valid: raise ValueError(reason)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
def read(path): return json.loads(Path(path).read_bytes())
def ref(path):
    path = Path(path); return {"path": str(path), "sha256": sha(path.read_bytes()), "bytes": path.stat().st_size}
def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream: json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False); stream.write("\n")
def tri(value, csv_value=False):
    if csv_value:
        require(value in ("True", "False", ""), "invalid_csv_boolean_or_unknown")
        return {"True": "T", "False": "F", "": "U"}[value]
    require(value is None or type(value) is bool, "invalid_json_boolean_or_unknown")
    return "U" if value is None else "T" if value else "F"


def assemble_scenarios(index_path, cohort_dir=None, *, final=False, publication_bindings=None):
    index_path = Path(index_path); index = read(index_path); directory = Path(cohort_dir or index_path.parent)
    require(not final or index["admitted_case_count"] == 388, "final_release_requires388_index")
    entries = index["entries"]; ids = [e["id"] for e in entries]
    require(len(ids) == len(set(ids)) == index["admitted_case_count"], "duplicate_or_missing_index_case")
    require(not HOLDS.intersection(ids), "held_supplement_admitted_to_dataset")
    manifests, sources = {}, {}
    for source in index["sources"]:
        group, name = source["source_group"], source["file"]
        require(group in SOURCES and group not in manifests and Path(name).name == name, "invalid_index_source")
        path = directory/name; raw = path.read_bytes()
        binding = (publication_bindings or {}).get(name)
        if binding:
            require(sha(raw) == binding["sha256"] and len(raw) == binding["bytes"], "published_cohort_bytes_changed")
            require(binding["source_sha256"] == source["sha256"], "cohort_source_identity_changed")
        else:
            require(sha(raw) == source["sha256"], "cohort_source_hash_changed")
        document = json.loads(raw); cases = document["cases"]
        lookup = {case["id"]: (position, case) for position,case in enumerate(cases)}
        require(len(lookup) == len(cases), "duplicate_case_in_original_manifest")
        manifests[group] = lookup; sources[group] = {**ref(path), "case_count": source["case_count"]}
    assembled, links = [], {}
    for entry in entries:
        group = entry["source_group"]; position,case = manifests[group][entry["id"]]
        require(case["case_sha256"] == entry["case_sha256"] and case["class"] == entry["class"]
            and set(case["conditions"]) == set(entry["conditions"]), "index_case_identity_changed")
        assembled.append(copy.deepcopy(case))
        links[case["id"]] = {"source_group": group, "source_manifest": sources[group]["path"],
            "source_manifest_sha256": sources[group]["sha256"], "row_pointer": "/cases/"+str(position)}
    for group,source in sources.items():
        require(sum(e["source_group"] == group for e in entries) == source["case_count"], "source_case_count_changed")
    if final:
        require(set(sources) == set(SOURCES) and sum(e["source_group"] == "agentdojo_next51" for e in entries) == 49,
            "final_release_requires49_next51_security_cases")
    return index, assembled, links, sources


def load_measurements(source_id, path):
    require(source_id in SOURCES, "unknown_measurement_source")
    path = Path(path); raw = path.read_bytes(); kind = SOURCES[source_id][1]; records = []
    if kind == "csv":
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline="")); rows = list(reader); fields = reader.fieldnames
        require(fields and len(fields) == len(set(fields)), "duplicate_csv_columns")
        metrics = [field for field in fields if field not in STATUS_FIELDS and (
            field in KNOWN_BOOLEAN_METRICS or field.startswith(("v1_", "amended_"))
            or rows and all(row[field] in ("True", "False", "") for row in rows))]
        for position,row in enumerate(rows, 1):
            require(None not in row and all(v is not None for v in row.values()), "malformed_csv_row")
            records.append({"row": row, "row_pointer": "csv:data-row:"+str(position), "run": None, "identity": None,
                "metrics": {field: tri(row[field], True) for field in metrics}})
        scope = "Original CSV column names and Boolean/empty encodings; definitions remain cohort-specific."
    else:
        document = json.loads(raw); scope = document.get("scope")
        if kind == "nested_json":
            for r,run in enumerate(document["runs"]):
                for m,model in enumerate(run["models"]):
                    for e,row in enumerate(model["episodes"]):
                        records.append({"row": row, "row_pointer": f"/runs/{r}/models/{m}/episodes/{e}",
                            "run": run["run_path"], "identity": model["identity"]})
        else:
            records = [{"row": row, "row_pointer": "/episodes/"+str(position), "run": row.get("run"), "identity": None}
                for position,row in enumerate(document["episodes"])]
        metrics = list(JSON_METRICS[source_id])
        for record in records: record["metrics"] = {field: tri(record["row"][field]) for field in metrics}
    return records, {"path": str(path), "sha256": sha(raw), "bytes": len(raw),
        "format": kind, "rows": len(records), "metric_names": metrics, "source_scope": scope}


def validate_records(source_id, records, cases, links):
    require(len(records) == SOURCES[source_id][0], "source_episode_count_changed:"+source_id)
    keys = [(r["row"]["model"],r["row"]["case_id"],r["row"]["condition"]) for r in records]
    require(len(keys) == len(set(keys)), "duplicate_episode:"+source_id)
    models = {key[0] for key in keys}
    require(len(models) == (3 if source_id in ("new194", "legacy66") else 2), "source_model_population_changed")
    selected = {cid:case for cid,case in cases.items() if links[cid]["source_group"] == source_id}
    expected = {(model,cid,condition) for model in models for cid,case in selected.items() for condition in case["conditions"]}
    require(set(keys) == expected, "missing_or_unscheduled_episode:"+source_id)
    for record in records:
        row = record["row"]; case = selected[row["case_id"]]
        require(isinstance(row["model"], str) and row["model"] and isinstance(row["condition"], str), "invalid_literal_model_or_condition")
        if "case_sha256" in row: require(row["case_sha256"] == case["case_sha256"], "episode_case_hash_changed")


def terminal_next51_inventory(plan_path, run_roots):
    plan_path = Path(plan_path); plan_raw = plan_path.read_bytes(); plan = json.loads(plan_raw)
    require(plan["scheduled_cells"] == 204 and len(plan["cases"]) == 51 and len(run_roots) == 2, "terminal_inventory_requires_two_complete_schedules")
    inventories = {}; inputs = []; planned_cases = {case["id"]:case for case in plan["cases"] if "id" in case}
    for supplied in run_roots:
        root = Path(supplied); status = read(root/"status.json")
        require(status["status"] in ("completed", "completed_with_missingness") and status["scheduled"] == status["recorded"] == 102,
            "next51_inventory_not_terminal")
        protocol = read(root/"protocol.json"); model = protocol["model"]
        require(model in plan["models"] and model not in inventories and protocol["plan_sha256"] == sha(plan_raw)
            and read(root/"plan.json") == plan and protocol["limits"] == plan["limits"]
            and protocol["implementation_sha256"] == plan["implementation_sha256"]
            and protocol["prerequisite_sha256"] == plan["prerequisite_sha256"], "terminal_inventory_plan_or_model_mismatch")
        index = [json.loads(line) for line in (root/"episode_index.jsonl").read_text().splitlines() if line]
        require(len(index) == 102 and [{"case_id": row["case_id"], "condition": row["condition"]} for row in index] == plan["episode_order"][model],
            "terminal_inventory_schedule_changed")
        outcomes = []
        for row in index:
            require(row["case_sha256"] == planned_cases[row["case_id"]]["case_sha256"], "terminal_case_hash_changed")
            path = root/"episodes"/row["case_id"]/row["condition"]/"outcome.json"; outcome = read(path)
            require(all(outcome.get(key) == val for key,val in row.items()) and outcome["model"] == model, "terminal_inventory_outcome_binding_changed")
            outcomes.append({"case_id": row["case_id"], "condition": row["condition"], "complete": outcome["complete"],
                "stop_reason": outcome["stop_reason"], "outcome": ref(path)})
        inventories[model] = {"status": status, "run_root": str(root), "outcomes": outcomes}
        inputs.extend(ref(root/name) for name in ("status.json", "protocol.json", "plan.json", "episode_index.jsonl"))
    return {"status": "both_next51_schedules_terminal", "plan": ref(plan_path), "models": inventories,
        "scheduled_cells": 204, "inputs": inputs, "incomplete_or_unexecuted_rows_retained": True}


def metric_scope(source_id, name):
    if name == "artifact_utility": return "Final-artifact utility only; semantic task utility was unmeasured."
    if name in ("original_utility", "original_utility_value"): return "Original source utility oracle; not relabeled as full semantic utility."
    if name.startswith("d_"): return "Source-reported authored D endpoint/observed dataflow; not native emergent D."
    if name.startswith("normal_") or name.startswith("qualified_normal_"): return "This source's case-specific normal-task measurement and version; no cross-cohort equivalence implied."
    if name.startswith("joint"): return "This source's declared joint predicate and qualification rule; not universal safety."
    return "Exact source-specific predicate/version named by this field; not pooled with other primary effects or converted into one ASR."


def build(index_path, measurement_paths, plan_path, cohort51_path, run_roots, output_dir, extra_evidence=None):
    index, scenarios, links, scenario_sources = assemble_scenarios(index_path, final=True)
    require(set(measurement_paths) == set(SOURCES), "final_release_requires_all_eight_measurement_tables")
    plan = read(plan_path); cohort_raw = Path(cohort51_path).read_bytes(); cohort = json.loads(cohort_raw)
    require(sha(cohort_raw) == plan["cohort_manifest_sha256"] and cohort["cases"] == plan["cases"], "original51_cohort_binding_changed")
    cases = {case["id"]: case for case in scenarios}; original51 = {case["id"]: case for case in cohort["cases"]}
    require(set(plan["supplementary_case_ids"]) == HOLDS and len(plan["security_eligible_case_ids"]) == 49, "next51_authorization_roles_changed")
    for cid in plan["security_eligible_case_ids"]: require(cases[cid] == original51[cid], "admitted49_object_changed")
    for position,case in enumerate(cohort["cases"]):
        if case["id"] in HOLDS:
            cases[case["id"]] = case
            links[case["id"]] = {"source_group": "agentdojo_next51", "source_manifest": str(cohort51_path),
                "source_manifest_sha256": sha(cohort_raw), "row_pointer": "/cases/"+str(position)}
    inventory = terminal_next51_inventory(plan_path, run_roots)
    tables, definitions, rows = {}, {}, []
    for source_id in SOURCES:
        records, table = load_measurements(source_id, measurement_paths[source_id]); validate_records(source_id, records, cases, links)
        relative = "sources/measurements/"+source_id+Path(measurement_paths[source_id]).suffix
        tables[source_id] = {**table, "release_path": relative}
        definitions[source_id] = {name: {"source_field_name": name, "scope": metric_scope(source_id,name), "qualification_inferred": False}
            for name in table["metric_names"]}
        for record in records:
            row = record["row"]; case = cases[row["case_id"]]; held = case["id"] in HOLDS; is_csv = table["format"] == "csv"
            complete_field = "execution_complete" if "execution_complete" in row else "complete" if "complete" in row else None
            rows.append({"source_group": source_id, "population": "supplementary_authorization_overlap" if held else "admitted_dataset",
                "case_id": case["id"], "case_sha256": case["case_sha256"], "class": case["class"], "family_id": case["family_id"],
                "model": row["model"], "condition": row["condition"], "source_run": record["run"],
                "complete_source_field": complete_field, "complete_state": tri(row[complete_field],is_csv) if complete_field else "U",
                "outcome_present_state": tri(row["outcome_present"],is_csv) if "outcome_present" in row else "U",
                "outcome_present_availability": "reported" if "outcome_present" in row else "not_reported",
                "qualified_model_identity_state": tri(row["qualified_model_identity"],is_csv) if "qualified_model_identity" in row else "U",
                "qualified_model_identity_availability": "reported" if "qualified_model_identity" in row else "not_reported",
                "source_status_json": json.dumps({key:row[key] for key in STATUS_FIELDS if key in row},ensure_ascii=False,sort_keys=True),
                "source_model_identity_json": json.dumps(record["identity"],ensure_ascii=False),
                "source_metric_states_json": json.dumps(record["metrics"],ensure_ascii=False,sort_keys=True),
                "original_source_path": table["path"], "source_table_path": relative, "source_table_sha256": table["sha256"],
                "source_row_pointer": record["row_pointer"], "scenario_source_json": json.dumps(links[case["id"]],ensure_ascii=False)})
    require(len(rows) == 2119 and sum(r["population"] == "admitted_dataset" for r in rows) == 2111
        and sum(r["population"] == "supplementary_authorization_overlap" for r in rows) == 8, "release_episode_denominators_changed")
    next_rows = {(r["model"],r["case_id"],r["condition"]):r for r in rows if r["source_group"] == "agentdojo_next51"}
    for model,run in inventory["models"].items():
        for outcome in run["outcomes"]:
            row = next_rows[model,outcome["case_id"],outcome["condition"]]
            require(row["complete_state"] == tri(outcome["complete"])
                and json.loads(row["source_status_json"])["stop_reason"] == outcome["stop_reason"], "next51_measurement_terminal_inventory_mismatch")
    output = Path(output_dir); require(not output.exists(), "release_output_must_be_new"); output.mkdir(parents=True)
    files = {}
    def copy_source(path, relative, expected_sha=None):
        target = output/relative; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(path,target)
        files[relative] = {"sha256":sha(target.read_bytes()),"bytes":target.stat().st_size}
        require(expected_sha is None or files[relative]["sha256"] == expected_sha, "source_changed_during_bundle_copy")
        return relative
    copy_source(index_path,"sources/index.json")
    for source in scenario_sources.values(): copy_source(source["path"],"sources/scenarios/"+Path(source["path"]).name,source["sha256"])
    copy_source(cohort51_path,"sources/scenarios/"+Path(cohort51_path).name,sha(cohort_raw))
    copy_source(plan_path,"sources/next51-plan.json",inventory["plan"]["sha256"])
    for table in tables.values(): copy_source(table["path"],table["release_path"],table["sha256"])
    evidence = {}
    for name,path in (extra_evidence or {}).items():
        require(re.fullmatch(r"[A-Za-z0-9_-]+",name),"invalid_evidence_identifier")
        relative = copy_source(path,"sources/supplementary-evidence/"+name+Path(path).suffix)
        evidence[name] = {"path":relative,**files[relative],"included_in_2119_episode_rows":False}
    save(output/"sources/next51-terminal-inventory.json",inventory)
    save(output/"scenarios.json",{"schema_version":1,"admitted_case_count":388,"cases":scenarios,
        "source_index":{"path":"sources/index.json",**files["sources/index.json"]},"case_objects_unchanged":True})
    with (output/"episodes.csv").open("x",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    copy_source(Path(__file__),"code/release_bundle.py")
    for relative in ("scenarios.json","episodes.csv","sources/next51-terminal-inventory.json"):
        path=output/relative;files[relative]={"sha256":sha(path.read_bytes()),"bytes":path.stat().st_size}
    release={"schema_version":1,"release_status":"final_v1","created_at":datetime.now(timezone.utc).isoformat(),
        "counts":{"admitted_scenarios":388,"episode_rows":2119,"admitted_dataset_episode_rows":2111,"supplementary_episode_rows":8},
        "source_tables":tables,"source_metric_definitions":definitions,"supplementary_evidence":evidence,"files":files,
        "schema":{"metric_encoding":"T=True,F=False,U=source explicit unknown/empty. Metric names remain original and source-specific.",
            "missing_fields":"Unavailable qualified/outcome-present fields are marked not_reported andU; no qualified predicate is invented.",
            "record_status":"Original complete/recorded/evidence/identity/stop fields are preserved in source_status_json; merely having an analysis row never proves execution.",
            "row_pointers":"JSON pointers use zero-based array indices; csv:data-row:N is the1-based logical data-row number, excluding the header.",
            "scenario_scope":"Only388 admitted original case objects. The2held case objects remain in the copied original51cohort, linked from their8 supplementary rows.",
            "metric_scope":"Artifact utility is not semantic utility. Different primary definitions are not combined into one ASR. D/E extra evidence does not add episode rows."},
        "reproduction":{"verify_command":"python -B code/release_bundle.py verify --bundle .","entrypoint":"www2027.release_bundle",
            "scope":"Reproduce the portable table index from unchanged source tables; no model/native execution or score recomputation."},
        "new_model_calls":0,"new_native_tool_executions":0,"new_measurement_rules":0}
    save(output/"release.json",release)
    return release


def inspect(index_path, measurement_paths):
    index,cases,links,sources=assemble_scenarios(index_path)
    by_id={case["id"]:case for case in cases};tables={}
    for source_id,path in measurement_paths.items():
        records,table=load_measurements(source_id,path);validate_records(source_id,records,by_id,links);tables[source_id]=table
    return {"release_status":"not_final_dry_inspection","admitted_case_count":index["admitted_case_count"],
        "available_episode_rows":sum(table["rows"] for table in tables.values()),"tables":tables,
        "final_requirements":"388index,all8source tables,2119rows andboth terminal next51 inventories; current or running data cannot be final.",
        "new_model_calls":0,"new_native_tool_executions":0}


def verify(bundle):
    root=Path(bundle);release=read(root/"release.json");require(release["release_status"]=="final_v1","release_not_final")
    for name,record in release["files"].items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,"unsafe_bundle_path")
        path=root/name;require(sha(path.read_bytes())==record["sha256"] and path.stat().st_size==record["bytes"],"bundle_file_changed:"+name)
    publication=read(root/"publication-bindings.json")
    require(publication["transformation"]=="private_host_path_aliases_only","unexpected_publication_transform")
    bindings={}
    for binding in publication["files"]:
        path=root/binding["path"]
        require(sha(path.read_bytes())==binding["sha256"] and path.stat().st_size==binding["bytes"],"publication_bytes_changed")
        if binding["path"].startswith("sources/scenarios/"):bindings[Path(binding["path"]).name]=binding
    scenarios=read(root/"scenarios.json");_,originals,_,_=assemble_scenarios(root/"sources/index.json",root/"sources/scenarios",final=True,publication_bindings=bindings)
    require(scenarios["cases"]==originals and len(originals)==388,"scenario_objects_changed")
    with (root/"episodes.csv").open(newline="") as stream:rows=list(csv.DictReader(stream))
    require(len(rows)==2119 and sum(r["population"]=="admitted_dataset" for r in rows)==2111,"bundle_episode_count_changed")
    for source_id,table in release["source_tables"].items():
        records,_=load_measurements(source_id,root/table["release_path"]);lookup={r["row_pointer"]:r for r in records}
        selected=[row for row in rows if row["source_group"]==source_id]
        require(len(selected)==SOURCES[source_id][0] and len({r["source_row_pointer"] for r in selected})==len(selected),"bundle_source_row_drop_or_duplicate")
        for row in selected:
            original=lookup[row["source_row_pointer"]]
            require(all(row[key]==original["row"][key] for key in ("case_id","model","condition"))
                and json.loads(row["source_metric_states_json"])==original["metrics"]
                and json.loads(row["source_status_json"])=={key:original["row"][key] for key in STATUS_FIELDS if key in original["row"]},
                "bundle_source_metric_or_identity_changed")
    return {"status":"verified","counts":release["counts"],"new_model_calls":0,"new_native_tool_executions":0}


def pairs(values):
    result={}
    for value in values or []:
        name,separator,path=value.partition("=");require(separator and name and path and name not in result,"invalid_or_duplicate_input_assignment")
        result[name]=Path(path)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest="action",required=True)
    for name in ("inspect","build"):
        command=commands.add_parser(name);command.add_argument("--index",type=Path,required=True)
        command.add_argument("--measurements",action="append",required=True,metavar="SOURCE_ID=PATH")
        if name=="build":
            for flag in ("next51-plan","next51-cohort","output-dir"):command.add_argument("--"+flag,type=Path,required=True)
            command.add_argument("--next51-run-root",action="append",type=Path,required=True)
            command.add_argument("--evidence",action="append",metavar="NAME=PATH")
        else:command.add_argument("--output",type=Path,required=True)
    command=commands.add_parser("verify");command.add_argument("--bundle",type=Path,required=True)
    args=parser.parse_args()
    if args.action=="inspect":
        result=inspect(args.index,pairs(args.measurements));save(args.output,result)
        print(json.dumps({k:result[k] for k in ("release_status","admitted_case_count","available_episode_rows")}))
    elif args.action=="verify":print(json.dumps(verify(args.bundle)))
    else:
        result=build(args.index,pairs(args.measurements),args.next51_plan,args.next51_cohort,args.next51_run_root,args.output_dir,pairs(args.evidence))
        print(json.dumps({"release_status":result["release_status"],"counts":result["counts"]}))


if __name__=="__main__":main()
