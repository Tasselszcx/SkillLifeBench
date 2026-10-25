#!/usr/bin/env python3
"""Incremental saved-only qualification and Boolean scoring for Qwen policy runs.

Pilot records verify the protocol but are never scored or admitted to results.
Every full-run output binds exact Default/Check instruction bytes, public task,
tool schemas, native receipts, local checkpoint identity and server PID.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time

A = Path(__file__).resolve().parent
R = A.parents[1]
C = A.parents[2] / 'SafeSkillbench'
sys.path.insert(0, str(C))
sys.path.insert(0, str(A))
sys.dont_write_bytecode = True
from saved_runtime_inputs_v56 import load_inputs


def digest(path):
    h = sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def bind(path):
    return {'path': str(path), 'sha256': digest(path), 'bytes': Path(path).stat().st_size}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def json_extra(value):
    if isinstance(value, Decimal):
        return str(value)
    raise TypeError(type(value).__name__)


def write(path, value, exclusive=False):
    mode = 'x' if exclusive else 'w'
    with Path(path).open(mode) as f:
        json.dump(value, f, ensure_ascii=False, sort_keys=True, indent=2, default=json_extra)
        f.write('\n')


def module_from(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Qualifier:
    def __init__(self, run_root, output, protocol_only):
        self.root, self.output = Path(run_root), Path(output)
        self.protocol = json.loads((self.root / 'protocol.json').read_text())
        self.manifest = self.protocol['frozen_manifest']
        self.protocol_only = protocol_only
        if self.protocol['phase'] == 'pilot':
            assert protocol_only, 'pilot_must_not_be_scored'
        else:
            assert self.protocol['phase'] == 'full' and self.protocol['is_ranked_full_cohort'] is True
        self.output.mkdir(parents=True, exist_ok=False)
        (self.output / 'cells').mkdir()
        (self.output / 'source-snapshot').mkdir()
        for path in (Path(__file__), A / 'saved_runtime_inputs_v56.py',
                     C / 'www2027/agentdojo_binary_task_v56.py', C / 'www2027/agentdojo_binary_goal_v56.py'):
            (self.output / 'source-snapshot' / path.name).write_bytes(path.read_bytes())
        manifest_path = Path(self.protocol['manifest_path'])
        assert digest(manifest_path) == self.protocol['manifest_sha256']
        assert json.loads(manifest_path.read_text()) == self.manifest
        self.manifest_dir = manifest_path.parent
        pins = []
        for b in self.manifest['implementation_bindings']:
            source = Path(b['path'])
            assert source.name not in {'.env', 'legacy_a_cases.py', 'auth.json', 'credentials.json'}
            if digest(source) != b['sha256']:
                source = self.manifest_dir / 'source-snapshot/www2027' / source.name
            assert digest(source) == b['sha256'], 'historical_code_binding_missing:' + b['path']
            (self.output / 'source-snapshot' / source.name).write_bytes(source.read_bytes())
            pins.append(bind(source))
        for key in ('parent_protocol', 'cases', 'schedule', 'system_default', 'check_append_only', 'system_check'):
            b = self.manifest[key]
            assert digest(b['path']) == b['sha256']
        self.default = Path(self.manifest['system_default']['path']).read_text()
        self.check = Path(self.manifest['system_check']['path']).read_text()
        self.check_block = Path(self.manifest['check_append_only']['path']).read_text()
        assert self.check == self.default + '\n\n' + self.check_block
        self.cases = {r['id']: r for r in json.loads(Path(self.manifest['cases']['path']).read_text())['cases']}
        assert len(self.cases) == 89
        self.jobs = {j['job_id']: j for j in (json.loads(l) for l in Path(self.manifest['schedule']['path']).open())}
        assert len(self.jobs) == 534
        self.models = {m['key']: m for m in self.manifest['models']}
        self.identities = {}
        self.server_bindings = []
        for key, model in self.models.items():
            observed = self.protocol['observed_servers'][key]
            assert all(observed.get(k) == v for k, v in model['expected_identity'].items())
            assert type(observed['pid']) is int and observed['loaded_parameter_count'] > 0
            served_path = Path(model['instance_root']) / 'served_identity.json'
            saved_identity = json.loads(served_path.read_text())
            assert {k: v for k, v in saved_identity.items() if k != 'updated_at'} == observed
            assert digest(model['pinned_manifest']['path']) == model['pinned_manifest']['sha256']
            assert digest(model['server_source']['path']) == model['server_source']['sha256']
            self.identities[key] = {**model['expected_identity'], 'pid': observed['pid']}
            self.server_bindings.append({'model_key': key, 'served_identity': bind(served_path),
                                         'checkpoint_manifest': model['pinned_manifest'],
                                         'server_source': model['server_source']})
        frozen = R / 'audit/paper-final-v14/argument-qualification-v2/full-derivative-plan-run02-cache'
        loader = module_from(frozen / 'run_saved_derivative.py', 'v56_qwen_source_gate_loader')
        adapter = json.loads((frozen / 'execution-plan.json').read_text())['adapter']
        self.science, self.qualification, self.context, _ = loader.load_science(adapter)
        controller_path = self.output / 'source-snapshot/qwen_runtime_repair_v56.py'
        self.controller = module_from(controller_path, 'v56_qwen_bound_controller_rules')
        self.task_contracts, self.goal_contracts = {}, {}
        for group, n, g in [('agentdojo_next40', '40', '60'), ('agentdojo_next51', '51', '51')]:
            self.task_contracts[group] = {c['candidate_id']: c for c in json.loads((R / f'dataset/agentdojo-next{n}-normal-utility-contracts.json').read_text())['contracts']}
            self.goal_contracts[group] = {(c['candidate_id'], c['condition']): c for c in json.loads((R / f'dataset/agentdojo-next{g}-target-contracts.json').read_text())['contracts']}
        if not protocol_only:
            from www2027.agentdojo_binary_task_v56 import score_binary_task
            from www2027.agentdojo_binary_goal_v56 import score_binary_goal
            self.score_task, self.score_goal = score_binary_task, score_binary_goal
            self.task_freeze = json.loads((A / 'grader-freeze05.json').read_text())
            self.goal_freeze = json.loads((A / 'goal-grader-freeze01.json').read_text())
            assert digest(C / 'www2027/agentdojo_binary_task_v56.py') == self.task_freeze['bindings'][0]['sha256']
            assert digest(C / 'www2027/agentdojo_binary_goal_v56.py') == self.goal_freeze['source']['sha256']
        write(self.output / 'qualification-protocol.json', {'run_protocol': bind(self.root / 'protocol.json'),
              'manifest': bind(manifest_path), 'protocol_only': protocol_only,
              'identity_sources': self.server_bindings, 'implementation_pins': pins,
              'source_qualification': adapter, 'new_model_calls': 0}, exclusive=True)

    def qualify(self, selected):
        job = self.jobs[selected['job_id']]
        assert all(selected[k] == v for k, v in job.items())
        choice = selected['selected_attempt']
        if choice is None:
            return {'job_id': job['job_id'], 'status': 'infrastructure_pending', 'attempts': selected['attempts']}
        assert choice == next(x['attempt'] for x in selected['attempts'] if x['valid_execution_candidate'])
        terminal = next(x for x in selected['attempts'] if x['attempt'] == choice)
        cell = Path(terminal['cell'])
        outcome_path = cell / 'session/outcome.json'
        assert digest(outcome_path) == terminal['outcome_sha256']
        outcome = json.loads(outcome_path.read_text())
        model, case = self.models[job['model_key']], self.cases[job['case_id']]
        assert outcome['harness'] == job['harness'] == 'native'
        assert outcome['model'] == model['model_id']
        assert all(outcome[k] == job[k] for k in ('case_id', 'case_sha256', 'condition'))
        policy = json.loads((cell / 'policy-binding.json').read_text())
        assert policy['job'] == job and policy['policy'] == job['policy']
        assert policy['default_system_sha256'] == sha256(self.default.encode()).hexdigest()
        assert policy['check_append_sha256'] == sha256(self.check_block.encode()).hexdigest()
        assert policy['user_message_unchanged'] is True and policy['public_tools_unchanged'] is True
        expected_system = self.default if job['policy'] == 'Default' else self.check
        assert sha256(expected_system.encode()).hexdigest() == job['system_sha256'] == policy['actual_system_sha256']
        initial = json.loads((cell / 'session/initial-input.json').read_text())
        assert initial['messages'][0] == {'role': 'system', 'content': expected_system}
        assert len(initial['messages']) == 2 and initial['messages'][1]['role'] == 'user'
        assert sha256(initial['messages'][1]['content'].encode()).hexdigest() == job['task_sha256'] == case['normal_prompt_sha256']
        assert sha256(self.science.canonical([t['function'] for t in initial['tools']]).encode()).hexdigest() == job['catalog_sha256']
        assert initial['limits'] == self.manifest['harness_limits'] == outcome['limits']
        assert initial['backend_provenance'] == outcome['source_backend']
        assert {k: v for k, v in outcome['source_backend'].items() if k != 'initial_binding'} == job['source_binding']
        ib = json.loads((cell / 'session/initial-binding.json').read_text())
        expected_initial = {k: case['conditions'][job['condition']][k] for k in ('initial_state_sha256', 'source_map_sha256', 'effective_map_sha256')}
        assert ib['verified_before_model_request'] is True and ib['expected'] == ib['observed'] == expected_initial
        api_model = {'model': model['model_id'], 'identity_contract': self.identities[job['model_key']]}
        api = self.science.bind_matrix_api(cell / 'session', outcome, api_model, self.manifest['harness_limits'])
        classification = None
        classification_path = cell / 'terminal-classification.json'
        if classification_path.exists():
            classification = json.loads(classification_path.read_text())
            last_path = sorted((cell / 'session').glob('api-*.json'))[-1]
            expected_classification = self.controller.classify_local_terminal(outcome['stop_reason'],
                json.loads(last_path.read_text()), model, self.identities[job['model_key']])
            expected_classification.update(raw_api_path=str(last_path), raw_api_sha256=digest(last_path))
            assert classification == expected_classification == terminal['terminal_classification']
            assert classification['derived_stop_reason'] == terminal['stop_reason']
        qualified_identity = api['qualified'] is True
        # A source-pinned context rejection can occur before any generation.
        # It is tied to the model endpoint, frozen capacity and startup PID,
        # rather than asserted to be a generated model response.
        context_only = classification and classification['classification'] == 'exact_pinned_context_budget_error'
        generated_terminal = classification and classification['classification'] in {
            'pinned_model_generated_syntax_failure', 'pinned_incomplete_generation'}
        assert qualified_identity or (api['qualified'] is None and (context_only or generated_terminal)), 'local_identity_not_qualified'
        group = job['source_binding']['source_group']
        verifier = self.qualification._receipts40 if group == 'agentdojo_next40' else self.qualification._receipts51
        native = verifier(cell / 'backend', Path(self.manifest['source_root']))
        raw = {'job_id': job['job_id'], 'case_id': job['case_id'], 'case_sha256': job['case_sha256'],
               'condition': job['condition'], 'policy': job['policy'], 'harness': 'native',
               'model_key': job['model_key'], 'model': model['model_id'], 'source_group': group,
               'outcome_path': str(outcome_path), 'outcome_sha256': terminal['outcome_sha256'],
               'stop_reason': terminal['stop_reason'], 'raw_stop_reason': outcome['stop_reason'],
               'execution_complete': outcome.get('complete') is True,
               'receipt_measurements': native['rows'], 'source_measurements': {},
               'runtime_issues': native.get('issues', []), 'issues': [],
               'model_identity_kind': 'pinned_local_checkpoint_and_pid',
               'model_observation_qualified': True, 'local_identity_observations': api['identity_rows'],
               'local_identity_contract': api_model['identity_contract'],
               'policy_binding': bind(cell / 'policy-binding.json'),
               'physical_api_receipt_bindings': [bind(p) for p in sorted((cell / 'session').glob('api-*.json'))],
               'selected_attempt': choice, 'phase': self.protocol['phase']}
        if classification:
            raw['qualified_terminal_classification'] = bind(classification_path) | {'source_classification_verified': True}
        inputs = load_inputs(raw, {'scheduled_row': {'model_observation_qualified': True}})
        assert inputs['validity'] == 'valid', json.dumps(inputs['binding_proof']['issues'])
        result = {'job_id': job['job_id'], 'model_key': job['model_key'], 'case_id': job['case_id'],
                  'policy': job['policy'], 'condition': job['condition'], 'harness': 'native',
                  'status': 'qualified', 'phase': self.protocol['phase'], 'counts_in_final': not self.protocol_only,
                  'outcome': bind(outcome_path), 'source_record': raw,
                  'binding_proof': inputs['binding_proof'], 'new_model_calls': 0}
        if not self.protocol_only:
            task = self.score_task(group, self.task_contracts[group][job['case_id']], inputs['initial_state'],
                                   inputs['final_state'], inputs['final_answer'], inputs['observations'], evidence_valid=True)
            goal = self.score_goal(group, self.goal_contracts[group][job['case_id'], job['condition']], inputs['initial_state'],
                                   inputs['transitions'], final_answer=inputs['final_answer'] or '',
                                   user_visible_outputs=inputs['user_visible_outputs'], evidence_valid=True)
            result.update(task=task, goal=goal, task_success=task['task_success'], goal_success=goal['goal_success'],
                          primary_effect=goal['primary_effect'],
                          joint_success=task['task_success'] and not goal['goal_success']
                          if type(task['task_success']) is bool and type(goal['goal_success']) is bool else None)
            if task['status'] == 'review_required' or goal['status'] == 'review_required':
                result['anonymous_review'] = {'review_id': sha256(('qwen-v56:' + job['job_id'] + ':' + terminal['outcome_sha256']).encode()).hexdigest()[:20],
                    'case_id': job['case_id'], 'policy': job['policy'], 'condition': job['condition'],
                    'outcome_sha256': terminal['outcome_sha256'], 'public_task': case['task'],
                    'contract_parameters': self.task_contracts[group][job['case_id']]['parameters'],
                    'final_answer': inputs['final_answer'], 'task_measurement': task, 'goal_measurement': goal,
                    'observations': inputs['observations'], 'initial_state': inputs['initial_state'], 'final_state': inputs['final_state']}
        filename = sha256(job['job_id'].encode()).hexdigest()[:24] + '.json'
        write(self.output / 'cells' / filename, result, exclusive=True)
        return {k: v for k, v in result.items() if k not in ('source_record', 'binding_proof', 'anonymous_review', 'task', 'goal')} | {
            'record': bind(self.output / 'cells' / filename), 'semantic_review_required': 'anonymous_review' in result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--protocol-only', action='store_true')
    parser.add_argument('--follow', action='store_true')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    assert 1 <= args.workers <= 8
    q = Qualifier(args.run_root, args.output, args.protocol_only)
    from www2027.gateway_direct_measurement01 import offline_guard
    done, errors, pending = {}, [], {}
    with offline_guard() as denied:
        while True:
            selections = json.loads((args.run_root / 'selection.json').read_text()) if (args.run_root / 'selection.json').exists() else []
            selected = [s for s in selections if s['job_id'] not in done]
            def work(s):
                try:
                    return q.qualify(s)
                except Exception as e:
                    return {'job_id': s['job_id'], 'status': 'qualification_error', 'error': type(e).__name__ + ':' + str(e)}
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                for row in pool.map(work, selected):
                    if row['status'] == 'qualified':
                        done[row['job_id']] = row
                        pending.pop(row['job_id'], None)
                    else:
                        pending[row['job_id']] = row
                    print(row['job_id'], row['status'], row.get('error', ''), flush=True)
            snapshot = {'qualified': len(done), 'selected_terminals': len(selections),
                        'phase': q.protocol['phase'], 'protocol_only': args.protocol_only,
                        'model_calls': 0, 'tool_executions': 0, 'denied_operations': dict(denied),
                        'records': list(done.values()), 'pending': list(pending.values())}
            write(args.output / 'status.json.tmp', snapshot)
            (args.output / 'status.json.tmp').replace(args.output / 'status.json')
            if not args.follow or (args.run_root / 'complete.json').exists() or (args.run_root / 'controller-abort.json').exists():
                write(args.output / 'complete.json', snapshot, exclusive=True)
                print('DONE', len(done), 'pending', len(pending), 'protocol_only', args.protocol_only, flush=True)
                break
            time.sleep(20)


if __name__ == '__main__':
    main()
