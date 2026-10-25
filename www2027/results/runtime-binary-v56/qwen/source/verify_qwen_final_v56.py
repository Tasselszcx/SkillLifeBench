#!/usr/bin/env python3
"""Independently reconcile final Qwen case ledgers, raw bindings and pair counts."""
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import re


def binding(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha256(data).hexdigest()}


def checked(descriptor):
    actual = binding(descriptor['path'])
    for key in ('sha256', 'bytes'):
        if key in descriptor:
            assert actual[key] == descriptor[key], (descriptor['path'], key)
    return json.loads(Path(descriptor['path']).read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--summary-root', type=Path, required=True)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    summary = json.loads((args.summary_root / 'summary.json').read_text())
    rows = json.loads((args.summary_root / 'rows.json').read_text())
    ledger = [json.loads(line) for line in (args.summary_root / 'case-verdicts.jsonl').read_text().splitlines()]
    pairs = json.loads((args.summary_root / 'paired-default-check.json').read_text())
    complete = json.loads((args.run_root / 'complete.json').read_text())
    protocol = json.loads((args.run_root / 'protocol.json').read_text())
    assert summary['publication_ready'] and summary['semantic_review_rows'] == 0
    assert summary['qualification_pending'] == []
    assert len(rows) == len(ledger) == complete['planned'] == complete['terminal'] == 534
    assert protocol['phase'] == 'full' and protocol['is_ranked_full_cohort'] is True
    assert summary['pilot_records_used'] == 0 and summary['author_aggregate_counts_used'] is False
    manifest = protocol['frozen_manifest']
    systems = {}
    for key, policy in [('system_default', 'Default'), ('system_check', 'Check')]:
        descriptor = manifest[key]
        assert binding(descriptor['path'])['sha256'] == descriptor['sha256']
        systems[policy] = Path(descriptor['path']).read_text()
    assert systems['Check'].startswith(systems['Default'])
    append = manifest['check_append_only']
    assert binding(append['path'])['sha256'] == append['sha256']
    assert systems['Check'][len(systems['Default']):].strip() == Path(append['path']).read_text().strip()
    index, groups, policies, actual_initial_requests = {}, defaultdict(list), {}, {}
    decisions, stops = Counter(), Counter()
    ledger_by_id = {r['job_id']: r for r in ledger}
    assert len(ledger_by_id) == 534
    exposed_identity = re.compile(r'local[49]b|qwen3\.5-[49]b|Qwen3\.5-[49]B|/Default/|/Check/')
    for row in rows:
        key = row['model_key'], row['policy'], row['condition'], row['case_id']
        assert key not in index
        index[key] = row
        groups[key[:3]].append(row)
        assert row['status'] == 'qualified' and row['validity'] == 'valid'
        assert row['phase'] == 'full' and row['counts_in_final'] is True and row['harness'] == 'native'
        assert row['new_model_calls'] == 0
        assert all(type(row[k]) is bool for k in ('task_success', 'goal_success', 'primary_effect', 'joint_success'))
        assert row['joint_success'] == (row['task_success'] and not row['goal_success'])
        compact = {k: v for k, v in row.items() if k not in ('task', 'goal')}
        assert compact == ledger_by_id[row['job_id']]
        qualified = checked(row['qualified_record'])
        outcome = checked(row['outcome'])
        assert qualified['job_id'] == row['job_id']
        assert qualified['outcome'] == row['outcome']
        assert qualified['binding_proof']['issues'] == []
        assert qualified['binding_proof']['gateway_observation_qualified'] is True
        assert qualified['binding_proof']['model_identity_kind'] == 'pinned_local_checkpoint_and_pid'
        assert not qualified['binding_proof']['service_error_signatures']
        assert all(all(receipt['checks'].values()) for receipt in qualified['binding_proof']['receipts'])
        if qualified.get('anonymous_review'):
            blinded = {k: v for k, v in qualified['anonymous_review'].items() if k != 'policy'}
            assert not exposed_identity.search(json.dumps(blinded, ensure_ascii=False)), 'review_packet_exposes_model_or_policy_metadata'
        policy = checked(row['policy_binding'])
        policies[key] = policy
        assert policy['user_message_unchanged'] and policy['public_tools_unchanged']
        assert policy['job']['job_id'] == row['job_id']
        assert policy['actual_system_sha256'] == sha256(systems[row['policy']].encode()).hexdigest()
        assert policy['job']['case_sha256'] == row['case_sha256']
        request_path = Path(row['outcome']['path']).parent / 'request-000.json'
        request = json.loads(request_path.read_text())
        # Independently compare the actual initial request, not only its binding flags.
        if 'request' in request:
            request = request['request']
        assert request['messages'][0]['role'] == 'system'
        assert request['messages'][0]['content'] == systems[row['policy']]
        actual_initial_requests[key] = request
        stops[(row['model_key'], row['policy'], str(outcome.get('stop_reason')))] += 1
        if row.get('adjudication'):
            decision = row['adjudication']
            assert decision['outcome_sha256'] == row['outcome']['sha256']
            assert decision['task_success'] == row['task_success']
            if 'goal_success' in decision:
                assert decision['goal_success'] == row['goal_success']
            decisions[(row['model_key'], row['policy'])] += 1
        else:
            assert row['task_success'] == qualified['task_success']
            assert row['goal_success'] == qualified['goal_success']
    assert len(groups) == 6 and all(len(group) == 89 for group in groups.values())
    case_sets = [{r['case_id'] for r in group} for group in groups.values()]
    assert all(cases == case_sets[0] and len(cases) == 89 for cases in case_sets)
    counts = []
    for key, group in sorted(groups.items()):
        cross = Counter(('T' if r['task_success'] else 'F') + ('T' if r['goal_success'] else 'F') for r in group)
        item = dict(zip(('model_key', 'policy', 'condition'), key))
        item.update(N=89, task_true=sum(r['task_success'] for r in group),
                    goal_true=sum(r['goal_success'] for r in group),
                    joint_true=sum(r['joint_success'] for r in group),
                    four_cells={k: cross[k] for k in ('TT', 'TF', 'FT', 'FF')})
        reported = next(g for g in summary['groups'] if tuple(g[k] for k in ('model_key', 'policy', 'condition')) == key)
        for field in ('task', 'goal', 'joint'):
            assert item[field + '_true'] == reported[field]['T']
        counts.append(item)
    assert len(pairs) == 178 and len({(p['model_key'], p['case_id']) for p in pairs}) == 178
    transitions = defaultdict(Counter)
    compare_job = ('case_id', 'case_sha256', 'catalog_sha256', 'condition', 'harness',
                   'initial_state_sha256', 'model_key', 'source_binding', 'task_sha256')
    for pair in pairs:
        keys = [(pair['model_key'], policy, 'injected', pair['case_id']) for policy in ('Default', 'Check')]
        default, check = [index[key] for key in keys]
        assert default['identity_contract'] == check['identity_contract']
        assert all(policies[keys[0]]['job'][k] == policies[keys[1]]['job'][k] for k in compare_job)
        default_request, check_request = [actual_initial_requests[key] for key in keys]
        assert default_request.keys() == check_request.keys()
        assert all(default_request[k] == check_request[k] for k in default_request if k != 'messages')
        assert default_request['messages'][1:] == check_request['messages'][1:]
        for prefix, row in [('default', default), ('check', check)]:
            assert pair[prefix + '_record'] == row['qualified_record']
            assert pair[prefix + '_outcome'] == row['outcome']
            for field in ('task_success', 'goal_success', 'joint_success'):
                assert pair[prefix + '_' + field] == row[field]
        assert pair['default_is_the_same_record_as_leaderboard'] is True
        transitions[pair['model_key']][('T' if default['joint_success'] else 'F') + ('T' if check['joint_success'] else 'F')] += 1
    for key, cross in transitions.items():
        reported = next(x for x in summary['paired_summary'] if x['model_key'] == key)
        assert reported['joint_default_check_transitions'] == {k: cross[k] for k in ('TT', 'TF', 'FT', 'FF')}
    result = {'schema': 'independent-qwen-final-verification/v56', 'status': 'passed',
              'records': 534, 'cases': 89, 'shared_default_records': 356, 'same_record_check_pairs': 178,
              'all_task_goal_joint_primary_values_boolean': True,
              'actual_initial_request_only_system_check_append_differs': True,
              'all_native_receipt_checks_passed': True,
              'all_raw_outcome_and_qualification_hashes_verified': True,
              'explicit_model_and_policy_metadata_absent_from_review_packets': True,
              'counts': counts, 'paired_transitions': {k: dict(v) for k, v in transitions.items()},
              'codex_assisted_adjudications': sum(decisions.values()),
              'codex_assisted_adjudication_counts': [{'model_key': k[0], 'policy': k[1], 'N': v} for k, v in sorted(decisions.items())],
              'raw_stop_reasons': [{'model_key': k[0], 'policy': k[1], 'stop_reason': k[2], 'N': v} for k, v in sorted(stops.items())],
              'input_bindings': [binding(args.summary_root / name) for name in ('summary.json', 'rows.json', 'case-verdicts.jsonl', 'paired-default-check.json')],
              'model_calls': 0, 'native_tool_executions': 0}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'records': 534, 'pairs': 178, 'codex_assisted_adjudications': sum(decisions.values())}))


if __name__ == '__main__':
    main()
