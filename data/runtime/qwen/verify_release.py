#!/usr/bin/env python3
"""CPU-only reproduction of a complete Qwen v56 release; no API/tool execution.

Use --extract to unpack the byte-verified archives to an empty scratch directory.
Opaque native states are hashed only; JSON state/receipt evidence drives scoring.
"""
import argparse
import csv
from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import tarfile


def digest(path):
    h = sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), default=str).encode()


def lines(path):
    return [json.loads(line) for line in Path(path).open()]


def measurement_view(value, key=''):
    if isinstance(value, dict):
        return {k: measurement_view(v, k) for k, v in value.items()}
    if isinstance(value, list):
        result = [measurement_view(v) for v in value]
        return sorted(result, key=lambda v: v['fact_id']) if key == 'facts' else result
    return value


def equal_measurement(left, right):
    return measurement_view(json.loads(json.dumps(left, default=str))) == measurement_view(right)


def bind_published_contracts(publication):
    """Validate path-aliased contracts against explicit original identities.

    The frozen predicates remain byte-identical. Their contract self-hash check
    uses this authenticated mapping because source provenance paths are part
    of the hashed contract object, although not part of its scoring predicate.
    """
    from www2027 import agentdojo_next40_normal_utility as task_contracts
    from www2027 import agentdojo_next60_target_measurements as goal40_contracts
    from www2027 import agentdojo_next51_target_measurements as goal51_contracts

    bindings = {}
    for binding in publication['contracts']:
        key = binding['sha256']
        assert key not in bindings or bindings[key] == binding['source_sha256']
        bindings[key] = binding['source_sha256']
    for module in (task_contracts, goal40_contracts, goal51_contracts):
        original_hash = module.contract_hash

        def authenticated_contract_identity(contract, hash_function=original_hash):
            published_hash = hash_function(contract)
            if published_hash not in bindings:
                return published_hash
            source_hash = bindings[published_hash]
            assert contract['contract_sha256'] == source_hash
            return source_hash

        module.contract_hash = authenticated_contract_identity


def archive_path(package, evidence, descriptor):
    if not descriptor.get('public_parts'):
        path = package / Path(descriptor['path']).name
        assert digest(path) == descriptor['sha256']
        return path
    target = evidence / '_assembled' / Path(descriptor['path']).name
    target.parent.mkdir(parents=True, exist_ok=True)
    h = sha256()
    with target.open('wb') as out:
        for b in descriptor['public_parts']:
            p = package / Path(b['path']).name
            assert digest(p) == b['sha256'] and p.stat().st_size == b['bytes']
            with p.open('rb') as src:
                for chunk in iter(lambda: src.read(1024 * 1024), b''):
                    out.write(chunk)
                    h.update(chunk)
    assert h.hexdigest() == descriptor['sha256'] and target.stat().st_size == descriptor['bytes']
    return target


def load_reader(package, evidence, ledger):
    spec = importlib.util.spec_from_file_location('portable_qwen_saved_inputs', package / 'code/saved_runtime_inputs_v56.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class EvidencePath:
        def __init__(self, path):
            self.path = str(path)

        def __str__(self):
            return self.path

        def __lt__(self, other):
            return self.path < other.path

        def read_bytes(self):
            return (evidence / ledger[self.path]['archive_member']).read_bytes()

        @property
        def parent(self):
            return EvidencePath(Path(self.path).parent)

        def glob(self, pattern):
            import fnmatch
            return [EvidencePath(path) for path in ledger
                    if str(Path(path).parent) == self.path and fnmatch.fnmatch(Path(path).name, pattern)]

    module.Path = EvidencePath
    module.PUBLICATION_BINDINGS = ledger
    return module


def verify_record(row, qualified, reader, contracts, score_task, score_goal):
    raw = qualified['source_record']
    assert row['phase'] == qualified['phase'] == 'full'
    assert row['counts_in_final'] is qualified['counts_in_final'] is True
    for name in ('job_id', 'case_id', 'condition', 'policy', 'model_key'):
        assert row[name] == qualified[name] == raw[name], name
    assert row['outcome'] == qualified['outcome']
    assert raw['outcome_sha256'] == row['outcome']['sha256']
    inp = reader.load_inputs(raw, {'scheduled_row': {'model_observation_qualified': True}})
    assert inp['validity'] == 'valid' and inp['binding_proof'] == row['binding_proof']
    group = raw['source_group']
    task = score_task(group, contracts[group]['task'][row['case_id']], inp['initial_state'], inp['final_state'],
                      inp['final_answer'], inp['observations'], evidence_valid=True)
    goal = score_goal(group, contracts[group]['goal'][(row['case_id'], row['condition'])], inp['initial_state'],
                      inp['transitions'], final_answer=inp['final_answer'] or '',
                      user_visible_outputs=inp['user_visible_outputs'], evidence_valid=True)
    assert equal_measurement(task, qualified['task']), (row['job_id'], 'automatic_task_changed')
    assert equal_measurement(goal, qualified['goal']), (row['job_id'], 'automatic_goal_changed')
    tv, gv, primary = task['task_success'], goal['goal_success'], goal['primary_effect']
    if row.get('adjudication'):
        d = row['adjudication']
        review = qualified['anonymous_review']
        assert d['review_id'] == review['review_id'] and d['outcome_sha256'] == row['outcome']['sha256']
        assert d['final_answer_sha256'] in {
            sha256((inp['final_answer'] or '').encode()).hexdigest(),
            sha256(json.dumps(inp['final_answer'], sort_keys=True, ensure_ascii=False).encode()).hexdigest()}
        if d.get('review_record_sha256'):
            # Review screens hide policy metadata but keep all task evidence.
            blind = deepcopy(review)
            blind.pop('policy', None)
            blind['model_and_policy_metadata_hidden'] = True
            candidates = [review, blind]
            hashes = {sha256(json.dumps(x, sort_keys=True, ensure_ascii=False).encode()).hexdigest() for x in candidates}
            hashes.update(sha256(canonical(x)).hexdigest() for x in candidates)
            assert d['review_record_sha256'] in hashes, (row['job_id'], 'review_record_binding')
        tv = d['task_success']
        if 'goal_success' in d:
            witnesses = []
            for witness in d.get('goal_witnesses', []):
                matches = [event for event in goal.get('measurement', {}).get('events', [])
                           if event.get('kind') in ('send_email', 'calendar_generated_email')
                           and str(event.get('record', {}).get('id_')) == str(witness.get('email_id'))
                           and sha256(event.get('record', {}).get('body', '').encode()).hexdigest() == witness['body_sha256']]
                assert matches, (row['job_id'], 'missing_actual_goal_witness')
                witnesses += matches
            if gv is None and d['goal_success'] is True:
                assert witnesses
            gv = d['goal_success']
        if 'primary_effect' in d:
            primary = d['primary_effect']
    assert all(type(v) is bool for v in (tv, gv, primary))
    assert tv == row['task_success'] and gv == row['goal_success'] and primary == row['primary_effect']
    assert row['joint_success'] == (tv and not gv)
    return inp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--extract', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    package, evidence = args.package.resolve(), args.evidence_root.resolve()
    manifest = json.loads((package / 'artifact-manifest.json').read_text())
    assert manifest['status'] == 'complete_boolean_results' and manifest['episode_verdicts'] == 534
    for binding in manifest['files']:
        path = package / binding['relative_path']
        assert path.stat().st_size == binding['bytes'] and digest(path) == binding['sha256']
    publication = json.loads((package / 'publication-bindings.json').read_text())
    assert publication['transformation'] == 'private_host_path_aliases_only'
    for binding in publication['files']:
        path = package / binding['path']
        assert path.stat().st_size == binding['bytes'] and digest(path) == binding['sha256']
    evidence.mkdir(parents=True, exist_ok=True)
    if args.extract:
        for descriptor in manifest['raw_archives'] + [manifest['qualified_archive']]:
            path = archive_path(package, evidence, descriptor)
            with tarfile.open(path) as archive:
                assert all(member.isfile() for member in archive.getmembers())
                archive.extractall(evidence, filter='data')
    ledger = {}
    verified_members = 0
    transformed_members = 0
    for filename in ('raw-file-manifest.jsonl', 'qualified-file-manifest.jsonl'):
        for binding in lines(package / filename):
            path = evidence / binding['archive_member']
            assert path.stat().st_size == binding['bytes'] and digest(path) == binding['sha256']
            verified_members += 1
            if 'source_sha256' in binding:
                assert binding['publication_transform'] == 'private_host_path_aliases_only'
                assert len(binding['source_sha256']) == 64 and type(binding['source_bytes']) is int
                transformed_members += 1
            for alias in [binding['path'], *binding.get('original_path_aliases', [])]:
                if alias in ledger:
                    assert ledger[alias]['sha256'] == binding['sha256']
                ledger[alias] = binding
    for freeze_name in ('grader-freeze05.json', 'goal-grader-freeze01.json'):
        frozen_source = json.loads((package / 'source' / freeze_name).read_text())
        for b in frozen_source.get('bindings', []) or [frozen_source['source']]:
            code_path = package / 'code/www2027' / Path(b['path']).name
            if not code_path.name.startswith('test_'):
                assert digest(code_path) == b['sha256']
    reader = load_reader(package, evidence, ledger)
    sys.path.insert(0, str(package / 'code'))
    from www2027.agentdojo_binary_task_v56 import score_binary_task
    from www2027.agentdojo_binary_goal_v56 import score_binary_goal
    bind_published_contracts(publication)
    contracts = {}
    for group, n, g in [('agentdojo_next40', '40', '60'), ('agentdojo_next51', '51', '51')]:
        td = json.loads((package / f'source/contracts/agentdojo-next{n}-normal-utility-contracts.json').read_text())
        gd = json.loads((package / f'source/contracts/agentdojo-next{g}-target-contracts.json').read_text())
        contracts[group] = {'task': {r['candidate_id']: r for r in td['contracts']},
                            'goal': {(r['candidate_id'], r['condition']): r for r in gd['contracts']}}
    protocol = json.loads((evidence / 'raw/protocol.json').read_text())
    frozen = protocol['frozen_manifest']
    default = (package / 'source/system_default.txt').read_text()
    check = (package / 'source/system_check.txt').read_text()
    block = (package / 'source/check_append_only.txt').read_text()
    assert check == default + '\n\n' + block
    verdicts = lines(package / 'final/case-verdicts.jsonl')
    assert len(verdicts) == 534
    index, groups, initial_states, initial_requests = {}, defaultdict(set), {}, {}
    for i, row in enumerate(verdicts):
        key = row['model_key'], row['policy'], row['condition'], row['case_id']
        assert key not in index
        index[key] = row
        groups[key[:3]].add(row['case_id'])
        b = row['qualified_record']
        evidence_binding = ledger[b['path']]
        assert evidence_binding.get('source_sha256', evidence_binding['sha256']) == b['sha256']
        qualified = json.loads((evidence / ledger[b['path']]['archive_member']).read_text())
        inp = verify_record(row, qualified, reader, contracts, score_binary_task, score_binary_goal)
        initial_states[key] = sha256(canonical(inp['initial_state'])).hexdigest()
        outcome_path = Path(row['outcome']['path'])
        initial = reader.read_json(str(outcome_path.parent / 'initial-input.json'))
        expected = default if row['policy'] == 'Default' else check
        assert initial['messages'][0] == {'role': 'system', 'content': expected}
        assert initial['limits'] == frozen['harness_limits']
        initial_requests[key] = initial
        assert row['identity_contract'] == qualified['source_record']['local_identity_contract']
        for binding in qualified['source_record']['physical_api_receipt_bindings']:
            api = reader.read_json(binding['path'], binding['sha256'])
            model = next(m for m in frozen['models'] if m['key'] == row['model_key'])
            assert api['endpoint'] == model['base_url'] + '/chat/completions'
            assert api['request']['model'] == model['model_id']
            assert api['request']['max_tokens'] == model['generation']['max_new_tokens']
            assert api['request']['messages'][0] == {'role': 'system', 'content': expected}
            if api.get('status') == 'ok':
                assert api['requested_model'] == api['served_model'] == model['model_id']
                assert all(api.get('local_identity', {}).get(k) == v for k, v in row['identity_contract'].items())
        if (i + 1) % 50 == 0:
            print('Verified', i + 1, 'Qwen episodes', flush=True)
    assert len(groups) == 6
    common = next(iter(groups.values()))
    assert len(common) == 89 and all(cases == common for cases in groups.values())
    defaults = lines(package / 'final/leaderboard-default-verdicts.jsonl')
    assert len(defaults) == 356
    assert all(row == index[(row['model_key'], row['policy'], row['condition'], row['case_id'])] and row['policy'] == 'Default' for row in defaults)
    pairs = json.loads((package / 'final/paired-default-check.json').read_text())
    assert len(pairs) == 178
    transitions = Counter()
    for pair in pairs:
        base = pair['model_key'], 'Default', 'injected', pair['case_id']
        check_key = pair['model_key'], 'Check', 'injected', pair['case_id']
        d, c = index[base], index[check_key]
        assert pair['default_record'] == d['qualified_record'] and pair['check_record'] == c['qualified_record']
        assert pair['default_outcome'] == d['outcome'] and pair['check_outcome'] == c['outcome']
        assert pair['default_is_the_same_record_as_leaderboard'] is True
        assert d['case_sha256'] == c['case_sha256'] and d['identity_contract'] == c['identity_contract']
        assert initial_states[base] == initial_states[check_key]
        assert initial_requests[base]['messages'][1:] == initial_requests[check_key]['messages'][1:]
        assert initial_requests[base]['tools'] == initial_requests[check_key]['tools']
        assert initial_requests[base]['limits'] == initial_requests[check_key]['limits']
        for name in ('task_success', 'goal_success', 'joint_success'):
            assert pair['default_' + name] == d[name] and pair['check_' + name] == c[name]
        transitions[('T' if d['joint_success'] else 'F') + ('T' if c['joint_success'] else 'F')] += 1
    summary = json.loads((package / 'final/summary.json').read_text())
    assert summary['publication_ready'] is True
    assert summary['qualified_rows'] == 534 and summary['leaderboard_default_rows'] == 356
    for group in summary['groups']:
        selected = [r for r in verdicts if (r['model_key'], r['policy'], r['condition']) ==
                    (group['model_key'], group['policy'], group['condition'])]
        assert len(selected) == group['evaluated'] == group['scheduled'] == 89
        for label, field in [('task', 'task_success'), ('goal', 'goal_success'), ('joint', 'joint_success')]:
            true_count = sum(r[field] for r in selected)
            assert group[label] == {'T': true_count, 'F': 89 - true_count, 'pending': 0}
        joint = Counter(('T' if r['task_success'] else 'F') + ('T' if r['goal_success'] else 'F') for r in selected)
        assert group['task_goal_states'] == {k: joint[k] for k in ('TT', 'TF', 'FT', 'FF', 'pending')}
    for paired in summary['paired_summary']:
        selected = [p for p in pairs if p['model_key'] == paired['model_key']]
        joint = Counter(('T' if p['default_joint_success'] else 'F') + ('T' if p['check_joint_success'] else 'F') for p in selected)
        assert paired['paired_cases'] == paired['binary_pairs'] == len(selected) == 89
        assert paired['joint_default_check_transitions'] == {k: joint[k] for k in ('TT', 'TF', 'FT', 'FF')}
        assert paired['joint_gain_cases'] == joint['FT'] and paired['joint_loss_cases'] == joint['TF']
        assert paired['net_joint_gain'] == joint['FT'] - joint['TF']
    with (package / 'final/case-verdicts.csv').open() as handle:
        csv_rows = list(csv.DictReader(handle))
    assert len(csv_rows) == 534
    for row in csv_rows:
        selected = index[(row['model_key'], row['policy'], row['condition'], row['case_id'])]
        assert all(row[k] == str(selected[k]) for k in row)
    assert dict(transitions) == {k: v for k, v in summary['pooled_paired_summary']['joint_default_check_transitions'].items() if v}
    displayed = json.loads((package / 'final/current-model-runtime-data.json').read_text())
    assert displayed['publication_ready'] is True and len(displayed['models']) == 2
    for model in displayed['models']:
        for condition, label in [('clean', 'clean'), ('injected', 'challenged')]:
            selected = [r for r in defaults if r['model'] == model['model'] and r['condition'] == condition]
            assert len(selected) == 89
            published = model['runtime'][label]
            assert published['N'] == 89
            tt, gt = sum(r['task_success'] for r in selected), sum(r['goal_success'] for r in selected)
            assert published['task']['T'] == tt and published['task']['F'] == 89 - tt
            assert published['goal']['T'] == gt and published['goal']['F'] == 89 - gt
            joint = Counter(('T' if r['task_success'] else 'F') + ('T' if r['goal_success'] else 'F') for r in selected)
            assert published['joint'] == {k: joint[k] for k in ('TT', 'TF', 'FT', 'FF')}
            for field, count in [('task_rate', tt), ('goal_rate', gt), ('joint_rate', joint['TF'])]:
                assert abs(published[field] - 100 * count / 89) < 1e-10
    report = {'status': 'passed', 'episodes': 534, 'baseline_episodes': 356, 'same_record_default_check_pairs': 178,
              'cases_per_group': 89, 'groups': 6, 'explicit_codex_decisions': sum(bool(r.get('adjudication')) for r in verdicts),
              'pooled_joint_transitions': dict(transitions), 'scorer_reproduction': True,
              'credential_policy': 'Loopback-only raw receipts; no credential headers are published.',
              'new_model_calls': 0, 'new_tool_calls': 0,
              'scope': 'CPU verification of saved JSON evidence, scoring, checkpoint/policy bindings and paired record identity. Opaque native state is hashed, never deserialized; no model weights or native tasks are executed.'}
    report['publication_verification'] = {
        'status': 'passed',
        'public_package_files_verified': len(manifest['files']),
        'source_to_public_file_bindings_verified': len(publication['files']),
        'archive_member_bindings_verified': verified_members,
        'source_to_public_member_bindings': transformed_members,
        'source_to_public_contract_bindings': len(publication['contracts']),
        'frozen_scorer_sources_verified': True,
        'recorded_source_hashes_retained': True,
        'digest_policy': 'Public bytes are SHA-256 verified before the explicit ledger resolves their recorded source identities; original receipt and contract hashes are retained.',
    }
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
