#!/usr/bin/env python3
"""Package completed local Qwen traces and Boolean decisions without credentials."""
import argparse
import ast
import csv
import re
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tarfile

A = Path(__file__).resolve().parent
FORBIDDEN = {'.env', 'legacy_a_cases.py', 'auth.json', 'credentials.json'}
SECRET_PREFIX = re.compile(rb'(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9]{25,}|ghp_[A-Za-z0-9]{20,}|olp_[A-Za-z0-9]{20,})')
C = A.parents[2] / 'SafeSkillbench'
R = A.parents[1]


def bind(path):
    h = sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return {'path': str(path), 'bytes': Path(path).stat().st_size, 'sha256': h.hexdigest()}


def assert_public_file(path):
    """Fail closed; never print possible credential values or mutate raw files."""
    path = Path(path)
    assert path.name not in FORBIDDEN and not path.is_symlink()
    if path.suffix not in {'.xz', '.gz'}:
        with path.open('rb') as handle:
            carry = b''
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                data = carry + block
                assert not SECRET_PREFIX.search(data), 'credential_prefix_requires_review:' + str(path)
                carry = data[-256:]


def portable_code(output):
    code = output / 'code'
    (code / 'www2027').mkdir(parents=True)
    (code / 'www2027/__init__.py').write_text('')
    todo, copied = {'agentdojo_binary_task_v56', 'agentdojo_binary_goal_v56'}, set()
    while todo - copied:
        name = sorted(todo - copied)[0]
        assert name != 'legacy_a_cases'
        path = C / 'www2027' / (name + '.py')
        assert_public_file(path)
        text = path.read_text()
        shutil.copyfile(path, code / 'www2027' / path.name)
        copied.add(name)
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                todo.update([node.module.split('.')[0]] if node.module else [n.name for n in node.names])
    shutil.copyfile(A / 'saved_runtime_inputs_v56.py', code / 'saved_runtime_inputs_v56.py')
    (code / 'replays').mkdir()
    shutil.copyfile(A / 'replays/service_error_rule.py', code / 'replays/service_error_rule.py')
    shutil.copyfile(A / 'verify_qwen_runtime_release_v56.py', output / 'verify_release.py')
    contracts = output / 'source/contracts'
    contracts.mkdir()
    for name in ('agentdojo-next40-normal-utility-contracts.json', 'agentdojo-next51-normal-utility-contracts.json',
                 'agentdojo-next60-target-contracts.json', 'agentdojo-next51-target-contracts.json'):
        shutil.copyfile(R / 'dataset' / name, contracts / name)
    for freeze_name in ('grader-freeze05.json', 'goal-grader-freeze01.json'):
        freeze = json.loads((A / freeze_name).read_text())
        for b in freeze.get('bindings', []) or [freeze['source']]:
            assert bind(b['path'])['sha256'] == b['sha256'], 'frozen_source_changed'


def split_if_large(archive, output):
    descriptor = bind(archive)
    if archive.stat().st_size <= 95 * 1024 * 1024:
        return descriptor
    parts = []
    with archive.open('rb') as source:
        index = 0
        while True:
            block = source.read(90 * 1024 * 1024)
            if not block:
                break
            part = archive.with_name(archive.name + f'.part{index:03d}')
            part.write_bytes(block)
            parts.append(bind(part))
            index += 1
    # The oversized derived archive is kept outside the publication tree.
    # Original experimental evidence is untouched.
    local = output.parent / (output.name + '-local-full-archives')
    local.mkdir(exist_ok=True)
    kept = local / archive.name
    assert not kept.exists()
    archive.rename(kept)
    descriptor.update(public_parts=parts, full_archive_is_local_only=True,
                      local_full_archive_path=str(kept))
    return descriptor


def add_deterministic(tf, path, member):
    # Always store regular bytes, including when source files are hardlinked.
    info = tarfile.TarInfo(member)
    info.size = path.stat().st_size
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    info.mode = 0o644
    with path.open('rb') as handle:
        tf.addfile(info, handle)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--run-root', type=Path, required=True)
    p.add_argument('--qualified-root', type=Path, required=True)
    p.add_argument('--summary-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.run_root = args.run_root.resolve()
    args.qualified_root = args.qualified_root.resolve()
    args.summary_root = args.summary_root.resolve()
    args.output = args.output.resolve()
    summary = json.loads((args.summary_root / 'summary.json').read_text())
    complete = json.loads((args.run_root / 'complete.json').read_text())
    assert summary['publication_ready'] is True and summary['qualified_rows'] == 534
    assert complete['planned'] == complete['terminal'] == 534
    assert bind(summary['source_status']['path']) == summary['source_status']
    independent = json.loads((args.summary_root / 'independent-checks.json').read_text())
    assert independent['status'] == 'passed' and independent['records'] == 534
    protocol = json.loads((args.run_root / 'protocol.json').read_text())
    assert protocol['phase'] == 'full' and protocol['is_ranked_full_cohort'] is True
    allowed_endpoints = {m['base_url'] + '/chat/completions' for m in protocol['frozen_manifest']['models']}
    assert all(s.startswith('http://127.0.0.1:') for s in allowed_endpoints)
    args.output.mkdir(parents=True, exist_ok=False)
    final = args.output / 'final'
    final.mkdir()
    for filename in ('summary.json', 'rows.json', 'case-verdicts.jsonl', 'paired-default-check.json',
                     'independent-checks.json', 'current-model-runtime-data.json', 'seal.json'):
        shutil.copyfile(args.summary_root / filename, final / filename)
    rows = [json.loads(l) for l in (final / 'case-verdicts.jsonl').open()]
    assert len(rows) == 534
    assert all(r['validity'] == 'valid' and all(type(r[k]) is bool for k in
               ('task_success', 'goal_success', 'primary_effect', 'joint_success')) for r in rows)
    defaults = [r for r in rows if r['policy'] == 'Default']
    assert len(defaults) == 356
    assert len({r['job_id'] for r in rows}) == 534
    case_sets = [{r['case_id'] for r in rows if (r['model_key'], r['policy'], r['condition']) == g}
                 for g in {(r['model_key'], r['policy'], r['condition']) for r in rows}]
    assert len(case_sets) == 6 and all(len(x) == 89 and x == case_sets[0] for x in case_sets)
    with (final / 'case-verdicts.csv').open('w', newline='') as handle:
        fields = ['model', 'model_key', 'policy', 'case_id', 'condition', 'task_success', 'goal_success', 'primary_effect', 'joint_success']
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: r[k] for k in fields} for r in rows)
    (final / 'leaderboard-default-verdicts.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in defaults))
    decisions = [r['adjudication'] for r in rows if r.get('adjudication')]
    (final / 'explicit-codex-decisions.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in decisions))
    source = args.output / 'source'
    source.mkdir()
    manifest_dir = Path(protocol['manifest_path']).parent
    # The manifest and historical code snapshots are exact inputs from launch.
    for path in sorted(manifest_dir.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            assert_public_file(path)
            assert path.name not in FORBIDDEN and not path.is_symlink()
            target = source / 'execution-plan' / path.relative_to(manifest_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    for filename in ('grader-freeze05.json', 'goal-grader-freeze01.json', 'binary-grader-protocol.txt',
                     'semantic-adjudication-rubric.txt', 'qualify_qwen_runtime_v56.py',
                     'summarize_qwen_runtime_v56.py', 'saved_runtime_inputs_v56.py',
                     'verify_qwen_final_v56.py', 'package_qwen_runtime_v56.py'):
        shutil.copyfile(A / filename, source / filename)
    shutil.copytree(args.qualified_root / 'source-snapshot', source / 'qualification-source-snapshot', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for key in ('cases', 'schedule', 'system_default', 'check_append_only', 'system_check'):
        b = protocol['frozen_manifest'][key]
        assert bind(b['path'])['sha256'] == b['sha256']
        shutil.copyfile(b['path'], source / (key + Path(b['path']).suffix))
    portable_code(args.output)
    raw_bindings, api_count = [], 0
    raw_groups = {'protocol': [], 'local9b': [], 'local4b': []}
    for path in sorted(args.run_root.rglob('*')):
        if not path.is_file() or path.name.startswith('monitor') or path.suffix == '.tmp':
            continue
        assert not path.is_symlink() and path.name not in FORBIDDEN
        assert_public_file(path)
        if path.name.startswith('api-') and path.suffix == '.json':
            receipt = json.loads(path.read_text())
            assert receipt['endpoint'] in allowed_endpoints
            assert not ({'api_key', 'authorization_header', 'authorization_token', 'access_token',
                         'refresh_token', 'bearer_token', 'request_headers'} & set(receipt))
            for header_field in ('headers', 'response_headers'):
                headers = receipt.get(header_field, {})
                if isinstance(headers, dict):
                    assert not any(k.lower() in {'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key'} for k in headers)
                elif isinstance(headers, list):
                    assert not headers, 'unexpected_local_header_list_requires_review'
            api_count += 1
        b = bind(path)
        b['archive_member'] = 'raw/' + path.relative_to(args.run_root).as_posix()
        parts = path.relative_to(args.run_root).parts
        group = parts[2] if len(parts) > 2 and parts[1] == 'episodes' else 'protocol'
        assert group in raw_groups
        b['archive_group'] = group
        raw_bindings.append(b)
        raw_groups[group].append((path, b))
    raw_archives = []
    for group, members in raw_groups.items():
        temporary = args.output / ('raw-' + group + '.tar.xz')
        with tarfile.open(temporary, 'w:xz', preset=3) as tf:
            for path, b in members:
                add_deterministic(tf, path, b['archive_member'])
                assert bind(path)['sha256'] == b['sha256'], 'closed_raw_input_changed_during_packaging'
        initial = bind(temporary)
        archive = temporary.with_name('raw-' + group + '-' + initial['sha256'][:12] + '.tar.xz')
        temporary.rename(archive)
        descriptor = split_if_large(archive, args.output) | {'group': group, 'members': len(members)}
        raw_archives.append(descriptor)
    (args.output / 'raw-file-manifest.jsonl').write_text(''.join(json.dumps(b, sort_keys=True) + '\n' for b in raw_bindings))
    qualified_archive = args.output / 'qualified-records.tar.xz'
    qualification_bindings = []
    with tarfile.open(qualified_archive, 'w:xz', preset=3) as tf:
        for path in sorted(args.qualified_root.rglob('*')):
            if path.is_file() and path.suffix != '.tmp' and '__pycache__' not in path.parts:
                assert_public_file(path)
                assert path.name not in FORBIDDEN
                b = bind(path)
                b['archive_member'] = 'qualified/' + path.relative_to(args.qualified_root).as_posix()
                qualification_bindings.append(b)
                add_deterministic(tf, path, b['archive_member'])
                assert bind(path)['sha256'] == b['sha256'], 'closed_qualification_changed_during_packaging'
    qualified_descriptor = split_if_large(qualified_archive, args.output)
    (args.output / 'qualified-file-manifest.jsonl').write_text(''.join(json.dumps(b, sort_keys=True) + '\n' for b in qualification_bindings))
    readme = '''This package contains 534 completed Qwen checkpoint/policy episodes: each checkpoint has 89 Default clean episodes, 89 Default challenged episodes, and 89 Check challenged episodes.

final/case-verdicts.jsonl is the Boolean final verdict ledger with exact source and outcome hashes, local checkpoint identity, native invocation binding proof, and explicit Codex-assisted adjudication where used. The adjudications are not human annotations. Original automatic measurements and all actual model responses remain in the qualified and raw archives.

final/leaderboard-default-verdicts.jsonl contains the same 356 Default records used in final/paired-default-check.json. No alternative baseline run or author aggregate is substituted. Pilot episodes are excluded.

The content-addressed raw-local9b/raw-local4b/raw-protocol .tar.xz archives contain every original full-run attempt, including failed attempts, exact prompts/API requests/API responses, policy bindings, outcomes, and native receipts with before/after JSON snapshots and opaque native state. The local endpoints do not use gateway credentials. The protocol is source/execution-plan/manifest.json and source files retain launch-time hashes. If public_parts are listed, concatenate them in order and verify the full archive SHA-256 before extraction; each part is at most 90 MiB.

raw-file-manifest.jsonl and qualified-file-manifest.jsonl map original absolute paths to archive members and SHA-256 hashes. Extract to a fresh directory, resolve recorded paths through these manifests, and verify bytes before replaying scoring. JSON state snapshots support offline scoring; opaque native state is hashed rather than decoded by the verifier. The included code/ dependencies and source/contracts/ support standalone CPU scoring reproduction. Full native task re-execution would additionally require the original benchmark implementation and model weights; the portable verifier executes neither.

Reproduce on CPU: python3 verify_release.py --evidence-root /tmp/skilllife-qwen-evidence --extract --output /tmp/qwen-verification.json
The verifier checks every byte binding, reconstructs receipt-bound task inputs, reruns the exact frozen task/goal scoring, applies explicit trace-bound Codex decisions, and verifies all 178 Default/Check pairs reuse the 356 leaderboard Default records.

The scoring implementation is task v56.5 and goal v56, followed by the bound explicit semantic decision ledger. Default/Check differ only by the exact appended authorization-check instruction block; task, tool schema, initial scenario state, checkpoint, harness, decoding and budgets remain fixed for each paired checkpoint study.
'''
    (args.output / 'README.txt').write_text(readme)
    manifest = {'schema': 'qwen-complete-runtime-replay-artifact/v56', 'status': 'complete_boolean_results',
                'models': ['Qwen3.5-9B', 'Qwen3.5-4B'], 'case_ids_per_condition': 89,
                'episode_verdicts': 534, 'leaderboard_default_verdicts': 356, 'paired_check_cases': 178,
                'explicit_codex_decisions': len(decisions), 'raw_files': len(raw_bindings), 'api_receipts': api_count,
                'all_raw_attempts_preserved': True, 'pilot_included': False,
                'credential_check': 'Loopback local endpoints only; captured API receipts have no authentication header/key fields.',
                'raw_archives': raw_archives, 'qualified_archive': qualified_descriptor,
                'source_summary': bind(args.summary_root / 'summary.json'),
                'files': []}
    for path in sorted(args.output.rglob('*')):
        if path.is_file():
            assert_public_file(path)
            assert path.stat().st_size < 100000000, 'publication_blob_too_large:' + str(path)
            manifest['files'].append(bind(path) | {'relative_path': path.relative_to(args.output).as_posix()})
    (args.output / 'artifact-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Packaged534Booleanepisodes,356sharedDefaultrecords,178pairs; rawAPIreceipts', api_count)


if __name__ == '__main__':
    main()
