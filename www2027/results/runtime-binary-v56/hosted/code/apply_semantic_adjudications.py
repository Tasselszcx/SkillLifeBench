#!/usr/bin/env python3
"""Apply explicit, model-blinded Codex semantic adjudications to exact traces."""
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path

A = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def binding(path):
    raw = Path(path).read_bytes()
    return {'path': str(path), 'sha256': sha256(raw).hexdigest(), 'bytes': len(raw)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--review', action='append', default=[])
    args = ap.parse_args()
    args.output.mkdir(exist_ok=False)
    original_keys = json.loads((A / 'offline-run02/review-key-map.json').read_text())
    original_rows = {json.loads(line)['review_id']: json.loads(line)
                     for line in (A / 'offline-run02/anonymous-review.jsonl').open()}
    original_emissions = {json.loads(line)['review_id']: json.loads(line)
                          for line in (A / 'offline-run02/anonymous-assistant-emissions.jsonl').open()}
    # A generic grader repair may resolve a row that was reviewed in a prior
    # pass. Keep the exact prior row/key binding even if it leaves the queue.
    for path in sorted(A.glob('offline-run*/review-key-map.json')):
        for key, value in json.loads(path.read_text()).items():
            original_keys.setdefault(key, value)
        review_path = path.parent / 'anonymous-review.jsonl'
        for line in review_path.open():
            value = json.loads(line)
            original_rows.setdefault(value['review_id'], value)
    current_keys = json.loads((args.input / 'review-key-map.json').read_text())
    current_reviews = {json.loads(line)['review_id']: json.loads(line)
                       for line in (args.input / 'anonymous-review.jsonl').open()}
    input_rows = [json.loads(line) for line in (args.input / 'candidate-records.jsonl').open()]
    input_by_key = {(row['phase_id'], row['job_id']): row for row in input_rows}
    decisions = defaultdict(list)
    source_bindings = []
    enriched = defaultdict(list)
    for path in (A / 'offline-run02/review-entity_facts.jsonl',
                 A / 'offline-run02/review-actions_only.jsonl', A / 'root-entity-pending01.json',
                 args.input / 'anonymous-review.jsonl'):
        if path.exists():
            values = ([json.loads(line) for line in path.open()] if path.suffix == '.jsonl'
                      else json.loads(path.read_text()))
            for value in values:
                enriched[value['review_id']].append(sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest())
    for filename in args.review:
        path = Path(filename)
        source_bindings.append(binding(path))
        rows = ([json.loads(line) for line in path.open()] if path.suffix == '.jsonl'
                else json.loads(path.read_text()))
        for row in rows:
            if type(row.get('task_success')) is bool:
                decisions[row['review_id']].append(row | {'adjudication_source': str(path)})
    by_key = {}
    for opaque, ds in decisions.items():
        assert len({x['task_success'] for x in ds}) == 1, 'conflicting_adjudications:' + opaque
        assert (opaque in original_keys and opaque in original_rows) or (opaque in current_keys and opaque in current_reviews)
        d = ds[-1]
        source = original_rows.get(opaque) or current_reviews[opaque]
        keys = original_keys.get(opaque) or current_keys[opaque]
        key = keys['phase_id'], keys['job_id']
        if opaque in original_emissions:
            emissions = original_emissions[opaque]
        else:
            effective = input_by_key[key].get('effective_outcome', input_by_key[key]['original_outcome'])
            outcome = json.loads(Path(effective['path']).read_text())
            assert binding(effective['path'])['sha256'] == effective['sha256']
            emissions = {'outcome_sha256': effective['sha256'],
                         'assistant_messages': [{'model_round': t['model_round'],
                                                 'content': t['message'].get('content')}
                                                for t in outcome.get('model_turns', [])]}
        expected_answer = sha256((source['final_answer'] or '').encode()).hexdigest()
        expected_answer_json = sha256(json.dumps(source['final_answer'], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        assert all(x['final_answer_sha256'] in (expected_answer, expected_answer_json) for x in ds), 'review_answer_binding_mismatch:' + opaque
        for item in ds:
            if item.get('review_record_sha256'):
                assert (item['review_record_sha256'] in enriched[opaque]
                        or item.get('outcome_sha256') == emissions['outcome_sha256']), 'enriched_review_binding_mismatch:' + opaque
        if d.get('outcome_sha256'):
            assert d['outcome_sha256'] == emissions['outcome_sha256']
        by_key[key + (emissions['outcome_sha256'],)] = {'decision': d, 'all_decisions': ds, 'review_id': opaque,
                       'outcome_sha256': emissions['outcome_sha256'], 'final_answer_sha256': expected_answer,
                       'review_source_row_sha256': sha256(canonical(source)).hexdigest(),
                       'actual_emissions_sha256': sha256(canonical(emissions)).hexdigest()}
    applied, skipped, pending, candidate_rows = [], [], [], []
    summaries = defaultdict(lambda: {'N': 0, 'validity': Counter(), 'task': Counter(), 'goal': Counter(), 'joint': Counter()})
    for row in input_rows:
        key = row['phase_id'], row['job_id']
        accepted = False
        effective = row.get('effective_outcome', row['original_outcome'])
        decision = by_key.get(key + (effective['sha256'],))
        if decision:
            if row['validity'] != 'valid':
                skipped.append({'key': key, 'reason': 'invalid_execution_cannot_be_adjudicated'})
            elif decision['outcome_sha256'] != effective['sha256']:
                skipped.append({'key': key, 'reason': 'new_execution_requires_separate_adjudication'})
            else:
                raw = Path(effective['path']).read_bytes()
                assert sha256(raw).hexdigest() == effective['sha256']
                outcome = json.loads(raw)
                assert sha256((outcome.get('final_output') or '').encode()).hexdigest() == decision['final_answer_sha256']
                contract = decision['decision'].get('source_contract_sha256')
                if contract:
                    assert contract == row['task_measurement']['source_contract_sha256']
                row['automatic_task'] = row['new_task']
                row['new_task'] = 'T' if decision['decision']['task_success'] else 'F'
                row['semantic_adjudication'] = decision | {
                    'method': 'Codex-assisted semantic review with model identity hidden; exact saved trace binding',
                    'not_human_annotation': True}
                applied.append({'key': key, 'review_id': decision['review_id'],
                                'automatic': row['automatic_task'], 'adjudicated': row['new_task']})
                accepted = True
        reasons = []
        if row['validity'] == 'valid':
            if row['new_task'] is None:
                reasons.append('semantic_verdict_pending')
            if (not accepted and row['old']['task'] in ('T', 'F')
                    and row['new_task'] in ('T', 'F') and row['old']['task'] != row['new_task']):
                reasons.append('unreviewed_binary_flip')
        if reasons:
            opaque = sha256(('v56-review:' + key[0] + ':' + key[1]).encode()).hexdigest()[:20]
            if row.get('replacement'):
                opaque += '-r' + effective['sha256'][:8]
            review = current_reviews.get(opaque)
            pending.append({'review_id': opaque, 'reasons': reasons, 'review_record': review,
                            'effective_outcome_sha256': effective['sha256']})
        summary = summaries[row['model'], row['condition']]
        summary['N'] += 1
        summary['validity'][row['validity']] += 1
        summary['task'][row['new_task'] or 'pending'] += 1
        summary['goal'][row['new_goal'] or 'pending'] += 1
        summary['joint'][(row['new_task'] + row['new_goal']) if row['new_task'] and row['new_goal'] else 'pending'] += 1
        candidate_rows.append(row)
    (args.output / 'candidate-records.jsonl').write_text(''.join(json.dumps(r, sort_keys=True, ensure_ascii=False) + '\n' for r in candidate_rows))
    (args.output / 'remaining-review.jsonl').write_text(''.join(json.dumps(r, sort_keys=True, ensure_ascii=False) + '\n' for r in pending))
    summary = {'schema': 'explicit-semantic-adjudication-overlay/v56', 'candidate_only': True,
               'source': binding(args.input / 'candidate-records.jsonl'), 'adjudication_sources': source_bindings,
               'applied': applied, 'skipped': skipped, 'remaining_review_count': len(pending),
               'model_condition_summaries': [dict(model=k[0], condition=k[1], **v) for k, v in sorted(summaries.items())],
               'original_data_changed': False, 'models_used_to_select_adjudications': False}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('adjudications', len(applied), 'skipped', len(skipped), 'remaining', len(pending))


if __name__ == '__main__':
    main()
