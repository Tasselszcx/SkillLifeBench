"""Read and authenticate saved JSON inputs for pure v56 rescoring."""
from copy import deepcopy
from hashlib import sha256
import json
import importlib.util
from pathlib import Path

INFRA_STOPS = {'api_error', 'gateway_label_mismatch'}
MODEL_STOPS = {'completed', 'model_output_truncated', 'invalid_tool_call',
               'round_limit', 'tool_step_limit', 'model_refusal',
               'model_tool_format_error', 'wall_limit', 'invalid_final_message',
               'model_context_limit', 'model_output_incomplete'}
_signature_path = Path(__file__).resolve().parent / 'replays/service_error_rule.py'
_signature_spec = importlib.util.spec_from_file_location('v56_exact_service_signatures', _signature_path)
_signatures = importlib.util.module_from_spec(_signature_spec)
_signature_spec.loader.exec_module(_signatures)


def read_json(path, expected=None):
    raw = Path(path).read_bytes()
    if expected is not None and sha256(raw).hexdigest() != expected:
        raise ValueError('saved_checksum_mismatch:' + str(path))
    return json.loads(raw)


def snapshot(row, side):
    b = row['verified_snapshots'][side]
    return read_json(b['json_path'], b['json_sha256'])


def load_inputs(raw, selected):
    """Return actual state transitions and task observations, with binding proof.

    Old evidence_complete mixed termination and evaluator coverage. This reader
    instead checks the saved receipt chain, events, snapshots and final output.
    It never grants validity to an API/serving failure.
    """
    outcome = read_json(raw['outcome_path'], raw['outcome_sha256'])
    receipts = sorted(raw['receipt_measurements'], key=lambda x: x['sequence'])
    issues = []
    recovered = []
    events = []
    transitions = []
    proof = []
    initial = None
    final = None
    previous_hash = None
    previous_state = None
    score_answer = None
    service_signatures = []
    physical = {x['path']: x['sha256'] for x in raw.get('physical_api_receipt_bindings', [])}
    for path in sorted(Path(raw['outcome_path']).parent.glob('api-*.json')):
        data = path.read_bytes()
        actual_digest = sha256(data).hexdigest()
        if str(path) in physical and actual_digest != physical[str(path)]:
            raise ValueError('saved_api_checksum_mismatch:' + str(path))
        signature = (None if raw.get('model_identity_kind') == 'pinned_local_checkpoint_and_pid'
                     else _signatures.classify(json.loads(data)))
        if signature:
            service_signatures.append({'signature': signature, 'path': str(path), 'sha256': actual_digest})
    for index, row in enumerate(receipts):
        r = read_json(row['receipt_path'], row['receipt_sha256'])
        request = r['request']
        worker = r['worker_result']
        checks = {
            'sequence': row['sequence'] == request['sequence'] == index,
            'operation': row['operation'] == request['operation'] == worker['operation'],
            'case': row['candidate_id'] == worker['candidate_id'] == raw['case_id'],
            'condition': row['condition'] == request['condition'] == worker['condition'] == raw['condition'],
            'parent': request.get('parent_receipt_sha256') == previous_hash,
            'state_integrity': row.get('state_integrity_verified') is True,
            'invocation_binding': row.get('invocation_source_binding_verified') is True,
            'lineage': row.get('lineage_verified') is True,
            'no_identity_issue': not row.get('identity_issues'),
            'no_receipt_issue': not row.get('issues'),
        }
        before = snapshot(row, 'before')
        after = snapshot(row, 'after')
        if index == 0:
            checks['initial_operation'] = request['operation'] == 'initialize'
            initial = before
        else:
            checks['state_continuity'] = before == previous_state
        failed = [k for k, v in checks.items() if not v]
        if failed:
            issues.append({'receipt': row['receipt_path'], 'failed': failed})
        operation = request['operation']
        if operation == 'step':
            tool = worker['tool_outcome']
            entry = row.get('actual_entry_arguments')
            # Source-verified rows sometimes store this only in the native tool
            # record, notably a rejected/no-entry invocation.
            if entry is None:
                entry = tool.get('normalized_before_execution')
            callee_entered = bool(tool.get('original_tool_invocations'))
            event = {'sequence': request['sequence'], 'tool_name': request['tool_name'],
                     'effective_arguments': deepcopy(entry) if isinstance(entry, dict) else {},
                     'callee_entered': callee_entered, 'error': tool.get('error'),
                     'returned_text': tool.get('text'), 'format_error': tool.get('format_error'),
                     'receipt_sha256': row['receipt_sha256'], 'before_state': before, 'after_state': after}
            events.append(event)
            transitions.append({'before_state': before, 'after_state': after,
                                'tool_name': request['tool_name'],
                                'effective_arguments': event['effective_arguments'],
                                'tool_error': tool.get('error'), 'callee_entered': callee_entered,
                                'receipt_sha256': row['receipt_sha256']})
            if (raw['source_group'] == 'agentdojo_next40'
                    and request['tool_name'] == 'get_unread_emails'
                    and row.get('source_contract_sha256') is None
                    and row.get('family_contract_sha256') is None and not failed):
                recovered.append({'sequence': index, 'receipt_sha256': row['receipt_sha256'],
                                  'reason': 'Derived target-check fields were absent; raw case, condition, receipt chain, native state and invocation binding are verified.'})
        elif operation == 'score':
            score_answer = request.get('final_output')
            checks['terminal_score'] = index == len(receipts) - 1
            if not checks['terminal_score']:
                issues.append({'receipt': row['receipt_path'], 'failed': ['terminal_score']})
        proof.append({'receipt_sha256': row['receipt_sha256'], 'sequence': index, 'checks': checks})
        previous_hash = row['receipt_sha256']
        previous_state = after
        final = after
    if not receipts:
        issues.append({'failed': ['no_receipts']})
    out_events = outcome.get('events', [])
    if len(out_events) != len(events):
        issues.append({'failed': ['event_count'], 'outcome': len(out_events), 'receipts': len(events)})
    for index, (out_event, event) in enumerate(zip(out_events, events)):
        if (out_event.get('name') != event['tool_name']
                or out_event.get('runtime_receipt', {}).get('receipt_sha256') != event['receipt_sha256']):
            issues.append({'event': index, 'failed': ['event_receipt_binding']})
    if receipts and receipts[-1]['operation'] != 'score':
        issues.append({'failed': ['missing_terminal_score']})
    # The controller stores a missing final answer as null in outcome.json and
    # passes an empty string to its terminal source-score receipt.
    if (score_answer or '') != (outcome.get('final_output') or ''):
        issues.append({'failed': ['final_answer_binding']})
    source = raw.get('source_measurements', {})
    archived = source.get('authenticated_model_observations')
    # Preserve the authenticated original source timeline if available. For
    # next40, its analyzer's event schema is reconstructed from the same native
    # receipts, with all fields tied to immutable files above.
    if archived:
        observations = deepcopy(archived)
        observations['coverage'] = 'complete' if not issues else 'partial'
    else:
        # The next40 archive predates the cross-modal observation projection.
        # Reconstruct exactly the controller order from its accepted assistant
        # messages and receipt-bound native events; never expose reasoning.
        messages, ordered_events, timeline = [], [], []
        by_receipt = {x['receipt_sha256']: x for x in events}
        position = 0
        for turn in sorted(outcome.get('model_turns', []), key=lambda x: x['model_round']):
            rid, message = turn['model_round'], turn['message']
            content = message.get('content')
            if content is not None:
                if not isinstance(content, str):
                    issues.append({'failed': ['nontext_assistant_content']})
                else:
                    messages.append({'sequence': position, 'model_round': rid,
                                     'content': content, 'origin': 'bound_controller_assistant_content',
                                     'before_same_response_native_batch': True,
                                     'ui_delivery_or_cognitive_use_inferred': False})
            timeline.append({'kind': 'assistant_response', 'sequence': position, 'model_round': rid})
            position += 1
            for native in sorted((e for e in out_events if e['model_round'] == rid), key=lambda e: e['tool_call_index']):
                event = deepcopy(by_receipt[native['runtime_receipt']['receipt_sha256']])
                event.update(native_sequence=event['sequence'], sequence=position,
                             model_round=rid, tool_call_index=native['tool_call_index'],
                             tool_call_id=native['tool_call_id'])
                ordered_events.append(event)
                timeline.append({'kind': 'native_tool', 'sequence': position, 'model_round': rid,
                                 'receipt_sha256': event['receipt_sha256']})
                position += 1
        if len(ordered_events) != len(events):
            issues.append({'failed': ['unassigned_native_event']})
        observations = {'coverage': 'complete' if not issues else 'partial', 'tool_events': ordered_events,
                        'assistant_messages': messages, 'timeline': timeline,
                        'sequence_basis': 'Bound controller assistant.content before calls in its response; no reasoning fields.'}
    stop = outcome.get('stop_reason')
    terminal_classification = raw.get('qualified_terminal_classification')
    if terminal_classification:
        assert terminal_classification.get('source_classification_verified') is True
        classification = read_json(terminal_classification['path'], terminal_classification['sha256'])
        assert classification['raw_stop_reason'] == stop
        stop = classification['derived_stop_reason']
    selected_identity = selected['scheduled_row']
    model_qualified = selected_identity.get('model_observation_qualified',
                                            selected_identity.get('gateway_observation_qualified')) is True
    if stop in INFRA_STOPS or service_signatures:
        validity = 'invalid_infrastructure'
    elif stop not in MODEL_STOPS:
        validity = 'review_required_stop_reason'
    elif issues:
        validity = 'invalid_evidence_binding'
    elif not model_qualified:
        validity = 'invalid_model_identity_binding'
    else:
        validity = 'valid'
    # Match the frozen model analyzer's _output_values projection exactly.
    outputs = [{'user_visible': True, 'text': x['content'], 'sequence': x['sequence'],
                'model_round': x['model_round'], 'origin': x['origin']}
               for x in observations.get('assistant_messages', [])]
    answer = outcome.get('final_output')
    prior = source.get('normal') or source.get('normal_measurement_versions', {}).get('amendment02')
    return {'initial_state': initial, 'final_state': final, 'final_answer': answer,
            'observations': observations, 'transitions': transitions, 'user_visible_outputs': outputs,
            'prior_measurement': prior, 'outcome': outcome,
            'validity': validity, 'evidence_valid': validity == 'valid',
            'binding_proof': {'issues': issues, 'receipts': proof, 'recovered_derived_omissions': recovered,
                              'gateway_observation_qualified': model_qualified,
                              'model_identity_kind': raw.get('model_identity_kind', 'gateway_route_and_literal_label'),
                              'terminal_classification': terminal_classification,
                              'service_error_signatures': service_signatures}}
