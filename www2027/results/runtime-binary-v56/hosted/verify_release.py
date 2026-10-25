#!/usr/bin/env python3
"""Offline verification; performs no model requests or native task executions."""
from pathlib import Path
from collections import Counter,defaultdict
import argparse,base64,hashlib,importlib.util,json,sys,tarfile,types
ROOT=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def canon(x):return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def rows(p):return [json.loads(l) for l in p.open()]
def measurement_view(x,key=''):
 if isinstance(x,dict):return {k:measurement_view(v,k) for k,v in x.items()}
 if isinstance(x,list):
  values=[measurement_view(v) for v in x]
  return sorted(values,key=lambda v:v['fact_id']) if key=='facts' else values
 return x
def measurement_equal(a,b):
 return measurement_view(json.loads(json.dumps(a,default=str)))==measurement_view(b)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--evidence-root',type=Path,required=True);ap.add_argument('--extract',action='store_true');ap.add_argument('--output',type=Path);args=ap.parse_args()
 if args.extract:
  args.evidence_root.mkdir(parents=True,exist_ok=True)
  for bundle in sorted((ROOT/'bundles').glob('*.tar.xz')):
   with tarfile.open(bundle) as tar:tar.extractall(args.evidence_root,filter='data')
 manifest=json.loads((ROOT/'manifest.json').read_text())
 for f in manifest['files']:
  b=(ROOT/f['path']).read_bytes();assert len(b)==f['bytes'] and sha(b)==f['sha256'],f['path']
 sys.path.insert(0,str(ROOT/'code'))
 contracts=json.loads((ROOT/'data/contracts.json').read_text())
 # Alias-only provenance edits change canonical contract bytes, not their
 # original identity. Authenticate each published body before restoring its
 # recorded original digest for the frozen contract validators.
 contract_bindings=json.loads((ROOT/'protocol/publication-contract-bindings.json').read_text())
 original_contract_digests={}
 for binding in contract_bindings['bindings']:
  value=contracts
  for part in binding['pointer']:value=value[part]
  if isinstance(value,dict):value={k:v for k,v in value.items() if k!=binding['excluded_hash_field']}
  actual=sha(canon(value));assert actual==binding['publication_sha256']
  if actual in original_contract_digests:assert original_contract_digests[actual]==binding['original_sha256']
  original_contract_digests[actual]=binding['original_sha256']
 def bind_digest(fn):
  def digest(value):
   result=fn(value);return original_contract_digests.get(result,result)
  return digest
 # Install only on canonical-digest helpers, before scorer functions clone
 # their globals. Any unlisted or changed contract still fails validation.
 for name in ['agentdojo_next40_normal_utility','agentdojo_candidate_utility','agentdojo_next60_target_measurements','agentdojo_next51_target_measurements','agentdojo_banking_record_measurements']:
  dependency=__import__('www2027.'+name,fromlist=['digest'])
  if hasattr(dependency,'digest'):dependency.digest=bind_digest(dependency.digest)
 from www2027.agentdojo_binary_task_v56 import score_binary_task
 from www2027.agentdojo_binary_goal_v56 import score_binary_goal
 verdicts=rows(ROOT/'data/runtime-case-verdicts.jsonl');vmap={(r['model'],r['case_id'],r['condition']):r for r in verdicts}
 assert len(vmap)==len(verdicts)==2136
 case_sets=[{r['case_id'] for r in verdicts if r['model']==m and r['condition']==c} for m in {r['model'] for r in verdicts} for c in ['clean','injected']]
 assert all(len(x)==89 and x==case_sets[0] for x in case_sets)
 reviews={r['sha256']:r for r in rows(ROOT/'protocol/adjudication-inputs.jsonl')}
 emissions={r['sha256']:r for r in rows(ROOT/'protocol/adjudication-emissions.jsonl')}
 totals=Counter();summary=defaultdict(Counter)
 for model in sorted({r['model'] for r in verdicts}):
  d=args.evidence_root/model
  ledger={r['original_path']:r for r in rows(d/'file-map.jsonl')}
  verified={}
  for p,r in ledger.items():
   b=(d/r['publication_path']).read_bytes();assert len(b)==r['publication_bytes'] and sha(b)==r['publication_sha256']
   transformations=r.get('transformations',[] if r['transform']=='verbatim' else [r['transform']])
   if r['transform']=='verbatim':assert sha(b)==r['original_sha256'] and not transformations
   else:
    assert transformations and set(transformations)<=set(['credential_header_removal','session_field_removal','path_aliasing','binary_content_omission'])
    if 'credential_header_removal' in transformations:assert r['removed_header_fields']
    if 'session_field_removal' in transformations:assert any(x['kind']=='session_field_removal' for x in r['publication_changes'])
    if 'path_aliasing' in transformations:assert r.get('path_fields_aliased') or any(x['kind']=='path_aliasing' for x in r.get('publication_changes',[]))
    if 'binary_content_omission' in transformations:
     omitted=json.loads(b);assert omitted['schema']=='omitted-nongrading-binary/v1' and omitted['original_sha256']==r['original_sha256']
   verified[p]=b;totals['file_path_bindings']+=1
   totals['credential_header_publication_copies']+='credential_header_removal' in transformations
   totals['session_field_publication_copies']+='session_field_removal' in transformations
   totals['path_aliased_publication_copies']+='path_aliasing' in transformations
   totals['omitted_nongrading_binary_files']+='binary_content_omission' in transformations
  # The reader is identical except its physical API digest check accepts the
  # explicit raw->published binding after publication bytes were verified.
  # Removed transport/session fields cannot be cryptographically reconstructed.
  # Native JSON states, receipts, outputs and scoring content are retained;
  # publication ledgers separate original source identity from public bytes.
  source=(ROOT/'code/saved_runtime_inputs_v56.py').read_text()
  assert source.count('actual_digest = sha256(data).hexdigest()')==1
  source=source.replace('actual_digest = sha256(data).hexdigest()','actual_digest = publication_original_digest(str(path), data)')
  module=types.ModuleType('portable_saved_inputs');module.__file__=str(ROOT/'code/saved_runtime_inputs_v56.py');exec(compile(source,module.__file__,'exec'),module.__dict__)
  class PublishedPath:
   def __init__(self,p):self.p=str(p)
   def __str__(self):return self.p
   def read_bytes(self):return verified[self.p]
   @property
   def parent(self):return PublishedPath(str(Path(self.p).parent))
   def glob(self,pattern):
    import fnmatch
    return [PublishedPath(p) for p in ledger if str(Path(p).parent)==self.p and fnmatch.fnmatch(Path(p).name,pattern)]
   def __lt__(self,o):return self.p<o.p
  def original_digest(path,data):
   r=ledger[path];assert sha(data)==r['publication_sha256'];return r['original_sha256']
  def read_json(path,expected=None):
   p=str(path);r=ledger[p]
   if expected is not None:assert r['original_sha256']==expected
   return json.loads(verified[p])
  module.Path=PublishedPath;module.read_json=read_json;module.publication_original_digest=original_digest
  sources=rows(d/'source-records.jsonl');inputs=rows(d/'grading-inputs.jsonl');candidates=rows(d/'candidate-records.jsonl')
  assert len(inputs)==len(sources)==len(candidates)==178
  for s,inp,c in zip(sources,inputs,candidates):
   v=vmap[(model,inp['case_id'],inp['condition'])]
   line=base64.b64decode(s['source_line_base64']);assert sha(line)==s.get('publication_source_line_sha256',s['source_line_sha256']) and json.loads(line)==s['source_record']
   assert s['source_line_sha256']==c['effective_source_record']['sha256']==inp['source_record_sha256']
   raw=json.loads(line)
   assert raw['job_id']==c['job_id'] and raw['audit_phase']==c['phase_id'] and c['model']==model
   assert raw['case_id']==inp['case_id'] and raw['condition']==inp['condition']
   assert raw['outcome_sha256']==v['outcome']['sha256']==inp['outcome_sha256']
   restored=module.load_inputs(raw,{'scheduled_row':s['selected_identity']});assert restored['validity']=='valid'
   for key in ['initial_state','final_state','final_answer','observations','transitions','user_visible_outputs','prior_measurement','evidence_valid','binding_proof']:
    assert restored[key]==inp[key],(model,inp['case_id'],key)
   # Score reconstructed original objects, retaining native dictionary order.
   inp={**inp,**restored}
   group=inp['source_group'];contract=contracts[group]['task'][inp['case_id']]
   task=score_binary_task(group,contract,inp['initial_state'],inp['final_state'],inp['final_answer'],inp['observations'],evidence_valid=True,prior_measurement=inp['prior_measurement'])
   assert measurement_equal(task,c['task_measurement']),(model,inp['case_id'],'automatic_task_reproducibility')
   tv=task['task_success']
   if v['adjudication']:
    a=v['adjudication'];assert a['not_human_annotation'] is True
    assert a['outcome_sha256']==v['outcome']['sha256']
    assert a['final_answer_sha256']==sha((inp['final_answer'] or '').encode())
    rr=reviews[a['review_source_row_sha256']];assert sha(canon(rr['record']))==rr.get('publication_record_sha256',rr['sha256'])
    em=emissions[a['actual_emissions_sha256']];assert sha(canon(em['record']))==em.get('publication_record_sha256',em['sha256'])
    assert em['record']['outcome_sha256']==a['outcome_sha256']
    tv=a['decision']['task_success'];assert all(x['task_success']==tv for x in a['all_decisions'])
    totals['codex_semantic_reviews']+=1
   goal=score_binary_goal(group,contracts[group]['goal'][inp['case_id']+'|'+inp['condition']],inp['initial_state'],inp['transitions'],final_answer=inp['final_answer'] or '',user_visible_outputs=inp['user_visible_outputs'],evidence_valid=True)
   assert measurement_equal(goal,c['goal_measurement']),(model,inp['case_id'],'goal_reproducibility')
   assert type(tv) is bool and tv==v['task_success']
   assert goal['goal_success']==v['goal_success'] and goal['primary_effect']==v['primary_effect']
   assert v['joint_success']==(tv and not v['goal_success'])
   totals['boolean_records']+=1
   condition=inp['condition'];summary[(model,condition)]['N']+=1
   summary[(model,condition)]['task_T']+=tv;summary[(model,condition)]['goal_T']+=v['goal_success'];summary[(model,condition)]['joint_T']+=v['joint_success']
  print('VERIFIED',model,flush=True)
 assert totals['boolean_records']==2136
 assert all(s['N']==89 for s in summary.values()) and len(summary)==24
 report={'status':'passed','scope':'12 hosted models; 89 cases in both clean and challenged conditions; local Qwen is a separate package','totals':dict(totals),'model_conditions':[dict(model=k[0],condition=k[1],**v) for k,v in sorted(summary.items())],'redaction_note':'Publication copies omit credential headers and opaque session fields, alias private experiment paths, and explicitly bind original source identities to published bytes. Removed bytes cannot be reconstructed. All scoring-bearing JSON evidence is retained.','reviews':'Model-blinded Codex-assisted semantic adjudication; not human annotations.'}
 if args.output:args.output.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(dict(totals),sort_keys=True))
if __name__=='__main__':main()
