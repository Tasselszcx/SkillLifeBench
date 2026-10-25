"""Schema-aware native Qwen XML parsing for the separate 32k profile.

String-only fields retain the original raw-string behavior. In nullable unions,
the exact native/JSON literals None and null are reserved for a null value.
Other unions are decoded branch by branch; different valid typed values are an
error. JSON objects/arrays are parsed, never evaluated or repaired. Local $defs
references are supported; remote references and unimplemented constraints fail.
"""
from __future__ import annotations

import json
import math
import re
from .local_client import ToolParseError

TYPES={'string','integer','number','boolean','object','array','null'}
ANNOTATIONS={'title','description','default'}
KEYWORDS={'type','anyOf','enum','properties','required','additionalProperties','items','$defs','$ref'} | ANNOTATIONS


class AmbiguousToolParseError(ToolParseError):
    """An ambiguous inner union must not disappear behind a valid outer branch."""


def _equal(left,right):
    if type(left) is not type(right):return False
    if isinstance(left,dict):return left.keys()==right.keys() and all(_equal(left[k],right[k]) for k in left)
    if isinstance(left,list):return len(left)==len(right) and all(_equal(a,b) for a,b in zip(left,right))
    return left==right


def _enum_equal(left,right):
    if type(left) in (int,float) and type(right) in (int,float):return left==right
    return _equal(left,right)


def _finite_json(value):
    if isinstance(value,float) and not math.isfinite(value):raise ToolParseError('Nonfinite JSON number')
    if isinstance(value,dict):
        for child in value.values():_finite_json(child)
    elif isinstance(value,list):
        for child in value:_finite_json(child)


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ToolParseError('Duplicate JSON object key')
        result[key]=value
    return result


def _json(raw):
    def reject(value):raise ToolParseError('Nonfinite JSON literal')
    try:value=json.loads(raw,object_pairs_hook=_pairs,parse_constant=reject)
    except ToolParseError:raise
    except ValueError as error:raise ToolParseError('Non-JSON scalar/object parameter') from error
    _finite_json(value)
    return value


def _resolve(schema,root,seen=()):
    if not isinstance(schema,dict) or '$ref' not in schema:return schema
    reference=schema['$ref']
    if not isinstance(reference,str) or not reference.startswith('#/$defs/'):
        raise ToolParseError('Only local #/$defs references are supported')
    if reference in seen:raise ToolParseError('Cyclic schema reference')
    if set(schema)-{'$ref','$defs'}-ANNOTATIONS:raise ToolParseError('Unsupported constraint alongside $ref')
    current=root
    for raw_part in reference[2:].split('/'):
        part=raw_part.replace('~1','/').replace('~0','~')
        if not isinstance(current,dict) or part not in current:raise ToolParseError('Unresolved local schema reference')
        current=current[part]
    return _resolve(current,root,seen+(reference,))


def check_schema(schema,root=None,depth=0):
    """Validate the supported schema subset without changing the source schema."""
    root=schema if root is None else root
    if depth>32:raise ToolParseError('Schema nesting exceeds bound')
    if type(schema) is bool:return
    if not isinstance(schema,dict):raise ToolParseError('Schema must be an object or boolean')
    unknown=set(schema)-KEYWORDS
    if unknown:raise ToolParseError('Unsupported schema keywords: '+','.join(sorted(unknown)))
    if '$ref' in schema:
        check_schema(_resolve(schema,root),root,depth+1);return
    if 'type' in schema and (not isinstance(schema['type'],str) or schema['type'] not in TYPES):
        raise ToolParseError('Unsupported schema type')
    if 'anyOf' in schema:
        if not isinstance(schema['anyOf'],list) or not schema['anyOf']:raise ToolParseError('Empty or invalid anyOf')
        for branch in schema['anyOf']:check_schema(branch,root,depth+1)
    if 'enum' in schema:
        if not isinstance(schema['enum'],list) or not schema['enum']:raise ToolParseError('Empty or invalid enum')
        _finite_json(schema['enum'])
    if 'properties' in schema:
        if not isinstance(schema['properties'],dict):raise ToolParseError('Invalid properties declaration')
        for child in schema['properties'].values():check_schema(child,root,depth+1)
    if 'required' in schema:
        required=schema['required']
        if not isinstance(required,list) or any(not isinstance(x,str) for x in required) or len(set(required))!=len(required):
            raise ToolParseError('Invalid required declaration')
    for key in ['items','additionalProperties']:
        if key in schema:check_schema(schema[key],root,depth+1)
    if '$defs' in schema:
        if not isinstance(schema['$defs'],dict):raise ToolParseError('Invalid $defs declaration')
        for child in schema['$defs'].values():check_schema(child,root,depth+1)


def _validate(value,schema,root,depth=0):
    if depth>32:raise ToolParseError('Value nesting exceeds bound')
    schema=_resolve(schema,root)
    if schema is True:return
    if schema is False:raise ToolParseError('Value rejected by false schema')
    if 'anyOf' in schema:
        matched=False
        for branch in schema['anyOf']:
            try:_validate(value,branch,root,depth+1);matched=True;break
            except ToolParseError:pass
        if not matched:raise ToolParseError('Parameter matches no anyOf branch')
    kind=schema.get('type')
    if kind:
        correct=(kind=='string' and type(value) is str or kind=='integer' and type(value) is int or
                 kind=='number' and type(value) in (int,float) or kind=='boolean' and type(value) is bool or
                 kind=='object' and type(value) is dict or kind=='array' and type(value) is list or
                 kind=='null' and value is None)
        if not correct:raise ToolParseError('Parameter type mismatch')
    if 'enum' in schema and not any(_enum_equal(value,item) for item in schema['enum']):
        raise ToolParseError('Parameter outside enum')
    if isinstance(value,dict):
        properties=schema.get('properties',{})
        if not set(schema.get('required',[])).issubset(value):raise ToolParseError('Missing required object field')
        additional=schema.get('additionalProperties',True)
        for key,child in value.items():
            if key in properties:_validate(child,properties[key],root,depth+1)
            elif additional is False:raise ToolParseError('Unknown object field')
            elif isinstance(additional,dict):_validate(child,additional,root,depth+1)
    if isinstance(value,list) and 'items' in schema:
        for child in value:_validate(child,schema['items'],root,depth+1)


def _decode(raw,schema,root,depth=0):
    if depth>32:raise ToolParseError('Parameter schema exceeds nesting bound')
    schema=_resolve(schema,root)
    if not isinstance(schema,dict):raise ToolParseError('Parameter schema does not resolve a wire type')
    if 'anyOf' in schema:
        # The native template serializes None literally. Reserve these explicit
        # null tokens for nullable unions; do not fill absent optional fields.
        if raw in ('null','None'):
            try:_validate(None,schema,root);return None
            except ToolParseError:pass
        candidates=[]
        for branch in schema['anyOf']:
            try:
                value=_decode(raw,branch,root,depth+1);_validate(value,schema,root)
                if not any(_equal(value,prior) for prior in candidates):candidates.append(value)
            except AmbiguousToolParseError:raise
            except ToolParseError:pass
        if not candidates:raise ToolParseError('Parameter matches no anyOf decoding')
        if len(candidates)!=1:raise AmbiguousToolParseError('Ambiguous anyOf parameter decoding')
        return candidates[0]
    kind=schema.get('type')
    if kind=='string':value=raw
    elif kind=='boolean' and raw in ('True','False'):value=raw=='True'
    elif kind=='null' and raw=='None':value=None
    elif kind in TYPES:value=_json(raw)
    else:raise ToolParseError('Parameter schema does not resolve a wire type')
    _validate(value,schema,root)
    return value


def parse_qwen_tools(text,tools):
    schemas={}
    for tool in tools or []:
        name=tool['function']['name']
        if name in schemas:raise ToolParseError('Duplicate function schema')
        schemas[name]=tool['function']['parameters']
    if '<tool_call>' not in text:
        if '<function=' in text or '</tool_call>' in text:raise ToolParseError('Incomplete tool-call envelope')
        return [],text.strip()
    blocks=list(re.finditer(r'<tool_call>\s*(.*?)\s*</tool_call>',text,re.DOTALL))
    if text.count('<tool_call>')!=len(blocks) or text.count('</tool_call>')!=len(blocks):
        raise ToolParseError('Unbalanced tool-call envelope')
    calls=[]
    for block in blocks:
        matched=re.fullmatch(r'<function=([A-Za-z_][A-Za-z0-9_]*)>\s*(.*?)\s*</function>',block.group(1),re.DOTALL)
        if not matched:raise ToolParseError('Malformed function block')
        name,body=matched.groups()
        if name not in schemas:raise ToolParseError('Unknown function name')
        schema=schemas[name];check_schema(schema);arguments={};position=0
        for parameter in re.finditer(r'<parameter=([A-Za-z_][A-Za-z0-9_]*)>\s*(.*?)\s*</parameter>',body,re.DOTALL):
            if body[position:parameter.start()].strip():raise ToolParseError('Unexpected text between parameters')
            key,raw=parameter.groups();raw=raw.strip()
            if key in arguments:raise ToolParseError('Duplicate parameter')
            spec=schema.get('properties',{}).get(key)
            if spec is None:raise ToolParseError('Unknown parameter')
            arguments[key]=_decode(raw,spec,schema);position=parameter.end()
        if body[position:].strip():raise ToolParseError('Unexpected function-body text')
        _validate(arguments,schema,schema)
        calls.append({'id':'local-call-'+str(len(calls)),'type':'function',
                      'function':{'name':name,'arguments':json.dumps(arguments,ensure_ascii=False)}})
    remainder=text
    for block in reversed(blocks):remainder=remainder[:block.start()]+remainder[block.end():]
    return calls,remainder.strip()


def parse_qwen_completion(raw,tools):
    text=raw.rstrip()
    for ending in ('<|im_end|>','<|endoftext|>'):
        if text.endswith(ending):text=text[:-len(ending)].rstrip()
    reasoning=None
    if text.lstrip().startswith('<think>'):
        match=re.match(r'^\s*<think>(.*?)</think>\s*',text,re.DOTALL)
        if not match:raise ToolParseError('Unclosed reasoning block')
        reasoning=match.group(1).strip();text=text[match.end():]
    calls,content=parse_qwen_tools(text,tools)
    return calls,content,reasoning
