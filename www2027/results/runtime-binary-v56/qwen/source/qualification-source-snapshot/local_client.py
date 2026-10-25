"""Receipt-compatible localhost client and a strict Qwen XML tool-call parser."""
from __future__ import annotations
import copy
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime,timezone

MODEL_ID='Qwen3.5-9B@c202236235762e1c871ad0ccb60c8ee5ba337b9a'


class ToolParseError(ValueError): pass


def parse_qwen_tools(text,tools):
    """Parse model text as data; no evaluation or execution of returned text."""
    schemas={tool['function']['name']:tool['function']['parameters'] for tool in tools or []}
    if '<tool_call>' not in text:
        if '<function=' in text or '</tool_call>' in text:
            raise ToolParseError('Incomplete tool-call envelope')
        return [],text.strip()
    blocks=list(re.finditer(r'<tool_call>\s*(.*?)\s*</tool_call>',text,re.DOTALL))
    if text.count('<tool_call>')!=len(blocks) or text.count('</tool_call>')!=len(blocks):
        raise ToolParseError('Unbalanced tool-call envelope')
    calls=[]
    for block in blocks:
        matched=re.fullmatch(r'<function=([A-Za-z_][A-Za-z0-9_]*)>\s*(.*?)\s*</function>',block.group(1),re.DOTALL)
        if not matched: raise ToolParseError('Malformed function block')
        name,body=matched.groups()
        if name not in schemas: raise ToolParseError('Unknown function name')
        schema=schemas[name]; arguments={}; position=0
        for parameter in re.finditer(r'<parameter=([A-Za-z_][A-Za-z0-9_]*)>\s*(.*?)\s*</parameter>',body,re.DOTALL):
            if body[position:parameter.start()].strip(): raise ToolParseError('Unexpected text between parameters')
            key,raw=parameter.groups(); raw=raw.strip()
            if key in arguments: raise ToolParseError('Duplicate parameter')
            spec=schema.get('properties',{}).get(key)
            if spec is None: raise ToolParseError('Unknown parameter')
            kind=spec.get('type')
            if kind=='string': value=raw
            # The pinned Qwen template renders scalar historical arguments with
            # Jinja's string filter (False/True/None), not the JSON filter used
            # for arrays and objects. Accept only these exact typed spellings.
            elif kind=='boolean' and raw in ('True','False'): value=raw=='True'
            elif kind=='null' and raw=='None': value=None
            else:
                try: value=json.loads(raw)
                except ValueError as error: raise ToolParseError('Non-JSON scalar/object parameter') from error
                correct=(kind=='integer' and type(value) is int or
                         kind=='number' and type(value) in (int,float) or
                         kind=='boolean' and type(value) is bool or
                         kind=='object' and isinstance(value,dict) or
                         kind=='array' and isinstance(value,list) or
                         kind=='null' and value is None)
                if not correct: raise ToolParseError('Parameter type mismatch')
            if 'enum' in spec and value not in spec['enum']: raise ToolParseError('Parameter outside enum')
            arguments[key]=value; position=parameter.end()
        if body[position:].strip(): raise ToolParseError('Unexpected function-body text')
        if not set(schema.get('required',[])).issubset(arguments): raise ToolParseError('Missing required parameter')
        calls.append({'id':'local-call-'+str(len(calls)), 'type':'function',
                      'function':{'name':name,'arguments':json.dumps(arguments,ensure_ascii=False)}})
    remainder=text
    for block in reversed(blocks): remainder=remainder[:block.start()]+remainder[block.end():]
    return calls,remainder.strip()


def prepare_qwen_messages(messages):
    """Convert OpenAI JSON argument strings for the native template, by copy."""
    if not isinstance(messages,list) or not messages:
        raise ValueError('messages must be a nonempty list')
    prepared=copy.deepcopy(messages)
    for message in prepared:
        for call in message.get('tool_calls',[]) or []:
            function=call.get('function',call)
            if isinstance(function.get('arguments'),str):
                function['arguments']=json.loads(function['arguments'])
            if not isinstance(function.get('arguments',{}),dict):
                raise ValueError('Historical tool arguments must be JSON objects')
    return prepared


def parse_qwen_completion(raw,tools):
    """Separate reasoning before parsing executable calls; retain raw upstream."""
    text=raw.rstrip()
    for ending in ('<|im_end|>','<|endoftext|>'):
        if text.endswith(ending): text=text[:-len(ending)].rstrip()
    reasoning=None
    if text.lstrip().startswith('<think>'):
        match=re.match(r'^\s*<think>(.*?)</think>\s*',text,re.DOTALL)
        if not match: raise ToolParseError('Unclosed reasoning block')
        reasoning=match.group(1).strip(); text=text[match.end():]
    calls,content=parse_qwen_tools(text,tools)
    return calls,content,reasoning


class LocalModelClient:
    def __init__(self,base_url='http://127.0.0.1:8765/v1',timeout=180):
        if not (base_url.startswith('http://127.0.0.1:') or base_url.startswith('http://localhost:')):
            raise ValueError('Local model transport must use loopback')
        self.base_url=base_url.rstrip('/'); self.timeout=timeout

    def complete(self,model,messages,tools=None,max_tokens=1024,tool_choice=None):
        payload={'model':model,'messages':messages,'max_tokens':max_tokens}
        if tools: payload['tools']=tools
        if tool_choice is not None: payload['tool_choice']=tool_choice
        body=json.dumps(payload,ensure_ascii=False).encode(); started=time.monotonic()
        receipt={'requested_model':model,'endpoint':self.base_url+'/chat/completions',
                 'timestamp':datetime.now(timezone.utc).isoformat(),'request_sha256':hashlib.sha256(body).hexdigest(),
                 'request':payload,'status':'pending'}
        request=urllib.request.Request(receipt['endpoint'],data=body,headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request,timeout=self.timeout) as response:
                raw=response.read(8*1024*1024); receipt['http_status']=response.status
            data=json.loads(raw)
            receipt.update(status='ok',served_model=data.get('model'),usage=data.get('usage'),
                           response_sha256=hashlib.sha256(raw).hexdigest(),response=data,
                           local_identity=data.get('local_identity'))
            if data.get('tool_parse_error'):
                receipt.update(status='tool_parse_error',error=data['tool_parse_error'])
        except urllib.error.HTTPError as error:
            receipt.update(status='http_error',http_status=error.code,error=error.read(8192).decode(errors='replace'))
        except (urllib.error.URLError,TimeoutError,OSError,ValueError) as error:
            receipt.update(status='transport_error',error=type(error).__name__+': '+str(error))
        receipt['elapsed_seconds']=round(time.monotonic()-started,3)
        return receipt
