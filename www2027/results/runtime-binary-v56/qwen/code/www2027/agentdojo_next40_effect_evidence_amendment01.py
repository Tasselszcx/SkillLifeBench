"""Narrow next40 identity amendment for original SharingPermission JSON values.

The frozen v1 adapter rejects the original share_file permission property's local
$ref. This amendment resolves only its pinned string enum, retains every other
identity check, and never changes native receipts or frozen v1 measurements.
"""
from __future__ import annotations

import copy
from pathlib import Path
import types

from . import agentdojo_next40_effect_evidence as frozen

sha,canonical,require=frozen.sha,frozen.canonical,frozen.require
FROZEN_ADAPTER_SHA256='97b89bf46958c0f3a7a757b0bcdeb8700e1b12ee7d1e7a7b356ee940d54fef71'
SHARE_CATALOG_SHA256='d0a8a2da58b492d495c0bc09430901a356efeb953b6d6ab70cff908271a9e6a8'
SHARE_SOURCE_SHA256='9bb419e0bbf8a503fc10d92dd56eed92e4c853407c39a07c1be44920ec952a4f'
SHARE_MODULE_SHA256='19376d95731c46477037986319bc8522b4bc96f4924e730b11906df23fc00b93'
ENUM_SOURCES={
    'src/agentdojo/default_suites/v1/tools/types.py':'691ed3353bd04e9f8233c4f70901daefb564e56209a8946f516496520aca3c13',
    'src/agentdojo/strenum.py':'ac76fd07924a27fc42c33e626c77ed93ea48e9f7d4effc1548b8b908b166737f'}


def _arguments(tool,request,resolution,before):
    if request['tool_name']!='share_file':
        return frozen._arguments(tool,request,resolution,before)
    source=resolution['tool_sources']['share_file']
    require(source['module']=='agentdojo.default_suites.v1.tools.cloud_drive_client'
            and source['qualified_name']=='share_file'
            and source['module_sha256']==SHARE_MODULE_SHA256
            and source['source_segment_sha256']==SHARE_SOURCE_SHA256,
            'sharing_permission_source_outside_amendment')
    catalog=[item for item in resolution['verified_catalog'] if item['name']=='share_file']
    require(len(catalog)==1 and sha(canonical(catalog[0]))==SHARE_CATALOG_SHA256,
            'sharing_permission_catalog_outside_amendment')
    # Exact catalog/source hashes above bind this single local definition. No
    # remote refs, cycles, coercions or arbitrary schema expansion are accepted.
    expanded=copy.deepcopy(catalog[0]);schema=expanded['parameters']
    require(schema['properties']['permission']['$ref']=='#/$defs/SharingPermission'
            and schema['$defs']['SharingPermission']=={
                'enum':['r','rw'],'title':'SharingPermission','type':'string'},
            'sharing_permission_definition_changed')
    schema['properties']['permission']={**schema['$defs']['SharingPermission'],
        'description':schema['properties']['permission']['description']}
    local_resolution={**resolution,'verified_catalog':[
        expanded if item['name']=='share_file' else item for item in resolution['verified_catalog']]}
    return frozen._arguments(tool,request,local_resolution,before)


def _load_context(root,research):
    require(sha(frozen._bytes(frozen.__file__))==FROZEN_ADAPTER_SHA256,'frozen_next40_adapter_changed')
    context=frozen._load_context(root,research)
    for path,expected in ENUM_SOURCES.items():
        require(sha(frozen._bytes(frozen.base._source_path(context['source_cache'],path)))==expected,
                'sharing_permission_enum_source_changed')
    return context


_verify_identity=types.FunctionType(frozen._verify_identity.__code__,
    {**frozen._verify_identity.__globals__,'_arguments':_arguments},name='verify_next40_identity_amendment01')
_verify_receipts=types.FunctionType(frozen.verify_next40_receipts.__code__,
    {**frozen.verify_next40_receipts.__globals__,'_verify_identity':_verify_identity,'_load_context':_load_context},
    name='verify_next40_receipts_amendment01')


def amendment_metadata():
    return {'version':'next40_receipt_identity_amendment01',
        'implementation_sha256':sha(frozen._bytes(__file__)),
        'frozen_v1_implementation_sha256':FROZEN_ADAPTER_SHA256,
        'resolved_schema':'share_file.permission: #/$defs/SharingPermission -> string enum r/rw',
        'share_catalog_sha256':SHARE_CATALOG_SHA256,'share_source_sha256':SHARE_SOURCE_SHA256,
        'original_enum_sources':ENUM_SOURCES,
        'scope':'Only pinned original string-enum JSON argument identity; native state deltas, task semantics, target measurements and admissions are unchanged.',
        'frozen_v1_preserved':True}


def verify_next40_receipts(runtime_root,research_root):
    report=_verify_receipts(runtime_root,research_root)
    report['identity_amendment']=amendment_metadata()
    return report


# Preserve the original target semantics and expose the same adapter API.
measure_verified_target_item=frozen.measure_verified_target_item
_score_run=types.FunctionType(frozen.score_next40_run.__code__,
    {**frozen.score_next40_run.__globals__,'verify_next40_receipts':verify_next40_receipts,'__file__':__file__},
    name='score_next40_run_amendment01',argdefs=frozen.score_next40_run.__defaults__)


def score_next40_run(runtime_root,source_cache,source_measurement_plan,target_contracts,target_amendment,control_plan=None):
    report=_score_run(runtime_root,source_cache,source_measurement_plan,target_contracts,target_amendment,control_plan)
    report['identity_amendment']=amendment_metadata()
    return report
