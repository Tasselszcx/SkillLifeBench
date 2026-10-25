"""Exact service signatures; no generic refusal or answer-content filtering."""
import json
DEPRECATION='Gemini 3.5 Flash is no longer available. Please switch to Gemini 3.7 Flash in the latest version of Antigravity.'
def classify(receipt):
    response=receipt.get('response')
    if not isinstance(response,dict)or receipt.get('http_status')!=200:return None
    if response.get('id')=='chatcmpl-gateway-error':return 'gateway_error_response_id'
    choices=response.get('choices')
    if not isinstance(choices,list)or len(choices)!=1:return None
    message=choices[0].get('message',{})
    if (message.get('content')==DEPRECATION and not message.get('tool_calls')
            and DEPRECATION not in json.dumps(receipt.get('logical_request',{}),ensure_ascii=False)):
        return 'explicit_endpoint_deprecation_banner'
    return None
