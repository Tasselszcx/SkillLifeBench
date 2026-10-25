SkillLifeBench lifecycle decisions: portable public evidence

The archive retains original attempts, infrastructure retries, valid task failures and final selected results. Administrative delegated_before_execution records contain no model call or outcome. Analysis selects the same 1,680 valid clean/challenged executions. No task outcome or scoring criterion changes during publication.

Publication removes credential-bearing headers and opaque provider state (X-Codex-Turn-State and encrypted_content). The same removal applies to nested JSON and base64-encoded request/response bodies. Private host paths use stable /slb/ aliases. Synthetic task paths, executable action arguments, task snapshots and the frozen grading sources remain available; no pickle objects are loaded for verification.

release/portable-path-index.jsonl distinguishes each original SHA256 from its public derivative SHA256. It records changed JSON pointers, original/public token hashes, complete byte-interval mappings and decoded-body public hashes. An original request/response hash remains a historical binding; it does not assert that a sanitized body is byte-identical. The ledger checks every public token and every unchanged byte interval. release/privacy-publication.json summarizes the publication policy.

Resolve an aliased path and its original SHA256 through the portable index, then validate the resulting public file using public_sha256. Several immutable snapshots may share one historical path. release/proof-scope.json identifies earlier-study provenance documents whose nested bindings belong to separate releases. Those nested bindings are not claimed to be recursively verified lifecycle evidence.

From the repository root:
  python3 data/lifecycle/evidence/verify_public_export.py --archive-index data/lifecycle/evidence/archive-index.json
  python3 -m skilllifebench replay --output /tmp/skilllifebench-replay

The complete replay verifies 1,680 outcomes and 8,036 execution prefixes with the byte-identical frozen graders, without model calls or skill-code execution. Public derivatives are resolved explicitly; direct comparison of their bytes to original transport hashes is not a supported verification method.
