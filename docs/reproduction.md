# Reproduce the published results

All commands below are offline. Run them from the repository root with a new output directory.

## One-command verification

```sh
python3 -m skilllifebench verify --output /tmp/skilllifebench-check
python3 -m skilllifebench verify --full --output /tmp/skilllifebench-full-check
```

The quick check validates file hashes, 388 source scenarios, the exact runtime/lifecycle schedules, Boolean outcome algebra, and consistency with the published tables. The full check additionally reconstructs frozen outcomes from evidence. Expect several GB of extracted files and reserve about 10 GB of scratch space.

## What is reproduced?

| Artifact | Records | Check |
|---|---:|---|
| Hosted runtime models | 2,136 | Reconstruct inputs; recompute task/goal measurements; verify recorded adjudication bindings |
| Two Qwen runtime models | 356 Default + 178 Check | Recompute measurements; verify final decisions and exact Default/Check pairing |
| Lifecycle decisions | 1,680 | Recompute Boolean outcomes from saved evidence and all prefixes |
| Source corpus | 388 scenarios | Verify source bindings and construction-release consistency |

The main runtime leaderboard uses 2,492 Default records (2,136 + 356). The additional 178 Check records belong to the authorization intervention, not the default leaderboard.

Full verification has reproduced all 1,680 lifecycle records, including 8,036 prefixes, and all runtime record bindings. It makes zero model calls and executes no skill payloads. Opaque native states are hashed, not unpickled.

## Individual commands

Runtime — 12 hosted models:

```sh
python3 data/runtime/hosted/verify_release.py --extract --evidence-root /tmp/skilllifebench-hosted-evidence --output /tmp/skilllifebench-hosted-report.json
```

Runtime — two Qwen models and the paired intervention:

```sh
python3 data/runtime/qwen/verify_release.py --extract --evidence-root /tmp/skilllifebench-qwen-evidence --output /tmp/skilllifebench-qwen-report.json
```

Lifecycle:

```sh
python3 -m skilllifebench replay --output /tmp/skilllifebench-lifecycle-replay
```

Source corpus:

```sh
python3 data/scenarios/code/release_bundle.py verify --bundle data/scenarios
```

## Evidence layout

`data/runtime/hosted/` and `data/runtime/qwen/` are sealed packages with their own manifests, frozen graders, source contracts, per-case decisions and compressed evidence. `data/lifecycle/evidence/` contains a compressed archive and a path/hash index. The portable lifecycle resolver maps historical source paths to archive members on the local machine.

Published API receipts remove credential headers and opaque continuation fields, including their encoded JSON copies. Experiment host paths use stable `/slb/` aliases. Source and public hashes are recorded separately in publication ledgers, and the verifiers authenticate each published file before checking its source binding. Task outputs, actions, scoring criteria and final decisions are preserved. Frozen native state is byte-identical and is never deserialized during verification.

Files under `data/studies/` are the plotted/tabulated inputs for supporting studies. Supporting-study files provide reported measurements and provenance; complete evidence replay is available for the two decision tracks above.

## Running new models versus replay

Replay checks the recorded experiments. A fresh run performs new model requests and can differ because of provider revisions, stochastic outputs or endpoint changes. Record that configuration separately rather than replacing published results. [Quickstart](quickstart.md) shows the Linux prerequisites and one-task smoke run.
