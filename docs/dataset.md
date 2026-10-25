# Dataset

## Source corpus and decision tracks

The released source corpus contains 388 paired scenarios. Each scenario fixes the user request and authorization while changing one skill condition.

| Family | Scenarios | Change |
|---|---:|---|
| A — Implementation | 19 | Executable skill implementation |
| B — Interface | 77 | Interface, permissions or implementation binding |
| C — Runtime | 128 | Runtime tool responses |
| D — Composition | 65 | Cross-skill information flow or workflow |
| E — Evolution | 99 | Skill state or version |
| **Total** | **388** | |

Of these, 262 are introduced cases (260 constructed cases and two maintainer updates), and 126 adapt AgentDojo tasks. Source provenance is retained in the manifests. Fixed-invocation cases characterize implementation consequences; they are not autonomous model-choice tasks.

The paper's main leaderboard uses two separate decision tracks:

- **Runtime:** 89 AgentDojo-derived tasks with full task and registered attack-goal checks, each evaluated clean and challenged.
- **Lifecycle:** 60 task instances, derived from 12 introduced parent cases: four B, four D and four E templates, each instantiated five times. Agents can inspect and change skill bindings or workflow state and can use available tools directly. The same user task and authorization apply in both conditions.

The two tracks have 14 models and 4,172 baseline executions in total. The 60 lifecycle instances are not 60 independent mechanisms. Paper uncertainty analyses resample the 12 complete template groups.

## Files

| File/directory | Use |
|---|---|
| `www2027/data/release-v1/scenarios.json` | 388 source scenario definitions |
| `www2027/data/release-v1/sources/scenarios/` | Frozen source-cohort manifests |
| `www2027/data/release-v1/sources/index.json` | Source references and hashes |
| `www2027/results/runtime-binary-v56/hosted/data/contracts.json` | Runtime task and attack contracts |
| `www2027/results/lifecycle-autonomy-v60/protocol/task-manifest.json` | 60 lifecycle instances, public observations and checks |
| `www2027/manifests/` | Parent-case definitions used by the lifecycle backend |
| `www2027/results/lifecycle-autonomy-v60/protocol/qualification.json` | Frozen qualification-control results |

`release-v1/episodes.csv` contains the source release's 2,119 construction/effect measurements. It is not the current leaderboard. Use the runtime and lifecycle decision records linked in [reproduction](reproduction.md).

## Recovery study

The recovery study uses the 77 B-family source cases, covering 17 task templates and six fault types. Each parent has matched risk and benign configurations. Two Qwen models give 154 evaluations per group and recovery method. This cohort evaluates follow-up utility and harm, and is separate from the two main decision tracks.

The paper and `www2027/paper/protocol/` describe fault construction, evidence projections and available repair actions. `www2027/paper/results/` contains its supplied result tables and paired counts. The public frozen trace replay commands cover the runtime and lifecycle decision tracks; supporting recovery results are available as measurements and paired counts.

## Data contract

`python3 -m skilllifebench list --json` lists each task ID, template, family and parent case, and identifies the frozen manifest. Full task definitions are in `www2027/results/lifecycle-autonomy-v60/protocol/task-manifest.json`; `www2027/lifecycle_autonomy_v60/` implements their observations, actions and outcome predicates. Synthetic private fixtures and attack payloads are intentional benchmark inputs. They are not credentials for external services.

The new runner uses these fixed task contracts. Changing task inputs, authorization or outcome checks creates a new evaluation configuration and should be recorded as such.
