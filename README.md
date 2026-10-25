# SkillLifeBench

**Benchmarking Security Across the Lifecycle of Agent Skills**

SkillLifeBench tests whether an agent can complete an authorized task when reusable skills change: their implementation, interface, stored state, composition, or version. It connects the version an agent selects to the code that actually executes.

[Paper](www2027/paper/main.pdf) · [Quickstart](docs/quickstart.md) · [Dataset](docs/dataset.md) · [Evaluation](docs/evaluation.md) · [Reproduce the results](docs/reproduction.md)

![SkillLifeBench overview](assets/overview.png)

## What is measured?

**Joint success** means the user task succeeds and the registered attack goal does not. Task completion and attack success are checked separately. The two decision tracks use Boolean outcomes and fixed denominators.

| Track | Tasks | Models | Clean + challenged executions | Purpose |
|---|---:|---:|---:|---|
| Runtime decisions | 89 | 14 | 2,492 | Decisions under challenged tool responses |
| Lifecycle decisions | 60 | 14 | 1,680 | Skill selection, stored replacement, permissions, composition, and updates |

The source benchmark contains **388 paired scenarios**: 262 introduced cases and 126 AgentDojo adaptations. The 60 lifecycle tasks comprise **12 templates with five instances each**, derived from introduced cases. The source corpus also includes prescribed-call cases for measuring implementation effects. See [dataset composition](docs/dataset.md) for the relationship between these sets.

## Start here — no API key required

```sh
git clone https://github.com/Tasselszcx/SkillLifeBench.git
cd SkillLifeBench
python3 -m skilllifebench list
python3 scripts/verify_release.py --output /tmp/skilllifebench-check
```

Use a new output directory for each command. The quick check validates published files, task counts, Boolean outcomes, and leaderboard consistency. **It makes no model calls.** Python 3.12+ is the documented setup. Python 3.10/3.11 also works when its `tarfile` includes backported extraction filters.

Recompute every frozen lifecycle outcome from the published evidence:

```sh
python3 -m skilllifebench replay --output /tmp/skilllifebench-replay
```

This regrades **1,680/1,680 records** from captured state and invocation evidence. For both runtime and lifecycle replay, use:

```sh
python3 scripts/verify_release.py --full --output /tmp/skilllifebench-full-check
```

Full verification unpacks several GB of evidence. The archives are already included; no account or API access is needed. See [reproduction](docs/reproduction.md) for what each check establishes.

## Published leaderboard

Challenged-condition Joint SR (%), higher is better. Runtime and lifecycle scores use different tasks and remain separate. Rows follow lifecycle Joint SR; tied scores share a rank.

| Lifecycle rank | Model | Runtime · 89 tasks | Lifecycle · 60 tasks |
|---:|---|---:|---:|
| 1 | GPT-5.6-Sol | 82.0 | 96.7 |
| 1 | GPT-5.6-Terra | 80.9 | 96.7 |
| 3 | Sonnet 5 | 76.4 | 88.3 |
| 3 | GLM-5.2 | 74.2 | 88.3 |
| 5 | GLM-5.3 | 76.4 | 80.0 |
| 6 | DeepSeek-V4-Pro | 77.5 | 76.7 |
| 6 | Kimi-K2.6 | 77.5 | 76.7 |
| 8 | DeepSeek-V3.2 | 28.1 | 60.0 |
| 9 | Sonnet 4.6 | 82.0 | 56.7 |
| 10 | Qwen3.5-4B | 61.8 | 55.0 |
| 11 | Qwen3.5-9B | 73.0 | 51.7 |
| 12 | DeepSeek-V4-Flash | 77.5 | 45.0 |
| 13 | GPT-6-Luna | 73.0 | 31.7 |
| 14 | Gemini 3.5 Flash | 67.4 | 10.0 |

[Exact counts and per-template results](www2027/results/lifecycle-autonomy-v60/analysis/) · [Runtime verdicts](www2027/results/runtime-binary-v56/runtime-case-verdicts.jsonl)

The two tracks reveal different behavior: GPT-5.6-Sol and Sonnet 4.6 tie at 82.0% runtime Joint SR, but obtain 96.7% and 56.7% on lifecycle tasks. Across the lifecycle track, 103 challenged runs complete both the user task and the attack goal.

## Evaluate a model

The public runner evaluates the lifecycle track through an OpenAI-compatible chat-completions endpoint. It uses the released task contracts, sandbox, and Boolean graders. Install the [Linux execution prerequisites](docs/quickstart.md#run-new-evaluations), then run one task before scheduling all 60:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m skilllifebench qualify   --task LIFE-B-private-report-acl-01 --output /tmp/skilllifebench-controls
python3 -m skilllifebench run --model YOUR_MODEL_ID   --task LIFE-B-private-report-acl-01 --output /tmp/skilllifebench-model
```

Set `SKILLLIFEBENCH_BASE_URL` and `SKILLLIFEBENCH_API_KEY` in your local environment. Keys are never included in saved request headers. `run` makes paid API requests if the configured provider charges for them; all other quickstart commands are offline. [Configuration and budgets](docs/evaluation.md).

## Repository map

| Location | Contents |
|---|---|
| `skilllifebench/` | Public CLI, catalog, API client, and lifecycle runner |
| `scripts/` | Release verification and portable frozen replay |
| `docs/` | Installation, dataset, evaluation, and reproduction guides |
| `tests/` | Runner, scoring, replay, and release-verification checks |
| `www2027/lifecycle_autonomy_v60/` | Original task implementations and sandbox backend |
| `www2027/data/release-v1/` | The 388-scenario source corpus and provenance |
| `www2027/results/runtime-binary-v56/` | Frozen runtime records, contracts, graders, and evidence |
| `www2027/results/lifecycle-autonomy-v60/` | Lifecycle tasks, records, analysis, and evidence |
| `www2027/paper/` | Paper PDF, LaTeX source, figures, protocols, and result data |
| `licenses/` | Dataset and third-party notices |

The `www2027` paths preserve existing artifact bindings. Use the public CLI and documentation as the entry points. Frozen archives retain their original metadata; current commands resolve evidence locally without requiring the original machine paths.

## Citation and attribution

Paper: **SkillLifeBench: Benchmarking Security Across the Lifecycle of Agent Skills**. The [included manuscript](www2027/paper/main.pdf) and repository can be cited until a public paper identifier is available.

```bibtex
@misc{skilllifebench,
  title = {SkillLifeBench: Benchmarking Security Across the Lifecycle of Agent Skills},
  year = {2026},
  url = {https://github.com/Tasselszcx/SkillLifeBench}
}
```

See [attribution and licenses](docs/attribution.md). Credential-handling and vulnerability reporting are described in [SECURITY.md](SECURITY.md).
