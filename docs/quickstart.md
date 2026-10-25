# Quickstart

## Inspect and verify without an API key

Clone the repository and run commands from its root. Use Python 3.10 or newer (3.12 recommended). No Python dependencies are needed for task listing or frozen replay.

```sh
git clone https://github.com/Tasselszcx/SkillLifeBench.git
cd SkillLifeBench
python3 -m skilllifebench list
python3 -m skilllifebench list --json
python3 scripts/verify_release.py --output /tmp/skilllifebench-check
python3 -m skilllifebench replay --output /tmp/skilllifebench-replay
```

Each output directory must be new. Listing shows 60 lifecycle instances from 12 templates. The verification report checks release integrity and data consistency. Replay reconstructs 1,680 lifecycle outcomes from the published evidence, including attacks achieved at earlier execution prefixes.

For all frozen runtime and lifecycle outcomes:

```sh
python3 scripts/verify_release.py --full --output /tmp/skilllifebench-full-check
```

Reserve about 10 GB of scratch space for full extraction. Extraction and checks run on the CPU; no model requests, skill execution, or access to original private machine paths is required. See [reproduction](reproduction.md).

## Run new evaluations

Use an editable install from the cloned repository so the code and frozen task data remain together. New lifecycle execution requires Linux. The sandbox uses user, network and PID namespaces, a disposable filesystem and seccomp. On Debian/Ubuntu, install the system prerequisites:

```sh
sudo apt-get install python3 python3-yaml python3-cryptography python3-cffi libseccomp2 util-linux
python3 -m pip install -e .
```

The sandbox specifically uses `/usr/bin/python3`; installing packages only in a virtual environment does not install them for that interpreter. The host must permit user namespaces. Some container configurations disable them; use a suitable Linux host rather than disabling the sandbox.

First run a real positive/negative control, which requires no model:

```sh
python3 -m skilllifebench qualify --task LIFE-B-private-report-acl-01 --output /tmp/skilllifebench-control
```

Omit `--task` to verify all 560 controls across 60 tasks. A failed containment check stops execution.

Configure an OpenAI-compatible endpoint and enter the key without adding it to shell history (Bash):

```bash
export SKILLLIFEBENCH_BASE_URL=https://api.openai.com/v1
read -r -s -p "API key: " SKILLLIFEBENCH_API_KEY
export SKILLLIFEBENCH_API_KEY
```

Then evaluate a selected model on one task, in both conditions:

```sh
python3 -m skilllifebench run --model YOUR_MODEL_ID --task LIFE-B-private-report-acl-01 --output /tmp/skilllifebench-model
```

The model identifier must match the provider's returned identifier. Repeat `--task` for multiple tasks, or omit it for all 60. `--condition clean` or `--condition attack` selects one condition. By default, both run. These commands incur your provider's model costs.

The runner writes each episode and a summary under the supplied output directory. Infrastructure failures remain explicit and do not become model failures or fabricated benchmark results. A complete selected run has Boolean task, attack, and joint outcomes. See [evaluation](evaluation.md) for budgets and retry rules.

## Development checks

```sh
python3 -m unittest discover -s tests
```

The tests use frozen data and explicit control transports. They do not call a live model.
