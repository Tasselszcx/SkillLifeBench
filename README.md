# SkillLifeBench: Benchmarking Lifecycle Security of LLM Agent Skills

> NeurIPS 2026 Datasets & Benchmarks Track (under review)

**Dataset:** [huggingface.co/datasets/SkillLifeBench2026/SkillLifeBench](https://huggingface.co/datasets/SkillLifeBench2026/SkillLifeBench) | **Code:** [anonymous.4open.science/r/SkillLifeBench-55C1](https://anonymous.4open.science/r/SkillLifeBench-55C1)

---

**SkillLifeBench** is the first executable benchmark to evaluate the security of LLM agent skills across their full lifecycle. Unlike existing benchmarks that treat tools as static, trusted objects, SkillLifeBench recognizes that skills are dynamic, evolving artifacts — and the lifecycle itself is an attack surface.

```
Acquire → Store → Retrieve → Execute → Evolve
```

LLM agents are increasingly built on reusable skill ecosystems where a skill can be compromised **before** execution (injected code, deceptive metadata), **during** execution (runtime injection, context leakage), **through multi-skill composition** (privilege escalation chains), or **across version updates** (evolution regressions). SkillLifeBench evaluates *exploitability* rather than mere vulnerability presence: every entry is executable, containerized, and scored by a hybrid oracle.

---

## Benchmark at a Glance

| | |
|---|---|
| **Entries** | 194 benchmark entries |
| **Classes** | 5 vulnerability classes, 17 subclasses |
| **Clean skills** | 73 reference skills across 6 domains |
| **Models evaluated** | 5 frontier LLMs |
| **Baseline ASR range** | 40.2% – 63.4% (non-saturating) |
| **Oracle agreement** | Cohen's κ = 0.71 (substantial) |

---

## Comparison with Existing Benchmarks

| Benchmark | Untrusted Skill | Lifecycle | Runtime | Comp. | Evol. | Harm Oracle |
|-----------|:-:|:-:|:-:|:-:|:-:|:-:|
| AgentDojo | ✗ | ✗ | ✓ | ✗ | ✗ | △ |
| InjecAgent | ✗ | ✗ | ✓ | ✗ | ✗ | △ |
| ToolSword | ✗ | ✗ | ✓ | ✗ | ✗ | △ |
| AgentDAM | ✗ | ✗ | ✓ | ✗ | ✗ | ✓ |
| R-Judge | ✗ | ✗ | ✓ | ✗ | ✗ | △ |
| Skill-Inject | ✓ | △ | ✓ | ✗ | ✗ | ✓ |
| SkillsBench | ✓ | △ | ✓ | ✗ | ✗ | △ |
| **SkillLifeBench** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** |

---

## Repository Structure

```
SkillLifeBench/
├── injector/              # Injection engine (static / dynamic / evolution modes)
├── harness/               # Evaluation framework (SkillLifeEval)
│   ├── pipeline.py        # Main pipeline orchestration entry point
│   └── runner/            # Agent framework runners (Docker-isolated execution)
├── oracle/                # Hybrid Oracle (6 predicate detectors)
│   └── detectors/         # DynamicBehavior, PermViolation, DataExfil,
│                          #   TaskHijack, StateCorrupt, EvoRegress
├── skill_guardian/        # SkillScanner three-gate defense middleware
├── docker/                # safebench-sandbox Docker image definition
│   └── safebench-sandbox/
├── scripts/               # Evaluation and analysis scripts
│   ├── run_eval.py         # Single-model evaluation
│   ├── compare_models.py   # Cross-model ASR comparison
│   ├── analyze_results.py  # Summary statistics
│   ├── run_llm_judge.py    # LLM-as-judge runner
│   └── build_docker.sh     # Build sandbox image
└── run_experiments.py     # Multi-model full experiment entry point
```

---

## Vulnerability Taxonomy (5 Classes, 17 Subclasses)

| Class | Subclasses | Entries | Lifecycle Stage | Key Oracle Predicates |
|-------|------------|---------|----------------|-----------------------|
| **A — Code-Level** | A1–A3 | 38 | Acquire / Store | DynBeh, PermViol, StateCorrupt |
| **B — Interface Deception** | B1–B3 | 32 | Retrieve | PermViol, TaskHijack |
| **C — Runtime Injection** | C1–C4 | 46 | Execute | TaskHijack, DataExfil, StateCorrupt |
| **D — Compositional** ★ | D1–D3 | 38 | Execute (multi-skill) | PermViol, TaskHijack, StateCorrupt |
| **E — Lifecycle** ★★ | E1–E4 | 40 | Evolve | EvoRegress |

**D-class** harm is realized only through multi-skill composition chains — one target skill carries injected behavior, but the breach requires the agent's multi-step planner to route it across clean skills.

**E-class** entries compare v1/v2 skill versions via the safety delta Δ_safe(b); the regression can be invisible to static analysis (e.g., a safety check silently removed by reward hacking).

---

## Threat Model

| Adversary | Acts At | Covered Classes |
|-----------|---------|-----------------|
| **Adv-Supply** | Acquire / Store / Retrieve — modifies skill code, metadata, descriptions, parameters | A, B, D (target skill), E3 |
| **Adv-Runtime** | Execute — poisons content returned by a skill at call time | C |
| **Adv-Evolution** | Evolve — poisons training traces or reward signals across skill versions | E1, E2, E4 |

---

## Hybrid Oracle (6 Predicates)

| Predicate | Detection Logic | Classes |
|-----------|----------------|---------|
| **DynamicBehavior** | Injected code path becomes reachable in the execution trace | A/B/C/D/E |
| **PermViolation** | Runtime action exceeds the declared permission scope | B/C/D |
| **DataExfil** | Sensitive data flows to an unauthorized external sink | C/D/E |
| **TaskHijack** | Final output aligns with injected objective (cosine ≥ 0.75) | B/C/D |
| **StateCorrupt** | Workspace state modified beyond authorized task scope | A/C/D |
| **EvoRegress** | Safety degrades between skill versions v1 → v2 | E |

An entry is scored **Breach** if any required predicate (declared in the registry YAML) fires on the collected execution trace.

---

## Quick Start

**Prerequisites:**
```bash
pip install -r requirements.txt

# Build the Docker sandbox image (required on first run)
bash scripts/build_docker.sh
# or: docker build -t safebench-sandbox:latest docker/safebench-sandbox/
```

**Configure API keys** (create a `.env` file):
```env
OPENAI_API_KEY=<your_key>
OPENAI_BASE_URL=<your_base_url>
```

**Run multi-model experiments:**
```bash
# All models, Baseline configuration (no defense)
python run_experiments.py

# Single model
python run_experiments.py --model GLM-4.6

# Specific vulnerability classes
python run_experiments.py --model GLM-4.6 --classes A,B,C
```

**Enable SkillScanner defense (layer ablation):**
```bash
# Baseline (no defense)
python run_experiments.py

# L1 only — Acquire Gate (AST + regex static analysis)
python run_experiments.py --layers L1

# L1 + L2 — Acquire + Invoke Gate (permission checking)
python run_experiments.py --layers L1,L2

# Full — all three gates (L1 + L2 + L3 Response Gate)
python run_experiments.py --layers L1,L2,L3
```

---

## Baseline Results (5 Models × 194 Entries)

Overall ASR (%) under Baseline configuration (no defense). **Lower is better for the agent.**

| Model | Type | Overall | A (38) | B (32) | C (46) | D (38) | E (40) |
|-------|------|---------|--------|--------|--------|--------|--------|
| **qwen3-32b** | Open | **63.4** | 57.9 | 53.1 | 67.4 | 57.9 | 77.5 |
| kimi-k2.5 | Open | 62.4 | 60.5 | 59.4 | 52.2 | 60.5 | 80.0 |
| gpt-5-mini | Closed | 54.6 | 47.4 | 53.1 | 54.3 | 55.3 | 62.5 |
| deepseek-v3 | Open | 45.9 | 39.5 | 43.8 | 43.5 | 44.7 | 57.5 |
| **GLM-4.6** | Open | **40.2** | 42.1 | 37.5 | 39.1 | 39.5 | 42.5 |
| **Avg.** | | **53.3** | **49.5** | **49.4** | **51.3** | **51.6** | **64.0** |

**Key findings:**
1. **23.2 pp model spread** (40.2%–63.4%) — the benchmark is non-saturating and discriminates meaningfully among models.
2. **E/D classes are hardest** (avg 64.0% and 51.6%) — lifecycle and composition-mediated attacks expose structural failure modes that execution-focused benchmarks miss.
3. **E-class shows widest inter-model spread** (42.5%–80.0%, 37.5 pp) — models differ substantially in handling cross-version regressions.
4. **Positive D/E vs. A/B/C gap across all models** (mean +7.7 pp) — lifecycle-phase attacks are structurally harder to defend.

---

## SkillScanner Defense Evaluation

Layer-wise ablation: overall ASR (%) across four configurations.

| Model | Baseline | L1 | L1+L2 | Full | Δ (Full − Base) |
|-------|----------|----|-------|------|-----------------|
| qwen3-32b | 63.4 | 61.1 | 60.4 | **56.2** | −7.2 pp |
| kimi-k2.5 | 62.4 | 59.7 | 59.1 | **55.1** | −7.2 pp* |
| gpt-5-mini† | 54.6 | 51.9 | 50.5 | **47.4** | −7.2 pp |
| deepseek-v3 | 45.9 | 44.1 | 43.5 | **41.2** | −4.7 pp |
| GLM-4.6 | 40.2 | 39.2 | 38.7 | **35.0** | −5.2 pp |
| **Avg.** | **53.3** | **51.2** | **50.4** | **47.0** | **−6.3 pp** |

†Closed-source model; others are open-source.  
\*62.4→55.1 = −7.3 pp (weighted).

**Layer contributions (averaged across 5 models):**

| Gate | Trigger | Contribution | Primary Effect |
|------|---------|-------------|----------------|
| **L1 Acquire Gate** | Skill loading | −2.1 pp | Blocks A-class (eval/exec/pickle/subprocess, hard-coded credentials) |
| **L2 Invoke Gate** | Before skill call | −0.7 pp | Blocks B/C-class (undeclared privilege, permission surface mismatch) |
| **L3 Response Gate** | After skill return | −3.4 pp | Blocks C-class DataExfil (PII patterns, injection markers in output) |

**SkillScanner (Full) reduces overall ASR by 6.3 pp on average.** However, D/E-class attacks remain largely unmitigated (−2.1 pp and −2.0 pp respectively): D-class chains evade per-turn gate checks via chained semantic invocations; E-class regressions depend on cross-version behavioural deltas invisible to single-trace analysis.

---

## Oracle Validity

Expert reference annotation of all 194 entries (blind to oracle decisions) confirms substantial validity.

| Metric | Overall | Code/Iface. (A/B) | Runtime (C) | Comp./Life. (D/E) |
|--------|---------|-------------------|-------------|-------------------|
| Cohen's κ | **0.707** | 0.646 | **0.815** | 0.675 |
| Precision | 0.833 | 0.771 | 0.871 | 0.862 |
| Recall | **0.992** | 0.974 | 1.000 | 1.000 |
| F1 | **0.906** | 0.860 | 0.931 | 0.926 |

**Comparison with LLM Judges** — all six LLM judges show high precision but low recall; the hybrid oracle achieves recall=0.992 at near-zero marginal cost.

| Oracle | κ | Precision | Recall | F1 |
|--------|---|-----------|--------|----|
| **Hybrid (ours)** | **0.707** | 0.833 | **0.992** | **0.906** |
| LLM Judge (qwen3-32b) | 0.691 | 0.979 | 0.772 | 0.864 |
| LLM Judge (GLM-4.6) | 0.555 | 0.976 | 0.650 | 0.780 |
| LLM Judge (claude-sonnet-4-6) | 0.498 | 0.950 | 0.618 | 0.749 |
| LLM Judge (deepseek-v3.2) | 0.402 | 0.955 | 0.512 | 0.667 |
| LLM Judge (gpt-5-mini) | 0.391 | 0.940 | 0.512 | 0.663 |
| LLM Judge (gpt-5.2) | 0.225 | 0.911 | 0.333 | 0.488 |

Even the strongest LLM judge (qwen3-32b, recall=0.772) misses 23% of expert-labelled breaches; the weakest (gpt-5.2, recall=0.333) misses two-thirds.

---

## Citation

```bibtex
@inproceedings{skilllifebench2026,
  title     = {SkillLifeBench: Benchmarking Lifecycle Security of {LLM} Agent Skills},
  author    = {Anonymous Authors},
  booktitle = {Advances in Neural Information Processing Systems},
  year      = {2026},
  url       = {https://anonymous.4open.science/r/SkillLifeBench-55C1}
}
```

---

## License

Code: MIT License. Dataset: CC BY 4.0.
