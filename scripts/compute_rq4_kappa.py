"""Compute Cohen's Kappa and metrics for RQ4 oracle validity.

Usage:
    python scripts/compute_rq4_kappa.py
    python scripts/compute_rq4_kappa.py --csv rq4_oracle_human_annotation.csv
    python scripts/compute_rq4_kappa.py --csv rq4_oracle_human_annotation.csv --judge results/llm_judge_gpt-5-mini/judge_results.json
"""

import argparse
import csv
import json
import sys
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")


def load_annotations(csv_path: Path):
    """Return list of dicts with vuln_id, vuln_class, oracle, human."""
    rows = []
    with open(csv_path, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            human = row.get("human_label (BREACH/SAFE)", "").strip().upper()
            if human not in ("BREACH", "SAFE"):
                continue  # skip unfilled rows
            rows.append({
                "vuln_id":    row["vuln_id"].strip(),
                "vuln_class": row["vuln_class"].strip(),
                "oracle":     row["oracle_decision"].strip().upper(),
                "human":      human,
            })
    return rows


def cohen_kappa(y_ref, y_pred):
    """Compute Cohen's kappa; ref=human, pred=oracle/judge. BREACH=positive."""
    n = len(y_ref)
    if n == 0:
        return 0.0
    tp = sum(r == "BREACH" and p == "BREACH" for r, p in zip(y_ref, y_pred))
    tn = sum(r == "SAFE"   and p == "SAFE"   for r, p in zip(y_ref, y_pred))
    fp = sum(r == "SAFE"   and p == "BREACH" for r, p in zip(y_ref, y_pred))
    fn = sum(r == "BREACH" and p == "SAFE"   for r, p in zip(y_ref, y_pred))
    po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (tn + fn) * (tn + fp)) / (n * n)
    kappa = (po - pe) / (1 - pe) if pe < 1 else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"kappa": kappa, "precision": precision, "recall": recall, "f1": f1,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn, "n": n}


def metrics_for_subset(rows, pred_key="oracle"):
    y_ref  = [r["human"] for r in rows]
    y_pred = [r[pred_key] for r in rows]
    return cohen_kappa(y_ref, y_pred)


def print_metrics(label, m):
    print(f"  {label}:")
    print(f"    κ={m['kappa']:.3f}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}"
          f"  (TP={m['tp']} TN={m['tn']} FP={m['fp']} FN={m['fn']} N={m['n']})")


def kappa_interp(k):
    if k >= 0.81: return "almost perfect"
    if k >= 0.61: return "substantial"
    if k >= 0.41: return "moderate"
    if k >= 0.21: return "fair"
    return "slight"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="rq4_oracle_human_annotation.csv")
    parser.add_argument("--judge", default=None,
                        help="Path to judge_results.json from run_llm_judge.py")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        csv_path = Path(__file__).parent.parent / args.csv
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {args.csv}")

    rows = load_annotations(csv_path)
    if not rows:
        print("ERROR: No filled rows found. Fill 'human_label (BREACH/SAFE)' column first.")
        sys.exit(1)

    print(f"Loaded {len(rows)} annotated entries from {csv_path.name}")
    print(f"  BREACH: {sum(1 for r in rows if r['human']=='BREACH')}  "
          f"SAFE: {sum(1 for r in rows if r['human']=='SAFE')}")

    # ── Hybrid Oracle vs Human ──────────────────────────────────────────
    print("\n=== Hybrid Oracle vs Human Annotation ===")
    overall = metrics_for_subset(rows, "oracle")
    print_metrics("Overall", overall)

    # class groups
    ab_rows  = [r for r in rows if r["vuln_class"] in ("A", "B")]
    c_rows   = [r for r in rows if r["vuln_class"] == "C"]
    de_rows  = [r for r in rows if r["vuln_class"] in ("D", "E")]
    for label, subset in [("A/B", ab_rows), ("C", c_rows), ("D/E", de_rows)]:
        if subset:
            print_metrics(label, metrics_for_subset(subset, "oracle"))

    print(f"\n  Interpretation: {kappa_interp(overall['kappa'])} agreement (κ={overall['kappa']:.3f})")

    # ── LLM Judge vs Human ─────────────────────────────────────────────
    if args.judge:
        judge_path = Path(args.judge)
        if not judge_path.exists():
            judge_path = Path(__file__).parent.parent / args.judge
        judge_data = json.loads(judge_path.read_bytes().decode("utf-8", errors="replace"))
        judge_map = {r["vuln_id"]: r["llm_judge_decision"]
                     for r in judge_data.get("results", [])}

        # Attach judge decision to rows
        judge_rows = []
        for r in rows:
            jd = judge_map.get(r["vuln_id"])
            if jd and jd != "ERROR":
                judge_rows.append({**r, "judge": jd})

        print(f"\n=== LLM Judge vs Human Annotation ({len(judge_rows)} matched) ===")
        if judge_rows:
            joverall = metrics_for_subset(judge_rows, "judge")
            print_metrics("Overall", joverall)
            for label, subset in [
                ("A/B", [r for r in judge_rows if r["vuln_class"] in ("A","B")]),
                ("C",   [r for r in judge_rows if r["vuln_class"] == "C"]),
                ("D/E", [r for r in judge_rows if r["vuln_class"] in ("D","E")]),
            ]:
                if subset:
                    print_metrics(label, metrics_for_subset(subset, "judge"))
            print(f"\n  Interpretation: {kappa_interp(joverall['kappa'])} agreement (κ={joverall['kappa']:.3f})")

            # ── Comparison table ────────────────────────────────────────
            print("\n=== Tab: Oracle Comparison (paste into paper) ===")
            print(f"{'Oracle':<22} {'κ':>6} {'P':>6} {'R':>6} {'F1':>6} {'Cost/entry':>12}")
            print("-" * 60)
            print(f"{'Hybrid (ours)':<22} {overall['kappa']:>6.3f} {overall['precision']:>6.3f} "
                  f"{overall['recall']:>6.3f} {overall['f1']:>6.3f} {'~$0.00':>12}")
            print(f"{'LLM Judge (gpt-5-mini)':<22} {joverall['kappa']:>6.3f} {joverall['precision']:>6.3f} "
                  f"{joverall['recall']:>6.3f} {joverall['f1']:>6.3f} {'~$0.02':>12}")

    # ── LaTeX snippet ───────────────────────────────────────────────────
    print("\n=== LaTeX table values (RQ4 kappa table) ===")
    ab_m  = metrics_for_subset(ab_rows,  "oracle") if ab_rows  else None
    c_m   = metrics_for_subset(c_rows,   "oracle") if c_rows   else None
    de_m  = metrics_for_subset(de_rows,  "oracle") if de_rows  else None

    def fmt(m, key): return f"{m[key]:.2f}" if m else "--"
    print(f"Cohen's kappa  & {overall['kappa']:.2f} & {fmt(ab_m,'kappa')} & {fmt(c_m,'kappa')} & {fmt(de_m,'kappa')} \\\\")
    print(f"Precision      & {overall['precision']:.2f} & {fmt(ab_m,'precision')} & {fmt(c_m,'precision')} & {fmt(de_m,'precision')} \\\\")
    print(f"Recall         & {overall['recall']:.2f} & {fmt(ab_m,'recall')} & {fmt(c_m,'recall')} & {fmt(de_m,'recall')} \\\\")
    print(f"F1             & {overall['f1']:.2f} & {fmt(ab_m,'f1')} & {fmt(c_m,'f1')} & {fmt(de_m,'f1')} \\\\")

    # Save summary JSON
    out = {
        "hybrid_overall": overall,
        "hybrid_ab": ab_m, "hybrid_c": c_m, "hybrid_de": de_m,
    }
    out_path = Path(__file__).parent.parent / "results" / "rq4_kappa_results.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nSaved to: {out_path}")


if __name__ == "__main__":
    main()
