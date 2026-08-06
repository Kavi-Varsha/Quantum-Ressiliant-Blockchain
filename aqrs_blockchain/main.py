"""
Module 7: Main Entry Point
Orchestrates the full AQRS Blockchain Simulation end-to-end.
"""

import json
import os
import sys

# Ensure all sibling modules are importable regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from transaction_generator import generate_transactions
from simulation import run_simulation
from aqrs_calculator import compute_all_aqrs_scores
import visualizer

_MODES = ["ECDSA", "DIL2", "DIL3", "DIL5", "AQRS"]
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    print("=" * 62)
    print("  AQRS Blockchain Simulation System")
    print("  Adaptive Quantum-Readiness Scoring")
    print("=" * 62)

    # ── Step 1-2: Generate transactions ──────────────────────────────
    print("\nGenerating 100 transactions...")
    transactions = generate_transactions(100)

    low_n  = sum(1 for t in transactions if t.risk_level == "LOW")
    med_n  = sum(1 for t in transactions if t.risk_level == "MEDIUM")
    high_n = sum(1 for t in transactions if t.risk_level == "HIGH")
    print(f"  Generated {len(transactions)} transactions  "
          f"[ LOW: {low_n} | MEDIUM: {med_n} | HIGH: {high_n} ]")

    # ── Step 3-5: Run simulation for every mode ───────────────────────
    print("\nRunning simulation for all 5 modes...")
    all_mode_results: dict = {}

    for mode in _MODES:
        print(f"\n  [{_MODES.index(mode) + 1}/5] Mode: {mode:<6} ...", end="", flush=True)
        result = run_simulation(mode, transactions)
        all_mode_results[mode] = result
        print(
            f"  Done  |  Avg Sign: {result['average_signing_time_ms']:7.3f} ms  "
            f"|  TPS: {result['throughput_tps']:8.2f}"
        )

    # ── Step 6: Compute AQRS scores ───────────────────────────────────
    print("\nComputing AQRS scores...")
    aqrs_scores = compute_all_aqrs_scores(all_mode_results)
    for mode, score in aqrs_scores.items():
        print(f"  {mode:<6}  AQRS Score = {score:.4f}")

    # ── Step 7: Persist results to JSON ──────────────────────────────
    results_path = os.path.join(_BASE_DIR, "results.json")
    print(f"\nSaving results to {results_path} ...")
    _save_results(all_mode_results, aqrs_scores, results_path)
    print("  Saved.")

    # ── Step 8-9: Generate plots and summary table ────────────────────
    print("\nGenerating plots...")
    plots_dir = os.path.join(_BASE_DIR, "plots")
    visualizer.generate_all_plots(all_mode_results, aqrs_scores, plots_dir=plots_dir)

    # ── Step 10 ───────────────────────────────────────────────────────
    print("Simulation complete. Results saved to results.json")


def _save_results(all_mode_results: dict, aqrs_scores: dict, path: str) -> None:
    """Serialize all results to a JSON file."""
    output = {
        "aqrs_scores": aqrs_scores,
        "modes": {},
    }

    for mode, result in all_mode_results.items():
        output["modes"][mode] = {
            "mode":                         result["mode"],
            "total_transactions":           result["total_transactions"],
            "total_chain_size_bytes":       result["total_chain_size_bytes"],
            "average_block_size_bytes":     result["average_block_size_bytes"],
            "total_signing_time_ms":        result["total_signing_time_ms"],
            "total_verification_time_ms":   result["total_verification_time_ms"],
            "average_signing_time_ms":      result["average_signing_time_ms"],
            "average_verification_time_ms": result["average_verification_time_ms"],
            "average_signature_size_bytes": result["average_signature_size_bytes"],
            "throughput_tps":               result["throughput_tps"],
            "aqrs_score":                   aqrs_scores.get(mode, 0),
            "transactions":                 result["transactions"],
        }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
