"""
TrustBoundary Command-Line Interface (CLI).
Enables automated benchmarking, single-prompt security auditing, and report generation.
"""

import os
import sys
import json
import argparse
from typing import List

# Ensure package directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from trustboundary.schema import RedTeamSample, DefenseTier
from trustboundary.evaluator import TrustBoundaryEvaluator
from trustboundary.defense_pipeline import DefensePipeline
from trustboundary.visualizer import TrustBoundaryVisualizer
from trustboundary.report_generator import TrustBoundaryReportGenerator


def load_dataset(dataset_path: str) -> List[RedTeamSample]:
    """Loads JSONL red team samples."""
    samples = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(RedTeamSample.from_dict(json.loads(line)))
    return samples


def run_benchmark_cmd(args):
    """Executes benchmark evaluation across all 4 defense tiers."""
    dataset_path = args.dataset or os.path.join(os.path.dirname(__file__), "..", "data", "redteam_benchmark.jsonl")
    dataset_path = os.path.abspath(dataset_path)

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)

    print(f"[*] Loading Red-Team Benchmark from: {dataset_path}")
    samples = load_dataset(dataset_path)
    print(f"[*] Loaded {len(samples)} evaluation scenarios ({sum(1 for s in samples if s.is_malicious)} malicious, {sum(1 for s in samples if not s.is_malicious)} benign).")

    evaluator = TrustBoundaryEvaluator()
    print("[*] Running multi-tier defense evaluation...")
    benchmark_data = evaluator.run_benchmark(samples)

    # Output directory
    output_dir = args.output_dir or os.path.join(os.path.dirname(__file__), "..", "reports")
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    figures_dir = os.path.join(output_dir, "figures")

    # Generate Reports
    md_path = os.path.join(output_dir, "benchmark_report.md")
    json_path = os.path.join(output_dir, "benchmark_summary.json")
    csv_path = os.path.join(output_dir, "benchmark_per_sample.csv")

    TrustBoundaryReportGenerator.generate_markdown_report(benchmark_data, md_path)
    TrustBoundaryReportGenerator.export_json(benchmark_data, json_path)
    TrustBoundaryReportGenerator.export_csv(benchmark_data["raw_results"], csv_path)
    print(f"[+] Exported Markdown report: {md_path}")
    print(f"[+] Exported JSON summary: {json_path}")
    print(f"[+] Exported CSV traces: {csv_path}")

    # Generate Figures
    if not args.no_figures:
        fig1 = os.path.join(figures_dir, "security_utility_tradeoff.png")
        fig2 = os.path.join(figures_dir, "threat_category_breakdown.png")
        fig3 = os.path.join(figures_dir, "canary_and_tool_exfil.png")
        fig4 = os.path.join(figures_dir, "latency_overhead.png")

        metrics_by_tier = benchmark_data["metrics_by_tier"]
        TrustBoundaryVisualizer.plot_security_utility_tradeoff(metrics_by_tier, fig1)
        TrustBoundaryVisualizer.plot_threat_category_breakdown(metrics_by_tier, fig2)
        TrustBoundaryVisualizer.plot_canary_and_tool_exfil(metrics_by_tier, fig3)
        TrustBoundaryVisualizer.plot_latency_overhead(metrics_by_tier, fig4)
        print(f"[+] Generated publication figures in: {figures_dir}")

    # Display console summary table
    print("\n" + "=" * 80)
    print("TRUSTBOUNDARY ADVERSARIAL BENCHMARK RESULTS")
    print("=" * 80)
    print(f"{'Defense Tier':<30} | {'ASR (%)':<8} | {'BUP (%)':<8} | {'ORR (%)':<8} | {'CLR (%)':<8} | {'F_sec (%)':<9}")
    print("-" * 80)
    for tier, m in benchmark_data["metrics_by_tier"].items():
        print(f"{tier:<30} | {m['attack_success_rate']:<8.1f} | {m['benign_utility_preservation']:<8.1f} | {m['over_refusal_rate']:<8.1f} | {m['canary_leakage_ratio']:<8.1f} | {m['harmonic_security_score']:<9.1f}")
    print("=" * 80 + "\n")


def audit_prompt_cmd(args):
    """Audits a single prompt against all defense tiers."""
    pipeline = DefensePipeline()
    sample = RedTeamSample(
        sample_id="AUDIT-01",
        category="Direct_Jailbreak",
        attack_vector="Manual Prompt Audit",
        prompt=args.prompt,
        is_malicious=True,
        ground_truth_verdict="REJECT",
        injected_context=args.context,
        canary_token=args.canary,
    )

    print(f"\n[*] Auditing Prompt: '{args.prompt}'")
    if args.context:
        print(f"[*] Injected Context: '{args.context}'")
    if args.canary:
        print(f"[*] Canary Token: '{args.canary}'")
    print("-" * 75)

    tiers = [
        DefenseTier.BASELINE_RAW,
        DefenseTier.KEYWORD_REGEX_FILTER,
        DefenseTier.INGRESS_ONLY_GUARDRAIL,
        DefenseTier.DUAL_BOUNDARY_FIREWALL,
    ]

    for tier in tiers:
        res = pipeline.evaluate_sample(sample, tier)
        status = "BLOCKED [SAFE]" if res.was_blocked else "ALLOWED [EXPOSED]"
        print(f"[{tier.value}]: {status}")
        print(f"   Reason: {res.block_reason}")
        print(f"   Response Preview: {res.response_content[:80]}...")
    print("-" * 75 + "\n")


def main():
    parser = argparse.ArgumentParser(description="TrustBoundary AI Security Evaluation CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Run full multi-tier benchmark")
    bench_parser.add_argument("--dataset", type=str, default=None, help="Path to redteam_benchmark.jsonl")
    bench_parser.add_argument("--output-dir", type=str, default=None, help="Directory to save reports")
    bench_parser.add_argument("--no-figures", action="store_true", help="Skip figure generation")

    # audit command
    audit_parser = subparsers.add_parser("audit", help="Audit a single prompt or payload")
    audit_parser.add_argument("--prompt", type=str, required=True, help="Prompt text to audit")
    audit_parser.add_argument("--context", type=str, default=None, help="Untrusted context string")
    audit_parser.add_argument("--canary", type=str, default=None, help="Secret canary token")

    args = parser.parse_args()
    if args.command == "benchmark":
        run_benchmark_cmd(args)
    elif args.command == "audit":
        audit_prompt_cmd(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
