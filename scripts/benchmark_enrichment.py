from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO_ROOT / "generated" / "synthetic-scan-results-500k.json"
DEFAULT_VT_METADATA = REPO_ROOT / "generated" / "synthetic-vt-metadata.json"
DEFAULT_REPORT = REPO_ROOT / "generated" / "enrichment-benchmark-report.json"


def ensure_rust_binary() -> Path:
    candidate = REPO_ROOT / "target" / "release" / "scan-enrich-results"
    if candidate.is_file():
        return candidate
    subprocess.run(
        ["cargo", "build", "--release", "-p", "scan-enrichment"],
        cwd=REPO_ROOT,
        check=True,
    )
    if not candidate.is_file():
        raise FileNotFoundError("Rust enrichment binary was not built at target/release/scan-enrich-results")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def semantic_sha256_file(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def run_command(command: list[str], *, env: dict[str, str]) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(prefix="enrichment-bench-", suffix=".json", delete=False) as tmp:
        output_path = Path(tmp.name)
    started = time.perf_counter()
    try:
        subprocess.run(command + ["--output", str(output_path)], cwd=REPO_ROOT, env=env, check=True)
        elapsed = time.perf_counter() - started
        return {
            "command": command,
            "elapsed_seconds": elapsed,
            "output_path": str(output_path),
            "output_bytes": output_path.stat().st_size,
            "byte_output_sha256": sha256_file(output_path),
            "semantic_output_sha256": semantic_sha256_file(output_path),
        }
    except Exception:
        output_path.unlink(missing_ok=True)
        raise


def summarize_runs(label: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    timings = [run["elapsed_seconds"] for run in runs]
    byte_hashes = {run["byte_output_sha256"] for run in runs}
    semantic_hashes = {run["semantic_output_sha256"] for run in runs}
    output_sizes = {run["output_bytes"] for run in runs}
    if len(byte_hashes) != 1 or len(semantic_hashes) != 1 or len(output_sizes) != 1:
        raise ValueError(f"{label} runs did not produce stable output")
    return {
        "label": label,
        "runs": runs,
        "min_seconds": min(timings),
        "max_seconds": max(timings),
        "mean_seconds": statistics.mean(timings),
        "median_seconds": statistics.median(timings),
        "byte_output_sha256": next(iter(byte_hashes)),
        "semantic_output_sha256": next(iter(semantic_hashes)),
        "output_bytes": next(iter(output_sizes)),
    }


def cleanup_runs(runs: list[dict[str, Any]]) -> None:
    for run in runs:
        Path(run["output_path"]).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark Python vs Rust OpenVAS enrichment on a generated scan-results payload"
    )
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--vt-metadata", type=Path, default=DEFAULT_VT_METADATA)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    if not args.results.is_file():
        raise FileNotFoundError(f"Results file not found: {args.results}")
    if not args.vt_metadata.is_file():
        raise FileNotFoundError(f"VT metadata file not found: {args.vt_metadata}")

    rust_bin = ensure_rust_binary()
    python_env = os.environ.copy()
    python_env["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + python_env.get("PYTHONPATH", "")

    python_command = [
        sys.executable,
        "-m",
        "scan_examples.enrichment",
        "--engine",
        "python",
        "--results",
        str(args.results),
        "--vt-metadata",
        str(args.vt_metadata),
    ]
    rust_command = [
        str(rust_bin),
        "--results",
        str(args.results),
        "--vt-metadata",
        str(args.vt_metadata),
    ]

    for _ in range(args.warmups):
        warm_python = run_command(python_command, env=python_env)
        warm_rust = run_command(rust_command, env=os.environ.copy())
        cleanup_runs([warm_python, warm_rust])

    python_runs = [run_command(python_command, env=python_env) for _ in range(args.runs)]
    rust_runs = [run_command(rust_command, env=os.environ.copy()) for _ in range(args.runs)]

    try:
        python_summary = summarize_runs("python", python_runs)
        rust_summary = summarize_runs("rust", rust_runs)
        byte_for_byte_output_parity = (
            python_summary["byte_output_sha256"]
            == rust_summary["byte_output_sha256"]
        )
        semantic_parity = (
            python_summary["semantic_output_sha256"]
            == rust_summary["semantic_output_sha256"]
        )
        report = {
            "results_path": str(args.results),
            "vt_metadata_path": str(args.vt_metadata),
            "runs": args.runs,
            "warmups": args.warmups,
            "python": python_summary,
            "rust": rust_summary,
            "byte_for_byte_output_parity": byte_for_byte_output_parity,
            "semantic_output_parity": semantic_parity,
            "speedup_vs_python": (
                python_summary["mean_seconds"] / rust_summary["mean_seconds"]
                if rust_summary["mean_seconds"]
                else None
            ),
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        if not semantic_parity:
            raise SystemExit("python and rust outputs differed semantically")
    finally:
        cleanup_runs(python_runs + rust_runs)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
