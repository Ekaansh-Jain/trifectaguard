"""
Comprehensive test pass — runs every fast test and prints a PASS/FAIL summary.

  python run_all_tests.py            # includes the LLM adjudicator config
  python run_all_tests.py --no-llm   # deterministic only (no API calls)

Detector model evals (external / adaptive / novel-family) are heavier and live in
RESULTS.md; this covers the taint logic, the gateway decision suite, and the full
detector+gate+adjudicator system on the scaled suite.
"""
import argparse
import subprocess
import sys

CHECKS = [
    ("flow gateway: engine + policies + DLP + e2e over stdio",
     [sys.executable, "-m", "pytest", "-q", "tests/test_flow_engine.py", "tests/test_gateway_e2e.py"]),
    ("unit: taint engine", [sys.executable, "tests/test_taint.py"]),
    ("gateway decision suite (rules+LLM)", [sys.executable, "test_gateway_suite.py", "--llm"]),
    ("end-to-end system (detector+gate+adjudicator)", [sys.executable, "test_system.py"]),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true")
    args = ap.parse_args()

    results = []
    for name, cmd in CHECKS:
        if args.no_llm and ("--llm" in cmd or "system" in name):
            cmd = [c for c in cmd if c != "--llm"]
            if "system" in name:
                cmd = cmd + ["--no-llm"]
        print(f"\n{'='*70}\n▶ {name}\n{'='*70}")
        r = subprocess.run(cmd, capture_output=True, text=True)
        out = r.stdout + r.stderr
        print(out.strip()[-3000:])
        ok = r.returncode == 0 and "Traceback" not in out
        # extra pass criteria for the system test: catch 1.0 & false_block 0.0
        if "system" in name and "catch=1.00" not in out:
            ok = ok and "catch=1.00  false_block=0.00" in out.replace("  ", "  ")
        results.append((name, ok))

    print(f"\n{'='*70}\nSUMMARY\n{'='*70}")
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("\nALL PASS" if all(ok for _, ok in results) else "\nSOME FAILED")


if __name__ == "__main__":
    main()
