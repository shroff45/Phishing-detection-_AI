"""
PhishGuard ML v4.1 — Pipeline Runner
One-click sequential execution of the entire ML pipeline.

Stage 2 fix: every stage that exits non-zero now aborts the pipeline.
Previously evaluate (stage 5) and deploy (stage 6) failures were swallowed.
"""

import sys
import time
from pathlib import Path

# Ensure ml-retrain is on sys.path
sys.path.insert(0, str(Path(__file__).parent))


# Stages where a failure is always fatal (no point continuing)
_ALWAYS_FATAL = {"1/6", "2/6", "3/6", "4/6", "5/6", "6/6"}


def run():
    """Execute all pipeline stages in order.

    Any stage that raises an exception or calls sys.exit(1) aborts the
    pipeline immediately with a non-zero exit code.
    """
    print("╔" + "═" * 58 + "╗")
    print("║  PHISHGUARD ML v4.1 — FULL PIPELINE                      ║")
    print("╚" + "═" * 58 + "╝")
    start = time.time()

    stages = [
        ("1/6", "SYNTHETIC DATA GENERATION", "synth_generator", "generate_all"),
        ("2/6", "DATASET DOWNLOAD",          "download_datasets", "download"),
        ("3/6", "DATA PREPARATION",          "prepare_data",       "prepare"),
        ("4/6", "MODEL TRAINING",            "train_model",        "train"),
        ("5/6", "EVALUATION",                "evaluate",           "evaluate"),
        ("6/6", "DEPLOYMENT",                "deploy",             "deploy"),
    ]

    for step, title, module_name, func_name in stages:
        print(f"\n\n{'━' * 60}")
        print(f"  [{step}] {title}")
        print(f"{'━' * 60}\n")

        stage_start = time.time()
        try:
            module = __import__(module_name)
            func = getattr(module, func_name)
            func()
            elapsed = time.time() - stage_start
            print(f"\n  ✓ {title} — {elapsed:.1f}s")
        except SystemExit as exc:
            # sys.exit(1) from evaluate() or deploy() is a deliberate gate failure
            elapsed = time.time() - stage_start
            code = exc.code if exc.code is not None else 1
            print(f"\n  ✗ {title} FAILED after {elapsed:.1f}s (exit code {code})")
            print("  FATAL: Pipeline aborted — gate or stage failed.")
            sys.exit(code)
        except Exception as e:
            elapsed = time.time() - stage_start
            print(f"\n  ✗ {title} FAILED after {elapsed:.1f}s: {e}")
            import traceback
            traceback.print_exc()
            print("  FATAL: Cannot continue after stage failure.")
            sys.exit(1)

    total = time.time() - start
    print(f"\n\n{'╔' + '═' * 58 + '╗'}")
    print(f"║  PIPELINE COMPLETE — Total: {total:.0f}s                        ║")
    print(f"{'╚' + '═' * 58 + '╝'}")


if __name__ == "__main__":
    run()
