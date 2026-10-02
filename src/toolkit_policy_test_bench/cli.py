from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__
from .categories import CategoryRules
from .compare import CompareBudget, compare_reports
from .envelope import build_envelope, file_ref, is_envelope, validate_envelope, write_envelope
from .evidence import build_evidence, load_controls, to_markdown
from .formatting import format_output
from .importers import DEFAULT_MAX_TEXT, DEFAULT_THRESHOLD, SOURCES, import_findings
from .io import read_bytes, read_json, read_text, write_json, write_text
from .judge import make_litellm_judge
from .pack import create_pack, load_suite_from_path, verify_pack
from .plugins import DetectorRegistry
from .report import PolicyReport, write_report_json
from .runner import run_suite
from .signing import generate_ed25519_keypair, sign_bytes, verify_bytes

logger = logging.getLogger(__name__)


class _JSONLogFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, sort_keys=True)


EXIT_SUCCESS = 0
EXIT_CLI_ERROR = 2
EXIT_UNEXPECTED_ERROR = 3
EXIT_VALIDATION_FAILED = 4


def _cmd_pack_create(args: argparse.Namespace) -> int:
    """Create a suite pack zip from a suite directory."""
    suite_dir = Path(args.suite_dir).resolve()
    out = Path(args.out).resolve()

    logger.info(f"Creating pack from: {suite_dir}")

    try:
        create_pack(suite_dir=suite_dir, out_zip=out)
        print(str(out))
        logger.info(f"Pack created: {out}")
        return EXIT_SUCCESS
    except (ValueError, FileNotFoundError, PermissionError, OSError) as e:
        logger.error(f"Failed to create pack: {e}")
        return EXIT_CLI_ERROR


def _cmd_pack_inspect(args: argparse.Namespace) -> int:
    """Inspect a suite (dir or zip)."""
    suite_path = Path(args.suite).resolve()
    logger.info(f"Inspecting suite: {suite_path}")

    try:
        suite = load_suite_from_path(suite_path)
        print(json.dumps(suite.to_dict(), indent=2, sort_keys=True))
        logger.info("Suite inspected successfully")
        return EXIT_SUCCESS
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to inspect suite: {e}")
        return EXIT_CLI_ERROR


def _cmd_pack_verify(args: argparse.Namespace) -> int:
    """Verify pack integrity (hashes)."""
    pack_path = Path(args.suite).resolve()
    logger.info(f"Verifying pack: {pack_path}")

    try:
        res = verify_pack(pack_zip=pack_path)
        ok = bool(res.get("ok"))
        print(json.dumps(res, indent=2, sort_keys=True))

        if ok:
            logger.info("Pack verification passed")
            return EXIT_SUCCESS
        else:
            logger.warning("Pack verification failed")
            return EXIT_VALIDATION_FAILED
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to verify pack: {e}")
        return EXIT_CLI_ERROR


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate Ed25519 keypair for signing."""
    private_key_path = Path(args.private_key).resolve()
    public_key_path = Path(args.public_key).resolve()
    logger.info("Generating Ed25519 keypair...")

    try:
        kp = generate_ed25519_keypair()
        logger.info("Keypair generated successfully")
    except Exception as e:
        logger.error(f"Failed to generate keypair: {e}")
        return EXIT_CLI_ERROR

    try:
        write_text(private_key_path, kp.private_key_pem)
        logger.info(f"Wrote private key to: {private_key_path}")
        write_text(public_key_path, kp.public_key_pem)
        logger.info(f"Wrote public key to: {public_key_path}")
        return EXIT_SUCCESS
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to write key files: {e}")
        return EXIT_CLI_ERROR


def _cmd_pack_sign(args: argparse.Namespace) -> int:
    """Sign a pack zip (detached signature JSON)."""
    pack_path = Path(args.suite).resolve()
    private_key_path = Path(args.private_key).resolve()
    logger.info(f"Signing pack: {pack_path}")

    try:
        payload = read_bytes(pack_path)
        logger.debug("Pack loaded successfully")
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read pack: {e}")
        return EXIT_CLI_ERROR

    try:
        private_pem = read_text(private_key_path)
        logger.debug("Private key loaded")
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read private key: {e}")
        return EXIT_CLI_ERROR

    try:
        sig = sign_bytes(payload=payload, private_key_pem=private_pem)
        logger.info("Pack signed successfully")
    except Exception as e:
        logger.error(f"Failed to sign pack: {e}")
        return EXIT_CLI_ERROR

    sig_obj = {"algorithm": "ed25519", "signature_b64": sig}

    try:
        if args.out:
            write_json(Path(args.out), sig_obj)
        else:
            print(json.dumps(sig_obj, indent=2, sort_keys=True))
        return EXIT_SUCCESS
    except (OSError, PermissionError, ValueError) as e:
        logger.error(f"Failed to write signature: {e}")
        return EXIT_CLI_ERROR


def _cmd_pack_verify_sig(args: argparse.Namespace) -> int:
    """Verify a pack signature."""
    pack_path = Path(args.suite).resolve()
    signature_path = Path(args.signature).resolve()
    public_key_path = Path(args.public_key).resolve()
    logger.info(f"Verifying signature for: {pack_path}")

    try:
        sig_obj = read_json(signature_path)
        if not isinstance(sig_obj, dict):
            raise ValueError("Signature file must contain a JSON object")
        sig_b64 = str(sig_obj.get("signature_b64") or "")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read signature: {e}")
        return EXIT_CLI_ERROR

    try:
        public_pem = read_text(public_key_path)
        logger.debug("Public key loaded")
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read public key: {e}")
        return EXIT_CLI_ERROR

    try:
        payload = read_bytes(pack_path)
        ok = verify_bytes(payload=payload, signature_b64=sig_b64, public_key_pem=public_pem)

        if ok:
            logger.info("Signature verified successfully")
        else:
            logger.warning("Signature verification failed")

        print(json.dumps({"ok": ok}, indent=2, sort_keys=True))
        return EXIT_SUCCESS if ok else EXIT_VALIDATION_FAILED
    except (FileNotFoundError, PermissionError, Exception) as e:
        logger.error(f"Failed to verify signature: {e}")
        return EXIT_CLI_ERROR


def _verify_pack_for_run(args: argparse.Namespace, pack_path: Path) -> str:
    """Check pack hashes and, when requested, its detached signature.

    Returns an empty string when the pack may be run, otherwise the reason.
    """
    res = verify_pack(pack_zip=pack_path)
    if not res.get("ok"):
        return f"pack integrity check failed: {json.dumps(res, sort_keys=True)}"

    if not args.signature:
        return ""
    sig_obj = read_json(Path(args.signature).resolve())
    if not isinstance(sig_obj, dict):
        raise ValueError("Signature file must contain a JSON object")
    ok = verify_bytes(
        payload=read_bytes(pack_path),
        signature_b64=str(sig_obj.get("signature_b64") or ""),
        public_key_pem=read_text(Path(args.public_key).resolve()),
    )
    return "" if ok else "pack signature verification failed"


# Headline numbers a gate reads; everything else goes to ``details``.
_RUN_SUMMARY_KEYS = (
    "cases",
    "failed_cases",
    "missing_predictions",
    "fail_rate",
    "pii_total_hits",
    "secret_total_hits",
    "expected_refusals",
    "missed_refusals",
    "over_refusals",
)


def _suite_inputs(
    suite_path: Path, is_pack: bool, extra: list[Path] | None = None
) -> list[dict[str, Any]]:
    """Suite files (or the pack zip) plus any existing extra input files."""
    if is_pack:
        refs = [file_ref(suite_path)] if suite_path.is_file() else []
    else:
        refs = [
            file_ref(suite_path / name)
            for name in ("suite.json", "cases.jsonl")
            if (suite_path / name).is_file()
        ]
    return refs + [file_ref(p) for p in extra or [] if p.is_file()]


def _run_error(
    args: argparse.Namespace,
    exit_code: int,
    message: str,
    *,
    suite_path: Path,
    is_pack: bool,
    predictions_path: Path,
    pattern_paths: list[Path] | None = None,
) -> int:
    """Log the error and, with ``--out``, record it as a ``verdict: error`` envelope.

    The envelope is written only when the predictions file (the subject) can be
    hashed; the legacy format has no error shape.
    """
    logger.error(message)
    if args.out and not args.legacy_json and predictions_path.is_file():
        env = build_envelope(
            kind="policy.run",
            verdict="error",
            exit_code=exit_code,
            subject=[file_ref(predictions_path)],
            inputs=_suite_inputs(suite_path, is_pack, pattern_paths) + [file_ref(predictions_path)],
            details={"error": message},
        )
        try:
            write_envelope(env, Path(args.out).resolve())
        except OSError as e:
            logger.error(f"Failed to write error report: {e}")
    return exit_code


def _cmd_run(args: argparse.Namespace) -> int:
    """Run a policy suite against predictions.

    Exits ``EXIT_VALIDATION_FAILED`` when the pack fails verification (nothing
    is run) or when any case fails, including PII/secret findings and missing
    predictions. The report is still written in the latter case.
    """
    suite_path = Path(args.suite).resolve()
    predictions_path = Path(args.predictions).resolve()
    pattern_paths = [Path(p).resolve() for p in args.patterns or []]
    logger.info(f"Running suite: {suite_path}")
    logger.debug(f"Predictions: {predictions_path}")

    if bool(args.signature) != bool(args.public_key):
        logger.error("--signature and --public-key must be given together")
        return EXIT_CLI_ERROR
    is_pack = suite_path.is_file() and suite_path.suffix.lower() == ".zip"
    if args.signature and not is_pack:
        logger.error("--signature requires --suite to be a .zip pack")
        return EXIT_CLI_ERROR

    def error(exit_code: int, message: str) -> int:
        return _run_error(
            args,
            exit_code,
            message,
            suite_path=suite_path,
            is_pack=is_pack,
            predictions_path=predictions_path,
            pattern_paths=pattern_paths,
        )

    if is_pack:
        try:
            reason = _verify_pack_for_run(args, suite_path)
        except (ValueError, FileNotFoundError, PermissionError, RuntimeError) as e:
            return error(EXIT_CLI_ERROR, f"Failed to verify pack: {e}")
        if reason:
            return error(EXIT_VALIDATION_FAILED, f"Refusing to run: {reason}")

    try:
        suite = load_suite_from_path(suite_path)
        logger.info(f"Loaded suite: {suite.name}")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return error(EXIT_CLI_ERROR, f"Failed to load suite: {e}")

    registry = None
    if pattern_paths:
        registry = DetectorRegistry()
        try:
            for path in pattern_paths:
                registry.load_patterns_file(path)
        except (ValueError, FileNotFoundError, OSError) as e:
            return error(EXIT_CLI_ERROR, f"Failed to load pattern file: {e}")

    try:
        judge: dict[str, Any] = {}
        if args.refusal_judge:
            classify, judge_meta = make_litellm_judge(args.refusal_judge)
            judge = {
                "refusal_classifier": classify,
                "refusal_method": f"judge:{args.refusal_judge}",
                "refusal_meta": judge_meta,
            }
        report = run_suite(
            suite=suite, predictions_path=predictions_path, registry=registry, **judge
        )
        logger.info("Suite run completed")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return error(EXIT_CLI_ERROR, f"Failed to run suite: {e}")

    summary = report.summary
    failed = (
        int(summary.get("failed_cases", 0)) > 0
        or int(summary.get("pii_total_hits", 0)) > 0
        or int(summary.get("secret_total_hits", 0)) > 0
    )
    exit_code = EXIT_VALIDATION_FAILED if failed else EXIT_SUCCESS
    envelope = build_envelope(
        kind="policy.run",
        verdict="fail" if failed else "pass",
        exit_code=exit_code,
        subject=[file_ref(predictions_path)],
        inputs=_suite_inputs(suite_path, is_pack, pattern_paths) + [file_ref(predictions_path)],
        summary={k: summary[k] for k in _RUN_SUMMARY_KEYS if k in summary},
        details={
            "run_id": summary.get("run_id"),
            "suite": report.suite,
            "meta": report.meta,
            "cases": report.cases,
        },
    )

    if args.out:
        out = Path(args.out).resolve()
        try:
            if args.legacy_json:
                write_report_json(report, out)
            else:
                write_envelope(envelope, out)
            logger.info(f"Wrote report to: {out}")
        except (OSError, PermissionError) as e:
            logger.error(f"Failed to write report: {e}")
            return EXIT_CLI_ERROR

    out_fmt = getattr(args, "format", "json")
    shown = report.to_dict() if (out_fmt == "table" or args.legacy_json) else envelope
    print(format_output(shown, out_fmt))

    if failed:
        logger.warning(
            "Policy run failed: %s of %s cases failed",
            summary.get("failed_cases"),
            summary.get("cases"),
        )
    return exit_code


_COMPARE_KEYS = ("fail_rate", "pii_total_hits", "secret_total_hits")


def _load_report_for_compare(path: Path) -> PolicyReport:
    """Load a run report (envelope or legacy) that ``compare`` can judge.

    Raises:
        ValueError: for an ``error`` report or a summary without the compared
            numbers, so a report that could not judge never compares as clean.
    """
    obj = read_json(path)
    if not isinstance(obj, dict):
        raise ValueError(f"{path}: report must be a JSON object")
    if is_envelope(obj):
        pred = obj.get("predicate") or {}
        if pred.get("kind") != "policy.run":
            raise ValueError(f"{path}: expected a policy.run report, got {pred.get('kind')!r}")
        if pred.get("verdict") == "error":
            raise ValueError(f"{path}: the run ended in an error and has no results")
    report = PolicyReport.from_dict(obj)
    missing = [k for k in _COMPARE_KEYS if k not in report.summary]
    if missing:
        raise ValueError(f"{path}: summary is missing {', '.join(missing)}")
    return report


def _cmd_compare(args: argparse.Namespace) -> int:
    """Compare candidate report against baseline report."""
    baseline_path = Path(args.baseline).resolve()
    candidate_path = Path(args.candidate).resolve()
    logger.info("Comparing reports")
    logger.debug(f"Baseline: {baseline_path}")
    logger.debug(f"Candidate: {candidate_path}")

    try:
        baseline = _load_report_for_compare(baseline_path)
        logger.info("Loaded baseline report")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read baseline: {e}")
        return EXIT_CLI_ERROR

    try:
        candidate = _load_report_for_compare(candidate_path)
        logger.info("Loaded candidate report")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read candidate: {e}")
        return EXIT_CLI_ERROR

    try:
        budget = CompareBudget(
            max_fail_rate_increase_pct=float(args.max_fail_rate_increase_pct),
            max_pii_hits_increase=int(args.max_pii_hits_increase),
            max_secret_hits_increase=int(args.max_secret_hits_increase),
        )
        result = compare_reports(baseline=baseline, candidate=candidate, budget=budget)
    except Exception as e:
        logger.error(f"Failed to compare reports: {e}")
        return EXIT_CLI_ERROR

    passed = bool(result["passed"])
    exit_code = EXIT_SUCCESS if passed else EXIT_VALIDATION_FAILED
    if passed:
        logger.info("Comparison passed")
    else:
        logger.warning("Comparison failed")
    envelope = build_envelope(
        kind="policy.compare",
        verdict="pass" if passed else "fail",
        exit_code=exit_code,
        subject=[file_ref(candidate_path)],
        inputs=[file_ref(baseline_path), file_ref(candidate_path)],
        summary={"passed": passed, "failures": result["failures"], "deltas": result["deltas"]},
        details={
            "baseline": result["baseline"],
            "candidate": result["candidate"],
            "budget": result["budget"],
        },
    )
    if args.out:
        try:
            write_envelope(envelope, Path(args.out).resolve())
        except OSError as e:
            logger.error(f"Failed to write comparison: {e}")
            return EXIT_CLI_ERROR

    out_fmt = getattr(args, "format", "json")
    print(format_output(result if out_fmt == "table" else envelope, out_fmt))
    return exit_code


def _cmd_validate_report(args: argparse.Namespace) -> int:
    """Validate a report: a v1 envelope, or the legacy policy report shape."""
    report_path = Path(args.report).resolve()
    logger.info(f"Validating report: {report_path}")

    try:
        obj = read_json(report_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read report: {e}")
        return EXIT_CLI_ERROR

    payload: dict[str, Any]
    if is_envelope(obj):
        problems = validate_envelope(obj)
        payload = {
            "ok": not problems,
            "schema": "report-envelope",
            "schema_version": 1,
            "problems": problems,
        }
    else:
        ok = (
            isinstance(obj, dict)
            and isinstance(obj.get("suite"), dict)
            and isinstance(obj.get("summary"), dict)
            and isinstance(obj.get("cases"), list)
        )
        payload = {"ok": ok, "schema": "toolkit_policy_report", "schema_version": 1}

    if payload["ok"]:
        logger.info("Report validation passed")
    else:
        logger.warning("Report validation failed")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return EXIT_SUCCESS if payload["ok"] else EXIT_VALIDATION_FAILED


def _cmd_import(args: argparse.Namespace) -> int:
    """Import garak / promptfoo / PyRIT results as normalized findings and gate on them.

    Fails (exit 4) when failed + errored findings exceed ``--max-failures``: an item
    the source tool could not judge counts against the gate, never for it.
    """
    input_path = Path(args.input).resolve()
    categories_path = Path(args.categories).resolve() if args.categories else None
    if not input_path.is_file():
        logger.error(f"Input file not found: {input_path}")
        return EXIT_CLI_ERROR

    def inputs() -> list[dict[str, Any]]:
        refs = [file_ref(input_path)]
        if categories_path and categories_path.is_file():
            refs.append(file_ref(categories_path))
        return refs

    def error(message: str) -> int:
        logger.error(message)
        if args.out:
            env = build_envelope(
                kind="policy.import",
                verdict="error",
                exit_code=EXIT_CLI_ERROR,
                subject=[file_ref(input_path)],
                inputs=inputs(),
                details={"error": message, "source": args.source},
            )
            write_envelope(env, Path(args.out).resolve())
        return EXIT_CLI_ERROR

    if args.max_failures < 0:
        return error("--max-failures must be >= 0")
    try:
        rules = CategoryRules.load(categories_path)
        result = import_findings(
            args.source,
            input_path,
            rules,
            threshold=float(args.threshold),
            max_text=int(args.max_text_chars),
        )
    except (ValueError, OSError, UnicodeDecodeError) as e:
        return error(f"Failed to import {args.source} results: {e}")

    if not result.findings:
        return error(f"No judged items in {input_path.name}; nothing to gate on")
    summary = result.summary()
    summary["max_failures"] = int(args.max_failures)
    passed = summary["failed"] + summary["errors"] <= args.max_failures
    exit_code = EXIT_SUCCESS if passed else EXIT_VALIDATION_FAILED
    envelope = build_envelope(
        kind="policy.import",
        verdict="pass" if passed else "fail",
        exit_code=exit_code,
        subject=[file_ref(input_path)],
        inputs=inputs(),
        summary=summary,
        details={"findings": result.findings, "notes": result.notes},
    )
    if args.out:
        try:
            write_envelope(envelope, Path(args.out).resolve())
        except OSError as e:
            logger.error(f"Failed to write findings: {e}")
            return EXIT_CLI_ERROR
    print(format_output(summary, getattr(args, "format", "json")))
    if not passed:
        logger.warning(
            "Import gate failed: %s failed + %s errored findings (budget %s)",
            summary["failed"],
            summary["errors"],
            args.max_failures,
        )
    return exit_code


def _cmd_evidence(args: argparse.Namespace) -> int:
    """Summarize run/import reports as evidence per control and gate on failures."""
    report_paths = [Path(p).resolve() for p in args.report]
    controls_path = Path(args.controls).resolve() if args.controls else None
    categories_path = Path(args.categories).resolve() if args.categories else None
    extra_inputs = [p for p in (controls_path, categories_path) if p and p.is_file()]

    def error(message: str) -> int:
        logger.error(message)
        subject = [file_ref(p) for p in report_paths if p.is_file()]
        if args.out and subject:
            env = build_envelope(
                kind="policy.evidence",
                verdict="error",
                exit_code=EXIT_CLI_ERROR,
                subject=subject,
                inputs=subject + [file_ref(p) for p in extra_inputs],
                details={"error": message},
            )
            write_envelope(env, Path(args.out).resolve())
        return EXIT_CLI_ERROR

    if args.max_failures < 0:
        return error("--max-failures must be >= 0")
    try:
        rules = CategoryRules.load(categories_path)
        controls = load_controls(rules, controls_path)
        reports = []
        for path in report_paths:
            obj = read_json(path)
            if not is_envelope(obj):
                raise ValueError(f"{path.name}: not a v1 report envelope")
            reports.append((file_ref(path), obj))
        summary, details = build_evidence(reports, controls, rules)
    except (ValueError, FileNotFoundError, PermissionError, OSError) as e:
        return error(f"Failed to build evidence: {e}")

    summary["max_failures"] = int(args.max_failures)
    passed = summary["failed_results"] <= args.max_failures
    exit_code = EXIT_SUCCESS if passed else EXIT_VALIDATION_FAILED
    refs = [ref for ref, _ in reports]
    envelope = build_envelope(
        kind="policy.evidence",
        verdict="pass" if passed else "fail",
        exit_code=exit_code,
        subject=refs,
        inputs=refs + [file_ref(p) for p in extra_inputs],
        summary=summary,
        details=details,
    )
    if args.out:
        try:
            write_envelope(envelope, Path(args.out).resolve())
        except OSError as e:
            logger.error(f"Failed to write evidence: {e}")
            return EXIT_CLI_ERROR
    if args.format == "markdown":
        print(to_markdown(summary, details))
    else:
        print(format_output(summary, args.format))
    if not passed:
        logger.warning(
            "Evidence gate failed: %s failed or unjudged results (budget %s)",
            summary["failed_results"],
            args.max_failures,
        )
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="toolkit-policy",
        description="Toolkit Policy Test Bench - Run and validate policy compliance suites",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )
    p.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format (default: text)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    keygen = sub.add_parser("keygen", help="Generate an Ed25519 keypair for signing suite packs.")
    keygen.add_argument("--private-key", required=True, help="Output private key file path")
    keygen.add_argument("--public-key", required=True, help="Output public key file path")
    keygen.set_defaults(func=_cmd_keygen)

    pack = sub.add_parser("pack", help="Suite pack utilities (zip).")
    pack_sub = pack.add_subparsers(dest="pack_cmd", required=True)

    pack_create = pack_sub.add_parser(
        "create", help="Create a suite pack zip from a suite directory."
    )
    pack_create.add_argument("--suite-dir", required=True, help="Suite directory path")
    pack_create.add_argument("--out", required=True, help="Output pack zip file path")
    pack_create.set_defaults(func=_cmd_pack_create)

    pack_inspect = pack_sub.add_parser("inspect", help="Inspect a suite (dir or zip).")
    pack_inspect.add_argument("--suite", required=True, help="Suite path (directory or zip)")
    pack_inspect.set_defaults(func=_cmd_pack_inspect)

    pack_verify = pack_sub.add_parser("verify", help="Verify pack integrity (hashes).")
    pack_verify.add_argument("--suite", required=True, help="Pack zip file path")
    pack_verify.set_defaults(func=_cmd_pack_verify)

    pack_sign = pack_sub.add_parser("sign", help="Sign a pack zip (detached signature JSON).")
    pack_sign.add_argument("--suite", required=True, help="Pack zip file path")
    pack_sign.add_argument("--private-key", required=True, help="Private key PEM file path")
    pack_sign.add_argument("--out", default="", help="Output signature file (default: stdout)")
    pack_sign.set_defaults(func=_cmd_pack_sign)

    pack_verify_sig = pack_sub.add_parser("verify-signature", help="Verify a pack signature.")
    pack_verify_sig.add_argument("--suite", required=True, help="Pack zip file path")
    pack_verify_sig.add_argument("--signature", required=True, help="Signature JSON file path")
    pack_verify_sig.add_argument("--public-key", required=True, help="Public key PEM file path")
    pack_verify_sig.set_defaults(func=_cmd_pack_verify_sig)

    run = sub.add_parser("run", help="Run a policy suite against predictions.")
    run.add_argument("--suite", required=True, help="Suite path (directory or zip)")
    run.add_argument("--predictions", required=True, help="Predictions JSONL (id+prediction)")
    run.add_argument(
        "--out", default="", help="Write the report (a v1 envelope, canonical JSON) to this path"
    )
    run.add_argument(
        "--patterns",
        action="append",
        default=[],
        metavar="FILE",
        help="JSON pattern file of custom PII/secret detectors; repeat for several files",
    )
    run.add_argument(
        "--refusal-judge",
        default="",
        metavar="MODEL",
        help="Judge expected refusals with this LiteLLM model instead of keywords "
        "(needs the [judge] extra; off by default)",
    )
    run.add_argument(
        "--legacy-json",
        action="store_true",
        help="Write the pre-1.0 report shape instead of the envelope (deprecated)",
    )
    run.add_argument(
        "--format", choices=["json", "table"], default="json", help="Output format (default: json)"
    )
    run.add_argument(
        "--signature",
        default="",
        help="Detached signature JSON; the pack must verify before it runs (needs --public-key)",
    )
    run.add_argument(
        "--public-key", default="", help="Ed25519 public key PEM used with --signature"
    )
    run.set_defaults(func=_cmd_run)

    compare = sub.add_parser("compare", help="Compare candidate report against baseline report.")
    compare.add_argument("--baseline", required=True, help="Baseline report JSON file path")
    compare.add_argument("--candidate", required=True, help="Candidate report JSON file path")
    compare.add_argument(
        "--out", default="", help="Write the comparison (a v1 envelope) to this path"
    )
    compare.add_argument(
        "--format", choices=["json", "table"], default="json", help="Output format (default: json)"
    )
    compare.add_argument(
        "--max-fail-rate-increase-pct",
        default="0.0",
        help="Max fail rate increase %% (default: 0.0)",
    )
    compare.add_argument(
        "--max-pii-hits-increase",
        default="0",
        help="Max PII hits increase (default: 0)",
    )
    compare.add_argument(
        "--max-secret-hits-increase",
        default="0",
        help="Max secret hits increase (default: 0)",
    )
    compare.set_defaults(func=_cmd_compare)

    imp = sub.add_parser(
        "import",
        help="Import garak, promptfoo or PyRIT results as findings and gate on them.",
    )
    imp.add_argument("--source", required=True, choices=SOURCES, help="Tool that wrote --input")
    imp.add_argument(
        "--input",
        required=True,
        help="garak report.jsonl, promptfoo results.json, or PyRIT memory .db / score JSON",
    )
    imp.add_argument("--out", default="", help="Write the findings (a v1 envelope) to this path")
    imp.add_argument(
        "--max-failures",
        type=int,
        default=0,
        help="Failed plus unjudged findings allowed before the gate fails (default: 0)",
    )
    imp.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="garak detector / PyRIT float score at or above which a finding fails (default: 0.5)",
    )
    imp.add_argument(
        "--max-text-chars",
        type=int,
        default=DEFAULT_MAX_TEXT,
        help="Truncate prompt and output text in findings (0 = keep all; default: 500)",
    )
    imp.add_argument("--categories", default="", help="Custom category rules JSON")
    imp.add_argument(
        "--format", choices=["json", "table"], default="json", help="Stdout summary format"
    )
    imp.set_defaults(func=_cmd_import)

    ev = sub.add_parser(
        "evidence",
        help="Summarize run and import reports as evidence per control (OWASP, NIST, EU AI Act).",
    )
    ev.add_argument(
        "--report",
        action="append",
        required=True,
        help="A policy.run or policy.import envelope; repeat for several reports",
    )
    ev.add_argument("--out", default="", help="Write the evidence (a v1 envelope) to this path")
    ev.add_argument("--controls", default="", help="Custom control mapping JSON")
    ev.add_argument("--categories", default="", help="Custom category rules JSON")
    ev.add_argument(
        "--max-failures",
        type=int,
        default=0,
        help="Failed plus unjudged results allowed before the gate fails (default: 0)",
    )
    ev.add_argument(
        "--format",
        choices=["json", "table", "markdown"],
        default="json",
        help="Stdout format: summary as json or table, or a markdown evidence table",
    )
    ev.set_defaults(func=_cmd_evidence)

    validate_report = sub.add_parser(
        "validate-report", help="Validate a policy report JSON has the expected shape."
    )
    validate_report.add_argument(
        "--report",
        required=True,
        help="Report JSON file path to validate",
    )
    validate_report.set_defaults(func=_cmd_validate_report)

    return p


def main(argv: list[str] | None = None) -> int:
    """Main entry point for CLI.

    Args:
        argv: Command line arguments (defaults to sys.argv)

    Returns:
        Exit code (0 = success, non-zero = error)
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)
    if args.log_format == "json":
        handler.setFormatter(_JSONLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
    logging.basicConfig(level=log_level, handlers=[handler])

    try:
        return int(args.func(args))
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"{type(e).__name__}: {e}")
        return EXIT_CLI_ERROR
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return EXIT_UNEXPECTED_ERROR
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(
            "\nAn unexpected error occurred. Please report this issue.",
            file=sys.stderr,
        )
        return EXIT_UNEXPECTED_ERROR
