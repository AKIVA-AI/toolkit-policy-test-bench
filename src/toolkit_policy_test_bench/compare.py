from __future__ import annotations

from dataclasses import dataclass

from .report import PolicyReport


@dataclass(frozen=True)
class CompareBudget:
    max_fail_rate_increase_pct: float = 0.0
    max_pii_hits_increase: int = 0
    max_secret_hits_increase: int = 0


def compare_reports(
    *, baseline: PolicyReport, candidate: PolicyReport, budget: CompareBudget
) -> dict:
    base_fail = float(baseline.summary.get("fail_rate", 0.0))
    cand_fail = float(candidate.summary.get("fail_rate", 0.0))

    base_pii = int(baseline.summary.get("pii_total_hits", 0))
    cand_pii = int(candidate.summary.get("pii_total_hits", 0))

    base_sec = int(baseline.summary.get("secret_total_hits", 0))
    cand_sec = int(candidate.summary.get("secret_total_hits", 0))

    fail_increase_pct = (cand_fail - base_fail) * 100.0
    pii_increase = cand_pii - base_pii
    sec_increase = cand_sec - base_sec

    failures: list[str] = []
    if fail_increase_pct > budget.max_fail_rate_increase_pct:
        failures.append("fail_rate_regression")
    if pii_increase > budget.max_pii_hits_increase:
        failures.append("pii_regression")
    if sec_increase > budget.max_secret_hits_increase:
        failures.append("secret_regression")

    return {
        "passed": not failures,
        "failures": failures,
        "baseline": {
            "fail_rate": base_fail,
            "pii_total_hits": base_pii,
            "secret_total_hits": base_sec,
        },
        "candidate": {
            "fail_rate": cand_fail,
            "pii_total_hits": cand_pii,
            "secret_total_hits": cand_sec,
        },
        "deltas": {
            "fail_rate_increase_pct": fail_increase_pct,
            "pii_hits_increase": pii_increase,
            "secret_hits_increase": sec_increase,
        },
        "budget": {
            "max_fail_rate_increase_pct": budget.max_fail_rate_increase_pct,
            "max_pii_hits_increase": budget.max_pii_hits_increase,
            "max_secret_hits_increase": budget.max_secret_hits_increase,
        },
    }
