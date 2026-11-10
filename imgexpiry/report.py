"""Join in-use images with expiry predictions, then format the result.

One finding per distinct image: the same image used by several workloads
(for example a Deployment pod and a CronJob template) is one row.

An in-use image with no digest (CronJob template, pod that hasn't started)
is resolved by looking its tag up in the registry's image list. An image
that is not in the registry at all is reported as already deleted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from imgexpiry.predictor import EXPIRES_AFTER_PUSHES, EXPIRES_AT, SAFE

MISSING = "missing"

NOTE = (
    "Predictions assume no new pushes and no policy changes. ECR can take up to "
    "24 hours after an image meets its expiry criteria to delete it."
)


@dataclass
class Finding:
    repository: str
    tag: str
    digest: str | None
    status: str
    expires_at: datetime | None = None
    pushes: int | None = None
    workloads: list = field(default_factory=list)


def build_findings(in_use: list, images: list, predictions: list, repo: str) -> list:
    """Return findings for `repo`, most urgent first.

    `in_use` are inventory.InUse records, `images` the repository's images and
    `predictions` the predictor's output for those images.
    """
    by_tag = {tag: image.digest for image in images for tag in image.tags}
    known = {p.digest: p for p in predictions}

    findings = {}
    for item in in_use:
        if item.repository != repo:
            continue
        digest = item.digest or by_tag.get(item.tag)
        pred = known.get(digest)
        key = digest if pred else (MISSING, item.digest, item.tag)
        if key not in findings:
            findings[key] = _new_finding(item, digest, pred)
        workload = f"{item.namespace}/{item.workload_kind}/{item.workload_name}"
        if workload not in findings[key].workloads:
            findings[key].workloads.append(workload)
    return sorted(findings.values(), key=_urgency)


def _new_finding(item, digest, pred) -> Finding:
    if pred is None:
        return Finding(item.repository, item.tag, item.digest, MISSING)
    return Finding(item.repository, item.tag, digest, pred.status, pred.expires_at, pred.pushes)


def _urgency(f: Finding):
    """Missing first, then by expiry date, then by pushes remaining, safe last."""
    if f.status == MISSING:
        return (0, 0, f.tag)
    if f.status == EXPIRES_AT:
        return (1, f.expires_at.timestamp(), f.tag)
    if f.status == EXPIRES_AFTER_PUSHES:
        return (2, f.pushes, f.tag)
    return (3, 0, f.tag)


def at_risk(findings: list, warn_days: int, now: datetime) -> list:
    """Findings already deleted, or due within `warn_days` (including overdue)."""
    deadline = now + timedelta(days=warn_days)
    return [
        f for f in findings
        if f.status == MISSING or (f.status == EXPIRES_AT and f.expires_at <= deadline)
    ]


def exit_code(findings: list, warn_days: int, now: datetime) -> int:
    """1 if any in-use image is at risk, else 0.

    Images that expire "after N pushes" are not at risk: whether that happens
    soon depends on future pushes the tool can't see.
    """
    return 1 if at_risk(findings, warn_days, now) else 0


def describe(f: Finding, now: datetime) -> str:
    if f.status == MISSING:
        return "already deleted from ECR"
    if f.status == SAFE:
        return "safe"
    if f.status == EXPIRES_AFTER_PUSHES:
        return f"after {f.pushes} more push{'' if f.pushes == 1 else 'es'}"
    delta = f.expires_at - now
    if delta <= timedelta(0):
        return "due now" if f.expires_at == now else f"overdue since {f.expires_at:%Y-%m-%d}"
    return f"{f.expires_at:%Y-%m-%d} (in {delta.days}d)" if delta.days else f"{f.expires_at:%Y-%m-%d} (<1d)"


def format_report(findings: list, now: datetime, ignored: int = 0) -> str:
    if not findings:
        lines = ["No running images from this repository."]
    else:
        rows = [["IMAGE", "DIGEST", "EXPIRES", "WORKLOADS"]]
        for f in findings:
            rows.append([_label(f), f.digest[:19] if f.digest else "-", describe(f, now), str(len(f.workloads))])
        lines = _table(rows)
    lines.append("")
    if ignored:
        lines.append(f"Ignored {ignored} container{'' if ignored == 1 else 's'} using non-ECR images.")
    lines.append(NOTE)
    return "\n".join(lines)


def _label(f: Finding) -> str:
    return f"{f.repository}:{f.tag}" if f.tag else f"{f.repository}@{(f.digest or '')[:19]}"


def _table(rows: list) -> list:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return ["  ".join(cell.ljust(w) for cell, w in zip(r, widths)).rstrip() for r in rows]
