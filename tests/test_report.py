import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from imgexpiry import registry
from imgexpiry.inventory import from_kubectl_json
from imgexpiry.policy import parse_policy
from imgexpiry.predictor import EXPIRES_AFTER_PUSHES, EXPIRES_AT, SAFE, predict
from imgexpiry.report import (
    MISSING, Finding, _urgency, at_risk, build_findings, describe, exit_code, format_report,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)


def d(char):
    return "sha256:" + char * 64


@pytest.fixture(scope="module")
def world():
    images = registry.load_images_file(FIXTURES / "describe-images.json")
    rules = parse_policy(registry.load_policy_file(FIXTURES / "lifecycle-policy.json"))
    inventory = from_kubectl_json(json.loads((FIXTURES / "k8s-items.json").read_text()))
    return inventory, images, predict(rules, images, NOW)


def findings_for(world, repo="demo"):
    inventory, images, predictions = world
    return build_findings(inventory.images, images, predictions, repo)


# --- join --------------------------------------------------------------------

def test_fixture_findings_are_ordered_most_urgent_first(world):
    fs = findings_for(world)
    assert [(f.tag, f.status, f.pushes) for f in fs] == [
        ("v1.0.0", EXPIRES_AT, None),             # beyond the keep-3 limit: due now
        ("v1.1.0", EXPIRES_AFTER_PUSHES, 1),
        ("v1.2.0", EXPIRES_AFTER_PUSHES, 2),
        ("v1.3.0", EXPIRES_AFTER_PUSHES, 3),
    ]


def test_tag_only_inventory_entries_are_resolved_through_the_registry(world):
    by_tag = {f.tag: f for f in findings_for(world)}
    assert by_tag["v1.2.0"].digest == d("2")   # pending pod, no digest of its own


def test_same_image_from_several_workloads_is_one_finding(world):
    by_tag = {f.tag: f for f in findings_for(world)}
    assert by_tag["v1.0.0"].workloads == ["shop/Deployment/worker", "shop/CronJob/nightly"]


def test_other_repositories_are_filtered_out(world):
    assert findings_for(world, repo="something-else") == []


def test_digest_not_in_registry_is_missing(world):
    inventory, images, predictions = world
    gone = replace(inventory.images[0], digest=d("f"), tag="v0.9.0")
    fs = build_findings([gone], images, predictions, "demo")
    assert [(f.status, f.digest, f.tag) for f in fs] == [(MISSING, d("f"), "v0.9.0")]


def test_tag_not_in_registry_is_missing(world):
    inventory, images, predictions = world
    gone = replace(inventory.images[0], digest=None, tag="v0.9.0")
    assert build_findings([gone], images, predictions, "demo")[0].status == MISSING


def test_missing_sorts_before_everything(world):
    inventory, images, predictions = world
    gone = replace(inventory.images[0], digest=None, tag="v0.9.0")
    fs = build_findings(inventory.images + [gone], images, predictions, "demo")
    assert fs[0].status == MISSING


def test_urgency_order():
    ordered = [
        finding(MISSING),
        finding(EXPIRES_AT, expires_at=NOW - timedelta(days=1)),
        finding(EXPIRES_AT, expires_at=NOW + timedelta(days=1)),
        finding(EXPIRES_AFTER_PUSHES, pushes=1),
        finding(EXPIRES_AFTER_PUSHES, pushes=5),
        finding(SAFE),
    ]
    assert sorted(reversed(ordered), key=_urgency) == ordered


# --- exit code ---------------------------------------------------------------

def finding(status, **kw):
    return Finding("demo", "v1", d("1"), status, **kw)


@pytest.mark.parametrize("name, f, warn_days, expected", [
    ("missing is always at risk", finding(MISSING), 0, 1),
    ("overdue is at risk", finding(EXPIRES_AT, expires_at=NOW - timedelta(days=3)), 0, 1),
    ("due inside the window", finding(EXPIRES_AT, expires_at=NOW + timedelta(days=13)), 14, 1),
    ("due exactly at the boundary", finding(EXPIRES_AT, expires_at=NOW + timedelta(days=14)), 14, 1),
    ("due just outside the window", finding(EXPIRES_AT, expires_at=NOW + timedelta(days=15)), 14, 0),
    ("push-count expiry is not judged", finding(EXPIRES_AFTER_PUSHES, pushes=1), 14, 0),
    ("safe", finding(SAFE), 14, 0),
], ids=lambda v: v if isinstance(v, str) else "")
def test_exit_code(name, f, warn_days, expected):
    assert exit_code([f], warn_days, NOW) == expected


def test_exit_code_with_no_findings_is_zero():
    assert exit_code([], 14, NOW) == 0


def test_at_risk_returns_only_risky_findings():
    risky = finding(MISSING)
    assert at_risk([risky, finding(SAFE)], 14, NOW) == [risky]


# --- formatting --------------------------------------------------------------

@pytest.mark.parametrize("f, expected", [
    (finding(MISSING), "already deleted from ECR"),
    (finding(SAFE), "safe"),
    (finding(EXPIRES_AFTER_PUSHES, pushes=1), "after 1 more push"),
    (finding(EXPIRES_AFTER_PUSHES, pushes=3), "after 3 more pushes"),
    (finding(EXPIRES_AT, expires_at=NOW), "due now"),
    (finding(EXPIRES_AT, expires_at=NOW - timedelta(days=2)), "overdue since 2026-11-07"),
    (finding(EXPIRES_AT, expires_at=NOW + timedelta(days=10)), "2026-11-19 (in 10d)"),
    (finding(EXPIRES_AT, expires_at=NOW + timedelta(hours=5)), "2026-11-09 (<1d)"),
])
def test_describe(f, expected):
    assert describe(f, NOW) == expected


def test_format_report_table(world):
    inventory, _, _ = world
    out = format_report(findings_for(world), NOW, ignored=inventory.ignored)
    lines = out.splitlines()
    assert lines[0].split() == ["IMAGE", "DIGEST", "EXPIRES", "WORKLOADS"]
    assert lines[1].split()[:2] == ["demo:v1.0.0", d("4")[:19]]
    assert "due now" in lines[1] and lines[1].endswith("2")
    assert "after 1 more push" in lines[2]
    assert "Ignored 1 container using non-ECR images." in out
    assert "no new pushes" in out


def test_format_report_with_no_findings():
    out = format_report([], NOW)
    assert out.startswith("No running images from this repository.")
    assert "Ignored" not in out


def test_digest_only_reference_is_labelled_by_digest():
    out = format_report([Finding("demo", "", d("a"), SAFE, workloads=["n/Pod/p"])], NOW)
    assert "demo@" + d("a")[:19] in out
