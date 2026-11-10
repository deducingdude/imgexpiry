import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from imgexpiry import cli, registry

FIXTURES = Path(__file__).parent.parent / "fixtures"
NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)

FIXTURE_ARGS = [
    "--repo", "imgexpiry-demo",
    "--policy-file", str(FIXTURES / "lifecycle-policy.json"),
    "--images-file", str(FIXTURES / "describe-images.json"),
    "--inventory-file", str(FIXTURES / "k8s-items.json"),
]


def run(capsys, *args):
    code = cli.main(list(args), now=NOW)
    out = capsys.readouterr()
    return code, out.out, out.err


def only_pod_inventory(tmp_path, keep_name):
    """Inventory with just one of the fixture pods."""
    items = json.loads((FIXTURES / "k8s-items.json").read_text())["items"]
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"items": [i for i in items if i["metadata"]["name"].startswith(keep_name)]}))
    return str(path)


def test_at_risk_exits_1_and_prints_report(capsys):
    code, out, _ = run(capsys, *FIXTURE_ARGS)
    assert code == cli.AT_RISK
    assert "imgexpiry-demo:v1.0.0" in out and "due now" in out
    assert "2 images at risk" in out


def test_nothing_at_risk_exits_0(capsys, tmp_path):
    args = ["--repo", "imgexpiry-demo", "--policy-file", str(FIXTURES / "lifecycle-policy.json"),
            "--images-file", str(FIXTURES / "describe-images.json"),
            "--inventory-file", only_pod_inventory(tmp_path, "web")]
    code, out, _ = run(capsys, *args)
    assert code == cli.OK
    assert "after 3 more pushes" in out
    assert "at risk" not in out


def test_warn_days_is_respected(capsys, tmp_path):
    # The untagged image was pushed 2026-11-03 12:00, so the 7 day rule expires it
    # 2026-11-10 12:00: 1.5 days after NOW.
    items = [{"kind": "Pod", "metadata": {"name": "p", "namespace": "n"},
              "spec": {"containers": [{"name": "c", "image": f"340754910639.dkr.ecr.us-west-2.amazonaws.com/imgexpiry-demo@sha256:{'5' * 64}"}]}}]
    inv = tmp_path / "inv.json"
    inv.write_text(json.dumps({"items": items}))
    base = ["--repo", "imgexpiry-demo", "--policy-file", str(FIXTURES / "lifecycle-policy.json"),
            "--images-file", str(FIXTURES / "describe-images.json"), "--inventory-file", str(inv)]
    assert run(capsys, *base, "--warn-days", "1")[0] == cli.OK
    assert run(capsys, *base, "--warn-days", "2")[0] == cli.AT_RISK


def test_repo_is_required(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 2


@pytest.mark.parametrize("flag, value", [
    ("--policy-file", "does-not-exist.json"),
    ("--images-file", "does-not-exist.json"),
    ("--inventory-file", "does-not-exist.json"),
])
def test_missing_input_file_is_an_error(capsys, flag, value):
    args = FIXTURE_ARGS + [flag, value]  # later flag wins
    code, out, err = run(capsys, *args)
    assert code == cli.ERROR
    assert err.startswith("error:") and out == ""


def test_invalid_policy_is_an_error(capsys, tmp_path):
    bad = tmp_path / "policy.json"
    bad.write_text('{"rules": [{"rulePriority": 1}]}')
    code, _, err = run(capsys, *FIXTURE_ARGS, "--policy-file", str(bad))
    assert code == cli.ERROR
    assert "rule 1" in err


def test_unsupported_policy_feature_is_an_error(capsys, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"rules": [{
        "rulePriority": 1,
        "selection": {"tagStatus": "any", "countType": "sinceImagePulled", "countUnit": "days", "countNumber": 30},
        "action": {"type": "transition"},
    }]}))
    code, _, err = run(capsys, *FIXTURE_ARGS, "--policy-file", str(policy))
    assert code == cli.ERROR and "not supported" in err


def test_repository_without_policy_warns_and_nothing_expires(capsys, monkeypatch):
    monkeypatch.setattr(registry, "ecr_client", lambda profile, region: object())
    monkeypatch.setattr(registry, "fetch_policy", lambda client, repo: None)
    args = [a for a in FIXTURE_ARGS if a not in ("--policy-file", str(FIXTURES / "lifecycle-policy.json"))]
    code, out, err = run(capsys, *args)
    assert code == cli.OK
    assert "no lifecycle policy" in err
    assert "safe" in out
    assert "more push" not in out and "due now" not in out


def test_aws_is_not_contacted_when_all_inputs_are_files(capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("AWS client created")
    monkeypatch.setattr(registry, "ecr_client", boom)
    assert run(capsys, *FIXTURE_ARGS)[0] == cli.AT_RISK
