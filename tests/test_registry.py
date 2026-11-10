from datetime import datetime, timezone
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber

from imgexpiry import registry
from imgexpiry.policy import parse_policy
from imgexpiry.predictor import Image

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def client():
    return boto3.client("ecr", region_name="us-west-2", aws_access_key_id="x", aws_secret_access_key="y")


def test_load_images_file():
    images = registry.load_images_file(FIXTURES / "describe-images.json")
    assert len(images) == 8
    assert images[0] == Image(
        digest="sha256:" + "1" * 64,
        pushed_at=datetime(2026, 10, 20, 14, 3, 11, 250000, tzinfo=timezone.utc),
        tags=("v1.3.0", "latest"),
    )
    assert images[4].tags == ()  # untagged image has no imageTags key


def test_load_policy_file_parses():
    rules = parse_policy(registry.load_policy_file(FIXTURES / "lifecycle-policy.json"))
    assert [r.priority for r in rules] == [1, 2, 3, 4]


@pytest.mark.parametrize("value", [
    "2026-10-20T14:03:11+00:00",
    "2026-10-20T14:03:11Z",
    datetime(2026, 10, 20, 14, 3, 11, tzinfo=timezone.utc),
    datetime(2026, 10, 20, 14, 3, 11),  # naive is treated as UTC
])
def test_timestamps_are_normalised_to_utc(value):
    assert registry._as_datetime(value) == datetime(2026, 10, 20, 14, 3, 11, tzinfo=timezone.utc)


def test_fetch_images_follows_pagination(client):
    def page(digest, token=None):
        resp = {"imageDetails": [{"imageDigest": digest, "imagePushedAt": datetime(2026, 1, 1, tzinfo=timezone.utc)}]}
        if token:
            resp["nextToken"] = token
        return resp

    with Stubber(client) as stub:
        stub.add_response("describe_images", page("sha256:a", "t1"), {"repositoryName": "imgexpiry-demo"})
        stub.add_response("describe_images", page("sha256:b"), {"repositoryName": "imgexpiry-demo", "nextToken": "t1"})
        images = registry.fetch_images(client, "imgexpiry-demo")
    assert [i.digest for i in images] == ["sha256:a", "sha256:b"]


def test_fetch_policy_returns_text(client):
    text = registry.load_policy_file(FIXTURES / "lifecycle-policy.json")
    with Stubber(client) as stub:
        stub.add_response("get_lifecycle_policy", {"lifecyclePolicyText": text}, {"repositoryName": "imgexpiry-demo"})
        assert registry.fetch_policy(client, "imgexpiry-demo") == text


def test_fetch_policy_returns_none_when_repo_has_no_policy(client):
    with Stubber(client) as stub:
        stub.add_client_error("get_lifecycle_policy", service_error_code="LifecyclePolicyNotFoundException")
        assert registry.fetch_policy(client, "imgexpiry-demo") is None
