"""Inventory parsing against recorded Kubernetes JSON.

The live cluster path (`list_inventory`) is an integration concern: it needs
a kind cluster and is not covered here.
"""
import json
from pathlib import Path

import pytest

from imgexpiry.inventory import from_items, from_kubectl_json, parse_image_ref

FIXTURES = Path(__file__).parent.parent / "fixtures"
HOST = "340754910639.dkr.ecr.us-west-2.amazonaws.com"
DIGEST = "sha256:" + "1" * 64


def d(char):
    return "sha256:" + char * 64


@pytest.fixture(scope="module")
def inventory():
    return from_kubectl_json(json.loads((FIXTURES / "k8s-items.json").read_text()))


def by_container(inventory):
    return {(i.workload_name, i.container): i for i in inventory.images}


@pytest.mark.parametrize("ref, expected", [
    (f"{HOST}/imgexpiry-demo:v1", (HOST, "imgexpiry-demo", "v1", None)),
    (f"{HOST}/team/imgexpiry-demo:v1", (HOST, "team/imgexpiry-demo", "v1", None)),
    (f"{HOST}/imgexpiry-demo", (HOST, "imgexpiry-demo", "latest", None)),
    (f"{HOST}/imgexpiry-demo@{DIGEST}", (HOST, "imgexpiry-demo", "", DIGEST)),
    (f"{HOST}/imgexpiry-demo:v1@{DIGEST}", (HOST, "imgexpiry-demo", "v1", DIGEST)),
    ("340754910639.dkr.ecr-fips.us-gov-west-1.amazonaws.com/imgexpiry-demo:v1",
     ("340754910639.dkr.ecr-fips.us-gov-west-1.amazonaws.com", "imgexpiry-demo", "v1", None)),
    ("nginx:1.27", None),
    ("ghcr.io/org/app:1", None),
    ("123.dkr.ecr.us-west-2.amazonaws.com/imgexpiry-demo:v1", None),  # account id must be 12 digits
])
def test_parse_image_ref(ref, expected):
    assert parse_image_ref(ref) == expected


def test_pod_digest_comes_from_container_status(inventory):
    web = by_container(inventory)[("web", "app")]
    assert (web.repository, web.tag, web.digest) == ("imgexpiry-demo", "v1.3.0", DIGEST)
    assert (web.namespace, web.workload_kind) == ("shop", "Deployment")


def test_replicaset_owner_is_reported_as_its_deployment(inventory):
    assert by_container(inventory)[("worker", "worker")].workload_kind == "Deployment"


def test_init_containers_are_included(inventory):
    migrate = by_container(inventory)[("worker", "migrate")]
    assert (migrate.tag, migrate.digest) == ("v1.1.0", "sha256:" + "3" * 64)


def test_pod_without_status_is_unresolved(inventory):
    pending = by_container(inventory)[("pending-0", "app")]
    assert pending.digest is None
    assert pending.tag == "v1.2.0"
    assert pending.workload_kind == "Pod"  # no owner


def test_cronjob_template_is_included_without_digest(inventory):
    nightly = by_container(inventory)[("nightly", "report")]
    assert (nightly.workload_kind, nightly.tag, nightly.digest) == ("CronJob", "v1.0.0", None)


def test_other_registries_are_ignored_and_counted(inventory):
    assert inventory.ignored == 1
    assert ("web", "proxy") not in by_container(inventory)


def test_standalone_pod_running_a_release_candidate(inventory):
    runner = by_container(inventory)[("rc-runner", "runner")]
    assert (runner.workload_kind, runner.tag, runner.digest) == ("Pod", "build-7-rc2", d("7"))


def test_total_images(inventory):
    assert len(inventory.images) == 6


def test_digest_pinned_spec_is_used_when_status_is_missing():
    pod = {"kind": "Pod", "metadata": {"name": "p", "namespace": "n"},
           "spec": {"containers": [{"name": "c", "image": f"{HOST}/imgexpiry-demo@{DIGEST}"}]}}
    assert from_items([pod]).images[0].digest == DIGEST


def test_bare_config_digest_image_id_is_not_trusted():
    pod = {"kind": "Pod", "metadata": {"name": "p", "namespace": "n"},
           "spec": {"containers": [{"name": "c", "image": f"{HOST}/imgexpiry-demo:v1"}]},
           "status": {"containerStatuses": [{"name": "c", "imageID": DIGEST}]}}
    assert from_items([pod]).images[0].digest is None


def test_unknown_kinds_are_skipped():
    assert from_items([{"kind": "Service", "metadata": {"name": "s"}}]).images == []


def test_empty_cluster():
    inv = from_kubectl_json({"items": []})
    assert (inv.images, inv.ignored) == ([], 0)
