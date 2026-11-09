"""Kubernetes side: find the ECR images that workloads use.

Sources:
- Pods: containers and init containers. The digest comes from the container
  status `imageID`, since tags are mutable. A pod whose container hasn't
  started has no status, so its digest is None (unresolved).
- CronJobs: the pod template of each CronJob, because every run pulls its
  image again. There is no pod, so the digest is None and the tag must be
  resolved against ECR by the caller (the next run pulls whatever the tag
  points to at that time).

Everything parses plain dicts in the shape of `kubectl get -o json`, so it
can be tested from fixtures without a cluster.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Union

_ECR_REF = re.compile(
    r"^(?P<registry>\d{12}\.dkr\.ecr(?:-fips)?\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?)"
    r"/(?P<repository>[^:@]+)"
    r"(?::(?P<tag>[^@]+))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)
_IMAGE_ID_DIGEST = re.compile(r"@(sha256:[0-9a-f]{64})$")


@dataclass(frozen=True)
class InUse:
    registry: str
    repository: str
    tag: str
    digest: Union[str, None]
    namespace: str
    workload_kind: str
    workload_name: str
    container: str


@dataclass
class Inventory:
    images: list = field(default_factory=list)
    ignored: int = 0  # containers using images from other registries


def list_inventory(context: Union[str, None] = None, namespace: Union[str, None] = None) -> Inventory:
    """Read pods and cronjobs from the cluster behind `context`."""
    from kubernetes import client, config

    api_client = config.new_client_from_config(context=context)
    core, batch = client.CoreV1Api(api_client), client.BatchV1Api(api_client)
    if namespace:
        responses = {"Pod": core.list_namespaced_pod(namespace), "CronJob": batch.list_namespaced_cron_job(namespace)}
    else:
        responses = {"Pod": core.list_pod_for_all_namespaces(), "CronJob": batch.list_cron_job_for_all_namespaces()}

    items = []
    for kind, response in responses.items():
        for item in api_client.sanitize_for_serialization(response)["items"]:
            items.append({**item, "kind": kind})
    return from_items(items)


def from_items(items: list) -> Inventory:
    """Build an inventory from Pod and CronJob dicts (each with a `kind`)."""
    inventory = Inventory()
    for item in items:
        if item.get("kind") == "Pod":
            found = _from_pod(item)
        elif item.get("kind") == "CronJob":
            found = _from_cronjob(item)
        else:
            continue
        inventory.images.extend(found[0])
        inventory.ignored += found[1]
    return inventory


def from_kubectl_json(doc: dict) -> Inventory:
    """Build an inventory from `kubectl get pods,cronjobs -A -o json`."""
    return from_items(doc.get("items", []))


def parse_image_ref(ref: str):
    """Split an ECR image reference into (registry, repository, tag, digest), or None if not ECR."""
    m = _ECR_REF.match(ref)
    if not m:
        return None
    return m["registry"], m["repository"], m["tag"] or ("" if m["digest"] else "latest"), m["digest"]


def _from_pod(pod: dict):
    meta, spec, status = pod["metadata"], pod.get("spec", {}), pod.get("status", {})
    kind, name = _pod_workload(meta)
    statuses = {s["name"]: s for s in status.get("containerStatuses", []) + status.get("initContainerStatuses", [])}

    containers = spec.get("containers", []) + spec.get("initContainers", [])
    return _collect(
        containers, meta.get("namespace", "default"), kind, name,
        image_id=lambda c: statuses.get(c["name"], {}).get("imageID"),
    )


def _from_cronjob(cronjob: dict):
    meta = cronjob["metadata"]
    pod_spec = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
    return _collect(containers, meta.get("namespace", "default"), "CronJob", meta["name"], image_id=lambda c: None)


def _collect(containers: list, namespace: str, kind: str, name: str, image_id):
    images, ignored = [], 0
    for c in containers:
        ref = parse_image_ref(c["image"])
        if ref is None:
            ignored += 1
            continue
        registry, repository, tag, spec_digest = ref
        images.append(InUse(
            registry=registry,
            repository=repository,
            tag=tag,
            digest=_digest_from_image_id(image_id(c)) or spec_digest,
            namespace=namespace,
            workload_kind=kind,
            workload_name=name,
            container=c["name"],
        ))
    return images, ignored


def _digest_from_image_id(image_id: Union[str, None]) -> Union[str, None]:
    """Only trust an imageID that carries a manifest digest after '@'.

    A bare `sha256:...` imageID (some runtimes) is the image config digest,
    which ECR does not know about.
    """
    m = _IMAGE_ID_DIGEST.search(image_id or "")
    return m.group(1) if m else None


def _pod_workload(meta: dict):
    """Return (kind, name) of the pod's controller.

    A ReplicaSet named `<deployment>-<hash>` is reported as its Deployment.
    That is a naming heuristic: a standalone ReplicaSet with a dash in its
    name would be mislabeled.
    """
    owner = next((o for o in meta.get("ownerReferences", []) if o.get("controller")), None)
    if owner is None:
        return "Pod", meta["name"]
    if owner["kind"] == "ReplicaSet" and "-" in owner["name"]:
        return "Deployment", owner["name"].rsplit("-", 1)[0]
    return owner["kind"], owner["name"]
