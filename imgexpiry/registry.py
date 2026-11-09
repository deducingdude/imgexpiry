"""ECR side: fetch a repository's lifecycle policy and images.

Thin wrapper over boto3, plus loaders for recorded fixtures (the output of
`aws ecr describe-images`, and a plain lifecycle policy document).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Union

import boto3

from imgexpiry.predictor import Image


def ecr_client(profile: Union[str, None] = None, region: Union[str, None] = None):
    return boto3.Session(profile_name=profile, region_name=region).client("ecr")


def fetch_policy(client, repo: str) -> Union[str, None]:
    """Return the repository's lifecycle policy text, or None if it has none."""
    try:
        return client.get_lifecycle_policy(repositoryName=repo)["lifecyclePolicyText"]
    except client.exceptions.LifecyclePolicyNotFoundException:
        return None


def fetch_images(client, repo: str) -> list:
    pages = client.get_paginator("describe_images").paginate(repositoryName=repo)
    return images_from_details(d for page in pages for d in page["imageDetails"])


def load_policy_file(path: str) -> str:
    with open(path) as f:
        return f.read()


def load_images_file(path: str) -> list:
    with open(path) as f:
        return images_from_details(json.load(f)["imageDetails"])


def images_from_details(details) -> list:
    """Convert `imageDetails` entries (boto3 or CLI JSON) into Images."""
    return [
        Image(
            digest=d["imageDigest"],
            pushed_at=_as_datetime(d["imagePushedAt"]),
            tags=tuple(d.get("imageTags", [])),
        )
        for d in details
    ]


def _as_datetime(value: Union[str, datetime]) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value
