"""Predict which images an ECR lifecycle policy will expire, and when.

Pure functions, no I/O. Semantics follow the ECR docs:

- Every image is owned by the highest-priority rule whose tag selection it
  matches. Only the owning rule can expire it, so an image matching a
  higher-priority rule's tags is protected from lower-priority rules even if
  that rule would keep it.
- A rule counts every image matching its tag selection when ranking for
  `imageCountMoreThan`, including images owned by higher-priority rules
  (docs: rules "can still identify them as if they haven't been expired").
  This reading is not stated outright; verify it with the lifecycle preview.

What it cannot know: future pushes, policy changes, and ECR's up to 24 hour
delay between meeting the criteria and actually expiring the image.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Union

from imgexpiry.policy import Rule

SAFE = "safe"
EXPIRES_AT = "expires_at"
EXPIRES_AFTER_PUSHES = "expires_after_pushes"


@dataclass(frozen=True)
class Image:
    digest: str
    pushed_at: datetime
    tags: tuple = ()


@dataclass(frozen=True)
class Prediction:
    digest: str
    status: str
    expires_at: Union[datetime, None] = None
    pushes: Union[int, None] = None
    rule_priority: Union[int, None] = None


def predict(rules: list, images: list, now: datetime) -> list:
    """Return one Prediction per image, in the order of `images`.

    `rules` must be sorted by priority, highest priority first (as returned
    by parse_policy). `now` is used when an image is already past its limit.
    """
    ranks = {r.priority: _ranks(r, images) for r in rules if r.count_type == "imageCountMoreThan"}
    return [_predict_one(rules, image, now, ranks) for image in images]


def _predict_one(rules: list, image: Image, now: datetime, ranks: dict) -> Prediction:
    owner = next((r for r in rules if _matches(r, image)), None)
    if owner is None:
        return Prediction(image.digest, SAFE)

    if owner.count_type == "sinceImagePushed":
        expires_at = image.pushed_at + timedelta(days=owner.count_number)
        return Prediction(image.digest, EXPIRES_AT, expires_at=expires_at, rule_priority=owner.priority)

    rank = ranks[owner.priority][image.digest]
    if rank >= owner.count_number:
        return Prediction(image.digest, EXPIRES_AT, expires_at=now, rule_priority=owner.priority)
    return Prediction(
        image.digest, EXPIRES_AFTER_PUSHES, pushes=owner.count_number - rank, rule_priority=owner.priority
    )


def _ranks(rule: Rule, images: list) -> dict:
    """Rank images matching the rule's tags, newest first (0 = newest).

    Ties on push time are broken by digest so the output is deterministic;
    how ECR orders ties is not documented.
    """
    matching = [i for i in images if _matches(rule, i)]
    matching.sort(key=lambda i: (-i.pushed_at.timestamp(), i.digest))
    return {image.digest: rank for rank, image in enumerate(matching)}


def _matches(rule: Rule, image: Image) -> bool:
    if rule.tag_status == "any":
        return True
    if rule.tag_status == "untagged":
        return not image.tags
    if not image.tags:
        return False
    if rule.tag_prefixes:
        return all(any(t.startswith(p) for t in image.tags) for p in rule.tag_prefixes)
    return all(any(_pattern(p).fullmatch(t) for t in image.tags) for p in rule.tag_patterns)


def _pattern(pattern: str) -> re.Pattern:
    return re.compile(".*".join(re.escape(part) for part in pattern.split("*")))
