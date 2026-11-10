"""ECR lifecycle policy model and parsing.

Validation follows the ECR docs (https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html).

Rules that archive images (`sinceImagePulled`, `sinceImageTransitioned`, `transition`
actions) are out of scope and rejected with UnsupportedPolicyError.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

TAG_STATUSES = ("tagged", "untagged", "any")
SUPPORTED_COUNT_TYPES = ("imageCountMoreThan", "sinceImagePushed")
ARCHIVE_COUNT_TYPES = ("sinceImagePulled", "sinceImageTransitioned")
MAX_PATTERN_WILDCARDS = 4


class PolicyError(ValueError):
    """The policy is not valid according to the ECR docs."""


class UnsupportedPolicyError(PolicyError):
    """The policy is valid, but uses a feature this tool does not predict."""


@dataclass(frozen=True)
class Rule:
    priority: int
    tag_status: str
    count_type: str
    count_number: int
    tag_prefixes: tuple = ()
    tag_patterns: tuple = ()
    count_unit: str | None = None
    description: str = ""


def parse_policy(policy: str | dict) -> list:
    """Parse a lifecycle policy (JSON text or decoded dict) into rules.

    Returns the rules sorted by priority, highest priority (lowest number) first.
    """
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError as e:
            raise PolicyError(f"policy is not valid JSON: {e}") from e
    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise PolicyError("policy must be an object with a 'rules' list")

    rules = sorted((_parse_rule(r) for r in policy["rules"]), key=lambda r: r.priority)
    _check_rule_set(rules)
    return rules


def _parse_rule(raw: object) -> Rule:
    if not isinstance(raw, dict):
        raise PolicyError("each rule must be an object")
    priority = raw.get("rulePriority")
    if not _is_int(priority) or priority < 1:
        raise PolicyError(f"rulePriority must be a positive integer, got {priority!r}")

    where = f"rule {priority}"
    action = raw.get("action")
    action_type = action.get("type") if isinstance(action, dict) else None
    if action_type != "expire":
        if action_type == "transition":
            raise UnsupportedPolicyError(f"{where}: 'transition' actions are not supported")
        raise PolicyError(f"{where}: action type must be 'expire', got {action_type!r}")

    sel = raw.get("selection")
    if not isinstance(sel, dict):
        raise PolicyError(f"{where}: missing 'selection'")

    tag_status = sel.get("tagStatus")
    if tag_status not in TAG_STATUSES:
        raise PolicyError(f"{where}: tagStatus must be one of {TAG_STATUSES}, got {tag_status!r}")
    prefixes = _string_list(sel, "tagPrefixList", where)
    patterns = _string_list(sel, "tagPatternList", where)
    _check_tag_filters(tag_status, prefixes, patterns, where)

    count_type = sel.get("countType")
    if count_type in ARCHIVE_COUNT_TYPES:
        raise UnsupportedPolicyError(f"{where}: countType {count_type!r} is not supported")
    if count_type not in SUPPORTED_COUNT_TYPES:
        raise PolicyError(f"{where}: countType must be one of {SUPPORTED_COUNT_TYPES}, got {count_type!r}")
    count_number = sel.get("countNumber")
    if not _is_int(count_number) or count_number < 1:
        raise PolicyError(f"{where}: countNumber must be a positive integer, got {count_number!r}")
    count_unit = sel.get("countUnit")
    if count_type == "sinceImagePushed" and count_unit != "days":
        raise PolicyError(f"{where}: sinceImagePushed requires countUnit 'days', got {count_unit!r}")
    if count_type == "imageCountMoreThan" and count_unit is not None:
        raise PolicyError(f"{where}: countUnit is not allowed with imageCountMoreThan")

    return Rule(
        priority=priority,
        tag_status=tag_status,
        count_type=count_type,
        count_number=count_number,
        tag_prefixes=tuple(prefixes),
        tag_patterns=tuple(patterns),
        count_unit=count_unit,
        description=raw.get("description", ""),
    )


def _check_tag_filters(tag_status: str, prefixes: list, patterns: list, where: str) -> None:
    if tag_status == "tagged":
        if prefixes and patterns:
            raise PolicyError(f"{where}: use either tagPrefixList or tagPatternList, not both")
        if not prefixes and not patterns:
            raise PolicyError(f"{where}: tagged requires tagPrefixList or tagPatternList")
    elif prefixes or patterns:
        raise PolicyError(f"{where}: tagPrefixList and tagPatternList are only allowed with tagged")
    for p in patterns:
        if p.count("*") > MAX_PATTERN_WILDCARDS:
            raise PolicyError(f"{where}: pattern {p!r} has more than {MAX_PATTERN_WILDCARDS} wildcards")


def _check_rule_set(rules: list) -> None:
    seen = set()
    for r in rules:
        if r.priority in seen:
            raise PolicyError(f"duplicate rulePriority {r.priority}")
        seen.add(r.priority)
    for r in rules[:-1]:
        if r.tag_status == "any":
            raise PolicyError(f"rule {r.priority}: a tagStatus 'any' rule must have the highest rulePriority number")


def _string_list(sel: dict, key: str, where: str) -> list:
    value = sel.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError(f"{where}: {key} must be a list of non-empty strings")
    return value


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
