import json

import pytest

from imgexpiry.policy import PolicyError, Rule, UnsupportedPolicyError, parse_policy


def rule(priority=1, selection=None, action="expire"):
    selection = {"tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 5, **(selection or {})}
    return {"rulePriority": priority, "selection": selection, "action": {"type": action}}


def policy(*rules):
    return {"rules": list(rules)}


def test_parses_age_rule():
    sel = {"tagStatus": "tagged", "tagPrefixList": ["v"], "countType": "sinceImagePushed",
           "countUnit": "days", "countNumber": 30}
    assert parse_policy(policy(rule(1, sel))) == [
        Rule(priority=1, tag_status="tagged", count_type="sinceImagePushed", count_number=30,
             tag_prefixes=("v",), count_unit="days")
    ]


def test_parses_count_rule_with_patterns_and_description():
    sel = {"tagStatus": "tagged", "tagPatternList": ["prod*"], "countNumber": 3}
    raw = rule(2, sel)
    raw["description"] = "keep 3"
    assert parse_policy(policy(raw)) == [
        Rule(priority=2, tag_status="tagged", count_type="imageCountMoreThan", count_number=3,
             tag_patterns=("prod*",), description="keep 3")
    ]


def test_parses_json_text():
    text = json.dumps(policy(rule(1, {"tagStatus": "untagged"})))
    assert parse_policy(text)[0].tag_status == "untagged"


def test_rules_sorted_by_priority_regardless_of_input_order():
    rules = parse_policy(policy(rule(10, {"tagStatus": "untagged"}), rule(3, {"tagStatus": "untagged"})))
    assert [r.priority for r in rules] == [3, 10]


def test_any_rule_allowed_when_it_has_highest_priority_number():
    rules = parse_policy(policy(rule(2), rule(1, {"tagStatus": "untagged"})))
    assert [r.tag_status for r in rules] == ["untagged", "any"]


def test_empty_rules_list_is_valid():
    assert parse_policy({"rules": []}) == []


@pytest.mark.parametrize("bad", [
    "not json",
    "[]",
    {},
    {"rules": "nope"},
    {"rules": ["nope"]},
])
def test_malformed_policy_rejected(bad):
    with pytest.raises(PolicyError):
        parse_policy(bad)


@pytest.mark.parametrize("name, bad", [
    ("zero priority", rule(0)),
    ("bool priority", rule(True)),
    ("missing selection", {"rulePriority": 1, "action": {"type": "expire"}}),
    ("bad action", rule(1, action="delete")),
    ("bad tagStatus", rule(1, {"tagStatus": "some"})),
    ("tagged without filters", rule(1, {"tagStatus": "tagged"})),
    ("tagged with both lists", rule(1, {"tagStatus": "tagged", "tagPrefixList": ["a"], "tagPatternList": ["a*"]})),
    ("untagged with prefix", rule(1, {"tagStatus": "untagged", "tagPrefixList": ["a"]})),
    ("any with pattern", rule(1, {"tagStatus": "any", "tagPatternList": ["a*"]})),
    ("empty prefix string", rule(1, {"tagStatus": "tagged", "tagPrefixList": [""]})),
    ("too many wildcards", rule(1, {"tagStatus": "tagged", "tagPatternList": ["a*b*c*d*e*"]})),
    ("unknown count type", rule(1, {"countType": "forever"})),
    ("zero count", rule(1, {"countNumber": 0})),
    ("string count", rule(1, {"countNumber": "5"})),
    ("age rule without unit", rule(1, {"countType": "sinceImagePushed"})),
    ("age rule with wrong unit", rule(1, {"countType": "sinceImagePushed", "countUnit": "weeks"})),
    ("count rule with unit", rule(1, {"countUnit": "days"})),
], ids=lambda v: v if isinstance(v, str) else "")
def test_invalid_rule_rejected(name, bad):
    with pytest.raises(PolicyError):
        parse_policy(policy(bad))


def test_four_wildcards_is_allowed():
    sel = {"tagStatus": "tagged", "tagPatternList": ["*a*b*c*"]}
    assert parse_policy(policy(rule(1, sel)))[0].tag_patterns == ("*a*b*c*",)


def test_duplicate_priorities_rejected():
    with pytest.raises(PolicyError, match="duplicate"):
        parse_policy(policy(rule(1, {"tagStatus": "untagged"}), rule(1, {"tagStatus": "untagged"})))


def test_any_rule_before_other_rules_rejected():
    with pytest.raises(PolicyError, match="any"):
        parse_policy(policy(rule(1), rule(2, {"tagStatus": "untagged"})))


@pytest.mark.parametrize("sel", [
    {"countType": "sinceImagePulled", "countUnit": "days"},
    {"countType": "sinceImageTransitioned", "countUnit": "days"},
])
def test_archive_count_types_unsupported(sel):
    with pytest.raises(UnsupportedPolicyError):
        parse_policy(policy(rule(1, sel)))


def test_transition_action_unsupported():
    with pytest.raises(UnsupportedPolicyError):
        parse_policy(policy(rule(1, action="transition")))


def test_unsupported_is_a_policy_error():
    assert issubclass(UnsupportedPolicyError, PolicyError)
