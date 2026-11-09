from datetime import datetime, timedelta, timezone

import pytest

from imgexpiry.policy import parse_policy
from imgexpiry.predictor import EXPIRES_AFTER_PUSHES, EXPIRES_AT, SAFE, Image, predict

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def days_ago(n):
    return NOW - timedelta(days=n)


def img(digest, age_days, *tags):
    return Image(digest=digest, pushed_at=days_ago(age_days), tags=tags)


def rule(priority, tag_status="any", count_type="imageCountMoreThan", count_number=5, **selection):
    sel = {"tagStatus": tag_status, "countType": count_type, "countNumber": count_number, **selection}
    if count_type == "sinceImagePushed":
        sel["countUnit"] = "days"
    return {"rulePriority": priority, "selection": sel, "action": {"type": "expire"}}


def run(rules, images):
    preds = predict(parse_policy({"rules": rules}), images, NOW)
    return {p.digest: p for p in preds}


def summary(pred):
    """Compact (status, expires_at days from now / pushes, rule) for table asserts."""
    if pred.status == EXPIRES_AT:
        return (EXPIRES_AT, (pred.expires_at - NOW).days, pred.rule_priority)
    if pred.status == EXPIRES_AFTER_PUSHES:
        return (EXPIRES_AFTER_PUSHES, pred.pushes, pred.rule_priority)
    return (SAFE, None, None)


# --- age rules ---------------------------------------------------------------

@pytest.mark.parametrize("age, expected_days_left", [
    (29, 1),    # just inside the window
    (30, 0),    # exactly at the limit: expires now
    (31, -1),   # just outside: already overdue
])
def test_age_rule_expiry_date(age, expected_days_left):
    out = run([rule(1, count_type="sinceImagePushed", count_number=30)], [img("a", age)])
    assert summary(out["a"]) == (EXPIRES_AT, expected_days_left, 1)
    assert out["a"].expires_at == days_ago(age) + timedelta(days=30)


# --- count rules -------------------------------------------------------------

def test_count_rule_exactly_n_images_all_survive_for_now():
    images = [img("a", 1), img("b", 2), img("c", 3)]
    out = run([rule(1, count_number=3)], images)
    # one more push moves "c" past the limit; "a" needs three
    assert {d: summary(p) for d, p in out.items()} == {
        "a": (EXPIRES_AFTER_PUSHES, 3, 1),
        "b": (EXPIRES_AFTER_PUSHES, 2, 1),
        "c": (EXPIRES_AFTER_PUSHES, 1, 1),
    }


def test_count_rule_n_plus_one_expires_the_oldest_now():
    images = [img("a", 1), img("b", 2), img("c", 3), img("d", 4)]
    out = run([rule(1, count_number=3)], images)
    assert out["d"].status == EXPIRES_AT
    assert out["d"].expires_at == NOW
    assert out["c"].pushes == 1


def test_count_rule_ranks_by_push_time_not_input_order():
    images = [img("old", 10), img("new", 1), img("mid", 5)]
    out = run([rule(1, count_number=2)], images)
    assert summary(out["new"]) == (EXPIRES_AFTER_PUSHES, 2, 1)
    assert summary(out["mid"]) == (EXPIRES_AFTER_PUSHES, 1, 1)
    assert out["old"].status == EXPIRES_AT


def test_count_rule_ties_on_push_time_are_broken_by_digest():
    images = [img("b", 1), img("a", 1)]
    out = run([rule(1, count_number=1)], images)
    assert out["a"].status == EXPIRES_AFTER_PUSHES
    assert out["b"].status == EXPIRES_AT


def test_count_rule_only_counts_images_matching_its_tags():
    images = [img("a", 1, "v1"), img("b", 2, "dev"), img("c", 3, "dev")]
    out = run([rule(1, "tagged", count_number=1, tagPrefixList=["dev"])], images)
    assert out["a"].status == SAFE
    assert out["b"].status == EXPIRES_AFTER_PUSHES
    assert out["c"].status == EXPIRES_AT


# --- tag selection -----------------------------------------------------------

@pytest.mark.parametrize("tag_status, selection, tags, expected", [
    ("any", {}, (), True),
    ("any", {}, ("v1",), True),
    ("untagged", {}, (), True),
    ("untagged", {}, ("v1",), False),
    ("tagged", {"tagPrefixList": ["v"]}, ("v1",), True),
    ("tagged", {"tagPrefixList": ["v"]}, ("latest", "v1"), True),
    ("tagged", {"tagPrefixList": ["v"]}, ("latest",), False),
    ("tagged", {"tagPrefixList": ["v"]}, (), False),
    ("tagged", {"tagPrefixList": ["v", "rel"]}, ("v1", "release"), True),
    ("tagged", {"tagPrefixList": ["v", "rel"]}, ("v1",), False),
    ("tagged", {"tagPatternList": ["prod*"]}, ("production-1",), True),
    ("tagged", {"tagPatternList": ["*prod*"]}, ("repo-prod-x",), True),
    ("tagged", {"tagPatternList": ["prod*"]}, ("my-prod",), False),
    ("tagged", {"tagPatternList": ["v1.*"]}, ("v1x2",), False),  # '.' is literal
    ("tagged", {"tagPatternList": ["v*.*.*"]}, ("v1.2.3",), True),
])
def test_tag_selection(tag_status, selection, tags, expected):
    out = run([rule(1, tag_status, count_type="sinceImagePushed", count_number=30, **selection)],
              [img("a", 1, *tags)])
    assert (out["a"].status == EXPIRES_AT) is expected
    assert (out["a"].status == SAFE) is (not expected)


# --- multiple rules ----------------------------------------------------------

def test_multiple_rules_each_image_gets_its_own_rule():
    rules = [
        rule(1, "untagged", count_type="sinceImagePushed", count_number=7),
        rule(2, "tagged", count_number=2, tagPrefixList=["v"]),
    ]
    images = [img("u", 1), img("v1", 1, "v1"), img("v2", 2, "v2"), img("v3", 3, "v3")]
    out = run(rules, images)
    assert summary(out["u"]) == (EXPIRES_AT, 6, 1)
    assert summary(out["v1"]) == (EXPIRES_AFTER_PUSHES, 2, 2)
    assert summary(out["v2"]) == (EXPIRES_AFTER_PUSHES, 1, 2)
    assert out["v3"].status == EXPIRES_AT and out["v3"].rule_priority == 2


def test_higher_priority_rule_protects_images_matching_its_tags_from_lower_rules():
    rules = [
        rule(1, "tagged", count_number=10, tagPrefixList=["release"]),
        rule(2, "any", count_type="sinceImagePushed", count_number=30),
    ]
    out = run(rules, [img("rel", 400, "release-1"), img("other", 400, "dev")])
    assert out["rel"].rule_priority == 1       # kept by rule 1's count, not expired by rule 2
    assert out["rel"].status == EXPIRES_AFTER_PUSHES
    assert out["other"].rule_priority == 2
    assert out["other"].status == EXPIRES_AT


def test_rule_counts_images_owned_by_higher_priority_rules():
    # Documented reading: rule 2 ranks every image matching its tags, including
    # those rule 1 owns, so "old" is pushed past rule 2's limit of 1 by "owned".
    rules = [
        rule(1, "tagged", count_type="sinceImagePushed", count_number=1000, tagPrefixList=["keep"]),
        rule(2, "any", count_number=1),
    ]
    images = [img("owned", 1, "keep-1"), img("old", 5, "dev")]
    out = run(rules, images)
    assert out["owned"].rule_priority == 1
    assert out["old"].status == EXPIRES_AT and out["old"].expires_at == NOW


def test_image_matching_no_rule_is_safe():
    out = run([rule(1, "tagged", count_number=1, tagPrefixList=["dev"])], [img("a", 99, "v1")])
    assert out["a"].status == SAFE and out["a"].rule_priority is None


# --- edges -------------------------------------------------------------------

def test_empty_repository():
    assert predict(parse_policy({"rules": [rule(1)]}), [], NOW) == []


def test_no_rules_everything_safe():
    out = run([], [img("a", 1), img("b", 500, "v1")])
    assert {p.status for p in out.values()} == {SAFE}


def test_predictions_follow_input_order():
    images = [img("z", 1), img("a", 2), img("m", 3)]
    preds = predict(parse_policy({"rules": [rule(1)]}), images, NOW)
    assert [p.digest for p in preds] == ["z", "a", "m"]
