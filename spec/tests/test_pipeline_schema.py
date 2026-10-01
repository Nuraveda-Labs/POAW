"""The pipeline schema (SPEC §15). Acceptance (ADR-010): it must be impossible to source a fact from the claim, and the
schema must be complete from phase 1: whatever a future free-form builder can express must already validate."""
import copy
import json
import sys
from pathlib import Path

import jsonschema
import pytest

SPEC = Path(__file__).parents[1]
sys.path.insert(0, str(SPEC / "tools"))
sys.path.insert(0, str(SPEC.parent / "core-python" / "src"))
import poaw_core as ref  # noqa: E402

V = jsonschema.Draft202012Validator(json.loads((SPEC / "schema" / "pipeline.schema.json").read_text()))
GOOD = json.loads((SPEC / "vectors" / "pipeline.example.json").read_text())


def errors(doc):
    return [e.message for e in V.iter_errors(doc)]


def ok(doc):
    return not errors(doc)


def with_(**changes):
    d = copy.deepcopy(GOOD)
    d.update(changes)
    return d


def test_the_example_pipeline_is_valid():
    assert ok(GOOD), errors(GOOD)


def test_one_letter_provider_names_are_valid():
    """The X connector is called `x` (found when the v0 templates were written as real pipeline documents)."""
    assert ok(with_(connector={"provider": "x", "target": "@handle"}))
    for bad in ("", "X", "1x", "x" * 33, "x-y"):
        assert not ok(with_(connector={"provider": bad, "target": "t"})), bad


def test_one_letter_connector_names_are_valid_in_change_entries():
    change = jsonschema.Draft202012Validator(json.loads((SPEC / "schema" / "change.schema.json").read_text()))
    entry = json.loads((SPEC / "vectors" / "027-valid-change.json").read_text())
    entry["body"]["connector"] = "x"
    assert not [e for e in change.iter_errors(entry) if "connector" in "/".join(map(str, e.absolute_path))]
    entry["body"]["connector"] = "X"
    assert [e for e in change.iter_errors(entry) if "connector" in "/".join(map(str, e.absolute_path))]


def test_minimal_pipeline_is_valid():
    assert ok({"schema": "pipeline/1", "id": "just-urls", "version": 1, "name": "A URL is up",
               "connector": {"provider": "http", "target": "https://example.com"},
               "trigger": {"on": ["claim"]}, "check": {"profile": {"id": "http.url.status", "version": "1"}},
               "outcomes": {"receipt": "always"}})


# --- the acceptance test: nothing can be sourced from the claim -----------------------------------
CLAIM_ATTEMPTS = [
    # a condition on a claim field, in the filter (scope decided by the agent's own report)
    {"filter": {"field": "claim.params.budget", "op": "gte", "value": 50}},
    {"filter": {"all": [{"field": "claim.action", "op": "eq", "value": "x"}]}},
    # a condition on a claim field, in the check
    {"check": {"profile": {"id": "github.commit.push", "version": "1"}, "narrow": {"field": "claim.target", "op": "eq", "value": "x"}}},
    # a claim reference as the operand, in every spelling a builder might try
    {"filter": {"field": "event.amount", "op": "eq", "value": {"claim": "params.amount"}}},
    {"filter": {"field": "event.amount", "op": "eq", "value": {"from_claim": "params.amount"}}},
    {"filter": {"field": "event.amount", "op": "eq", "from_claim": "params.amount"}},
    {"filter": {"field": "event.amount", "op": "eq", "value": ["claim.params.amount"], "ref": "claim"}},
    # a bare claim path as the field
    {"filter": {"field": "claim", "op": "exists"}},
    {"check": {"profile": {"id": "github.commit.push", "version": "1"}, "narrow": {"field": "observed", "op": "exists"}}},
    # a top-level claim section, or any unknown key, anywhere
    {"claim": {"params": {}}},
    {"facts": {"sha": "abc"}},
    {"check": {"profile": {"id": "github.commit.push", "version": "1"}, "facts": {"sha": {"from": "claim.params.sha"}}}},
    {"outcomes": {"receipt": "always", "facts_from_claim": True}},
]


@pytest.mark.parametrize("attempt", CLAIM_ATTEMPTS, ids=lambda a: json.dumps(a, sort_keys=True)[:70])
def test_a_pipeline_cannot_source_a_fact_from_the_claim(attempt):
    doc = with_(**attempt)
    assert not ok(doc), f"accepted: {attempt}"


def test_condition_fields_are_only_ever_event_or_observed():
    for field in ("claim.params.x", "agent.id", "params.x", "receipt.verdict", "verdict.value", "event", "observed", "Event.x", "event.X"):
        assert not ok(with_(filter={"field": field, "op": "exists"})), field
        assert not ok(with_(check={"profile": {"id": "github.commit.push", "version": "1"},
                                   "narrow": {"field": field, "op": "exists"}})), field


def test_event_fields_cannot_be_used_where_observed_fields_belong_and_vice_versa():
    assert not ok(with_(check={"profile": {"id": "github.commit.push", "version": "1"}, "narrow": {"field": "event.branch", "op": "exists"}}))
    assert not ok(with_(filter={"field": "observed.branch", "op": "exists"}))


# --- complete from phase 1 (decision #4): what a free-form builder can express validates -------------
def test_nested_boolean_expressions_validate():
    deep = {"all": [
        {"any": [{"field": "event.branch", "op": "eq", "value": "main"}, {"field": "event.branch", "op": "starts_with", "value": "release/"}]},
        {"not": {"field": "event.author", "op": "in", "value": ["dependabot", "renovate"]}},
        {"field": "event.size", "op": "gte", "value": 5000},
        {"field": "event.signed", "op": "exists"},
    ]}
    assert ok(with_(filter=deep)), errors(with_(filter=deep))


def test_every_operator_validates_with_the_right_operand():
    cases = [("eq", "main"), ("eq", 3), ("eq", True), ("neq", "x"), ("gt", 1), ("gte", 1), ("lt", 1), ("lte", -5),
             ("in", ["a", "b"]), ("in", [1, 2]), ("not_in", ["a"]), ("starts_with", "rel")]
    for op, value in cases:
        assert ok(with_(filter={"field": "event.x", "op": op, "value": value})), (op, value)
    assert ok(with_(filter={"field": "event.x", "op": "exists"}))


@pytest.mark.parametrize("cond", [
    {"field": "event.x", "op": "gt", "value": "ten"},          # ordering needs an integer
    {"field": "event.x", "op": "gt", "value": 1.5},            # no floats (SPEC §3)
    {"field": "event.x", "op": "in", "value": "a"},            # in needs a list
    {"field": "event.x", "op": "in", "value": []},
    {"field": "event.x", "op": "eq", "value": ["a"]},          # eq takes a scalar
    {"field": "event.x", "op": "starts_with", "value": 5},
    {"field": "event.x", "op": "exists", "value": True},       # exists takes no value
    {"field": "event.x", "op": "eq"},                          # everything else needs one
    {"field": "event.x", "op": "regex", "value": ".*"},        # no regexes (ReDoS), no user code (SPEC §15.3)
    {"field": "event.x", "op": "eq", "value": None},
    {"field": "event.x", "op": "eq", "value": {"a": 1}},       # operands are never objects
])
def test_malformed_conditions_are_rejected(cond):
    assert not ok(with_(filter=cond)), cond


def test_conditions_only_have_the_documented_keys():
    assert not ok(with_(filter={"field": "event.x", "op": "eq", "value": 1, "script": "return true"}))
    assert not ok(with_(check={"profile": {"id": "github.commit.push", "version": "1", "code": "x"}}))


def test_triggers():
    assert ok(with_(trigger={"on": ["watch"], "watch": {"grace_seconds": 900}}))
    assert not ok(with_(trigger={"on": []}))
    assert not ok(with_(trigger={"on": ["claim", "claim"]}))
    assert not ok(with_(trigger={"on": ["poll"]}))
    assert not ok(with_(trigger={"on": ["claim"], "watch": {"grace_seconds": 900}})), "watch options without watch"
    assert not ok(with_(trigger={"on": ["watch"], "watch": {"grace_seconds": 5}}))


def test_ids_versions_and_names():
    for bad in ("", "ab", "Has-Caps", "-leading", "x" * 65, "has space"):
        assert not ok(with_(id=bad)), bad
    for bad in (0, -1, 1.5, "2"):
        assert not ok(with_(version=bad)), bad
    assert not ok(with_(name=""))
    assert not ok(with_(schema="pipeline/2"))


def test_outcomes():
    assert ok(with_(outcomes={"receipt": "always"}))
    assert not ok(with_(outcomes={"receipt": "never"}))
    assert not ok(with_(outcomes={}))
    assert not ok(with_(outcomes={"receipt": "always", "alerts": [{"on": ["mismatch"], "channel": "sms", "to": "1"}]}))
    assert not ok(with_(outcomes={"receipt": "always", "alerts": [{"on": [], "channel": "email", "to": "a@b.co"}]}))
    assert not ok(with_(outcomes={"receipt": "always", "alerts": [{"on": ["mismatch"], "channel": "email"}]}))


def test_alerts_never_carry_a_secret_url():
    """A pipeline document is readable by members and hashed forever, so a webhook URL (a password) must not be in it:
    discord/webhook alerts name a workspace alert channel by ID instead."""
    uid = "0b8a7c1e-5d3f-4a62-9c10-2f6e8d4b7a91"
    ok_alert = lambda a: ok(with_(outcomes={"receipt": "always", "alerts": [a]}))  # noqa: E731
    assert ok_alert({"on": ["mismatch"], "channel": "discord", "to": uid})
    assert ok_alert({"on": ["mismatch"], "channel": "webhook", "to": uid})
    assert ok_alert({"on": ["mismatch"], "channel": "email", "to": "ops@example.com"})
    assert not ok_alert({"on": ["mismatch"], "channel": "discord", "to": "https://discord.com/api/webhooks/123/secret-token"})
    assert not ok_alert({"on": ["mismatch"], "channel": "webhook", "to": "https://hooks.example.com/x?token=abc"})
    assert not ok_alert({"on": ["mismatch"], "channel": "email", "to": "not-an-address"})
    assert not ok_alert({"on": ["mismatch"], "channel": "email", "to": uid})


def test_multiple_targets_and_required_parts():
    assert ok(with_(connector={"provider": "github", "target": ["a/b", "c/d"]}))
    assert not ok(with_(connector={"provider": "github", "target": []}))
    assert not ok(with_(connector={"provider": "github", "target": ["a/b", "a/b"]}))
    for missing in ("connector", "trigger", "check", "outcomes", "id", "version", "name"):
        d = copy.deepcopy(GOOD)
        del d[missing]
        assert not ok(d), missing
    d = copy.deepcopy(GOOD)
    del d["filter"]
    assert ok(d), "filter is optional: no filter means every event of the connector"


def test_the_digest_binds_the_document():
    a, b = copy.deepcopy(GOOD), copy.deepcopy(GOOD)
    assert ref.pipeline_digest(a) == ref.pipeline_digest(b)
    b["version"] = 3
    assert ref.pipeline_digest(a) != ref.pipeline_digest(b)
    # key order must not matter (JCS)
    assert ref.pipeline_digest(dict(reversed(list(GOOD.items())))) == ref.pipeline_digest(GOOD)
