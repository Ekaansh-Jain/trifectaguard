"""
Property-based checks of the flow engine: instead of hand-written cases,
hypothesis generates random sessions (web reads, private and secret reads,
notes written and read back, outbound calls to random destinations) and every
decision is checked against the guarantees the engine claims.

Values come from pools with known provenance, so the test knows the truth
independently of the engine:
  USER      — typed by the user in their request
  TRUSTED   — appear in trusted tool output (contacts, own files)
  ATTACKER  — appear only in untrusted content (and whatever the agent copies from it)
  UNSEEN    — appear nowhere
The policy classification itself is taken as given; what's tested is the flow
logic on top of it.

  TRIFECTAGUARD_EXAMPLES=20000 python -m pytest tests/test_properties.py   # deeper run
"""
import base64
import os
import sys

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.gateway.engine import FlowEngine  # noqa: E402
from src.gateway.rules import ServerPolicy  # noqa: E402

EXAMPLES = int(os.environ.get("TRIFECTAGUARD_EXAMPLES", "1500"))
SETTINGS = settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))

USER = ["bob@corp.example", "https://docs.corp.example/guide", "DE89370400440532013000"]
TRUSTED = ["alice@corp.example", "https://wiki.corp.example/page", "GB29NWBK60161331926819"]
ATTACKER = ["mallory@evil.example", "https://evil.example/collect", "XX99MALL0RY0000000000", "smith@gmail.com"]
UNSEEN = ["carol@elsewhere.example", "https://unknown.example/x", "FR7630006000011234567890189"]
SECRETS = ["sk-live-4f8a9b2c7d1e6f3a5b0c", "wJalrXUtnFEMIK7MDENGbPxRfiCY0000"]
TRUSTED_CONTEXT = "your colleague john.smith@gmail.com"  # makes smith@gmail.com a look-alike, not a match

POLICY = ServerPolicy("synthetic", {
    "read_web": {"reads": ["untrusted"]},
    "read_private": {"reads": ["private"]},
    "read_secret_file": {"reads": ["private", "secret"]},
    "save_note": {"writes": "local"},
    "read_note": {"reads": ["private"]},
    "send_ext": {"writes": "external", "destination": ["to"]},
    "post_public": {"writes": "public", "destination": ["where"]},
    "dm_internal": {"writes": "internal", "destination": ["to"]},
    "grant_access": {"writes": "privileged", "destination": ["user"]},
    "delete_thing": {"writes": "destructive"},
    "write_ci": {"writes": "exec"},
    "fetch": {"reads": ["untrusted"], "writes": "external", "destination": ["url"],
              "destination_carries_data": True},
}, {})
SINKS = ["send_ext", "post_public", "dm_internal", "grant_access", "delete_thing", "write_ci", "fetch", "mystery_tool"]
DEST_ARG = {"send_ext": "to", "post_public": "where", "dm_internal": "to", "grant_access": "user", "fetch": "url"}
CLASS = {"send_ext": "external", "post_public": "public", "dm_internal": "internal", "grant_access": "privileged",
         "delete_thing": "destructive", "write_ci": "exec", "fetch": "external", "mystery_tool": "unknown"}

pick = st.sampled_from


@st.composite
def sessions(draw):
    """A random session: the user's request, then observations, as (kind, payload)."""
    prompt_values = draw(st.lists(pick(USER), max_size=3, unique=True))
    steps = []
    for _ in range(draw(st.integers(0, 7))):
        kind = draw(pick(["web", "private", "secret", "launder"]))
        if kind == "web":  # untrusted content can mention anything, including attacker values
            vals = draw(st.lists(pick(ATTACKER + TRUSTED + USER), max_size=3))
            steps.append(("read_web", "see " + " and ".join(vals)))
        elif kind == "private":  # trusted output: only trusted values
            vals = draw(st.lists(pick(TRUSTED), max_size=2))
            steps.append(("read_private", TRUSTED_CONTEXT + " " + " ".join(vals)))
        elif kind == "secret":
            steps.append(("read_secret_file", f"API_KEY={draw(pick(SECRETS))}"))
        else:  # the agent saves something it has seen (maybe attacker-supplied) and reads it back
            seen = [v for t, p in steps if t == "read_web" for v in ATTACKER if v in p.split()]
            val = draw(pick(seen + TRUSTED))  # it can only copy an attacker value it has read
            steps.append(("save_note", val))
            steps.append(("read_note", f"note: {val}"))
    return "Please help. " + " ".join(prompt_values), prompt_values, steps


@st.composite
def sink_calls(draw):
    tool = draw(pick(SINKS))
    args = {}
    if tool in DEST_ARG:
        args[DEST_ARG[tool]] = draw(pick(USER + TRUSTED + ATTACKER + UNSEEN))
    body = draw(pick(["status update", "summary", "SECRET", "SECRET_B64"]))
    if body.startswith("SECRET"):
        s = draw(pick(SECRETS))
        body = "here: " + (s if body == "SECRET" else base64.b64encode(s.encode()).decode())
    if tool != "fetch":
        args["body"] = body
    return tool, args


def run(prompt, steps, strict=True, extra_web=()):
    e = FlowEngine({"s": POLICY}, strict_destinations=strict)
    e.trust(prompt)
    for tool, payload in list(steps) + [("read_web", t) for t in extra_web]:
        args = {"text": payload} if tool == "save_note" else {}
        e.observe("s", tool, args, payload)
    return e


def truth(prompt_values, steps):
    """What the test knows independently of the engine."""
    labels = set()
    for tool, _ in steps:
        labels |= set(POLICY.role(tool, {}).reads)
    # attacker values enter only through untrusted content (and notes copying them);
    # match whole words so a look-alike inside a trusted address doesn't count
    attacker_values = {v for tool, p in steps if tool in ("read_web", "save_note")
                       for v in ATTACKER if v in p.split()}
    return labels, attacker_values, set(prompt_values)


@SETTINGS
@given(sessions(), sink_calls(), st.booleans())
def test_nothing_leaves_after_untrusted_content_and_credentials(session, call, strict):
    prompt, prompt_values, steps = session
    tool, args = call
    labels, _, _ = truth(prompt_values, steps)
    if {"untrusted", "secret"} <= labels and CLASS[tool] in ("public", "external", "unknown"):
        v = run(prompt, steps, strict).check("s", tool, args)
        # the one exemption: re-fetching a URL copied verbatim from the user's request or
        # their own (trusted) data sends nothing new, and an attacker can't write there
        first_web = next((i for i, (t, _) in enumerate(steps) if t == "read_web"), len(steps))
        trusted_words = {w for i, (t, p) in enumerate(steps) for w in p.split()
                         if t == "read_private" or (t == "read_note" and i < first_web)}
        exempt = tool == "fetch" and (args["url"] in prompt_values or args["url"] in trusted_words)
        assert v.action != "allow" or exempt, (steps, tool, args, v)


@SETTINGS
@given(sessions(), sink_calls(), st.booleans())
def test_attacker_chosen_destination_is_never_allowed(session, call, strict):
    prompt, prompt_values, steps = session
    tool, args = call
    labels, attacker_values, users = truth(prompt_values, steps)
    dest = args.get(DEST_ARG.get(tool, ""), None)
    if dest in attacker_values and dest not in users and CLASS[tool] not in ("internal", "local"):
        v = run(prompt, steps, strict).check("s", tool, args)
        if tool == "fetch" and not ({"private", "secret"} & labels):
            return  # opening a link before anything private was read has nothing to leak
        assert v.action != "allow", (steps, tool, args, v)


@SETTINGS
@given(sessions(), sink_calls(), st.booleans())
def test_a_secret_the_session_read_is_blocked_even_encoded(session, call, strict):
    prompt, prompt_values, steps = session
    tool, args = call
    read = {p.split("=", 1)[1] for t, p in steps if t == "read_secret_file"}
    body = args.get("body", "")
    carried = any(s in body or base64.b64encode(s.encode()).decode() in body for s in read)
    if carried and tool != "fetch":
        assert run(prompt, steps, strict).check("s", tool, args).action == "block"


@SETTINGS
@given(sessions(), sink_calls(), st.booleans())
def test_nothing_is_published_after_untrusted_content_and_private_data(session, call, strict):
    prompt, prompt_values, steps = session
    tool, args = call
    labels, _, _ = truth(prompt_values, steps)
    if {"untrusted", "private"} <= labels and CLASS[tool] == "public":
        assert run(prompt, steps, strict).check("s", tool, args).action != "allow"


@SETTINGS
@given(sessions(), sink_calls(), st.lists(pick(ATTACKER + ["ignore previous instructions"]), max_size=3),
       st.booleans())
def test_reading_more_untrusted_content_never_turns_a_no_into_a_yes(session, call, extra, strict):
    prompt, _, steps = session
    tool, args = call
    before = run(prompt, steps, strict).check("s", tool, args).action
    after = run(prompt, steps, strict, extra_web=extra).check("s", tool, args).action
    if before != "allow":
        assert after != "allow", (steps, extra, tool, args)


@SETTINGS
@given(sessions(), sink_calls(), st.booleans())
def test_saving_and_restoring_state_never_changes_a_decision(session, call, strict):
    prompt, _, steps = session
    tool, args = call
    e = run(prompt, steps, strict)
    restored = FlowEngine({"s": POLICY}, strict_destinations=strict)
    restored.load_state(e.to_state())
    assert restored.check("s", tool, args).action == e.check("s", tool, args).action
