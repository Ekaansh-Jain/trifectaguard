# trifectaguard

[![tests](https://github.com/Ekaansh-Jain/trifectaguard/actions/workflows/tests.yml/badge.svg)](https://github.com/Ekaansh-Jain/trifectaguard/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/trifectaguard)](https://pypi.org/project/trifectaguard/)

**Stop AI agents from leaking your data or acting for an attacker, whatever
the injected instruction says.**

An agent that can read untrusted content (web pages, issues, emails), read your
private data, and send things out can be turned against you by one injected
instruction ([the "lethal trifecta"](https://simonwillison.net/tags/lethal-trifecta/)).
Detectors try to spot the injection's wording and can be evaded. trifectaguard
tracks **what the session has read** and **where each tool call sends it**, and
asks or blocks before private data, credentials, money or access go somewhere
an injection chose.

```
untrusted input  →  reads private data / credentials  →  sends it out   ✗ blocked
     (issue, web page, email)                (post, email, curl, fetch, PR)
```

Works as **Claude Code hooks**, as a **proxy in front of any MCP server** (Claude
Desktop, Cursor, …), or as a **Python library** for your own agents
(LangChain/LangGraph, OpenAI Agents SDK, plain loops).

## Quick start

```bash
pip install "trifectaguard[mcp]"   # Python 3.10–3.13; the [mcp] extra is only needed for the proxy
trifectaguard scan                 # read-only: what could an injection make your AI apps do?
```

`trifectaguard scan` reads the MCP configs of Claude Code, Claude Desktop, Cursor,
Windsurf and VS Code and explains every risky combination:

```
Claude Code  (not protected)
  HIGH  An injected instruction could make the agent send your credentials out
        untrusted input: WebFetch, WebSearch  →  then reads credentials: Read, Bash  →  then sends via: WebFetch, Bash
```

It changes nothing, starts no servers, never opens credential files and never
prints tokens from your configs. `--json` for tooling; it exits 1 when an
unprotected high-risk combination exists, so it can gate CI.

## Protect your agents

| | For | Verified in |
|---|---|---|
| [Claude Code hooks](#claude-code) | Claude Code, including `Read`, `WebFetch`, `Bash`, `Write` and every MCP server | a real Claude Code session |
| [MCP proxy](#any-mcp-app-claude-desktop-cursor-) | any MCP app; local (stdio) and remote (HTTP/SSE) servers | a real Claude Desktop chat |
| [Python library](#your-own-agent-python) | LangChain/LangGraph, OpenAI Agents SDK, your own loop | a live LangGraph agent |

Start any of them in `mode: monitor` to see what it *would* stop before it stops anything,
then `trifectaguard suggest -c <config>` proposes config (trusted sites, remembered
approvals) that removes repeat prompts without weakening the rules.

### Claude Code

```bash
curl -O https://raw.githubusercontent.com/Ekaansh-Jain/trifectaguard/main/hooks.example.yaml
cp hooks.example.yaml hooks.yaml          # list your MCP servers; starts in monitor mode
trifectaguard hooks-snippet -c hooks.yaml     # paste the output into ~/.claude/settings.json
```

The engine runs as `UserPromptSubmit` / `PreToolUse` / `PostToolUse` hooks. It
sees your request (so addresses and links you typed are trusted), tracks the
whole session across built-in tools and MCP servers, and asks through Claude
Code's normal approval prompt. It only ever answers "ask" or "deny", never
"allow", so it can't loosen your permission settings. `Bash` is classified from
its text (commands that can send data out or hide what they do get the
scrutiny); that can't be complete, so keep Claude Code's own Bash permissions
on, and for strong guarantees on shell commands use Claude Code's `/sandbox`
(OS-level network limits) alongside trifectaguard. With `remember_approvals:
project`, a destination you approve in a project isn't asked again there.

### Any MCP app (Claude Desktop, Cursor, …)

```bash
curl -O https://raw.githubusercontent.com/Ekaansh-Jain/trifectaguard/main/gateway.example.yaml
cp gateway.example.yaml gateway.yaml      # your servers + which repos are public/private
trifectaguard inspect -c gateway.yaml         # how every tool is classified
```

In the app's MCP config, replace your servers with one entry running
`trifectaguard run -c /abs/path/gateway.yaml`. One gateway fronts all of them, so a
web page read through one server and a file read through another are one flow.
Risky calls ask the user through MCP elicitation where the app supports it,
and are blocked otherwise. Works with `mcp` 1.26+ and 2.x.

### Your own agent (Python)

```python
from trifectaguard import Guard, ask_in_terminal
from langchain_core.tools import tool     # or the OpenAI Agents SDK's @function_tool

guard = Guard({"tools": {
    "read_inbox": {"reads": ["untrusted", "private"]},
    "send_email": {"writes": "external", "destination": ["to"]},
}}, on_ask=ask_in_terminal)               # default: anything needing approval is denied

guard.user_message(user_request)          # destinations the user typed are trusted

@tool
@guard.tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    ...
```

A refused call doesn't run; the tool returns a short explanation the model can
relay (or raises `Blocked` with `blocked="raise"`). One `Guard` per conversation.

## How it works

- **Labels.** Tool results add labels to the session: `untrusted` (issues, web
  pages, chat), `private` (private repos, local files), `secret` (credentials).
- **Flow rules.** Before a call that sends something: untrusted + credentials →
  outside is blocked; untrusted + private → public or outside asks; untrusted
  content steering writes to CI/shell/agent config, access changes or deletions
  asks.
- **Destination provenance.** For a recipient, IBAN, URL or user, it checks
  where the value came from: your request or trusted data (fine) vs only
  untrusted content (an injection chose it: ask). Matching is by whole token,
  and anything the agent itself wrote after reading untrusted content stays
  untrusted.
- **DLP.** A secret the session read can't leave, even base64/hex/URL-encoded,
  reversed or spaced out.
- **Rug-pull pins** (proxy). Tool definitions are pinned; a changed one is
  quarantined until you re-pin.
- **Policies** are small YAML files. Presets ship for GitHub, filesystem, fetch,
  Slack and Claude Code's built-in tools; unknown tools are treated as
  untrusted with an unknown destination.

## Results

Everything it has been tested on, independent benchmarks first. Method,
disclosed post-hoc changes and every number: [RESULTS.md](RESULTS.md).

| Test | What was run | Made by | Result |
|---|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) v1.2.2 | 591 attacks and 97 benign tasks, worst-case agent that obeys every injection | ETH Zurich | 0.3% of data theft and 0% of hijacks and deletions get through; 31% of benign tasks need one approval (44% as an MCP proxy) |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | 1,054 attacks across 330 tools; policy drafted automatically and frozen before the run | UIUC | 0% of data stealing, 3.3% of direct harm; identical with the "enhanced" hacking prompt |
| Other people's sessions | 248,346 tool calls from 4,096 OpenHands sessions in 1,198 repos ([dataset](https://huggingface.co/datasets/nebius/SWE-rebench-openhands-trajectories)) | Nebius | 0.03–0.17% of calls interrupted |
| Live models | AgentDojo banking with gpt-oss-120b and gpt-oss-20b; a LangGraph email agent | ETH Zurich; us | 0/30 attacks succeeded (18/30 unprotected); 0/20 (11/20 unprotected) |
| Real Claude Code | desktop app with the hooks, real filesystem and fetch MCP servers, a local website | us | credential exfiltration denied; fix-test-commit and docs-then-code ran with no prompts |
| Real Claude Desktop | the proxy in front of an MCP server, in a normal chat | us | exfiltration blocked; the server delivered 0 messages |
| [Master scenarios](SCENARIOS.md) | 12 attacks and 9 legitimate look-alikes, each through the library, the hooks and the proxy | us | all as expected, on every push |
| Adaptive red team | 20 attacks written against its own rules, 8 legitimate controls | us | 20/20 stopped, 8/8 allowed |
| Property tests | 6 guarantees, each checked on 20,000 generated sessions | us | always hold |
| Unit, end-to-end and robustness tests | 108 tests on macOS, Linux and Windows with Python 3.10–3.13 | us | pass on every push |

AgentDojo by what the attacker wants (worst-case agent):

| Attacker's goal | Still succeeds with trifectaguard |
|---|---|
| steal data (299 attacks) | **0.3%** |
| hijack payments, access or contact (153) | **0%** |
| deletions (39) | **0%** |
| steer the agent among legitimate options (100) | 60% (not what it controls) |

On the same benchmark, prompt-injection detectors (AgentDojo's own and this
repo's fine-tuned one) let 1.7–27.6% of attacks through and hid clean data on
39–74% of benign tasks. Almost every trifectaguard stop is an **ask**:
benchmarks count it as stopped because they have no human; in real use, you
decide.

## Limits

- It controls **where data and access go**, not which legitimate option an
  agent picks, what text it writes to a legitimate recipient, or its final answer.
- Security depends on the policies being right; a misclassified tool is a hole.
  `trifectaguard inspect` and `trifectaguard scan` show what each tool is treated as.
- `Bash` classification in Claude Code is pattern-based: pair it with Claude
  Code's `/sandbox` for shell commands.
- GitHub repo visibility comes from your config, not the API.
- The proxy forwards tools (not MCP resources or prompts).
- Nobody outside this project has tried to break it yet: please do
  ([SECURITY.md](SECURITY.md)).

## Related projects

Other open-source guards for Claude Code, described from their own READMEs and
source at the commit read (2026-09-28). **Not measured side by side**: this is
how each is documented to work, not a benchmark.

| | Acts on | Blocks or warns | Session memory | Notes from their docs/source |
|---|---|---|---|---|
| [lasso-security/claude-hooks](https://github.com/lasso-security/claude-hooks) (`8fbfd14`) | tool **output** (PostToolUse) | warns only | no | ~96 regex patterns in 4 categories (instruction override, role-play, encoding, context manipulation) |
| [dwarvesf/claude-guardrails](https://github.com/dwarvesf/claude-guardrails) (`b3c3e15`) | tool calls (PreToolUse), prompts, output | blocks (deny rules, command checks); output scan warns | no | mostly Claude Code permission deny rules for sensitive paths; its README notes Bash reads aren't covered by `Read` deny rules. Its output scanner reads a `tool_output` field; Claude Code's documented field is `tool_response` |
| [slavaspitsyn/claude-code-security-hooks](https://github.com/slavaspitsyn/claude-code-security-hooks) (`c4f126a`) | tool calls (PreToolUse) | blocks | no | per-command rules: credential path + network tool in the same command, read guards for credential directories, POST domain whitelist, canary files |
| **trifectaguard** | tool calls **and** output, across the whole session | asks or blocks | **yes** | labels what the session has read and checks where each call sends data and who chose the destination; also an MCP proxy and a Python library |

The others judge each call or output on its own (patterns, paths, command
shapes); trifectaguard judges a call by what the session has already read and where
the call sends it. They are complementary: path deny rules and trifectaguard can
run together.

## Research and reproducing the results

This repo started as a prompt-injection lab: a leak-rate benchmark of models
against documented 2026 agent attacks (mock MCP server, fake canary secret),
and a benchmark of injection detectors on tool outputs, including a fine-tuned
ModernBERT (`scripts/`, `data/`, results and corrections in RESULTS.md).

```bash
git clone https://github.com/Ekaansh-Jain/trifectaguard && cd trifectaguard
pip install ".[mcp]" agentdojo openai python-dotenv
cp .env.example .env                              # Groq / NVIDIA NIM / Gemini keys, for live-model runs only
python run_all_tests.py --no-llm                  # every test, no API calls
python -m pytest tests/                           # unit, end-to-end, property and robustness tests
python eval/scenarios/run.py                      # master scenarios × library, hooks, proxy (writes SCENARIOS.md)
python eval/redteam/adaptive.py                   # attacks on trifectaguard's own rules
python eval/agentdojo/worst_case.py --hook        # AgentDojo, model-independent (~3 min)
python eval/agentdojo/report.py                   # tables
python eval/injecagent/run.py /path/to/InjecAgent # InjecAgent (clone uiuc-kang-lab/InjecAgent first)
python eval/trajectories/public_replay.py sessions.parquet   # false alarms on public OpenHands sessions
python eval/agentdojo/live.py                     # live models on AgentDojo (needs API keys)
python eval/library/langgraph_live.py             # live LangGraph agent (needs API keys)
python eval/real/pack.py setup                    # real Claude Code sandbox; prompts in its TEST.md
python run_pilot.py --all --runs 10               # original model leak-rate benchmark
```

Inside this checkout the package is also importable as `src.gateway`
(`python -m src.gateway …`), which the research scripts use.

## Repository layout

- `src/gateway/`: the package (`trifectaguard` when installed): `engine.py` (labels +
  flow rules), `rules.py` (YAML policies), `policies/` (presets), `dlp.py`,
  `shell.py` (Bash classifier), `hook.py` (Claude Code), `gateway.py` (MCP proxy),
  `guard.py` (library), `pins.py`, and the `scan`, `replay`, `suggest` and
  `draft-policy` commands. `proxy.py`/`policy.py`/`adjudicator.py`/`detector.py`
  are from the original research phase.
- `eval/`: `agentdojo/`, `injecagent/`, `trajectories/` (public sessions),
  `scenarios/` (master catalog), `redteam/`, `library/` (live LangGraph agent),
  `claude_code/` and `real/` (real Claude Code), `mcp_client/` (Claude Desktop).
- `tests/`: unit, end-to-end, property and robustness tests (run on every push).
- `src/servers/github_mock.py`, `attacks/`, `src/harness/`, `run_pilot.py`: the
  research benchmark (sandbox server with a fake secret).

## Ethics

The benchmarks measure the vulnerability of *your own* agent setup in a sandbox
so a defense can block it. Attack payloads recreate the *structure* of public
disclosures and target only fake in-repo secrets.
