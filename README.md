# MCP injection lab

A defensive-security project in three parts:

1. **Leak-rate benchmark** — replays publicly documented 2026 agent attacks
   (malicious GitHub issue, hidden instruction in a fetched web page) against
   many models through a mock MCP server, and measures how often each model
   leaks a canary secret into a tool call. *(this stage)*
2. **Detector benchmark** — compares hosted/open prompt-injection detectors
   (Prompt Guard 2, gpt-oss-safeguard, LLM judges, …) on *tool outputs*, on
   detection rate, false positives on hard negatives, and latency.
3. **Flow-control gateway** — one MCP server that fronts all of an agent's MCP
   servers and enforces information-flow rules across them (below).

The benchmarks run locally against a sandbox. No real accounts, tokens, or repos.

## Flow-control gateway

Prompt-injection detectors guess from wording and can be evaded (see RESULTS.md).
The gateway instead tracks **what kind of data the session has touched** and
stops it moving somewhere it shouldn't — whatever the injection said.

```
agent ──► gateway ──► github / filesystem / fetch / slack / …
```

- **Labels, across servers.** Tool results add labels to the session:
  `untrusted` (issues, web pages, chat), `private` (private repos, local files),
  `secret` (credentials). One process fronts every server, so a web page read
  via fetch and a file read via filesystem are part of the same flow.
- **Flow rules.** Before a sink call: `untrusted + private → public` asks the
  user, `untrusted + secret → public/external` blocks, untrusted content steering
  a write into CI/shell/agent config asks, and so on (`DEFAULT_FLOWS` in
  `src/gateway/engine.py`).
- **Ask, don't just block.** Uses MCP elicitation to show the user *why* ("private
  data from gh/get_file_contents after untrusted content from gh/get_issue") with
  allow once / allow for this session / block. Fails closed if the client can't prompt.
- **Destination provenance.** For sinks that name a recipient, IBAN, URL or
  user, it checks where that value came from: your request or trusted data
  (fine, and private data may go there) vs. only untrusted content (an
  injection chose it: ask).
- **DLP.** Any secret the session read is hard-blocked from leaving, including
  base64/hex/URL-encoded/reversed/spaced-out copies.
- **Rug-pull pins.** Tool definitions are pinned on disk; a changed definition
  is quarantined until you re-pin.
- **Monitor mode.** Log what would have been stopped, without stopping it.
- **Presets** for the GitHub, filesystem, fetch and Slack servers, built from
  their real tool lists. Unknown tools are treated as untrusted + unknown sink.

```bash
pip install mcp pyyaml
cp gateway.example.yaml gateway.yaml                # list your servers + repos
python -m src.gateway inspect -c gateway.yaml       # see how every tool is classified
python -m src.gateway run -c gateway.yaml           # the command your MCP client runs
python -m src.gateway run --policy github -- npx -y @modelcontextprotocol/server-github   # one server, no config
```

### Three ways to run it (same engine, same policies)

| | For | Verified |
|---|---|---|
| **Library** (`from flowguard import Guard`) | any Python agent: LangChain/LangGraph, OpenAI Agents SDK, your own loop | tool-integration tests with real LangChain and OpenAI Agents SDK tools; AgentDojo "library mode" numbers |
| **Claude Code hooks** | Claude Code, including its built-in tools | real Claude Code session (RESULTS.md) |
| **MCP proxy** | any MCP app: Claude Desktop, Cursor, … (local and remote servers) | scripted MCP client over stdio and HTTP; real-app check in `eval/mcp_client/desktop_test.py` |

```bash
pip install .            # library + Claude Code hooks
pip install ".[mcp]"     # + the MCP proxy
```

### As a library

```python
from flowguard import Guard, ask_in_terminal

guard = Guard({"tools": {
    "read_inbox": {"reads": ["untrusted", "private"]},
    "send_email": {"writes": "external", "destination": ["to"]},
}}, on_ask=ask_in_terminal)          # default on_ask denies: nothing needing approval runs unattended
guard.user_message(user_request)     # destinations the user typed are trusted

@tool                                # LangChain's @tool or the Agents SDK's @function_tool go on top
@guard.tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
```

A refused call doesn't run; the tool returns a short explanation for the model
(or raises `Blocked` with `blocked="raise"`). Policies can also be presets or
YAML paths, one per tool source: `Guard({"mail": {...}, "fs": "filesystem"})`.
One `Guard` per conversation.

### In Claude Code: hook mode (recommended there)

In Claude Code the engine runs as hooks instead of a proxy. That way it sees
your request (so destinations you typed are trusted: 30.9% of AgentDojo's
benign tasks need an approval instead of 44.3%, same attack results), covers
Claude Code's own tools (`Read`, `WebFetch`, `Write`, `Bash`) as well as every
MCP server, and asks through Claude Code's normal approval prompt. It only
ever answers "ask" or "deny", never "allow", so it can't loosen your
permission settings.

```bash
python -m src.gateway hooks-snippet -c gateway.yaml   # paste into ~/.claude/settings.json or .claude/settings.json
python eval/claude_code/e2e.py                        # real Claude Code, with vs without the hook (needs `claude` /login)
```

Config: `builtin: {policy: claude-code}` for the built-in tools, and under
`servers:` your Claude Code MCP server names with their policies (no
`command` needed). `Bash` is classified from its text: commands that can send
data out (`curl`, `ssh`, `git push`, …) or hide what they do (`base64 -d`,
`eval`, `| sh`, `python -c`) get the scrutiny; that list can't be complete, so
keep Claude Code's own Bash permissions on. The detector isn't available in
hook mode (each hook is a fresh process).

### As an MCP proxy (other clients)

In your MCP client, replace the individual servers with one entry whose command
is `python -m src.gateway run -c /abs/path/gateway.yaml` (cwd = this repo). With
several servers, tools are exposed as `<server>__<tool>`.

**On AgentDojo** (worst-case agent that obeys every injection), it lets through
0.3% of data-theft attacks and none of the payment/access hijacks or deletions,
with 30.9% of benign tasks needing an approval (44.3% as an MCP gateway, which
can't see your request); it does not stop steering among legitimate options.
An adaptive red-team suite against its own rules passes 20/20. Full comparison with detectors and tool filtering in
[RESULTS.md](RESULTS.md).

**Limits.** It controls flows, not intent: an approved or unlabelled flow is not
inspected further, and a model can paraphrase a secret past DLP (the flow rules
still apply). GitHub repo visibility comes from your config, not the API. Only
tools are proxied (not resources/prompts), over stdio.

## Setup

```bash
pip install mcp openai python-dotenv
cp .env.example .env   # add your Groq + NVIDIA NIM keys
```

## Run the leak-rate benchmark

```bash
python run_pilot.py --models "gpt-oss-20b (Groq)" "mistral-large-2 (NIM)" --runs 10
python run_pilot.py --all --runs 10
```

Results: `results/summary.json` + raw traces in `results/raw/`.

## Layout

- `src/servers/github_mock.py` — sandbox MCP server (issues, fake secret, sinks)
- `attacks/scenarios.py` — attack payloads (structure of real 2026 incidents)
- `src/harness/` — provider registry + tool-calling agent
- `run_pilot.py` — the benchmark runner
- `src/gateway/` — flow-control gateway: `rules.py` (YAML policies), `engine.py`
  (labels + flow rules, MCP-agnostic), `dlp.py`, `pins.py`, `gateway.py` (MCP
  server), `policies/` (presets). `proxy.py` is the original single-server
  research proxy used by the benchmarks.

## Ethics

This measures the vulnerability of *your own* agent setup in a sandbox so a
defense can block it. Attack payloads recreate the *structure* of public
disclosures, not verbatim exploits, and target only a fake in-repo canary.
