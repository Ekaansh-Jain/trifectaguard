# MCP injection lab

A defensive-security project in three parts:

1. **Leak-rate benchmark** — replays publicly documented 2026 agent attacks
   (malicious GitHub issue, hidden instruction in a fetched web page) against
   many models through a mock MCP server, and measures how often each model
   leaks a canary secret into a tool call. *(this stage)*
2. **Detector benchmark** — compares hosted/open prompt-injection detectors
   (Prompt Guard 2, gpt-oss-safeguard, LLM judges, …) on *tool outputs*, on
   detection rate, false positives on hard negatives, and latency.
3. **Gateway** — an MCP proxy with a deterministic taint tripwire
   (untrusted source → sensitive sink ⇒ block/confirm) + tool-description hash
   pinning, with the best detector plugged in.

Everything runs locally against a sandbox. No real accounts, tokens, or repos.

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

## Ethics

This measures the vulnerability of *your own* agent setup in a sandbox so a
defense can block it. Attack payloads recreate the *structure* of public
disclosures, not verbatim exploits, and target only a fake in-repo canary.
