# AgentDojo evaluation

Evaluates the flow-control engine (`src/gateway/engine.py`) on
[AgentDojo](https://github.com/ethz-spylab/agentdojo) v1.2.2, the standard
prompt-injection benchmark for tool-using agents (workspace, travel, banking,
slack suites), against AgentDojo's own defenses as baselines.

```bash
pip install agentdojo
python eval/agentdojo/worst_case.py --detectors   # model-independent, ~10 min, no API
python eval/agentdojo/live.py --model "gpt-oss-120b (Groq)" --suites banking slack travel workspace \
    --pairs 12 --benign 8 --defense none flow --out live_gpt-oss-120b.jsonl
python eval/agentdojo/report.py                   # markdown tables from results/agentdojo/
```

## Two evaluations

**1. Worst-case agent (`worst_case.py`).** A scripted agent that is perfectly
capable and perfectly gullible: it performs the user task with AgentDojo's
ground-truth tool calls, and the moment a tool output shows it the injection it
carries out the attacker's goal (the injection task's ground-truth calls), then
resumes. Undefended, every attack succeeds by construction, so a defense is
scored on what it can stop *regardless of the model*, which is the property
flow control claims. Every (user task × injection task) pair is run and scored
with AgentDojo's own `utility` / `security` checks.

- Injection tasks AgentDojo ships without ground-truth calls (workspace 6–13,
  travel 6) can't be scripted and are skipped here; the live run covers them.
- Security is reported over the attacks that succeed against the undefended
  agent (591 pairs; a few fail even undefended because the user task's own
  later calls interfere with AgentDojo's check).
- A call a defense refuses is not executed and is left out of the trace
  AgentDojo scores (one slack check reads the trace, and would otherwise count
  an attempted-but-blocked invite as a success).
- `ask` has no human in a benchmark: it is scored as a refusal and reported
  separately as "needing approval", the burden a real user would see.

**2. Live models (`live.py`).** A real LLM agent (AgentDojo's default system
prompt, `important_instructions` attack) on a fixed random sample of pairs and
benign tasks per suite, with the defense between the model's tool calls and
their execution, exactly where the gateway sits. Refused calls return the
gateway's error message to the model.

## Defenses compared

| Defense | What it is |
|---|---|
| no defense | |
| tool filter (oracle) | AgentDojo's `tool_filter` lets an LLM choose the tools a task needs before reading any data. The oracle version allows exactly the tools the ground truth uses: its best case, not what an LLM achieves. |
| PI detector (protectai deberta) | AgentDojo's `transformers_pi_detector`: flagged tool outputs are redacted. Scanned in overlapping 512-token windows (AgentDojo's truncates), i.e. a more generous version. |
| our detector (ModernBERT) | this repo's fine-tuned detector, same redaction behaviour, 128-token windows. |
| flow control (library mode) | the engine with the user's request registered as trusted (`trust(prompt)`) and strict destinations: what an agent framework integration sees. |
| flow control (mcp mode) | the same engine as the MCP gateway runs it: it never sees the user's prompt, so destinations the user typed look unseen (lenient mode). |

## Policies

`policies/*.yaml` classify every tool of every suite (67 tools, none
unclassified). They were written from what each tool does (who can write the
data it returns; where its writes go) **before** looking at any injection
task.

After the first run, three changes were made. Both runs are reported
(`results/agentdojo/worst_case_summary_v1_initial.json` is the first):

1. **slack policy:** `get_channels` → untrusted. Channel names are written by
   any workspace member; the first policy marked them private-only, and the
   benchmark hides an injection in a channel name. A policy bug.
2. **slack policy:** `add_user_to_channel`'s destination is the grantee
   (`user`), not the channel. A policy bug.
3. **engine:** the "untrusted destination" check no longer applies to
   `internal`/`local` sinks. Their destinations are inside the trust boundary
   (a workspace member), so they can't be attacker-owned. This trades a few
   incidental catches of "send a phishing link to a teammate" (an integrity
   attack flow control doesn't model) for fewer approval prompts on benign
   tasks.

Change 3 is a design choice made after seeing results, and it is a real
trade-off: with it reverted (library mode, worst case) 66/591 attacks get
through instead of 82/591, but 27/97 benign tasks need approval instead of
20/97 (utility 73.2% vs 80.4%). The extra catches are phishing-style messages
to teammates whose name happened to appear only in untrusted text.

## What flow control does not stop

By design it controls *where data and access go*, not *what the agent decides*:

- steering among legitimate options (book the most expensive hotel on the
  platform, create a harmless-looking calendar entry);
- wrong content sent to a legitimate recipient (a phishing link to a teammate);
- visiting a link that appeared in untrusted content (allowed, because opening
  a link from a message is normal and sends no private data);
- text-only manipulation of the final answer.

These are integrity attacks; stopping them needs either a human in the loop or
data-dependency tracking of every value the model uses (as in CaMeL), which
requires controlling the agent's execution, not just its tool calls.
