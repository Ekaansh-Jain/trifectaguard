# Security policy

flowguard is a security tool, so a way around it is the most useful bug you can
report. Please try to break it.

## What counts as a bypass

With a correct policy for the tools involved, any of these:

- data the session read from a private source, or a credential, reaches a
  public or external destination without an ask or a block;
- a destination (recipient, URL, account, IBAN) that only untrusted content
  supplied is used without an ask;
- an action classed as access change, deletion or a write to an executable
  location runs after untrusted content without an ask;
- a crash, malformed input or lost state that makes the hook, proxy or library
  allow a call it would otherwise stop.

Out of scope, because flowguard doesn't claim them (see the README's *Limits*):
steering an agent among legitimate options, the text an agent writes to a
legitimate recipient, the agent's final answer, and shell commands whose effect
isn't visible in their text (use an OS sandbox for those).

A policy that misclassifies a tool in a preset we ship is in scope too.

## How to report

Open a private security advisory on the repository (GitHub → Security →
Report a vulnerability), or email the maintainer. Include the smallest session
that reproduces it: the user's request, the tool calls and results in order,
and the call that should have been stopped. The easiest form is a test:

- a case in `eval/redteam/adaptive.py` (a list of steps and the expected outcome), or
- a failing property in `tests/test_properties.py`.

Fixed bypasses become regression tests and are credited in the changelog
unless you'd rather not be named.

## Verifying claims yourself

```bash
python run_all_tests.py --no-llm                           # unit, e2e, red-team, properties
FLOWGUARD_EXAMPLES=20000 python -m pytest tests/test_properties.py
python eval/agentdojo/worst_case.py --hook                 # AgentDojo, model-independent
```
