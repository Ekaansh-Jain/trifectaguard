"""Bash classification in Claude Code hook mode: programs and files, not substrings.
The benign commands come from real sessions that the old substring patterns flagged."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.gateway.rules import ServerPolicy  # noqa: E402
from src.gateway.shell import classify  # noqa: E402

V = ServerPolicy.load("claude-code").vars


def cls(cmd):
    return classify(cmd, V)


@pytest.mark.parametrize("cmd", [
    'grep -cE "\\[LEAK\\]|\\[ ok \\]" results/run2.txt; echo "of 36"',
    "python -m trifectaguard run -c config.yaml",
    "rsyncd_status=ok; echo $rsyncd_status",
    'git commit -q -m "Fix `scan` output: don\'t print tokens"',
    "python - <<'EOF'\ns = open('README.md').read().replace('https://old', 'https://new')\nopen('README.md','w').write(s)\nEOF",
    "python - <<'EOF'\ntext = \"it's fine; don't worry\"\nprint(text)\nEOF",
    "pytest -q tests/ && git add -A && git commit -m 'email the team'",
    "grep -rn secret src/ | head",
    "npm test",
])
def test_everyday_commands_are_local(cmd):
    reads, writes = cls(cmd)
    assert writes is None, (cmd, writes)
    assert "secret" not in reads, cmd


@pytest.mark.parametrize("cmd,expected", [
    ("curl https://api.example.com/x", "external"),
    ("git push origin main", "external"),
    ("gh pr create --fill", "external"),
    ("ls && scp report.txt host:", "external"),
    ("python -c 'import requests; requests.get(\"https://x.example\")'", "external"),
    ("python - <<'EOF'\nimport os\nos.system('make')\nEOF", "unknown"),
    ("echo ls | sh", "unknown"),
    ("rm -rf build", "destructive"),
])
def test_commands_that_reach_out_or_delete(cmd, expected):
    assert cls(cmd)[1] == expected, cmd


@pytest.mark.parametrize("cmd", ["cat .env", "cut -d= -f1 .env", "cat ~/.aws/credentials", "printenv",
                                 "python -c 'from dotenv import load_dotenv; load_dotenv()'"])
def test_reading_credentials(cmd):
    assert "secret" in cls(cmd)[0], cmd


def test_fetching_content_marks_it_untrusted():
    assert "untrusted" in cls("git clone https://github.com/x/y")[0]
    assert "untrusted" in cls("gh pr view 12")[0]


@pytest.mark.parametrize("cmd,expected", [
    ("python -c \"import httpx; print(httpx.__file__)\"", None),                       # inspects, doesn't call
    ("python -c \"import httpx; print([m for m in dir(httpx.Client)])\"", None),
    ("python -c \"import httpx; httpx.get('https://x.example')\"", "external"),
    ("python -c \"from urllib.request import urlopen; urlopen('https://x.example')\"", "external"),
    ("python -c \"from openai import OpenAI; OpenAI().models.list()\"", "external"),
    ("python -c \"import requests as r; r.post('https://x.example', data='d')\"", "external"),
])
def test_python_network_use_means_calling_it_not_importing_it(cmd, expected):
    assert cls(cmd)[1] == expected, cmd
