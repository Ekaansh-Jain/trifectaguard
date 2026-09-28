"""
Classify a Bash command by the programs it runs and the files it names,
instead of by substrings of its text (which flagged `grep -c`, "sync" and
"email" as network tools on real sessions).

The command is split into simple commands (on ; && || | & and newlines, plus
the contents of $(…) and `…`), each reduced to its program (env assignments,
wrappers like sudo/env/time/xargs and directory prefixes removed) and its
arguments. Then:

  external     a program that sends data off the machine (curl, ssh, …), a
               sending subcommand (git push, gh pr create, npm publish, …),
               bash's /dev/tcp, or inline interpreter code using the network
  unknown      inline code whose behaviour isn't visible (it builds code at run
               time: exec/eval/base64 decoding/dynamic imports), eval/source,
               or piping into a shell
  destructive  rm -r, git reset --hard, … (policy globs, on the simple command)
  local        anything else

It reads secrets when an argument is a path to a credential file (policy
secret_paths, matched against path-like arguments, not arbitrary words) or the
command dumps the environment. It reads untrusted content when it fetches
someone else's content (curl, git clone/pull, gh pr view, …).

Scripts run by an interpreter (`python app.py`, `npm test`) are local: their
code isn't in the command. That's a known gap; Claude Code's /sandbox limits
what they can reach.
"""
import fnmatch
import os
import re
import shlex

WRAPPERS = {"sudo", "env", "command", "builtin", "exec", "nohup", "time", "nice", "timeout", "stdbuf",
            "xargs", "caffeinate", "doas"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
INTERPRETERS = SHELLS | {"python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php"}
INLINE_FLAGS = {"-c", "-e", "--eval", "-p"}
SEPARATORS = {";", "&&", "||", "|", "&", ";;", "|&"}
SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
SINGLE_QUOTED = re.compile(r"'[^'\n]*'")


def split_heredocs(command: str) -> tuple[str, list[str]]:
    """Remove heredoc bodies (data fed to a program, not commands) and return
    them in order, so `python - <<'EOF' … EOF` can be checked like inline code."""
    lines, out, bodies = command.split("\n"), [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        for m in HEREDOC.finditer(line):
            end, body = m.group(2), []
            i += 1
            while i < len(lines) and lines[i].strip() != end:
                body.append(lines[i])
                i += 1
            bodies.append("\n".join(body))
        i += 1
    return "\n".join(out), bodies
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _tokens(text: str) -> list[str]:
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:  # unbalanced quotes (often an apostrophe in text): split roughly instead
        return re.findall(r"\|\||&&|[;&|<>()]|[^\s;&|<>()]+", text.replace('"', " ").replace("'", " "))


def simple_commands(command: str) -> list[tuple[list[str], bool]]:
    """[(words, fed_by_pipe)] for every simple command, including $(…) and `…` contents."""
    out = []
    unquoted = SINGLE_QUOTED.sub("''", command)  # `…` or $(…) inside '…' is just text
    pieces = [command] + [a or b for a, b in SUBSTITUTION.findall(unquoted)]
    for piece in pieces:
        for line in piece.replace("\\\n", " ").splitlines():
            toks = _tokens(line)
            words, piped = [], False
            for t in toks:
                if t in SEPARATORS:
                    if words:
                        out.append((words, piped))
                    words, piped = [], t in ("|", "|&")
                elif t in ("(", ")"):
                    continue
                else:
                    words.append(t)
            if words:
                out.append((words, piped))
    return out


def program(words: list[str]) -> tuple[str, list[str]]:
    """Strip env assignments, wrappers (and their options) and directory prefixes."""
    w = list(words)
    while w and (ASSIGNMENT.match(w[0]) or os.path.basename(w[0]) in WRAPPERS):
        head = os.path.basename(w.pop(0))
        while head in WRAPPERS and w and (w[0].startswith("-") or (head == "timeout" and w[0][:1].isdigit())):
            w.pop(0)
    if not w:
        return "", []
    return os.path.basename(w[0]).lstrip("\\"), w[1:]


def _starts(prog: str, args: list[str], entries) -> bool:
    """entries like 'git push' or 'gh pr create': program plus leading subcommand words."""
    for e in entries:
        parts = e.split()
        if parts[0] == prog and args[:len(parts) - 1] == parts[1:]:
            return True
    return False


DYNAMIC_MODULES = {"subprocess", "importlib", "ctypes", "marshal", "pty", "multiprocessing"}
DYNAMIC_CALLS = {"exec", "eval", "compile", "__import__", "system", "popen", "spawn", "b64decode",
                 "decode", "loads", "execv", "execve", "Popen"}


def inspect_python(code: str, network_modules: list[str]) -> str | None:
    """'dynamic' | 'network' | None for Python source, from its syntax tree:
    what it imports and calls, not words inside its strings. Returns 'unparsed'
    if it isn't valid Python."""
    import ast
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return "unparsed"
    net = {m.split(".")[0] for m in network_modules}
    imported, found = set(), None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
            if name in {"exec", "eval", "compile", "__import__"}:
                found = "dynamic"
            elif name in ("system", "popen") and isinstance(f, ast.Attribute):
                found = "dynamic"  # os.system / os.popen run a shell command
            elif name in ("urlopen", "fetch"):
                found = found or "network"
    if imported & DYNAMIC_MODULES:
        found = "dynamic"
    if found != "dynamic" and imported & net:
        found = "network"
    return found


def uses_network(code: str, modules: list[str]) -> bool:
    """Network use visible in inline code: an import/require of a network
    module, or a direct network call."""
    mods = "|".join(re.escape(m) for m in modules)
    if not mods:
        return False
    patterns = [
        rf"(?m)^\s*(?:import|from)\s+(?:{mods})(?:[\s.,;]|$)",           # python: import requests / from urllib.request …
        rf"(?:^|[;\s])import\s+(?:{mods})(?:[\s.,;]|$)",                 # python one-liners: …; import socket
        rf"require\(\s*['\"](?:node:)?(?:{mods})['\"]\s*\)",            # node: require('https')
        rf"from\s+['\"](?:node:)?(?:{mods})['\"]",                        # node ESM: import x from 'axios'
        r"\b(?:urlopen|fetch)\s*\(",                                      # urlopen(…), fetch(…)
    ]
    return any(re.search(p, code) for p in patterns)


def _pathlike(arg: str) -> bool:
    return "/" in arg or arg.startswith(".") or "." in os.path.basename(arg)


def classify(command: str, v: dict) -> tuple[set, str | None]:
    """(reads, writes) for one Bash command; v = the policy's vars."""
    reads, writes = {"private"}, "local"
    rank = {"local": 0, "destructive": 1, "external": 2, "unknown": 3}

    def worse(w):
        nonlocal writes
        writes = w if rank[w] > rank[writes] else writes

    if "/dev/tcp/" in command or "/dev/udp/" in command:
        worse("external")
    secret_globs = [g.lower() for g in v.get("secret_paths", [])]
    command, heredocs = split_heredocs(command)
    for words, piped in simple_commands(command):
        if words == ["env"] or os.path.basename(words[0]) == "printenv" or words[:2] == ["export", "-p"]:
            reads.add("secret")  # dumping the environment exposes the tokens in it
        prog, args = program(words)
        if not prog:
            continue
        joined = " ".join([prog, *args]).lower()
        if prog in v.get("egress_programs", []) or _starts(prog, args, v.get("egress_subcommands", [])):
            worse("external")
        if prog in v.get("egress_programs", []) or _starts(prog, args, v.get("fetch_subcommands", [])):
            reads.add("untrusted")  # what comes back was written by someone else
        if prog in ("eval", "source", "."):
            worse("unknown")
        if prog in SHELLS and (piped or not args) and "<<" not in args:
            worse("unknown")  # a script piped into a shell
        inline = prog in INTERPRETERS and args and args[0] in INLINE_FLAGS
        fed = prog in INTERPRETERS and "<<" in args and heredocs  # python - <<'EOF' … EOF
        if prog in SHELLS and fed:
            r, w = classify(heredocs.pop(0), v)  # a shell script in a heredoc: classify it as one
            reads |= r
            if w:
                worse(w)
        elif inline or fed:
            code = heredocs.pop(0) if fed and not inline else " ".join(args[1:])
            verdict = inspect_python(code, v.get("network_modules", [])) if prog.startswith("python") \
                else "unparsed"
            if verdict == "unparsed":  # not Python (node, ruby, …): fall back to text markers
                if any(m in code for m in v.get("dynamic_code_markers", [])):
                    verdict = "dynamic"
                elif uses_network(code, v.get("network_modules", [])):
                    verdict = "network"
            if verdict == "dynamic":
                worse("unknown")  # it builds or runs other code: behaviour not visible
            elif verdict == "network":
                worse("external")
            if any(m in code.lower() for m in v.get("secret_code_markers", [])):
                reads.add("secret")  # e.g. load_dotenv(): the script reads credentials
        if any(fnmatch.fnmatchcase(joined, g) for g in v.get("destructive_commands", [])):
            worse("destructive")
        for a in args:
            if _pathlike(a) and any(fnmatch.fnmatchcase(a.lower(), g) or fnmatch.fnmatchcase("/" + a.lower(), g)
                                    for g in secret_globs):
                reads.add("secret")
    return reads, (None if writes == "local" else writes)
