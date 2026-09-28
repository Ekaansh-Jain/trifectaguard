"""
`trifectaguard draft-policy`: propose a policy for tools we have no preset for,
from each tool's name and parameters, with fixed and published rules. It's a
starting point for review, not a substitute for it: read the output before
using it, and `trifectaguard inspect` shows what each tool ended up as.

Rules, in order (the first match wins):
  destructive  a deleting verb                         delete, remove, cancel, …
  external     a verb that sends data, money or orders  send, share, transfer, pay, post, …
  privileged   a verb or object that changes access,   grant, unlock, set, …; guest, permission, …
               accounts, settings or devices
  internal     a verb that creates or edits the user's create, add, save, write, …
               own things
  reads        a reading verb                          get, search, read, view, list, …
  otherwise    unclassified (treated as untrusted content with an unknown destination)

Every read is marked untrusted + private: without knowing who can write the
data a tool returns, assume someone else can. A parameter named like a
recipient (to, email, account, url, …) becomes the tool's destination.
"""
import re

DESTRUCTIVE = {"delete", "remove", "cancel", "clear", "erase", "terminate", "discard", "destroy", "purge",
               "wipe", "drop", "unsubscribe", "revoke", "deactivate", "disable", "uninstall", "unfollow"}
EXTERNAL = {"send", "share", "transfer", "pay", "post", "publish", "upload", "forward", "reply", "tweet",
            "retweet", "comment", "email", "message", "mail", "invite", "book", "order", "purchase", "buy",
            "donate", "submit", "trade", "sell", "withdraw", "deposit", "call", "sms", "text", "notify",
            "broadcast", "reserve", "checkout", "tip", "request", "export", "sync", "dm", "follow",
            "like", "repost", "subscribe", "apply", "refer", "transmit", "dispatch", "wire",
            # filling or clicking in a web page hands what you enter to that site
            "fill", "autofill", "input", "type", "click"}
PRIVILEGED = {"grant", "unlock", "lock", "update", "modify", "change", "set", "edit", "enable", "control",
              "manage", "schedule", "register", "authorize", "assign", "approve", "move", "turn", "adjust",
              "start", "stop", "activate", "configure", "install", "reset", "restore", "block", "unblock",
              "allow", "deny", "launch", "trigger", "arm", "disarm", "dispense", "prescribe", "execute",
              "run", "operate", "open", "close", "go", "pick", "place", "handle", "toggle", "play",
              "pause", "resume", "redeem", "transfer_ownership", "promote", "demote", "ban", "kick"}
PRIVILEGED_OBJECTS = {"guest", "access", "permission", "permissions", "password", "role", "admin", "collaborator",
                      "member", "members", "key", "keys", "credential", "credentials", "owner", "ownership",
                      "policy", "rule", "rules", "door", "lock", "alarm", "device", "settings", "setting"}
INTERNAL = {"create", "add", "save", "write", "append", "insert", "copy", "rename", "tag", "mark", "star",
            "bookmark", "label", "sort", "organize", "merge", "duplicate", "archive", "draft", "note",
            "record", "log", "store", "upsert", "put", "select", "scroll"}
READ = {"get", "search", "read", "view", "list", "retrieve", "check", "find", "query", "lookup", "look",
        "browse", "fetch", "download", "show", "describe", "navigate", "scan", "analyze", "track", "monitor",
        "count", "calculate", "compute", "estimate", "convert", "translate", "summarize", "recommend",
        "verify", "validate", "preview", "locate", "identify", "detect", "inspect", "watch", "load",
        "collect", "discover", "explore", "compare", "predict", "forecast", "extract"}
DESTINATION_PARAM = re.compile(
    r"(^|_)(to|recipient|recipients|email|emails|email_address|account|account_number|to_account|payee|"
    r"phone|phone_number|url|user|username|user_id|user_email|guest|guests|guest_id|contact|receiver|"
    r"beneficiary|attendees|participants|collaborator|member|address|handle|channel|repo|repository)$")


def words(name: str) -> list[str]:
    """'TransferFunds' / 'transfer_funds' / 'transferFunds' → ['transfer', 'funds']."""
    parts = re.split(r"[_\-\s.]+", name)
    out = []
    for p in parts:
        out += re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", p)
    return [w.lower() for w in out if w]


def classify_tool(name: str, params: list[str]) -> tuple[dict, str]:
    """(policy entry, why) for one tool."""
    w = words(name)
    dests = [p for p in params if DESTINATION_PARAM.search(p.lower())]

    def sink(cls):
        entry = {"writes": cls}
        if dests and cls in ("external", "privileged", "destructive"):
            entry["destination"] = dests
        return entry

    # the first verb-like word decides (tool names usually lead with the verb)
    for word in w:
        if word in DESTRUCTIVE:
            return sink("destructive"), f"verb '{word}'"
        if word in EXTERNAL:
            return sink("external"), f"verb '{word}'"
        if word in PRIVILEGED:
            return sink("privileged"), f"verb '{word}'"
        if word in INTERNAL:
            if set(w) & PRIVILEGED_OBJECTS:
                return sink("privileged"), f"verb '{word}' on {sorted(set(w) & PRIVILEGED_OBJECTS)}"
            return {"writes": "internal"}, f"verb '{word}'"
        if word in READ:
            return {"reads": ["untrusted", "private"]}, f"verb '{word}'"
    return None, "no known verb: left unclassified"


def draft(tools: list[dict], name: str = "drafted") -> tuple[dict, list[tuple[str, str]]]:
    """tools: [{"name": str, "params": [str, …]}] → (policy document, [(tool, why)])."""
    policy, notes = {"name": name, "tools": {}}, []
    for t in tools:
        entry, why = classify_tool(t["name"], list(t.get("params", [])))
        notes.append((t["name"], why))
        if entry is not None:
            policy["tools"][t["name"]] = entry
    return policy, notes
