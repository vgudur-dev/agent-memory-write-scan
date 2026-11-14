"""Static scan: memory-write entry points in open-source agent frameworks,
and whether any validation-like step appears inside them.

Heuristic, by design. Parses source with `ast`; never imports or runs the code.

Definitions
- Library source: .py files, excluding test, example, cookbook, doc, notebook,
  benchmark and script directories.
- Memory module: a library source file whose path contains "memory"/"memories"
  (case-insensitive), or that defines a class whose name contains "Memory".
  "In-memory" (RAM storage) is not counted as agent memory.
- Memory-write site: a public function or method (name not starting with "_")
  in a memory module whose name is a write verb (optionally prefixed with "a"
  for async variants), either alone (add, save, put) or followed by a word that
  names memory content (add_messages, save_context, upsert_user_memory), and
  whose body does more than pass / ... / raise NotImplementedError.
  Names about configuration, logging, sessions, schemas or prompts are excluded.
- Validation indicator: any of VALIDATION_TERMS appearing anywhere in the
  function's source, docstring included. Keyword presence is not proof of
  real validation, so the "no indicator" share is a lower bound.
"""
import ast
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

EXCLUDE_DIRS = re.compile(
    r"(^|/)(tests?|testing|examples?|cookbooks?|docs?|notebooks?|benchmarks?|"
    r"scripts?|samples?|demos?|tutorials?|\.github|site-packages|node_modules)(/|$)",
    re.I,
)
WRITE_VERB = re.compile(
    r"^a?(add|save|store|put|upsert|insert|write|append|update|remember|persist|record|set|create)(?:_(?P<rest>.*))?$"
)
# The part after the verb must be empty (e.g. add, aadd, save) or name memory content.
MEMORY_NOUN = re.compile(
    r"memor|messag|context|fact|episod|histor|entr|item|document|knowledge|observ|experien|insight|"
    r"chat|turn|event|note|conversation|summar|reflect|thought|preferen|profile|record|text|chunk|triple|node|vector|data",
    re.I,
)
NOT_CONTENT = re.compile(r"config|setting|log|level|status|token|prompt|eval|exception|strategy|client|factory|path|session|col$|index|schema|table", re.I)
VALIDATION_TERMS = [
    "validat", "sanitiz", "sanitis", "guard", "verify", "verif", "moderat",
    "allowlist", "whitelist", "denylist", "blocklist", "inject", "redact",
    "is_safe", "unsafe", "trust", "provenance", "hmac", "signature", "policy",
]
VAL_RE = re.compile("|".join(VALIDATION_TERMS), re.I)
# Narrower set: terms that point at checking the *content* for security, not argument validation.
SEC_TERMS = [t for t in VALIDATION_TERMS if t not in ("validat", "verif", "verify", "signature", "policy", "trust")]
SEC_RE = re.compile("|".join(SEC_TERMS), re.I)


def is_write_name(name: str) -> bool:
    m = WRITE_VERB.match(name)
    if not m:
        return False
    rest = m.group("rest") or ""
    if not rest:
        return True
    return bool(MEMORY_NOUN.search(rest)) and not NOT_CONTENT.search(rest)


def is_stub(fn: ast.AST) -> bool:
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body:
        return True
    if len(body) == 1:
        s = body[0]
        if isinstance(s, ast.Pass):
            return True
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis:
            return True
        if isinstance(s, ast.Raise):
            exc = s.exc
            name = getattr(getattr(exc, "func", exc), "id", "") if exc is not None else ""
            if name == "NotImplementedError":
                return True
    return False


def scan_repo(root: Path):
    files = [p for p in root.rglob("*.py") if p.is_file()]
    lib = [p for p in files if not EXCLUDE_DIRS.search(str(p.relative_to(root)))]
    sites, parse_errors, memory_modules = [], 0, 0
    for p in lib:
        rel = str(p.relative_to(root))
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except (SyntaxError, ValueError, RecursionError):
            parse_errors += 1
            continue
        has_mem_class = any(isinstance(n, ast.ClassDef) and "memory" in n.name.lower().replace("inmemory", "")
                            for n in ast.walk(tree))
        path_hit = re.search(r"memor(y|ies)", re.sub(r"in_?memory", "", rel, flags=re.I), re.I)
        if not (path_hit or has_mem_class):
            continue
        memory_modules += 1
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_") \
                    and is_write_name(node.name) and not is_stub(node):
                seg = ast.get_source_segment(src, node) or ""
                m = VAL_RE.search(seg)
                sites.append({
                    "file": rel, "line": node.lineno, "function": node.name,
                    "validation_indicator": bool(m), "matched_term": m.group(0).lower() if m else "",
                    "security_indicator": bool(SEC_RE.search(seg)),
                })
    return {"py_files": len(files), "library_py_files": len(lib), "memory_modules": memory_modules,
            "parse_errors": parse_errors, "sites": sites}


def main(repos_dir: str, out_dir: str):
    repos_dir, out = Path(repos_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary, all_sites = [], []
    for d in sorted(p for p in repos_dir.iterdir() if p.is_dir()):
        sha = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        r = scan_repo(d)
        n = len(r["sites"])
        v = sum(s["validation_indicator"] for s in r["sites"])
        name = d.name.replace("__", "/").replace("_", "/", 1) if "/" not in d.name else d.name
        summary.append({"repo": name, "commit": sha, "py_files": r["py_files"], "library_py_files": r["library_py_files"],
                        "memory_modules": r["memory_modules"], "write_sites": n, "with_indicator": v,
                        "without_indicator": n - v, "with_security_indicator": sum(s["security_indicator"] for s in r["sites"]), "parse_errors": r["parse_errors"]})
        for s in r["sites"]:
            all_sites.append({"repo": name, "commit": sha[:12], **s})
    with open(out / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys())); w.writeheader(); w.writerows(summary)
    with open(out / "sites.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(all_sites[0].keys())); w.writeheader(); w.writerows(all_sites)
    tot = {k: sum(s[k] for s in summary) for k in ["py_files", "library_py_files", "memory_modules", "write_sites", "with_indicator", "without_indicator", "with_security_indicator"]}
    tot["repos"] = len(summary)
    tot["repos_with_sites"] = sum(1 for s in summary if s["write_sites"])
    (out / "totals.json").write_text(json.dumps(tot, indent=2))
    print(json.dumps(tot, indent=2))
    for s in summary:
        print(f"{s['repo']:38} {s['commit'][:10]} files={s['py_files']:6} lib={s['library_py_files']:5} memmods={s['memory_modules']:4} sites={s['write_sites']:4} ind={s['with_indicator']:3} sec={s['with_security_indicator']:3}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
