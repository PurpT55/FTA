#!/usr/bin/env python3
"""Generate PROJECT_INDEX.json: a single machine-readable synthesis of the repository.

Curated knowledge (purpose, maturity, history, limitations, roadmap, conventions) lives in
``tools/index_meta.json``. Everything that can be derived from the code is extracted here, so the index
cannot silently drift: file inventory with one-line summaries, analysers and rule tables, finding ids
per language and their parity gap, CLI commands and options, Android permissions/components, tests,
docs and skills.

    python3 tools/gen_index.py           # write PROJECT_INDEX.json
    python3 tools/gen_index.py --check   # exit 1 if the committed index is stale (used by CI)
    python3 tools/gen_index.py --stdout  # print instead of writing

Consumers: read ``components`` for what exists and how mature it is, ``extension_points`` + ``rules`` to
extend, ``files[].summary`` to locate code without opening it, ``known_limitations`` before promising things.
"""
from __future__ import annotations

import argparse
import ast
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "PROJECT_INDEX.json")
META = os.path.join(ROOT, "tools", "index_meta.json")
SCHEMA = "fta-project-index/1"
LANG = {".py": "python", ".kt": "kotlin", ".kts": "gradle-kotlin", ".sh": "bash", ".md": "markdown", ".json": "json",
        ".yml": "yaml", ".yaml": "yaml", ".html": "html", ".xml": "xml", ".properties": "properties", ".toml": "toml", ".txt": "text"}
SKIP = re.compile(r"(^|/)(\.git|build|\.gradle|__pycache__|node_modules)(/|$)|\.(jar|apk|zip|keystore|png)$|^PROJECT_INDEX\.json$")


def rel(p: str) -> str:
    return os.path.relpath(p, ROOT).replace(os.sep, "/")


def read(path: str) -> str:
    with open(os.path.join(ROOT, path), encoding="utf-8", errors="replace") as fh:
        return fh.read()


def tracked_files() -> list[str]:
    """git ls-files when available (respects .gitignore), else a filtered walk."""
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.split("\n")
        files = [f for f in out if f and os.path.isfile(os.path.join(ROOT, f))]
    except (OSError, subprocess.CalledProcessError):
        files = [rel(os.path.join(d, f)) for d, _, fs in os.walk(ROOT) for f in fs]
    return sorted(f for f in set(files) if not SKIP.search(f))


# --------------------------------------------------------------------------- summaries
FALLBACK = {"pyproject.toml": "Python packaging: droidtriage console script, stdlib only",
            "AndroidManifest.xml": "Android manifest: permissions and components",
            "build.gradle.kts": "Gradle build script", "settings.gradle.kts": "Gradle settings: module list",
            "gradle.properties": "Gradle properties", "gradle-wrapper.properties": "Gradle wrapper version",
            "index_meta.json": "Curated metadata merged into PROJECT_INDEX.json by tools/gen_index.py",
            "__init__.py": "Package marker", "custom_example.txt": "Example custom IOC list (type:value lines)"}


def summary(path: str, text: str) -> str:
    """First meaningful line: module docstring, KDoc/comment, markdown heading, or shell header comment."""
    s = _summary(path, text)
    return s or FALLBACK.get(os.path.basename(path), "")


def _summary(path: str, text: str) -> str:
    ext = os.path.splitext(path)[1]
    if ext in (".yml", ".yaml"):
        m = re.search(r"^name:\s*(.+)$", text, re.M)
        return f"Workflow: {m.group(1)}" if m else ""
    try:
        if ext == ".py":
            doc = ast.get_docstring(ast.parse(text)) or ""
            return doc.strip().split("\n")[0]
        if ext in (".kt", ".kts"):
            m = re.search(r"/\*\*\s*\n?\s*\*?\s*(.+?)(?:\n|\*/)", text) or re.search(r"^\s*//\s*(.+)$", text, re.M)
            return m.group(1).strip().rstrip("*/ ").strip() if m else ""
        if ext == ".md":
            m = re.search(r"^description:\s*(.+)$", text, re.M) or re.search(r"^#+\s+(.+)$", text, re.M)
            return m.group(1).strip() if m else ""
        if ext == ".sh":
            lines = [ln[1:].strip() for ln in text.splitlines()[1:6] if ln.startswith("#")]
            return lines[0] if lines else ""
        if ext == ".html":
            m = re.search(r"<title>(.*?)</title>", text)
            return m.group(1) if m else ""
    except (SyntaxError, ValueError):
        return ""
    return ""


def file_inventory(files: list[str]) -> list[dict]:
    out = []
    for f in files:
        ext = os.path.splitext(f)[1]
        if ext not in LANG:
            continue
        text = read(f)
        out.append({"path": f, "language": LANG[ext], "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
                    "sha256": hashlib.sha256(text.encode()).hexdigest()[:16], "summary": summary(f, text)[:200]})
    return out


# --------------------------------------------------------------------------- python introspection
def python_section() -> dict:
    sys.path.insert(0, os.path.join(ROOT, "analyzer"))
    import droidtriage
    from droidtriage import apk, cli, logs, pipeline  # noqa: F401  (pipeline registers analysers)
    from droidtriage.playbook import PLAYBOOK
    from droidtriage.registry import ordered

    ids = set()
    for f in glob.glob(os.path.join(ROOT, "analyzer", "droidtriage", "*.py")):
        ids |= set(re.findall(r'(?:Finding|add)\("([a-z][\w.\-]*[\w])"', read(rel(f))))
    ids |= {"log." + r.id for r in logs.RULES} | {"apk." + r[0] for r in apk.API_RULES} | {"apk." + r[0] for r in apk.MANIFEST_RULES}
    ids.discard("wifi.open")   # docstring example in registry.py
    return {
        "version": droidtriage.__version__,
        "analyzers": [{"name": a.name, "order": a.order, "title": a.title, "description": a.description,
                       "function": f"{a.fn.__module__}.{a.fn.__name__}"} for a in ordered()],
        "logcat_rules": [{"id": "log." + r.id, "severity": r.severity, "category": r.category, "title": r.title, "mitre": r.mitre}
                         for r in logs.RULES],
        "apk_code_rules": [{"id": "apk." + r[0], "severity": r[2], "category": r[3], "title": r[4], "mitre": r[5]} for r in apk.API_RULES],
        "apk_manifest_rules": [{"id": "apk." + r[0], "severity": r[2], "category": r[3], "title": r[4], "mitre": r[5]} for r in apk.MANIFEST_RULES],
        "trackers": sorted(set(apk.TRACKERS.values())),
        "packers": sorted(set(apk.PACKER_LIBS.values()) | set(apk.PACKER_CLASSES.values())),
        "playbook_prefixes": [p for p, _ in PLAYBOOK],
        "finding_ids": sorted(ids),
        "cli": cli_section(cli.build_parser()),
    }


def portable(v):
    """Replace machine-specific absolute paths so the index is identical on every checkout."""
    if not isinstance(v, str):
        return v
    v = v.replace(os.path.join(ROOT, "analyzer", "iocs"), "<repo>/analyzer/iocs").replace(ROOT, "<repo>")
    return v.replace(os.path.expanduser("~"), "~")


def cli_section(parser: argparse.ArgumentParser) -> dict:
    def args_of(p):
        out = []
        for a in p._actions:
            if isinstance(a, (argparse._HelpAction, argparse._SubParsersAction)) or a.help == argparse.SUPPRESS:
                continue
            default = a.default if isinstance(a.default, (str, int, float, bool, type(None))) else str(a.default)
            # Machine-dependent defaults would make `--check` fail on another computer: describe them instead.
            default = {"vt_key": "$VT_API_KEY", "jobs": "min(4, CPUs)"}.get(a.dest, default)
            if a.dest == "dest":
                default = "default IOC folder"
            out.append({"flags": a.option_strings or [a.dest], "help": portable(a.help or ""), "default": portable(default),
                        "choices": list(a.choices) if a.choices else None})
        return out

    def walk(p, prefix=""):
        cmds = []
        for action in p._actions:
            if isinstance(action, argparse._SubParsersAction):
                helps = {c.dest: c.help for c in action._choices_actions}
                for name, sp in action.choices.items():
                    full = f"{prefix}{name}"
                    cmds.append({"command": full, "help": helps.get(name, ""), "arguments": args_of(sp)})
                    cmds += walk(sp, full + " ")
        return cmds
    return {"program": parser.prog, "global": args_of(parser), "commands": walk(parser),
            "exit_codes": {"0": "nothing above --fail-on", "1": "HIGH findings", "2": "malware indicators / IOC match",
                           "3": "usage or I/O error", "130": "interrupted"}}


# --------------------------------------------------------------------------- kotlin / android
def kotlin_section(files: list[str]) -> dict:
    def ids_in(pattern):
        out = set()
        for f in files:
            if f.endswith(".kt") and re.search(pattern, f):
                out |= set(re.findall(r'Finding\("([\w.]+)"', read(f)))
        return sorted(out)

    def fun_vals(path, kind):
        return re.findall(rf"^    val (\w+) = {kind}\b", read(path), re.M) if path in files else []

    events = set()
    for f in files:
        if f.endswith(".kt") and "/sentinel/" in f:
            events |= set(re.findall(r'(?:ev|Event)\([^)]*?"((?:[a-z]+\.)?[a-z]+(?:\.[a-z]+)?)",\s*"', read(f)))
    manifests = {}
    for f in files:
        if f.endswith("AndroidManifest.xml"):
            x = read(f)
            manifests[f.split("/")[1]] = {
                "permissions": sorted(set(re.findall(r'uses-permission android:name="([^"]+)"', x))),
                "defines_permissions": sorted(set(re.findall(r'<permission\s+android:name="([^"]+)"', x))),
                "components": sorted(set(re.findall(r'<(activity|service|receiver|provider)\s+android:name="([^"]+)"', x))),
            }
    core = "android/core/src/main/java/org/droidsuite/core/"
    return {
        "app_rules": fun_vals(core + "AppRules.kt", "AppRule"),
        "device_rules": fun_vals(core + "DeviceRules.kt", "DeviceRule"),
        "finding_ids": ids_in(r"Rules\.kt$"),
        "sentinel_event_types": sorted(e for e in events if len(e) > 2),
        "manifests": {k: {**v, "components": [f"{t}:{n}" for t, n in v["components"]]} for k, v in manifests.items()},
    }


# --------------------------------------------------------------------------- tests / docs / skills
def tests_section(files: list[str]) -> dict:
    py = [f for f in files if f.startswith("analyzer/tests/test_") and f.endswith(".py")]
    kt = [f for f in files if "/src/test/" in f and f.endswith(".kt")]
    py_count = sum(len(re.findall(r"^\s+def test_", read(f), re.M)) for f in py)
    kt_count = sum(read(f).count("@Test") for f in kt)
    return {
        "python": {"files": py, "count": py_count, "run": "cd analyzer && python3 -W error::ResourceWarning -m unittest discover -s tests -t .",
                   "optional": "DROIDTRIAGE_TEST_APK=<real.apk> enables binary-parser tests"},
        "kotlin": {"files": kt, "count": kt_count, "run": "tools/kotlin_check.sh  (or: cd android && ./gradlew test)"},
        "ci": [f for f in files if f.startswith(".github/workflows/")],
    }


def skills_section(files: list[str]) -> list[dict]:
    out = []
    for f in files:
        if f.startswith(".claude/skills/") and f.endswith("SKILL.md"):
            t = read(f)
            name = re.search(r"^name:\s*(.+)$", t, re.M)
            desc = re.search(r"^description:\s*(.+)$", t, re.M)
            out.append({"name": name.group(1).strip() if name else f, "path": f, "description": desc.group(1).strip() if desc else ""})
    return out


def docs_section(files: list[str]) -> list[dict]:
    return [{"path": f, "title": summary(f, read(f))} for f in files
            if f.endswith(".md") and not f.startswith(".claude/") and "/iocs/" not in f]


# --------------------------------------------------------------------------- assemble
def build() -> dict:
    with open(META, encoding="utf-8") as fh:
        meta = json.load(fh)
    files = tracked_files()
    inv = file_inventory(files)
    py = python_section()
    kt = kotlin_section(files)
    loc: dict[str, int] = {}
    for f in inv:
        loc[f["language"]] = loc.get(f["language"], 0) + f["lines"]
    tree = hashlib.sha256("".join(f["path"] + f["sha256"] for f in inv).encode()).hexdigest()[:16]
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_tree_hash": tree,
        "how_to_use": "Curated sections come from tools/index_meta.json; files/rules/cli/tests are extracted from code by tools/gen_index.py. "
                      "Regenerate after any change; CI runs --check.",
        "project": meta["project"],
        "stats": {"files": len(inv), "lines_by_language": dict(sorted(loc.items())),
                  "python_tests": None, "kotlin_tests": None},
        "components": meta["components"],
        "extension_points": meta["extension_points"],
        "rules": {
            "python": {k: py[k] for k in ("analyzers", "logcat_rules", "apk_code_rules", "apk_manifest_rules", "trackers", "packers", "playbook_prefixes", "finding_ids")},
            "kotlin": {k: kt[k] for k in ("app_rules", "device_rules", "finding_ids", "sentinel_event_types")},
            "parity_gap_kotlin_only": sorted(set(kt["finding_ids"]) - set(py["finding_ids"])),
        },
        "cli": py["cli"],
        "android": kt["manifests"],
        "tests": tests_section(files),
        "skills": skills_section(files),
        "docs": docs_section(files),
        "conventions": meta["conventions"],
        "known_limitations": meta["known_limitations"],
        "roadmap": meta["roadmap"],
        "history": meta["history"],
        "files": inv,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if PROJECT_INDEX.json is stale")
    ap.add_argument("--stdout", action="store_true", help="print the index instead of writing it")
    a = ap.parse_args()
    idx = build()
    idx["stats"]["python_tests"] = idx["tests"]["python"]["count"]
    idx["stats"]["kotlin_tests"] = idx["tests"]["kotlin"]["count"]
    text = json.dumps(idx, indent=1, ensure_ascii=False) + "\n"
    if a.stdout:
        sys.stdout.write(text)
        return 0
    if a.check:
        try:
            with open(OUT, encoding="utf-8") as fh:
                old = json.load(fh)
        except (OSError, ValueError):
            print("PROJECT_INDEX.json missing or invalid: run python3 tools/gen_index.py", file=sys.stderr)
            return 1
        strip = lambda d: {k: v for k, v in d.items() if k != "generated_at"}  # noqa: E731
        if strip(old) != strip(json.loads(text)):
            changed = sorted(k for k in idx if k != "generated_at" and old.get(k) != idx[k])
            print(f"PROJECT_INDEX.json is stale (sections: {', '.join(changed)}): run python3 tools/gen_index.py", file=sys.stderr)
            return 1
        print("PROJECT_INDEX.json is up to date")
        return 0
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {rel(OUT)}: {idx['stats']['files']} files, {len(idx['rules']['python']['finding_ids'])} python ids, "
          f"{len(idx['rules']['kotlin']['finding_ids'])} kotlin ids, {idx['stats']['python_tests']}+{idx['stats']['kotlin_tests']} tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
