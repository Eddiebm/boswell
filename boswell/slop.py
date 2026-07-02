"""
AI Slop Detection — identifies patterns of AI-generated code degradation.

Detects:
  - Utility explosion (too many helper/util files)
  - Single-call wrapper functions (fake abstractions)
  - Duplicated helper names across files
  - Cargo-cult patterns (empty catches, TODO storms, generic names)
  - Re-export chains (index files that add nothing)
  - Dead comment density (AI-generated noise)
"""

import re
from collections import defaultdict
from pathlib import Path

_SKIP_DIRS = {
    "node_modules", ".next", "dist", "out", ".vercel", ".wrangler",
    "build", ".turbo", "coverage", ".boswell", "__pycache__",
}
_SOURCE_EXTS = {".ts", ".tsx", ".js", ".jsx"}

_UTIL_DIR_NAMES = {"utils", "util", "helpers", "helper", "shared", "common", "utilities", "lib"}
_UTIL_STEM_PREFIXES = ("util", "helper", "shared", "common", "misc", "tools")

# Function names so generic they carry no meaning
_GENERIC_NAMES = {
    "handleData", "processData", "manageData", "handleResponse", "processResponse",
    "handleResult", "processResult", "handleRequest", "processRequest",
    "formatData", "parseData", "transformData", "validateData",
    "getData", "setData", "fetchData", "sendData", "updateData",
    "handleError", "processError", "manageError",
    "doSomething", "handleSomething", "processSomething",
    "wrapper", "handler", "processor", "manager", "helper",
}

# TypeScript type/interface names so generic they signal hallucination
_GENERIC_TYPE_NAMES = {
    "Data", "Config", "Options", "Params", "Props", "State", "Context",
    "Result", "Response", "Request", "Payload", "Input", "Output",
    "Item", "Entity", "Record", "Object", "Type", "Model",
}


def _source_files(repo_path: Path) -> list[Path]:
    files = []
    for f in repo_path.rglob("*"):
        if any(p in _SKIP_DIRS for p in f.parts):
            continue
        if f.suffix in _SOURCE_EXTS and f.is_file():
            files.append(f)
    return files


# ── detectors ─────────────────────────────────────────────────────────────

def detect_utility_sprawl(repo_path: Path) -> dict:
    """Count utility/helper files and flag if excessive."""
    util_files: list[str] = []
    seen: set[str] = set()

    for f in _source_files(repo_path):
        rel = str(f.relative_to(repo_path))
        # In a util-named directory
        in_util_dir = any(part.lower() in _UTIL_DIR_NAMES for part in f.parts[:-1])
        # Named like a util file
        is_util_stem = f.stem.lower().startswith(_UTIL_STEM_PREFIXES)
        if (in_util_dir or is_util_stem) and rel not in seen:
            seen.add(rel)
            util_files.append(rel)

    total = len(util_files)
    score = 0
    if total > 30:
        score = 40
    elif total > 15:
        score = 25
    elif total > 8:
        score = 10

    return {
        "count": total,
        "files": util_files[:10],
        "score": score,
        "verdict": (
            f"{total} utility/helper files — severe sprawl" if total > 30
            else f"{total} utility/helper files — concerning" if total > 15
            else f"{total} utility/helper files" if total > 8
            else f"{total} utility/helper files — normal"
        ),
    }


def detect_single_call_wrappers(repo_path: Path) -> dict:
    """Detect functions whose entire body is one call to another function."""
    # Matches: function foo(...) { \n  return bar(...); \n }
    # or: const foo = (...) => bar(...);
    wrapper_re = re.compile(
        r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{[^{}]{0,120}?\breturn\s+\w+\([^)]*\)\s*;?\s*\}',
        re.DOTALL,
    )
    arrow_wrapper_re = re.compile(
        r'(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\w+\([^)]*\)\s*;',
    )

    wrappers: list[dict] = []
    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            rel = str(f.relative_to(repo_path))
            for m in list(wrapper_re.finditer(content)) + list(arrow_wrapper_re.finditer(content)):
                body = m.group(0)
                # Skip if body has meaningful logic (multiple lines, conditionals)
                if body.count("\n") > 4:
                    continue
                if any(kw in body for kw in ("if ", "for ", "while ", "switch ", "try ", "await ")):
                    continue
                fn_name = m.group(1)
                if fn_name in ("exports", "module"):
                    continue
                line_no = content[: m.start()].count("\n") + 1
                wrappers.append({"file": rel, "line": line_no, "name": fn_name})
                if len(wrappers) >= 20:
                    break
        except Exception:
            pass
        if len(wrappers) >= 20:
            break

    count = len(wrappers)
    score = min(30, count * 3)

    return {
        "count": count,
        "examples": wrappers[:8],
        "score": score,
        "verdict": (
            f"{count} single-call wrappers — hallucinated abstraction layer" if count > 10
            else f"{count} single-call wrappers — suspicious" if count > 4
            else f"{count} single-call wrappers"
        ),
    }


def detect_duplicate_helpers(repo_path: Path) -> dict:
    """Find function/const names exported from 3+ different files."""
    export_re = re.compile(r'export\s+(?:(?:async\s+)?function|const|class|type|interface)\s+(\w+)')
    name_files: dict[str, list[str]] = defaultdict(list)

    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            rel = str(f.relative_to(repo_path))
            for m in export_re.finditer(content):
                name = m.group(1)
                if len(name) < 4 or name[0].isupper():  # skip types and short names
                    continue
                name_files[name].append(rel)
        except Exception:
            pass

    duplicates = {
        name: files for name, files in name_files.items()
        if len(files) >= 3
    }

    count = len(duplicates)
    score = min(25, count * 5)

    return {
        "count": count,
        "examples": dict(list(duplicates.items())[:6]),
        "score": score,
        "verdict": (
            f"{count} function names duplicated across 3+ files — copy-paste engineering" if count > 5
            else f"{count} duplicated helpers" if count > 1
            else "No duplicated helpers"
        ),
    }


def detect_cargo_cult(repo_path: Path) -> dict:
    """Detect empty catches, TODO storms, and AI boilerplate noise."""
    empty_catch_re = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')
    todo_re = re.compile(r'//\s*(?:TODO|FIXME|HACK|XXX)\b', re.IGNORECASE)
    generic_fn_re = re.compile(r'(?:function|const)\s+(' + '|'.join(_GENERIC_NAMES) + r')\b')

    empty_catches: list[dict] = []
    todo_count = 0
    generic_fn_count = 0
    total_lines = 0

    for f in _source_files(repo_path):
        try:
            content = f.read_text(errors="replace")
            rel = str(f.relative_to(repo_path))
            total_lines += content.count("\n")

            for m in empty_catch_re.finditer(content):
                line_no = content[: m.start()].count("\n") + 1
                empty_catches.append({"file": rel, "line": line_no})
                if len(empty_catches) >= 10:
                    break

            todo_count += len(todo_re.findall(content))
            generic_fn_count += len(generic_fn_re.findall(content))
        except Exception:
            pass

    todo_density = round(todo_count / max(total_lines, 1) * 1000, 1)  # per 1000 lines

    score = 0
    score += min(15, len(empty_catches) * 3)
    score += min(10, int(todo_density * 2))
    score += min(10, generic_fn_count * 2)

    return {
        "empty_catches": len(empty_catches),
        "empty_catch_examples": empty_catches[:5],
        "todo_count": todo_count,
        "todo_density_per_1k": todo_density,
        "generic_function_count": generic_fn_count,
        "score": min(35, score),
        "verdict": (
            f"{len(empty_catches)} empty catches, {todo_count} TODOs, {generic_fn_count} generic function names"
        ),
    }


def detect_reexport_chains(repo_path: Path) -> dict:
    """Find index files that only re-export — adding no logic."""
    reexport_line_re = re.compile(r'^\s*export\s*(?:\*|\{[^}]*\})\s*from\s*[\'"]', re.MULTILINE)
    non_reexport_line_re = re.compile(r'^\s*(?!export\s*(?:\*|\{[^}]*\})\s*from|//|$)', re.MULTILINE)

    chains: list[dict] = []

    for f in _source_files(repo_path):
        if f.stem.lower() not in ("index",):
            continue
        try:
            content = f.read_text(errors="replace").strip()
            if not content:
                continue
            reexport_lines = len(reexport_line_re.findall(content))
            non_reexport = len(non_reexport_line_re.findall(content))
            if reexport_lines >= 3 and non_reexport <= 2:
                rel = str(f.relative_to(repo_path))
                chains.append({"file": rel, "reexport_lines": reexport_lines})
        except Exception:
            pass

    count = len(chains)
    score = min(10, count * 2)

    return {
        "count": count,
        "files": chains[:8],
        "score": score,
        "verdict": (
            f"{count} barrel files (re-export only index files)" if count > 0
            else "No re-export chains"
        ),
    }


def detect_generic_types(repo_path: Path) -> dict:
    """Find TypeScript interfaces/types with names too generic to be useful."""
    type_re = re.compile(r'(?:interface|type)\s+(' + '|'.join(_GENERIC_TYPE_NAMES) + r')\b')
    hits: list[dict] = []

    for f in _source_files(repo_path):
        if f.suffix not in (".ts", ".tsx"):
            continue
        try:
            content = f.read_text(errors="replace")
            for m in type_re.finditer(content):
                line_no = content[: m.start()].count("\n") + 1
                hits.append({
                    "file": str(f.relative_to(repo_path)),
                    "line": line_no,
                    "name": m.group(1),
                })
                if len(hits) >= 15:
                    break
        except Exception:
            pass
        if len(hits) >= 15:
            break

    count = len(hits)
    score = min(10, count * 2)

    return {
        "count": count,
        "examples": hits[:6],
        "score": score,
        "verdict": (
            f"{count} overly generic type names (Data, Config, Options…)" if count > 0
            else "No generic type names"
        ),
    }


# ── main entry point ───────────────────────────────────────────────────────

def compute_slop(repo_path: Path) -> dict:
    """Run all slop detectors and return a composite result."""
    sprawl = detect_utility_sprawl(repo_path)
    wrappers = detect_single_call_wrappers(repo_path)
    duplicates = detect_duplicate_helpers(repo_path)
    cargo = detect_cargo_cult(repo_path)
    reexports = detect_reexport_chains(repo_path)
    generic_types = detect_generic_types(repo_path)

    raw_score = (
        sprawl["score"]
        + wrappers["score"]
        + duplicates["score"]
        + cargo["score"]
        + reexports["score"]
        + generic_types["score"]
    )
    slop_score = min(100, raw_score)

    label = (
        "Clean" if slop_score <= 10
        else "Mild Slop" if slop_score <= 25
        else "Moderate Slop" if slop_score <= 45
        else "Heavy Slop" if slop_score <= 65
        else "Slop Crisis"
    )

    return {
        "slop_score": slop_score,
        "label": label,
        "utility_sprawl": sprawl,
        "single_call_wrappers": wrappers,
        "duplicate_helpers": duplicates,
        "cargo_cult": cargo,
        "reexport_chains": reexports,
        "generic_types": generic_types,
    }
