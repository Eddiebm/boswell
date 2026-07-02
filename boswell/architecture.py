"""
Architecture scanner — static analysis without AST tools.
Checks: giant files, circular imports, dependency sprawl, state manager conflicts, TypeScript strict.
"""

import json
import re
import subprocess
from pathlib import Path


_SKIP_DIRS = {"node_modules", ".next", "dist", "out", ".vercel", ".wrangler", "build", ".turbo", "coverage"}
_SOURCE_EXTS = {".ts", ".tsx", ".js", ".jsx"}


def _source_files(repo_path: Path) -> list[Path]:
    files = []
    for f in repo_path.rglob("*"):
        if any(p in _SKIP_DIRS for p in f.parts):
            continue
        if f.suffix in _SOURCE_EXTS and f.is_file():
            files.append(f)
    return files


def check_giant_files(repo_path: Path) -> dict:
    """Flag source files over 300 lines and components over 250 lines."""
    giant = []
    component_dirs = {"components", "pages", "app", "views", "screens", "ui"}

    for f in _source_files(repo_path):
        try:
            lines = f.read_text(errors="replace").count("\n")
        except Exception:
            continue
        rel = str(f.relative_to(repo_path))
        is_component = any(d in f.parts for d in component_dirs)
        threshold = 250 if is_component else 300
        if lines > threshold:
            giant.append({"file": rel, "lines": lines, "threshold": threshold})

    giant.sort(key=lambda x: -x["lines"])
    return {
        "count": len(giant),
        "files": giant[:10],
        "score": min(40, len(giant) * 5),  # 0-40 penalty
    }


def _build_import_graph(files: list[Path], repo_path: Path) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    import_re = re.compile(r'(?:from|import)\s+[\'"](\.[^\'"]+)[\'"]')

    for f in files:
        rel = str(f.relative_to(repo_path))
        graph[rel] = set()
        try:
            content = f.read_text(errors="replace")
        except Exception:
            continue
        for m in import_re.finditer(content):
            imp = m.group(1)
            base = (f.parent / imp).resolve()
            for ext in ("", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js"):
                candidate = Path(str(base) + ext) if ext and not base.suffix else base
                if candidate.is_file():
                    try:
                        graph[rel].add(str(candidate.relative_to(repo_path)))
                    except ValueError:
                        pass
                    break
    return graph


def check_circular_deps(repo_path: Path) -> dict:
    """Detect circular imports via DFS on the import graph."""
    files = _source_files(repo_path)
    if len(files) > 500:
        return {"count": 0, "cycles": [], "score": 0, "note": "Too many files — skipped"}

    graph = _build_import_graph(files, repo_path)
    cycles: list[list[str]] = []
    color: dict[str, int] = {}  # 0=unvisited 1=in-progress 2=done

    def dfs(u: str, path: list[str]) -> None:
        color[u] = 1
        for v in graph.get(u, set()):
            if len(cycles) >= 5:
                return
            if color.get(v, 0) == 1:
                try:
                    idx = path.index(v)
                    cycles.append(path[idx:] + [v])
                except ValueError:
                    cycles.append([u, v])
            elif color.get(v, 0) == 0:
                dfs(v, path + [v])
        color[u] = 2

    for node in list(graph.keys()):
        if color.get(node, 0) == 0 and len(cycles) < 5:
            dfs(node, [node])

    return {
        "count": len(cycles),
        "cycles": cycles,
        "score": 30 if cycles else 0,  # flat 30 penalty if any cycle found
    }


def check_dependency_sprawl(repo_path: Path) -> dict:
    """Count deps, detect multiple state managers, flag missing lockfile."""
    pkg_path = repo_path / "package.json"
    if not pkg_path.exists():
        return {"dep_count": 0, "dev_count": 0, "state_managers": [], "has_lockfile": True, "score": 0}

    try:
        pkg = json.loads(pkg_path.read_text())
    except Exception:
        return {"dep_count": 0, "dev_count": 0, "state_managers": [], "has_lockfile": True, "score": 0}

    deps = set(pkg.get("dependencies", {}).keys())
    dev_deps = set(pkg.get("devDependencies", {}).keys())
    all_deps = deps | dev_deps

    state_managers = [d for d in ["zustand", "redux", "@reduxjs/toolkit", "jotai", "recoil", "mobx", "valtio", "xstate"]
                      if d in all_deps]
    has_lockfile = (repo_path / "package-lock.json").exists() or (repo_path / "yarn.lock").exists() or (repo_path / "pnpm-lock.yaml").exists()

    dep_count = len(deps)
    score = 0
    if dep_count > 60:
        score += 25
    elif dep_count > 40:
        score += 15
    elif dep_count > 20:
        score += 5
    if len(state_managers) > 1:
        score += 15
    if not has_lockfile:
        score += 10

    return {
        "dep_count": dep_count,
        "dev_count": len(dev_deps),
        "state_managers": state_managers,
        "has_lockfile": has_lockfile,
        "score": min(40, score),
    }


def check_typescript_config(repo_path: Path) -> dict:
    """Check for strict TypeScript config."""
    for tsconfig in ["tsconfig.json", "tsconfig.app.json", "apps/web/tsconfig.json"]:
        p = repo_path / tsconfig
        if p.exists():
            try:
                data = json.loads(p.read_text())
                strict = data.get("compilerOptions", {}).get("strict", False)
                return {"found": True, "strict": strict, "score": 0 if strict else 10}
            except Exception:
                pass
    return {"found": False, "strict": False, "score": 5}


def check_maintainability(repo_path: Path) -> dict:
    """File count and average size as a rough maintainability proxy."""
    files = _source_files(repo_path)
    if not files:
        return {"file_count": 0, "avg_lines": 0, "max_lines": 0, "score": 0}

    line_counts = []
    for f in files:
        try:
            line_counts.append(f.read_text(errors="replace").count("\n"))
        except Exception:
            line_counts.append(0)

    avg = sum(line_counts) // len(line_counts) if line_counts else 0
    mx = max(line_counts) if line_counts else 0
    count = len(files)

    score = 0
    if count > 200:
        score += 20
    elif count > 100:
        score += 10
    if avg > 200:
        score += 15
    elif avg > 100:
        score += 5
    if mx > 1000:
        score += 15
    elif mx > 500:
        score += 5

    return {"file_count": count, "avg_lines": avg, "max_lines": mx, "score": min(40, score)}


def run_architecture_checks(repo_path: Path) -> dict:
    """Run all architecture checks and return structured results."""
    giant = check_giant_files(repo_path)
    circular = check_circular_deps(repo_path)
    sprawl = check_dependency_sprawl(repo_path)
    tsconfig = check_typescript_config(repo_path)
    maintain = check_maintainability(repo_path)

    # Architecture score 0-100 (higher = worse)
    raw = giant["score"] + circular["score"] + sprawl["score"] + tsconfig["score"] + maintain["score"]
    architecture_score = min(100, raw)

    return {
        "architecture_score": architecture_score,
        "giant_files": giant,
        "circular_deps": circular,
        "dependency_sprawl": sprawl,
        "typescript": tsconfig,
        "maintainability": maintain,
    }
