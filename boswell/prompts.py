"""All LLM prompts for Boswell."""

FOLDER_SUMMARY_SYSTEM = """\
You are a senior software engineer performing a codebase audit.
Your job is to read the files from one directory and write a compact 3-5 sentence technical summary.
Cover: what this directory is responsible for, what it imports/depends on, what it exports or exposes, and any notable patterns or red flags.
Be dense and precise. No filler."""


def folder_summary_prompt(dir_name: str, files_content: str) -> str:
    return f"""\
Directory: {dir_name}

Files:
{files_content}

Write a 3-5 sentence technical summary of this directory. Be specific about what it does, not generic."""


FILE_CLASSIFIER_SYSTEM = """\
You are a senior software engineer. Given a list of files in a repository, identify the 25 most important ones for understanding the codebase.
Return only a JSON array of relative file paths. No explanation. Format: ["path/to/file", ...]"""


def file_classifier_prompt(file_list: str) -> str:
    return f"""\
Repository files:
{file_list}

Return a JSON array of the 25 most important file paths for understanding this codebase. Prioritize: entry points, auth, data models, main business logic, config files. Exclude: tests, generated files, assets."""


AUDIT_SYSTEM = """\
You are a senior software engineer conducting a formal technical audit.
You produce thorough, citation-heavy, opinionated reports. You use exact file paths and line numbers when possible.
You never soften findings. If something is broken, say it's broken. If something is a security risk, name the CVE or OWASP category.
Format your output as clean Markdown."""


def audit_prompt(
    repo_name: str,
    stack: list[str],
    env_vars: list[str],
    key_files: dict[str, str],
    folder_summaries: dict[str, str],
    npm_audit: str | None,
    pip_audit: str | None,
    secret_warnings: list[str],
    git_log: str,
) -> str:
    key_files_block = "\n\n".join(
        f"### {path}\n```\n{content[:3000]}\n```" for path, content in key_files.items()
    )
    summaries_block = "\n\n".join(
        f"**{d}:** {s}" for d, s in folder_summaries.items()
    )
    secrets_block = "\n".join(secret_warnings) if secret_warnings else "No secrets detected in git history."
    npm_block = npm_audit[:3000] if npm_audit else "npm audit not available or no lockfile."
    pip_block = pip_audit[:2000] if pip_audit else "pip-audit not available."
    env_block = "\n".join(f"- {k}" for k in env_vars) if env_vars else "None detected."
    stack_block = ", ".join(stack) if stack else "Unknown — check key files."

    return f"""\
Conduct a full technical audit of the repository "{repo_name}".

## Detected Stack
{stack_block}

## Environment Variables (keys only — never values)
{env_block}

## Key Files
{key_files_block}

## Folder Summaries
{summaries_block}

## Dependency Vulnerability Scan
### npm audit
{npm_block}

### pip-audit
{pip_block}

## Git History Secret Scan
{secrets_block}

## Recent Git Activity (last 6 months)
{git_log[:3000] if git_log else "No git history available."}

---

Produce a technical audit report with exactly these four sections. Use `## ` headings.

## 1. Production Readiness
Assess: build/deploy configuration, environment variable completeness, error handling, logging, monitoring, rollback story.
End with a **Verdict** line: one of "Could deploy tomorrow" / "Needs N specific fixes (list them)" / "Do not deploy — reasons."

## 2. Security
Assess: auth and authorization pattern, OWASP Top 10 issues, dependency vulnerabilities (from the audit JSON above), exposed routes, CORS config, secret leaks (from git scan above), input validation.
List each finding as: `- [SEVERITY] Description — file:line (if known)`
Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
End with a **Security verdict** line summarizing overall risk level.

## 3. Code Quality & Architecture
Assess: folder structure, dead code, test coverage signal, lint config, dependency sprawl, complexity hotspots, TODO/FIXME count, adherence to framework conventions.
End with a **What a senior engineer would flag in PR review** subsection — bullet list, specific.

## 4. UX / First-Run Polish
If this is a web/mobile/desktop app: assess onboarding, error states, empty states, mobile responsiveness, performance budget, the 30-second trust check.
If this is a library, script, API, or MCP server: write "N/A — [repo type]. Skipping UX section."

Be specific. Cite files. Don't hedge. This is an internal audit, not a public review."""


HANDOFF_SYSTEM = """\
You are writing a handoff document for a solo founder's repository.
Your audience is: (a) a developer who might take over or buy this, (b) an executor who has to decide what to do with it after the founder is gone.
Write clearly, specifically, and without filler. Every section should be useful to someone who has never seen this codebase."""


def handoff_prompt(
    repo_name: str,
    stack: list[str],
    env_vars: list[str],
    key_files: dict[str, str],
    folder_summaries: dict[str, str],
    secret_warnings: list[str],
    git_log: str,
    boswell_context: str | None,
) -> str:
    key_files_block = "\n\n".join(
        f"### {path}\n```\n{content[:3000]}\n```" for path, content in key_files.items()
    )
    summaries_block = "\n\n".join(
        f"**{d}:** {s}" for d, s in folder_summaries.items()
    )
    env_block = "\n".join(f"- {k}" for k in env_vars) if env_vars else "None detected."
    stack_block = ", ".join(stack) if stack else "Unknown"
    context_block = boswell_context if boswell_context else "[No personal context provided — see Section 4]"

    return f"""\
Write a handoff document for the repository "{repo_name}".

## Detected Stack
{stack_block}

## Environment Variables Required (keys only)
{env_block}

## Key Files
{key_files_block}

## Folder Summaries
{summaries_block}

## Git History Secret Warnings
{chr(10).join(secret_warnings) if secret_warnings else "None."}

## Recent Commits
{git_log[:2000] if git_log else "No history."}

## Personal Context from Owner
{context_block}

---

Produce a handoff document with exactly these four sections. Use `## ` headings.

## 1. Technical Handoff

### Architecture
Draw a text-based diagram showing: top-level folders, key modules, data flow, external services. Use ASCII art or indented tree format.

### Build & Deploy
Exact commands to build and deploy. What works. What is known to fail or be incomplete. What the CI/CD story is (or isn't).

### The 5 Most Important Files
Number them 1-5. For each: path + one sentence on why it matters most.

### What's Broken Right Now
Bullet list. Be specific. "Broken" means: throws errors, doesn't do what it claims, or is obviously incomplete.

### What's Half-Built
Bullet list. Code exists but the feature isn't done. Where does it stop?

### Next 3 Things a Developer Should Do
Number them. Prioritized by impact. Specific enough that a developer could start on Monday.

## 2. Business / Product Handoff

**What this app does:** [one sentence — a stranger should understand it]
**Who it's for:** [target user, be specific]
**Problem it solves:** [one paragraph]
**Estimated value:** [your best guess at what a buyer would pay, or why it's valuable, or "marginal — explain"]
**Customers:** [are there any real users? paying customers? where are they?]
**Unit economics:** [LLM cost per session if applicable, hosting cost, revenue if any]
**Recommended fate:** [one of: Continue building / Sell / Open-source / Sunset] — [2-3 sentence justification]

## 3. Estate / Access Handoff

List everything someone would need to access or cancel this service. Format as:

**Domains:** [domain names and where they're likely registered — infer from configs]
**Deployment:** [platform — Cloudflare Pages / Vercel / AWS / etc.]
**Services that bill:**
- [Service name] — detected via [env var or SDK import]

**Required credentials (inventory only — never values):**
- [ENV_VAR_NAME] — [what it is / which service]

**Where to log in to cancel or transfer:**
- [Service] → [URL or description of where to go]

## 4. Personal Context

{context_block}

[If no context was provided, write: "The owner did not provide personal context for this repository. Ask them: Why did you build this? What did you hope it would become? Drop your answer in BOSWELL_CONTEXT.md and re-run boswell."]

Write the full document now. Be specific, honest, and useful."""


SIMPLE_AUDIT_SYSTEM = """\
You are translating a technical software audit into plain English for a non-technical family member who needs to make decisions about what to do with a software product they've inherited.

Rules you must follow:
1. No jargon without immediate translation in parentheses.
2. Every recommendation must answer "what does this mean for ME, the reader."
3. End with a "What should I do with this app?" section in 3-5 bullet points that a non-technical reader can act on.
4. Use short paragraphs. No bullet lists longer than 5 items. Explain numbers in plain terms.
5. Never be condescending — write like you're explaining to a smart person who hasn't programmed before."""


def simple_audit_prompt(repo_name: str, technical_audit: str) -> str:
    return f"""\
Here is a technical audit of the software project "{repo_name}":

{technical_audit}

---

Rewrite this audit in plain English for a non-technical reader (e.g., a family member who has to decide what to do with this software after the owner is gone).

Structure your response with these sections:
## Is This App Working?
## Is It Safe?
## Is the Code in Good Shape?
## What the App Looks and Feels Like (if applicable)
## What Should I Do With This App?

Follow the three rules strictly:
1. Translate every technical term immediately in parentheses.
2. Every recommendation explains what it means for the reader personally.
3. End with 3-5 bullet points in the "What Should I Do" section that are actionable by a non-technical person."""


SIMPLE_HANDOFF_SYSTEM = """\
You are translating a technical handoff document into plain English for a non-technical family member.
Same rules as before: translate jargon, explain implications, end with action steps.
Think of yourself as explaining what someone's business was, how it worked, and what to do with it."""


LESSONS_SYSTEM = """\
You are a senior software engineer who has just done a deep audit of a codebase.
You are writing a "lessons learned" document for the original author — someone who built this themselves, probably fast, and wants to know:
what should I do differently next time I build something like this?

You are not criticizing. You are distilling transferable wisdom.
Write like a mentor who respects the builder's work but is honest about the craft.
Focus on patterns, not individual bugs."""


def lessons_prompt(
    repo_name: str,
    audit_text: str,
    handoff_text: str,
    stack: list[str],
) -> str:
    stack_block = ", ".join(stack) if stack else "unknown"
    return f"""\
You have just audited the repository "{repo_name}" (stack: {stack_block}).

Here is the technical audit:
{audit_text[:4000]}

Here is the handoff document:
{handoff_text[:4000]}

---

Write a "Lessons for Next Time" document with these sections:

## What This Project Got Right
3-5 bullet points. Be specific. What patterns, decisions, or choices here are worth carrying forward?

## Architectural Mistakes to Avoid Next Time
For each: name the pattern, explain why it causes pain, and give the specific better alternative.
Format: ### Mistake N: [Name]
[What happened] → [What to do instead]

## The 3 Most Impactful Changes (If You Rebuilt This Tomorrow)
If starting from scratch with what you know now, what are the three highest-leverage changes?
Number them. Be concrete — specific tools, patterns, or structural decisions.

## Patterns to Carry Forward (Reusable Across Projects)
What did you learn from this codebase that applies to ALL your projects?
These are your new personal engineering principles. Extract them as numbered rules.
Example format: "Rule: Always separate [X] from [Y] because [Z]."

## What This Project Reveals About How You Build
An honest, kind observation about the builder's habits — based purely on what the code shows.
What do you reach for first? Where do you cut corners? What do you over-engineer?
This section should feel like insight, not criticism.

Be specific to this codebase. Don't write generic advice that could apply to any project."""


def simple_handoff_prompt(repo_name: str, technical_handoff: str) -> str:
    return f"""\
Here is a technical handoff document for the software project "{repo_name}":

{technical_handoff}

---

Rewrite this in plain English for a non-technical person who may need to manage or transfer this software product.

Structure your response with these sections:
## What Is This?
## How Was It Built and Deployed? (Plain English)
## What's Working and What Isn't?
## Is This Worth Anything? What Should Happen to It?
## Access and Accounts (What You Need to Log In To)
## Why the Owner Built This (Personal Context)
## What Should I Do? (Action Steps)

Translate all technical terms. Explain what each service costs and what happens if you stop paying.
End with 3-5 numbered action steps for a non-technical executor."""
