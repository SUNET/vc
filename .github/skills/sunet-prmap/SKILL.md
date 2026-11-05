---
name: sunet-prmap
description: Map open GitHub PRs into linked stacks with priority, complexity and merge order. Use when the user types /sunet-prmap or asks for an overview of open PRs.
---

## Style
- Use concise language: short sentences, no filler or restating.
- Structure all output as bullet points under the required headings; use tables only where the report format asks for them.

You are helping me get an overview of many open, complex pull requests, some of which are stacked on top of each other. Read only. Do NOT comment, approve, merge, rebase, or push anything.

## 0. Scope
What follows the command decides which PRs to include:
- `OWNER/REPO` (or nothing, inside a repo): all open PRs in that repo.
- `mine`: PRs I authored (`--author @me`), across repos if no repo is given (`gh search prs --author @me --state open`).
- `reviews`: PRs where my review is requested (`--search "review-requested:@me"`).
- Anything else (a label, a person, "only drafts"): apply it as a filter.

If `gh` is not installed or authenticated, tell me to run `gh auth login` and stop.

## 1. Collect data
For the repo(s) in scope:

```
gh pr list --repo OWNER/REPO --state open --limit 200 --json number,title,author,url,isDraft,baseRefName,headRefName,headRepositoryOwner,createdAt,updatedAt,additions,deletions,changedFiles,labels,reviewDecision,reviewRequests,mergeable,body
```

For each PR also get, when useful:
- `gh pr checks N --repo OWNER/REPO` (CI status)
- `gh pr view N --repo OWNER/REPO --json commits,files,comments,reviews` (commit SHAs, touched paths, open review state)

## 2. Find how PRs are linked
Build a dependency graph. PR B depends on PR A if ANY of these holds (record which signal you used):
1. **Base branch:** B's `baseRefName` equals A's `headRefName` (same repo or same fork owner).
2. **Description:** B's body mentions A as a dependency or stack position ("depends on #A", "based on #A", "stacked on", "after #A merges", "contains A's commit", "part 2/3", "A: #814, B: #815").
3. **Shared commits:** B contains commits whose SHAs also appear in A (typical for fork PRs that all target `main` but are actually stacked). Compare commit lists.
4. **Weak signal — overlapping files only:** many of the same files changed. Do not treat this as a dependency; list it under "Possible conflicts" instead.

Group linked PRs into **stacks**, ordered bottom (merge first) to top. A PR with no links is a **standalone**. Flag anything odd: cycles, a PR whose base PR is closed/merged (needs rebase), a stack where a lower PR is failing CI or has requested changes (blocks everything above it).

## 3. Rate each PR

**Complexity** (judge from size, files touched, and what the code does — not lines alone):
- **S — Simple:** small, local change; docs, config, tests, trivial fix.
- **M — Moderate:** a feature or fix across a few files; clear logic.
- **L — Large:** many files or packages; new APIs, schema/config changes, non-trivial logic.
- **XL — Critical-complex:** security, crypto, auth, protocol/spec handling, concurrency, data migrations, or very large diffs. Needs a careful, focused review.

**Priority** (what to look at first):
- **P1 — Now:** blocks other PRs (bottom of a stack), security fixes, broken main/CI fixes, or explicitly urgent labels.
- **P2 — Soon:** ready for review (CI green, not draft), active discussion, or waiting on me.
- **P3 — Later:** depends on an unmerged PR lower in its stack, or low impact.
- **P4 — Parked:** draft, stale (no updates for 30+ days), or blocked by failing CI / unresolved conflicts.

A PR higher in a stack can never have a higher priority than the PR it depends on. Give a one-line reason for every rating.

## 4. Output
Use exactly this structure.

### Overview
One short paragraph: how many PRs, how many stacks, how many standalone, and the 1–3 things I should do first.

### Stack: <short descriptive name, e.g. "TS12 payment SCA (#814 → #815 → #816)">
One sentence on what the stack achieves together and the signal(s) that link it.

```
#814  feat: payment request           [P1 · XL]  base: main
 └─ #815  feat: validate responses    [P3 · XL]  base: #814 (shared commits)
     └─ #816  feat: operator page     [P3 · M]   base: #815 (description "3/3")
```

| Order | PR | Title | Author | Priority | Complexity | CI | Review | Status / blocker |
|---|---|---|---|---|---|---|---|---|

**Merge order:** #814 → #815 → #816. Note what has to happen first (e.g. "#815 needs a rebase after #814 merges").

(Repeat a "Stack:" section for each stack, highest-priority stack first.)

### Standalone PRs
Same table, sorted by priority, then complexity.

### Possible conflicts
PRs that touch the same files without being stacked, and what might collide.

### Suggested review plan
A numbered list of which PRs to review in what order today, with a rough time estimate per PR based on complexity (S ≈ 10 min, M ≈ 30 min, L ≈ 1 h, XL ≈ 2 h+).

Link every PR number to its URL. Be honest about uncertainty: if a link is inferred from a weak signal, say so.
