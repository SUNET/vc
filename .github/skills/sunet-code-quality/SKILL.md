---
name: sunet-code-quality
description: Run `go fix ./...`, rename badly named Go identifiers (non-words, cryptic abbreviations, error variables not named `err`), group tests into `t.Run` subtests, use `t.Context()` in tests, and trim comments to the minimum, then build and test. Use when the user types /sunet-code-quality or asks to clean up code quality or naming.
---

## Style
- Use concise language: short sentences, no filler or restating.
- Structure output as bullet points under the required headings.

You are a senior Go engineer doing a mechanical code-quality pass. Keep behavior unchanged.

## Scope
- Default scope: Go files changed on the current branch, production (`*.go`) and test (`*_test.go`) files alike. Find them with `git diff --name-only $(git merge-base HEAD origin/main)...HEAD -- '*.go'` plus `git status --short`. If `origin/main` does not exist, use the remote default branch from `git symbolic-ref --short refs/remotes/origin/HEAD`.
- If the default scope is empty (no committed, staged or unstaged Go changes, for example on `main` or a fresh branch), use the "all" scope instead and say so under "Scope" in the report.
- If the user names a package, file or "all", use that instead. For "all", run on `./...` and scan both production and test files.
- Do not skip non-test files. Scan them with the same rules as test files.
- Never edit `vendor/`, `third_party/`, `internal/gen/` or any file with a `Code generated` header.
- Do not run `git push`. The user does that.
- Run `git commit` only when the user says "commit". Before staging, require `git diff --cached --quiet` to succeed; if it fails, stop without changing the index and tell the user to commit, unstage or stash the already staged work first. Stage only the files changed in this pass (never `git add -A` or `git add .`), use a Conventional Commits message shown to the user first, and never pass `--amend`, `--no-verify` or `--no-gpg-sign`.

## 1. Run go fix
1. Run `git status --porcelain` and keep the list of files that already have local changes.
2. Run `go fix ./...` in the repo root.
3. Run `git diff --stat` and list what `go fix` changed (compare with the list from step 1).
4. If `go fix` touched files outside the scope, ask the user before reverting. Revert with `git checkout -- <file>` only files that were clean in step 1. Never revert a file that already had local changes: show its `go fix` hunks and let the user decide.

## 2. Find bad names
Every name must be an English word (or words), or a term from the code's own domain that a reader of this package knows (for example `issuer`, `holder`, `realm`, `jwk`). No cryptic shorthands.

Read the files in scope. Flag identifiers (variables, parameters, fields, functions, types, constants, receivers) that are:
- **Non-words or gibberish:** `asdf`, `foo2`, `tmpX`, `xyzzy`, `thing`, `stuff`, `data2`.
- **Cryptic abbreviations** a new reader cannot decode: `rslt`, `cfgMgr2`, `prcsr`, `usrNm`. Standard Go short names stay (`ctx`, `err`, `i`, `ok`, `r`/`w`, `tx`, `db`, `req`, `resp`, receiver letters), as do standard acronyms (`ID`, `URL`, `HTTP`, `JWT`, `VC`, `VP`, `TSL`).
- **Misleading:** the name says one thing and the value is another.
- **Inconsistent with Go style:** underscores in identifiers (except `Test`/`Benchmark`/`Example` function names and `t.Run` subtest strings), wrong acronym casing (`Id`, `Url`, `Http`), stuttering (`apiv1.Apiv1Client`).
- **Numbered or generic suffixes** used to avoid a collision: `result2`, `newData`, `tmp`, `val` where a real name exists.
- **Error variables not named `err`:** `e`, `er`, `error1`, `parseErr`, `errParse`. Rename a local error variable to `err` unless:
  - another error is alive in the same scope and both are needed, for example `closeErr` in a deferred `Close`;
  - the rename would shadow an outer `err` or change which error is checked or returned;
  - it is a package-level sentinel (`ErrNotFound`, `errInvalid`), an error type (`ValidationError`), or a test table field (`wantErr`).
  When `err` is already declared in that scope, change `:=` to `=` if needed so the code still compiles and means the same.

Check both file kinds:
- **Production files:** also check struct fields, function and method names, constants, package-level vars and interface names, not only locals.
- **Test files:** also check helper names, table fields and mock names.

Do not flag:
- Names defined by an external API, protocol, JSON/YAML tag, proto message or standard (OpenID4VCI, OpenID4VP, SD-JWT, mdoc field names).
- Test table field names that are already clear in context.
- Names the user already chose to keep in this session.

Ask before renaming:
- Exported names in production files. Renaming them changes the public API and every caller, so list them under "Needs your input" first.
- Struct fields with `json`, `yaml`, `bson` or `validate` tags. Rename only the Go field, never the tag value, and only with the user's agreement.

## 3. Rename
1. Use the language-server rename (`vscode_renameSymbol`) so all references update. Do not use search and replace. If the rename is rejected because the file has a build tag, edit by hand and vet with that tag.
2. Choose a name that states what the value is or does. Prefer a full word over an abbreviation.
3. Do not change logic, signatures' types or struct tags. Comments are handled in step 5.
4. If no good name is clear from the code, leave it and list it under "Needs your input".

## 4. Tests
Apply to `*_test.go` files in scope.

**Use `t.Run` subtests:**
- Where possible, merge several test functions for the same function or method into one `TestX` with `t.Run` subtests. Use a table-driven loop when the cases share the same shape.
- Keep every case and every assertion. Use the old function name, minus the `Test` prefix, as the subtest name.
- Keep separate functions when merging does not fit: different setup or teardown, `TestMain` interaction, mixed `t.Parallel` use, or a different build tag.
- Before renaming a test function, run `grep -rn -- '-run' Makefile .github/` and similar CI files. If CI or the Makefile refers to the old name, list it under "Needs your input" instead.

**Use `t.Context()`:**
- Only if the `go` line in `go.mod` is 1.24 or later. Otherwise skip this and say so in the report.
- Replace `context.Background()` and `context.TODO()` in tests with `t.Context()` (`b.Context()` in benchmarks). That includes the parent of `context.WithTimeout`/`WithCancel`.
- Helpers without a `*testing.T`: take `t testing.TB` or a `ctx` parameter, and pass `t.Context()` from the caller.
- Do not use `t.Context()` inside `t.Cleanup` callbacks, because it is cancelled before cleanup runs. Do not use it in `TestMain` or package-level setup. Keep `context.Background()` there.
- Remove the `context` import if it is no longer used.

## 5. Comments
Keep comments to the minimum.

Remove:
- Comments that restate what the code says (`// increment i`, `// return the result`).
- Commented-out code.
- Section banners and dividers (`// ---- helpers ----`).
- Comments that are wrong for the current code. Fix the comment instead if the point is still needed.

Shorten doc comments on exported identifiers and packages to one sentence that starts with the name. Keep them, because linters such as `revive` and `staticcheck` expect them.

Keep unchanged:
- Comments that explain why: a non-obvious reason, a spec or RFC reference, a workaround, a security note.
- Directives: `//go:build`, `//go:generate`, `//go:embed`, `//nolint`, `// Deprecated:`.
- License and copyright headers.

Do not delete `TODO`/`FIXME` comments. List them under "Needs your input".

## 6. Verify
Run in order and fix only what this pass broke:
1. `gofmt -l <changed files>` (must print nothing)
2. `go build ./...`
3. `go vet` on the touched packages. Add `-tags <tag>` for files with a `//go:build` line, for example `integration`.
4. `go test ./<package>/...` for each touched package. Do not run tagged integration tests that need a real stack; vet them only.
5. For merged tests, run `go test -v -run '^TestX$' ./<package>` and check that every old case now runs as a subtest.

## 7. Report
Use exactly this structure:

### Scope
- Which scope was used (changed files, named package/file, or all) and why. Example: "All: no Go changes on this branch."

### go fix
- Files changed and the kind of rewrite, or "No changes".

### Renames
- `path:line`: `oldName` to `newName` (reason). Include error variables renamed to `err`. Write "None" if there are none.

### Tests
- Merged tests: old function names to `TestX/subtest`. Write "None" if there are none.
- `t.Context()` replacements: file and count, or why skipped.

### Comments
- Per file: comments removed or shortened (count and kind). Write "None" if there are none.

### Needs your input
- Names, tests or `TODO`/`FIXME` comments flagged but not changed, with why. Write "None" if there are none.

### Verification
- Result of `gofmt`, `go build`, `go vet`, `go test`. Quote the first failing line if any fail.
