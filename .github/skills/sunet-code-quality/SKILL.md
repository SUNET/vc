---
name: sunet-code-quality
description: Run `go fix ./...` and rename badly named Go identifiers (strange names, non-words, cryptic abbreviations), then build and test. Use when the user types /sunet-code-quality or asks to clean up code quality or naming.
---

## Style
- Use concise language: short sentences, no filler or restating.
- Structure output as bullet points under the required headings.

You are a senior Go engineer doing a mechanical code-quality pass. Keep behavior unchanged.

## Scope
- Default scope: Go files changed on the current branch, production (`*.go`) and test (`*_test.go`) files alike. Find them with `git diff --name-only $(git merge-base HEAD origin/main)...HEAD -- '*.go'` plus `git status --short`.
- If the user names a package, file or "all", use that instead. For "all", run on `./...` and scan both production and test files.
- Do not skip non-test files. Scan them with the same rules as test files.
- Never edit `vendor/`, `third_party/`, `internal/gen/` or any file with a `Code generated` header.
- Do not run `git commit` or `git push`. The user does that.

## 1. Run go fix
1. Run `go fix ./...` in the repo root.
2. Run `git diff --stat` and list what changed.
3. If `go fix` touched files outside the scope, revert only those files with `git checkout -- <file>` after asking the user.

## 2. Find bad names
Read the files in scope. Flag identifiers (variables, parameters, fields, functions, types, constants, receivers) that are:
- **Non-words or gibberish:** `asdf`, `foo2`, `tmpX`, `xyzzy`, `thing`, `stuff`, `data2`.
- **Cryptic abbreviations** a new reader cannot decode: `rslt`, `cfgMgr2`, `prcsr`. Standard Go short names stay (`ctx`, `err`, `i`, `ok`, `r`/`w`, `tx`, `db`, `req`, `resp`, receiver letters), as do standard acronyms (`ID`, `URL`, `HTTP`, `JWT`, `VC`, `VP`, `TSL`).
- **Misleading:** the name says one thing and the value is another.
- **Inconsistent with Go style:** underscores in identifiers (except `Test`/`Benchmark`/`Example` function names and `t.Run` subtest strings), wrong acronym casing (`Id`, `Url`, `Http`), stuttering (`apiv1.Apiv1Client`).
- **Numbered or generic suffixes** used to avoid a collision: `result2`, `newData`, `tmp`, `val` where a real name exists.

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
3. Do not change logic, signatures' types, struct tags or comments beyond names.
4. If no good name is clear from the code, leave it and list it under "Needs your input".

## 4. Verify
Run in order and fix only what the rename or `go fix` broke:
1. `gofmt -l <changed files>` (must print nothing)
2. `go build ./...`
3. `go vet` on the touched packages. Add `-tags <tag>` for files with a `//go:build` line, for example `integration`.
4. `go test ./<package>/...` for each touched package. Do not run tagged integration tests that need a real stack; vet them only.

## 5. Report
Use exactly this structure:

### go fix
- Files changed and the kind of rewrite, or "No changes".

### Renames
- `path:line`: `oldName` to `newName` (reason). Write "None" if there are none.

### Needs your input
- Names flagged but not changed, with why. Write "None" if there are none.

### Verification
- Result of `gofmt`, `go build`, `go vet`, `go test`. Quote the first failing line if any fail.
