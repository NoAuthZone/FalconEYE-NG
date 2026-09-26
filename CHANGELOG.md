# Changelog

All notable changes of FalconEYE-NG compared to the original FalconEYE
(release tag `v2.1.0`, commit `92c3d76`) are documented here, as required by
AGPL-3.0 section 5(a).

## 2026-09-26 – Version 3.0.0

- Version set to **3.0.0** (FalconEYE-NG). The version is now defined once in
  `falconeye/__init__.py`; CLI help, `falconeye info`, banner, JSON and SARIF
  reports read it from there instead of hard-coded "2.0"/"2.0.0" strings.
- Banner and CLI help show "FalconEYE-NG" with attribution to the original
  authors.
- Note: JSON reports now contain `"tool": {"version": "3.0.0"}` (previously "2.0").

## 2026-09-26 – FalconEYE-NG: TypeScript fix, discovery overhaul, false-positive reduction

### Fixed (robustness)
- **Files were skipped when the model returned unexpected field types**, e.g.
  `code_snippet` as a list of lines (`'list' object has no attribute
  'splitlines'` – seen on `python/billing_service.py`). `SecurityFinding.create`
  now normalizes all LLM-provided fields: lists are joined to text, line numbers
  like `"12"`, `"line 12"` or `"12-14"` become integers.
- `~` in `logging.file` is expanded.

### Fixed (logging)
- **`falconeye.log` was never written.** The logger singleton was first created
  by adapters without a log file, and the later call with the configured
  `logging.file` was ignored. The configured log file is now applied when
  passed (JSON lines, path relative to the working directory by default).

### Fixed (false positives, found via Security-Testfiles run: 42/43 recall, 48 FPs)
- **Findings from RAG context files were attributed to the reviewed file.**
  E.g. `types.d.ts` (type declarations only) received 9 findings that describe
  `legacy.cts`, `fetcher.mts`, `Profile.tsx` and even a Dart file. The prompt now
  marks related code as background-only with an explicit scope rule, and a
  grounding check drops findings whose snippet exists only in the context code
  or whose title names another context file.
- **Findings the enrichment step judged as "not vulnerable" were kept** (only
  downgraded to info/low). Enrichment now returns `is_valid` / `invalid_reason`;
  explicitly invalid findings are removed and logged.
- **RAG query embeddings ignored the configuration**: `ContextAssembler` created
  its own `OllamaLLMAdapter()` with hard-coded `localhost` and default embedding
  model. It now uses the configured LLM service (same host/model as indexing).

### Added
- `tests/test_finding_grounding.py` – regression tests for the above.

### Fixed
- **TypeScript files were silently skipped / analyzed poorly**
  - `.mts` and `.cts` were not registered as TypeScript, so they were never
    indexed or reviewed (e.g. `fetcher.mts`, `legacy.cts` in Security-Testfiles).
  - `get_plugin("typescript")` returned `None` because the JS plugin was only
    registered as `javascript`; all TS files fell back to the generic prompt.
    The JS/TS plugin is now also registered for `typescript`.
  - `.tsx` was parsed with the `typescript` grammar (JSX = parse errors, almost
    no structure extracted). It now uses the `tsx` grammar.
- **`review <dir>` ignored all exclusions** – it used a raw `rglob`, so
  `node_modules`, `.git`, `venv`, `dist` etc. were sent to the LLM.
- **Exclusion patterns did not work on Windows** (matching relied on `/`) and
  excluded *everything* when the project itself lived below a directory such as
  `build/`, `env/` or `target/`. Matching now uses fnmatch on the path relative
  to the scan root, identical on Windows and POSIX.
- **Document indexing crawled `node_modules`** (13 separate `rglob` passes),
  embedding thousands of npm READMEs/LICENSEs, and picked up binary files under
  `docs/`. Now a single pruned walk, binaries skipped.
- **Offline / first-run failure**: metadata and registry collections let ChromaDB
  compute ONNX embeddings on every upsert (downloads ~80 MB, fails without
  internet, slows indexing). They now store placeholder embeddings (compatible
  with existing collections).
- Files with a UTF-8 BOM or non-UTF-8 characters no longer abort with
  `UnicodeDecodeError`.
- Directory reviews reported `files_analyzed: 0` and `completed_at: null`.
- Progress bar double-counted files in directory reviews.
- JS/TS AST: the `function` keyword token was counted as an anonymous function;
  `import x = require()` was counted twice; arrow functions assigned to a
  variable now get their variable name.
- `requirements.txt` installed `mlx` unconditionally (fails on Linux/Windows);
  now restricted to Apple Silicon via environment markers.

### Improved
- One shared file-discovery implementation (`LanguageDetector.discover_source_files`)
  for index, review and scan; skipped directories are pruned instead of walked;
  deterministic (sorted) processing order.
- `index` no longer walks the whole tree an extra time for an unused file count.
- AST traversal is iterative and collects several node types in one pass.
- Removed duplicated extension→language table in `security.py`.
- Removed unused imports / placeholder-less f-strings (ruff).
