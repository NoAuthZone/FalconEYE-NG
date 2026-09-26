"""Regression tests: findings from RAG context files must not be reported
for the reviewed file, and findings rejected during enrichment are dropped."""

import asyncio
import json

from falconeye.domain.models.prompt import PromptContext
from falconeye.domain.services.security_analyzer import SecurityAnalyzer

TYPES_DTS = """declare module "legacy-auth" {
  export interface Session {
    userId: string;
  }
  export function verify(token: string): Promise<Session | null>;
}
"""

LEGACY_CTS = """import fs = require("fs");
export function calculate(expression: string): number {
  return eval(expression);
}
"""

ACCOUNTS_TS = """app.get("/accounts", async (req, res) => {
  const result = await db.query("SELECT id, name FROM accounts WHERE name = $1", [String(req.query.name)]);
  res.json(result.rows);
});
"""

SERVER_TS = """app.get("/users", async (req, res) => {
  const sql = `SELECT id, name FROM users WHERE name = '${req.query.name}'`;
  const result = await db.query(sql);
});
"""

RELATED = f"[Related Code 1] From src/legacy.cts:\n{LEGACY_CTS}\n"


class FakeLLM:
    def __init__(self, analysis, enrichment):
        self.analysis = analysis
        self.enrichment = enrichment

    async def analyze_code_security(self, context, system_prompt, stream_callback=None):
        data = self.enrichment if context.analysis_type == "enrichment" else self.analysis
        return json.dumps(data)


def _finding(issue, snippet, line, severity="high"):
    return {
        "issue": issue,
        "reasoning": "Detailed reasoning about exploitability and impact. " * 2,
        "mitigation": "Use a specific fix in the handler function.",
        "severity": severity,
        "confidence": 0.9,
        "code_snippet": snippet,
        "line_start": line,
        "line_end": line,
    }


def _analyze(path, source, llm):
    ctx = PromptContext(
        file_path=path,
        code_snippet=source,
        language="typescript",
        related_code=RELATED,
        analysis_type="review",
    )
    return asyncio.run(SecurityAnalyzer(llm).analyze_code(ctx, "system"))


def test_findings_from_context_files_are_dropped():
    llm = FakeLLM(
        {"reviews": [
            _finding("Command Injection via eval() in legacy.cts", "return eval(expression);", 3, "critical"),
            _finding("Code injection", "return eval(expression);", 3, "critical"),
        ]},
        {"enriched": []},
    )
    assert _analyze("src/types.d.ts", TYPES_DTS, llm) == []


def test_enrichment_rejection_drops_finding():
    llm = FakeLLM(
        {"reviews": [_finding(
            "SQL Injection",
            'const result = await db.query("SELECT id, name FROM accounts WHERE name = $1", [String(req.query.name)]);',
            2,
        )]},
        {"enriched": [{"index": 0, "adjusted_severity": "info", "is_valid": False,
                       "invalid_reason": "parameterized query"}]},
    )
    assert _analyze("src/accounts.ts", ACCOUNTS_TS, llm) == []


def test_real_and_paraphrased_findings_are_kept():
    llm = FakeLLM(
        {"reviews": [
            _finding("SQL Injection",
                     "const sql = `SELECT id, name FROM users WHERE name = '${req.query.name}'`;", 2, "critical"),
            _finding("Unsafe query building", "query built from user input (paraphrased)", 2),
        ]},
        {"enriched": [{"index": 0, "adjusted_severity": "critical", "is_valid": True},
                      {"index": 1, "adjusted_severity": "high"}]},
    )
    issues = sorted(f.issue for f in _analyze("src/server.ts", SERVER_TS, llm))
    assert issues == ["SQL Injection", "Unsafe query building"]


def test_llm_field_types_are_normalized():
    """Models sometimes return code_snippet as a list of lines or line numbers
    as strings; this crashed the analysis ('list' object has no attribute
    'splitlines') and the file was skipped."""
    llm = FakeLLM(
        {"reviews": [{
            "issue": "SQL Injection",
            "reasoning": ["Line one of reasoning.", "Line two."],
            "mitigation": "Use parameterized queries in the users handler.",
            "severity": "critical",
            "confidence": 0.9,
            "code_snippet": [
                "  const sql = `SELECT id, name FROM users WHERE name = '${req.query.name}'`;",
                "  const result = await db.query(sql);",
            ],
            "line_start": "2-3",
            "line_end": None,
        }]},
        {"enriched": [{"index": 0, "adjusted_severity": "critical",
                       "code_snippet": ["const result = await db.query(sql);"],
                       "line_start": "line 3", "is_valid": "true"}]},
    )
    findings = _analyze("src/server.ts", SERVER_TS, llm)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f.code_snippet, str) and isinstance(f.reasoning, str)
    assert isinstance(f.line_start, int)
