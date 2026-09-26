"""HTML formatter for human-readable security reports."""

from typing import Dict
from datetime import datetime
from ...domain.models.security import SecurityReview, SecurityFinding, Severity
from .base_formatter import OutputFormatter


class HTMLFormatter(OutputFormatter):
    """
    Format security review results as HTML.
    
    Provides a rich, interactive HTML report with:
    - Executive summary with statistics
    - Severity-based filtering
    - Code snippets with syntax highlighting
    - Detailed finding information
    """

    def format_review(self, review: SecurityReview) -> str:
        """
        Format complete security review as HTML.

        Args:
            review: SecurityReview to format

        Returns:
            HTML string
        """
        stats = self._calculate_statistics(review)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FalconEYE Security Report - {review.codebase_path}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: linear-gradient(135deg, #f5f7fa 0%, #e9ecef 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #0a1929 0%, #1a2332 50%, #0a1929 100%);
            color: white;
            padding: 50px 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.3);
            border: 1px solid rgba(0, 255, 255, 0.2);
            position: relative;
            overflow: hidden;
        }}
        
        header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at 50% 50%, rgba(0, 255, 255, 0.1) 0%, transparent 70%);
            pointer-events: none;
        }}
        
        header h1 {{
            font-size: 2.8em;
            margin-bottom: 5px;
            font-weight: 700;
            letter-spacing: 2px;
            color: #00ffff;
            text-transform: uppercase;
            text-shadow: 0 0 20px rgba(0, 255, 255, 0.5);
            position: relative;
            z-index: 1;
        }}
        
        header .subtitle {{
            font-size: 1.1em;
            color: #7dd3fc;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-bottom: 25px;
            font-weight: 400;
            position: relative;
            z-index: 1;
        }}
        
        header .meta {{
            opacity: 0.95;
            font-size: 0.95em;
            margin-top: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            position: relative;
            z-index: 1;
        }}
        
        header .meta > div {{
            padding: 8px 0;
            color: #e0f2fe;
        }}
        
        header .meta strong {{
            color: #00ffff;
            font-weight: 600;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
            border-left: 4px solid #00d4ff;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.12);
        }}
        
        .stat-card.critical {{
            border-left-color: #dc2626;
        }}
        
        .stat-card.high {{
            border-left-color: #ea580c;
        }}
        
        .stat-card.medium {{
            border-left-color: #f59e0b;
        }}
        
        .stat-card.low {{
            border-left-color: #3b82f6;
        }}
        
        .stat-card .label {{
            font-size: 0.85em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }}
        
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}
        
        .filters {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
        }}
        
        .filters h3 {{
            margin-bottom: 18px;
            color: #1f2937;
            font-size: 1.2em;
            font-weight: 600;
        }}
        
        .filter-buttons {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .filter-btn {{
            padding: 10px 20px;
            border: 2px solid #e5e7eb;
            background: white;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.9em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .filter-btn:hover {{
            border-color: #00d4ff;
            color: #00d4ff;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 212, 255, 0.2);
        }}
        
        .filter-btn.active {{
            background: linear-gradient(135deg, #00d4ff 0%, #0891b2 100%);
            color: white;
            border-color: transparent;
            box-shadow: 0 4px 12px rgba(0, 212, 255, 0.3);
        }}
        
        .filter-btn[data-filter="critical"] {{
            border-color: #dc2626;
            color: #dc2626;
        }}
        
        .filter-btn[data-filter="critical"]:hover {{
            background: #dc2626;
            color: white;
            border-color: #dc2626;
            box-shadow: 0 4px 8px rgba(220, 38, 38, 0.3);
        }}
        
        .filter-btn[data-filter="critical"].active {{
            background: #dc2626;
            color: white;
            border-color: #dc2626;
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.4);
        }}
        
        .filter-btn[data-filter="high"] {{
            border-color: #ea580c;
            color: #ea580c;
        }}
        
        .filter-btn[data-filter="high"]:hover {{
            background: #ea580c;
            color: white;
            border-color: #ea580c;
            box-shadow: 0 4px 8px rgba(234, 88, 12, 0.3);
        }}
        
        .filter-btn[data-filter="high"].active {{
            background: #ea580c;
            color: white;
            border-color: #ea580c;
            box-shadow: 0 4px 12px rgba(234, 88, 12, 0.4);
        }}
        
        .filter-btn[data-filter="medium"] {{
            border-color: #f59e0b;
            color: #f59e0b;
        }}
        
        .filter-btn[data-filter="medium"]:hover {{
            background: #f59e0b;
            color: white;
            border-color: #f59e0b;
            box-shadow: 0 4px 8px rgba(245, 158, 11, 0.3);
        }}
        
        .filter-btn[data-filter="medium"].active {{
            background: #f59e0b;
            color: white;
            border-color: #f59e0b;
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4);
        }}
        
        .filter-btn[data-filter="low"] {{
            border-color: #3b82f6;
            color: #3b82f6;
        }}
        
        .filter-btn[data-filter="low"]:hover {{
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
            box-shadow: 0 4px 8px rgba(59, 130, 246, 0.3);
        }}
        
        .filter-btn[data-filter="low"].active {{
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }}
        
        .filter-btn[data-filter="info"] {{
            border-color: #6b7280;
            color: #6b7280;
        }}
        
        .filter-btn[data-filter="info"]:hover {{
            background: #6b7280;
            color: white;
            border-color: #6b7280;
            box-shadow: 0 4px 8px rgba(107, 114, 128, 0.3);
        }}
        
        .filter-btn[data-filter="info"].active {{
            background: #6b7280;
            color: white;
            border-color: #6b7280;
            box-shadow: 0 4px 12px rgba(107, 114, 128, 0.4);
        }}
        
        .findings {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        
        .finding {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
            border-left: 5px solid #00d4ff;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .finding:hover {{
            transform: translateX(2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.12);
        }}
        
        .finding.critical {{
            border-left-color: #dc2626;
        }}
        
        .finding.high {{
            border-left-color: #ea580c;
        }}
        
        .finding.medium {{
            border-left-color: #f59e0b;
        }}
        
        .finding.low {{
            border-left-color: #3b82f6;
        }}
        
        .finding.info {{
            border-left-color: #6b7280;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .finding-title {{
            font-size: 1.4em;
            font-weight: 600;
            color: #1f2937;
            flex: 1;
        }}
        
        .badges {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .badge {{
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .badge.critical {{
            background: #fee2e2;
            color: #dc2626;
        }}
        
        .badge.high {{
            background: #ffedd5;
            color: #ea580c;
        }}
        
        .badge.medium {{
            background: #fef3c7;
            color: #d97706;
        }}
        
        .badge.low {{
            background: #dbeafe;
            color: #2563eb;
        }}
        
        .badge.info {{
            background: #f3f4f6;
            color: #6b7280;
        }}
        
        .badge.confidence {{
            background: #f0fdf4;
            color: #16a34a;
        }}
        
        .finding-location {{
            color: #6b7280;
            font-size: 0.9em;
            margin-bottom: 15px;
            font-family: 'Monaco', 'Courier New', monospace;
        }}
        
        .finding-section {{
            margin-bottom: 20px;
        }}
        
        .finding-section h4 {{
            color: #4b5563;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .finding-section p {{
            color: #374151;
            line-height: 1.7;
        }}
        
        .code-snippet {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.6;
            margin-top: 10px;
        }}
        
        .code-snippet pre {{
            margin: 0;
            white-space: pre;
        }}
        
        .code-line {{
            display: block;
        }}
        
        .code-line.highlight {{
            background: rgba(251, 191, 36, 0.1);
            border-left: 3px solid #fbbf24;
            padding-left: 5px;
            margin-left: -8px;
        }}
        
        .mitigation {{
            background: #f0fdf4;
            border-left: 4px solid #16a34a;
            padding: 15px;
            border-radius: 6px;
            color: #166534;
        }}
        
        .mitigation ul {{
            margin: 0;
            padding-left: 20px;
            list-style-type: disc;
        }}
        
        .mitigation li {{
            margin: 8px 0;
            line-height: 1.6;
        }}
        
        .mitigation p {{
            margin: 0;
        }}
        
        footer {{
            text-align: center;
            padding: 40px 30px;
            color: #6b7280;
            font-size: 0.9em;
            margin-top: 50px;
            border-top: 1px solid rgba(0,0,0,0.1);
        }}
        
        footer p {{
            margin: 5px 0;
        }}
        
        footer strong {{
            color: #00d4ff;
            font-weight: 600;
        }}
        
        .no-findings {{
            background: white;
            padding: 60px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .no-findings h2 {{
            color: #16a34a;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .no-findings p {{
            color: #6b7280;
            font-size: 1.1em;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            
            .filters {{
                display: none;
            }}
            
            .finding {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>FALCONEYE</h1>
            <div class="subtitle">Security Code Review</div>
            <div class="meta">
                <div><strong>Project:</strong> {review.codebase_path}</div>
                <div><strong>Languages:</strong> {self._format_languages(review)}</div>
                <div><strong>Scan Date:</strong> {review.started_at.strftime('%Y-%m-%d %H:%M:%S')}</div>
                <div><strong>Files Analyzed:</strong> {self._get_files_analyzed_count(review)}</div>
                <div><strong>Duration:</strong> {self._format_duration(review)}</div>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Findings</div>
                <div class="value">{stats['total']}</div>
            </div>
            <div class="stat-card critical">
                <div class="label">Critical</div>
                <div class="value">{stats['critical']}</div>
            </div>
            <div class="stat-card high">
                <div class="label">High</div>
                <div class="value">{stats['high']}</div>
            </div>
            <div class="stat-card medium">
                <div class="label">Medium</div>
                <div class="value">{stats['medium']}</div>
            </div>
            <div class="stat-card low">
                <div class="label">Low</div>
                <div class="value">{stats['low']}</div>
            </div>
        </div>
        
        {self._render_filters() if stats['total'] > 0 else ''}
        
        <div class="findings">
            {self._render_findings(review) if stats['total'] > 0 else self._render_no_findings()}
        </div>
        
        <footer>
            <p>Generated by <strong>FalconEYE</strong> - AI-Powered Security Analysis</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
    
    <script>
        // Filter functionality
        document.addEventListener('DOMContentLoaded', function() {{
            const filterButtons = document.querySelectorAll('.filter-btn');
            const findings = document.querySelectorAll('.finding');
            
            filterButtons.forEach(button => {{
                button.addEventListener('click', function() {{
                    const filter = this.dataset.filter;
                    
                    // Update active state
                    filterButtons.forEach(btn => btn.classList.remove('active'));
                    this.classList.add('active');
                    
                    // Filter findings
                    findings.forEach(finding => {{
                        if (filter === 'all' || finding.classList.contains(filter)) {{
                            finding.style.display = 'block';
                        }} else {{
                            finding.style.display = 'none';
                        }}
                    }});
                }});
            }});
        }});
    </script>
</body>
</html>"""
        
        return html

    def format_finding(self, finding: SecurityFinding) -> str:
        """
        Format single security finding as HTML.

        Args:
            finding: SecurityFinding to format

        Returns:
            HTML string
        """
        return self._render_finding(finding)

    def get_file_extension(self) -> str:
        """Get file extension for HTML format."""
        return ".html"

    def _calculate_statistics(self, review: SecurityReview) -> Dict[str, int]:
        """Calculate statistics from review."""
        return {
            'total': len(review.findings),
            'critical': review.get_critical_count(),
            'high': review.get_high_count(),
            'medium': review.get_medium_count(),
            'low': review.get_low_count(),
        }

    def _get_files_analyzed_count(self, review: SecurityReview) -> int:
        """
        Get the number of files analyzed.
        
        If files_analyzed is 0, calculate from unique file paths in findings.
        """
        if review.files_analyzed > 0:
            return review.files_analyzed
        
        # Calculate from unique file paths in findings
        unique_files = set()
        for finding in review.findings:
            if finding.file_path:
                unique_files.add(finding.file_path)
        
        return len(unique_files) if unique_files else 1  # At least 1 if we have findings

    def _format_duration(self, review: SecurityReview) -> str:
        """Format duration in human-readable format."""
        if not review.completed_at:
            return "In progress"
        
        duration = (review.completed_at - review.started_at).total_seconds()
        
        if duration < 60:
            return f"{int(duration)}s"
        elif duration < 3600:
            minutes = int(duration / 60)
            seconds = int(duration % 60)
            return f"{minutes}m {seconds}s"
        else:
            hours = int(duration / 3600)
            minutes = int((duration % 3600) / 60)
            return f"{hours}h {minutes}m"

    def _format_languages(self, review: SecurityReview) -> str:
        """
        Format languages for display in HTML report.
        
        Shows all unique languages detected in the analyzed files.
        
        Args:
            review: SecurityReview containing findings
            
        Returns:
            Formatted language string
        """
        languages = review.get_all_languages()
        
        if len(languages) == 1:
            return languages[0].capitalize()
        else:
            # Capitalize each language and join with commas
            formatted = ", ".join(lang.capitalize() for lang in languages)
            return formatted

    def _render_filters(self) -> str:
        """Render filter buttons."""
        return """
        <div class="filters">
            <h3>Filter by Severity</h3>
            <div class="filter-buttons">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="critical">Critical</button>
                <button class="filter-btn" data-filter="high">High</button>
                <button class="filter-btn" data-filter="medium">Medium</button>
                <button class="filter-btn" data-filter="low">Low</button>
                <button class="filter-btn" data-filter="info">Info</button>
            </div>
        </div>
        """

    def _render_findings(self, review: SecurityReview) -> str:
        """Render all findings."""
        # Sort by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(
            review.findings,
            key=lambda f: severity_order.get(f.severity, 999)
        )
        
        return '\n'.join(self._render_finding(f) for f in sorted_findings)

    def _render_finding(self, finding: SecurityFinding) -> str:
        """Render a single finding."""
        severity = finding.severity.value.lower()
        confidence = finding.confidence.value
        
        # Format location
        location = finding.file_path
        if finding.line_start:
            if finding.line_end and finding.line_end != finding.line_start:
                location += f" (lines {finding.line_start}-{finding.line_end})"
            else:
                location += f" (line {finding.line_start})"
        
        # Format code snippet with line highlighting
        code_html = self._format_code_snippet(finding.code_snippet, finding.line_start, finding.line_end)
        
        return f"""
        <div class="finding {severity}" data-severity="{severity}">
            <div class="finding-header">
                <div class="finding-title">{self._escape_html(finding.issue)}</div>
                <div class="badges">
                    <span class="badge {severity}">{severity}</span>
                    <span class="badge confidence">{confidence}</span>
                </div>
            </div>
            
            <div class="finding-location">{self._escape_html(location)}</div>
            
            <div class="finding-section">
                <h4>Description</h4>
                <p>{self._escape_html(finding.reasoning)}</p>
            </div>
            
            {f'<div class="finding-section"><h4>Code Snippet</h4>{code_html}</div>' if finding.code_snippet else ''}
            
            <div class="finding-section">
                <h4>Recommendation</h4>
                <div class="mitigation">
                    {self._format_mitigation(finding.mitigation)}
                </div>
            </div>
            
            {f'<div class="finding-section"><h4>CWE ID</h4><p>{finding.cwe_id}</p></div>' if finding.cwe_id else ''}
            {f'<div class="finding-section"><h4>Tags</h4><p>{", ".join(finding.tags)}</p></div>' if finding.tags else ''}
        </div>
        """

    def _format_code_snippet(self, snippet: str, line_start: int = None, line_end: int = None) -> str:
        """Format code snippet with syntax highlighting."""
        if not snippet:
            return ""
        
        lines = snippet.split('\n')
        formatted_lines = []
        
        for line in lines:
            # Check if line should be highlighted (contains > marker)
            is_highlight = '>' in line[:10]  # Check first 10 chars for line number marker
            css_class = ' class="code-line highlight"' if is_highlight else ' class="code-line"'
            formatted_lines.append(f'<span{css_class}>{self._escape_html(line)}</span>')
        
        code_content = '\n'.join(formatted_lines)
        
        return f'<div class="code-snippet"><pre>{code_content}</pre></div>'

    def _render_no_findings(self) -> str:
        """Render message when no findings."""
        return """
        <div class="no-findings">
            <h2>No Security Issues Found</h2>
            <p>The security analysis did not identify any vulnerabilities in the scanned code.</p>
        </div>
        """

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

    def _format_mitigation(self, mitigation: str) -> str:
        """
        Format mitigation text as bullet points if multi-line, otherwise as paragraph.
        
        Args:
            mitigation: Mitigation recommendation text
            
        Returns:
            HTML formatted mitigation
        """
        if not mitigation:
            return ""
        
        # Check if mitigation has multiple lines or numbered points
        lines = [line.strip() for line in mitigation.split('\n') if line.strip()]
        
        # If single line, return as paragraph
        if len(lines) == 1:
            return f"<p>{self._escape_html(mitigation)}</p>"
        
        # Check if lines start with numbers (1., 2., etc.) or bullets (-, *, •)
        has_markers = any(
            line[0].isdigit() or line.startswith(('-', '*', '•', '→', '▸'))
            for line in lines if line
        )
        
        # Format as bullet list
        bullet_items = []
        for line in lines:
            # Remove common prefixes like "1.", "2.", "-", "*", etc.
            cleaned = line.lstrip('0123456789.-*•→▸ ')
            if cleaned:
                bullet_items.append(f"<li>{self._escape_html(cleaned)}</li>")
        
        if bullet_items:
            return f"<ul>{''.join(bullet_items)}</ul>"
        
        # Fallback to paragraph
        return f"<p>{self._escape_html(mitigation)}</p>"
