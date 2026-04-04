import json
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime


class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate_html(self, scan_data: Dict, clause_results: Dict, compliance_score_str: str) -> str:
        timestamp = scan_data.get("timestamp", datetime.now().isoformat())
        domain = self._extract_domain(scan_data.get("url", ""))
        screenshot_base64 = scan_data.get("screenshot_base64")
        
        cookie_status = "✅ FOUND" if scan_data.get("cookie_banner") else "❌ NOT FOUND"
        policy_status = f"✅ {scan_data.get('privacy_policy')}" if scan_data.get("privacy_policy") else "❌ NOT FOUND"
        
        screenshot_html = ""
        if screenshot_base64:
            screenshot_html = f'<img src="data:image/png;base64,{screenshot_base64}" alt="Screenshot" style="max-width:100%; border:1px solid #ddd; border-radius:4px;">'
        else:
            screenshot_html = "<p>No screenshot available</p>"
        
        clauses_html = ""
        for clause_name, result in clause_results.items():
            status = "✅" if result["found"] else "❌"
            snippet = result.get("snippet") or "N/A"
            clauses_html += f"""
            <tr>
                <td>{clause_name.replace('_', ' ').title()}</td>
                <td>{status}</td>
                <td><code>{self._escape_html(snippet[:100])}</code></td>
            </tr>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GDPR Compliance Report - {domain}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; margin-top: 0; }}
        .score {{ font-size: 48px; font-weight: bold; color: #333; }}
        .status {{ padding: 10px 15px; border-radius: 4px; margin: 5px 0; }}
        .status-found {{ background: #d4edda; color: #155724; }}
        .status-missing {{ background: #f8d7da; color: #721c24; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; word-break: break-all; }}
        .meta {{ color: #666; font-size: 0.9em; }}
        .screenshot-container {{ margin-top: 15px; }}
    </style>
</head>
<body>
    <h1>GDPR Compliance Report</h1>
    
    <div class="card">
        <p class="meta">URL: {self._escape_html(scan_data.get('url', 'N/A'))}</p>
        <p class="meta">Scanned: {timestamp}</p>
        <p class="meta">Domain: {domain}</p>
    </div>
    
    <div class="card">
        <h2>Overall Score</h2>
        <div class="score">{compliance_score_str}</div>
    </div>
    
    <div class="card">
        <h2>Cookie Banner</h2>
        <div class="status {'status-found' if scan_data.get('cookie_banner') else 'status-missing'}">
            {cookie_status}
        </div>
        {f"<p class='meta'>Selector: {scan_data.get('banner_selector')}</p>" if scan_data.get('banner_selector') else ''}
        {f"<p class='meta'>Action Taken: {scan_data.get('cookie_action_taken')}</p>" if scan_data.get('cookie_action_taken') else ''}
        <p class='meta'>Initial Cookies Count: {len(scan_data.get('initial_cookies', []))}</p>
        <p class='meta'>Post-Action Cookies Count: {len(scan_data.get('post_action_cookies', []))}</p>
    </div>
    
    <div class="card">
        <h2>Privacy Policy</h2>
        <div class="status {'status-found' if scan_data.get('privacy_policy') else 'status-missing'}">
            {policy_status}
        </div>
    </div>
    
    <div class="card">
        <h2>GDPR Clause Analysis</h2>
        <table>
            <thead>
                <tr><th>Clause</th><th>Status</th><th>Match</th></tr>
            </thead>
            <tbody>
                {clauses_html}
            </tbody>
        </table>
    </div>
    
    <div class="card">
        <h2>Screenshot</h2>
        <div class="screenshot-container">
            {screenshot_html}
        </div>
    </div>
    
    <div class="card">
        <h2>Evidence Files</h2>
        {f"<p>Landing Page HTML: <code>{scan_data.get('html_path', 'N/A')}</code></p>" if scan_data.get('html_path') else ''}
        {f"<p>Landing Page Text: <code>{scan_data.get('html_text_path', 'N/A')}</code></p>" if scan_data.get('html_text_path') else ''}
        {f"<p>Privacy Policy HTML: <code>{scan_data.get('privacy_policy_html', 'N/A')}</code></p>" if scan_data.get('privacy_policy_html') else ''}
        {f"<p>Privacy Policy Text: <code>{scan_data.get('privacy_policy_text', 'N/A')}</code></p>" if scan_data.get('privacy_policy_text') else ''}
    </div>
    
    <div class="card">
        <p class="meta">Generated by GDPR Compliance Crawler</p>
    </div>
</body>
</html>"""
        
        return html

    def generate_json(self, scan_data: Dict, clause_results: Dict, compliance_score_str: str) -> str:
        report = {
            "url": scan_data.get("url"),
            "timestamp": scan_data.get("timestamp"),
            "compliance_score": compliance_score_str,
            "cookie_banner": {
                "found": scan_data.get("cookie_banner"),
                "selector": scan_data.get("banner_selector"),
                "action_taken": scan_data.get("cookie_action_taken"),
                "initial_cookies_count": len(scan_data.get("initial_cookies", [])),
                "post_action_cookies_count": len(scan_data.get("post_action_cookies", []))
            },
            "privacy_policy": scan_data.get("privacy_policy"),
            "clauses": clause_results,
            "evidence": {
                "html": scan_data.get("html_path"),
                "html_text": scan_data.get("html_text_path"),
                "privacy_policy_html": scan_data.get("privacy_policy_html"),
                "privacy_policy_text": scan_data.get("privacy_policy_text"),
            }
        }
        return json.dumps(report, indent=2)

    def save_report(self, scan_data: Dict, clause_results: Dict, compliance_score_str: str, 
                    format: str = "html") -> Path:
        domain = self._extract_domain(scan_data.get("url", ""))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "html":
            content = self.generate_html(scan_data, clause_results, compliance_score_str)
            filename = f"{domain}_{timestamp}.html"
        else:
            content = self.generate_json(scan_data, clause_results, compliance_score_str)
            filename = f"{domain}_{timestamp}.json"
        
        filepath = self.output_dir / filename
        filepath.write_text(content, encoding="utf-8")
        return filepath

    def _extract_domain(self, url: str) -> str:
        from urllib.parse import urlparse
        return urlparse(url).netloc.replace(".", "_")

    def _escape_html(self, text: str) -> str:
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))
