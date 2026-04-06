import asyncio
import argparse
import sys
from pathlib import Path
from typing import Optional

from crawler.browser import crawl_site
from analysis.gdpr_check import (
    check_gdpr_clauses, calculate_compliance_score, 
    get_missing_clauses, get_found_clauses, 
    has_critical_failures
)
from storage.db import init_db, save_scan
from reports.report import ReportGenerator


CRITICAL_CLAUSES = ["right_to_delete", "data_collection", "legal_basis"]


def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║         GDPR Compliance Crawler v1.0             ║
║    Cookie Banner & Privacy Policy Checker         ║
╚══════════════════════════════════════════════════╝
    """)


def print_result(result: dict, found_count: int, total_count: int, 
                 score_str: str, missing_clauses: list, found_clauses: list) -> None:
    url = result.get("url", "N/A")
    
    print(f"\n[SCAN COMPLETE] {url}")
    print("─" * 60)
    print(f"Cookie Banner:     {'✅ FOUND' if result.get('cookie_banner') else '❌ NOT FOUND'}")
    if result.get("banner_selector"):
        print(f"  → Selector: {result['banner_selector']}")
    if result.get("cookie_action_taken"):
        print(f"  → Action Taken: {result['cookie_action_taken']}")
        print(f"  → Initial Cookies: {len(result.get('initial_cookies', []))}")
        print(f"  → Post-Action Cookies: {len(result.get('post_action_cookies', []))}")
    
    if result.get("privacy_policy"):
        print(f"Privacy Policy:    ✅ FOUND")
        print(f"  → {result['privacy_policy']}")
    else:
        print(f"Privacy Policy:    ❌ NOT FOUND")
    
    print(f"\nCompliance Score:  {score_str}")
    
    print(f"\nGDPR Clauses ({found_count}/{total_count} found):")
    for clause in found_clauses:
        critical = " [CRITICAL]" if clause in CRITICAL_CLAUSES else ""
        print(f"  ✅ {clause.replace('_', ' ').title()}{critical}")
    for clause in missing_clauses:
        critical = " [CRITICAL]" if clause in CRITICAL_CLAUSES else ""
        print(f"  ❌ {clause.replace('_', ' ').title()}{critical}")
    
    if result.get("html_path"):
        print(f"\nHTML:       {result['html_path']}")
    
    if result.get("error"):
        print(f"\n⚠️  ERROR: {result['error']}")


async def scan_url(url: str, output_dir: str = "evidence", 
                   report_format: str = "html", 
                   save_to_db: bool = True) -> dict:
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    print(f"🔍 Scanning: {url}")
    
    result = await crawl_site(url, output_dir)
    
    if result.get("error"):
        print(f"❌ {result['error']}")
        return result
    
    if result.get("privacy_policy_text"):
        text_to_analyze = Path(result["privacy_policy_text"]).read_text(encoding="utf-8")
    elif result.get("html_text_path"):
        text_to_analyze = Path(result["html_text_path"]).read_text(encoding="utf-8")
    else:
        text_to_analyze = ""
    
    clause_results = check_gdpr_clauses(text_to_analyze)
    found_count, total_count, score_str = calculate_compliance_score(clause_results)
    missing_clauses = get_missing_clauses(clause_results)
    found_clauses = get_found_clauses(clause_results)
    critical_failed = has_critical_failures(clause_results)
    
    print_result(result, found_count, total_count, score_str, missing_clauses, found_clauses)
    
    report_gen = ReportGenerator()
    report_path = report_gen.save_report(result, clause_results, score_str, report_format)
    print(f"\n📄 Report saved: {report_path}")
    
    if save_to_db:
        init_db()
        scan_id = save_scan(result, clause_results, score_str)
        print(f"💾 Saved to DB (ID: {scan_id})")
    
    result["critical_failed"] = critical_failed
    result["score_str"] = score_str
    result["clause_results"] = clause_results
    
    return result


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="GDPR Compliance Crawler")
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("-f", "--file", help="File with URLs (one per line)")
    parser.add_argument("-o", "--output", default="evidence", help="Output directory")
    parser.add_argument("--format", choices=["html", "json"], default="html", help="Report format")
    parser.add_argument("--no-db", action="store_true", help="Skip saving to database")
    
    args = parser.parse_args()
    
    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        urls = [line.strip() for line in Path(args.file).read_text().splitlines() if line.strip()]
    
    if not urls:
        print("Usage: python main.py <url>")
        print("   or: python main.py -f urls.txt")
        sys.exit(1)
    
    save_to_db = not args.no_db
    has_critical = False
    
    for i, url in enumerate(urls, 1):
        if len(urls) > 1:
            print(f"\n[{i}/{len(urls)}] Processing: {url}")
        
        result = asyncio.run(scan_url(
            url, 
            output_dir=args.output,
            report_format=args.format,
            save_to_db=save_to_db
        ))
        
        if result and result.get("critical_failed"):
            has_critical = True
    
    if has_critical:
        print("\n⚠️  WARNING: Critical GDPR clauses missing in one or more scans")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
