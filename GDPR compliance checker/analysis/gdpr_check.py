import re
from typing import Dict, List, Tuple

from config import REQUIRED_CLAUSES


CRITICAL_CLAUSES = ["right_to_delete", "data_collection", "legal_basis"]


def check_gdpr_clauses(text: str) -> Dict[str, dict]:
    text_lower = text.lower()
    results = {}

    for clause_name, pattern in REQUIRED_CLAUSES.items():
        try:
            match = re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL)
            if match:
                snippet = match.group(0)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace("\n", " ").strip()
            else:
                snippet = None
                context = None
            
            results[clause_name] = {
                "found": match is not None,
                "snippet": snippet,
                "context": context,
            }
        except re.error:
            results[clause_name] = {
                "found": False,
                "snippet": None,
                "context": None,
                "error": "Invalid regex pattern"
            }

    return results


def calculate_compliance_score(clause_results: Dict[str, dict]) -> Tuple[int, int, str]:
    if not clause_results:
        return 0, 0, "0/0"
    
    found_count = sum(1 for r in clause_results.values() if r["found"])
    total_count = len(clause_results)
    percentage = round((found_count / total_count) * 100)
    
    return found_count, total_count, f"{found_count}/{total_count} ({percentage}%)"


def get_missing_clauses(clause_results: Dict[str, dict]) -> List[str]:
    return [name for name, result in clause_results.items() if not result["found"]]


def get_found_clauses(clause_results: Dict[str, dict]) -> List[str]:
    return [name for name, result in clause_results.items() if result["found"]]


def has_critical_failures(clause_results: Dict[str, dict]) -> bool:
    for clause in CRITICAL_CLAUSES:
        if clause in clause_results and not clause_results[clause]["found"]:
            return True
    return False
