from urllib.parse import urlparse
from typing import Optional

from crawler.http import RobotsChecker


def check_robots_txt(url: str) -> dict:
    checker = RobotsChecker()
    can_fetch = checker.can_fetch(url)
    
    return {
        "url": url,
        "allowed": can_fetch,
        "message": "Crawling allowed" if can_fetch else "Blocked by robots.txt"
    }


def get_base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
