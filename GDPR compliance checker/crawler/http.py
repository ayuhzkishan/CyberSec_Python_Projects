import time
import random
import urllib.robotparser
from urllib.parse import urlparse
from typing import Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import HEADERS, SETTINGS


class RateLimiter:
    def __init__(self, delay: float = SETTINGS["rate_limit_delay"]):
        self.delay = delay
        self.last_request = 0.0

    def wait(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request = time.time()


class PoliteSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        
        retry_strategy = Retry(
            total=SETTINGS["max_retries"],
            backoff_factor=SETTINGS["retry_backoff"],
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.rate_limiter = RateLimiter()

    def get(self, url: str, timeout: int = 30) -> Optional[requests.Response]:
        self.rate_limiter.wait()
        try:
            response = self.session.get(url, timeout=timeout, headers={
                "User-Agent": HEADERS["User-Agent"]
            })
            return response
        except requests.RequestException:
            return None


class RobotsChecker:
    def __init__(self):
        self.parser = urllib.robotparser.RobotFileParser()
        self.cache = {}

    def can_fetch(self, url: str, user_agent: str = "*") -> bool:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        if robots_url not in self.cache:
            self.parser.set_url(robots_url)
            try:
                self.parser.read()
                self.cache[robots_url] = self.parser
            except Exception:
                return True
        
        return self.cache[robots_url].can_fetch(user_agent, url)


def check_robots_txt(url: str) -> Tuple[bool, Optional[str]]:
    checker = RobotsChecker()
    can_crawl = checker.can_fetch(url)
    return can_crawl, None
