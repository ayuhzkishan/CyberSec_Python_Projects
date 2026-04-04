BANNER_SELECTORS = [
    "#cookie-banner", ".cookie-consent", ".cookie-notice",
    "#CybotCookiebotDialog", ".cc-banner", ".cc-window",
    ".qc-cmp2-container", ".optanon-alert-box-wrapper",
    "[id*='cookie']", "[class*='cookie']", "[class*='gdpr']",
    "[class*='consent']", "[aria-label*='cookie']",
    ".cookieConsent", "#cookieConsent", ".CookieConsent",
]

POLICY_SELECTORS = [
    "a[href*='privacy']", "a[href*='privacy-policy']",
    "a[href*='privacypolicy']", "a[href*='privacy_notice']",
    "a[href*='data-protection']", "a[href*='dataprotection']",
]

POLICY_KEYWORDS = [
    "privacy policy", "privacy notice", "data protection",
    "privacy statement", "privacy statement", "cookie policy"
]

REQUIRED_CLAUSES = {
    "right_to_delete": r"right to (erasure|deletion|be forgotten|remove)",
    "data_collection": r"(we collect|data we collect|information collected|personal data we)",
    "third_party": r"(third.party|share.*data|data.*share|disclose.*third)",
    "contact_dpo": r"(data protection officer|DPO|contact.*privacy|privacy.*contact)",
    "legal_basis": r"(legitimate interest|consent|legal obligation|lawful basis)",
    "retention_period": r"(retain|retention|store.*data|how long|period.*keep)",
    "user_rights": r"(your rights|right to access|right.*withdraw|data subject rights)",
    "cookies_disclosure": r"(cookie|tracking|analytics|advertisement)",
}

HEADERS = {
    "User-Agent": "GDPR-Crawler/1.0 (Educational Tool; respects robots.txt)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}

SETTINGS = {
    "timeout": 30000,
    "screenshot_delay": 2000,
    "max_retries": 3,
    "retry_backoff": 2,
    "rate_limit_delay": 1.0,
    "content_selectors": ["main", "article", "[role='main']", ".content", "#content"],
}
