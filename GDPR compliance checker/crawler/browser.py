import asyncio
import base64
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple

from playwright.async_api import async_playwright, Page, Error as PlaywrightError

from config import BANNER_SELECTORS, POLICY_SELECTORS, POLICY_KEYWORDS, SETTINGS
from crawler.robots import check_robots_txt


class BrowserCrawler:
    def __init__(self, output_dir: str = "evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.playwright = None
        self.browser = None

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        return self

    async def __aexit__(self, *args):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def crawl(self, url: str) -> dict:
        robots_check = check_robots_txt(url)
        if not robots_check.get("allowed"):
            return {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "cookie_banner": None,
                "banner_selector": None,
                "privacy_policy": None,
                "privacy_policy_html": None,
                "html_path": None,
                "screenshot_base64": None,
                "error": f"Blocked by robots.txt"
            }

        context = await self.browser.new_context(
            user_agent="GDPR-Crawler/1.0 (Educational Tool)",
            viewport={"width": 1280, "height": 800},
        )
        page = await context.new_page()
        
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "cookie_banner": None,
            "banner_selector": None,
            "privacy_policy": None,
            "privacy_policy_html": None,
            "privacy_policy_text": None,
            "html_path": None,
            "html_text_path": None,
            "screenshot_base64": None,
            "initial_cookies": [],
            "post_action_cookies": [],
            "cookie_action_taken": None,
            "error": None,
        }

        try:
            await self._navigate_with_retry(page, url)
            await asyncio.sleep(SETTINGS["screenshot_delay"] / 1000)

            # Capture initial cookies
            result["initial_cookies"] = await context.cookies()

            result["cookie_banner"], result["banner_selector"] = await self._find_cookie_banner(page)
            
            # Deep cookie interaction
            if result["cookie_banner"] and result["banner_selector"]:
                action_taken = await self._interact_with_cookie_banner(page, result["banner_selector"])
                result["cookie_action_taken"] = action_taken
                # Wait for any scripts to execute and set cookies
                await asyncio.sleep(2)
                result["post_action_cookies"] = await context.cookies()
            else:
                result["post_action_cookies"] = result["initial_cookies"]

            result["privacy_policy"] = await self._find_privacy_policy(page)
            
            domain = self._extract_domain(url)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save raw HTML
            html_content = await page.content()
            html_path = self.output_dir / f"{domain}_{timestamp}.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            result["html_path"] = str(html_path)

            # Save clean text
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            clean_text = soup.get_text(separator="\n", strip=True)
            html_text_path = self.output_dir / f"{domain}_{timestamp}.txt"
            with open(html_text_path, "w", encoding="utf-8") as f:
                f.write(clean_text)
            result["html_text_path"] = str(html_text_path)
            
            screenshot_bytes = await page.screenshot(path=None, full_page=True)
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode()
            result["screenshot_base64"] = screenshot_base64

            if result["privacy_policy"]:
                policy_html_path, policy_text_path = await self._crawl_privacy_policy(context, result["privacy_policy"], domain, timestamp)
                result["privacy_policy_html"] = policy_html_path
                result["privacy_policy_text"] = policy_text_path

        except PlaywrightError as e:
            result["error"] = str(e)
        finally:
            await context.close()

        return result

    async def _navigate_with_retry(self, page: Page, url: str):
        max_retries = SETTINGS["max_retries"]
        last_error = None
        
        for attempt in range(max_retries):
            try:
                await page.goto(url, timeout=SETTINGS["timeout"], wait_until="networkidle")
                return
            except PlaywrightError as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = SETTINGS["retry_backoff"] ** attempt
                    await asyncio.sleep(wait_time)
        
        raise last_error or PlaywrightError("Failed to navigate after retries")

    async def _crawl_privacy_policy(self, context, policy_url: str, domain: str, timestamp: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            page = await context.new_page()
            await page.goto(policy_url, timeout=SETTINGS["timeout"], wait_until="networkidle")
            
            html_content = await page.content()
            
            policy_html_path = self.output_dir / f"{domain}_privacy_{timestamp}.html"
            with open(policy_html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            clean_text = soup.get_text(separator="\n", strip=True)
            
            policy_text_path = self.output_dir / f"{domain}_privacy_{timestamp}.txt"
            with open(policy_text_path, "w", encoding="utf-8") as f:
                f.write(clean_text)
            
            await page.close()
            return str(policy_html_path), str(policy_text_path)
        except Exception:
            return None, None

    async def _interact_with_cookie_banner(self, page: Page, banner_selector: str) -> Optional[str]:
        # Tries to find 'Reject' and then 'Accept' buttons
        reject_keywords = ['reject', 'deny', 'decline', 'refuse']
        accept_keywords = ['accept', 'allow', 'agree', 'got it', 'ok', 'consent']
        
        try:
            banner = page.locator(banner_selector).first
            if await banner.count() == 0:
                return None
                
            buttons = banner.locator("button, a, [role='button']")
            count = await buttons.count()
            
            # 1. First search for a Reject button
            for i in range(count):
                btn = buttons.nth(i)
                text = (await btn.inner_text() or "").lower()
                if any(kw in text for kw in reject_keywords):
                    await btn.scroll_into_view_if_needed()
                    await btn.click(timeout=3000)
                    return "Rejected"
                    
            # 2. If no Reject, search for an Accept button
            for i in range(count):
                btn = buttons.nth(i)
                text = (await btn.inner_text() or "").lower()
                if any(kw in text for kw in accept_keywords):
                    await btn.scroll_into_view_if_needed()
                    await btn.click(timeout=3000)
                    return "Accepted"
        except Exception:
            pass
            
        return None

    async def _find_cookie_banner(self, page: Page) -> Tuple[bool, Optional[str]]:
        for selector in BANNER_SELECTORS:
            try:
                element = page.locator(selector).first
                if await element.count() > 0 and await element.is_visible():
                    return True, selector
            except Exception:
                continue
        return False, None

    async def _find_privacy_policy(self, page: Page) -> Optional[str]:
        for selector in POLICY_SELECTORS:
            try:
                elements = page.locator(selector)
                count = await elements.count()
                for i in range(count):
                    href = await elements.nth(i).get_attribute("href")
                    text = await elements.nth(i).text_content()
                    if href and any(kw in (href + (text or "")).lower() for kw in POLICY_KEYWORDS):
                        if href.startswith("http"):
                            return href
                        elif href.startswith("/"):
                            page_url = page.url
                            parsed = page_url.split("//", 1)[1] if "//" in page_url else page_url
                            base = parsed.split("/", 1)[0]
                            return f"https://{base}{href}"
                        else:
                            return href
            except Exception:
                continue
        return None

    def _extract_domain(self, url: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc.replace(".", "_")


async def crawl_site(url: str, output_dir: str = "evidence") -> dict:
    async with BrowserCrawler(output_dir) as crawler:
        return await crawler.crawl(url)
