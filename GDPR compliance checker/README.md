# 🛡️ GDPR Compliance Crawler

An automated, python-based web crawler and analyzer designed to help developers, security engineers, and legal teams audit websites for General Data Protection Regulation (GDPR) tracking compliance. 

The tool systematically maps web domains, simulates cookie interactions mimicking a real user, extracts and parses legal documents, and evaluates the presence of mandatory privacy clauses seamlessly.

## ✨ Features
* **Automated Crawler:** Uses `Playwright` to navigate domains seamlessly, rendering JavaScript and tracking network exchanges to evaluate exactly what happens when the page loads.
* **Cookie Banner Detection:** Identifies the presence of Cookie Consent Banners. It clicks "Accept" or "Reject" buttons and actively measures the quantity of cookies dropped before and after interacting with the banner.
* **Privacy Policy Discovery:** Scrapes and isolates the designated privacy policy pages by traversing site structure. 
* **Dynamic Legal Clause Analysis:** Contextually scans the text of privacy policies mapped against a strictly configured Regex taxonomy for 8 critical GDPR obligations.
* **Evidence Collection:** Automatically exports clean `.txt` copies of policies, raw HTML code, and captures Base64 full-page screenshots of scanned targets into the `/evidence` directory.
* **Aggregated Reporting:** Auto-generates shareable, elegantly designed HTML scorecards or raw JSON dumps in the `/reports` directory.
* **SQLite Archival:** Logs historical scan data inside a lightweight `gdpr_crawler.db` for trend tracking.

## ⚖️ Tracked Compliance Clauses
The crawler measures the text found across web estates and policies to assert if the following criteria are properly disclosed:

1. **Right to Delete:** Ensuring users can request erasure ("Right to be Forgotten"). 
2. **Data Collection Scope:** Express statements defining *what* data is being hoarded.
3. **Third Party Sharing:** Exposing definitions of who the data gets routed to.
4. **Data Protection Officer (DPO):** Validating reachable contact info to privacy regulators or the DPO.
5. **Legal Basis:** Explaining the lawful justification for keeping information.
6. **Retention Period:** Disclosing exactly how long user data is stored before destruction.
7. **User Rights:** Catch-all for Subject Access Requests and withdrawals.
8. **Cookies Disclosure:** Acknowledging the use of analytics, ad-tracking, or necessary cookies.

## 🚀 How to Run

### Installation
Ensure that you have installed all python dependencies before crawling:
```bash
pip install -r requirements.txt
playwright install
```

### Usage
Run the crawler against a single domain. It will auto-resolve protocols (`https://`) if omitted and begin evaluating compliance!
```bash
python main.py <target-url>
```
*Example:* `python main.py vssut.ac.in`

You can also run batch scans by feeding it a text file with one URL per line:
```bash
python main.py -f urls.txt
```

### Advanced Usage Flags
* `-o`, `--output`: Change the default evidence directory.
* `--format`: Choose output report format (`html` or `json`).
* `--no-db`: Skips writing the local compliance findings to `gdpr_crawler.db`.

## ⚙️ Architecture & Workflow
1. **Intake & Normalization:** Target passed by CLI is cleaned, validated, and tested against `robots.txt` rules out of compliance respect.
2. **Deep-Crawl Phase:** Chromium spins up headless. It navigates to the domain and waits until the DOM structure completes loading. 
3. **Evidence & Interaction:** Pre-action cookies are captured. If a banner matches CSS selectors, it evaluates compliance strings to determine rejection/acceptance functionality and measures post-action cookies. 
4. **Analysis Phase:** Target privacy text undergoes Regex scanning evaluating the strict presence of mandated terminology.
5. **Scoring & Output:** A score metric is generated determining compliance thresholds. The output creates an HTML execution receipt.
