Crawly
Crawly is a fast, parallel processing web scanner that crawls websites to detect privacy-impacting elements like tracking cookies, social media embeds, and analytics scripts using Playwright and BeautifulSoup. It can also run in scraper mode to search for specific keywords or file types (like *.pdf or token) across a site.

Features
🔍 Detects tracking cookies, social media plugins, analytics tools, and suspicious domains

🔎 Scraper mode: search for custom strings or patterns like "login" or "*.pdf"

⚡ Fast, multithreaded scanning with ThreadPoolExecutor

🎭 Uses Playwright to simulate real browser visits and collect JavaScript-set cookies

🧠 Smart filtering of URLs and crawl depth

💾 Save raw scan results to JSON for re-export

♻️ Re-export CSVs with different filters without rescanning

⏹️ Gracefully stop crawling by pressing q and proceed to scanning

📄 Outputs results to a CSV for easy review

Installation
Requirements
Python 3.7 or later

Install Crawly (via PyPI)
bash
Copy
Edit
pip install crawly-zarcuel
playwright install
Install Crawly (for development)
bash
Copy
Edit
pip install beautifulsoup4 playwright
playwright install
Usage
bash
Copy
Edit
python crawly.py -u <start_url> [options]
Or if installed via pip:

bash
Copy
Edit
crawly-zarcuel -u <start_url> [options]
Options
Option	Description
-u, --url	Required. Starting URL to scan
-d	Crawl depth (default: 2)
-e, --exclude	List of substrings to exclude from crawling (e.g., logout, contact)
-w, --workers	Number of parallel workers/threads (default: 4)
-o, --output	Output CSV filename (default: scan_results.csv)
-s, --scan-limit	Max number of pages to scan (optional)
-f, --filter	Substrings to filter out from final CSV output (e.g., googletagmanager)
--scrape	Enable scraper mode (e.g., "*.pdf" or "token")
--save-json	Save raw scan results to a JSON file
--reexport <file>	Re-export from a previous JSON file without crawling or scanning again

Example: Full Scan
bash
Copy
Edit
python crawly.py -u https://example.com -d 2 -w 5 -e logout contact -o report.csv --save-json raw.json
Example: Scraper Mode
bash
Copy
Edit
python crawly.py -u https://example.com --scrape "*.pdf"
python crawly.py -u https://example.com --scrape "login"
Example: Re-export with new filters (no scanning)
bash
Copy
Edit
python crawly.py --reexport raw.json -o clean.csv -f googletagmanager facebook
Output
The output is a CSV file with columns:

URL – the scanned page

Detected – Yes or No depending on if matches were found

Source – all matched sources (scripts, embeds, file links, or patterns)

Cookies – matched cookie names and headers (only in detection mode)

Optional: Save raw scan results to a .json file for reuse and offline re-filtering.

Author
Zarcuel — Privacy-focused pentester and creator of Crawly 🕷️

License
MIT License
© 2025 Zarcuel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
