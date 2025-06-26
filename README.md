# Crawly

**Crawly** is a fast, parallelized web scanner that crawls websites to detect privacy-impacting elements like tracking cookies, social media embeds, and analytics scripts using Playwright and BeautifulSoup.

---

## Features

* 🔍 Detects tracking cookies, social media plugins, analytics tools, and suspicious domains
* ⚡ Fast, multithreaded scanning with ThreadPoolExecutor
* 🎭 Uses Playwright to simulate real browser visits and collect JavaScript-set cookies
* 🧠 Smart filtering of URLs and crawl depth
* 📄 Outputs results to a CSV for easy review

---

## Installation

### Requirements

* Python 3.7 or later

### Install Crawly (for development)

```bash
pip install beautifulsoup4 playwright
playwright install
```

---

## Usage

```bash
python crawly.py -u <start_url> [options]
```

### Options

| Option               | Description                                                             |
| -------------------- | ----------------------------------------------------------------------- |
| `-u`, `--url`        | **Required.** Starting URL to scan                                      |
| `-d`                 | Crawl depth (default: `2`)                                              |
| `-e`, `--exclude`    | List of substrings to exclude from crawling (e.g., `logout`, `contact`) |
| `-w`, `--workers`    | Number of parallel workers/threads (default: `4`)                       |
| `-o`, `--output`     | Output CSV filename (default: `scan_results.csv`)                       |
| `-s`, `--scan-limit` | Max number of pages to scan (optional)                                  |

### Example

```bash
python crawly.py -u https://example.com -d 2 -w 5 -e logout contact -o report.csv
```

---

## Output

The output is a CSV file with columns:

* `URL` – the scanned page
* `Detected` – `Yes` or `No` depending on if trackers were found
* `Source` – all tracking/script sources detected
* `Cookies` – matched cookie names and headers

---



## Author

Zarcuel — Privacy-focused pentester and creator of Crawly 🕷️
