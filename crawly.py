import sys
import time
import argparse
import csv
import json
import threading
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from concurrent.futures import ThreadPoolExecutor, as_completed
import fnmatch

class PageScanner:
    def __init__(self, start_url=None, max_depth=2, delay=1.0, exclude_patterns=None, workers=4, scrape_pattern=None):
        self.start_url = start_url
        self.max_depth = max_depth
        self.delay = delay
        self.exclude_patterns = exclude_patterns or []
        self.workers = workers
        self.visited = set()
        self.processed_datarefs = set()
        self.stop_event = threading.Event()
        self.scrape_pattern = scrape_pattern

    def normalize_url(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for key in ['cache', 'back', 'template']:
            query.pop(key, None)
        new_query = '&'.join(f"{k}={v[0]}" for k, v in query.items())
        clean = parsed._replace(query=new_query, fragment="")
        return urlunparse(clean)

    def crawl(self, limit=None):
        queue = [(self.start_url, 0)]
        urls_to_scan = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            while queue and not self.stop_event.is_set():
                url, depth = queue.pop(0)
                normalized_url = self.normalize_url(url)
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                dataref = query.get("dataRef", [None])[0]

                if dataref and dataref in self.processed_datarefs:
                    continue

                if normalized_url in self.visited or depth > self.max_depth:
                    continue

                self.visited.add(normalized_url)
                print(f"[+] Queued for scan ({depth}): {url}")
                urls_to_scan.append(normalized_url)

                if dataref:
                    self.processed_datarefs.add(dataref)

                if limit is not None and len(urls_to_scan) >= limit:
                    break

                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=10000)
                    html = page.content()
                except Exception:
                    continue

                soup = BeautifulSoup(html, 'html.parser')
                for tag in soup.find_all('a', href=True):
                    link = urljoin(url, tag['href'])
                    should_exclude = any(pattern in link for pattern in self.exclude_patterns)
                    normalized_link = self.normalize_url(link)
                    if self.is_internal(url, link) and normalized_link not in self.visited and not should_exclude:
                        queue.append((link, depth + 1))

            browser.close()
        return urls_to_scan

    def scan_url(self, url):
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                page.goto(url, wait_until="networkidle")
                html = page.content()
                cookies = context.cookies()
                set_cookie_headers = page.evaluate("() => document.cookie")
                browser.close()
                print(f"[✓] Scanned: {url}")
        except Exception as e:
            print(f"[!] Error visiting {url}: {e}")
            return None

        soup = BeautifulSoup(html, 'html.parser')
        if self.scrape_pattern:
            return self.scrape_mode(url, soup)
        return self.parse(url, soup, cookies, set_cookie_headers)

    def is_internal(self, base_url, test_url):
        base_domain = urlparse(base_url).netloc
        test_domain = urlparse(test_url).netloc
        return base_domain == test_domain

    def scrape_mode(self, page_url, soup):
        matches = []
        for tag in soup.find_all(['a', 'link', 'script', 'iframe']):
            for attr in ['href', 'src']:
                value = tag.get(attr)
                if value and fnmatch.fnmatch(value, self.scrape_pattern):
                    matches.append(value)
        return {'url': page_url, 'matches': list(set(matches))}

    def parse(self, page_url, soup, cookies, set_cookie_headers):
        scripts = [tag.get('src') for tag in soup.find_all('script') if tag.get('src')]
        iframes = [tag.get('src') for tag in soup.find_all('iframe') if tag.get('src')]
        links = [tag.get('href') for tag in soup.find_all('link') if tag.get('href')]
        all_sources = scripts + iframes + links

        findings = {
            'url': page_url,
            'facebook_plugins': [],
            'twitter_plugins': [],
            'linkedin_plugins': [],
            'instagram_plugins': [],
            'youtube_embeds': [],
            'tiktok_embeds': [],
            'analytics': [],
            'cookie_trackers': [],
            'suspicious_domains': [],
            'cookies': []
        }

        patterns = {
            'facebook_plugins': ['facebook.com/plugins', 'connect.facebook.net'],
            'twitter_plugins': ['platform.twitter.com', 'twitter.com/widgets.js'],
            'linkedin_plugins': ['platform.linkedin.com'],
            'instagram_plugins': ['instagram.com/embed', 'instagr.am'],
            'youtube_embeds': ['youtube.com/embed', 'youtu.be'],
            'tiktok_embeds': ['tiktok.com/embed'],
            'analytics': [
                'googletagmanager.com/gtag/js', 'google-analytics.com', 'gtag/js', 'analytics.js',
                'plausible.io/js', 'matomo.js', 'hotjar.com', 'mixpanel.com', 'segment.com',
                'amplitude.com'
            ],
            'cookie_trackers': [
                'connect.facebook.net/en_US/fbevents.js', 'facebook.com/tr',
                'googleads.g.doubleclick.net/pagead', 'googletagmanager.com/gtag/js',
                'bat.bing.com/bat.js', 'snap.licdn.com/li.lms-analytics/insight.min.js',
                't.co/i/adsct', 'ads-twitter.com/uwt.js', 'cdn.taboola.com/libtrc/unip/',
                'analytics.tiktok.com/i18n/pixel'
            ]
        }

        cookie_name_patterns = [
            '_fbp', '_fbc', 'fr', 'ajs_user_id', 'ajs_anonymous_id', 'amplitude_id_',
            'optimizelyEndUserId', 'hubspotutk', 'intercom-id-', 'intercom-session-', 'pardot',
            'driftt_aid', 'tracking_id', 'visitor_id', '_ga', '_gid', '_gat', '__hstc', '__hssrc',
            '__cf_bm', '__cfruid', 'MXP_TRACKINGID'
        ]

        for src in all_sources:
            for key, subs in patterns.items():
                if any(sub in src for sub in subs):
                    findings[key].append(src)

        domain = urlparse(page_url).netloc
        findings['suspicious_domains'] = [
            src for src in all_sources
            if (
                src and
                urlparse(src).netloc and
                domain not in src and
                not any(src in v for k, v in findings.items() if k != 'suspicious_domains')
            )
        ]

        cookie_matches = []
        for c in cookies:
            for pattern in cookie_name_patterns:
                if pattern in c['name']:
                    cookie_matches.append(c['name'])

        if set_cookie_headers:
            for pattern in cookie_name_patterns:
                if pattern in set_cookie_headers:
                    cookie_matches.append(f"header:{pattern}")

        findings['cookies'] = list(set(cookie_matches))
        return findings


def export_to_csv(results, filename="scan_results.csv", filter_out=None):
    filter_out = filter_out or []

    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if 'matches' in results[0]:
            writer.writerow(['URL', 'Matches'])
            for item in results:
                writer.writerow([item['url'], '; '.join(item['matches'])])
        else:
            writer.writerow(['URL', 'Detected', 'Source', 'Cookies'])
            for item in results:
                detected = any(len(v) > 0 for k, v in item.items() if k not in ['url', 'cookies'])
                flat_sources = []
                for k, v in item.items():
                    if k not in ['url', 'cookies'] and v:
                        flat_sources.extend(v)
                flat_sources = [s for s in set(flat_sources) if all(f not in s for f in filter_out)]
                writer.writerow([
                    item['url'],
                    'Yes' if detected else 'No',
                    '; '.join(flat_sources),
                    '; '.join(item['cookies'])
                ])


def start_quit_listener(stop_event):
    def listen():
        print("[i] Press 'q' then Enter to stop crawling and begin scanning.")
        while not stop_event.is_set():
            if sys.stdin.readline().strip().lower() == 'q':
                print("[!] Crawl stopped by user. Proceeding to scan...")
                stop_event.set()
    thread = threading.Thread(target=listen, daemon=True)
    thread.start()


def main():
    parser = argparse.ArgumentParser(description="Scans website for embedded social media elements or custom patterns")
    parser.add_argument("-u", "--url", help="Starting url to scan")
    parser.add_argument("-d", type=int, help="Scan depth", default=2)
    parser.add_argument("-e", "--exclude", nargs='*', default=[], help="Exclude substrings")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Number of workers")
    parser.add_argument("-o", "--output", help="CSV output file", default="scan_results.csv")
    parser.add_argument("-s", "--scan-limit", type=int, help="Max pages to scan")
    parser.add_argument("-f", "--filter", nargs='*', default=[], help="Filter substrings from CSV")
    parser.add_argument("--save-json", help="Save raw scan results to JSON")
    parser.add_argument("--reexport", help="Re-export CSV from existing JSON results")
    parser.add_argument("--scrape", help="Pattern to scrape instead of full scan (e.g. '*.pdf')")

    args = parser.parse_args()

    if args.reexport:
        with open(args.reexport, "r", encoding="utf-8") as jf:
            results = json.load(jf)
        export_to_csv(results, args.output, args.filter)
        print(f"[+] Re-exported filtered results to: {args.output}")
        return

    if not args.url:
        print("[!] Error: --url is required when not re-exporting")
        return

    scanner = PageScanner(start_url=args.url, max_depth=args.d, delay=1.5,
                          exclude_patterns=args.exclude, workers=args.workers,
                          scrape_pattern=args.scrape)

    start_quit_listener(scanner.stop_event)

    results = []

    try:
        urls = scanner.crawl(limit=args.scan_limit)
        if scanner.stop_event.is_set() and not urls:
            urls = list(scanner.visited)
        print(f"[+] Scanning {len(urls)} URLs...")

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(scanner.scan_url, url) for url in urls]

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        print(f"[+] Got result for: {result['url']}")
                        results.append(result)
                    else:
                        print("[!] No result returned")
                except Exception as e:
                    print(f"[!] Error scanning URL: {e}")

    except KeyboardInterrupt:
        print("[!] Interrupted. Saving partial results...")
        scanner.stop_event.set()

    finally:
        if args.save_json:
            with open(args.save_json, "w", encoding="utf-8") as jf:
                json.dump(results, jf, indent=2)
            print(f"[+] Raw scan results saved to: {args.save_json}")
        export_to_csv(results, args.output, args.filter)
        print(f"[+] Filtered CSV saved to: {args.output}")


if __name__ == "__main__":
    main()
