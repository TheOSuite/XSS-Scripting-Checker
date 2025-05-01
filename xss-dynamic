import requests
from bs4 import BeautifulSoup
import argparse
import logging
from urllib.parse import urljoin, urlparse
import html
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Default payloads
DEFAULT_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    ""><script>alert('XSS')</script>"
]

# Logger setup
def setup_logger(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')

# URL validation with scheme fallback
def validate_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url
        parsed = urlparse(url)
    return all([parsed.scheme, parsed.netloc])

# Load payloads
def load_payloads(file_path=None):
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            logging.warning(f"Error reading payload file: {e}")
    logging.info("Using default payloads.")
    return DEFAULT_PAYLOADS

# XSS Detection (forms and query parameters)
class XSSDetector:
    def __init__(self, url):
        self.url = url

    def extract_forms(self):
        try:
            soup = BeautifulSoup(requests.get(self.url).text, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            logging.warning(f"Error fetching forms: {e}")
            return []

    def get_form_details(self, form):
        details = {"action": form.get("action"), "method": form.get("method", "get").lower(), "fields": []}
        for tag in form.find_all(["input", "textarea"]):
            name = tag.get("name")
            type_ = tag.get("type", "text")
            if name:
                details["fields"].append({"name": name, "type": type_})
        return details

    def extract_params(self):
        parsed = urlparse(self.url)
        return dict(param.split("=") if "=" in param else (param, "") for param in parsed.query.split("&") if param)

# XSS Testing
class XSSTester:
    def __init__(self, url, payloads):
        self.url = url
        self.payloads = payloads

    def test_reflected_xss(self):
        results = []
        params = XSSDetector(self.url).extract_params()
        for payload in self.payloads:
            test_params = {k: payload for k in params}
            try:
                resp = requests.get(self.url, params=test_params, timeout=5)
                if payload in resp.text:
                    results.append({"url": resp.url, "payload": payload})
            except requests.RequestException as e:
                logging.debug(f"Request failed: {e}")
        return results

    def test_stored_xss(self):
        results = []
        detector = XSSDetector(self.url)
        forms = detector.extract_forms()
        for form in forms:
            details = detector.get_form_details(form)
            for payload in self.payloads:
                data = {field["name"]: payload for field in details["fields"]}
                url = urljoin(self.url, details["action"])
                try:
                    if details["method"] == "post":
                        requests.post(url, data=data, timeout=5)
                    else:
                        requests.get(url, params=data, timeout=5)
                    resp = requests.get(self.url, timeout=5)
                    if payload in resp.text:
                        results.append({"form": details, "field": list(data.keys())[0], "payload": payload})
                except requests.RequestException as e:
                    logging.debug(f"Form request failed: {e}")
        return results

# Report generation
def generate_reports(results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "report.json")
    html_path = os.path.join(output_dir, "report.html")

    with open(json_path, "w") as jf:
        json.dump(results, jf, indent=4)

    with open(html_path, "w") as hf:
        hf.write("<html><body><h1>XSS Scan Report</h1>")
        for kind, items in results.items():
            hf.write(f"<h2>{kind.upper()} XSS</h2>")
            if not items:
                hf.write("<p>None found</p>")
            else:
                for item in items:
                    if kind == "reflected":
                        hf.write(f"<p><b>URL:</b> {html.escape(item.get('url', ''))}<br>"
                                 f"<b>Payload:</b> {html.escape(item.get('payload', ''))}</p>")
                    else:
                        form = item.get('form', {})
                        hf.write(f"<p><b>Form action:</b> {html.escape(str(form.get('action', '')))}<br>"
                                 f"<b>Field:</b> {html.escape(str(item.get('field', '')))}<br>"
                                 f"<b>Payload:</b> {html.escape(str(item.get('payload', '')))}</p>")
        hf.write("</body></html>")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Simple XSS Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-p", "--payloads", help="Custom payload file")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    setup_logger(args.verbose)

    if not validate_url(args.url):
        logging.error("Invalid URL format.")
        return

    payloads = load_payloads(args.payloads)
    tester = XSSTester(args.url, payloads)
    results = {"reflected": [], "stored": []}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(tester.test_reflected_xss): "reflected",
            executor.submit(tester.test_stored_xss): "stored"
        }
        for f in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            result_type = futures[f]
            try:
                results[result_type].extend(f.result())
            except Exception as e:
                logging.error(f"Error during {result_type} scan: {e}")

    generate_reports(results, args.output)
    print("Scan complete. Reports saved to:", args.output)

if __name__ == "__main__":
    main()
