import os
import re
import json
from bs4 import BeautifulSoup

class DOMXSSScanner:
    def __init__(self, target_url, payload_file=None):
        self.target_url = target_url
        self.payloads = self._load_payloads(payload_file)

    def _load_payloads(self, payload_file):
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return ['<script>alert(1)</script>', '" onmouseover=alert(1)', "'><img src=x onerror=alert(1)>", 'javascript:alert(1)']

    def scan_js(self, js_code):
        sources = ['document.location', 'document.referrer', 'window.location', 'window.location.href']
        sinks = ['innerHTML', 'outerHTML', 'document.write', 'eval']
        vulnerabilities = []

        for source in sources:
            for sink in sinks:
                pattern = re.compile(r'({})\s*=\s*({})'.format(source, sink))
                if pattern.search(js_code):
                    vulnerabilities.append({'source': source, 'sink': sink})
        return vulnerabilities

    def analyze_html(self):
        response = requests.get(self.target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        inline_scripts = soup.find_all('script')

        js_files = [script['src'] for script in scripts]
        inline_js = [script.string for script in inline_scripts if script.string]

        return js_files, inline_js

    def generate_report(self, vulnerabilities):
        report = {'vulnerabilities': vulnerabilities}
        with open('dom_xss_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        print("[+] Report generated: dom_xss_report.json")

    def run(self):
        js_files, inline_js = self.analyze_html()
        all_vulnerabilities = []

        for js_file in js_files:
            response = requests.get(js_file)
            vulnerabilities = self.scan_js(response.text)
            all_vulnerabilities.extend(vulnerabilities)

        for js_code in inline_js:
            vulnerabilities = self.scan_js(js_code)
            all_vulnerabilities.extend(vulnerabilities)

        if all_vulnerabilities:
            self.generate_report(all_vulnerabilities)
        else:
            print("[-] No DOM XSS vulnerabilities found.")

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    payload_file = input("Enter the path to custom payload file (optional): ") or None
    scanner = DOMXSSScanner(target_url, payload_file)
    scanner.run()
