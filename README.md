# XSS Vulnerability Testing Suite

This package includes multiple scripts for detecting and analyzing various types of Cross-Site Scripting (XSS) vulnerabilities in web applications. It provides manual, automated, and DOM-based testing tools, along with detailed reporting features.

---

## 1. Basic XSS Testing Script (`xss_static.py`)

### Overview
An interactive script that tests a specified URL for **Stored** and **Reflected** XSS vulnerabilities using payloads from user-selected files in the `payloads/` directory.

### Features
- **Automatic Payload Selection:** Lists available payload files in `payloads/` for quick selection.
- **Stored & Reflected XSS Testing:** Tests both types concurrently.
- **Multithreading & Progress Bars:** Uses `concurrent.futures` and `tqdm` for efficiency and visual progress.
- **Logging & Summary:** Results are logged in `xss_test_results.log` and summarized after testing.

### Usage
- Prepare payload files in the `payloads/` folder.
- Run:
  ```bash
  python xss-static.py
  ```
- Follow prompts to input URLs, select payloads, set timeout, and proceed.

### Output
- Console updates with vulnerabilities detected.
- Log file: `xss_test_results.log`.
- Summary printed at the end.

---

## 2. Automated XSS Scanner (`xss-dynamic.py`)

### Overview
A comprehensive scanner that:
- Crawls the target URL to find forms, links, and URL parameters.
- Detects stored and reflected XSS by submitting payloads.
- Generates detailed HTML and JSON reports.

### Features
- Uses `BeautifulSoup` for HTML parsing.
- Finds input fields in forms for stored XSS testing.
- Supports custom payload lists via CLI.
- Produces detailed, navigable reports.

### Usage
```bash
python xss-dynamic.py --url http://targetsite.com --payload-file path/to/payloads.txt --output report.html --json results.json
```

### Example
```bash
python xss-dynamic.py --url http://testsite.com --payload-file payloads/xss_payloads.txt
```

### Output
- Console logs.
- HTML report (`report.html`).
- JSON report (`results.json`).

---

## 3. DOM-Based XSS Scanner (`xss-DOM.py`)

### Overview
Analyzes inline and external JavaScript for potential DOM-based XSS vulnerabilities by checking source-sink patterns.

### Features
- Loads custom payloads.
- Fetches and examines external scripts and inline JS.
- Checks for source-to-sink assignments indicating vulnerabilities.
- Generates a JSON report.

### Usage
```bash
python xss-DOM.py
```
Follow prompts to enter:
- Target URL.
- Optional custom payload file path.

### Example
```bash
python xss-DOM.py
# Follow prompts
Enter the target URL: http://testsite.com
Enter the path to custom payload file (optional): payloads/dom_payloads.txt
```

### Output
- `dom_xss_report.json` containing detected vulnerabilities.

---

## Setup & Requirements

- **Python 3.x**  
- Libraries to install:
  ```bash
  pip install requests tqdm beautifulsoup4
  ```

- Folder structure:
  ```
  xss-check/
  ├── README.md
  ├── payloads.txt
  ├── xss-static.py
  ├── xss_dynamic.py
  └── xss-DOM.py
  ```

---

## How to Use

### Manual Testing (`xss-static.py`)
1. Navigate to folder:
   ```bash
   cd path/to/xss-check
   ```
2. Run:
   ```bash
   python xss-static.py
   ```
3. Follow prompts:
   - Stored URL
   - Reflected URL
   - Select payload file
   - Set timeout
   - Confirm to start testing

Results appear live, and logs are saved in `xss_test_results.log`.

---

### Automated Scanner (`xss-dynamic.py`)
Execute with parameters:
```bash
python xss-dynamic.py --url http://yourtarget.com --payload-file payloads/your_payloads.txt
```

### DOM-based Scanner (`xss-DOM.py`)
Run:
```bash
python xss-DOM.py
```
Input target URL and optional payload file when prompted.

---

## Example Output Snippet

```plaintext
Welcome to the XSS Testing Script!

Enter the URL for Stored XSS testing (e.g., example.com/submit): http://example.com/submit
Enter the URL for Reflected XSS testing (e.g., example.com/search?q=): http://example.com/search?q=

Available Payload Files:
1. payload1.txt
2. payload2.txt

Select a payload file by number: 1

Enter the timeout value for requests (in seconds, e.g., 10): 10

Do you want to proceed with testing? (yes/no): yes

Testing Stored XSS:
[+] Stored XSS Vulnerability Found with Payload: <script>alert('XSS')</script>
[-] No Stored XSS Vulnerability Detected with Payload: <img src="x" onerror="alert(1)">
...

Testing Reflected XSS:
[+] Reflected XSS Vulnerability Found with Payload: <script>alert('XSS')</script>
[-] No Reflected XSS Vulnerability Detected with Payload: <img src="x" onerror="alert(1)">
...

--- Summary of XSS Testing ---
Total Payloads Tested: 10
Stored XSS Vulnerabilities Found: 1
Reflected XSS Vulnerabilities Found: 1
```

---

## Happy Testing!
