# WEB-APPLICATION-VULNERABILITY-SCANNER
***COMPANY***: CDETECH IT SOLUTION

***NAME***: Sobiya vhora

***INTERN ID***: CT08GRD

***DOMAIN***: Cyber Security & Ethical Hacking

***BATCH DURATION***: December 25th, 2024 to January 25th, 2025

***MENTOR NAME***: Neela Santhosh

***DESCRIPTION OF TASK-2***
# WEB-APPLICATION-VULNERABILITY-SCANNER
## Objective
This Python-based **Web Application Vulnerability Scanner** is designed to identify common security vulnerabilities in web applications. It automates the process of testing for **SQL Injection**, **Cross-Site Scripting (XSS)**, and checks for the presence of common **admin panels**. The tool is useful for cybersecurity professionals and penetration testers to quickly assess the security posture of web applications.

## Key Features
- **SQL Injection Detection**:
  - Tests query parameters, headers, and cookies for SQL injection vulnerabilities.
  - Example payloads:
    - `' OR '1'='1`
    - `'; DROP TABLE users; --`
    - `' UNION SELECT null, version(); --`

- **Cross-Site Scripting (XSS) Detection**:
  - Scans query parameters, headers, cookies, and dynamic content for XSS vulnerabilities.
  - Example payloads:
    - `<script>alert('XSS')</script>`
    - `<img src=x onerror=alert('XSS')>`

- **Admin Panel Detection**:
  - Searches for common admin panel endpoints such as:
    - `/admin`
    - `/administrator`
    - `/admin/login`
    - `/admin/dashboard`

- **File Metadata Injection**:
  - Tests for XSS vulnerabilities through uploaded file metadata.

- **Dynamic Content Injection**:
  - Checks if the application is vulnerable to dynamic content injection through query strings.

## Example Usage
```bash
$ python WEBAPP-SCANNER.py
Enter the target URL: https://example.com

[START] Scanning URL: https://example.com
[INFO] Testing query parameters for SQL Injection...
[VULNERABLE] SQL Injection in parameter 'id' with payload: ' OR '1'='1
[INFO] Testing headers for XSS...
[VULNERABLE] XSS in header 'Referer' with payload: <script>alert('XSS')</script>
[INFO] Testing admin panel endpoints...
[INFO] Admin panel not found at https://example.com/admin.
[SUMMARY] Scan completed.
[END] Thank you for using the scanner!
```

## Requirements
- Python 3.x
- Required libraries:
  - `requests`
  - `bs4` (BeautifulSoup)
  - `colorama`

Install the required libraries using:
```bash
pip install -r requirements.txt
```

## How to Run
1. Clone the repository:
   ```bash
   git clone https://github.com/SobiyMariyam/webapp-vulnerability-scanner.git
   cd webapp-vulnerability-scanner
   ```
2. Run the script:
   ```bash
   python WEBAPP-SCANNER.py
   ```

## How It Works
1. The user provides a target URL as input.
2. The scanner sequentially tests:
   - Query parameters
   - HTTP headers
   - Cookies
   - Common admin panel endpoints
   - File upload metadata
3. After testing, the tool summarizes the vulnerabilities found.

## Disclaimer
This tool is intended for educational purposes and authorized penetration testing only. Ensure you have proper permission before scanning any web application.

## Output Example
![Screenshot 2025-01-11 115926](https://github.com/user-attachments/assets/b74d6ee8-1171-49fd-af67-c4f11fa631aa)


