from scanner.crawler import WebCrawler
from scanner.injector import PayloadInjector
from scanner.analyzer import ResponseAnalyzer
from scanner.report import ReportGenerator
import argparse

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--output", default="report.html", help="Output report file")
    args = parser.parse_args()

    print(f"Starting scan for {args.url}...")

    # Step 1: Crawl the target website
    crawler = WebCrawler(args.url)
    endpoints = crawler.discover_endpoints()

    # Step 2: Inject payloads into endpoints
    injector = PayloadInjector(endpoints)
    test_results = injector.test_endpoints()

    # Step 3: Analyze the responses
    analyzer = ResponseAnalyzer(test_results)
    vulnerabilities = analyzer.find_vulnerabilities()

    # Step 4: Generate the report
    report = ReportGenerator(vulnerabilities, args.output)
    report.create_report()

    print(f"Scan completed. Report saved to {args.output}")

if __name__ == "__main__":
    main()
