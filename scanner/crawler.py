import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Set, Dict, Optional
import time
import logging
import concurrent.futures
from collections import defaultdict
from requests.exceptions import RequestException
import re
from datetime import datetime

class WebCrawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = 2,
        max_retries: int = 3,
        delay: float = 1.0,
        concurrent_requests: int = 3,
        timeout: int = 10,
        user_agent: Optional[str] = None
    ):
        """
        Initialize the WebCrawler with enhanced configuration options.
        
        Args:
            base_url: The base URL to start crawling from
            max_depth: Maximum depth to crawl
            max_retries: Maximum number of retry attempts for failed requests
            delay: Delay between requests in seconds
            concurrent_requests: Maximum number of concurrent requests
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
        """
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_retries = max_retries
        self.delay = delay
        self.concurrent_requests = concurrent_requests
        self.timeout = timeout
        
        self.visited: Set[str] = set()
        self.endpoints: List[str] = []
        self.errors: Dict[str, List[str]] = defaultdict(list)
        self.metadata: Dict[str, Dict] = {}
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Setup session with custom headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'CustomWebCrawler/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

    def is_valid_url(self, url: str) -> bool:
        """
        Enhanced URL validation with additional checks.
        """
        try:
            parsed = urlparse(url)
            base_domain = urlparse(self.base_url).netloc
            
            # Additional validation criteria
            return all([
                bool(parsed.netloc),
                bool(parsed.scheme),
                parsed.scheme in ['http', 'https'],
                parsed.netloc.endswith(base_domain),
                not any(ext in url.lower() for ext in ['.pdf', '.jpg', '.png', '.gif']),
                '#' not in url  # Avoid anchor links
            ])
        except Exception as e:
            self.logger.warning(f"URL validation error for {url}: {e}")
            return False

    def extract_page_metadata(self, soup: BeautifulSoup, url: str) -> Dict:
        """
        Extract metadata from the page.
        """
        return {
            'title': soup.title.string if soup.title else None,
            'meta_description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else None,
            'h1_tags': [h1.text.strip() for h1 in soup.find_all('h1')],
            'timestamp': datetime.now().isoformat()
        }

    def get_links(self, url: str) -> List[str]:
        """
        Enhanced link extraction with better error handling and metadata collection.
        """
        links = []
        retry_count = 0
        
        while retry_count < self.max_retries:
            try:
                time.sleep(self.delay)  # Rate limiting
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Store page metadata
                self.metadata[url] = self.extract_page_metadata(soup, url)
                
                # Extract links from various sources
                sources = {
                    'a': 'href',
                    'link': 'href',
                    'script': 'src',
                    'img': 'src',
                    'form': 'action'
                }
                
                for tag, attr in sources.items():
                    for element in soup.find_all(tag, {attr: True}):
                        link = element.get(attr, '').strip()
                        if link:
                            absolute_url = urljoin(url, link)
                            if self.is_valid_url(absolute_url):
                                links.append(absolute_url)
                
                # Extract URLs from JavaScript
                script_tags = soup.find_all('script')
                for script in script_tags:
                    if script.string:
                        urls = re.findall(r'["\'](https?://[^\s<>"\']+)["\']', script.string)
                        links.extend([url for url in urls if self.is_valid_url(url)])
                
                return list(set(links))  # Remove duplicates
                
            except RequestException as e:
                retry_count += 1
                self.logger.warning(f"Attempt {retry_count}/{self.max_retries} failed for {url}: {e}")
                if retry_count == self.max_retries:
                    self.errors[url].append(str(e))
                time.sleep(self.delay * retry_count)  # Exponential backoff
            
            except Exception as e:
                self.logger.error(f"Unexpected error processing {url}: {e}")
                self.errors[url].append(str(e))
                break
                
        return []

    def crawl_url(self, url: str, depth: int) -> None:
        """
        Crawl a single URL and its links up to the maximum depth.
        """
        if depth > self.max_depth or url in self.visited:
            return
            
        self.logger.info(f"Crawling: {url} (Depth: {depth})")
        self.visited.add(url)
        
        links = self.get_links(url)
        if links:
            self.endpoints.extend(links)
            
            # Process next level with concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrent_requests) as executor:
                futures = [
                    executor.submit(self.crawl_url, link, depth + 1)
                    for link in links
                ]
                concurrent.futures.wait(futures)

    def discover_endpoints(self) -> Dict:
        """
        Start crawling and return comprehensive results.
        """
        start_time = time.time()
        self.crawl_url(self.base_url, 0)
        end_time = time.time()
        
        # Prepare results
        results = {
            'endpoints': list(set(self.endpoints)),
            'total_urls': len(self.endpoints),
            'unique_urls': len(set(self.endpoints)),
            'execution_time': end_time - start_time,
            'errors': dict(self.errors),
            'metadata': self.metadata
        }
        
        return results

def validate_url(url: str) -> bool:
    """
    Validate URL format and accessibility.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def main():
    """
    Enhanced main function with better input handling and result presentation.
    """
    try:
        user_url = input("Enter the URL to start crawling: ").strip()
        
        if not validate_url(user_url):
            raise ValueError("Please enter a valid URL starting with http:// or https://")
            
        max_depth = input("Enter the maximum crawl depth (default is 2): ").strip()
        delay = input("Enter delay between requests in seconds (default is 1.0): ").strip()
        
        # Validate inputs
        max_depth = int(max_depth) if max_depth.isdigit() else 2
        delay = float(delay) if delay and float(delay) > 0 else 1.0
        
        # Initialize and run crawler
        crawler = WebCrawler(
            user_url,
            max_depth=max_depth,
            delay=delay,
            concurrent_requests=3
        )
        
        results = crawler.discover_endpoints()
        
        # Display results
        print("\n=== Crawling Results ===")
        print(f"Total URLs discovered: {results['total_urls']}")
        print(f"Unique URLs: {results['unique_urls']}")
        print(f"Execution time: {results['execution_time']:.2f} seconds")
        
        print("\nDiscovered endpoints:")
        for endpoint in results['endpoints']:
            print(f"  - {endpoint}")
            if endpoint in results['metadata']:
                meta = results['metadata'][endpoint]
                if meta['title']:
                    print(f"    Title: {meta['title']}")
        
        if results['errors']:
            print("\nErrors encountered:")
            for url, errors in results['errors'].items():
                print(f"  {url}:")
                for error in errors:
                    print(f"    - {error}")
                    
    except KeyboardInterrupt:
        print("\nCrawling interrupted by user")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()