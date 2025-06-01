# shadowfox/agents/shadow_spider.py

import requests
import re
import json
import time
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from collections import deque, defaultdict
from typing import Dict, List, Set, Tuple, Any, Optional
import concurrent.futures
from dataclasses import dataclass, asdict
import logging
from pathlib import Path
import random
import asyncio
from datetime import datetime

@dataclass
class CrawlResult:
    """Struktura za jedan crawl rezultat"""
    url: str
    status_code: int
    title: str
    content_type: str
    content_length: int
    response_time: float
    parameters: Dict[str, List[str]]  # GET/POST parametri
    forms: List[Dict]
    links: List[str]
    js_files: List[str]
    interesting_strings: List[str]
    security_score: float  # 0-10, koliko je interesantno za testiranje
    vulnerability_hints: List[str]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    depth: int
    parent_url: str

class ShadowReconSpider:
    """
    Napredni AI-driven crawler koji mapira sajt i ocenjuje bezbednosne površine napada.
    Kombinuje brzinu Gospider-a sa inteligencijom AI analize.
    """
    
    def __init__(self, operator, max_depth: int = 3, max_urls: int = 500, threads: int = 10):
        self.operator = operator
        self.logger = logging.getLogger('ShadowReconSpider')
        
        # Crawler settings
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.threads = threads
        self.delay_range = (0.1, 0.5)  # Random delay između zahteva
        
        # State tracking
        self.visited_urls: Set[str] = set()
        self.url_queue: deque = deque()
        self.crawl_results: List[CrawlResult] = []
        self.domain_restrictions: Set[str] = set()
        
        # Session setup
        self.session = requests.Session()
        self.setup_session()
        
        # AI heuristike za scoring
        self.setup_ai_patterns()
    async def run(self):
         self.logger.info("🚀 ShadowReconAgent is running...")
         while True:
             task = await self.operator.brain.get_next_task("ReconAgent")
             if not task:
                 await asyncio.sleep(2)
                 continue

             self.logger.info(f"🎯 Obrađujem zadatak: {task.id}")
             spider = ShadowReconSpider(self.operator)
             try:
                 result = spider.crawl_target(task.target_url, task.mission_id)
                 self.logger.info(f"✅ Skeniranje završeno za {task.target_url}")
                # TODO: slanje rezultata nazad kroz event ili direktno
             except Exception as e:
                 self.logger.error(f"❌ Greška tokom skeniranja: {e}")

    def setup_session(self):
        """Postavlja HTTP session sa stealth parametrima"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        self.session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none'
        })
        
        self.session.timeout = 10
        self.session.allow_redirects = True
        self.session.max_redirects = 3
    
    def setup_ai_patterns(self):
        """Postavlja AI patterne za inteligentnu analizu"""
        
        # High-value endpoints (visok security score)
        self.high_value_patterns = [
            r'/admin', r'/administrator', r'/wp-admin', r'/panel',
            r'/login', r'/signin', r'/auth', r'/oauth',
            r'/api', r'/rest', r'/graphql', r'/v\d+',
            r'/upload', r'/file', r'/download', r'/backup',
            r'/config', r'/settings', r'/debug', r'/test',
            r'/user', r'/profile', r'/account', r'/dashboard',
            r'/search', r'/query', r'/sql', r'/db'
        ]
        
        # Interesting file extensions
        self.interesting_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
            '.json', '.xml', '.ajax', '.api',
            '.sql', '.db', '.backup', '.bak', '.old',
            '.config', '.conf', '.ini', '.env',
            '.log', '.txt', '.zip', '.tar', '.gz'
        ]
        
        # Vulnerability hint patterns
        self.vuln_patterns = {
            'sql_injection': [
                r'mysql_', r'SELECT\s+\*', r'WHERE\s+\w+\s*=', r'ORDER\s+BY',
                r'error.*sql', r'syntax.*error', r'mysql.*error'
            ],
            'xss': [
                r'<script', r'javascript:', r'onerror=', r'onload=',
                r'document\.write', r'innerHTML', r'eval\('
            ],
            'lfi': [
                r'include\s*\(', r'require\s*\(', r'file_get_contents',
                r'\.\./', r'/etc/passwd', r'/proc/version'
            ],
            'ssrf': [
                r'curl\s*\(', r'file_get_contents\s*\(', r'fsockopen',
                r'http://127\.0\.0\.1', r'localhost', r'internal'
            ],
            'info_disclosure': [
                r'debug\s*=\s*true', r'test\s*=\s*1', r'phpinfo\(',
                r'var_dump\(', r'print_r\(', r'error_reporting'
            ]
        }
        
        # Parameter names that suggest vulnerability
        self.interesting_params = [
            'id', 'user', 'page', 'file', 'path', 'url', 'redirect',
            'search', 'q', 'query', 'cmd', 'exec', 'eval',
            'include', 'require', 'lang', 'locale', 'debug'
        ]
    
    def crawl_target(self, target_url: str, mission_id: str = None) -> Dict[str, Any]:
        """
        Glavna crawl funkcija - mapira ceo sajt i vraća strukturirane rezultate
        """
        if mission_id:
            self.operator.current_mission_id = mission_id
        
        self.logger.info(f"🕷️ Pokretanje ShadowReconSpider za: {target_url}")
        
        # Reset state
        self.visited_urls.clear()
        self.url_queue.clear()
        self.crawl_results.clear()
        
        # Postavke domena
        parsed = urlparse(target_url)
        self.domain_restrictions.add(parsed.netloc)
        
        # Dodaj početni URL u queue
        self.url_queue.append((target_url, 0, ""))  # (url, depth, parent)
        
        start_time = time.time()
        
        try:
            # Multi-threaded crawling
            self._crawl_with_threads()
            
            # Post-processing i AI analiza
            crawl_summary = self._analyze_crawl_results()
            
            end_time = time.time()
            
            # Loguj rezultate
            self.operator.log_agent_action("ShadowReconSpider", "crawl_completed", {
                "target": target_url,
                "urls_found": len(self.crawl_results),
                "duration": end_time - start_time,
                "high_value_endpoints": len([r for r in self.crawl_results if r.security_score >= 7.0]),
                "forms_found": sum(len(r.forms) for r in self.crawl_results),
                "js_files_found": sum(len(r.js_files) for r in self.crawl_results)
            })
            
            self.logger.info(f"🎯 Crawl završen: {len(self.crawl_results)} URLs, {end_time - start_time:.2f}s")
            
            return crawl_summary
            
        except Exception as e:
            self.logger.error(f"Greška u crawling: {e}")
            return {"error": str(e), "partial_results": len(self.crawl_results)}
    
    def _crawl_with_threads(self):
        """Multi-threaded crawling sa rate limiting"""
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            while (self.url_queue or futures) and len(self.visited_urls) < self.max_urls:
                
                # Submit new tasks
                while (len(futures) < self.threads and 
                       self.url_queue and 
                       len(self.visited_urls) < self.max_urls):
                    
                    url, depth, parent = self.url_queue.popleft()
                    
                    if url in self.visited_urls or depth > self.max_depth:
                        continue
                    
                    if not self._is_url_in_scope(url):
                        continue
                    
                    self.visited_urls.add(url)
                    future = executor.submit(self._crawl_single_url, url, depth, parent)
                    futures[future] = url
                
                # Process completed tasks
                if futures:
                    done_futures = list(concurrent.futures.as_completed(futures, timeout=1))
                    
                    for future in done_futures:
                        url = futures.pop(future)
                        try:
                            result = future.result()
                            if result:
                                self.crawl_results.append(result)
                                # Dodaj nova URL-ova u queue
                                for link in result.links:
                                    if link not in self.visited_urls:
                                        self.url_queue.append((link, result.depth + 1, result.url))
                        except Exception as e:
                            self.logger.warning(f"Greška pri crawl {url}: {e}")
                
                # Rate limiting
                time.sleep(random.uniform(*self.delay_range))
    
    def _crawl_single_url(self, url: str, depth: int, parent_url: str) -> Optional[CrawlResult]:
        """Crawl jednog URL-a sa kompletnom analizom"""
        
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=10)
            response_time = time.time() - start_time
            
            # Osnovni podaci
            content = response.text
            content_type = response.headers.get('content-type', '').lower()
            
            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else ""
            
            # Extract links
            links = self._extract_links(content, url)
            
            # Extract forms
            forms = self._extract_forms(content, url)
            
            # Extract JS files
            js_files = self._extract_js_files(content, url)
            
            # Extract parameters
            parameters = self._extract_parameters(url, content, forms)
            
            # Find interesting strings
            interesting_strings = self._find_interesting_strings(content)
            
            # AI scoring
            security_score = self._calculate_security_score(url, content, parameters, forms)
            
            # Vulnerability hints
            vuln_hints = self._detect_vulnerability_hints(content, url)
            
            result = CrawlResult(
                url=url,
                status_code=response.status_code,
                title=title,
                content_type=content_type,
                content_length=len(content),
                response_time=response_time,
                parameters=parameters,
                forms=forms,
                links=links,
                js_files=js_files,
                interesting_strings=interesting_strings,
                security_score=security_score,
                vulnerability_hints=vuln_hints,
                headers=dict(response.headers),
                cookies=dict(response.cookies),
                depth=depth,
                parent_url=parent_url
            )
            
            self.logger.debug(f"📄 Crawled: {url} (score: {security_score:.1f})")
            return result
            
        except Exception as e:
            self.logger.warning(f"Failed to crawl {url}: {e}")
            return None
    
    def _extract_links(self, content: str, base_url: str) -> List[str]:
        """Extract sve linkove sa stranice"""
        links = set()
        
        # HTML links
        link_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'url\(["\']?([^"\')\s]+)["\']?\)'  # CSS url()
        ]
        
        for pattern in link_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                absolute_url = urljoin(base_url, match.strip())
                if self._is_valid_url(absolute_url):
                    links.add(absolute_url)
        
        # JavaScript links (basic extraction)
        js_url_patterns = [
            r'["\']([^"\']*\.[a-zA-Z]{2,4}(?:\?[^"\']*)?)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in js_url_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if '/' in match and not match.startswith('data:'):
                    absolute_url = urljoin(base_url, match)
                    if self._is_valid_url(absolute_url):
                        links.add(absolute_url)
        
        return list(links)
    
    def _extract_forms(self, content: str, base_url: str) -> List[Dict]:
        """Extract HTML forme sa detaljima"""
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, content, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract inputs
            inputs = []
            input_pattern = r'<(?:input|select|textarea)[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text",
                        "value": value_match.group(1) if value_match else ""
                    })
            
            forms.append({
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "inputs": inputs,
                "html_snippet": form_html[:200] + "..." if len(form_html) > 200 else form_html
            })
        
        return forms
    
    def _extract_js_files(self, content: str, base_url: str) -> List[str]:
        """Extract JavaScript fajlove"""
        js_files = set()
        
        # Script src
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        matches = re.findall(script_pattern, content, re.IGNORECASE)
        
        for match in matches:
            js_url = urljoin(base_url, match)
            if self._is_valid_url(js_url):
                js_files.add(js_url)
        
        return list(js_files)
    
    def _extract_parameters(self, url: str, content: str, forms: List[Dict]) -> Dict[str, List[str]]:
        """Extract parametere iz URL-a, formi i JS-a"""
        parameters = defaultdict(list)
        
        # URL parameters
        parsed = urlparse(url)
        if parsed.query:
            url_params = parse_qs(parsed.query)
            for key, values in url_params.items():
                parameters[key].extend(values)
        
        # Form parameters
        for form in forms:
            for input_field in form.get('inputs', []):
                param_name = input_field.get('name', '')
                if param_name:
                    parameters[param_name].append(input_field.get('value', ''))
        
        # JavaScript parameters (basic extraction)
        js_param_patterns = [
            r'["\'](\w+)["\']:\s*["\']?([^"\'},\s]+)',  # JSON-like
            r'\.(\w+)\s*=\s*["\']([^"\']+)["\']',        # Property assignment
            r'data\[\s*["\'](\w+)["\']',                  # data arrays
        ]
        
        for pattern in js_param_patterns:
            matches = re.findall(pattern, content)
            for key, value in matches:
                if key.lower() in self.interesting_params:
                    parameters[key].append(value)
        
        return dict(parameters)
    
    def _find_interesting_strings(self, content: str) -> List[str]:
        """Pronalazi interesantne stringove u kodu"""
        interesting = []
        
        patterns = [
            r'(?:password|passwd|pwd|secret|key|token|api)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?:mysql|postgresql|mongodb)://[^"\s]+',
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
            r'(?:http|ftp)s?://[^\s"\'<>]+',  # URLs
            r'/(?:etc|var|tmp|home)/[^\s"\'<>]+',  # File paths
            r'(?:admin|root|administrator)[:=][^"\s]+',
            r'(?:debug|test|dev)[:=\s]+(?:true|1|on)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    interesting.extend([m for m in match if m])
                else:
                    interesting.append(match)
        
        return list(set(interesting))[:10]  # Limit na 10
    
    def _calculate_security_score(self, url: str, content: str, parameters: Dict, forms: List[Dict]) -> float:
        """AI scoring algoritam za bezbednosnu važnost URL-a (0-10)"""
        score = 0.0
        
        # URL path scoring
        url_lower = url.lower()
        for pattern in self.high_value_patterns:
            if re.search(pattern, url_lower):
                score += 2.0
        
        # Extension scoring
        for ext in self.interesting_extensions:
            if url_lower.endswith(ext):
                score += 1.5
        
        # Parameter scoring
        for param_name in parameters.keys():
            if param_name.lower() in self.interesting_params:
                score += 1.0
        
        # Form scoring
        if forms:
            score += len(forms) * 1.5
            # Login forms are high value
            for form in forms:
                for input_field in form.get('inputs', []):
                    if input_field.get('type', '').lower() == 'password':
                        score += 3.0
        
        # Content analysis
        content_lower = content.lower()
        
        # Database errors, debug info
        if re.search(r'(?:mysql|sql|database).*error', content_lower):
            score += 2.5
        if re.search(r'debug|traceback|exception', content_lower):
            score += 1.5
        
        # Admin/sensitive content
        if re.search(r'admin|administrator|dashboard', content_lower):
            score += 2.0
        
        # Input fields count
        input_count = len(re.findall(r'<input', content, re.IGNORECASE))
        score += min(input_count * 0.3, 3.0)
        
        # Response code penalties
        if url.endswith(('.jpg', '.png', '.gif', '.css', '.ico')):
            score *= 0.1  # Static files su manje interesantni
        
        return min(score, 10.0)  # Cap na 10
    
    def _detect_vulnerability_hints(self, content: str, url: str) -> List[str]:
        """Detektuje hint-ove za ranjivosti u sadržaju"""
        hints = []
        
        for vuln_type, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    hints.append(f"{vuln_type.upper()}_HINT")
                    break  # Jedan hint po tipu je dovoljno
        
        return hints
    
    def _is_url_in_scope(self, url: str) -> bool:
        """Proverava da li je URL u scope-u crawlinga"""
        parsed = urlparse(url)
        return parsed.netloc in self.domain_restrictions
    
    def _is_valid_url(self, url: str) -> bool:
        """Osnovne validacije URL-a"""
        if not url or len(url) > 2000:
            return False
        
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Skip certain file types
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', 
                          '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.avi']
        
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        return True
    
    def _analyze_crawl_results(self) -> Dict[str, Any]:
        """Post-processing analiza svih crawl rezultata"""
        
        # Sortiranje po security score
        high_value = [r for r in self.crawl_results if r.security_score >= 7.0]
        medium_value = [r for r in self.crawl_results if 4.0 <= r.security_score < 7.0]
        
        # Statistike
        total_forms = sum(len(r.forms) for r in self.crawl_results)
        total_params = sum(len(r.parameters) for r in self.crawl_results)
        total_js = sum(len(r.js_files) for r in self.crawl_results)
        
        # Top endpoints za testiranje
        top_endpoints = sorted(self.crawl_results, key=lambda x: x.security_score, reverse=True)[:20]
        
        # Vulnerability hints summary
        all_hints = []
        for result in self.crawl_results:
            all_hints.extend(result.vulnerability_hints)
        hint_summary = {hint: all_hints.count(hint) for hint in set(all_hints)}
        
        # Entry points za payload testiranje
        entry_points = []
        for result in self.crawl_results:
            if result.forms or result.parameters:
                entry_points.append({
                    "url": result.url,
                    "method": "GET" if result.parameters else "POST",
                    "params": result.parameters,
                    "forms": len(result.forms),
                    "security_score": result.security_score
                })
        
        return {
            "summary": {
                "total_urls": len(self.crawl_results),
                "high_value_targets": len(high_value),
                "medium_value_targets": len(medium_value),
                "total_forms": total_forms,
                "total_parameters": total_params,
                "total_js_files": total_js,
                "unique_domains": len(self.domain_restrictions)
            },
            "top_endpoints": [asdict(ep) for ep in top_endpoints],
            "entry_points": entry_points,
            "vulnerability_hints": hint_summary,
            "crawl_results": [asdict(result) for result in self.crawl_results]
        }
    
    def get_priority_targets(self, min_score: float = 6.0) -> List[Dict]:
        """Vraća prioritetne mete za dalji testing"""
        priority_targets = []
        
        for result in self.crawl_results:
            if result.security_score >= min_score:
                priority_targets.append({
                    "url": result.url,
                    "score": result.security_score,
                    "params": result.parameters,
                    "forms": result.forms,
                    "vuln_hints": result.vulnerability_hints,
                    "reason": self._explain_score(result)
                })
        
        return sorted(priority_targets, key=lambda x: x['score'], reverse=True)
    
    def _explain_score(self, result: CrawlResult) -> str:
        """Objašnjava zašto je URL dobio određeni score"""
        reasons = []
        
        if any(pattern in result.url.lower() for pattern in ['/admin', '/login']):
            reasons.append("High-value endpoint")
        if result.forms:
            reasons.append(f"{len(result.forms)} forms found")
        if result.parameters:
            reasons.append(f"{len(result.parameters)} parameters")
        if result.vulnerability_hints:
            reasons.append(f"Vulnerability hints: {', '.join(result.vulnerability_hints)}")
        
        return "; ".join(reasons) if reasons else "Standard scoring"

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test spider
    op = ShadowFoxOperator()
    spider = ShadowReconSpider(op, max_depth=2, max_urls=50)
    
    # Test na bezbednom sajtu
    target = "http://testphp.vulnweb.com"  # Poznati test sajt
    mission_id = op.create_mission(target, "Spider test misija")
    
    results = spider.crawl_target(target, mission_id)
    
    print("🕷️ Spider Results Summary:")
    print(f"Total URLs: {results['summary']['total_urls']}")
    print(f"High-value targets: {results['summary']['high_value_targets']}")
    print(f"Forms found: {results['summary']['total_forms']}")
    
    priority = spider.get_priority_targets(5.0)
    print(f"\n🎯 Top Priority Targets ({len(priority)}):")
    for target in priority[:5]:
        print(f"  {target['score']:.1f} - {target['url']} ({target['reason']})")
