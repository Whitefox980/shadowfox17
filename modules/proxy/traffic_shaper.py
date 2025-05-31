# shadowfox/agents/traffic_shaper.py

import requests
import time
import random
import base64
import urllib.parse
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
import logging
from datetime import datetime
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class TrafficShaper:
    """
    TrafficShaper - Modifikuje saobraćaj za stealth operacije
    - Rotacija User-Agent stringova
    - Randomizovani delay-jevi
    - Encoding/obfuskacija payload-a
    - Proxy podrška
    - Rate limiting
    - Session management
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('TrafficShaper')
        
        # Thread-safe session pool
        self._session_pool = {}
        self._session_lock = threading.Lock()
        
        # Rate limiting
        self.last_request_time = {}
        self.request_counts = {}
        
        # Konfiguracija
        self.config = {
            "min_delay": 1.0,
            "max_delay": 3.0,
            "max_requests_per_minute": 30,
            "retry_attempts": 3,
            "timeout": 15,
            "follow_redirects": True,
            "verify_ssl": False  # Za penetration testing
        }
        
        # User-Agent rotacija
        self.user_agents = [
            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            
            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
            
            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            
            # Mobile
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
        ]
        
        # Accept headers kombinacije
        self.accept_headers = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'application/json, text/plain, */*',
            '*/*'
        ]
        
        # Accept-Language kombinacije
        self.accept_languages = [
            'en-US,en;q=0.9',
            'en-US,en;q=0.8',
            'en-GB,en-US;q=0.9,en;q=0.8',
            'en-US,en;q=0.5',
            'sr-RS,sr;q=0.9,en;q=0.8'  # Srpski za lokalne testove
        ]
        
        # Proxy lista (prazan za početak)
        self.proxies = []
        self.current_proxy_index = 0
    
    def get_session(self, session_id: str = "default") -> requests.Session:
        """
        Thread-safe session management
        """
        with self._session_lock:
            if session_id not in self._session_pool:
                session = requests.Session()
                
                # Retry strategija
                retry_strategy = Retry(
                    total=self.config["retry_attempts"],
                    backoff_factor=1,
                    status_forcelist=[429, 500, 502, 503, 504],
                )
                
                adapter = HTTPAdapter(max_retries=retry_strategy)
                session.mount("http://", adapter)
                session.mount("https://", adapter)
                
                # Osnovni headers
                session.headers.update(self._generate_random_headers())
                
                # SSL verifikacija
                session.verify = self.config["verify_ssl"]
                
                self._session_pool[session_id] = session
            
            return self._session_pool[session_id]
    
    def _generate_random_headers(self) -> Dict[str, str]:
        """
        Generiše randomizovane HTTP headers
        """
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': random.choice(self.accept_headers),
            'Accept-Language': random.choice(self.accept_languages),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': random.choice(['document', 'empty', 'script']),
            'Sec-Fetch-Mode': random.choice(['navigate', 'cors', 'no-cors']),
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
            'Cache-Control': random.choice(['no-cache', 'max-age=0', 'no-store'])
        }
    
    def _apply_rate_limiting(self, domain: str):
        """
        Primenjuje rate limiting po domenu
        """
        current_time = time.time()
        
        # Proveri poslednji zahtev za domen
        if domain in self.last_request_time:
            time_diff = current_time - self.last_request_time[domain]
            min_delay = self.config["min_delay"]
            
            if time_diff < min_delay:
                sleep_time = min_delay - time_diff + random.uniform(0, 1)
                self.logger.debug(f"Rate limiting: spavam {sleep_time:.2f}s za {domain}")
                time.sleep(sleep_time)
        
        # Brojanje zahteva po minutu
        minute_key = f"{domain}_{int(current_time // 60)}"
        self.request_counts[minute_key] = self.request_counts.get(minute_key, 0) + 1
        
        if self.request_counts[minute_key] > self.config["max_requests_per_minute"]:
            sleep_time = 60 - (current_time % 60) + random.uniform(1, 5)
            self.logger.warning(f"Rate limit dostignut za {domain}, spavam {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time[domain] = time.time()
    
    def _add_random_delay(self):
        """
        Dodaje randomizovani delay između zahteva
        """
        delay = random.uniform(self.config["min_delay"], self.config["max_delay"])
        time.sleep(delay)
    
    def _get_proxy(self) -> Optional[Dict[str, str]]:
        """
        Rotacija proxy servera
        """
        if not self.proxies:
            return None
            
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        
        return {
            'http': proxy,
            'https': proxy
        }
    
    def encode_payload(self, payload: str, encoding_type: str = "url") -> str:
        """
        Enkoduje payload u različitim formatima za obfuskaciju
        """
        encodings = {
            "url": urllib.parse.quote,
            "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: ''.join(f'%{ord(c):02x}' for c in x),
            "unicode": lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            "html": lambda x: ''.join(f'&#{ord(c)};' for c in x),
            "mixed_case": lambda x: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(x)),
            "null_byte": lambda x: x.replace(' ', '%00'),
            "tab_space": lambda x: x.replace(' ', '%09'),
            "newline": lambda x: x.replace(' ', '%0a')
        }
        
        if encoding_type == "random":
            encoding_type = random.choice(list(encodings.keys()))
        
        encoder = encodings.get(encoding_type, encodings["url"])
        encoded = encoder(payload)
        
        self.logger.debug(f"Encoded payload with {encoding_type}: {payload} -> {encoded}")
        return encoded
    
    def make_stealthy_request(self, method: str, url: str, 
                            payload: str = None, 
                            payload_location: str = "param",
                            param_name: str = "q",
                            encoding_type: str = "url",
                            session_id: str = "default",
                            additional_headers: Dict = None) -> requests.Response:
        """
        Pravi stealth HTTP zahtev sa svim modifikacijama
        
        Args:
            method: HTTP metod (GET, POST, PUT, etc.)
            url: Target URL
            payload: Payload za testiranje
            payload_location: Gde da stavi payload ("param", "header", "body", "cookie")
            param_name: Ime parametra za payload
            encoding_type: Tip enkodovanja payload-a
            session_id: ID session-a za reuse
            additional_headers: Dodatni headers
        """
        
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # Rate limiting
        self._apply_rate_limiting(domain)
        
        # Dobij session
        session = self.get_session(session_id)
        
        # Refresh headers za ovaj zahtev
        session.headers.update(self._generate_random_headers())
        
        # Dodaj custom headers
        if additional_headers:
            session.headers.update(additional_headers)
        
        # Proxy
        proxies = self._get_proxy()
        
        # Pripremi payload
        encoded_payload = self.encode_payload(payload, encoding_type) if payload else None
        
        # Pripremi zahtev na osnovu lokacije payload-a
        request_kwargs = {
            'timeout': self.config['timeout'],
            'allow_redirects': self.config['follow_redirects'],
            'proxies': proxies
        }
        
        if payload_location == "param" and encoded_payload:
            if method.upper() == "GET":
                # GET parametar
                separator = "&" if "?" in url else "?"
                url = f"{url}{separator}{param_name}={encoded_payload}"
            else:
                # POST data
                request_kwargs['data'] = {param_name: encoded_payload}
                
        elif payload_location == "header" and encoded_payload:
            session.headers[param_name] = encoded_payload
            
        elif payload_location == "body" and encoded_payload:
            request_kwargs['data'] = encoded_payload
            session.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            
        elif payload_location == "cookie" and encoded_payload:
            session.cookies.set(param_name, encoded_payload)
            
        elif payload_location == "json" and encoded_payload:
            request_kwargs['json'] = {param_name: encoded_payload}
            
        # Log zahteva
        self.operator.log_agent_action("TrafficShaper", "request_shaped", {
            "method": method,
            "url": url,
            "payload_location": payload_location,
            "encoding_type": encoding_type,
            "session_id": session_id,
            "proxy_used": bool(proxies)
        })
        
        try:
            # Pošalji zahtev
            response = session.request(method.upper(), url, **request_kwargs)
            
            # Log odgovora
            self.operator.log_agent_action("TrafficShaper", "response_received", {
                "status_code": response.status_code,
                "response_size": len(response.content),
                "response_time": response.elapsed.total_seconds()
            })
            
            # Random delay posle zahteva
            self._add_random_delay()
            
            return response
            
        except Exception as e:
            self.logger.error(f"Greška u stealth zahtevu: {e}")
            self.operator.log_agent_action("TrafficShaper", "request_failed", {
                "error": str(e),
                "url": url
            })
            raise
    
    def batch_requests(self, requests_data: List[Dict], 
                      max_concurrent: int = 3,
                      delay_between_batches: float = 5.0) -> List[requests.Response]:
        """
        Izvršava batch zahteve sa pametnim rate limiting-om
        
        Args:
            requests_data: Lista dict-ova sa podacima za zahteve
            max_concurrent: Maksimalno istovremenih zahteva
            delay_between_batches: Delay između batch-eva
        """
        import concurrent.futures
        
        responses = []
        
        # Podeli u batch-eve
        for i in range(0, len(requests_data), max_concurrent):
            batch = requests_data[i:i + max_concurrent]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                # Svaki zahtev dobija jedinstveni session_id
                futures = []
                for j, req_data in enumerate(batch):
                    req_data['session_id'] = f"batch_{i}_{j}"
                    future = executor.submit(self.make_stealthy_request, **req_data)
                    futures.append(future)
                
                # Skupi rezultate
                for future in concurrent.futures.as_completed(futures):
                    try:
                        response = future.result()
                        responses.append(response)
                    except Exception as e:
                        self.logger.error(f"Batch request failed: {e}")
                        responses.append(None)
            
            # Delay između batch-eva
            if i + max_concurrent < len(requests_data):
                self.logger.info(f"Batch {i//max_concurrent + 1} završen, spavam {delay_between_batches}s")
                time.sleep(delay_between_batches)
        
        return responses
    
    def add_proxy(self, proxy_url: str):
        """Dodaje proxy u rotaciju"""
        self.proxies.append(proxy_url)
        self.logger.info(f"Dodao proxy: {proxy_url}")
    
    def update_config(self, new_config: Dict):
        """Ažurira konfiguraciju"""
        self.config.update(new_config)
        self.logger.info("Konfiguracija ažurirana")
    
    def clear_sessions(self):
        """Briše sve session-e"""
        with self._session_lock:
            for session in self._session_pool.values():
                session.close()
            self._session_pool.clear()
        self.logger.info("Svi session-i obrisani")
    
    def get_stealth_stats(self) -> Dict:
        """Vraća statistike stealth operacija"""
        return {
            "active_sessions": len(self._session_pool),
            "proxies_configured": len(self.proxies),
            "rate_limits_tracked": len(self.last_request_time),
            "current_config": self.config.copy()
        }

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test setup
    op = ShadowFoxOperator()
    shaper = TrafficShaper(op)
    
    # Test različitih encoding-a
    test_payload = "<script>alert('XSS')</script>"
    
    encodings = ["url", "double_url", "base64", "hex", "html"]
    for enc in encodings:
        encoded = shaper.encode_payload(test_payload, enc)
        print(f"{enc}: {encoded}")
    
    # Test stealth zahteva (safe test)
    try:
        mission_id = op.create_mission("https://httpbin.org", "Test traffic shaping")
        response = shaper.make_stealthy_request(
            method="GET",
            url="https://httpbin.org/get",
            payload="test_payload",
            payload_location="param",
            param_name="test",
            encoding_type="url"
        )
        print(f"Response: {response.status_code}")
        print(f"Headers sent: {response.request.headers}")
        
    except Exception as e:
        print(f"Test greška: {e}")

