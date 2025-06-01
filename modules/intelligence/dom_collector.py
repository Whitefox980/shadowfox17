# shadowfox/utils/dom_collector.py

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import time
import os
from pathlib import Path
from datetime import datetime
import logging

class ImeKlase:
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('ImeKlase')

    def run(self):
        self.logger.info("✅ ImeKlase module started")
        # TODO: implement logic here
class DOMCollector:
    """
    Klasa za preuzimanje i čuvanje DOM-a stranica
    Podržava i statički HTML i dinamički JavaScript sadržaj
    """
    
    def __init__(self, operator, headless=True):
        self.operator = operator
        self.logger = logging.getLogger('DOMCollector')
        self.headless = headless
        self.session = requests.Session()
        
        # Setup User-Agent
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Chrome driver setup (za dinamički sadržaj)
        self.chrome_options = Options()
        if headless:
            self.chrome_options.add_argument('--headless')
        self.chrome_options.add_argument('--no-sandbox')
        self.chrome_options.add_argument('--disable-dev-shm-usage')
        self.chrome_options.add_argument('--disable-gpu')
        self.chrome_options.add_argument('--window-size=1920,1080')
        self.chrome_options.add_argument('--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
        
        self.driver = None
    
    def get_static_dom(self, url: str, save_path: str = None) -> dict:
        """
        Preuzima statički DOM (bez JavaScript izvršavanja)
        Brže za osnovne HTML stranice
        """
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Čuva HTML ako je potrebno
            if save_path:
                self._save_html_file(html_content, save_path)
            
            # Izvlači osnovne DOM informacije
            dom_info = self._extract_dom_info(soup, html_content)
            dom_info.update({
                'method': 'static',
                'url': url,
                'status_code': response.status_code,
                'content_length': len(html_content),
                'response_headers': dict(response.headers)
            })
            
            return dom_info
            
        except Exception as e:
            self.logger.error(f"Greška pri preuzimanju statičkog DOM-a: {e}")
            return {'error': str(e), 'method': 'static'}
    
    def get_dynamic_dom(self, url: str, save_path: str = None, wait_time: int = 3) -> dict:
        """
        Preuzima dinamički DOM (sa JavaScript izvršavanjem)
        Potrebno za SPA aplikacije i dinamički sadržaj
        """
        try:
            # Inicijalizuj driver ako nije
            if not self.driver:
                self.driver = webdriver.Chrome(options=self.chrome_options)
            
            # Učitaj stranicu
            self.driver.get(url)
            
            # Čekaj da se strana učita
            time.sleep(wait_time)
            
            # Čekaj na određene elemente ako je potrebno
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except:
                pass  # Ako ne uspe, nastavi dalje
            
            # Preuzmi konačni DOM
            html_content = self.driver.page_source
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Čuva HTML ako je potrebno
            if save_path:
                self._save_html_file(html_content, save_path)
            
            # Izvlači DOM informacije
            dom_info = self._extract_dom_info(soup, html_content)
            dom_info.update({
                'method': 'dynamic',
                'url': url,
                'final_url': self.driver.current_url,
                'title': self.driver.title,
                'content_length': len(html_content)
            })
            
            # Dodatne informacije dostupne kroz Selenium
            dom_info['cookies'] = self.driver.get_cookies()
            dom_info['local_storage'] = self._get_local_storage()
            dom_info['console_logs'] = self._get_console_logs()
            
            return dom_info
            
        except Exception as e:
            self.logger.error(f"Greška pri preuzimanju dinamičkog DOM-a: {e}")
            return {'error': str(e), 'method': 'dynamic'}
    
    def get_dom_after_payload(self, url: str, payload: str, method: str = 'GET', 
                             data: dict = None, save_path: str = None) -> dict:
        """
        Preuzima DOM nakon slanja payload-a
        Ovo je ključno za analizu da li je payload uspešan
        """
        try:
            if method.upper() == 'GET':
                # GET zahtev sa payload-om u URL-u
                if '?' in url:
                    test_url = f"{url}&{payload}"
                else:
                    test_url = f"{url}?{payload}"
                
                response = self.session.get(test_url, timeout=15)
                
            elif method.upper() == 'POST':
                # POST zahtev sa payload-om u data
                post_data = data.copy() if data else {}
                
                # Dodaj payload u postojeće podatke ili kreiraj nove
                if isinstance(payload, dict):
                    post_data.update(payload)
                else:
                    # Ako je payload string, pokušaj da ga parsiraš
                    post_data['payload'] = payload
                
                response = self.session.post(url, data=post_data, timeout=15)
            
            else:
                raise ValueError(f"Nepodržan HTTP method: {method}")
            
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Čuva HTML
            if save_path:
                self._save_html_file(html_content, save_path)
            
            # Izvlači DOM informacije
            dom_info = self._extract_dom_info(soup, html_content)
            dom_info.update({
                'method': 'payload_response',
                'url': url,
                'payload': payload,
                'http_method': method,
                'status_code': response.status_code,
                'content_length': len(html_content),
                'response_headers': dict(response.headers),
                'response_time': response.elapsed.total_seconds()
            })
            
            return dom_info
            
        except Exception as e:
            self.logger.error(f"Greška pri preuzimanju DOM-a nakon payload-a: {e}")
            return {'error': str(e), 'method': 'payload_response'}
    
    def _extract_dom_info(self, soup: BeautifulSoup, html_content: str) -> dict:
        """
        Izvlači korisne informacije iz DOM-a
        """
        try:
            # Osnovne informacije
            info = {
                'title': soup.title.string if soup.title else '',
                'html_length': len(html_content),
                'timestamp': datetime.now().isoformat()
            }
            
            # Forme
            forms = []
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_info['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                
                forms.append(form_info)
            
            info['forms'] = forms
            
            # Linkovi
            links = []
            for link in soup.find_all('a', href=True):
                links.append(link['href'])
            info['links'] = links[:50]  # Ograniči na 50 linkova
            
            # Script tagovi
            scripts = []
            for script in soup.find_all('script'):
                if script.get('src'):
                    scripts.append(script['src'])
                elif script.string:
                    scripts.append(script.string[:100])  # Prvi deo inline script-a
            info['scripts'] = scripts
            
            # Meta tagovi
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    meta_tags[name] = content
            info['meta_tags'] = meta_tags
            
            # Proveri da li postoje indikatori uspešnog payload-a
            info['potential_success_indicators'] = self._check_success_indicators(html_content, soup)
            
            return info
            
        except Exception as e:
            self.logger.error(f"Greška pri izvlačenju DOM informacija: {e}")
            return {'error': str(e)}
    
    def _check_success_indicators(self, html_content: str, soup: BeautifulSoup) -> list:
        """
        Proverava indikatore da li je payload možda uspešan
        """
        indicators = []
        html_lower = html_content.lower()
        
        # XSS indikatori
        xss_patterns = [
            '<script>alert(', '<script>prompt(', '<script>confirm(',
            'javascript:alert(', 'onerror=', 'onload=',
            '<img src=x onerror=', '<svg onload='
        ]
        
        for pattern in xss_patterns:
            if pattern in html_lower:
                indicators.append(f"Potential XSS: {pattern}")
        
        # SQL injection indikatori
        sql_patterns = [
            'mysql_fetch_array', 'ora-01756', 'microsoft jet database',
            'odbc drivers error', 'invalid query', 'sql syntax',
            'division by zero', 'quoted string not properly terminated'
        ]
        
        for pattern in sql_patterns:
            if pattern in html_lower:
                indicators.append(f"Potential SQLi: {pattern}")
        
        # Error stranice
        error_patterns = [
            'stack trace', 'exception', 'error in line',
            'fatal error', 'warning:', 'notice:'
        ]
        
        for pattern in error_patterns:
            if pattern in html_lower:
                indicators.append(f"Error disclosure: {pattern}")
        
        return indicators
    
    def _save_html_file(self, html_content: str, file_path: str):
        """
        Čuva HTML sadržaj u fajl
        """
        try:
            # Kreiraj direktorijum ako ne postoji
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.logger.info(f"HTML sačuvan u: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Greška pri čuvanju HTML fajla: {e}")
    
    def _get_local_storage(self) -> dict:
        """
        Čita localStorage iz browser-a (samo za dinamički DOM)
        """
        try:
            if self.driver:
                return self.driver.execute_script(
                    "return Object.assign({}, window.localStorage);"
                )
        except:
            pass
        return {}
    
    def _get_console_logs(self) -> list:
        """
        Čita console logove iz browser-a
        """
        try:
            if self.driver:
                logs = self.driver.get_log('browser')
                return [log['message'] for log in logs]
        except:
            pass
        return []
    
    def close_driver(self):
        """
        Zatvara Selenium driver
        """
        if self.driver:
            self.driver.quit()
            self.driver = None
    
    def __del__(self):
        """
        Automatski zatvara driver kad se objekat briše
        """
        self.close_driver()

# Pomoćna funkcija za lako korišćenje
def collect_dom_for_mission(operator, url: str, mission_id: str, payload: str = None, 
                           method: str = 'GET', use_dynamic: bool = False) -> str:
    """
    Glavna funkcija za preuzimanje DOM-a za misiju
    Vraća putanju do sačuvanog HTML fajla
    """
    collector = DOMCollector(operator)
    
    # Kreiraj putanju za čuvanje
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{mission_id}_{timestamp}"
    if payload:
        filename += "_with_payload"
    filename += ".html"
    
    html_path = operator.proofs_dir / filename
    
    try:
        if payload:
            # DOM nakon slanja payload-a
            dom_info = collector.get_dom_after_payload(url, payload, method, save_path=str(html_path))
        elif use_dynamic:
            # Dinamički DOM
            dom_info = collector.get_dynamic_dom(url, save_path=str(html_path))
        else:
            # Statički DOM
            dom_info = collector.get_static_dom(url, save_path=str(html_path))
        
        # Loguj u operator
        operator.log_agent_action("DOMCollector", "dom_collected", {
            "url": url,
            "method": dom_info.get('method', 'unknown'),
            "html_path": str(html_path),
            "success_indicators": dom_info.get('potential_success_indicators', [])
        })
        
        return str(html_path) if not dom_info.get('error') else None
        
    except Exception as e:
        logging.error(f"Greška pri preuzimanju DOM-a: {e}")
        return None
    finally:
        collector.close_driver()

# Test funkcionalnost
if __name__ == "__main__":
    from shadowfox.core.operator import ShadowFoxOperator
    
    # Test
    op = ShadowFoxOperator()
    mission_id = op.create_mission("https://httpbin.org/forms/post", "DOM test")
    
    # Test statički DOM
    html_path = collect_dom_for_mission(op, "https://httpbin.org/forms/post", mission_id)
    print(f"HTML sačuvan u: {html_path}")
    
    # Test DOM sa payload-om
    payload = "test_param=<script>alert('xss')</script>"
    html_path_payload = collect_dom_for_mission(
        op, "https://httpbin.org/post", mission_id, 
        payload=payload, method="POST"
    )
    print(f"HTML sa payload-om sačuvan u: {html_path_payload}")
