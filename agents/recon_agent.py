# shadowfox/agents/recon_agent.py

import requests
import socket
import ssl
import subprocess
import json
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any, Optional
import concurrent.futures
from datetime import datetime
import logging

class ReconAgent:
    """
    ReconAgent - Prikuplja osnovne podatke o meti
    (portovi, tehnologije, headers, potencijalni entry points)
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('ReconAgent')
        self.session = requests.Session()
        
        # Common User-Agents za stealth
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        self.session.headers.update({
            'User-Agent': self.user_agents[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def analyze_target(self, target_url: str, mission_id: str = None) -> Dict[str, Any]:
        """
        Glavna funkcija za analizu mete - sve informacije odjednom
        """
        if mission_id:
            self.operator.current_mission_id = mission_id
            
        self.logger.info(f"Počinje recon analize za: {target_url}")
        
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc or parsed_url.path
        
        recon_data = {
            "target_url": target_url,
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "basic_info": {},
            "technologies": {},
            "headers": {},
            "ports": {},
            "endpoints": [],
            "forms": [],
            "cookies": {},
            "ssl_info": {},
            "potential_vulns": []
        }
        
        try:
            # Osnovni HTTP zahtev
            recon_data["basic_info"] = self._get_basic_info(target_url)
            
            # Analiza zaglavlja
            recon_data["headers"] = self._analyze_headers(target_url)
            
            # Tehnologije (Wappalyzer-style)
            recon_data["technologies"] = self._detect_technologies(target_url)
            
            # Port skeniranje (brže, samo osnovni portovi)
            recon_data["ports"] = self._scan_common_ports(domain)
            
            # Potencijalni endpoints
            recon_data["endpoints"] = self._discover_endpoints(target_url)
            
            # Forme za testiranje
            recon_data["forms"] = self._find_forms(target_url)
            
            # SSL informacije
            if parsed_url.scheme == 'https':
                recon_data["ssl_info"] = self._get_ssl_info(domain, parsed_url.port or 443)
            
            # Početna analiza potencijalnih ranjivosti
            recon_data["potential_vulns"] = self._identify_potential_vulns(recon_data)
            
            # Loguj u bazu
            self.operator.log_agent_action("ReconAgent", "recon_completed", {
                "target": target_url,
                "endpoints_found": len(recon_data["endpoints"]),
                "forms_found": len(recon_data["forms"]),
                "technologies": list(recon_data["technologies"].keys())
            })
            
            self.logger.info(f"Recon završen za {target_url}. Pronađeno {len(recon_data['endpoints'])} endpoints")
            
        except Exception as e:
            self.logger.error(f"Greška u recon analizi: {e}")
            recon_data["error"] = str(e)
        
        return recon_data
    
    def _get_basic_info(self, url: str) -> Dict:
        """Osnovne informacije o HTTP zahtevu"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            return {
                "status_code": response.status_code,
                "final_url": response.url,
                "redirects": len(response.history),
                "content_length": len(response.content),
                "content_type": response.headers.get('content-type', ''),
                "server": response.headers.get('server', ''),
                "response_time": response.elapsed.total_seconds()
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_headers(self, url: str) -> Dict:
        """Analiza HTTP zaglavlja"""
        try:
            response = self.session.get(url, timeout=10)
            headers = dict(response.headers)
            
            # Sigurnosna zaglavlja
            security_headers = {
                "x-frame-options": headers.get('x-frame-options'),
                "x-xss-protection": headers.get('x-xss-protection'),
                "x-content-type-options": headers.get('x-content-type-options'),
                "strict-transport-security": headers.get('strict-transport-security'),
                "content-security-policy": headers.get('content-security-policy'),
                "x-powered-by": headers.get('x-powered-by')
            }
            
            return {
                "all_headers": headers,
                "security_headers": security_headers,
                "missing_security": [k for k, v in security_headers.items() if not v]
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _detect_technologies(self, url: str) -> Dict:
        """Detektuje tehnologije (jednostavna Wappalyzer logika)"""
        tech_patterns = {
            "WordPress": [r"wp-content", r"wp-includes", r"/wp-admin"],
            "Drupal": [r"sites/default", r"drupal", r"modules/"],
            "Joomla": [r"joomla", r"administrator/", r"components/"],
            "PHP": [r"\.php", r"PHPSESSID"],
            "ASP.NET": [r"\.aspx", r"ASP.NET", r"__VIEWSTATE"],
            "JavaScript": [r"\.js", r"<script"],
            "jQuery": [r"jquery", r"jQuery"],
            "Bootstrap": [r"bootstrap", r"Bootstrap"],
            "Laravel": [r"laravel", r"laravel_session"],
            "Django": [r"django", r"csrftoken"],
            "Apache": [r"Apache/"],
            "Nginx": [r"nginx"],
            "IIS": [r"Microsoft-IIS"]
        }
        
        detected = {}
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content) or re.search(pattern, headers):
                        detected[tech] = True
                        break
            
            return detected
        except Exception as e:
            return {"error": str(e)}
    
    def _scan_common_ports(self, domain: str) -> Dict:
        """Brže skeniranje samo najčešćih portova"""
        common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_port, port) for port in common_ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return {"open_ports": sorted(open_ports), "scanned_ports": common_ports}
    
    def _discover_endpoints(self, base_url: str) -> List[str]:
        """Otkriva potencijalne endpoints"""
        common_paths = [
            "/admin", "/login", "/wp-admin", "/administrator",
            "/api", "/api/v1", "/rest", "/graphql",
            "/search", "/contact", "/upload", "/download",
            "/user", "/users", "/profile", "/account",
            "/config", "/settings", "/debug", "/test",
            "/.git", "/.env", "/robots.txt", "/sitemap.xml"
        ]
        
        found_endpoints = []
        
        def check_endpoint(path):
            try:
                url = urljoin(base_url, path)
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code not in [404, 403]:
                    return url
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_endpoint, path) for path in common_paths]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_endpoints.append(result)
        
        return found_endpoints
    
    def _find_forms(self, url: str) -> List[Dict]:
        """Pronalazi HTML forme na stranici"""
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Simple regex za forme (bez BeautifulSoup da bude lakše)
            form_pattern = r'<form[^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*>'
            
            forms = []
            for form_match in re.finditer(form_pattern, content, re.DOTALL | re.IGNORECASE):
                form_html = form_match.group(0)
                
                # Izvuci action i method
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                
                action = action_match.group(1) if action_match else ""
                method = method_match.group(1).upper() if method_match else "GET"
                
                # Pronađi input polja
                inputs = []
                for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                    input_html = input_match.group(0)
                    name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                    type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                    
                    if name_match:
                        inputs.append({
                            "name": name_match.group(1),
                            "type": type_match.group(1) if type_match else "text"
                        })
                
                forms.append({
                    "action": urljoin(url, action) if action else url,
                    "method": method,
                    "inputs": inputs,
                    "full_html": form_html[:200] + "..." if len(form_html) > 200 else form_html
                })
            
            return forms
        except Exception as e:
            self.logger.error(f"Greška pri pronalaženju formi: {e}")
            return []
    
    def _get_ssl_info(self, domain: str, port: int = 443) -> Dict:
        """Informacije o SSL sertifikatu"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def _identify_potential_vulns(self, recon_data: Dict) -> List[str]:
        """Identifikuje potencijalne ranjivosti na osnovu recon podataka"""
        potential_vulns = []
        
        # Nedostaju sigurnosna zaglavlja
        if "missing_security" in recon_data.get("headers", {}):
            missing = recon_data["headers"]["missing_security"]
            if "x-frame-options" in missing:
                potential_vulns.append("Clickjacking - Missing X-Frame-Options")
            if "content-security-policy" in missing:
                potential_vulns.append("XSS - Missing CSP")
            if "strict-transport-security" in missing:
                potential_vulns.append("MITM - Missing HSTS")
        
        # Poznate tehnologije sa čestim ranjivostima
        technologies = recon_data.get("technologies", {})
        if "WordPress" in technologies:
            potential_vulns.append("WordPress - Check for outdated plugins")
        if "Drupal" in technologies:
            potential_vulns.append("Drupal - Check for known CVEs")
        if recon_data.get("headers", {}).get("all_headers", {}).get("x-powered-by"):
            potential_vulns.append("Information Disclosure - X-Powered-By header")
        
        # Otvoreni portovi
        open_ports = recon_data.get("ports", {}).get("open_ports", [])
        if 22 in open_ports:
            potential_vulns.append("SSH - Brute force potential")
        if 3306 in open_ports:
            potential_vulns.append("MySQL - Direct access potential")
        
        # Sensitive endpoints
        endpoints = recon_data.get("endpoints", [])
        for endpoint in endpoints:
            if "/.git" in endpoint:
                potential_vulns.append("Git Exposure - Source code disclosure")
            if "/.env" in endpoint:
                potential_vulns.append("Environment file exposure")
            if "/admin" in endpoint:
                potential_vulns.append("Admin panel - Brute force potential")
        
        return potential_vulns

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Inicijalizuj operator i recon agent
    op = ShadowFoxOperator()
    recon = ReconAgent(op)
    
    # Test recon
    target = "https://httpbin.org"  # Safe test target
    mission_id = op.create_mission(target, "Test recon misija")
    
    results = recon.analyze_target(target, mission_id)
    print(json.dumps(results, indent=2, default=str))
