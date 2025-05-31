# shadowfox/agents/pathfinder.py

import requests
import json
import re
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Dict, List, Any, Optional, Tuple
import concurrent.futures
from datetime import datetime
import logging
from dataclasses import dataclass
from collections import defaultdict
import xml.etree.ElementTree as ET

@dataclass
class AttackSurface:
    """Klasa koja predstavlja jednu attacke surface"""
    url: str
    surface_type: str  # form, parameter, endpoint, upload, etc.
    attack_vectors: List[str]  # SQLi, XSS, LFI, etc.
    priority: int  # 1-10 (10 = highest)
    parameters: Dict[str, str]
    forms: List[Dict]
    headers: Dict[str, str]
    method: str
    confidence: float  # 0.0-1.0
    reasoning: str

class AIPathfinder:
    """
    AI modul koji analizira response mapu i formira napadnu strategiju
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('AIPathfinder')
        self.session = requests.Session()
        
        # AI heuristike za prepoznavanje različitih tipova stranica
        self.page_patterns = {
            "login": {
                "keywords": ["login", "signin", "auth", "authenticate", "password", "username"],
                "form_fields": ["password", "user", "email", "login"],
                "attack_vectors": ["SQLi", "Brute Force", "Session Fixation"]
            },
            "upload": {
                "keywords": ["upload", "file", "attachment", "image", "document"],
                "form_fields": ["file", "upload", "attachment"],
                "attack_vectors": ["File Upload", "Path Traversal", "RCE"]
            },
            "search": {
                "keywords": ["search", "query", "find", "filter"],
                "form_fields": ["q", "search", "query", "term"],
                "attack_vectors": ["XSS", "SQLi", "LDAP Injection"]
            },
            "admin": {
                "keywords": ["admin", "administrator", "panel", "dashboard", "manage"],
                "form_fields": ["admin", "administrator"],
                "attack_vectors": ["Privilege Escalation", "IDOR", "Admin Bypass"]
            },
            "api": {
                "keywords": ["api", "rest", "json", "xml", "graphql"],
                "form_fields": [],
                "attack_vectors": ["API Abuse", "JSON Injection", "XXE"]
            },
            "contact": {
                "keywords": ["contact", "feedback", "message", "email"],
                "form_fields": ["name", "email", "message", "subject"],
                "attack_vectors": ["XSS", "Email Injection", "SMTP Injection"]
            },
            "profile": {
                "keywords": ["profile", "account", "user", "settings"],
                "form_fields": ["name", "email", "phone", "address"],
                "attack_vectors": ["IDOR", "XSS", "Profile Injection"]
            }
        }
        
        # Attack vector prioritization
        self.attack_priorities = {
            "SQLi": 10,
            "RCE": 10,
            "File Upload": 9,
            "XSS": 8,
            "IDOR": 8,
            "XXE": 7,
            "Path Traversal": 7,
            "CSRF": 6,
            "Session Fixation": 6,
            "Brute Force": 5,
            "Information Disclosure": 4
        }
    
    def analyze_site_map(self, target_url: str, mission_id: str = None) -> Dict[str, Any]:
        """
        Glavna funkcija - analizira ceo sajt i formira napadnu mapu
        """
        if mission_id:
            self.operator.current_mission_id = mission_id
            
        self.logger.info(f"AI Pathfinder započinje analizu za: {target_url}")
        
        analysis_result = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "discovered_urls": [],
            "attack_surfaces": [],
            "attack_strategy": {},
            "high_priority_targets": [],
            "payload_recommendations": {},
            "statistics": {}
        }
        
        try:
            # Korak 1: Otkrivanje svih URL-ova
            self.logger.info("Korak 1: Crawling i URL discovery")
            urls = self._discover_all_urls(target_url)
            analysis_result["discovered_urls"] = urls
            
            # Korak 2: Analiza svakog URL-a
            self.logger.info(f"Korak 2: Analiza {len(urls)} URL-ova")
            attack_surfaces = self._analyze_urls(urls)
            analysis_result["attack_surfaces"] = [self._surface_to_dict(surface) for surface in attack_surfaces]
            
            # Korak 3: AI strategija napada
            self.logger.info("Korak 3: Formiranje AI strategije")
            strategy = self._formulate_attack_strategy(attack_surfaces)
            analysis_result["attack_strategy"] = strategy
            
            # Korak 4: Prioritizovanje meta
            high_priority = self._prioritize_targets(attack_surfaces)
            analysis_result["high_priority_targets"] = [self._surface_to_dict(surface) for surface in high_priority]
            
            # Korak 5: Payload preporuke
            payload_recs = self._generate_payload_recommendations(attack_surfaces)
            analysis_result["payload_recommendations"] = payload_recs
            
            # Statistike
            analysis_result["statistics"] = self._generate_statistics(attack_surfaces)
            
            # Loguj rezultate
            self.operator.log_agent_action("AIPathfinder", "site_analysis_completed", {
                "total_urls": len(urls),
                "attack_surfaces": len(attack_surfaces),
                "high_priority": len(high_priority),
                "strategy_components": len(strategy)
            })
            
            self.logger.info(f"AI Pathfinder završen. Pronađeno {len(attack_surfaces)} attack surfaces")
            
        except Exception as e:
            self.logger.error(f"Greška u AI Pathfinder analizi: {e}")
            analysis_result["error"] = str(e)
        
        return analysis_result
    
    def _discover_all_urls(self, base_url: str, max_depth: int = 3) -> List[str]:
        """
        Otkriva sve URL-ove na sajtu (crawler + sitemap + robots.txt)
        """
        discovered_urls = set([base_url])
        
        # 1. Pokušaj sitemap.xml
        try:
            sitemap_urls = self._parse_sitemap(base_url)
            discovered_urls.update(sitemap_urls)
            self.logger.info(f"Sitemap: pronađeno {len(sitemap_urls)} URL-ova")
        except Exception as e:
            self.logger.debug(f"Sitemap greška: {e}")
        
        # 2. Pokušaj robots.txt
        try:
            robots_urls = self._parse_robots_txt(base_url)
            discovered_urls.update(robots_urls)
            self.logger.info(f"Robots.txt: pronađeno {len(robots_urls)} URL-ova")
        except Exception as e:
            self.logger.debug(f"Robots.txt greška: {e}")
        
        # 3. Crawler (ograničeno)
        try:
            crawled_urls = self._crawl_site(base_url, max_depth=max_depth, max_urls=50)
            discovered_urls.update(crawled_urls)
            self.logger.info(f"Crawler: pronađeno {len(crawled_urls)} URL-ova")
        except Exception as e:
            self.logger.debug(f"Crawler greška: {e}")
        
        return list(discovered_urls)[:100]  # Limit za performanse
    
    def _parse_sitemap(self, base_url: str) -> List[str]:
        """Parse sitemap.xml"""
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        response = self.session.get(sitemap_url, timeout=10)
        
        if response.status_code != 200:
            return []
        
        urls = []
        try:
            root = ET.fromstring(response.content)
            for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                loc = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                if loc is not None:
                    urls.append(loc.text)
        except:
            # Fallback - regex parsing
            urls = re.findall(r'<loc>(.*?)</loc>', response.text)
        
        return urls[:50]  # Limit
    
    def _parse_robots_txt(self, base_url: str) -> List[str]:
        """Parse robots.txt za dodatne URL-ove"""
        robots_url = urljoin(base_url, "/robots.txt")
        response = self.session.get(robots_url, timeout=10)
        
        if response.status_code != 200:
            return []
        
        urls = []
        for line in response.text.split('\n'):
            if line.strip().lower().startswith(('disallow:', 'allow:')):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full_url = urljoin(base_url, path)
                    urls.append(full_url)
        
        return urls
    
    def _crawl_site(self, start_url: str, max_depth: int = 2, max_urls: int = 30) -> List[str]:
        """
        Jednostavan crawler
        """
        discovered = set([start_url])
        to_crawl = [(start_url, 0)]
        base_domain = urlparse(start_url).netloc
        
        while to_crawl and len(discovered) < max_urls:
            url, depth = to_crawl.pop(0)
            
            if depth >= max_depth:
                continue
                
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    # Pronađi linkove
                    links = re.findall(r'href=["\']([^"\']*)["\']', response.text)
                    
                    for link in links:
                        if not link or link.startswith('#') or link.startswith('mailto:'):
                            continue
                            
                        absolute_url = urljoin(url, link)
                        parsed = urlparse(absolute_url)
                        
                        # Samo linkovi sa istog domena
                        if parsed.netloc == base_domain and absolute_url not in discovered:
                            discovered.add(absolute_url)
                            to_crawl.append((absolute_url, depth + 1))
                            
            except Exception as e:
                self.logger.debug(f"Crawler greška za {url}: {e}")
                continue
        
        return list(discovered)
    
    def _analyze_urls(self, urls: List[str]) -> List[AttackSurface]:
        """
        Analizira svaki URL i kreira AttackSurface objekte
        """
        attack_surfaces = []
        
        def analyze_single_url(url):
            return self._analyze_single_url(url)
        
        # Paralelno procesiranje
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(analyze_single_url, url) for url in urls]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    surfaces = future.result()
                    if surfaces:
                        attack_surfaces.extend(surfaces)
                except Exception as e:
                    self.logger.debug(f"Greška pri analizi URL-a: {e}")
        
        return attack_surfaces
    
    def _analyze_single_url(self, url: str) -> List[AttackSurface]:
        """
        Analizira jedan URL i vraća AttackSurface objekte
        """
        surfaces = []
        
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code not in [200, 301, 302]:
                return surfaces
            
            content = response.text.lower()
            parsed_url = urlparse(url)
            
            # 1. Analiza parametara u URL-u
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                surfaces.append(self._create_parameter_surface(url, params, response.headers))
            
            # 2. Analiza formi
            forms = self._extract_forms(content, url)
            for form in forms:
                surfaces.append(self._create_form_surface(url, form, content))
            
            # 3. Analiza tipa stranice
            page_type = self._classify_page_type(url, content)
            if page_type != "unknown":
                surfaces.append(self._create_page_surface(url, page_type, content, response.headers))
            
            # 4. Analiza JavaScript API poziva
            api_endpoints = self._extract_api_endpoints(content)
            for endpoint in api_endpoints:
                surfaces.append(self._create_api_surface(urljoin(url, endpoint)))
            
        except Exception as e:
            self.logger.debug(f"Greška pri analizi {url}: {e}")
        
        return surfaces
    
    def _create_parameter_surface(self, url: str, params: Dict, headers: Dict) -> AttackSurface:
        """Kreira attack surface za URL parametre"""
        attack_vectors = []
        confidence = 0.7
        
        # Heuristike za parametre
        for param_name in params.keys():
            param_lower = param_name.lower()
            if any(word in param_lower for word in ["id", "user", "page"]):
                attack_vectors.extend(["SQLi", "IDOR"])
            if any(word in param_lower for word in ["search", "query", "q"]):
                attack_vectors.extend(["XSS", "SQLi"])
            if any(word in param_lower for word in ["file", "path", "url"]):
                attack_vectors.extend(["Path Traversal", "LFI", "SSRF"])
        
        if not attack_vectors:
            attack_vectors = ["XSS", "SQLi"]  # Default
        
        priority = max([self.attack_priorities.get(av, 5) for av in attack_vectors])
        
        return AttackSurface(
            url=url,
            surface_type="parameter",
            attack_vectors=list(set(attack_vectors)),
            priority=priority,
            parameters={k: v[0] if v else "" for k, v in params.items()},
            forms=[],
            headers=dict(headers),
            method="GET",
            confidence=confidence,
            reasoning=f"URL parametri: {list(params.keys())}"
        )
    
    def _create_form_surface(self, url: str, form: Dict, content: str) -> AttackSurface:
        """Kreira attack surface za HTML forme"""
        attack_vectors = []
        confidence = 0.8
        
        # Analiza input polja
        for input_field in form.get("inputs", []):
            field_name = input_field.get("name", "").lower()
            field_type = input_field.get("type", "").lower()
            
            if field_type == "password" or "password" in field_name:
                attack_vectors.extend(["Brute Force", "SQLi"])
            elif field_type == "file":
                attack_vectors.extend(["File Upload", "Path Traversal"])
            elif "email" in field_name:
                attack_vectors.extend(["Email Injection", "XSS"])
            elif any(word in field_name for word in ["search", "query", "comment"]):
                attack_vectors.extend(["XSS", "SQLi"])
        
        # Analiza action URL-a
        action_url = form.get("action", "")
        if any(word in action_url.lower() for word in ["login", "auth"]):
            attack_vectors.extend(["SQLi", "Session Fixation"])
        elif any(word in action_url.lower() for word in ["upload", "file"]):
            attack_vectors.extend(["File Upload", "RCE"])
        
        if not attack_vectors:
            attack_vectors = ["XSS", "CSRF"]  # Default za forme
        
        priority = max([self.attack_priorities.get(av, 5) for av in attack_vectors])
        
        return AttackSurface(
            url=url,
            surface_type="form",
            attack_vectors=list(set(attack_vectors)),
            priority=priority,
            parameters={inp.get("name", ""): inp.get("type", "") for inp in form.get("inputs", [])},
            forms=[form],
            headers={},
            method=form.get("method", "POST"),
            confidence=confidence,
            reasoning=f"Forma sa {len(form.get('inputs', []))} polja"
        )
    
    def _create_page_surface(self, url: str, page_type: str, content: str, headers: Dict) -> AttackSurface:
        """Kreira attack surface za specifičan tip stranice"""
        pattern = self.page_patterns.get(page_type, {})
        attack_vectors = pattern.get("attack_vectors", ["XSS"])
        
        priority = max([self.attack_priorities.get(av, 5) for av in attack_vectors])
        
        return AttackSurface(
            url=url,
            surface_type=f"page_{page_type}",
            attack_vectors=attack_vectors,
            priority=priority,
            parameters={},
            forms=[],
            headers=dict(headers),
            method="GET",
            confidence=0.6,
            reasoning=f"Stranica tipa: {page_type}"
        )
    
    def _create_api_surface(self, url: str) -> AttackSurface:
        """Kreira attack surface za API endpoint"""
        return AttackSurface(
            url=url,
            surface_type="api",
            attack_vectors=["API Abuse", "JSON Injection", "XXE"],
            priority=7,
            parameters={},
            forms=[],
            headers={},
            method="POST",
            confidence=0.5,
            reasoning="Detektovan API endpoint"
        )
    
    def _extract_forms(self, content: str, base_url: str) -> List[Dict]:
        """Izvlači HTML forme iz sadržaja"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, content, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            # Action i method
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "POST"
            
            # Input polja
            inputs = []
            input_pattern = r'<input[^>]*>'
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
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "inputs": inputs
            })
        
        return forms
    
    def _classify_page_type(self, url: str, content: str) -> str:
        """Klasifikuje tip stranice na osnovu sadržaja i URL-a"""
        url_lower = url.lower()
        content_lower = content.lower()
        
        for page_type, pattern in self.page_patterns.items():
            # Proverava keywords u URL-u i sadržaju
            url_match = any(keyword in url_lower for keyword in pattern["keywords"])
            content_match = sum(1 for keyword in pattern["keywords"] if keyword in content_lower)
            
            if url_match or content_match >= 2:
                return page_type
        
        return "unknown"
    
    def _extract_api_endpoints(self, content: str) -> List[str]:
        """Izvlači API endpoints iz JavaScript koda"""
        api_patterns = [
            r'["\']([^"\']*(?:api|rest)[^"\']*)["\']',
            r'fetch\(["\']([^"\']*)["\']',
            r'\.get\(["\']([^"\']*)["\']',
            r'\.post\(["\']([^"\']*)["\']'
        ]
        
        endpoints = set()
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/') and len(match) > 1:
                    endpoints.add(match)
        
        return list(endpoints)[:10]  # Limit
    
    def _formulate_attack_strategy(self, attack_surfaces: List[AttackSurface]) -> Dict[str, Any]:
        """
        AI formira strategiju napada na osnovu attack surfaces
        """
        strategy = {
            "primary_targets": [],
            "attack_phases": [],
            "recommended_tools": [],
            "stealth_level": "medium",
            "estimated_time": "2-4 hours"
        }
        
        # Grupiši po tipovima napada
        attack_groups = defaultdict(list)
        for surface in attack_surfaces:
            for attack_vector in surface.attack_vectors:
                attack_groups[attack_vector].append(surface)
        
        # Prioritizuj napade
        sorted_attacks = sorted(attack_groups.items(), 
                              key=lambda x: max([s.priority for s in x[1]]), 
                              reverse=True)
        
        # Kreiraj faze napada
        phase_num = 1
        for attack_type, surfaces in sorted_attacks[:5]:  # Top 5 attack types
            high_priority_surfaces = [s for s in surfaces if s.priority >= 7]
            if high_priority_surfaces:
                strategy["attack_phases"].append({
                    "phase": phase_num,
                    "attack_type": attack_type,
                    "targets": len(high_priority_surfaces),
                    "estimated_success": min(0.9, len(high_priority_surfaces) * 0.1 + 0.3)
                })
                phase_num += 1
        
        # Primary targets
        strategy["primary_targets"] = sorted(
            [self._surface_to_dict(s) for s in attack_surfaces], 
            key=lambda x: x["priority"], 
            reverse=True
        )[:10]
        
        return strategy
    
    def _prioritize_targets(self, attack_surfaces: List[AttackSurface]) -> List[AttackSurface]:
        """Vraća high-priority attack surfaces"""
        return sorted([s for s in attack_surfaces if s.priority >= 7], 
                     key=lambda x: x.priority, reverse=True)[:15]
    
    def _generate_payload_recommendations(self, attack_surfaces: List[AttackSurface]) -> Dict[str, List[str]]:
        """Generiše preporuke za payload-e na osnovu attack surfaces"""
        recommendations = defaultdict(list)
        
        for surface in attack_surfaces:
            for attack_vector in surface.attack_vectors:
                if attack_vector == "SQLi":
                    recommendations[surface.url].extend([
                        "' OR '1'='1",
                        "'; DROP TABLE users; --",
                        "1' UNION SELECT NULL,NULL,NULL--"
                    ])
                elif attack_vector == "XSS":
                    recommendations[surface.url].extend([
                        "<script>alert('XSS')</script>",
                        "javascript:alert('XSS')",
                        "<img src=x onerror=alert('XSS')>"
                    ])
                elif attack_vector == "File Upload":
                    recommendations[surface.url].extend([
                        "shell.php",
                        "test.php%00.jpg",
                        "../../../etc/passwd"
                    ])
        
        return dict(recommendations)
    
    def _generate_statistics(self, attack_surfaces: List[AttackSurface]) -> Dict[str, Any]:
        """Generiše statistike analize"""
        total_surfaces = len(attack_surfaces)
        if total_surfaces == 0:
            return {}
        
        attack_vector_count = defaultdict(int)
        surface_type_count = defaultdict(int)
        priority_distribution = defaultdict(int)
        
        for surface in attack_surfaces:
            surface_type_count[surface.surface_type] += 1
            priority_distribution[surface.priority] += 1
            for av in surface.attack_vectors:
                attack_vector_count[av] += 1
        
        return {
            "total_attack_surfaces": total_surfaces,
            "high_priority_count": len([s for s in attack_surfaces if s.priority >= 8]),
            "attack_vector_distribution": dict(attack_vector_count),
            "surface_type_distribution": dict(surface_type_count),
            "average_priority": sum(s.priority for s in attack_surfaces) / total_surfaces,
            "confidence_score": sum(s.confidence for s in attack_surfaces) / total_surfaces
        }
    
    def _surface_to_dict(self, surface: AttackSurface) -> Dict:
        """Konvertuje AttackSurface u dictionary"""
        return {
            "url": surface.url,
            "surface_type": surface.surface_type,
            "attack_vectors": surface.attack_vectors,
            "priority": surface.priority,
            "parameters": surface.parameters,
            "forms": surface.forms,
            "method": surface.method,
            "confidence": surface.confidence,
            "reasoning": surface.reasoning
        }

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test
    op = ShadowFoxOperator()
    pathfinder = AIPathfinder(op)
    
    # Test analiza
    target = "https://httpbin.org"
    mission_id = op.create_mission(target, "Test AI Pathfinder")
    
    results = pathfinder.analyze_site_map(target, mission_id)
    print(json.dumps(results, indent=2, default=str))
