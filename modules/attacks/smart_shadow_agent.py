# shadowfox/agents/smart_shadow_agent.py

import requests
import time
import random
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
from typing import Dict, List, Any, Optional, Tuple
import logging
from datetime import datetime
import hashlib
import base64

class SmartShadowAgent:
    """
    SmartShadowAgent - Pametni agent koji izvršava napade koristeći AI heuristiku
    da bira najbolje payload-e i prilagođava se odgovorima servera
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('SmartShadowAgent')
        self.session = requests.Session()
        
        # AI heuristika - bodovanje različitih indikatora uspešnosti
        self.success_indicators = {
            # XSS indicators
            "xss_success": [
                r"<script>alert\(",
                r"javascript:alert\(",
                r"onload=alert\(",
                r"onerror=alert\(",
                r"prompt\(\d+\)",
                r"confirm\(['\"]"
            ],
            # SQL injection indicators
            "sqli_success": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"valid MySQL result",
                r"MySQLSyntaxErrorException",
                r"PostgreSQL.*ERROR",
                r"ORA-\d+",
                r"Microsoft.*ODBC.*SQL",
                r"SQLite.*error",
                r"sqlite3.OperationalError"
            ],
            # Directory traversal indicators
            "lfi_success": [
                r"root:.*:0:0:",
                r"\[boot loader\]",
                r"<\?php",
                r"define\('DB_NAME'",
                r"<!-- wp-config"
            ],
            # SSRF indicators
            "ssrf_success": [
                r"Connection refused",
                r"Connection timed out",
                r"Name or service not known",
                r"Internal Server Error",
                r"HTTP/1\.[01] 200 OK"
            ],
            # Command injection indicators
            "rce_success": [
                r"uid=\d+.*gid=\d+",
                r"Microsoft Windows \[Version",
                r"Linux.*\d+\.\d+\.\d+",
                r"total \d+",
                r"drwx"
            ]
        }
        
        # Stealth konfiguracija
        self.stealth_config = {
            "delay_range": (1, 3),  # sekunde između zahteva
            "max_requests_per_minute": 30,
            "user_agents": [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
            ]
        }
        
        self.request_count = 0
        self.last_request_time = 0
        
    def execute_attack_campaign(self, target_url: str, attack_types: List[str], 
                              recon_data: Dict = None, max_payloads_per_type: int = 20) -> Dict:
        """
        Glavna funkcija - izvršava kampanju napada sa AI heuristikom
        """
        self.logger.info(f"Pokretanje pametne attack kampanje za {target_url}")
        
        campaign_results = {
            "target_url": target_url,
            "attack_types": attack_types,
            "timestamp": datetime.now().isoformat(),
            "total_requests": 0,
            "successful_attacks": [],
            "potential_vulns": [],
            "ai_analysis": {},
            "performance_metrics": {}
        }
        
        start_time = time.time()
        
        for attack_type in attack_types:
            self.logger.info(f"Izvršavam {attack_type} napade...")
            
            # Dobij payload-e iz baze
            payloads = self.operator.get_payloads_by_type(attack_type)
            
            if not payloads:
                self.logger.warning(f"Nema payload-a za tip {attack_type}")
                continue
            
            # AI selekcija najboljih payload-a
            selected_payloads = self._ai_select_payloads(payloads, recon_data, max_payloads_per_type)
            
            # Izvršavanje napada sa AI heuristikom
            attack_results = self._execute_smart_attack(target_url, attack_type, selected_payloads, recon_data)
            
            campaign_results["total_requests"] += attack_results["requests_made"]
            campaign_results["successful_attacks"].extend(attack_results["successful_payloads"])
            campaign_results["potential_vulns"].extend(attack_results["potential_vulns"])
            
            # AI analiza rezultata za ovaj tip napada
            campaign_results["ai_analysis"][attack_type] = self._ai_analyze_attack_results(attack_results)
            
            self.operator.log_agent_action("SmartShadowAgent", f"{attack_type}_attack_completed", {
                "payloads_tested": len(selected_payloads),
                "requests_made": attack_results["requests_made"],
                "successful_hits": len(attack_results["successful_payloads"])
            })
        
        # Performance metrics
        campaign_results["performance_metrics"] = {
            "total_time": time.time() - start_time,
            "requests_per_second": campaign_results["total_requests"] / (time.time() - start_time),
            "success_rate": len(campaign_results["successful_attacks"]) / max(campaign_results["total_requests"], 1)
        }
        
        self.logger.info(f"Kampanja završena. {len(campaign_results['successful_attacks'])} uspešnih napada od {campaign_results['total_requests']} zahteva")
        
        return campaign_results
    
    def _ai_select_payloads(self, payloads: List[Dict], recon_data: Dict, max_count: int) -> List[Dict]:
        """
        AI selekcija najrelevantnih payload-a na osnovu recon podataka
        """
        if not recon_data:
            # Bez recon podataka, uzmi najbolje po success_rate
            return sorted(payloads, key=lambda x: x.get('success_rate', 0), reverse=True)[:max_count]
        
        scored_payloads = []
        
        for payload in payloads:
            score = payload.get('success_rate', 0.5)  # bazni skor
            
            # Bonus poeni na osnovu tehnologija
            technologies = recon_data.get('technologies', {})
            payload_text = payload.get('payload', '').lower()
            
            # PHP specifični payloadi
            if 'PHP' in technologies and any(php_indicator in payload_text for php_indicator in ['php', '$_', 'eval(']):
                score += 0.3
                
            # WordPress specifični
            if 'WordPress' in technologies and any(wp_indicator in payload_text for wp_indicator in ['wp-', 'wordpress']):
                score += 0.2
                
            # SQL injection bonus ako ima database teknologije
            if any(db in technologies for db in ['MySQL', 'PostgreSQL', 'SQLite']) and 'union' in payload_text:
                score += 0.25
                
            # XSS bonus ako nema CSP
            missing_headers = recon_data.get('headers', {}).get('missing_security', [])
            if 'content-security-policy' in missing_headers and any(xss_indicator in payload_text for xss_indicator in ['<script', 'javascript:', 'alert(']):
                score += 0.2
            
            # Penalty za kompleksne payloade ako je target jednostavan
            if len(payload_text) > 200 and not any(tech in technologies for tech in ['Laravel', 'Django', 'ASP.NET']):
                score -= 0.1
            
            scored_payloads.append((payload, score))
        
        # Sortiraj po skoru i uzmi top N
        scored_payloads.sort(key=lambda x: x[1], reverse=True)
        return [payload for payload, score in scored_payloads[:max_count]]
    
    def _execute_smart_attack(self, target_url: str, attack_type: str, payloads: List[Dict], recon_data: Dict) -> Dict:
        """
        Pametno izvršavanje napada sa prilagođavanjem na osnovu odgovora
        """
        results = {
            "attack_type": attack_type,
            "requests_made": 0,
            "successful_payloads": [],
            "potential_vulns": [],
            "response_patterns": {},
            "ai_insights": []
        }
        
        # Određi attack vektore na osnovu recon podataka
        attack_vectors = self._identify_attack_vectors(target_url, attack_type, recon_data)
        
        for vector in attack_vectors:
            self.logger.debug(f"Testiram vektor: {vector['type']} na {vector['url']}")
            
            vector_success = False
            
            for payload_data in payloads:
                payload = payload_data['payload']
                
                # Prilagodi payload za specifični vektor
                adapted_payload = self._adapt_payload_for_vector(payload, vector, attack_type)
                
                # Izvršavanje zahteva sa stealth
                response_data = self._execute_stealth_request(vector['url'], adapted_payload, vector, attack_type)
                
                if not response_data:
                    continue
                
                results["requests_made"] += 1
                
                # AI analiza odgovora
                analysis = self._ai_analyze_response(response_data, attack_type, adapted_payload)
                
                if analysis['is_successful']:
                    success_entry = {
                        "payload": adapted_payload,
                        "original_payload": payload,
                        "vector": vector,
                        "response": response_data,
                        "analysis": analysis,
                        "confidence": analysis['confidence'],
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    results["successful_payloads"].append(success_entry)
                    
                    # Sačuvaj dokaz u bazu
                    proof_id = self.operator.store_proof(
                        payload=adapted_payload,
                        url=vector['url'],
                        payload_type=attack_type,
                        response_code=response_data['status_code'],
                        response_raw=json.dumps(response_data)
                    )
                    
                    self.logger.info(f"USPEŠAN NAPAD! {attack_type} payload na {vector['url'][:50]}... (Proof ID: {proof_id})")
                    vector_success = True
                    
                    # Ako je našao ranjivost, pokušaj sa sličnim payload-ima
                    if analysis['confidence'] > 0.8:
                        similar_results = self._exploit_similar_payloads(vector, attack_type, adapted_payload, payloads[payloads.index(payload_data)+1:])
                        results["successful_payloads"].extend(similar_results)
                        results["requests_made"] += len(similar_results)
                
                elif analysis['is_potential']:
                    results["potential_vulns"].append({
                        "payload": adapted_payload,
                        "vector": vector,
                        "response": response_data,
                        "analysis": analysis,
                        "timestamp": datetime.now().isoformat()
                    })
                
                # Dodaj pattern u analizu odgovora
                status_code = response_data['status_code']
                if status_code not in results["response_patterns"]:
                    results["response_patterns"][status_code] = 0
                results["response_patterns"][status_code] += 1
                
                # Ako je vektor uspešan, ne testiramo ostale payloade za isti vektor (optimizacija)
                if vector_success and analysis['confidence'] > 0.9:
                    break
        
        return results
    
    def _identify_attack_vectors(self, target_url: str, attack_type: str, recon_data: Dict) -> List[Dict]:
        """
        Identifikuje moguće attack vektore na osnovu recon podataka
        """
        vectors = []
        
        if attack_type == "XSS":
            # URL parametri
            parsed = urlparse(target_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    vectors.append({
                        "type": "GET_param",
                        "url": target_url,
                        "param": param,
                        "method": "GET"
                    })
            
            # Forme iz recon podataka
            if recon_data and 'forms' in recon_data:
                for form in recon_data['forms']:
                    for input_field in form.get('inputs', []):
                        if input_field['type'] in ['text', 'search', 'email', 'url']:
                            vectors.append({
                                "type": "form_input",
                                "url": form['action'],
                                "param": input_field['name'],
                                "method": form['method'],
                                "form_data": form
                            })
        
        elif attack_type == "SQLi":
            # URL parametri sa potencijalnim ID-jima
            parsed = urlparse(target_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param, values in params.items():
                    if any(keyword in param.lower() for keyword in ['id', 'user', 'page', 'cat', 'item']):
                        vectors.append({
                            "type": "GET_param_sqli",
                            "url": target_url,
                            "param": param,
                            "method": "GET"
                        })
            
            # Login forme
            if recon_data and 'forms' in recon_data:
                for form in recon_data['forms']:
                    has_login_fields = any(
                        field['name'].lower() in ['username', 'email', 'user', 'login', 'password', 'pass']
                        for field in form.get('inputs', [])
                    )
                    if has_login_fields:
                        vectors.append({
                            "type": "login_form_sqli",
                            "url": form['action'],
                            "method": form['method'],
                            "form_data": form
                        })
        
        elif attack_type == "LFI":
            # File/path parametri
            parsed = urlparse(target_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    if any(keyword in param.lower() for keyword in ['file', 'path', 'page', 'include', 'doc']):
                        vectors.append({
                            "type": "GET_param_lfi",
                            "url": target_url,
                            "param": param,
                            "method": "GET"
                        })
        
        # Ako nema specifičnih vektora, dodaj osnovni
        if not vectors:
            vectors.append({
                "type": "basic",
                "url": target_url,
                "param": "test",
                "method": "GET"
            })
        
        return vectors
    
    def _adapt_payload_for_vector(self, payload: str, vector: Dict, attack_type: str) -> str:
        """
        Prilagođava payload za specifični vektor napada
        """
        adapted = payload
        
        # URL encoding za GET parametre
        if vector['type'] in ['GET_param', 'GET_param_sqli', 'GET_param_lfi']:
            adapted = payload.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E')
        
        # Double encoding za WAF bypass
        elif 'bypass' in payload.lower():
            adapted = payload.replace('<', '%253C').replace('>', '%253E').replace('script', 'scr%69pt')
        
        # Case variations
        if attack_type == "XSS" and random.random() < 0.3:
            adapted = self._randomize_case(adapted)
        
        return adapted
    
    def _execute_stealth_request(self, url: str, payload: str, vector: Dict, attack_type: str) -> Optional[Dict]:
        """
        Izvršava HTTP zahtev sa stealth tehnikama
        """
        # Rate limiting
        current_time = time.time()
        if self.request_count >= self.stealth_config["max_requests_per_minute"]:
            if current_time - self.last_request_time < 60:
                sleep_time = 60 - (current_time - self.last_request_time)
                time.sleep(sleep_time)
                self.request_count = 0
        
        # Random delay
        delay = random.uniform(*self.stealth_config["delay_range"])
        time.sleep(delay)
        
        # Random User-Agent
        self.session.headers.update({
            'User-Agent': random.choice(self.stealth_config["user_agents"])
        })
        
        try:
            if vector['method'] == 'GET':
                # GET zahtev sa payload-om u parametru
                parsed = urlparse(url)
                params = parse_qs(parsed.query) if parsed.query else {}
                params[vector['param']] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                response = self.session.get(test_url, timeout=10, allow_redirects=True)
                
            else:  # POST
                # POST zahtev sa payload-om u form data
                form_data = {}
                if 'form_data' in vector:
                    for input_field in vector['form_data'].get('inputs', []):
                        if input_field['name'] == vector['param']:
                            form_data[input_field['name']] = payload
                        else:
                            form_data[input_field['name']] = 'test'
                else:
                    form_data[vector['param']] = payload
                
                response = self.session.post(url, data=form_data, timeout=10, allow_redirects=True)
            
            self.request_count += 1
            self.last_request_time = current_time
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text,
                "url": response.url,
                "response_time": response.elapsed.total_seconds(),
                "payload_sent": payload
            }
            
        except Exception as e:
            self.logger.error(f"Greška u zahtev: {e}")
            return None
    
    def _ai_analyze_response(self, response_data: Dict, attack_type: str, payload: str) -> Dict:
        """
        AI analiza odgovora da odredi uspešnost napada
        """
        content = response_data.get('content', '').lower()
        status_code = response_data.get('status_code', 0)
        
        analysis = {
            "is_successful": False,
            "is_potential": False,
            "confidence": 0.0,
            "indicators": [],
            "reasoning": ""
        }
        
        # Proveri indikatore uspešnosti za specifični tip napada
        if attack_type in self.success_indicators:
            for pattern in self.success_indicators[attack_type]:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis["indicators"].append(pattern)
                    analysis["is_successful"] = True
                    analysis["confidence"] += 0.3
        
        # Specifični XSS testovi
        if attack_type == "XSS":
            payload_lower = payload.lower()
            if any(xss_test in payload_lower for xss_test in ['alert(', 'prompt(', 'confirm(']):
                if payload.lower() in content:
                    analysis["is_successful"] = True
                    analysis["confidence"] = 0.95
                    analysis["reasoning"] = "Payload reflected in response"
        
        # SQL injection testovi
        elif attack_type == "SQLi":
            if status_code == 500:
                analysis["is_potential"] = True
                analysis["confidence"] = 0.4
                analysis["reasoning"] = "Server error - possible SQL syntax error"
            
            if any(sql_error in content for sql_error in ['sql', 'mysql', 'syntax', 'database']):
                analysis["is_successful"] = True
                analysis["confidence"] = 0.8
                analysis["reasoning"] = "SQL error in response"
        
        # Directory traversal testovi
        elif attack_type == "LFI":
            if 'root:' in content or 'boot loader' in content:
                analysis["is_successful"] = True
                analysis["confidence"] = 0.95
                analysis["reasoning"] = "System file content detected"
        
        # Normalizuj confidence
        analysis["confidence"] = min(analysis["confidence"], 1.0)
        
        # Ako ima indikatore ali nije označen kao uspešan
        if analysis["indicators"] and not analysis["is_successful"]:
            analysis["is_potential"] = True
            analysis["confidence"] = max(analysis["confidence"], 0.3)
        
        return analysis
    
    def _exploit_similar_payloads(self, vector: Dict, attack_type: str, successful_payload: str, remaining_payloads: List[Dict]) -> List[Dict]:
        """
        Kada pronađe uspešan payload, testira slične da potvrdi ranjivost
        """
        similar_results = []
        
        # Testiraj samo prvih 5 sličnih payload-a
        for payload_data in remaining_payloads[:5]:
            payload = payload_data['payload']
            
            # Preskači ako je payload previše različit
            if self._calculate_payload_similarity(successful_payload, payload) < 0.3:
                continue
            
            adapted_payload = self._adapt_payload_for_vector(payload, vector, attack_type)
            response_data = self._execute_stealth_request(vector['url'], adapted_payload, vector, attack_type)
            
            if response_data:
                analysis = self._ai_analyze_response(response_data, attack_type, adapted_payload)
                
                if analysis['is_successful']:
                    similar_results.append({
                        "payload": adapted_payload,
                        "original_payload": payload,
                        "vector": vector,
                        "response": response_data,
                        "analysis": analysis,
                        "confidence": analysis['confidence'],
                        "timestamp": datetime.now().isoformat(),
                        "is_confirmation": True
                    })
        
        return similar_results
    
    def _calculate_payload_similarity(self, payload1: str, payload2: str) -> float:
        """
        Jednostavan algoritam za procenu sličnosti payload-a
        """
        # Jaccard similarity na osnovu karaktera
        set1 = set(payload1.lower())
        set2 = set(payload2.lower())
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0
    
    def _randomize_case(self, text: str) -> str:
        """
        Randomizuje velika/mala slova za WAF bypass
        """
        return ''.join(char.upper() if random.random() < 0.5 else char.lower() for char in text)
    
    def _ai_analyze_attack_results(self, attack_results: Dict) -> Dict:
        """
        AI analiza rezultata za ceo tip napada
        """
        total_requests = attack_results["requests_made"]
        successful_attacks = len(attack_results["successful_payloads"])
        potential_vulns = len(attack_results["potential_vulns"])
        
        analysis = {
            "success_rate": successful_attacks / max(total_requests, 1),
            "potential_rate": potential_vulns / max(total_requests, 1),
            "recommendation": "",
            "confidence_distribution": {},
            "most_effective_payloads": []
        }
        
        # Analiza distribucije confidence skorova
        if attack_results["successful_payloads"]:
            confidences = [attack["confidence"] for attack in attack_results["successful_payloads"]]
            analysis["confidence_distribution"] = {
                "high": len([c for c in confidences if c > 0.8]),
                "medium": len([c for c in confidences if 0.5 <= c <= 0.8]),
                "low": len([c for c in confidences if c < 0.5])
            }
            
            # Najboljи payload-i
            sorted_attacks = sorted(attack_results["successful_payloads"], key=lambda x: x["confidence"], reverse=True)
            analysis["most_effective_payloads"] = [
                {"payload": attack["payload"], "confidence": attack["confidence"]}
                for attack in sorted_attacks[:3]
            ]
        
        # Preporuke
        if analysis["success_rate"] > 0.1:
            analysis["recommendation"] = "CRITICAL: Multiple successful attacks detected. Immediate patching required."
        elif analysis["potential_rate"] > 0.2:
            analysis["recommendation"] = "WARNING: Multiple potential vulnerabilities. Further investigation needed."
        elif successful_attacks > 0:
            analysis["recommendation"] = "ALERT: At least one successful attack. Verify and patch vulnerability."
        else:
            analysis["recommendation"] = "INFO: No clear vulnerabilities detected, but continue monitoring."
        
        return analysis

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test setup
    op = ShadowFoxOperator()
    shadow = SmartShadowAgent(op)
    
    # Test napad
    mission_id = op.create_mission("https://httpbin.org/get?test=1", "Test smart attack")
    
    # Mock recon data
    recon_data = {
        "technologies": {"PHP": True},
        "headers": {"missing_security": ["content-security-policy"]},
        "forms": []
    }
    
    results = shadow.execute_attack_campaign(
        "https://httpbin.org/get?test=1", 
        ["XSS"], 
        recon_data,
        max_payloads_per_type=5
    )
    
    print(json.dumps(results, indent=2, default=str))
