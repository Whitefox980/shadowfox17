# shadowfox/ai/explainable_ai.py

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging
from urllib.parse import urlparse, parse_qs

class ExplainableAI:
    """
    Explainable AI modul koji objašnjava:
    1. ZAŠTO je određeni payload odabran
    2. KOJI deo aplikacije je potencijalno ranjiv
    3. KAKO payload eksploatiše ranjivost
    4. KOJI su indikatori uspešnosti
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('ExplainableAI')
        
        # Knowledge base za objašnjenja
        self.vulnerability_knowledge = self._build_knowledge_base()
        
    def _build_knowledge_base(self) -> Dict:
        """Gradi bazu znanja o ranjivostima i indikatorima"""
        return {
            "XSS": {
                "description": "Cross-Site Scripting omogućava izvršavanje JavaScript koda u browseru žrtve",
                "common_vectors": ["<script>", "javascript:", "onerror=", "onload=", "svg onload"],
                "indicators": {
                    "reflected": ["payload se pojavljuje u response-u bez enkodiranja"],
                    "stored": ["payload je sačuvan i izvršava se pri svakom učitavanju"],
                    "dom": ["payload manipuliše DOM bez server-side validacije"]
                },
                "detection_patterns": [
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"<img[^>]*onerror",
                    r"<svg[^>]*onload"
                ],
                "severity": "High",
                "impact": "Session hijacking, credential theft, defacement"
            },
            
            "SQLi": {
                "description": "SQL Injection omogućava manipulaciju SQL upita",
                "common_vectors": ["' OR 1=1--", "UNION SELECT", "'; DROP TABLE", "' AND SLEEP(5)--"],
                "indicators": {
                    "error_based": ["SQL error poruke u response-u"],
                    "blind": ["razlika u response vremenu ili sadržaju"],
                    "union": ["dodatni podaci iz drugih tabela"],
                    "boolean": ["true/false odgovori na logičke uslove"]
                },
                "detection_patterns": [
                    r"SQL syntax.*error",
                    r"mysql_fetch_array",
                    r"ORA-\d+",
                    r"Microsoft.*ODBC.*SQL",
                    r"PostgreSQL.*ERROR",
                    r"Warning.*mysql_"
                ],
                "severity": "Critical",
                "impact": "Data extraction, authentication bypass, data manipulation"
            },
            
            "LFI": {
                "description": "Local File Inclusion omogućava čitanje lokalnih fajlova",
                "common_vectors": ["../../../etc/passwd", "....//....//etc/passwd", "php://filter/"],
                "indicators": {
                    "direct": ["sadržaj sistema fajlova u response-u"],
                    "encoded": ["base64 enkodovani sadržaj fajlova"],
                    "wrapper": ["PHP wrapper protokoli"]
                },
                "detection_patterns": [
                    r"root:.*:/bin/",
                    r"\[boot loader\]",
                    r"<\?php",
                    r"BEGIN.*PRIVATE.*KEY"
                ],
                "severity": "High",
                "impact": "Source code disclosure, configuration file access"
            },
            
            "SSRF": {
                "description": "Server-Side Request Forgery primorava server da pravi zahteve",
                "common_vectors": ["http://localhost", "http://169.254.169.254", "file:///etc/passwd"],
                "indicators": {
                    "internal": ["pristup internim servisima"],
                    "metadata": ["cloud metadata endpoints"],
                    "port_scan": ["različiti response-ovi za različite portove"]
                },
                "detection_patterns": [
                    r"169\.254\.169\.254",
                    r"localhost",
                    r"127\.0\.0\.1",
                    r"metadata\.google",
                    r"instance-data"
                ],
                "severity": "High",
                "impact": "Internal network access, metadata disclosure"
            },
            
            "RCE": {
                "description": "Remote Code Execution omogućava izvršavanje komandi na serveru",
                "common_vectors": ["; whoami", "| id", "`uname -a`", "${IFS}"],
                "indicators": {
                    "command_output": ["output sistema komandi u response-u"],
                    "timing": ["kašnjenje koje odgovara sleep komandama"],
                    "error": ["shell error poruke"]
                },
                "detection_patterns": [
                    r"uid=\d+.*gid=\d+",
                    r"Linux.*GNU",
                    r"Windows.*Version",
                    r"Directory of [A-Z]:\\",
                    r"/bin/sh: .*: command not found"
                ],
                "severity": "Critical",
                "impact": "Full system compromise, data theft, backdoor installation"
            }
        }
    
    def explain_payload_selection(self, payload: str, payload_type: str, 
                                target_context: Dict, recon_data: Dict = None) -> Dict:
        """
        Objašnjava zašto je određeni payload odabran za dati kontekst
        """
        explanation = {
            "payload": payload,
            "payload_type": payload_type,
            "timestamp": datetime.now().isoformat(),
            "selection_reasoning": {},
            "vulnerability_context": {},
            "expected_behavior": {},
            "detection_strategy": {},
            "risk_assessment": {}
        }
        
        # Analiza zašto je payload odabran
        explanation["selection_reasoning"] = self._analyze_payload_selection(
            payload, payload_type, target_context, recon_data
        )
        
        # Kontekst ranjivosti
        explanation["vulnerability_context"] = self._explain_vulnerability_context(
            payload_type, target_context
        )
        
        # Očekivano ponašanje
        explanation["expected_behavior"] = self._predict_payload_behavior(
            payload, payload_type, target_context
        )
        
        # Strategija detekcije
        explanation["detection_strategy"] = self._explain_detection_strategy(
            payload, payload_type
        )
        
        # Procena rizika
        explanation["risk_assessment"] = self._assess_payload_risk(
            payload, payload_type, target_context
        )
        
        return explanation
    
    def _analyze_payload_selection(self, payload: str, payload_type: str, 
                                 target_context: Dict, recon_data: Dict = None) -> Dict:
        """Objašnjava logiku odabira payload-a"""
        reasoning = {
            "primary_factors": [],
            "contextual_factors": [],
            "technical_rationale": "",
            "confidence_score": 0.0
        }
        
        vuln_info = self.vulnerability_knowledge.get(payload_type, {})
        
        # Primarne faktore odabira
        if payload_type == "XSS":
            if "<script>" in payload:
                reasoning["primary_factors"].append(
                    "Osnovni <script> tag test - proverava da li aplikacija filtrira HTML tagove"
                )
            elif "onerror=" in payload:
                reasoning["primary_factors"].append(
                    "Event handler test - pokušava izvršavanje kroz HTML event handlere"
                )
            elif "javascript:" in payload:
                reasoning["primary_factors"].append(
                    "URL scheme test - testira izvršavanje kroz javascript: protokol"
                )
        
        elif payload_type == "SQLi":
            if "OR 1=1" in payload:
                reasoning["primary_factors"].append(
                    "Boolean logic test - testira da li aplikacija validira SQL logiku"
                )
            elif "UNION SELECT" in payload:
                reasoning["primary_factors"].append(
                    "Union injection test - pokušava ekstraktovanje podataka iz drugih tabela"
                )
            elif "SLEEP(" in payload or "WAITFOR" in payload:
                reasoning["primary_factors"].append(
                    "Time-based test - koristi kašnjenje za blind SQL injection detekciju"
                )
        
        # Kontekstualni faktori
        if target_context.get("input_type") == "search":
            reasoning["contextual_factors"].append(
                "Search parametar često koristi SQL LIKE operator - povećava verovatnoću SQLi"
            )
        
        if target_context.get("form_method") == "GET":
            reasoning["contextual_factors"].append(
                "GET parametri su vidljivi u URL-u - lakše za testiranje i eksploataciju"
            )
        
        if recon_data and "WordPress" in recon_data.get("technologies", {}):
            reasoning["contextual_factors"].append(
                "WordPress aplikacija - poznate ranjivosti u plugin-ima i temama"
            )
        
        # Tehnička argumentacija
        reasoning["technical_rationale"] = self._generate_technical_rationale(
            payload, payload_type, target_context
        )
        
        # Procena pouzdanosti
        reasoning["confidence_score"] = self._calculate_selection_confidence(
            payload, payload_type, target_context, recon_data
        )
        
        return reasoning
    
    def _explain_vulnerability_context(self, payload_type: str, target_context: Dict) -> Dict:
        """Objašnjava kontekst ranjivosti"""
        vuln_info = self.vulnerability_knowledge.get(payload_type, {})
        
        context = {
            "vulnerability_description": vuln_info.get("description", ""),
            "attack_surface": self._identify_attack_surface(target_context),
            "vulnerable_components": self._identify_vulnerable_components(payload_type, target_context),
            "exploitation_requirements": self._list_exploitation_requirements(payload_type),
            "common_scenarios": vuln_info.get("common_vectors", [])
        }
        
        return context
    
    def _predict_payload_behavior(self, payload: str, payload_type: str, target_context: Dict) -> Dict:
        """Predviđa ponašanje payload-a"""
        behavior = {
            "expected_outcomes": [],
            "success_indicators": [],
            "failure_indicators": [],
            "side_effects": []
        }
        
        vuln_info = self.vulnerability_knowledge.get(payload_type, {})
        
        if payload_type == "XSS":
            if "<script>alert(" in payload:
                behavior["expected_outcomes"].append("JavaScript alert dialog se prikazuje u browseru")
                behavior["success_indicators"].append("Alert popup se izvršava")
                behavior["failure_indicators"].append("Payload se prikazuje kao obični tekst")
            
        elif payload_type == "SQLi":
            if "SLEEP(" in payload:
                behavior["expected_outcomes"].append("Server response kašnji za specificirano vreme")
                behavior["success_indicators"].append("Response time > 5 sekundi")
                behavior["failure_indicators"].append("Normalno response vreme")
                behavior["side_effects"].append("Moguće povećanje server load-a")
                
        elif payload_type == "LFI":
            if "etc/passwd" in payload:
                behavior["expected_outcomes"].append("Sadržaj /etc/passwd fajla se prikazuje")
                behavior["success_indicators"].append("Lista user account-ova u response-u")
                behavior["failure_indicators"].append("Error poruka ili prazan response")
        
        return behavior
    
    def _explain_detection_strategy(self, payload: str, payload_type: str) -> Dict:
        """Objašnjava kako prepoznati uspešnost napada"""
        vuln_info = self.vulnerability_knowledge.get(payload_type, {})
        
        strategy = {
            "detection_methods": [],
            "response_patterns": vuln_info.get("detection_patterns", []),
            "timing_analysis": {},
            "content_analysis": {},
            "http_indicators": {}
        }
        
        # Metode detekcije
        if payload_type == "XSS":
            strategy["detection_methods"] = [
                "Proveri da li se payload izvršava kao JavaScript kod",
                "Analiza DOM-a za injektovane elemente",
                "Screenshot analiza za vizuelne promene"
            ]
            strategy["content_analysis"] = {
                "reflected_content": "Payload se pojavljuje u HTML response-u",
                "executed_code": "JavaScript kod se izvršava u browseru"
            }
            
        elif payload_type == "SQLi":
            strategy["detection_methods"] = [
                "Analiza SQL error poruka",
                "Timing analiza za blind injection",
                "Poređenje response-ova za različite payloade"
            ]
            strategy["timing_analysis"] = {
                "baseline_time": "Normalno response vreme",
                "injection_time": "Vreme sa SLEEP/WAITFOR payloadom",
                "threshold": "Razlika > 3 sekunde = potencijalni SQLi"
            }
        
        return strategy
    
    def _assess_payload_risk(self, payload: str, payload_type: str, target_context: Dict) -> Dict:
        """Procenjuje rizik od payload-a"""
        vuln_info = self.vulnerability_knowledge.get(payload_type, {})
        
        risk = {
            "severity_level": vuln_info.get("severity", "Medium"),
            "potential_impact": vuln_info.get("impact", "Unknown"),
            "likelihood": self._calculate_exploitation_likelihood(payload, target_context),
            "mitigation_difficulty": self._assess_mitigation_difficulty(payload_type),
            "detection_probability": self._assess_detection_probability(payload, payload_type)
        }
        
        return risk
    
    def explain_response_analysis(self, payload: str, payload_type: str, 
                                response_data: Dict, success_determination: bool) -> Dict:
        """
        Objašnjava kako je AI analizirao response i došao do zaključka
        """
        analysis = {
            "payload": payload,
            "payload_type": payload_type,
            "success_determined": success_determination,
            "analysis_process": {},
            "evidence_found": [],
            "evidence_against": [],
            "reasoning_chain": [],
            "confidence_factors": {}
        }
        
        # Proces analize
        analysis["analysis_process"] = self._explain_analysis_process(
            payload_type, response_data
        )
        
        # Dokazi ZA uspešnost
        analysis["evidence_found"] = self._identify_success_evidence(
            payload, payload_type, response_data
        )
        
        # Dokazi PROTIV uspešnosti
        analysis["evidence_against"] = self._identify_failure_evidence(
            payload, payload_type, response_data
        )
        
        # Lanac zaključivanja
        analysis["reasoning_chain"] = self._build_reasoning_chain(
            payload, payload_type, response_data, success_determination
        )
        
        # Faktori pouzdanosti
        analysis["confidence_factors"] = self._analyze_confidence_factors(
            payload, payload_type, response_data
        )
        
        return analysis
    
    def _build_reasoning_chain(self, payload: str, payload_type: str, 
                             response_data: Dict, success: bool) -> List[str]:
        """Gradi lanac logičkog zaključivanja"""
        chain = []
        
        response_code = response_data.get("status_code", 0)
        response_body = response_data.get("content", "")
        response_time = response_data.get("response_time", 0)
        
        # Korak 1: Analiza HTTP status koda
        if response_code == 200:
            chain.append("✓ HTTP 200 - Server je uspešno procesirao zahtev")
        elif response_code == 500:
            chain.append("⚠ HTTP 500 - Moguća greška uzrokovana payload-om")
        elif response_code >= 400:
            chain.append(f"✗ HTTP {response_code} - Client error, payload možda blokiran")
        
        # Korak 2: Analiza sadržaja
        vuln_info = self.vulnerability_knowledge.get(payload_type, {})
        patterns = vuln_info.get("detection_patterns", [])
        
        for pattern in patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                chain.append(f"✓ Pronađen indikator: '{pattern}' u response-u")
                break
        else:
            if patterns:
                chain.append("✗ Nisu pronađeni poznati indikatori ranjivosti")
        
        # Korak 3: Timing analiza
        if payload_type == "SQLi" and "SLEEP(" in payload:
            expected_delay = self._extract_sleep_time(payload)
            if response_time >= expected_delay * 0.8:  # 80% threshold
                chain.append(f"✓ Response time ({response_time:.2f}s) odgovara očekivanom kašnjenju")
            else:
                chain.append(f"✗ Response time ({response_time:.2f}s) premali za SLEEP payload")
        
        # Korak 4: Payload refleksija
        if payload in response_body:
            if payload_type == "XSS":
                chain.append("✓ XSS payload reflektovan u response-u - potencijalna ranjivost")
            else:
                chain.append("ℹ Payload reflektovan u response-u")
        
        # Korak 5: Finalni zaključak
        if success:
            chain.append("🎯 ZAKLJUČAK: Indikatori pokazuju uspešnu eksploataciju")
        else:
            chain.append("❌ ZAKLJUČAK: Nedovoljno dokaza za potvrdu ranjivosti")
        
        return chain
    
    def generate_human_readable_explanation(self, explanation_data: Dict) -> str:
        """
        Generiše objašnjenje čitljivo za ljudi
        """
        payload = explanation_data.get("payload", "")
        payload_type = explanation_data.get("payload_type", "")
        
        report = []
        report.append(f"🎯 ANALIZA PAYLOAD-A: {payload_type}")
        report.append(f"📝 Payload: {payload}")
        report.append("=" * 60)
        
        # Razlog odabira
        selection = explanation_data.get("selection_reasoning", {})
        if selection:
            report.append("\n🧠 ZAŠTO JE OVAJ PAYLOAD ODABRAN:")
            for factor in selection.get("primary_factors", []):
                report.append(f"  • {factor}")
            
            if selection.get("contextual_factors"):
                report.append("\n🎯 KONTEKSTUALNI FAKTORI:")
                for factor in selection.get("contextual_factors", []):
                    report.append(f"  • {factor}")
            
            if selection.get("technical_rationale"):
                report.append(f"\n🔧 TEHNIČKA ARGUMENTACIJA:")
                report.append(f"  {selection['technical_rationale']}")
        
        # Očekivano ponašanje
        behavior = explanation_data.get("expected_behavior", {})
        if behavior:
            report.append("\n📊 OČEKIVANO PONAŠANJE:")
            for outcome in behavior.get("expected_outcomes", []):
                report.append(f"  ✓ {outcome}")
            
            report.append("\n🔍 INDIKATORI USPEŠNOSTI:")
            for indicator in behavior.get("success_indicators", []):
                report.append(f"  ✓ {indicator}")
        
        # Strategija detekcije
        detection = explanation_data.get("detection_strategy", {})
        if detection:
            report.append("\n🕵️ KAKO PREPOZNATI USPEŠNOST:")
            for method in detection.get("detection_methods", []):
                report.append(f"  • {method}")
        
        # Procena rizika
        risk = explanation_data.get("risk_assessment", {})
        if risk:
            report.append("\n⚠️ PROCENA RIZIKA:")
            report.append(f"  • Nivo ozbiljnosti: {risk.get('severity_level', 'N/A')}")
            report.append(f"  • Potencijalni uticaj: {risk.get('potential_impact', 'N/A')}")
            report.append(f"  • Verovatnoća eksploatacije: {risk.get('likelihood', 'N/A')}")
        
        return "\n".join(report)
    
    # Helper metode
    def _generate_technical_rationale(self, payload: str, payload_type: str, target_context: Dict) -> str:
        """Generiše tehničku argumentaciju"""
        rationales = {
            "XSS": f"Payload '{payload}' testira client-side code execution kroz HTML injection",
            "SQLi": f"Payload '{payload}' manipuliše SQL logiku za test database interaction",
            "LFI": f"Payload '{payload}' pokušava file system traversal za pristup lokalnim fajlovima",
            "SSRF": f"Payload '{payload}' testira server-side URL fetching za pristup internim resursima",
            "RCE": f"Payload '{payload}' pokušava izvršavanje sistema komandi na serveru"
        }
        return rationales.get(payload_type, f"Payload testira {payload_type} ranjivost")
    
    def _calculate_selection_confidence(self, payload: str, payload_type: str, 
                                      target_context: Dict, recon_data: Dict) -> float:
        """Računa pouzdanost odabira payload-a"""
        confidence = 0.5  # Bazna vrednost
        
        # Povećaj na osnovu konteksta
        if target_context.get("input_type") in ["search", "query"]:
            confidence += 0.2
        
        if recon_data and payload_type in ["XSS", "SQLi"]:
            if any(tech in recon_data.get("technologies", {}) for tech in ["PHP", "WordPress", "MySQL"]):
                confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _identify_attack_surface(self, target_context: Dict) -> List[str]:
        """Identifikuje površinu napada"""
        surfaces = []
        if target_context.get("input_type") == "form":
            surfaces.append("HTML form input fields")
        if target_context.get("method") == "GET":
            surfaces.append("URL parameters")
        if target_context.get("content_type") == "application/json":
            surfaces.append("JSON API endpoints")
        return surfaces
    
    def _extract_sleep_time(self, payload: str) -> float:
        """Izvlači vreme spavanja iz SQL payload-a"""
        match = re.search(r'SLEEP\((\d+)\)', payload, re.IGNORECASE)
        if match:
            return float(match.group(1))
        match = re.search(r'WAITFOR DELAY.*(\d+)', payload, re.IGNORECASE)
        if match:
            return float(match.group(1))
        return 5.0  # Default
    
    # Ostale helper metode...
    def _identify_vulnerable_components(self, payload_type: str, target_context: Dict) -> List[str]:
        return ["Input validation", "Output encoding", "SQL query construction"]
    
    def _list_exploitation_requirements(self, payload_type: str) -> List[str]:
        return ["User input reflection", "Insufficient sanitization"]
    
    def _calculate_exploitation_likelihood(self, payload: str, target_context: Dict) -> str:
        return "Medium"
    
    def _assess_mitigation_difficulty(self, payload_type: str) -> str:
        return "Medium"
    
    def _assess_detection_probability(self, payload: str, payload_type: str) -> str:
        return "High"
    
    def _explain_analysis_process(self, payload_type: str, response_data: Dict) -> Dict:
        return {"steps": ["HTTP response analysis", "Pattern matching", "Timing analysis"]}
    
    def _identify_success_evidence(self, payload: str, payload_type: str, response_data: Dict) -> List[str]:
        evidence = []
        content = response_data.get("content", "")
        if payload in content:
            evidence.append(f"Payload '{payload}' reflektovan u response-u")
        return evidence
    
    def _identify_failure_evidence(self, payload: str, payload_type: str, response_data: Dict) -> List[str]:
        return []
    
    def _analyze_confidence_factors(self, payload: str, payload_type: str, response_data: Dict) -> Dict:
        return {"high_confidence": [], "low_confidence": []}

# Test explainable AI
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    op = ShadowFoxOperator()
    ai = ExplainableAI(op)
    
    # Test objašnjenja
    payload = "<script>alert('XSS')</script>"
    context = {"input_type": "search", "form_method": "GET"}
    
    explanation = ai.explain_payload_selection(payload, "XSS", context)
    readable_explanation = ai.generate_human_readable_explanation(explanation)
    
    print(readable_explanation)
