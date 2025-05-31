# shadowfox/agents/taktician_agent.py

import json
import random
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging
from collections import defaultdict

class TakticianAgent:
    """
    TakticianAgent - AI mozak koji pravi strategiju napada na osnovu recon podataka.
    Određuje redosled napada, prioritete, i koordinira sve ostale agente.
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('TakticianAgent')
        
        # Mapa prioriteta za različite tipove ranjivosti
        self.vuln_priorities = {
            "SQLi": {"priority": 9, "payloads_count": 15, "stealth_level": 3},
            "XSS": {"priority": 8, "payloads_count": 12, "stealth_level": 2},
            "LFI": {"priority": 7, "payloads_count": 10, "stealth_level": 4},
            "RFI": {"priority": 7, "payloads_count": 8, "stealth_level": 4},
            "SSRF": {"priority": 8, "payloads_count": 10, "stealth_level": 5},
            "XXE": {"priority": 6, "payloads_count": 8, "stealth_level": 4},
            "IDOR": {"priority": 6, "payloads_count": 5, "stealth_level": 2},
            "Command_Injection": {"priority": 9, "payloads_count": 12, "stealth_level": 5},
            "Path_Traversal": {"priority": 5, "payloads_count": 8, "stealth_level": 3},
            "JWT_Attack": {"priority": 7, "payloads_count": 6, "stealth_level": 3},
            "Clickjacking": {"priority": 3, "payloads_count": 3, "stealth_level": 1},
            "CSRF": {"priority": 5, "payloads_count": 5, "stealth_level": 2},
            "Information_Disclosure": {"priority": 4, "payloads_count": 8, "stealth_level": 1}
        }
        
        # Strategije za različite tipove aplikacija
        self.app_strategies = {
            "WordPress": ["SQLi", "XSS", "LFI", "Information_Disclosure"],
            "Drupal": ["SQLi", "XSS", "Command_Injection", "LFI"],
            "PHP": ["SQLi", "XSS", "LFI", "RFI", "Command_Injection"],
            "ASP.NET": ["SQLi", "XSS", "Path_Traversal", "XXE"],
            "Laravel": ["SQLi", "XSS", "IDOR", "CSRF"],
            "Django": ["SQLi", "XSS", "IDOR", "SSRF"],
            "API": ["IDOR", "JWT_Attack", "SSRF", "XXE"],
            "Admin_Panel": ["SQLi", "XSS", "Command_Injection", "CSRF"]
        }
        
        # Težište napada na osnovu formulara
        self.form_attack_mapping = {
            "login": ["SQLi", "XSS", "CSRF"],
            "search": ["SQLi", "XSS", "SSRF"],
            "contact": ["XSS", "CSRF", "Command_Injection"],
            "upload": ["LFI", "RFI", "Command_Injection", "XXE"],
            "comment": ["XSS", "CSRF", "SQLi"],
            "register": ["XSS", "SQLi", "CSRF"]
        }

    def create_attack_strategy(self, recon_data: Dict, mission_id: str) -> Dict[str, Any]:
        """
        Kreira kompletnu strategiju napada na osnovu recon podataka
        """
        self.operator.current_mission_id = mission_id
        
        self.logger.info(f"Kreiranje strategije napada za misiju {mission_id}")
        
        strategy = {
            "mission_id": mission_id,
            "target_info": {
                "url": recon_data.get("target_url"),
                "domain": recon_data.get("domain"),
                "technologies": recon_data.get("technologies", {}),
                "forms_count": len(recon_data.get("forms", [])),
                "endpoints_count": len(recon_data.get("endpoints", []))
            },
            "attack_phases": [],
            "payload_distribution": {},
            "stealth_settings": {},
            "success_metrics": {},
            "estimated_duration": 0,
            "risk_assessment": "medium"
        }
        
        # Analiziraj recon podatke
        attack_vectors = self._analyze_attack_vectors(recon_data)
        strategy["attack_phases"] = self._plan_attack_phases(attack_vectors, recon_data)
        strategy["payload_distribution"] = self._calculate_payload_distribution(attack_vectors)
        strategy["stealth_settings"] = self._determine_stealth_level(recon_data)
        strategy["success_metrics"] = self._define_success_metrics(attack_vectors)
        strategy["estimated_duration"] = self._estimate_duration(strategy["attack_phases"])
        strategy["risk_assessment"] = self._assess_risk_level(recon_data, attack_vectors)
        
        # Loguj strategiju
        self.operator.log_agent_action("TakticianAgent", "strategy_created", {
            "phases_count": len(strategy["attack_phases"]),
            "primary_vectors": list(attack_vectors.keys())[:3],
            "estimated_duration": strategy["estimated_duration"],
            "risk_level": strategy["risk_assessment"]
        })
        
        self.logger.info(f"Strategija kreirana: {len(strategy['attack_phases'])} faza, "
                        f"procenjeno vreme: {strategy['estimated_duration']} min")
        
        return strategy

    def _analyze_attack_vectors(self, recon_data: Dict) -> Dict[str, int]:
        """
        Analizira recon podatke i određuje najperspektivnije vektore napada
        """
        attack_vectors = defaultdict(int)
        
        # Na osnovu tehnologija
        technologies = recon_data.get("technologies", {})
        for tech in technologies:
            if tech in self.app_strategies:
                for attack_type in self.app_strategies[tech]:
                    attack_vectors[attack_type] += 3
        
        # Na osnovu potencijalnih ranjivosti iz recon-a
        potential_vulns = recon_data.get("potential_vulns", [])
        for vuln in potential_vulns:
            if "XSS" in vuln:
                attack_vectors["XSS"] += 4
            elif "SQL" in vuln:
                attack_vectors["SQLi"] += 4
            elif "Git" in vuln or "Environment" in vuln:
                attack_vectors["Information_Disclosure"] += 5
            elif "Admin" in vuln:
                attack_vectors["SQLi"] += 2
                attack_vectors["XSS"] += 2
        
        # Na osnovu formi
        forms = recon_data.get("forms", [])
        for form in forms:
            form_type = self._classify_form(form)
            if form_type in self.form_attack_mapping:
                for attack_type in self.form_attack_mapping[form_type]:
                    attack_vectors[attack_type] += 2
        
        # Na osnovu nedostajućih sigurnosnih zaglavlja
        missing_headers = recon_data.get("headers", {}).get("missing_security", [])
        if "x-frame-options" in missing_headers:
            attack_vectors["Clickjacking"] += 3
        if "content-security-policy" in missing_headers:
            attack_vectors["XSS"] += 2
        if "x-xss-protection" in missing_headers:
            attack_vectors["XSS"] += 1
        
        # Na osnovu endpoints-a
        endpoints = recon_data.get("endpoints", [])
        for endpoint in endpoints:
            if "/api" in endpoint:
                attack_vectors["IDOR"] += 2
                attack_vectors["JWT_Attack"] += 2
                attack_vectors["SSRF"] += 1
            if "/upload" in endpoint:
                attack_vectors["LFI"] += 3
                attack_vectors["RFI"] += 2
                attack_vectors["Command_Injection"] += 2
        
        # Sortiraj po prioritetu
        return dict(sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True))

    def _plan_attack_phases(self, attack_vectors: Dict[str, int], recon_data: Dict) -> List[Dict]:
        """
        Planira faze napada u optimalnom redosledu
        """
        phases = []
        
        # Faza 1: Informacijska - najstealthier napadi
        info_attacks = []
        for attack_type, score in attack_vectors.items():
            if self.vuln_priorities.get(attack_type, {}).get("stealth_level", 3) <= 2:
                info_attacks.append({
                    "attack_type": attack_type,
                    "score": score,
                    "payload_count": min(5, self.vuln_priorities.get(attack_type, {}).get("payloads_count", 5))
                })
        
        if info_attacks:
            phases.append({
                "phase_number": 1,
                "phase_name": "Information Gathering",
                "description": "Low-noise reconnaissance attacks",
                "attacks": sorted(info_attacks, key=lambda x: x["score"], reverse=True)[:3],
                "delay_between_requests": (2, 5),
                "concurrent_attacks": 1
            })
        
        # Faza 2: Eksploatacija - visoko-prioritetni napadi
        exploit_attacks = []
        for attack_type, score in list(attack_vectors.items())[:5]:  # Top 5
            if attack_type not in [a["attack_type"] for a in info_attacks]:
                priority = self.vuln_priorities.get(attack_type, {}).get("priority", 5)
                if priority >= 7:
                    exploit_attacks.append({
                        "attack_type": attack_type,
                        "score": score,
                        "payload_count": self.vuln_priorities.get(attack_type, {}).get("payloads_count", 10)
                    })
        
        if exploit_attacks:
            phases.append({
                "phase_number": 2,
                "phase_name": "High-Priority Exploitation",
                "description": "Critical vulnerability testing",
                "attacks": exploit_attacks,
                "delay_between_requests": (1, 3),
                "concurrent_attacks": 2
            })
        
        # Faza 3: Dublja eksploracija - ostali napadi
        deep_attacks = []
        for attack_type, score in attack_vectors.items():
            if attack_type not in [a["attack_type"] for phase in phases for a in phase["attacks"]]:
                deep_attacks.append({
                    "attack_type": attack_type,
                    "score": score,
                    "payload_count": self.vuln_priorities.get(attack_type, {}).get("payloads_count", 8)
                })
        
        if deep_attacks:
            phases.append({
                "phase_number": 3,
                "phase_name": "Deep Exploration",
                "description": "Comprehensive vulnerability assessment",
                "attacks": sorted(deep_attacks, key=lambda x: x["score"], reverse=True)[:4],
                "delay_between_requests": (3, 7),
                "concurrent_attacks": 1
            })
        
        return phases

    def _classify_form(self, form: Dict) -> str:
        """
        Klasifikuje tip forme na osnovu input polja i action-a
        """
        action = form.get("action", "").lower()
        inputs = [inp.get("name", "").lower() for inp in form.get("inputs", [])]
        input_types = [inp.get("type", "").lower() for inp in form.get("inputs", [])]
        
        # Login forma
        if any(field in inputs for field in ["username", "email", "login"]) and "password" in inputs:
            return "login"
        
        # Search forma
        if any(field in inputs for field in ["search", "query", "q", "keyword"]):
            return "search"
        
        # Upload forma
        if "file" in input_types or any(field in inputs for field in ["file", "upload", "attachment"]):
            return "upload"
        
        # Contact forma
        if any(field in inputs for field in ["message", "email", "contact", "subject"]):
            return "contact"
        
        # Comment forma
        if any(field in inputs for field in ["comment", "message", "text"]) and "email" in inputs:
            return "comment"
        
        # Register forma
        if "password" in inputs and any(field in inputs for field in ["confirm", "repeat"]):
            return "register"
        
        return "generic"

    def _calculate_payload_distribution(self, attack_vectors: Dict[str, int]) -> Dict[str, int]:
        """
        Računa koliko payload-a koristiti za svaki tip napada
        """
        total_score = sum(attack_vectors.values())
        distribution = {}
        
        for attack_type, score in attack_vectors.items():
            # Osnovna distribucija na osnovu skora
            base_count = self.vuln_priorities.get(attack_type, {}).get("payloads_count", 5)
            
            # Adjust na osnovu relativnog skora
            score_multiplier = score / max(total_score / len(attack_vectors), 1)
            adjusted_count = int(base_count * min(score_multiplier, 2.0))
            
            distribution[attack_type] = max(3, min(adjusted_count, 20))  # Između 3 i 20
        
        return distribution

    def _determine_stealth_level(self, recon_data: Dict) -> Dict[str, Any]:
        """
        Određuje nivo stealth-a na osnovu ciljane aplikacije
        """
        technologies = recon_data.get("technologies", {})
        
        # Ako je detektovan WAF ili sigurnosni sistem
        headers = recon_data.get("headers", {}).get("all_headers", {})
        has_waf = any(waf in str(headers).lower() for waf in 
                     ["cloudflare", "incapsula", "sucuri", "barracuda", "f5", "akamai"])
        
        if has_waf:
            stealth_level = "high"
            delay_range = (5, 15)
            user_agent_rotation = True
        elif any(enterprise in technologies for enterprise in ["IIS", "ASP.NET"]):
            stealth_level = "medium"
            delay_range = (2, 8)
            user_agent_rotation = True
        else:
            stealth_level = "low"
            delay_range = (1, 4)
            user_agent_rotation = False
        
        return {
            "level": stealth_level,
            "delay_range": delay_range,
            "user_agent_rotation": user_agent_rotation,
            "max_concurrent_requests": 3 if stealth_level == "high" else 5,
            "randomize_headers": stealth_level in ["medium", "high"]
        }

    def _define_success_metrics(self, attack_vectors: Dict[str, int]) -> Dict[str, Any]:
        """
        Definiše metrike uspešnosti misije
        """
        total_attacks = sum(self._calculate_payload_distribution(attack_vectors).values())
        
        return {
            "expected_total_requests": total_attacks,
            "success_threshold": {
                "critical": 1,  # Jedan kritičan finding je dovoljno
                "high": 2,
                "medium": 3,
                "low": 5
            },
            "time_limit_minutes": min(120, total_attacks * 0.5),  # Max 2h
            "false_positive_tolerance": 0.1,  # 10% false positives OK
            "coverage_target": 0.8  # 80% attack vectors coverage
        }

    def _estimate_duration(self, phases: List[Dict]) -> int:
        """
        Procenjuje trajanje misije u minutima
        """
        total_minutes = 0
        
        for phase in phases:
            phase_requests = sum(attack["payload_count"] for attack in phase["attacks"])
            avg_delay = sum(phase["delay_between_requests"]) / 2
            concurrent = phase.get("concurrent_attacks", 1)
            
            phase_time = (phase_requests * avg_delay) / concurrent / 60  # u minutima
            total_minutes += phase_time
        
        # Dodaj vreme za setup i cleanup
        total_minutes += 10
        
        return int(total_minutes)

    def _assess_risk_level(self, recon_data: Dict, attack_vectors: Dict) -> str:
        """
        Procenjuje nivo rizika napada
        """
        risk_factors = 0
        
        # WAF detection
        headers = recon_data.get("headers", {}).get("all_headers", {})
        if any(waf in str(headers).lower() for waf in ["cloudflare", "incapsula", "sucuri"]):
            risk_factors += 2
        
        # Enterprise technologies
        technologies = recon_data.get("technologies", {})
        if any(ent in technologies for ent in ["IIS", "ASP.NET", "Apache"]):
            risk_factors += 1
        
        # High-priority attacks
        high_priority_attacks = sum(1 for attack_type in attack_vectors 
                                  if self.vuln_priorities.get(attack_type, {}).get("priority", 0) >= 8)
        if high_priority_attacks >= 3:
            risk_factors += 1
        
        # SSL/Security headers
        if recon_data.get("ssl_info") and not recon_data.get("ssl_info", {}).get("error"):
            risk_factors -= 1  # HTTPS je bolje za stealth
        
        if risk_factors >= 3:
            return "high"
        elif risk_factors >= 1:
            return "medium"
        else:
            return "low"

    def adapt_strategy_realtime(self, current_results: List[Dict], strategy: Dict) -> Dict:
        """
        Prilagođava strategiju u realnom vremenu na osnovu trenutnih rezultata
        """
        adaptations = {
            "phase_adjustments": [],
            "payload_adjustments": {},
            "stealth_adjustments": {},
            "new_attack_vectors": []
        }
        
        # Analiziraj trenutne rezultate
        success_rate = len([r for r in current_results if r.get("success_rate", 0) > 0.7]) / max(len(current_results), 1)
        error_rate = len([r for r in current_results if r.get("error")]) / max(len(current_results), 1)
        
        # Ako je previše grešaka, povećaj stealth
        if error_rate > 0.3:
            adaptations["stealth_adjustments"] = {
                "increase_delays": True,
                "reduce_concurrency": True,
                "rotate_user_agents": True
            }
            self.logger.warning(f"Visoka stopa grešaka ({error_rate:.2f}), povećavam stealth")
        
        # Ako imamo uspešne napade, fokusiraj se na slične
        if success_rate > 0.2:
            successful_types = [r.get("payload_type") for r in current_results 
                              if r.get("success_rate", 0) > 0.7]
            for attack_type in set(successful_types):
                if attack_type in adaptations["payload_adjustments"]:
                    adaptations["payload_adjustments"][attack_type] += 5
                else:
                    adaptations["payload_adjustments"][attack_type] = 5
        
        # Loguj prilagođavanje
        if any(adaptations.values()):
            self.operator.log_agent_action("TakticianAgent", "strategy_adapted", {
                "success_rate": success_rate,
                "error_rate": error_rate,
                "adaptations": adaptations
            })
        
        return adaptations

    def generate_mission_summary(self, strategy: Dict, final_results: List[Dict]) -> Dict:
        """
        Generiše finalni sažetak misije
        """
        total_requests = len(final_results)
        successful_attacks = [r for r in final_results if r.get("success_rate", 0) > 0.7]
        confirmed_vulns = [r for r in final_results if r.get("status") == "confirmed"]
        
        summary = {
            "mission_id": strategy["mission_id"],
            "target": strategy["target_info"]["url"],
            "execution_summary": {
                "total_requests": total_requests,
                "successful_attacks": len(successful_attacks),
                "confirmed_vulnerabilities": len(confirmed_vulns),
                "success_rate": len(successful_attacks) / max(total_requests, 1),
                "phases_completed": len(strategy["attack_phases"])
            },
            "vulnerability_breakdown": self._categorize_findings(confirmed_vulns),
            "recommendations": self._generate_recommendations(confirmed_vulns, strategy),
            "tactical_assessment": {
                "strategy_effectiveness": "high" if len(confirmed_vulns) > 0 else "medium",
                "stealth_success": "good" if sum(1 for r in final_results if r.get("error")) / max(total_requests, 1) < 0.1 else "poor",
                "coverage_achieved": len(set(r.get("payload_type") for r in final_results)) / len(strategy.get("payload_distribution", {}))
            }
        }
        
        # Loguj finalni sažetak
        self.operator.log_agent_action("TakticianAgent", "mission_completed", summary["execution_summary"])
        
        return summary

    def _categorize_findings(self, findings: List[Dict]) -> Dict[str, List]:
        """
        Kategoriše pronađene ranjivosti po težini
        """
        categories = {"critical": [], "high": [], "medium": [], "low": []}
        
        severity_mapping = {
            "SQLi": "critical",
            "Command_Injection": "critical",
            "RFI": "high",
            "LFI": "high",
            "XSS": "medium",
            "SSRF": "high",
            "XXE": "high",
            "IDOR": "medium",
            "CSRF": "medium",
            "Information_Disclosure": "low",
            "Clickjacking": "low"
        }
        
        for finding in findings:
            payload_type = finding.get("payload_type", "")
            severity = severity_mapping.get(payload_type, "low")
            categories[severity].append({
                "type": payload_type,
                "url": finding.get("url"),
                "payload": finding.get("payload"),
                "success_rate": finding.get("success_rate")
            })
        
        return categories

    def _generate_recommendations(self, findings: List[Dict], strategy: Dict) -> List[str]:
        """
        Generiše preporuke na osnovu pronađenih ranjivosti
        """
        recommendations = []
        
        finding_types = set(f.get("payload_type") for f in findings)
        
        if "SQLi" in finding_types:
            recommendations.append("Implement parameterized queries and input validation")
        if "XSS" in finding_types:
            recommendations.append("Implement proper output encoding and CSP headers")
        if "LFI" in finding_types or "RFI" in finding_types:
            recommendations.append("Validate and sanitize file inclusion parameters")
        if "Command_Injection" in finding_types:
            recommendations.append("Avoid system calls with user input, use whitelisting")
        if "SSRF" in finding_types:
            recommendations.append("Validate and restrict outbound requests")
        
        # Opšte preporuke
        if not findings:
            recommendations.append("Continue monitoring - no critical vulnerabilities found")
        else:
            recommendations.append("Conduct immediate security patching for identified vulnerabilities")
            recommendations.append("Implement WAF rules for detected attack patterns")
        
        return recommendations

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Mock recon data for testing
    mock_recon = {
        "target_url": "https://example.com",
        "domain": "example.com",
        "technologies": {"PHP": True, "Apache": True},
        "forms": [
            {"action": "/login", "method": "POST", "inputs": [{"name": "username"}, {"name": "password"}]},
            {"action": "/search", "method": "GET", "inputs": [{"name": "q"}]}
        ],
        "endpoints": ["/admin", "/api/users"],
        "potential_vulns": ["XSS - Missing CSP", "Admin panel - Brute force potential"],
        "headers": {"missing_security": ["content-security-policy", "x-frame-options"]}
    }
    
    op = ShadowFoxOperator()
    takt = TakticianAgent(op)
    
    mission_id = op.create_mission("https://example.com", "Test taktička misija")
    strategy = takt.create_attack_strategy(mock_recon, mission_id)
    
    print(json.dumps(strategy, indent=2, default=str))
