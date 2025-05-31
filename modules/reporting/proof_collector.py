# shadowfox/agents/proof_collector.py

import os
import time
import base64
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
import logging
import json
import requests
from selenium import webdriver
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import subprocess

class ProofCollector:
    """
    ProofCollector - Kreira screenshot-ove i čuva dokaze o uspešnim payload-ima
    Sa custom header "CHUPKO WAS HERE <> H1:Whitefox980" za H1 bounty dokaze
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('ProofCollector')
        
        # Signature za bounty dokaze
        self.bounty_signature = "CHUPKO WAS HERE <> H1:Whitefox980"
        
        # Setup paths
        self.proofs_dir = self.operator.proofs_dir
        self.screenshots_dir = self.proofs_dir / "screenshots"
        self.html_dumps_dir = self.proofs_dir / "html_dumps"
        self.reports_dir = self.proofs_dir / "reports"
        
        # Kreiraj direktorijume
        for dir_path in [self.screenshots_dir, self.html_dumps_dir, self.reports_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Chrome driver setup
        self.driver = None
        self._setup_chrome_driver()
    
    def _setup_chrome_driver(self):
        """Setup Chrome WebDriver sa potrebnim opcijama"""
        try:
            chrome_options = Options()
            
            # Headless mode za server
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')  # Brže učitavanje
            
            # User agent
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            # Disable notifications
            prefs = {
                "profile.default_content_setting_values.notifications": 2,
                "profile.default_content_settings.popups": 0
            }
            chrome_options.add_experimental_option("prefs", prefs)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            
            self.logger.info("Chrome WebDriver uspešno inicijalizovan")
            
        except Exception as e:
            self.logger.error(f"Greška pri setup Chrome driver: {e}")
            self.driver = None
    
    def capture_proof(self, url: str, payload: str, payload_type: str, 
                     response_data: Dict, method: str = "GET", 
                     post_data: Dict = None, headers: Dict = None) -> Dict:
        """
        Glavni metod za kreiranje kompletnog dokaza (screenshot + HTML + metadata)
        """
        if not self.driver:
            self.logger.error("Chrome driver nije dostupan")
            return {"error": "WebDriver not available"}
        
        # Generiši unique identifikator za ovaj dokaz
        proof_id = self._generate_proof_id(url, payload)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        proof_data = {
            "proof_id": proof_id,
            "url": url,
            "payload": payload,
            "payload_type": payload_type,
            "method": method,
            "post_data": post_data,
            "headers": headers,
            "timestamp": timestamp,
            "bounty_signature": self.bounty_signature,
            "response_data": response_data,
            "files": {},
            "success": False
        }
        
        try:
            # 1. Screenshot osnovne stranice (pre payload-a)
            before_screenshot = self._take_screenshot(url, f"{proof_id}_before_{timestamp}")
            if before_screenshot:
                proof_data["files"]["before_screenshot"] = before_screenshot
            
            # 2. Izvršavanje payload-a i screenshot rezultata
            payload_result = self._execute_payload_and_capture(
                url, payload, payload_type, method, post_data, headers, proof_id, timestamp
            )
            
            if payload_result["success"]:
                proof_data["files"].update(payload_result["files"])
                proof_data["execution_details"] = payload_result["details"]
                proof_data["success"] = True
                
                # 3. Sačuvaj HTML source
                html_path = self._save_html_source(proof_id, timestamp)
                if html_path:
                    proof_data["files"]["html_source"] = html_path
                
                # 4. Kreiraj detaljni report
                report_path = self._create_proof_report(proof_data)
                if report_path:
                    proof_data["files"]["detailed_report"] = report_path
                
                # 5. Sačuvaj u bazu
                db_proof_id = self.operator.store_proof(
                    payload=payload,
                    url=url,
                    payload_type=payload_type,
                    response_code=response_data.get("status_code", 0),
                    response_raw=json.dumps(response_data),
                    screenshot_path=proof_data["files"].get("payload_screenshot"),
                    html_path=proof_data["files"].get("html_source")
                )
                
                proof_data["db_proof_id"] = db_proof_id
                
                self.logger.info(f"Dokaz uspešno kreiran: {proof_id}")
            else:
                self.logger.warning(f"Payload nije uspešno izvršen: {proof_id}")
        
        except Exception as e:
            self.logger.error(f"Greška pri kreiranju dokaza: {e}")
            proof_data["error"] = str(e)
        
        return proof_data
    
    def _execute_payload_and_capture(self, url: str, payload: str, payload_type: str,
                                   method: str, post_data: Dict, headers: Dict,
                                   proof_id: str, timestamp: str) -> Dict:
        """
        Izvršava payload i kreira screenshot dokaza
        """
        result = {
            "success": False,
            "files": {},
            "details": {}
        }
        
        try:
            if payload_type.upper() == "XSS":
                result = self._test_xss_payload(url, payload, proof_id, timestamp, method, post_data)
            elif payload_type.upper() == "SQLI":
                result = self._test_sqli_payload(url, payload, proof_id, timestamp, method, post_data)
            elif payload_type.upper() == "SSRF":
                result = self._test_ssrf_payload(url, payload, proof_id, timestamp, method, post_data)
            elif payload_type.upper() == "LFI":
                result = self._test_lfi_payload(url, payload, proof_id, timestamp, method, post_data)
            else:
                # Generic test
                result = self._test_generic_payload(url, payload, proof_id, timestamp, method, post_data)
                
        except Exception as e:
            self.logger.error(f"Greška pri testiranju {payload_type} payload: {e}")
            result["error"] = str(e)
        
        return result
    
    def _test_xss_payload(self, url: str, payload: str, proof_id: str, timestamp: str,
                         method: str = "GET", post_data: Dict = None) -> Dict:
        """
        Testira XSS payload i kreira screenshot ako je uspešan
        """
        result = {"success": False, "files": {}, "details": {}}
        
        try:
            # Dodaj bounty signature u XSS payload
            signed_payload = payload.replace("alert(", f"alert('{self.bounty_signature}:")
            if signed_payload == payload:  # Ako nema alert, dodaj custom
                signed_payload = f"{payload}<script>alert('{self.bounty_signature}')</script>"
            
            # Konstruiši test URL
            if method.upper() == "GET":
                test_url = f"{url}?test={signed_payload}" if "?" not in url else f"{url}&test={signed_payload}"
            else:
                test_url = url
            
            # Navigiraj na stranicu
            self.driver.get(test_url)
            
            # Za POST payload
            if method.upper() == "POST" and post_data:
                self._submit_post_data(post_data, signed_payload)
            
            # Čekaj na alert ili proveri DOM
            try:
                WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                if self.bounty_signature in alert_text:
                    result["success"] = True
                    result["details"]["alert_text"] = alert_text
                    result["details"]["payload_executed"] = signed_payload
                    
                    # Screenshot nakon uspešnog XSS-a
                    screenshot_path = self._take_screenshot(test_url, f"{proof_id}_xss_success_{timestamp}")
                    if screenshot_path:
                        result["files"]["payload_screenshot"] = screenshot_path
                        
            except TimeoutException:
                # Nema alert, proveri DOM za reflected XSS
                page_source = self.driver.page_source
                if signed_payload in page_source or self.bounty_signature in page_source:
                    result["success"] = True
                    result["details"]["reflected_in_dom"] = True
                    result["details"]["payload_executed"] = signed_payload
                    
                    screenshot_path = self._take_screenshot(test_url, f"{proof_id}_xss_reflected_{timestamp}")
                    if screenshot_path:
                        result["files"]["payload_screenshot"] = screenshot_path
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _test_sqli_payload(self, url: str, payload: str, proof_id: str, timestamp: str,
                          method: str = "GET", post_data: Dict = None) -> Dict:
        """
        Testira SQL injection payload
        """
        result = {"success": False, "files": {}, "details": {}}
        
        try:
            # SQL error keywords koji ukazuju na SQL injection
            sql_errors = [
                "mysql_fetch", "ora-", "microsoft ole db", "odbc", "sql syntax",
                "syntax error", "unclosed quotation", "quoted string not properly terminated",
                "mysql_", "warning: mysql", "valid mysql result", "postgresql query failed"
            ]
            
            # Konstruiši test URL
            if method.upper() == "GET":
                test_url = f"{url}?id={payload}" if "?" not in url else f"{url}&id={payload}"
            else:
                test_url = url
            
            self.driver.get(test_url)
            
            # Za POST
            if method.upper() == "POST" and post_data:
                self._submit_post_data(post_data, payload)
            
            # Čekaj da se stranica učita
            time.sleep(3)
            
            page_source = self.driver.page_source.lower()
            
            # Proveri za SQL greške
            for error in sql_errors:
                if error in page_source:
                    result["success"] = True
                    result["details"]["sql_error_found"] = error
                    result["details"]["payload_executed"] = payload
                    
                    screenshot_path = self._take_screenshot(test_url, f"{proof_id}_sqli_error_{timestamp}")
                    if screenshot_path:
                        result["files"]["payload_screenshot"] = screenshot_path
                    break
            
            # Dodatno: proveri za promene u response time (time-based SQLi)
            start_time = time.time()
            self.driver.refresh()
            response_time = time.time() - start_time
            
            if response_time > 10:  # Ako je odgovor sporiji od 10s
                result["details"]["possible_time_based"] = True
                result["details"]["response_time"] = response_time
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _test_generic_payload(self, url: str, payload: str, proof_id: str, timestamp: str,
                            method: str = "GET", post_data: Dict = None) -> Dict:
        """
        Opšti test za payload-e
        """
        result = {"success": False, "files": {}, "details": {}}
        
        try:
            if method.upper() == "GET":
                test_url = f"{url}?test={payload}" if "?" not in url else f"{url}&test={payload}"
            else:
                test_url = url
            
            self.driver.get(test_url)
            
            if method.upper() == "POST" and post_data:
                self._submit_post_data(post_data, payload)
            
            time.sleep(2)
            
            # Osnovni screenshot
            screenshot_path = self._take_screenshot(test_url, f"{proof_id}_generic_{timestamp}")
            if screenshot_path:
                result["files"]["payload_screenshot"] = screenshot_path
                result["success"] = True
                result["details"]["payload_executed"] = payload
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _submit_post_data(self, post_data: Dict, payload: str):
        """
        Submituje POST data preko Selenium-a
        """
        try:
            # Pronađi forme na stranici
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            
            if forms:
                form = forms[0]  # Uzmi prvu formu
                
                # Popuni polja
                for field_name, field_value in post_data.items():
                    try:
                        field = form.find_element(By.NAME, field_name)
                        field.clear()
                        # Koristi payload umesto original vrednosti za testiranje
                        field.send_keys(payload if field_name in ["test", "search", "q", "input"] else field_value)
                    except:
                        continue
                
                # Submit formu
                form.submit()
                time.sleep(3)
                
        except Exception as e:
            self.logger.error(f"Greška pri POST submit: {e}")
    
    def _take_screenshot(self, url: str, filename: str) -> Optional[str]:
        """
        Pravi screenshot stranice
        """
        try:
            if not self.driver:
                return None
            
            screenshot_path = self.screenshots_dir / f"{filename}.png"
            
            # Full page screenshot
            self.driver.execute_script("document.body.style.zoom='0.8'")  # Zoom out za bolje frame
            time.sleep(1)
            
            if self.driver.save_screenshot(str(screenshot_path)):
                self.logger.info(f"Screenshot sačuvan: {screenshot_path}")
                return str(screenshot_path)
            
        except Exception as e:
            self.logger.error(f"Greška pri screenshot: {e}")
        
        return None
    
    def _save_html_source(self, proof_id: str, timestamp: str) -> Optional[str]:
        """
        Čuva HTML source stranice
        """
        try:
            if not self.driver:
                return None
            
            html_path = self.html_dumps_dir / f"{proof_id}_{timestamp}.html"
            
            # Dodaj custom header u HTML
            html_content = f"""
<!-- {self.bounty_signature} -->
<!-- Proof ID: {proof_id} -->
<!-- Timestamp: {timestamp} -->
{self.driver.page_source}
"""
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML source sačuvan: {html_path}")
            return str(html_path)
            
        except Exception as e:
            self.logger.error(f"Greška pri čuvanju HTML: {e}")
        
        return None
    
    def _create_proof_report(self, proof_data: Dict) -> Optional[str]:
        """
        Kreira detaljni text report o dokazu
        """
        try:
            report_path = self.reports_dir / f"{proof_data['proof_id']}_report.txt"
            
            report_content = f"""
=== SHADOWFOX VULNERABILITY PROOF REPORT ===
{self.bounty_signature}

Proof ID: {proof_data['proof_id']}
Timestamp: {proof_data['timestamp']}
Target URL: {proof_data['url']}
Payload Type: {proof_data['payload_type']}
Method: {proof_data['method']}

=== PAYLOAD DETAILS ===
Payload: {proof_data['payload']}
Execution Success: {proof_data['success']}

=== EXECUTION DETAILS ===
{json.dumps(proof_data.get('execution_details', {}), indent=2)}

=== RESPONSE DATA ===
{json.dumps(proof_data.get('response_data', {}), indent=2)}

=== FILES GENERATED ===
"""
            
            for file_type, file_path in proof_data.get('files', {}).items():
                report_content += f"{file_type}: {file_path}\n"
            
            report_content += f"""
=== VERIFICATION STEPS ===
1. Open screenshot: {proof_data['files'].get('payload_screenshot', 'N/A')}
2. Review HTML source: {proof_data['files'].get('html_source', 'N/A')}
3. Verify payload execution in browser
4. Check for bounty signature: {self.bounty_signature}

Report generated by ShadowFox v15
"""
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return str(report_path)
            
        except Exception as e:
            self.logger.error(f"Greška pri kreiranju report-a: {e}")
        
        return None
    
    def _generate_proof_id(self, url: str, payload: str) -> str:
        """
        Generiše jedinstveni ID za dokaz
        """
        combined = f"{url}_{payload}_{datetime.now().isoformat()}"
        return hashlib.md5(combined.encode()).hexdigest()[:12]
    
    def close(self):
        """
        Zatvara WebDriver
        """
        if self.driver:
            try:
                self.driver.quit()
                self.logger.info("Chrome WebDriver zatvoren")
            except Exception as e:
                self.logger.error(f"Greška pri zatvaranju driver: {e}")

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test setup
    op = ShadowFoxOperator()
    collector = ProofCollector(op)
    
    # Test XSS proof
    mission_id = op.create_mission("https://httpbin.org/get", "Test proof collection")
    
    test_payload = "<script>alert('XSS')</script>"
    response_data = {"status_code": 200, "content": "test response"}
    
    proof = collector.capture_proof(
        url="https://httpbin.org/get",
        payload=test_payload,
        payload_type="XSS",
        response_data=response_data
    )
    
    print(json.dumps(proof, indent=2, default=str))
    
    # Cleanup
    collector.close()
