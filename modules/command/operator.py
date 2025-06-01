# shadowfox/core/operator.py

import sqlite3
import uuid
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import os
import importlib.util
from core.shadowfox_db import ShadowFoxDB
from payloads.mutation_engine import MutationEngine
from modules.payloads.mutation_engine import MutationEngine

class ShadowFoxOperator:
    """
    Centralni Operator v2 koji koordinira sve agente i baze podataka.
    Proširen sa podrškom za sve agente i JSON meta unos.
    """
    
    def __init__(self, base_dir: str = ".", db=None, event_bus=None):
        self.base_dir = base_dir
        self.logger = logging.getLogger("ShadowFoxOperator")
        self.logger.setLevel(logging.INFO)

            # 1. Init event bus & db
        self.event_bus = event_bus or ShadowFoxEventBus()
        self.db = db or ShadowFoxDB(Path(self.base_dir) / "databases" / "shadowfox.db")
        # ✅ Init Mutation Engine PRE AI BRAIN!
        from modules.payloads.mutation_engine import MutationEngine
        self.mutation_engine = MutationEngine(self, self.db)
        setattr(self, "mutation_engine", self.mutation_engine)
        # ✅ Tek sada AI Brain
        from modules.ai.ai_brain import AIBrain
        self.brain = AIBrain(operator=self)

        # ✅ Registruj Mutation Engine u brain
        self.brain.register_agent("MutationEngine", self.mutation_engine)


    # Init folder paths
        self.reports_dir = Path(self.base_dir) / "reports"
        self.proofs_dir = Path(self.base_dir) / "proofs"
        self.agents_dir = Path(self.base_dir) / "agents"
        for dir_path in [self.base_dir, self.reports_dir, self.proofs_dir, self.agents_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    # Baza putevi
        self.shadowfox_db = Path(self.base_dir) / "shadowfox.db"
        self.poc_db = Path(self.base_dir) / "poc.db"

    # Agent instance tracking
        self.agents = {}
        self.agent_classes = {
            "ReconAgent": None,
            "MutationEngine": None,
            "SmartShadowAgent": None,
            "TrafficShaper": None,
            "ATEvaluator": None,
            "PDFExporter": None,
            "ProofCollector": None,
            "TacticianAgent": None  # Novi taktičar
        }

        self.logger.info("✅ ShadowFox Operator v2 inicijalizovan uspešno")
    def _setup_logging(self):
        """Setup logging sistema"""
        log_dir = self.base_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"shadowfox_{datetime.now().strftime('%Y%m%d')}.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ShadowFoxOperator')
    async def initialize(self):
    # Dummy init za sada da prodje boot
        pass
    
    def _init_databases(self):
        """Inicijalizuje obe SQLite baze sa proširenim tabelama"""
        try:
            # SHADOWFOX.DB - Globalna baza
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS missions (
                        mission_id TEXT PRIMARY KEY,
                        target_url TEXT NOT NULL,
                        description TEXT,
                        mission_type TEXT DEFAULT 'standard',
                        target_meta TEXT,  -- JSON meta podaci o meti
                        recon_data TEXT,   -- JSON recon rezultati
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'active',
                        completed_at TIMESTAMP NULL,
                        success_rate REAL DEFAULT 0.0,
                        total_payloads INTEGER DEFAULT 0,
                        successful_payloads INTEGER DEFAULT 0
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS payload_library (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload_type TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        description TEXT,
                        success_rate REAL DEFAULT 0.0,
                        difficulty TEXT DEFAULT 'medium',
                        tags TEXT,  -- JSON array tagova
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_used TIMESTAMP NULL,
                        times_used INTEGER DEFAULT 0
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS agent_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mission_id TEXT NOT NULL,
                        agent_name TEXT NOT NULL,
                        action TEXT NOT NULL,
                        data TEXT,
                        execution_time REAL,
                        success BOOLEAN DEFAULT TRUE,
                        error_message TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (mission_id) REFERENCES missions (mission_id)
                    )
                ''')
                
                # Nova tabela za agent koordinaciju
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS agent_coordination (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mission_id TEXT NOT NULL,
                        agent_sequence TEXT,  -- JSON redosled izvršavanja
                        current_step INTEGER DEFAULT 0,
                        total_steps INTEGER DEFAULT 0,
                        coordination_data TEXT,  -- JSON podaci za koordinaciju
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (mission_id) REFERENCES missions (mission_id)
                    )
                ''')
                
            # POC.DB - Dokazi i rezultati (prošireno)
            with sqlite3.connect(self.poc_db) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS proofs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mission_id TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        original_payload TEXT,  -- Pre mutacije
                        url TEXT NOT NULL,
                        payload_type TEXT NOT NULL,
                        attack_vector TEXT,
                        status TEXT DEFAULT 'potential',
                        response_code INTEGER,
                        response_raw TEXT,
                        response_time REAL,
                        screenshot_path TEXT,
                        html_path TEXT,
                        raw_request TEXT,  -- Ceo HTTP zahtev
                        mutation_info TEXT,  -- JSON info o mutaciji
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS evaluations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        proof_id INTEGER NOT NULL,
                        mission_id TEXT NOT NULL,
                        evaluator_agent TEXT DEFAULT 'AIEvaluator',
                        success_rate REAL NOT NULL,
                        confidence_score REAL,
                        ai_analysis TEXT,
                        reasoning TEXT,
                        severity TEXT DEFAULT 'medium',
                        false_positive_probability REAL,
                        recommended_action TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (proof_id) REFERENCES proofs (id)
                    )
                ''')
                
            self.logger.info("Proširene baze podataka uspešno inicijalizovane")
            
        except Exception as e:
            self.logger.error(f"Greška pri inicijalizaciji baza: {e}")
            raise
    
    def create_mission_from_json(self, mission_json: Union[str, Dict]) -> str:
        """
        Kreira misiju iz JSON meta podataka
        Format:
        {
            "target_url": "https://example.com",
            "description": "Test misija",
            "mission_type": "full_scan|quick_scan|targeted",
            "target_meta": {
                "domain": "example.com",
                "ip": "1.2.3.4",
                "technologies": ["WordPress", "PHP"],
                "priority_vectors": ["XSS", "SQLi"],
                "custom_headers": {},
                "authentication": {}
            },
            "attack_config": {
                "max_payloads_per_type": 50,
                "delay_between_requests": 1.0,
                "user_agents_rotation": true,
                "stealth_mode": true
            }
        }
        """
        try:
            if isinstance(mission_json, str):
                mission_data = json.loads(mission_json)
            else:
                mission_data = mission_json
                
            # Validacija osnovnih polja
            if not mission_data.get("target_url"):
                raise ValueError("target_url je obavezno polje")
                
            mission_id = str(uuid.uuid4())
            
            # Pripremi podatke za bazu
            target_url = mission_data["target_url"]
            description = mission_data.get("description", "")
            mission_type = mission_data.get("mission_type", "standard")
            target_meta = json.dumps(mission_data.get("target_meta", {}))
            
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.execute('''
                    INSERT INTO missions (mission_id, target_url, description, 
                                        mission_type, target_meta)
                    VALUES (?, ?, ?, ?, ?)
                ''', (mission_id, target_url, description, mission_type, target_meta))
                
            self.current_mission_id = mission_id
            self.current_mission_data = mission_data
            
            # Kreiraj koordinaciju agenata
            self._setup_agent_coordination(mission_id, mission_data)
            
            self.log_agent_action("Operator", "mission_created_from_json", {
                "target_url": target_url,
                "mission_type": mission_type,
                "has_custom_config": bool(mission_data.get("attack_config"))
            })
            
            self.logger.info(f"Nova misija kreirana iz JSON: {mission_id} za {target_url}")
            return mission_id
            
        except Exception as e:
            self.logger.error(f"Greška pri kreiranju misije iz JSON: {e}")
            raise
    
    def _setup_agent_coordination(self, mission_id: str, mission_data: Dict):
        """Setup koordinacije između agenata"""
        mission_type = mission_data.get("mission_type", "standard")
        
        # Definišu redosled agenata na osnovu tipa misije
        sequences = {
            "quick_scan": [
                "ReconAgent",
                "MutationEngine", 
                "SmartShadowAgent",
                "AIEvaluator",
                "ProofCollector"
            ],
            "full_scan": [
                "ReconAgent",
                "TacticianAgent",
                "MutationEngine",
                "TrafficShaper", 
                "SmartShadowAgent",
                "AIEvaluator",
                "ProofCollector",
                "PDFExporter"
            ],
            "targeted": [
                "TacticianAgent",
                "MutationEngine",
                "SmartShadowAgent", 
                "AIEvaluator",
                "ProofCollector"
            ],
            "standard": [
                "ReconAgent",
                "MutationEngine",
                "SmartShadowAgent",
                "AIEvaluator", 
                "ProofCollector",
                "PDFExporter"
            ]
        }
        
        agent_sequence = sequences.get(mission_type, sequences["standard"])
        
        coordination_data = {
            "mission_config": mission_data.get("attack_config", {}),
            "target_meta": mission_data.get("target_meta", {}),
            "agent_params": {},
            "shared_state": {}
        }
        
        try:
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.execute('''
                    INSERT INTO agent_coordination 
                    (mission_id, agent_sequence, total_steps, coordination_data)
                    VALUES (?, ?, ?, ?)
                ''', (mission_id, json.dumps(agent_sequence), len(agent_sequence), 
                          json.dumps(coordination_data)))
                          
        except Exception as e:
            self.logger.error(f"Greška pri setup koordinacije: {e}")
    
    def load_agent(self, agent_name: str):
        """Lazy loading agenata"""
        if agent_name in self.agents:
            return self.agents[agent_name]
            
        try:
            # Pokušaj učitaj agent klasu
            agent_file = self.agents_dir / f"{agent_name.lower()}.py"
            
            if agent_file.exists():
                spec = importlib.util.spec_from_file_location(agent_name, agent_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Pretpostavi da je klasa istoimena sa fajlom
                agent_class = getattr(module, agent_name)
                self.agents[agent_name] = agent_class(self)
                
                self.logger.info(f"Agent {agent_name} uspešno učitan")
                return self.agents[agent_name]
            else:
                self.logger.warning(f"Agent fajl ne postoji: {agent_file}")
                return None
                
        except Exception as e:
            self.logger.error(f"Greška pri učitavanju agenta {agent_name}: {e}")
            return None
    
    def execute_mission(self, mission_id: str = None) -> Dict:
        """
        Izvršava celu misiju koordinišući sve agente
        """
        if not mission_id:
            mission_id = self.current_mission_id
            
        if not mission_id:
            raise ValueError("Nema aktivne misije")
            
        try:
            # Učitaj koordinaciju
            coordination = self._get_agent_coordination(mission_id)
            if not coordination:
                raise ValueError("Nema koordinacije za misiju")
                
            agent_sequence = json.loads(coordination["agent_sequence"])
            coordination_data = json.loads(coordination["coordination_data"])
            
            results = {
                "mission_id": mission_id,
                "executed_agents": [],
                "results": {},
                "errors": [],
                "execution_time": 0
            }
            
            start_time = datetime.now()
            
            # Izvršavaj agente u redosledu
            for i, agent_name in enumerate(agent_sequence):
                try:
                    self.logger.info(f"Izvršavam {agent_name} (korak {i+1}/{len(agent_sequence)})")
                    
                    agent = self.load_agent(agent_name)
                    if not agent:
                        raise Exception(f"Ne mogu učitati {agent_name}")
                    
                    # Ažuriraj trenutni korak
                    self._update_coordination_step(mission_id, i)
                    
                    # Izvršavaj agent sa kontekstom prethodnih rezultata
                    agent_result = self._execute_agent(agent, agent_name, coordination_data, results)
                    
                    results["executed_agents"].append(agent_name)
                    results["results"][agent_name] = agent_result
                    
                    # Ažuriraj deljeno stanje za sledeće agente
                    coordination_data["shared_state"][agent_name] = agent_result
                    
                except Exception as e:
                    error_msg = f"Greška u {agent_name}: {str(e)}"
                    self.logger.error(error_msg)
                    results["errors"].append(error_msg)
                    
                    # Odluči da li prekidati ili nastaviti
                    if agent_name in ["ReconAgent", "SmartShadowAgent"]:
                        # Kritični agenti - prekini
                        break
            
            end_time = datetime.now()
            results["execution_time"] = (end_time - start_time).total_seconds()
            
            # Ažuriraj status misije
            self.update_mission_status(mission_id, "completed")
            
            self.log_agent_action("Operator", "mission_executed", {
                "executed_agents": results["executed_agents"],
                "execution_time": results["execution_time"],
                "errors_count": len(results["errors"])
            })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Greška u izvršavanju misije {mission_id}: {e}")
            self.update_mission_status(mission_id, "failed")
            raise
    
    def _execute_agent(self, agent, agent_name: str, coordination_data: Dict, previous_results: Dict) -> Any:
        """Izvršava pojedinačni agent sa kontekstom"""
        try:
            # Pripremi kontekst za agenta
            context = {
                "mission_id": self.current_mission_id,
                "mission_data": self.current_mission_data,
                "coordination_data": coordination_data,
                "previous_results": previous_results["results"],
                "shared_state": coordination_data.get("shared_state", {})
            }
            
            # Pozovi glavnu metodu agenta
            if hasattr(agent, 'execute'):
                return agent.execute(context)
            elif hasattr(agent, 'analyze_target') and agent_name == "ReconAgent":
                target_url = self.current_mission_data.get("target_url")
                return agent.analyze_target(target_url, self.current_mission_id)
            else:
                raise Exception(f"Agent {agent_name} nema execute metodu")
                
        except Exception as e:
            self.log_agent_action(agent_name, "execution_failed", {"error": str(e)})
            raise
    
    def _get_agent_coordination(self, mission_id: str) -> Optional[Dict]:
        """Vraća koordinaciju za misiju"""
        try:
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM agent_coordination WHERE mission_id = ?
                ''', (mission_id,))
                
                row = cursor.fetchone()
                return dict(row) if row else None
                
        except Exception as e:
            self.logger.error(f"Greška pri čitanju koordinacije: {e}")
            return None
    
    def _update_coordination_step(self, mission_id: str, step: int):
        """Ažurira trenutni korak koordinacije"""
        try:
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.execute('''
                    UPDATE agent_coordination SET current_step = ?
                    WHERE mission_id = ?
                ''', (step, mission_id))
        except Exception as e:
            self.logger.error(f"Greška pri ažuriranju koraka: {e}")
    
    def get_mission_progress(self, mission_id: str) -> Dict:
        """Vraća progress misije"""
        try:
            coordination = self._get_agent_coordination(mission_id)
            if not coordination:
                return {"error": "Nema koordinacije"}
                
            agent_sequence = json.loads(coordination["agent_sequence"])
            current_step = coordination["current_step"]
            total_steps = coordination["total_steps"]
            
            return {
                "mission_id": mission_id,
                "current_step": current_step,
                "total_steps": total_steps,
                "progress_percent": (current_step / total_steps * 100) if total_steps > 0 else 0,
                "current_agent": agent_sequence[current_step] if current_step < len(agent_sequence) else "completed",
                "remaining_agents": agent_sequence[current_step:] if current_step < len(agent_sequence) else []
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    # Nasleđene metode iz v1 (proširene)
    
    def log_agent_action(self, agent_name: str, action: str, data: Dict = None, 
                        execution_time: float = None, success: bool = True, error_message: str = None):
        """Prošireno logovanje akcija agenata"""
        if not self.current_mission_id:
            self.logger.warning("Nema aktivne misije za logovanje")
            return
            
        try:
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.execute('''
                    INSERT INTO agent_log (mission_id, agent_name, action, data, 
                                         execution_time, success, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (self.current_mission_id, agent_name, action, 
                      json.dumps(data) if data else None, 
                      execution_time, success, error_message))
                
        except Exception as e:
            self.logger.error(f"Greška pri logovanju akcije {agent_name}: {e}")
    
    def store_proof_advanced(self, payload: str, url: str, payload_type: str, 
                           response_code: int, response_raw: str,
                           original_payload: str = None, attack_vector: str = None,
                           response_time: float = None, raw_request: str = None,
                           mutation_info: Dict = None, screenshot_path: str = None, 
                           html_path: str = None) -> int:
        """Prošireno čuvanje dokaza"""
        if not self.current_mission_id:
            raise ValueError("Nema aktivne misije")
            
        try:
            with sqlite3.connect(self.poc_db) as conn:
                cursor = conn.execute('''
                    INSERT INTO proofs (mission_id, payload, original_payload, url, payload_type, 
                                      attack_vector, response_code, response_raw, response_time,
                                      raw_request, mutation_info, screenshot_path, html_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (self.current_mission_id, payload, original_payload, url, payload_type, 
                      attack_vector, response_code, response_raw, response_time,
                      raw_request, json.dumps(mutation_info) if mutation_info else None,
                      screenshot_path, html_path))
                
                proof_id = cursor.lastrowid
                
            self.log_agent_action("ProofCollector", "advanced_proof_stored", {
                "proof_id": proof_id,
                "payload_type": payload_type,
                "attack_vector": attack_vector,
                "url": url
            })
            
            return proof_id
            
        except Exception as e:
            self.logger.error(f"Greška pri čuvanju naprednog dokaza: {e}")
            raise
    
    def get_mission_statistics(self, mission_id: str) -> Dict:
        """Detaljne statistike misije"""
        try:
            stats = {
                "mission_info": self.get_mission_data(mission_id),
                "agent_performance": {},
                "payload_stats": {},
                "success_rates": {},
                "timeline": []
            }
            
            # Agent performance
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT agent_name, COUNT(*) as actions, 
                           AVG(execution_time) as avg_time,
                           SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
                    FROM agent_log WHERE mission_id = ?
                    GROUP BY agent_name
                ''', (mission_id,))
                
                for row in cursor.fetchall():
                    stats["agent_performance"][row["agent_name"]] = dict(row)
            
            # Payload statistike
            with sqlite3.connect(self.poc_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT payload_type, COUNT(*) as total,
                           AVG(response_time) as avg_response_time,
                           COUNT(CASE WHEN status = 'confirmed' THEN 1 END) as confirmed
                    FROM proofs WHERE mission_id = ?
                    GROUP BY payload_type
                ''', (mission_id,))
                
                for row in cursor.fetchall():
                    stats["payload_stats"][row["payload_type"]] = dict(row)
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Greška pri čitanju statistike: {e}")
            return {}

# Ostale metode iz v1...
    def create_mission(self, target_url: str, description: str = "") -> str:
        """Jednostavan način kreiranja misije (kompatibilnost sa v1)"""
        mission_json = {
            "target_url": target_url,
            "description": description,
            "mission_type": "standard"
        }
        return self.create_mission_from_json(mission_json)

    def get_mission_data(self, mission_id: str) -> Optional[Dict]:
        """Vraća podatke o misiji"""
        try:
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM missions WHERE mission_id = ?
                ''', (mission_id,))
                
                row = cursor.fetchone()
                if row:
                    data = dict(row)
                    # Parse JSON polja
                    if data.get("target_meta"):
                        data["target_meta"] = json.loads(data["target_meta"])
                    if data.get("recon_data"):
                        data["recon_data"] = json.loads(data["recon_data"])
                    return data
                return None
                
        except Exception as e:
            self.logger.error(f"Greška pri čitanju misije {mission_id}: {e}")
            return None

    def update_mission_status(self, mission_id: str, status: str):
        """Ažurira status misije"""
        try:
            with sqlite3.connect(self.shadowfox_db) as conn:
                conn.execute('''
                    UPDATE missions SET status = ?, 
                    completed_at = CASE WHEN ? = 'completed' THEN CURRENT_TIMESTAMP ELSE completed_at END
                    WHERE mission_id = ?
                ''', (status, status, mission_id))
                
            self.log_agent_action("Operator", "mission_status_updated", {"status": status})
            
        except Exception as e:
            self.logger.error(f"Greška pri ažuriranju statusa misije: {e}")

# Test funkcionalnosti
if __name__ == "__main__":
    # Test JSON misije
    op = ShadowFoxOperator()
    
    test_mission = {
        "target_url": "https://httpbin.org",
        "description": "Test JSON misija",
        "mission_type": "full_scan",
        "target_meta": {
            "domain": "httpbin.org",
            "technologies": ["Python", "Flask"],
            "priority_vectors": ["XSS", "SQLi"]
        },
        "attack_config": {
            "max_payloads_per_type": 25,
            "delay_between_requests": 0.5,
            "stealth_mode": True
        }
    }
    
    mission_id = op.create_mission_from_json(test_mission)
    print(f"Kreirana JSON misija: {mission_id}")
    
    progress = op.get_mission_progress(mission_id)
    print(f"Progress: {progress}")
