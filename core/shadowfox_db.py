#!/usr/bin/env python3
"""
ShadowFox17 - Core Database System
Centralizovana baza za sve module sa AI learning capabilities
"""

import sqlite3
import json
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import threading
from contextlib import contextmanager

class ShadowFoxDB:
    def __init__(self, db_path: str = "data/shadowfox.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """Inicijalizuje sve potrebne tabele"""
        with self.get_connection() as conn:
            # Missions table - glavna tabela za tracking misija
            conn.execute('''
                CREATE TABLE IF NOT EXISTS missions (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    config JSON,
                    results_summary JSON,
                    completed_at TIMESTAMP
                )
            ''')
            
            # Module activities - log svih aktivnosti modula
            conn.execute('''
                CREATE TABLE IF NOT EXISTS module_activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT,
                    module_name TEXT,
                    action TEXT,
                    data JSON,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN,
                    execution_time REAL,
                    FOREIGN KEY (mission_id) REFERENCES missions (id)
                )
            ''')
            
            # Payloads - centralni storage za sve payloade
            conn.execute('''
                CREATE TABLE IF NOT EXISTS payloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_hash TEXT UNIQUE,
                    payload_text TEXT,
                    payload_type TEXT,
                    mutation_level INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 0.0,
                    created_by TEXT,
                    times_used INTEGER DEFAULT 0,
                    last_success TIMESTAMP,
                    metadata JSON
                )
            ''')
            
            # Vulnerabilities - svi pronađeni vulnerability
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT,
                    vuln_type TEXT,
                    endpoint TEXT,
                    payload_id INTEGER,
                    severity TEXT,
                    proof_data JSON,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verified BOOLEAN DEFAULT FALSE,
                    bounty_potential REAL,
                    FOREIGN KEY (mission_id) REFERENCES missions (id),
                    FOREIGN KEY (payload_id) REFERENCES payloads (id)
                )
            ''')
            
            # Intelligence - AI learning data
            conn.execute('''
                CREATE TABLE IF NOT EXISTS intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT,
                    pattern_data JSON,
                    success_correlation REAL,
                    frequency INTEGER DEFAULT 1,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    confidence_score REAL,
                    ai_notes TEXT
                )
            ''')
            
            # Event bus - komunikacija između modula
            conn.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT,
                    event_type TEXT,
                    event_data JSON,
                    processed BOOLEAN DEFAULT FALSE,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (mission_id) REFERENCES missions (id)
                )
            ''')
            
            # Performance metrics - tracking performansi
            conn.execute('''
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT,
                    module_name TEXT,
                    metric_name TEXT,
                    metric_value REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (mission_id) REFERENCES missions (id)
                )
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Thread-safe connection manager"""
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                yield conn
            finally:
                conn.close()
    
    # MISSION MANAGEMENT
    def create_mission(self, target_url: str, config: Dict = None) -> str:
        """Kreira novu misiju i vraća mission ID"""
        mission_id = hashlib.md5(f"{target_url}_{time.time()}".encode()).hexdigest()[:16]
        config = config or {}
        
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO missions (id, target_url, config)
                VALUES (?, ?, ?)
            ''', (mission_id, target_url, json.dumps(config)))
            conn.commit()
        
        self.publish_event(mission_id, 'mission_created', {'target_url': target_url})
        return mission_id
    
    def get_mission(self, mission_id: str) -> Optional[Dict]:
        """Vraća mission data"""
        with self.get_connection() as conn:
            row = conn.execute(
                'SELECT * FROM missions WHERE id = ?', (mission_id,)
            ).fetchone()
            
            if row:
                mission = dict(row)
                mission['config'] = json.loads(mission['config'] or '{}')
                mission['results_summary'] = json.loads(mission['results_summary'] or '{}')
                return mission
        return None
    
    def update_mission_status(self, mission_id: str, status: str, results: Dict = None):
        """Updates mission status i results"""
        with self.get_connection() as conn:
            if status == 'completed':
                conn.execute('''
                    UPDATE missions 
                    SET status = ?, results_summary = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (status, json.dumps(results or {}), mission_id))
            else:
                conn.execute('''
                    UPDATE missions SET status = ? WHERE id = ?
                ''', (status, mission_id))
            conn.commit()
    
    # MODULE ACTIVITY LOGGING
    def log_module_activity(self, mission_id: str, module_name: str, action: str, 
                          data: Dict, success: bool = True, execution_time: float = 0.0):
        """Loguje aktivnost modula"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO module_activities 
                (mission_id, module_name, action, data, success, execution_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (mission_id, module_name, action, json.dumps(data), success, execution_time))
            conn.commit()
    
    def get_module_activities(self, mission_id: str, module_name: str = None) -> List[Dict]:
        """Vraća aktivnosti modula"""
        with self.get_connection() as conn:
            if module_name:
                cursor = conn.execute('''
                    SELECT * FROM module_activities 
                    WHERE mission_id = ? AND module_name = ?
                    ORDER BY timestamp DESC
                ''', (mission_id, module_name))
            else:
                cursor = conn.execute('''
                    SELECT * FROM module_activities 
                    WHERE mission_id = ?
                    ORDER BY timestamp DESC
                ''', (mission_id,))
            
            activities = []
            for row in cursor.fetchall():
                activity = dict(row)
                activity['data'] = json.loads(activity['data'] or '{}')
                activities.append(activity)
            return activities
    
    # PAYLOAD MANAGEMENT
    def store_payload(self, payload_text: str, payload_type: str, created_by: str, 
                     mutation_level: int = 0, metadata: Dict = None) -> int:
        """Čuva payload i vraća ID"""
        payload_hash = hashlib.sha256(payload_text.encode()).hexdigest()
        metadata = metadata or {}
        
        with self.get_connection() as conn:
            try:
                cursor = conn.execute('''
                    INSERT INTO payloads 
                    (payload_hash, payload_text, payload_type, mutation_level, created_by, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (payload_hash, payload_text, payload_type, mutation_level, 
                      created_by, json.dumps(metadata)))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                # Payload već postoji, vraćamo postojeći ID
                row = conn.execute(
                    'SELECT id FROM payloads WHERE payload_hash = ?', (payload_hash,)
                ).fetchone()
                return row[0] if row else None
    
    def get_payload(self, payload_id: int) -> Optional[Dict]:
        """Vraća payload po ID"""
        with self.get_connection() as conn:
            row = conn.execute(
                'SELECT * FROM payloads WHERE id = ?', (payload_id,)
            ).fetchone()
            
            if row:
                payload = dict(row)
                payload['metadata'] = json.loads(payload['metadata'] or '{}')
                return payload
        return None
    
    def update_payload_success(self, payload_id: int, success: bool = True):
        """Updates payload success metrics"""
        with self.get_connection() as conn:
            if success:
                conn.execute('''
                    UPDATE payloads 
                    SET times_used = times_used + 1, 
                        last_success = CURRENT_TIMESTAMP,
                        success_rate = CASE 
                            WHEN times_used = 0 THEN 1.0
                            ELSE (success_rate * times_used + 1.0) / (times_used + 1)
                        END
                    WHERE id = ?
                ''', (payload_id,))
            else:
                conn.execute('''
                    UPDATE payloads 
                    SET times_used = times_used + 1,
                        success_rate = CASE 
                            WHEN times_used = 0 THEN 0.0
                            ELSE (success_rate * times_used) / (times_used + 1)
                        END
                    WHERE id = ?
                ''', (payload_id,))
            conn.commit()
    
    def get_best_payloads(self, payload_type: str, limit: int = 10) -> List[Dict]:
        """Vraća najbolje payloade po success rate"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM payloads 
                WHERE payload_type = ? AND times_used > 0
                ORDER BY success_rate DESC, times_used DESC
                LIMIT ?
            ''', (payload_type, limit))
            
            payloads = []
            for row in cursor.fetchall():
                payload = dict(row)
                payload['metadata'] = json.loads(payload['metadata'] or '{}')
                payloads.append(payload)
            return payloads
    
    # VULNERABILITY MANAGEMENT
    def store_vulnerability(self, mission_id: str, vuln_type: str, endpoint: str,
                          payload_id: int, severity: str, proof_data: Dict,
                          bounty_potential: float = 0.0) -> int:
        """Čuva pronađenu vulnerability"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO vulnerabilities 
                (mission_id, vuln_type, endpoint, payload_id, severity, proof_data, bounty_potential)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (mission_id, vuln_type, endpoint, payload_id, severity, 
                  json.dumps(proof_data), bounty_potential))
            conn.commit()
            
            vuln_id = cursor.lastrowid
            self.publish_event(mission_id, 'vulnerability_found', {
                'vuln_id': vuln_id,
                'type': vuln_type,
                'severity': severity,
                'endpoint': endpoint
            })
            return vuln_id
    
    def get_vulnerabilities(self, mission_id: str) -> List[Dict]:
        """Vraća sve vulnerability za misiju"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT v.*, p.payload_text, p.payload_type 
                FROM vulnerabilities v
                LEFT JOIN payloads p ON v.payload_id = p.id
                WHERE v.mission_id = ?
                ORDER BY v.discovered_at DESC
            ''', (mission_id,))
            
            vulns = []
            for row in cursor.fetchall():
                vuln = dict(row)
                vuln['proof_data'] = json.loads(vuln['proof_data'] or '{}')
                vulns.append(vuln)
            return vulns
    
    # INTELLIGENCE & AI LEARNING
    def store_intelligence(self, pattern_type: str, pattern_data: Dict, 
                         success_correlation: float, confidence_score: float,
                         ai_notes: str = ""):
        """Čuva AI learning patterns"""
        pattern_hash = hashlib.md5(json.dumps(pattern_data, sort_keys=True).encode()).hexdigest()
        
        with self.get_connection() as conn:
            # Proverava da li pattern već postoji
            existing = conn.execute('''
                SELECT id, frequency FROM intelligence 
                WHERE pattern_type = ? AND pattern_data = ?
            ''', (pattern_type, json.dumps(pattern_data))).fetchone()
            
            if existing:
                # Update postojeći pattern
                conn.execute('''
                    UPDATE intelligence 
                    SET frequency = frequency + 1,
                        success_correlation = (success_correlation * frequency + ?) / (frequency + 1),
                        confidence_score = ?,
                        last_seen = CURRENT_TIMESTAMP,
                        ai_notes = ?
                    WHERE id = ?
                ''', (success_correlation, confidence_score, ai_notes, existing[0]))
            else:
                # Dodaj novi pattern
                conn.execute('''
                    INSERT INTO intelligence 
                    (pattern_type, pattern_data, success_correlation, confidence_score, ai_notes)
                    VALUES (?, ?, ?, ?, ?)
                ''', (pattern_type, json.dumps(pattern_data), success_correlation, 
                      confidence_score, ai_notes))
            conn.commit()
    
    def get_intelligence_patterns(self, pattern_type: str = None, min_confidence: float = 0.5) -> List[Dict]:
        """Vraća AI learning patterns"""
        with self.get_connection() as conn:
            if pattern_type:
                cursor = conn.execute('''
                    SELECT * FROM intelligence 
                    WHERE pattern_type = ? AND confidence_score >= ?
                    ORDER BY success_correlation DESC, frequency DESC
                ''', (pattern_type, min_confidence))
            else:
                cursor = conn.execute('''
                    SELECT * FROM intelligence 
                    WHERE confidence_score >= ?
                    ORDER BY success_correlation DESC, frequency DESC
                ''', (min_confidence,))
            
            patterns = []
            for row in cursor.fetchall():
                pattern = dict(row)
                pattern['pattern_data'] = json.loads(pattern['pattern_data'] or '{}')
                patterns.append(pattern)
            return patterns
    
    # EVENT BUS SYSTEM
    def publish_event(self, mission_id: str, event_type: str, event_data: Dict):
        """Publishes event na event bus"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO events (mission_id, event_type, event_data)
                VALUES (?, ?, ?)
            ''', (mission_id, event_type, json.dumps(event_data)))
            conn.commit()
    
    def get_unprocessed_events(self, event_type: str = None) -> List[Dict]:
        """Vraća neprocessed events"""
        with self.get_connection() as conn:
            if event_type:
                cursor = conn.execute('''
                    SELECT * FROM events 
                    WHERE processed = FALSE AND event_type = ?
                    ORDER BY timestamp ASC
                ''', (event_type,))
            else:
                cursor = conn.execute('''
                    SELECT * FROM events 
                    WHERE processed = FALSE
                    ORDER BY timestamp ASC
                ''')
            
            events = []
            for row in cursor.fetchall():
                event = dict(row)
                event['event_data'] = json.loads(event['event_data'] or '{}')
                events.append(event)
            return events
    
    def mark_event_processed(self, event_id: int):
        """Označava event kao processed"""
        with self.get_connection() as conn:
            conn.execute('UPDATE events SET processed = TRUE WHERE id = ?', (event_id,))
            conn.commit()
    
    # PERFORMANCE METRICS
    def store_metric(self, mission_id: str, module_name: str, metric_name: str, metric_value: float):
        """Čuva performance metriku"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO performance_metrics (mission_id, module_name, metric_name, metric_value)
                VALUES (?, ?, ?, ?)
            ''', (mission_id, module_name, metric_name, metric_value))
            conn.commit()
    
    def get_metrics(self, mission_id: str, module_name: str = None) -> List[Dict]:
        """Vraća performance metrics"""
        with self.get_connection() as conn:
            if module_name:
                cursor = conn.execute('''
                    SELECT * FROM performance_metrics 
                    WHERE mission_id = ? AND module_name = ?
                    ORDER BY timestamp DESC
                ''', (mission_id, module_name))
            else:
                cursor = conn.execute('''
                    SELECT * FROM performance_metrics 
                    WHERE mission_id = ?
                    ORDER BY timestamp DESC
                ''', (mission_id,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # UTILITY METHODS
    def get_mission_stats(self, mission_id: str) -> Dict:
        """Vraća kompletnu statistiku misije"""
        with self.get_connection() as conn:
            stats = {}
            
            # Osnovne info
            mission = dict(conn.execute(
                'SELECT * FROM missions WHERE id = ?', (mission_id,)
            ).fetchone() or {})
            
            # Broj aktivnosti po modulima
            activities = conn.execute('''
                SELECT module_name, COUNT(*) as count, 
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) as successes
                FROM module_activities WHERE mission_id = ?
                GROUP BY module_name
            ''', (mission_id,)).fetchall()
            
            # Broj vulnerability po tipovima
            vulns = conn.execute('''
                SELECT vuln_type, COUNT(*) as count, severity
                FROM vulnerabilities WHERE mission_id = ?
                GROUP BY vuln_type, severity
            ''', (mission_id,)).fetchall()
            
            # Top payloads
            top_payloads = conn.execute('''
                SELECT p.payload_type, COUNT(*) as usage_count
                FROM vulnerabilities v
                JOIN payloads p ON v.payload_id = p.id
                WHERE v.mission_id = ?
                GROUP BY p.payload_type
                ORDER BY usage_count DESC
            ''', (mission_id,)).fetchall()
            
            stats = {
                'mission': dict(mission) if mission else {},
                'module_activities': [dict(row) for row in activities],
                'vulnerabilities': [dict(row) for row in vulns],
                'top_payloads': [dict(row) for row in top_payloads]
            }
            
            return stats
    
    def cleanup_old_data(self, days_old: int = 30):
        """Briše stare podatke starije od X dana"""
        with self.get_connection() as conn:
            conn.execute('''
                DELETE FROM module_activities 
                WHERE timestamp < datetime('now', '-{} days')
            '''.format(days_old))
            
            conn.execute('''
                DELETE FROM events 
                WHERE processed = TRUE AND timestamp < datetime('now', '-{} days')
            '''.format(days_old))
            
            conn.execute('''
                DELETE FROM performance_metrics 
                WHERE timestamp < datetime('now', '-{} days')
            '''.format(days_old))
            
            conn.commit()

# Singleton instance
_db_instance = None

def get_db() -> ShadowFoxDB:
    """Returns singleton database instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = ShadowFoxDB()
    return _db_instance
