#!/usr/bin/env python3
"""
ShadowFox17 - Base Module Class
Bazna klasa koju svi ShadowFox moduli nasljeđuju
"""

import time
import threading
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum

# Import naših core komponenti
from shadowfox_core_db import ShadowFoxDB, MissionData
from shadowfox_event_bus import ShadowFoxEventBus, ShadowFoxEvent, EventType, EventPriority

class ModuleStatus(Enum):
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"

class ModuleCategory(Enum):
    COMMAND = "command"
    INTELLIGENCE = "intelligence"
    PAYLOAD = "payload"
    ATTACK = "attack"
    AI = "ai"
    PROXY = "proxy"
    REPORTING = "reporting"

@dataclass
class ModuleConfig:
    """Konfiguracija modula"""
    enabled: bool = True
    priority: int = 5  # 1-10, 10 = najviši
    max_threads: int = 1
    timeout: int = 300  # sekunde
    retry_count: int = 3
    rate_limit: float = 0.0  # sekunde između poziva
    depends_on: List[str] = None  # lista modula od kojih zavisi
    custom_params: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []
        if self.custom_params is None:
            self.custom_params = {}

class ShadowFoxModule(ABC):
    """
    Bazna klasa za sve ShadowFox module
    Omogućava automatsko povezivanje sa bazom, event busom i AI sistemom
    """
    
    def __init__(self, mission_id: str, db: ShadowFoxDB = None, 
                 event_bus: ShadowFoxEventBus = None, config: ModuleConfig = None):
        
        # Osnovne informacije
        self.module_name = self.__class__.__name__
        self.mission_id = mission_id
        self.module_id = f"{self.module_name}_{int(time.time() * 1000)}"
        
        # Core komponente
        self.db = db or ShadowFoxDB()
        self.event_bus = event_bus or ShadowFoxEventBus()
        self.config = config or ModuleConfig()
        
        # Status tracking
        self.status = ModuleStatus.IDLE
        self.start_time = 0
        self.last_activity = 0
        self.error_count = 0
        self.success_count = 0
        self.total_operations = 0
        
        # Threading
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._thread_pool = []
        self._lock = threading.RLock()
        
        # Rate limiting
        self._last_operation_time = 0
        
        # Event handling
        self._event_handlers = {}
        
        # Logging
        self.logger = logging.getLogger(f"ShadowFox.{self.module_name}")
        
        # Mission data cache
        self._mission_cache = None
        self._cache_expiry = 0
        
        # Performance metrics
        self.metrics = {
            'operations_per_minute': 0,
            'avg_response_time': 0.0,
            'memory_usage': 0,
            'cpu_usage': 0.0
        }
        
        # Registruj osnovne event handlere
        self._register_base_events()
        
        self.logger.info(f"Module {self.module_name} initialized for mission {mission_id}")
    
    # === ABSTRACT METHODS ===
    
    @abstractmethod
    def get_module_info(self) -> Dict[str, Any]:
        """Vraća informacije o modulu"""
        pass
    
    @abstractmethod
    def get_module_category(self) -> ModuleCategory:
        """Vraća kategoriju modula"""
        pass
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Inicijalizuje modul - mora biti implementirano"""
        pass
    
    @abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """Glavna logika modula - mora biti implementirano"""
        pass
    
    @abstractmethod
    async def cleanup(self) -> bool:
        """Čišćenje resursa - mora biti implementirano"""
        pass
    
    # === LIFECYCLE MANAGEMENT ===
    
    async def start(self) -> bool:
        """Pokreće modul"""
        try:
            self.logger.info(f"Starting module {self.module_name}")
            self.status = ModuleStatus.INITIALIZING
            self.start_time = time.time()
            
            # Emit start event
            await self.emit_event(EventType.MODULE_STARTED, {
                'module_name': self.module_name,
                'mission_id': self.mission_id,
                'config': self.config.__dict__
            })
            
            # Inicijalizacija
            if not await self.initialize():
                self.status = ModuleStatus.ERROR
                return False
            
            self.status = ModuleStatus.RUNNING
            self.logger.info(f"Module {self.module_name} started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start module {self.module_name}: {e}")
            self.status = ModuleStatus.ERROR
            await self.emit_event(EventType.MODULE_ERROR, {
                'module_name': self.module_name,
                'error': str(e)
            })
            return False
    
    async def stop(self) -> bool:
        """Zaustavlja modul"""
        try:
            self.logger.info(f"Stopping module {self.module_name}")
            self._stop_event.set()
            
            # Sačekaj da se završe svi thread-ovi
            for thread in self._thread_pool:
                if thread.is_alive():
                    thread.join(timeout=10)
            
            # Cleanup
            await self.cleanup()
            
            self.status = ModuleStatus.STOPPED
            
            # Emit stop event
            await self.emit_event(EventType.MODULE_STOPPED, {
                'module_name': self.module_name,
                'runtime': time.time() - self.start_time,
                'total_operations': self.total_operations,
                'success_rate': self.success_count / max(self.total_operations, 1)
            })
            
            self.logger.info(f"Module {self.module_name} stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping module {self.module_name}: {e}")
            return False
    
    def pause(self):
        """Pauzira modul"""
        self._pause_event.set()
        self.status = ModuleStatus.PAUSED
        self.logger.info(f"Module {self.module_name} paused")
    
    def resume(self):
        """Nastavlja izvršavanje modula"""
        self._pause_event.clear()
        self.status = ModuleStatus.RUNNING
        self.logger.info(f"Module {self.module_name} resumed")
    
    def is_running(self) -> bool:
        """Proverava da li je modul aktivan"""
        return self.status == ModuleStatus.RUNNING and not self._stop_event.is_set()
    
    def should_pause(self) -> bool:
        """Proverava da li treba da se pauzira"""
        if self._pause_event.is_set():
            self._pause_event.wait()  # Čeka da se nastavi
        return False
    
    # === DATABASE OPERATIONS ===
    
    def log_activity(self, action: str, data: Dict = None, success: bool = None, 
                    execution_time: float = None):
        """Loguje aktivnost modula u bazu"""
        self.db.log_module_activity(
            self.mission_id, self.module_name, action, data, success, execution_time
        )
        self.last_activity = time.time()
        
        if success is not None:
            self.total_operations += 1
            if success:
                self.success_count += 1
            else:
                self.error_count += 1
    
    def get_mission_data(self, use_cache: bool = True) -> Optional[MissionData]:
        """Dobija podatke o misiji sa cache-om"""
        current_time = time.time()
        
        if use_cache and self._mission_cache and current_time < self._cache_expiry:
            return self._mission_cache
        
        self._mission_cache = self.db.get_mission(self.mission_id)
        self._cache_expiry = current_time + 60  # Cache 1 minut
        
        return self._mission_cache
    
    def store_intelligence(self, data_type: str, content: str, confidence: float) -> str:
        """Čuva intelligence podatke"""
        return self.db.store_intelligence(
            self.mission_id, data_type, content, confidence, self.module_name
        )
    
    def get_intelligence(self, data_type: str = None, min_confidence: float = 0.0):
        """Dobija intelligence podatke"""
        return self.db.get_intelligence(self.mission_id, data_type, min_confidence)
    
    def store_payload(self, payload_type: str, content: str, ai_score: float = 0.0) -> str:
        """Čuva payload"""
        return self.db.store_payload(self.mission_id, payload_type, content, ai_score)
    
    def get_best_payloads(self, payload_type: str, limit: int = 10):
        """Dobija najbolje payload-e"""
        return self.db.get_best_payloads(self.mission_id, payload_type, limit)
    
    def store_vulnerability(self, url: str, vuln_type: str, severity: str, 
                          payload_used: str, response_data: str) -> str:
        """Čuva ranjivost"""
        return self.db.store_vulnerability(
            self.mission_id, url, vuln_type, severity, payload_used, response_data
        )
    
    # === EVENT SYSTEM ===
    
    async def emit_event(self, event_type: EventType, data: Dict, 
                        priority: EventPriority = EventPriority.NORMAL,
                        correlation_id: str = None):
        """Emituje event"""
        event = ShadowFoxEvent(
            event_type=event_type,
            mission_id=self.mission_id,
            source_module=self.module_name,
            data=data,
            timestamp=time.time(),
            priority=priority,
            correlation_id=correlation_id
        )
        
        await self.event_bus.emit_event(event)
    
    def register_event_handler(self, event_types: List[EventType], 
                             callback: Callable, priority: int = 0):
        """Registruje event handler"""
        handler_id = self.event_bus.register_handler(
            event_types, callback, self.module_name, priority
        )
        self._event_handlers[handler_id] = callback
        return handler_id
    
    def _register_base_events(self):
        """Registruje osnovne event handlere"""
        # Handler za mission events
        self.register_event_handler(
            [EventType.MISSION_PHASE_CHANGED, EventType.MISSION_COMPLETED],
            self._handle_mission_events
        )
        
        # Handler za AI decision events
        self.register_event_handler(
            [EventType.AI_DECISION],
            self._handle_ai_events
        )
    
    async def _handle_mission_events(self, event: ShadowFoxEvent):
        """Obrađuje mission events"""
        if event.event_type == EventType.MISSION_COMPLETED:
            await self.stop()
        elif event.event_type == EventType.MISSION_PHASE_CHANGED:
            # Invalidate mission cache
            self._mission_cache = None
    
    async def _handle_ai_events(self, event: ShadowFoxEvent):
        """Obrađuje AI decision events"""
        # Implementiraj po potrebi u derived klasama
        pass
    
    # === RATE LIMITING ===
    
    def _apply_rate_limit(self):
        """Primenjuje rate limiting"""
        if self.config.rate_limit > 0:
            time_since_last = time.time() - self._last_operation_time
            if time_since_last < self.config.rate_limit:
                sleep_time = self.config.rate_limit - time_since_last
                time.sleep(sleep_time)
        
        self._last_operation_time = time.time()
    
    # === UTILITY METHODS ===
    
    def get_status_info(self) -> Dict[str, Any]:
        """Vraća detaljne informacije o statusu modula"""
        runtime = time.time() - self.start_time if self.start_time > 0 else 0
        
        return {
            'module_name': self.module_name,
            'module_id': self.module_id,
            'mission_id': self.mission_id,
            'status': self.status.value,
            'category': self.get_module_category().value,
            'runtime': runtime,
            'total_operations': self.total_operations,
            'success_count': self.success_count,
            'error_count': self.error_count,
            'success_rate': self.success_count / max(self.total_operations, 1),
            'last_activity': self.last_activity,
            'config': self.config.__dict__,
            'metrics': self.metrics
        }
    
    def update_metrics(self, operations_delta: int = 0, response_time: float = None):
        """Ažurira performance metrike"""
        if operations_delta > 0:
            # Izračunaj operations per minute
            runtime = time.time() - self.start_time
            if runtime > 0:
                self.metrics['operations_per_minute'] = (self.total_operations / runtime) * 60
        
        if response_time is not None:
            # Ažuriraj prosečno vreme odgovora
            if self.metrics['avg_response_time'] == 0:
                self.metrics['avg_response_time'] = response_time
            else:
                self.metrics['avg_response_time'] = (
                    (self.metrics['avg_response_time'] * (self.total_operations - 1)) + response_time
                ) / self.total_operations
    
    # === THREADING HELPERS ===
    
    def run_in_thread(self, target_func: Callable, *args, **kwargs) -> threading.Thread:
        """Pokreće funkciju u novom thread-u"""
        def wrapper():
            try:
                target_func(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"Thread error in {self.module_name}: {e}")
                self.error_count += 1
        
        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()
        self._thread_pool.append(thread)
        
        # Cleanup finished threads
        self._thread_pool = [t for t in self._thread_pool if t.is_alive()]
        
        return thread
    
    # === AI INTEGRATION ===
    
    def learn_from_success(self, pattern_type: str, pattern_data: str, confidence: float):
        """Čuva uspešne patterns za AI learning"""
        self.db.store_ai_learning(
            self.mission_id, pattern_type, pattern_data, True, confidence, self.module_name
        )
    
    def learn_from_failure(self, pattern_type: str, pattern_data: str, confidence: float):
        """Čuva neuspešne patterns za AI learning"""
        self.db.store_ai_learning(
            self.mission_id, pattern_type, pattern_data, False, confidence, self.module_name
        )
    
    def get_ai_patterns(self, pattern_type: str, success_only: bool = True):
        """Dobija AI patterns za učenje"""
        return self.db.get_ai_patterns(pattern_type, success_only)
    
    # === CONTEXT MANAGER SUPPORT ===
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()
    
    def __enter__(self):
        """Context manager entry"""
        asyncio.run(self.start())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        asyncio.run(self.stop())


# === DECORATOR UTILITIES ===

def log_operation(operation_name: str):
    """Decorator za logovanje operacija"""
    def decorator(func):
        async def async_wrapper(self, *args, **kwargs):
            start_time = time.time()
            try:
                result = await func(self, *args, **kwargs)
                execution_time = time.time() - start_time
                self.log_activity(operation_name, {'args': args, 'kwargs': kwargs}, 
                                True, execution_time)
                self.update_metrics(1, execution_time)
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                self.log_activity(operation_name, {'error': str(e)}, False, execution_time)
                raise
        
        def sync_wrapper(self, *args, **kwargs):
            start_time = time.time()
            try:
                result = func(self, *args, **kwargs)
                execution_time = time.time() - start_time
                self.log_activity(operation_name, {'args': args, 'kwargs': kwargs}, 
                                True, execution_time)
                self.update_metrics(1, execution_time)
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                self.log_activity(operation_name, {'error': str(e)}, False, execution_time)
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

def rate_limited(func):
    """Decorator za rate limiting"""
    async def async_wrapper(self, *args, **kwargs):
        self._apply_rate_limit()
        return await func(self, *args, **kwargs)
    
    def sync_wrapper(self, *args, **kwargs):
        self._apply_rate_limit()
        return func(self, *args, **kwargs)
    
    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


# === USAGE EXAMPLE ===
if __name__ == "__main__":
    
    # Primer implementacije modula
    class ExampleModule(ShadowFoxModule):
        
        def get_module_info(self) -> Dict[str, Any]:
            return {
                'name': 'ExampleModule',
                'version': '1.0.0',
                'description': 'Test module for ShadowFox',
                'author': 'ShadowFox Team'
            }
        
        def get_module_category(self) -> ModuleCategory:
            return ModuleCategory.INTELLIGENCE
        
        async def initialize(self) -> bool:
            self.logger.info("Initializing ExampleModule")
            return True
        
        @log_operation("example_scan")
        @rate_limited
        async def execute(self) -> Dict[str, Any]:
            # Simulacija rada
            await asyncio.sleep(1)
            
            # Store some intelligence
            intel_id = self.store_intelligence("test", "example data", 0.8)
            
            # Emit event
            await self.emit_event(EventType.TARGET_DISCOVERED, {
                'target': 'example.com',
                'intel_id': intel_id
            })
            
            return {'status': 'success', 'intel_id': intel_id}
        
        async def cleanup(self) -> bool:
            self.logger.info("Cleaning up ExampleModule")
            return True
    
    # Test
    async def test_module():
        db = ShadowFoxDB()
        mission_id = db.create_mission("https://example.com")
        
        config = ModuleConfig(rate_limit=0.5, max_threads=2)
        
        async with ExampleModule(mission_id, db, config=config) as module:
            result = await module.execute()
            print(f"Module result: {result}")
            print(f"Module status: {module.get_status_info()}")
    
    # Pokreni test
    asyncio.run(test_module())
