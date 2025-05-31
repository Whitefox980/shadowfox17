#!/usr/bin/env python3
"""
ShadowFox17 - Core Module Orchestrator
Inteligentno upravljanje i koordinacija svih ShadowFox modula
"""

import os
import sys
import importlib
import inspect
import asyncio
import threading
import time
import json
import traceback
from typing import Dict, List, Any, Optional, Type, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from collections import defaultdict, OrderedDict

# Import core components
from core.shadowfox_db import ShadowFoxDB
from core.shadowfox_event_bus import ShadowFoxEventBus, ShadowFoxEvent, EventType, EventPriority

class ModuleStatus(Enum):
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"

class ModulePriority(Enum):
    CRITICAL = 1     # Core system modules
    HIGH = 2         # Main attack modules
    NORMAL = 3       # Standard modules
    LOW = 4          # Optional/utility modules

@dataclass
class ModuleConfig:
    name: str
    file_path: str
    class_name: str
    dependencies: List[str] = field(default_factory=list)
    priority: ModulePriority = ModulePriority.NORMAL
    auto_start: bool = True
    max_restart_attempts: int = 3
    restart_delay: float = 5.0
    timeout: float = 30.0
    config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ModuleInstance:
    config: ModuleConfig
    module_class: Type
    instance: Any = None
    status: ModuleStatus = ModuleStatus.UNLOADED
    load_time: float = 0.0
    start_time: float = 0.0
    restart_count: int = 0
    last_error: str = ""
    performance_stats: Dict = field(default_factory=lambda: {
        'operations_count': 0,
        'success_count': 0,
        'error_count': 0,
        'avg_response_time': 0.0,
        'memory_usage': 0,
        'cpu_usage': 0.0
    })

class BaseShadowFoxModule:
    """
    Bazna klasa koju svi ShadowFox moduli nasleđuju
    """
    
    def __init__(self, mission_id: str, db: ShadowFoxDB, event_bus: ShadowFoxEventBus, config: Dict = None):
        self.mission_id = mission_id
        self.db = db
        self.event_bus = event_bus
        self.config = config or {}
        self.module_name = self.__class__.__name__
        self.status = ModuleStatus.LOADING
        self.start_time = time.time()
        self.logger = logging.getLogger(f"ShadowFox.{self.module_name}")
        
        # Performance tracking
        self._operation_count = 0
        self._success_count = 0
        self._error_count = 0
        self._total_response_time = 0.0
        
    async def initialize(self) -> bool:
        """Override u konkretnim modulima"""
        try:
            self.status = ModuleStatus.INITIALIZING
            # Default initialization logic
            await self._register_event_handlers()
            self.status = ModuleStatus.RUNNING
            self.log_activity("initialized", {"status": "success"})
            return True
        except Exception as e:
            self.status = ModuleStatus.ERROR
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    async def start(self) -> bool:
        """Override u konkretnim modulima za main logic"""
        self.logger.info(f"{self.module_name} started")
        return True
    
    async def stop(self) -> bool:
        """Graceful shutdown"""
        self.status = ModuleStatus.STOPPED
        self.logger.info(f"{self.module_name} stopped")
        return True
    
    async def pause(self) -> bool:
        """Pauza modula"""
        self.status = ModuleStatus.PAUSED
        return True
    
    async def resume(self) -> bool:
        """Nastavak rada modula"""
        self.status = ModuleStatus.RUNNING
        return True
    
    async def _register_event_handlers(self):
        """Registruje event handlers - override u konkretnim modulima"""
        pass
    
    def log_activity(self, action: str, data: Dict = None, success: bool = None, execution_time: float = None):
        """Loguje aktivnost modula"""
        self.db.log_module_activity(
            mission_id=self.mission_id,
            module_name=self.module_name,
            action=action,
            data=data,
            success=success,
            execution_time=execution_time
        )
    
    def emit_event(self, event_type: EventType, data: Dict, priority: EventPriority = EventPriority.NORMAL):
        """Emituje event"""
        event = ShadowFoxEvent(
            event_type=event_type,
            mission_id=self.mission_id,
            source_module=self.module_name,
            data=data,
            timestamp=time.time(),
            priority=priority
        )
        asyncio.create_task(self.event_bus.publish(event))
    
    def update_performance_stats(self, success: bool, response_time: float = 0.0):
        """Ažurira performance statistike"""
        self._operation_count += 1
        if success:
            self._success_count += 1
        else:
            self._error_count += 1
        self._total_response_time += response_time
    
    def get_performance_stats(self) -> Dict:
        """Vraća performance statistike"""
        return {
            'operations_count': self._operation_count,
            'success_count': self._success_count,
            'error_count': self._error_count,
            'success_rate': self._success_count / max(1, self._operation_count),
            'avg_response_time': self._total_response_time / max(1, self._operation_count),
            'uptime': time.time() - self.start_time,
            'status': self.status.value
        }

class ShadowFoxOrchestrator:
    """
    Glavni orkestrator koji upravlja svim ShadowFox modulima
    """
    
    def __init__(self, db: ShadowFoxDB, event_bus: ShadowFoxEventBus):
        self.db = db
        self.event_bus = event_bus
        self.modules: Dict[str, ModuleInstance] = OrderedDict()
        self.module_configs: Dict[str, ModuleConfig] = {}
        self.dependency_graph: Dict[str, List[str]] = defaultdict(list)
        self.reverse_dependencies: Dict[str, List[str]] = defaultdict(list)
        
        # Runtime state
        self.mission_id: Optional[str] = None
        self.is_running = False
        self._shutdown_event = asyncio.Event()
        self._lock = asyncio.Lock()
        
        # AI Decision Engine
        self.ai_strategies: Dict[str, Callable] = {}
        self.module_performance_history: Dict[str, List[Dict]] = defaultdict(list)
        
        # Monitoring
        self.logger = logging.getLogger("ShadowFoxOrchestrator")
        self._monitor_task = None
        
        # Register core event handlers
        self._register_core_handlers()
        
        # Load default module configurations
        self._load_default_configurations()
    async def initialize(self):
        """
        Pokreće inicijalizaciju svih modula i sistema
        (placeholder za sad)
        """
        self.logger.info("ShadowFoxOrchestrator.initialize() pozvan — OK")
    
    def _register_core_handlers(self):
        """Registruje core event handlers"""
        self.event_bus.register_handler(
            [EventType.MODULE_ERROR], 
            self._handle_module_error, 
            "orchestrator",
            priority=10
        )
        
        self.event_bus.register_handler(
            [EventType.VULNERABILITY_FOUND],
            self._handle_vulnerability_found,
            "orchestrator",
            priority=8
        )
    async def _handle_ai_decision(self, event: ShadowFoxEvent):
        """
        Obrada AI odluka — placeholder funkcija
        """
        self.logger.info(f"[🧠 AI-Decision] Primljen AI event: {event}")
        
        self.event_bus.register_handler(
            [EventType.AI_DECISION],
            self._handle_ai_decision,
            "orchestrator", 
            priority=9
        )
    
    def _load_default_configurations(self):
        """Učitava default konfiguracije za module"""
        
        # Core modules - kritični za rad sistema
        self.register_module_config(ModuleConfig(
            name="mission_controller",
            file_path="modules/command/mission_controller.py",
            class_name="MissionController",
            priority=ModulePriority.CRITICAL,
            dependencies=[],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="operator",
            file_path="modules/command/operator.py", 
            class_name="ShadowOperator",
            priority=ModulePriority.CRITICAL,
            dependencies=["mission_controller"],
            auto_start=True
        ))
        
        # Intelligence modules
        self.register_module_config(ModuleConfig(
            name="shadow_spider",
            file_path="modules/intelligence/shadow_spider.py",
            class_name="ShadowSpider",
            priority=ModulePriority.HIGH,
            dependencies=["mission_controller"],
            auto_start=True,
            config={"crawl_depth": 3, "ai_scoring": True}
        ))
        
        self.register_module_config(ModuleConfig(
            name="dom_collector", 
            file_path="modules/intelligence/dom_collector.py",
            class_name="DOMCollector",
            priority=ModulePriority.NORMAL,
            dependencies=["shadow_spider"],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="pathfinder",
            file_path="modules/intelligence/pathfinder.py", 
            class_name="PathFinder",
            priority=ModulePriority.HIGH,
            dependencies=["shadow_spider", "dom_collector"],
            auto_start=True
        ))
        
        # Payload modules
        self.register_module_config(ModuleConfig(
            name="payload_seeder",
            file_path="modules/payloads/payload_seeder.py",
            class_name="PayloadSeeder", 
            priority=ModulePriority.HIGH,
            dependencies=["mission_controller"],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="rainbow_mutation",
            file_path="modules/payloads/rainbow_mutation.py",
            class_name="RainbowMutation",
            priority=ModulePriority.NORMAL,
            dependencies=["payload_seeder"],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="mutation_engine",
            file_path="modules/payloads/mutation_engine.py",
            class_name="MutationEngine",
            priority=ModulePriority.HIGH,
            dependencies=["payload_seeder"],
            auto_start=True
        ))
        
        # Attack modules
        self.register_module_config(ModuleConfig(
            name="smart_shadow_agent",
            file_path="modules/attacks/smart_shadow_agent.py", 
            class_name="SmartShadowAgent",
            priority=ModulePriority.HIGH,
            dependencies=["payload_seeder", "mutation_engine", "pathfinder"],
            auto_start=True,
            config={"max_concurrent_attacks": 10, "ai_guided": True}
        ))
        
        self.register_module_config(ModuleConfig(
            name="fuzz_engine",
            file_path="modules/attacks/fuzz_engine.py",
            class_name="FuzzEngine", 
            priority=ModulePriority.NORMAL,
            dependencies=["payload_seeder"],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="xse_engine",
            file_path="modules/attacks/xse_engine.py",
            class_name="XSEEngine",
            priority=ModulePriority.NORMAL, 
            dependencies=["payload_seeder", "mutation_engine"],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="ghost_threads",
            file_path="modules/attacks/ghost_threads.py",
            class_name="GhostThreads",
            priority=ModulePriority.NORMAL,
            dependencies=["payload_seeder"],
            auto_start=True,
            config={"max_threads": 20}
        ))
        
        # AI modules
        self.register_module_config(ModuleConfig(
            name="ai_brain",
            file_path="modules/ai/ai_brain.py",
            class_name="AIBrain",
            priority=ModulePriority.HIGH,
            dependencies=["mission_controller"],
            auto_start=True,
            config={"decision_threshold": 0.7, "learning_rate": 0.1}
        ))
        
        self.register_module_config(ModuleConfig(
            name="explainable_ai",
            file_path="modules/ai/explainable_ai.py", 
            class_name="ExplainableAI",
            priority=ModulePriority.NORMAL,
            dependencies=["ai_brain"],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="taktician_agent",
            file_path="modules/ai/taktician_agent.py",
            class_name="TakticianAgent",
            priority=ModulePriority.HIGH,
            dependencies=["ai_brain", "pathfinder"],
            auto_start=True
        ))
        
        # Proxy modules
        self.register_module_config(ModuleConfig(
            name="shadow_proxy",
            file_path="modules/proxy/shadow_proxy.py",
            class_name="ShadowProxy", 
            priority=ModulePriority.HIGH,
            dependencies=["mission_controller"],
            auto_start=False,  # Optional
            config={"port": 8080, "ai_injection": True}
        ))
        
        self.register_module_config(ModuleConfig(
            name="traffic_shaper",
            file_path="modules/proxy/traffic_shaper.py",
            class_name="TrafficShaper",
            priority=ModulePriority.NORMAL,
            dependencies=["shadow_proxy"],
            auto_start=False
        ))
        
        # Reporting modules  
        self.register_module_config(ModuleConfig(
            name="proof_collector",
            file_path="modules/reporting/proof_collector.py",
            class_name="ProofCollector",
            priority=ModulePriority.NORMAL,
            dependencies=["mission_controller"],
            auto_start=True
        ))
        
        self.register_module_config(ModuleConfig(
            name="pdf_exporter", 
            file_path="modules/reporting/pdf_exporter.py",
            class_name="PDFExporter",
            priority=ModulePriority.LOW,
            dependencies=["proof_collector"],
            auto_start=False
        ))
        
        # Utility modules
        self.register_module_config(ModuleConfig(
            name="vulnerability_mapper",
            file_path="modules/intelligence/vulnerability_mapper.py",
            class_name="VulnerabilityMapper",
            priority=ModulePriority.NORMAL,
            dependencies=["smart_shadow_agent", "pathfinder"],
            auto_start=True
        ))
    
    def register_module_config(self, config: ModuleConfig):
        """Registruje konfiguraciju modula"""
        self.module_configs[config.name] = config
        
        # Build dependency graph
        for dep in config.dependencies:
            self.dependency_graph[dep].append(config.name)
            self.reverse_dependencies[config.name].append(dep)
    
    def get_load_order(self) -> List[str]:
        """Računa optimalni redosled učitavanja modula po dependency-jima"""
        loaded = set()
        load_order = []
        
        def can_load(module_name: str) -> bool:
            config = self.module_configs[module_name]
            return all(dep in loaded for dep in config.dependencies)
        
        # Sort by priority first
        sorted_modules = sorted(
            self.module_configs.keys(),
            key=lambda x: (self.module_configs[x].priority.value, x)
        )
        
        while len(loaded) < len(sorted_modules):
            made_progress = False
            
            for module_name in sorted_modules:
                if module_name not in loaded and can_load(module_name):
                    load_order.append(module_name)
                    loaded.add(module_name)
                    made_progress = True
            
            if not made_progress:
                # Circular dependency ili missing dependency
                remaining = set(sorted_modules) - loaded
                self.logger.error(f"Cannot resolve dependencies for: {remaining}")
                # Load kritične module first bez obzira na dependency
                for module_name in remaining:
                    if self.module_configs[module_name].priority == ModulePriority.CRITICAL:
                        load_order.append(module_name)
                        loaded.add(module_name)
                break
        
        return load_order
    
    async def load_module(self, module_name: str) -> bool:
        """Učitava pojedinačni modul"""
        if module_name not in self.module_configs:
            self.logger.error(f"Module config not found: {module_name}")
            return False
        
        config = self.module_configs[module_name]
        
        try:
            # Check if file exists
            if not Path(config.file_path).exists():
                self.logger.error(f"Module file not found: {config.file_path}")
                return False
            
            # Dynamic import
            spec = importlib.util.spec_from_file_location(module_name, config.file_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Get class
            if not hasattr(module, config.class_name):
                self.logger.error(f"Class {config.class_name} not found in {config.file_path}")
                return False
            
            module_class = getattr(module, config.class_name)
            
            # Create module instance record
            instance_record = ModuleInstance(
                config=config,
                module_class=module_class,
                status=ModuleStatus.LOADED,
                load_time=time.time()
            )
            
            self.modules[module_name] = instance_record
            self.logger.info(f"Module loaded: {module_name}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load module {module_name}: {e}")
            self.logger.error(traceback.format_exc())
            return False
    
    async def initialize_module(self, module_name: str) -> bool:
        """Inicijalizuje modul"""
        if module_name not in self.modules:
            return False
        
        instance_record = self.modules[module_name]
        config = instance_record.config
        
        try:
            # Create instance
            if issubclass(instance_record.module_class, BaseShadowFoxModule):
                instance = instance_record.module_class(
                    mission_id=self.mission_id,
                    db=self.db,
                    event_bus=self.event_bus,
                    config=config.config
                )
            else:
                # Legacy module support
                instance = instance_record.module_class()
            
            instance_record.instance = instance
            instance_record.status = ModuleStatus.INITIALIZING
            
            # Initialize
            if hasattr(instance, 'initialize'):
                if asyncio.iscoroutinefunction(instance.initialize):
                    success = await asyncio.wait_for(instance.initialize(), timeout=config.timeout)
                else:
                    success = await asyncio.get_event_loop().run_in_executor(
                        None, instance.initialize
                    )
            else:
                success = True
            
            if success:
                instance_record.status = ModuleStatus.RUNNING
                instance_record.start_time = time.time()
                self.logger.info(f"Module initialized: {module_name}")
                
                # Emit event
                await self.event_bus.publish(ShadowFoxEvent(
                    event_type=EventType.MODULE_STARTED,
                    mission_id=self.mission_id,
                    source_module="orchestrator",
                    data={"module_name": module_name},
                    priority=EventPriority.NORMAL
                ))
                
                return True
            else:
                instance_record.status = ModuleStatus.ERROR
                return False
                
        except asyncio.TimeoutError:
            self.logger.error(f"Module {module_name} initialization timeout")
            instance_record.status = ModuleStatus.ERROR
            return False
        except Exception as e:
            self.logger.error(f"Failed to initialize module {module_name}: {e}")
            instance_record.status = ModuleStatus.ERROR
            instance_record.last_error = str(e)
            return False
    
    async def start_module(self, module_name: str) -> bool:
        """Pokreće modul"""
        if module_name not in self.modules:
            return False
        
        instance_record = self.modules[module_name]
        instance = instance_record.instance
        
        if not instance or instance_record.status != ModuleStatus.RUNNING:
            return False
        
        try:
            if hasattr(instance, 'start'):
                if asyncio.iscoroutinefunction(instance.start):
                    # Run in background task
                    task = asyncio.create_task(instance.start())
                    instance_record.task = task
                else:
                    # Run in thread pool
                    task = asyncio.create_task(
                        asyncio.get_event_loop().run_in_executor(None, instance.start)
                    )
                    instance_record.task = task
            
            self.logger.info(f"Module started: {module_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start module {module_name}: {e}")
            instance_record.status = ModuleStatus.ERROR
            instance_record.last_error = str(e)
            return False
    
    async def stop_module(self, module_name: str) -> bool:
        """Zaustavlja modul"""
        if module_name not in self.modules:
            return False
        
        instance_record = self.modules[module_name]
        instance = instance_record.instance
        
        try:
            if instance and hasattr(instance, 'stop'):
                if asyncio.iscoroutinefunction(instance.stop):
                    await instance.stop()
                else:
                    await asyncio.get_event_loop().run_in_executor(None, instance.stop)
            
            # Cancel task if exists
            if hasattr(instance_record, 'task'):
                instance_record.task.cancel()
            
            instance_record.status = ModuleStatus.STOPPED
            
            # Emit event
            await self.event_bus.publish(ShadowFoxEvent(
                event_type=EventType.MODULE_STOPPED,
                mission_id=self.mission_id,
                source_module="orchestrator", 
                data={"module_name": module_name},
                priority=EventPriority.NORMAL
            ))
            
            self.logger.info(f"Module stopped: {module_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop module {module_name}: {e}")
            return False
    
    async def restart_module(self, module_name: str) -> bool:
        """Restartuje modul"""
        instance_record = self.modules.get(module_name)
        if not instance_record:
            return False
        
        # Check restart limits
        if instance_record.restart_count >= instance_record.config.max_restart_attempts:
            self.logger.error(f"Module {module_name} exceeded max restart attempts")
            return False
        
        instance_record.restart_count += 1
        
        # Stop first
        await self.stop_module(module_name)
        
        # Wait before restart
        await asyncio.sleep(instance_record.config.restart_delay)
        
        # Reinitialize and start
        success = await self.initialize_module(module_name)
        if success:
            success = await self.start_module(module_name)
        
        return success
    
    async def load_all_modules(self) -> bool:
        """Učitava sve konfigurisane module"""
        load_order = self.get_load_order()
        self.logger.info(f"Loading modules in order: {load_order}")
        
        success_count = 0
        
        for module_name in load_order:
            if await self.load_module(module_name):
                success_count += 1
            else:
                self.logger.error(f"Failed to load critical module: {module_name}")
                # Continue with non-critical modules
        
        self.logger.info(f"Loaded {success_count}/{len(load_order)} modules")
        return success_count > 0
    
    async def initialize_all_modules(self) -> bool:
        """Inicijalizuje sve učitane module"""
        load_order = self.get_load_order()
        
        success_count = 0
        for module_name in load_order:
            if module_name in self.modules:
                config = self.module_configs[module_name]
                if config.auto_start:
                    if await self.initialize_module(module_name):
                        success_count += 1
        
        self.logger.info(f"Initialized {success_count} modules")
        return success_count > 0
    
    async def start_all_modules(self) -> bool:
        """Pokreće sve inicijalizovane module"""
        load_order = self.get_load_order()
        
        success_count = 0
        for module_name in load_order:
            if (module_name in self.modules and 
                self.modules[module_name].status == ModuleStatus.RUNNING):
                if await self.start_module(module_name):
                    success_count += 1
        
        self.logger.info(f"Started {success_count} modules")
        return success_count > 0
    
    async def start_mission(self, target_url: str, config: Dict = None) -> str:
        """Pokreće kompletnu misiju"""
        # Create mission
        mission_id = self.db.create_mission(target_url, config)
        self.mission_id = mission_id
        
        self.logger.info(f"Starting mission {mission_id} for target: {target_url}")
        
        # Load and start modules
        await self.load_all_modules()
        await self.initialize_all_modules()
        await self.start_all_modules()
        
        # Start monitoring
        self._monitor_task = asyncio.create_task(self._monitor_modules())
        
        self.is_running = True
        
        # Emit mission started event
        await self.event_bus.publish(ShadowFoxEvent(
            event_type=EventType.MISSION_STARTED,
            mission_id=mission_id,
            source_module="orchestrator",
            data={"target_url": target_url, "config": config},
            priority=EventPriority.HIGH
        ))
        
        return mission_id
    
    async def stop_mission(self):
        """Zaustavlja misiju"""
        if not self.is_running:
            return
        
        self.logger.info(f"Stopping mission {self.mission_id}")
        
        # Stop all modules
        for module_name in reversed(self.get_load_order()):
            if module_name in self.modules:
                await self.stop_module(module_name)
        
        # Stop monitoring
        if self._monitor_task:
            self._monitor_task.cancel()
        
        self.is_running = False
        self._shutdown_event.set()
        
        # Update mission status
        if self.mission_id:
            self.db.update_mission_status(self.mission_id, "completed")
            
            # Emit mission completed event
            await self.event_bus.publish(ShadowFoxEvent(
                event_type=EventType.MISSION_COMPLETED,
                mission_id=self.mission_id,
                source_module="orchestrator",
                data={"status": "completed"},
                priority=EventPriority.HIGH
            ))
    
    async def _monitor_modules(self):
        """Kontinuirano prati status modula"""
        while self.is_running:
            try:
                await asyncio.sleep(10)  # Check every 10 seconds
                
                for module_name, instance_record in self.modules.items():
                    # Check if module is healthy
                    if instance_record.status == ModuleStatus.ERROR:
                        self.logger.warning(f"Module {module_name} in error state, attempting restart")
                        await self.restart_module(module_name)
                    
                    # Update performance stats
                    if instance_record.instance and hasattr(instance_record.instance, 'get_performance_stats'):
                        stats = instance_record.instance.get_performance_stats()
                        instance_record.performance_stats.update(stats)
                        
                        # Store in history for AI analysis
                        self.module_performance_history[module_name].append({
                            'timestamp': time.time(),
                            'stats': stats.copy()
                        })
                        
                        # Keep only last 100 entries
                        if len(self.module_performance_history[module_name]) > 100:
                            self.module_performance_history[module_name] = \
                                self.module_performance_history[module_name][-100:]
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
    
    async def _handle_module_error(self, event: ShadowFoxEvent):
        """Handles module error events"""
        module_name = event.data.get('module_name')
        if module_name and module_name in self.modules:
            self.logger.error(f"Module error detected: {module_name}")
            # Attempt restart
            await self.restart_module(module_name)
    
    async def _handle_vulnerability_found(self, event: ShadowFoxEvent):
        """
        Obradjuje event kad je pronađena ranjivost
        """
        vuln_data = event.data or {}
    
        endpoint = vuln_data.get("endpoint")
        vuln_type = vuln_data.get("type")
        severity = vuln_data.get("severity")
        payload_id = vuln_data.get("payload_id", None)
    
        self.logger.info(f"[VULN FOUND] → type={vuln_type} severity={severity} endpoint={endpoint}")
    
    # Upis u bazu za AI learning
        if endpoint and vuln_type:
            self.db.store_intelligence(
                pattern_type="vuln_detected",
                pattern_data={
                    "endpoint": endpoint,
                    "vuln_type": vuln_type,
                    "severity": severity
                },
                success_correlation=1.0,
                confidence_score=0.95,
                ai_notes="Detected via _handle_vulnerability_found"
            )
    
    # Moguće: povećati reputaciju modula koji je poslao event
        source_module = event.source_module
        if source_module in self.modules:
            stats = self.modules[source_module].performance_stats
            stats["success_count"] += 1

    # Označi event kao obrađen (ako koristiš bazu događaja)
        if hasattr(self.db, "mark_event_processed") and hasattr(event, "event_id"):
            self.db.mark_event_processed(event.event_id)
