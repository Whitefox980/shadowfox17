from modules.ai.ai_brain import TaskPriority
from modules.ai.explainable_ai import ExplainableAI
from modules.ai.taktician_agent import TakticianAgent
from modules.command.operator import ShadowFoxOperator
from modules.command.mission_controller import ShadowFoxMissionController
from modules.attacks.ghost_threads import ShadowPersona
from modules.attacks.fuzz_engine import FuzzEngine
from modules.attacks.smart_shadow_agent import SmartShadowAgent
from modules.attacks.xse_engine import VulnType
from modules.payloads.payload_seeder import PayloadLibrarySeeder
from modules.payloads.rainbow_mutation import RainbowMutation
from modules.payloads.mutation_engine import MutationEngine
from modules.intelligence.shadow_spider import CrawlResult
from modules.intelligence.dom_collector import DOMCollector
from modules.intelligence.pathfinder import AttackSurface
from modules.intelligence.vulnerability_mapper import VulnSeverity
from modules.reporting.pdf_exporter import PDFExporter
from modules.reporting.proof_collector import ProofCollector
from modules.proxy.shadow_proxy import AIPayloadMutator
from modules.proxy.traffic_shaper import TrafficShaper
from core.shadowfox_db import ShadowFoxDB
from core.orchestrator import ModuleStatus
from core.shadowfox_event_bus import EventHandler
#!/usr/bin/env python3
"""
ShadowFox17 Module Registry
"""

MODULES = {}

def register_module(name, module):
    MODULES[name] = module
    print(f"Module {name} registered in registry")

def get_module(name):
    return MODULES.get(name, None)

# Auto-registered
register_module("ai_brain", TaskPriority)

# Auto-registered
register_module("explainable_ai", ExplainableAI)

# Auto-registered
register_module("taktician_agent", TakticianAgent)

# Auto-registered
register_module("operator", ShadowFoxOperator)

# Auto-registered
register_module("mission_controller", ShadowFoxMissionController)

# Auto-registered
register_module("ghost_threads", ShadowPersona)

# Auto-registered
register_module("fuzz_engine", FuzzEngine)

# Auto-registered
register_module("smart_shadow_agent", SmartShadowAgent)

# Auto-registered
register_module("xse_engine", VulnType)

# Auto-registered
register_module("payload_seeder", PayloadLibrarySeeder)

# Auto-registered
register_module("rainbow_mutation", RainbowMutation)

# Auto-registered
register_module("mutation_engine", MutationEngine)

# Auto-registered
register_module("shadow_spider", CrawlResult)

# Auto-registered
register_module("dom_collector", DOMCollector)

# Auto-registered
register_module("pathfinder", AttackSurface)

# Auto-registered
register_module("vulnerability_mapper", VulnSeverity)

# Auto-registered
register_module("pdf_exporter", PDFExporter)

# Auto-registered
register_module("proof_collector", ProofCollector)

# Auto-registered
register_module("shadow_proxy", AIPayloadMutator)

# Auto-registered
register_module("traffic_shaper", TrafficShaper)

# Auto-registered
register_module("shadowfox_db", ShadowFoxDB)

# Auto-registered
register_module("orchestrator", ModuleStatus)

# Auto-registered
register_module("shadowfox_event_bus", EventHandler)
