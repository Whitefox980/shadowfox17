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
ShadowFox17 Option Router
"""

class OptionRouter:
    def __init__(self):
        self.routes = {}
    
    def add_route(self, name, handler):
        self.routes[name] = handler
    
    def execute(self, option):
        if option in self.routes:
            return self.routes[option]()
        else:
            print(f"Unknown option: {option}")

router = OptionRouter()

# Auto-added route
router.add_route("ai_brain", TaskPriority)

# Auto-added route
router.add_route("explainable_ai", ExplainableAI)

# Auto-added route
router.add_route("taktician_agent", TakticianAgent)

# Auto-added route
router.add_route("operator", ShadowFoxOperator)

# Auto-added route
router.add_route("mission_controller", ShadowFoxMissionController)

# Auto-added route
router.add_route("ghost_threads", ShadowPersona)

# Auto-added route
router.add_route("fuzz_engine", FuzzEngine)

# Auto-added route
router.add_route("smart_shadow_agent", SmartShadowAgent)

# Auto-added route
router.add_route("xse_engine", VulnType)

# Auto-added route
router.add_route("payload_seeder", PayloadLibrarySeeder)

# Auto-added route
router.add_route("rainbow_mutation", RainbowMutation)

# Auto-added route
router.add_route("mutation_engine", MutationEngine)

# Auto-added route
router.add_route("shadow_spider", CrawlResult)

# Auto-added route
router.add_route("dom_collector", DOMCollector)

# Auto-added route
router.add_route("pathfinder", AttackSurface)

# Auto-added route
router.add_route("vulnerability_mapper", VulnSeverity)

# Auto-added route
router.add_route("pdf_exporter", PDFExporter)

# Auto-added route
router.add_route("proof_collector", ProofCollector)

# Auto-added route
router.add_route("shadow_proxy", AIPayloadMutator)

# Auto-added route
router.add_route("traffic_shaper", TrafficShaper)

# Auto-added route
router.add_route("shadowfox_db", ShadowFoxDB)

# Auto-added route
router.add_route("orchestrator", ModuleStatus)

# Auto-added route
router.add_route("shadowfox_event_bus", EventHandler)
