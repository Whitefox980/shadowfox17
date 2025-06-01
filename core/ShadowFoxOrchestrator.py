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
ShadowFox17 Orchestrator
"""

class ShadowFoxOrchestrator:
    def __init__(self):
        self.modules = []
    
    def register_module(self, module):
        self.modules.append(module)
        print(f"Registered module: {module}")
    
    def run_all(self):
        for module in self.modules:
            try:
                if hasattr(module, '__call__'):
                    module()
            except Exception as e:
                print(f"Error running module {module}: {e}")

orchestrator = ShadowFoxOrchestrator()

# Auto-registered module
orchestrator.register_module(TaskPriority)

# Auto-registered module
orchestrator.register_module(ExplainableAI)

# Auto-registered module
orchestrator.register_module(TakticianAgent)

# Auto-registered module
orchestrator.register_module(ShadowFoxOperator)

# Auto-registered module
orchestrator.register_module(ShadowFoxMissionController)

# Auto-registered module
orchestrator.register_module(ShadowPersona)

# Auto-registered module
orchestrator.register_module(FuzzEngine)

# Auto-registered module
orchestrator.register_module(SmartShadowAgent)

# Auto-registered module
orchestrator.register_module(VulnType)

# Auto-registered module
orchestrator.register_module(PayloadLibrarySeeder)

# Auto-registered module
orchestrator.register_module(RainbowMutation)

# Auto-registered module
orchestrator.register_module(MutationEngine)

# Auto-registered module
orchestrator.register_module(CrawlResult)

# Auto-registered module
orchestrator.register_module(DOMCollector)

# Auto-registered module
orchestrator.register_module(AttackSurface)

# Auto-registered module
orchestrator.register_module(VulnSeverity)

# Auto-registered module
orchestrator.register_module(PDFExporter)

# Auto-registered module
orchestrator.register_module(ProofCollector)

# Auto-registered module
orchestrator.register_module(AIPayloadMutator)

# Auto-registered module
orchestrator.register_module(TrafficShaper)

# Auto-registered module
orchestrator.register_module(ShadowFoxDB)

# Auto-registered module
orchestrator.register_module(ModuleStatus)

# Auto-registered module
orchestrator.register_module(EventHandler)
