# modules/ai/shadow_operator.py
# shadow_operator.py

from dataclasses import dataclass
from typing import List, Optional
from core.shadowfox_event_bus import ShadowFoxEventBus, ShadowFoxEvent, EventType
from core.shadowfox_db import ShadowFoxDB
from core.shadowfox_db import MissionData
import uuid
from datetime import datetime
import hashlib
import time
import logging
import asyncio

@dataclass
class AgentProfile:
    name: str
    specialty: str
    active: bool = True
    priority: int = 5  # 1 (najviši) do 10 (najniži)

class ShadowFoxOperator:

    def __init__(self, base_dir: str = ".", db: Optional[ShadowFoxDB] = None, event_bus: Optional[ShadowFoxEventBus] = None):
        self.base_dir = base_dir

        import logging
        self.logger = logging.getLogger("ShadowFoxOperator")
        self.logger.setLevel(logging.INFO)

        # Pokreni event bus ako nije prosleđen
        self.event_bus = event_bus if event_bus else ShadowFoxEventBus()

        # Pokreni DB ako nije prosleđen
        self.db = db if db else ShadowFoxDB(event_bus=self.event_bus)

        # Učitaj agente (uvek će raditi)
        self.agents: List[AgentProfile] = self.load_agent_profiles()

        self.logger.info("✅ ShadowFoxOperator uspešno inicijalizovan.")
    def load_agent_profiles(self) -> List[AgentProfile]:
        return [
            AgentProfile(name="AgentX", specialty="Fuzzing", priority=2),
            AgentProfile(name="Specter", specialty="Reconnaissance", priority=3),
            AgentProfile(name="Payloador", specialty="Payload Mutation", priority=4),
            AgentProfile(name="Watcher", specialty="Monitoring", priority=5),
        ]

    def log(self, message: str):
        print(f"[ShadowOperator] {message}")

    def choose_agent(self, task: str) -> Optional[AgentProfile]:
        # Simple heuristic – choose active agent with lowest priority value matching the task
        suitable_agents = [agent for agent in self.agents if agent.active and task.lower() in agent.specialty.lower()]
        if not suitable_agents:
            self.log(f"Nema agenta za zadatak: {task}")
            return None
        chosen = sorted(suitable_agents, key=lambda a: a.priority)[0]
        self.log(f"Agent izabran: {chosen.name} za zadatak '{task}'")
        return chosen

    def get_payloads_by_type(self, payload_type: str):
        raise NotImplementedError("get_payloads_by_type nije još implementiran. Dodaj logiku pristupa payloadima iz baze.")

    @property
    def shadowfox_db(self):
        raise NotImplementedError("shadowfox_db nije definisan. Dodaj self.db ili ispravi logiku MutationEngine-a.")
    def execute_decision(self, task: str, mission_id: str = "default_mission"):
        agent = self.choose_agent(task)
        if agent:
            event = ShadowFoxEvent(
                event_type=EventType.TASK_ASSIGNED,
                payload={
                    "agent": agent.name,
                    "task": task,
                    "mission_id": mission_id
                }
            )
            self.event_bus.publish(event)
            self.log(f"Zadatak '{task}' delegiran agentu: {agent.name}")

    def integrate_with_command_system(self):
        # Placeholder: In future, register command via CLI or REST
        self.log("Integracija sa komandnim sistemom aktivirana.")

    def create_mission(self, target_url: str, description: str = "") -> str:
        """
        Kreira novu misiju i vraća mission_id
        """
        if not self.db:
            raise RuntimeError("ShadowFoxDB nije povezan sa operatorom.")

    # Generiši mission_id odmah
        mission_id = hashlib.md5(f"{target_url}_{time.time()}".encode()).hexdigest()

        config = {
            "description": description,
            "created_by": "ShadowFoxOperator",
            "origin": "manual"
        }

    # Zapiši u bazu
        mission_id = self.db.create_mission(target_url, config)
        mission = MissionData(
            id=mission_id,
            target=target_url,
            status='initialized',
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat()
        )
    # (opciono) kreiraj lokalni objekat

        self.logger.info(f"✅ Kreirana nova misija: {mission_id} ({target_url})")
        return mission_id
    def get_mission_context(self, mission_id: str) -> Optional[MissionData]:
        try:
            return self.db.get_mission_data(mission_id)
        except Exception as e:
            self.log(f"Greška pri dohvatu misije: {e}")
            return None
    async def initialize(self):
        self.logger.info("🔁 Pokrećem inicijalizaciju operatera...")
        await asyncio.sleep(0.5)  # simulacija čekanja
        self.logger.info("✅ Inicijalizacija ShadowFoxOperator završena.")
        return True

# Test pokretanje (samo ako se runuje direktno)
if __name__ == "__main__":
    op = ShadowOperator()
    op.execute_decision("Fuzzing")
    op.execute_decision("Reconnaissance")
    op.execute_decision("Payload Mutation")
