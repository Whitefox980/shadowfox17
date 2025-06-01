# shadowfox/core/ai_brain.py

import json
import logging
import time
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
import sqlite3
from pathlib import Path
from modules.ai.shadow_operator import ShadowFoxOperator
from modules.intelligence.shadow_spyder import ShadowReconSpider
from modules.payloads.mutation_engine import MutationEngine
from modules.attacks.smart_shadow_agent import SmartShadowAgent


import queue
import concurrent.futures

class TaskPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

class AgentStatus(Enum):
    IDLE = "idle"
    WORKING = "working"
    ERROR = "error"
    PAUSED = "paused"

@dataclass
class Task:
    sort_index: float = field(init=False, repr=False)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "unnamed_task"
    func: Optional[callable] = None
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    agent_name: str = ""
    action: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.MEDIUM
    created_at: datetime = field(default_factory=datetime.utcnow)
    depends_on: List[str] = field(default_factory=list)
    max_retries: int = 3
    current_retry: int = 0

    def __post_init__(self):
        # Za prioritetni queue (niža vrednost = viši prioritet)
        self.sort_index = self.priority.value
    def __lt__(self, other):
        return self.id < other.id  # bilo koji deterministički kriterijum

    def __repr__(self):
        return f"<Task {self.name} (id={self.id}, priority={self.priority.name})>"
@dataclass
class AgentState:
    name: str
    status: AgentStatus
    current_task: Optional[str] = None
    last_activity: datetime = None
    success_rate: float = 1.0
    total_tasks: int = 0
    failed_tasks: int = 0
    avg_execution_time: float = 0.0
class AIBrain:
    """
    Centralni AI Brain koji koordinira sve agente, upravlja zadacima,
    analizira rezultate i donosi odluke o daljem toku napada.
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('AIBrain')
        
        # Task management
        self.task_queue = queue.PriorityQueue()
        self.completed_tasks = {}
        self.failed_tasks = {}
        self.task_dependencies = {}
        
        # Agent management
        self.agents = {}
        self.agent_states = {}
        
        # Mission context
        self.current_mission_context = {}
        
        # AI decision engine
        self.decision_weights = {
            'success_rate_weight': 0.3,
            'execution_time_weight': 0.2,
            'priority_weight': 0.4,
            'dependency_weight': 0.1
        }
        
        # Thread management
        self.brain_active = False
        self.brain_thread = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        
        # Performance tracking
        self.mission_stats = {
            'total_payloads_tested': 0,
            'successful_exploits': 0,
            'false_positives': 0,
            'execution_start_time': None,
            'last_successful_exploit': None
        }
        
        self.logger.info("AI Brain inicijalizovan")
    
    def register_agent(self, agent_name: str, agent_instance):
        """Registruje agenta u AI Brain sistemu"""
        self.agents[agent_name] = agent_instance
        self.agent_states[agent_name] = AgentState(
            name=agent_name,
            status=AgentStatus.IDLE,
            last_activity=datetime.now()
        )
        self.logger.info(f"Agent {agent_name} registrovan")
    
    def start_mission_coordination(self, mission_id: str, target_url: str):
        """Pokretanje koordinacije misije"""
        self.current_mission_context = {
            'mission_id': mission_id,
            'target_url': target_url,
            'start_time': datetime.now(),
            'phase': 'recon',
            'discovered_vulns': [],
            'tested_payloads': [],
            'successful_exploits': []
        }
        
        self.mission_stats['execution_start_time'] = datetime.now()
        
        # Pokretanje brain thread-a
        self.brain_active = True
        self.brain_thread = threading.Thread(target=self._brain_main_loop, daemon=True)
        self.brain_thread.start()
        
        # Inicijalni plan napada
        self._create_initial_attack_plan(target_url)
        
        self.logger.info(f"Misija {mission_id} pokrenuta - AI Brain koordinira")
    
    def _create_initial_attack_plan(self, target_url: str):
        """Kreira inicijalni plan napada na osnovu AI analize"""
        
        # Faza 1: Recon
        self.add_task(
            agent_name="ReconAgent",
            action="analyze_target",
            params={"target_url": target_url},
            priority=TaskPriority.CRITICAL
        )
        
        # Faza 2: Traffic shaping (zavisi od recon-a)
        self.add_task(
            agent_name="TrafficShaper",
            action="setup_stealth_profile",
            params={"target_url": target_url},
            priority=TaskPriority.HIGH,
            depends_on=["recon_complete"]
        )
        
        # Faza 3: Počni sa osnovnim payload testiranjem
        self.add_task(
            agent_name="MutationEngine",
            action="prepare_initial_payloads",
            params={"target_url": target_url},
            priority=TaskPriority.HIGH,
            depends_on=["recon_complete"]
        )
    
    def add_task(self, agent_name: str, action: str, params: Dict, 
                 priority: TaskPriority = TaskPriority.MEDIUM, 
                 depends_on: List[str] = None, max_retries: int = 3) -> str:
        """Dodaje zadatak u queue sa AI prioritizacijom"""
        
        task_id = f"{agent_name}_{action}_{int(time.time())}"
        
        task = Task(
            id=task_id,
            agent_name=agent_name,
            action=action,
            params=params,
            priority=priority,
            created_at=datetime.now(),
            depends_on=depends_on or [],
            max_retries=max_retries
        )
        
        # AI prioritizacija na osnovu konteksta
        ai_priority = self._calculate_ai_priority(task)
        
        # Dodaj u queue sa AI prioritetom
        self.task_queue.put((ai_priority, task))
        
        if depends_on:
            self.task_dependencies[task_id] = depends_on
        
        self.logger.info(f"Zadatak {task_id} dodat sa prioritetom {ai_priority}")
        return task_id
    
    def _calculate_ai_priority(self, task: Task) -> float:
        """AI algoritam za izračunavanje prioriteta zadatka"""
        
        base_priority = task.priority.value
        
        # Agent performance faktor
        agent_state = self.agent_states.get(task.agent_name)
        if agent_state:
            performance_factor = agent_state.success_rate * self.decision_weights['success_rate_weight']
            time_factor = (1.0 / max(agent_state.avg_execution_time, 0.1)) * self.decision_weights['execution_time_weight']
        else:
            performance_factor = 0.5
            time_factor = 0.5
        
        # Mission context faktor
        context_factor = 0.0
        if self.current_mission_context.get('phase') == 'recon' and 'Recon' in task.agent_name:
            context_factor = 0.8
        elif self.current_mission_context.get('phase') == 'exploit' and 'Shadow' in task.agent_name:
            context_factor = 0.9
        
        # Dependency faktor
        dependency_factor = 0.0
        if not task.depends_on:
            dependency_factor = 0.5
        elif self._dependencies_satisfied(task.depends_on):
            dependency_factor = 0.8
        
        # Finalni AI prioritet (niži broj = viši prioritet)
        ai_priority = base_priority - (performance_factor + time_factor + context_factor + dependency_factor)
        
        return max(0.1, ai_priority)  # Minimum 0.1
    
    def _dependencies_satisfied(self, depends_on: List[str]) -> bool:
        """Proverava da li su dependency-ji zadovoljeni"""
        for dep in depends_on:
            if dep not in self.completed_tasks:
                return False
        return True
    
    def _brain_main_loop(self):
        """Glavni loop AI Brain-a koji koordinira sve agente"""
        
        while self.brain_active:
            try:
                # Proveri status agenata
                self._monitor_agents()
                
                # Obradi zadatke iz queue-a
                self._process_task_queue()
                
                # AI analiza trenutnog stanja
                self._analyze_mission_progress()
                
                # Adaptivno planiranje novih zadataka
                self._adaptive_task_planning()
                
                # Čekaj pre sledećeg ciklusa
                time.sleep(2)
                
            except Exception as e:
                self.logger.error(f"Greška u AI Brain main loop: {e}")
                time.sleep(5)
    
    def _monitor_agents(self):
        """Prati status svih agenata"""
        for agent_name, state in self.agent_states.items():
            # Proveri da li agent dugo ne odgovara
            if state.last_activity and (datetime.now() - state.last_activity) > timedelta(minutes=5):
                if state.status != AgentStatus.ERROR:
                    self.logger.warning(f"Agent {agent_name} ne odgovora već 5 minuta")
                    state.status = AgentStatus.ERROR
            
            # Ažuriraj success rate
            if state.total_tasks > 0:
                state.success_rate = 1.0 - (state.failed_tasks / state.total_tasks)
        # Ako su svi agenti u ERROR stanju, prekini misiju
            if all(state.status == AgentStatus.ERROR for state in self.agent_states.values()):
                self.logger.error("❌ Svi agenti su u ERROR stanju – zaustavljam AI Brain.")
                self.brain_active = False
    def _process_task_queue(self):
        """Obrađuje zadatke iz queue-a"""
        
        # Broj dostupnih agenata
        available_agents = [name for name, state in self.agent_states.items() 
                          if state.status == AgentStatus.IDLE]
        
        if not available_agents:
            return
        
        try:
            # Uzmi zadatak sa najvišim prioritetom
            if not self.task_queue.empty():
                priority, task = self.task_queue.get_nowait()
                
                # Proveri dependency-je
                if not self._dependencies_satisfied(task.depends_on):
                    # Vrati zadatak u queue
                    self.task_queue.put((priority, task))
                    return
                
                # Proveri da li je agent dostupan
                if task.agent_name not in available_agents:
                    # Vrati zadatak u queue
                    self.task_queue.put((priority, task))
                    return
                
                # Izvršavanje zadatka
                self._execute_task(task)
                
        except queue.Empty:
            pass
    
    def _execute_task(self, task: Task):
        """Izvršava zadatak preko odgovarajućeg agenta"""
        
        agent = self.agents.get(task.agent_name)
        if not agent:
            self.logger.error(f"Agent {task.agent_name} nije registrovan")
            return
        
        # Ažuriraj status agenta
        agent_state = self.agent_states[task.agent_name]
        agent_state.status = AgentStatus.WORKING
        agent_state.current_task = task.id
        agent_state.last_activity = datetime.now()
        
        self.logger.info(f"Izvršavam zadatak {task.id} preko {task.agent_name}")
        
        # Izvršavanje u background thread-u
        future = self.executor.submit(self._run_agent_action, agent, task)
        future.add_done_callback(lambda f: self._task_completed(task, f.result()))
    
    def _run_agent_action(self, agent, task: Task) -> Dict:
        """Pokreće akciju agenta"""
        start_time = time.time()
        
        try:
            # Dinamički pozovi akciju na agentu
            if hasattr(agent, task.action):
                method = getattr(agent, task.action)
                result = method(**task.params)
                
                execution_time = time.time() - start_time
                
                return {
                    'success': True,
                    'result': result,
                    'execution_time': execution_time,
                    'error': None
                }
            else:
                return {
                    'success': False,
                    'result': None,
                    'execution_time': time.time() - start_time,
                    'error': f"Agent {task.agent_name} nema akciju {task.action}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'result': None,
                'execution_time': time.time() - start_time,
                'error': str(e)
            }
    
    def _task_completed(self, task: Task, result: Dict):
        """Obrađuje završetak zadatka"""
        
        agent_state = self.agent_states[task.agent_name]
        agent_state.status = AgentStatus.IDLE
        agent_state.current_task = None
        agent_state.last_activity = datetime.now()
        agent_state.total_tasks += 1
        
        # Ažuriraj prosečno vreme izvršavanja
        if agent_state.avg_execution_time == 0:
            agent_state.avg_execution_time = result['execution_time']
        else:
            agent_state.avg_execution_time = (agent_state.avg_execution_time + result['execution_time']) / 2
        
        if result['success']:
            # Uspešno završen zadatak
            self.completed_tasks[task.id] = {
                'task': task,
                'result': result,
                'completed_at': datetime.now()
            }
            
            # AI analiza rezultata
            self._analyze_task_result(task, result)
            
            self.logger.info(f"Zadatak {task.id} uspešno završen")
            
        else:
            # Neuspešan zadatak
            agent_state.failed_tasks += 1
            
            if task.current_retry < task.max_retries:
                # Retry zadatak
                task.current_retry += 1
                retry_priority = self._calculate_ai_priority(task) + 1.0  # Smanji prioritet
                self.task_queue.put((retry_priority, task))
                
                self.logger.warning(f"Zadatak {task.id} neuspešan, retry {task.current_retry}/{task.max_retries}")
            else:
                # Konačno neuspešan
                self.failed_tasks[task.id] = {
                    'task': task,
                    'error': result['error'],
                    'failed_at': datetime.now()
                }
                
                self.logger.error(f"Zadatak {task.id} konačno neuspešan: {result['error']}")
    
    def _analyze_task_result(self, task: Task, result: Dict):
        """AI analiza rezultata zadatka za adaptivno planiranje"""
        
        if task.agent_name == "ReconAgent" and task.action == "analyze_target":
            # Recon završen - analiziraj rezultate i planiraj sledeće korake
            recon_data = result.get('result', {})
            
            # Signaliziraj da je recon završen
            self.completed_tasks['recon_complete'] = True
            
            # Promeni fazu misije
            self.current_mission_context['phase'] = 'payload_generation'
            
            # Analiziraj pronađene tehnologije i forme
            technologies = recon_data.get('technologies', {})
            forms = recon_data.get('forms', [])
            endpoints = recon_data.get('endpoints', [])
            
            # AI odlučuje koje tipove napada da prioritizuje
            attack_priorities = self._ai_determine_attack_priorities(recon_data)
            
            # Kreiraj payload generation zadatke na osnovu AI analize
            for attack_type, priority in attack_priorities.items():
                self.add_task(
                    agent_name="MutationEngine",
                    action="generate_payloads",
                    params={
                        "attack_type": attack_type,
                        "target_context": recon_data,
                        "payload_count": 20 if priority == TaskPriority.CRITICAL else 10
                    },
                    priority=priority
                )
        
        elif task.agent_name == "SmartShadowAgent":
            # Analiza rezultata napada
            attack_result = result.get('result', {})
            
            if attack_result.get('potential_vulnerability'):
                self.mission_stats['successful_exploits'] += 1
                self.mission_stats['last_successful_exploit'] = datetime.now()
                
                # Signaliziraj AI Evaluator-u da analizira
                self.add_task(
                    agent_name="AIEvaluator",
                    action="evaluate_vulnerability",
                    params=attack_result,
                    priority=TaskPriority.CRITICAL
                )
    
    def _ai_determine_attack_priorities(self, recon_data: Dict) -> Dict[str, TaskPriority]:
        """AI algoritam za određivanje prioriteta napada"""
        
        priorities = {}
        
        # Analiziraj tehnologije
        technologies = recon_data.get('technologies', {})
        forms = recon_data.get('forms', [])
        headers = recon_data.get('headers', {})
        
        # XSS prioritet
        if forms and not headers.get('security_headers', {}).get('content-security-policy'):
            priorities['XSS'] = TaskPriority.CRITICAL
        elif forms:
            priorities['XSS'] = TaskPriority.HIGH
        else:
            priorities['XSS'] = TaskPriority.LOW
        
        # SQLi prioritet
        if forms and any('PHP' in tech or 'MySQL' in tech for tech in technologies.keys()):
            priorities['SQLi'] = TaskPriority.CRITICAL
        elif forms:
            priorities['SQLi'] = TaskPriority.HIGH
        else:
            priorities['SQLi'] = TaskPriority.MEDIUM
        
        # SSRF prioritet
        if any('upload' in endpoint or 'api' in endpoint for endpoint in recon_data.get('endpoints', [])):
            priorities['SSRF'] = TaskPriority.HIGH
        else:
            priorities['SSRF'] = TaskPriority.MEDIUM
        
        # LFI/RFI prioritet
        if 'PHP' in technologies:
            priorities['LFI'] = TaskPriority.HIGH
        else:
            priorities['LFI'] = TaskPriority.LOW
        
        return priorities
    
    def _analyze_mission_progress(self):
        """AI analiza napretka misije"""
        
        # Proveri da li misija stagnira
        if self.mission_stats['execution_start_time']:
            runtime = datetime.now() - self.mission_stats['execution_start_time']
            
            # Ako nema uspešnih exploit-a duže od 10 minuta
            if (not self.mission_stats['last_successful_exploit'] and 
                runtime > timedelta(minutes=10)):
                
                self.logger.warning("Misija stagnira - menjam strategiju")
                self._change_attack_strategy()
            
            # Ako je prošlo više od 30 minuta, razmisli o završetku
            if runtime > timedelta(minutes=30):
                self.logger.info("Misija dugo traje - pripremam finalni izveštaj")
                self._prepare_mission_completion()
    
    def _adaptive_task_planning(self):
        """Adaptivno planiranje novih zadataka na osnovu AI analize"""
        
        # Ako je queue prazan i nema aktivnih zadataka
        if (self.task_queue.empty() and 
            all(state.status == AgentStatus.IDLE for state in self.agent_states.values())):
            
            current_phase = self.current_mission_context.get('phase')
            
            if current_phase == 'payload_generation':
                # Pripremi sledeću fazu - eksploitaciju
                self.current_mission_context['phase'] = 'exploitation'
                
                self.add_task(
                    agent_name="SmartShadowAgent",
                    action="begin_exploitation",
                    params={"mission_context": self.current_mission_context},
                    priority=TaskPriority.CRITICAL
                )
            
            elif current_phase == 'exploitation':
                # Počni sa prikupljanjem dokaza
                self.add_task(
                    agent_name="ProofCollector",
                    action="collect_evidence",
                    params={"mission_id": self.current_mission_context['mission_id']},
                    priority=TaskPriority.HIGH
                )
    
    def _change_attack_strategy(self):
        """Menja strategiju napada kada AI detektuje stagnaciju"""
        
        # Dodaj agresivnije payload-e
        self.add_task(
            agent_name="MutationEngine",
            action="generate_advanced_payloads",
            params={"strategy": "aggressive"},
            priority=TaskPriority.HIGH
        )
        
        # Promeni traffic shaping
        self.add_task(
            agent_name="TrafficShaper",
            action="change_stealth_profile",
            params={"new_profile": "aggressive"},
            priority=TaskPriority.HIGH
        )
    
    def _prepare_mission_completion(self):
        """Priprema završetak misije"""
        
        # Generiši finalni PDF izveštaj
        self.add_task(
            agent_name="PDFExporter",
            action="generate_final_report",
            params={"mission_id": self.current_mission_context['mission_id']},
            priority=TaskPriority.CRITICAL
        )
        
        # Ažuriraj status misije
        self.operator.update_mission_status(
            self.current_mission_context['mission_id'], 
            'completed'
        )
    
    def stop_mission_coordination(self):
        """Zaustavlja koordinaciju misije"""
        self.brain_active = False
        
        if self.brain_thread and self.brain_thread.is_alive():
            self.brain_thread.join(timeout=10)
        
        self.executor.shutdown(wait=True)
        
        self.logger.info("AI Brain koordinacija zaustavljena")
    
    def get_mission_status(self) -> Dict:
        """Vraća trenutni status misije"""
        
        active_agents = sum(1 for state in self.agent_states.values() 
                          if state.status == AgentStatus.WORKING)
        
        return {
            "mission_context": self.current_mission_context,
            "mission_stats": self.mission_stats,
            "active_agents": active_agents,
            "task_queue_size": self.task_queue.qsize(),
            "completed_tasks": len(self.completed_tasks),
            "failed_tasks": len(self.failed_tasks),
            "agent_states": {name: {
                "status": state.status.value,
                "success_rate": state.success_rate,
                "total_tasks": state.total_tasks,
                "current_task": state.current_task
            } for name, state in self.agent_states.items()}
        }

# Test AI Brain sistema
if __name__ == "__main__":
    
    # Setup
    op = ShadowFoxOperator()
    brain = ShadowFoxAIBrain(op)
    recon = ReconAgent(op)
    
    # Registruj agente
    brain.register_agent("ReconAgent", recon)
    
    # Test misija
    mission_id = op.create_mission("https://httpbin.org", "Test AI Brain koordinacija")
    brain.start_mission_coordination(mission_id, "https://httpbin.org")
    
    # Čekaj da se misija izvršava
    time.sleep(30)
    
    # Status
    status = brain.get_mission_status()
    print(json.dumps(status, indent=2, default=str))
    
    # Zaustavi
    brain.stop_mission_coordination()

#Izvrsno! Evo kompletnog AI Brain sistema koji koordinira sve agente. Ovaj sistem je dizajniran kao centralni "mozak" ShadowFox-a i ima sledeće ključne karakteristike:

## 🧠 **Ključne funkcionalnosti AI Brain-a:**

### **1. Inteligentna Task koordinacija**
#- Prioritizuje zadatke na osnovu AI algoritma
#- Upravlja dependency-jima između zadataka  
#- Adaptivno replaniranje na osnovu rezultata

### **2. Agent Management**
#- Prati status svih agenata u real-time
#- Balansira opterećenje između agenata
#- Detektuje neodgovarajuće agente

### **3. AI Decision Making**
#- Analizira recon rezultate i određuje prioritete napada
#- Menja strategiju kada detektuje stagnaciju
#- Automatski prelazi između faza misije (recon → exploit → report)

### **4. Mission Coordination**
#- Kreira dinamičke planove napada
#- Prati napredak misije i statistike
#- Automatski generiše finalne izveštaje

## 📋 **Kako da pokretaš sistem:**

#```python
# 1. Kreiraj operator i AI Brain
op = ShadowFoxOperator()
brain = AIBrain(op)
operator = ShadowFoxOperator()
recon_instance = ShadowReconSpider(operator)
shadow_instance = SmartShadowAgent(operator)

mutation_instance = MutationEngine(operator)
# 2. Registruj sve agente
brain.register_agent("ReconAgent", recon_instance)
brain.register_agent("MutationEngine", mutation_instance)
brain.register_agent("SmartShadowAgent", shadow_instance)
# ... ostali agenti

# 3. Pokreni misiju
mission_id = op.create_mission("https://target.com", "Opis misije")
brain.start_mission_coordination(mission_id, "https://target.com")

# 4. AI Brain automatski koordinira sve ostalo!

## 🎯 **Pametne AI funkcije:**

#- **Adaptivni prioriteti**: AI računa prioritet zadataka na osnovu performance-a agenata, konteksta misije, dependency-ja
#- **Strategijska analiza**: Na osnovu recon podataka, AI određuje koje tipove napada da prioritizuje (XSS, SQLi, SSRF...)
#- **Detekcija stagnacije**: Ako nema rezultata 10+ minuta, automatski menja strategiju
#- **Auto-completion**: Nakon 30 minuta ili završetka, automatski kreira finalni izveštaj

