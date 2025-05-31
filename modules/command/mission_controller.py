# shadowfox/core/mission_controller.py

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path

# Import svih agenata
from modules.command.operator import ShadowFoxOperator
from agents.recon_agent import ReconAgent
# from agents.mutator_engine import MutatorEngine
# from agents.smart_shadow_agent import SmartShadowAgent
# from agents.traffic_shaper import TrafficShaper
# from agents.ai_evaluator import AIEvaluator
# from agents.proof_collector import ProofCollector
# from agents.pdf_exporter import PDFExporter

class ShadowFoxMissionController:
    """
    Glavni orkestrator - koordinira sve agente u logičnom redosledu
    Ovo je MOZAK koji vodi celu misiju od početka do kraja
    """
    
    def __init__(self, base_dir: str = None):
        self.operator = ShadowFoxOperator(base_dir)
        self.logger = logging.getLogger('MissionController')
        
        # Inicijalizuj sve agente
        self.recon_agent = ReconAgent(self.operator)
        # self.mutator_engine = MutatorEngine(self.operator)
        # self.smart_shadow = SmartShadowAgent(self.operator)
        # self.traffic_shaper = TrafficShaper(self.operator)
        # self.ai_evaluator = AIEvaluator(self.operator)
        # self.proof_collector = ProofCollector(self.operator)
        # self.pdf_exporter = PDFExporter(self.operator)
        
        # Mission status tracking
        self.current_mission = None
        self.mission_status = "idle"
        
        self.logger.info("ShadowFox Mission Controller inicijalizovan")
    
    async def execute_full_mission(self, target_url: str, mission_config: Dict = None) -> str:
        """
        GLAVNA FUNKCIJA - izvršava kompletnu misiju od A do Z
        
        Workflow:
        1. Recon (prikupljanje informacija)
        2. Mutation Generation (kreiranje payload-a)
        3. Smart Attack (izvršavanje napada)
        4. AI Evaluation (analiza rezultata)
        5. Proof Collection (snimanje dokaza)
        6. PDF Report Generation (finalni izveštaj)
        """
        
        mission_id = self.operator.create_mission(target_url, f"Full pentest scan - {datetime.now()}")
        self.current_mission = mission_id
        self.mission_status = "running"
        
        self.logger.info(f"🚀 Pokretanje kompletne misije: {mission_id}")
        self.logger.info(f"🎯 Target: {target_url}")
        
        try:
            # ===========================================
            # FAZA 1: RECONNAISSANCE
            # ===========================================
            self.logger.info("📡 FAZA 1: Reconnaissance - prikupljanje meta podataka")
            self.mission_status = "recon"
            
            recon_data = self.recon_agent.analyze_target(target_url, mission_id)
            
            if recon_data.get("error"):
                raise Exception(f"Recon failed: {recon_data['error']}")
            
            self.logger.info(f"✅ Recon završen - pronađeno {len(recon_data.get('endpoints', []))} endpoints")
            
            # ===========================================
            # FAZA 2: PAYLOAD GENERATION
            # ===========================================
            self.logger.info("🧬 FAZA 2: Payload Generation - kreiranje mutacija")
            self.mission_status = "mutation"
            
            # Identifikuj tipove napada na osnovu recon podataka
            attack_types = self._determine_attack_types(recon_data)
            self.logger.info(f"🎯 Identifikovani tipovi napada: {', '.join(attack_types)}")
            
            # Kreiraj payload-e za svaki tip
            all_payloads = {}
            for attack_type in attack_types:
                payloads = await self._generate_payloads(attack_type, recon_data)
                all_payloads[attack_type] = payloads
                self.logger.info(f"📝 Generisano {len(payloads)} payload-a za {attack_type}")
            
            # ===========================================
            # FAZA 3: INTELLIGENT ATTACK EXECUTION  
            # ===========================================
            self.logger.info("⚔️ FAZA 3: Smart Attack Execution")
            self.mission_status = "attacking"
            
            successful_attacks = []
            
            for attack_type, payloads in all_payloads.items():
                self.logger.info(f"🚀 Testiranje {attack_type} napada...")
                
                for payload_data in payloads:
                    # Traffic shaping za stealth
                    await self._apply_traffic_shaping()
                    
                    # Izvršavanje napada
                    attack_result = await self._execute_attack(
                        target_url, payload_data, attack_type, recon_data
                    )
                    
                    if attack_result:
                        # AI evaluacija rezultata
                        evaluation = await self._evaluate_attack_result(attack_result)
                        
                        if evaluation.get("success_probability", 0) > 0.7:
                            successful_attacks.append({
                                "attack_result": attack_result,
                                "evaluation": evaluation
                            })
                            self.logger.info(f"✅ Uspešan napad detektovan: {attack_type}")
                    
                    # Delay između napada
                    await asyncio.sleep(1)
            
            # ===========================================
            # FAZA 4: PROOF COLLECTION
            # ===========================================
            self.logger.info("📸 FAZA 4: Proof Collection")
            self.mission_status = "collecting_proofs"
            
            collected_proofs = []
            for attack in successful_attacks:
                proof_id = await self._collect_proof(attack)
                if proof_id:
                    collected_proofs.append(proof_id)
            
            self.logger.info(f"📋 Prikupljeno {len(collected_proofs)} dokaza")
            
            # ===========================================
            # FAZA 5: REPORT GENERATION
            # ===========================================
            self.logger.info("📄 FAZA 5: PDF Report Generation")
            self.mission_status = "generating_report"
            
            report_path = await self._generate_pdf_report(mission_id, recon_data, successful_attacks)
            
            # ===========================================
            # FINALIZACIJA
            # ===========================================
            self.operator.update_mission_status(mission_id, "completed")
            self.mission_status = "completed"
            
            summary = {
                "mission_id": mission_id,
                "target": target_url,
                "duration": "calculated_duration",
                "recon_results": len(recon_data.get('endpoints', [])),
                "attack_types_tested": len(attack_types),
                "successful_attacks": len(successful_attacks),
                "proofs_collected": len(collected_proofs),
                "report_path": report_path,
                "status": "completed"
            }
            
            self.logger.info("🎉 MISIJA ZAVRŠENA USPEŠNO!")
            self.logger.info(f"📊 Summary: {json.dumps(summary, indent=2)}")
            
            return mission_id
            
        except Exception as e:
            self.logger.error(f"❌ Greška u misiji: {e}")
            self.operator.update_mission_status(mission_id, "failed")
            self.mission_status = "failed"
            raise
    
    def _determine_attack_types(self, recon_data: Dict) -> List[str]:
        """
        Na osnovu recon podataka određuje koje tipove napada treba testirati
        """
        attack_types = []
        
        # Uvek testiraj osnovne
        attack_types.extend(["XSS", "SQLi", "Directory_Traversal"])
        
        # Na osnovu tehnologija
        technologies = recon_data.get("technologies", {})
        if "PHP" in technologies:
            attack_types.append("LFI")
        if "WordPress" in technologies:
            attack_types.extend(["WordPress_Exploit", "Plugin_Scan"])
        
        # Na osnovu formi
        forms = recon_data.get("forms", [])
        if forms:
            attack_types.extend(["CSRF", "File_Upload"])
        
        # Na osnovu endpoint-a
        endpoints = recon_data.get("endpoints", [])
        for endpoint in endpoints:
            if "/api" in endpoint:
                attack_types.extend(["API_Injection", "JWT_Attack"])
            if "/upload" in endpoint:
                attack_types.append("File_Upload")
        
        # Na osnovu header-a
        headers = recon_data.get("headers", {}).get("missing_security", [])
        if "content-security-policy" in headers:
            attack_types.append("XSS_Advanced")
        
        return list(set(attack_types))  # Remove duplicates
    
    async def _generate_payloads(self, attack_type: str, recon_data: Dict) -> List[Dict]:
        """
        Poziva MutatorEngine da generiše payload-e za određeni tip napada
        """
        # TODO: Implementirati kada imamo MutatorEngine
        # return await self.mutator_engine.generate_payloads(attack_type, recon_data)
        
        # Placeholder - osnovni payload-i
        basic_payloads = {
            "XSS": [
                {"payload": "<script>alert('XSS')</script>", "type": "reflected"},
                {"payload": "javascript:alert('XSS')", "type": "href_injection"},
                {"payload": "\"><script>alert('XSS')</script>", "type": "attribute_breaking"}
            ],
            "SQLi": [
                {"payload": "' OR '1'='1", "type": "auth_bypass"},
                {"payload": "'; DROP TABLE users; --", "type": "destructive"},
                {"payload": "' UNION SELECT 1,2,3 --", "type": "union_based"}
            ],
            "Directory_Traversal": [
                {"payload": "../../../etc/passwd", "type": "linux_passwd"},
                {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "type": "windows_hosts"}
            ]
        }
        
        return basic_payloads.get(attack_type, [])
    
    async def _apply_traffic_shaping(self):
        """
        Primenjuje traffic shaping za stealth
        """
        # TODO: Implementirati TrafficShaper
        # await self.traffic_shaper.randomize_headers()
        # await self.traffic_shaper.apply_delay()
        pass
    
    async def _execute_attack(self, target_url: str, payload_data: Dict, 
                            attack_type: str, recon_data: Dict) -> Optional[Dict]:
        """
        Izvršava pojedinačni napad
        """
        # TODO: Implementirati SmartShadowAgent
        # return await self.smart_shadow.execute_attack(target_url, payload_data, attack_type, recon_data)
        
        # Placeholder
        return {
            "target": target_url,
            "payload": payload_data["payload"],
            "attack_type": attack_type,
            "response_code": 200,
            "response_body": "test response",
            "timestamp": datetime.now().isoformat()
        }
    
    async def _evaluate_attack_result(self, attack_result: Dict) -> Dict:
        """
        AI evaluacija rezultata napada
        """
        # TODO: Implementirati AIEvaluator
        # return await self.ai_evaluator.evaluate_result(attack_result)
        
        # Placeholder
        return {
            "success_probability": 0.8,
            "confidence": 0.9,
            "reasoning": "Placeholder evaluation",
            "threat_level": "medium"
        }
    
    async def _collect_proof(self, attack_data: Dict) -> Optional[int]:
        """
        Prikuplja dokaz (screenshot, response)
        """
        # TODO: Implementirati ProofCollector
        # return await self.proof_collector.collect_proof(attack_data)
        
        # Placeholder - upisuj u bazu
        return self.operator.store_proof(
            payload=attack_data["attack_result"]["payload"],
            url=attack_data["attack_result"]["target"],
            payload_type=attack_data["attack_result"]["attack_type"],
            response_code=attack_data["attack_result"]["response_code"],
            response_raw=attack_data["attack_result"]["response_body"]
        )
    
    async def _generate_pdf_report(self, mission_id: str, recon_data: Dict, 
                                 successful_attacks: List[Dict]) -> str:
        """
        Generiše finalni PDF izveštaj
        """
        # TODO: Implementirati PDFExporter
        # return await self.pdf_exporter.generate_report(mission_id, recon_data, successful_attacks)
        
        # Placeholder
        report_path = f"reports/mission_{mission_id}_report.pdf"
        self.logger.info(f"📄 PDF izveštaj bi bio generisan: {report_path}")
        return report_path
    
    def get_mission_status(self) -> Dict:
        """
        Vraća trenutni status misije
        """
        return {
            "mission_id": self.current_mission,
            "status": self.mission_status,
            "timestamp": datetime.now().isoformat()
        }
    
    async def stop_mission(self):
        """
        Zaustavlja trenutnu misiju
        """
        if self.current_mission:
            self.operator.update_mission_status(self.current_mission, "stopped")
            self.mission_status = "stopped"
            self.logger.info(f"🛑 Misija {self.current_mission} zaustavljena")

# CLI interface za testiranje
async def main():
    """
    Test CLI interface
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mission_controller.py <target_url>")
        return
    
    target_url = sys.argv[1]
    
    controller = ShadowFoxMissionController()
    
    try:
        mission_id = await controller.execute_full_mission(target_url)
        print(f"\n🎉 Misija završena uspešno: {mission_id}")
        
        # Prikaži rezultate
        results = controller.operator.get_mission_results(mission_id)
        print(f"\n📊 Rezultati:")
        print(f"   - Proofs: {len(results.get('proofs', []))}")
        print(f"   - Evaluations: {len(results.get('evaluations', []))}")
        print(f"   - Agent logs: {len(results.get('agent_logs', []))}")
        
    except Exception as e:
        print(f"❌ Greška: {e}")

if __name__ == "__main__":
    asyncio.run(main())
