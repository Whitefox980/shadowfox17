# modules/agents/ghost_threads.py

import logging
import asyncio
import json
import random
from datetime import datetime
from typing import Dict, List, Any, Optional
from core.shadowfox_event_bus import ShadowFoxEventBus, ShadowFoxEvent, EventType
# Import the original GhostThreadsEnginefrom modules.agents.ghost_threads import GhostThreadsEngine, ShadowPersona
from modules.agents.ghost_threads import GhostThreadsEngine, ShadowPersona
# modules/monitor/ghost_task_monitor.py

import threading
import time
import logging

class GhostThreadMonitor:
    def __init__(self):
        self.threads = []

    def register(self, thread):
        logging.info(f"📡 Monitoring thread: {thread.name}")
        self.threads.append(thread)

    def monitor(self):
        while True:
            for thread in self.threads:
                if not thread.is_alive():
                    logging.warning(f"👻 Ghost thread detected: {thread.name}")
            time.sleep(5)
class EnhancedGhostThreads:
    """
    Enhanced GhostThreads agent that integrates with the event bus
    and provides intelligent response to system events
    """
    
    def __init__(self, operator, event_bus: ShadowFoxEventBus):
        self.operator = operator
        self.event_bus = event_bus
        self.logger = logging.getLogger('EnhancedGhostThreads')
        
        # Initialize the original engine
        self.ghost_engine = GhostThreadsEngine(operator, max_personas=3)
        
        # Enhanced memory system
        self.memory = {
            'targets': {},
            'successful_payloads': [],
            'failed_payloads': [],
            'active_sessions': {},
            'persona_performance': {},
            'threat_intelligence': {}
        }
        
        # AI decision making
        self.ai_config = {
            'auto_response_threshold': 0.7,
            'learning_enabled': True,
            'adaptive_personas': True,
            'threat_correlation': True
        }
        
        # Active monitoring
        self.monitoring_active = False
        self.adaptive_learning_enabled = True

    async def start(self):
        """Start the enhanced GhostThreads agent"""
        self.logger.info("👻 Enhanced GhostThreads agent initializing...")
        
        # Register event handlers
        await self.event_bus.register_handler(self.handle_event)
        
        # Start background tasks
        asyncio.create_task(self.adaptive_learning_loop())
        asyncio.create_task(self.threat_correlation_loop())
        
        self.logger.info("🚀 Enhanced GhostThreads agent fully operational")

    async def handle_event(self, event: ShadowFoxEvent):
        """Enhanced event handler with AI decision making"""
        self.logger.info(f"📡 Enhanced GhostThreads processing: {event.type}")
        
        try:
            if event.type == EventType.TARGET_SCANNED:
                await self._handle_target_scanned(event)
            
            elif event.type == EventType.PAYLOAD_TESTED:
                await self._handle_payload_tested(event)
            
            elif event.type == EventType.AGENT_RESPONSE:
                await self._handle_agent_response(event)
            
            elif event.type == EventType.VULNERABILITY_FOUND:
                await self._handle_vulnerability_found(event)
            
            elif event.type == EventType.MISSION_COMPLETED:
                await self._handle_mission_completed(event)
            
            else:
                await self._handle_unknown_event(event)
                
        except Exception as e:
            self.logger.error(f"❌ Error handling event {event.type}: {e}")

    async def _handle_target_scanned(self, event: ShadowFoxEvent):
        """Handle target scan events with intelligent analysis"""
        target_data = event.payload
        target_url = target_data.get('url', 'unknown')
        
        # Store target information
        self.memory['targets'][target_url] = {
            'scan_data': target_data,
            'scanned_at': datetime.now().isoformat(),
            'threat_level': self._assess_threat_level(target_data),
            'recommended_personas': self._recommend_personas(target_data)
        }
        
        self.logger.info(f"🎯 Target analyzed: {target_url}")
        
        # Auto-deploy personas if threat level is high
        threat_level = self.memory['targets'][target_url]['threat_level']
        if threat_level > 0.7 and self.ai_config['auto_response_threshold'] <= threat_level:
            await self._auto_deploy_ghost_session(target_url, target_data)

    async def _handle_payload_tested(self, event: ShadowFoxEvent):
        """Handle payload test results with learning"""
        payload_data = event.payload
        
        if isinstance(payload_data, str):
            payload_info = {'payload': payload_data, 'success': 'error' not in payload_data.lower()}
        else:
            payload_info = payload_data
        
        # Learn from payload results
        if payload_info.get('success', False):
            self.memory['successful_payloads'].append({
                'payload': payload_info.get('payload'),
                'timestamp': datetime.now().isoformat(),
                'context': payload_info.get('context', {})
            })
            self.logger.info(f"✅ Successful payload learned: {payload_info.get('payload', 'Unknown')[:50]}...")
        else:
            self.memory['failed_payloads'].append({
                'payload': payload_info.get('payload'),
                'timestamp': datetime.now().isoformat(),
                'error': payload_info.get('error', 'Unknown error')
            })
            self.logger.warning(f"❌ Failed payload logged: {payload_info.get('payload', 'Unknown')[:50]}...")
        
        # Trigger adaptive learning
        if self.adaptive_learning_enabled:
            await self._update_persona_strategies()

    async def _handle_vulnerability_found(self, event: ShadowFoxEvent):
        """Handle discovered vulnerabilities"""
        vuln_data = event.payload
        
        self.logger.critical(f"🚨 VULNERABILITY DETECTED: {vuln_data}")
        
        # Store vulnerability intelligence
        vuln_id = f"vuln_{datetime.now().timestamp()}"
        self.memory['threat_intelligence'][vuln_id] = {
            'vulnerability': vuln_data,
            'discovered_at': datetime.now().isoformat(),
            'exploitation_attempted': False,
            'personas_deployed': []
        }
        
        # Auto-deploy specialized personas for exploitation
        await self._deploy_exploitation_personas(vuln_data)

    async def _handle_agent_response(self, event: ShadowFoxEvent):
        """Handle responses from other agents"""
        response_data = event.payload
        
        self.memory['last_response'] = {
            'data': response_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Analyze if response indicates successful infiltration
        if self._indicates_successful_infiltration(response_data):
            self.logger.info("🏆 Successful infiltration detected, enhancing stealth measures")
            await self._enhance_stealth_operations()

    async def _handle_mission_completed(self, event: ShadowFoxEvent):
        """Handle mission completion"""
        mission_data = event.payload
        
        self.logger.info(f"🎯 Mission completed: {mission_data}")
        
        # Generate intelligence report
        intelligence_report = await self._generate_intelligence_report(mission_data)
        
        # Store learned intelligence
        self.memory['threat_intelligence'][f"mission_{mission_data.get('id', 'unknown')}"] = intelligence_report

    async def _handle_unknown_event(self, event: ShadowFoxEvent):
        """Handle unknown events with curiosity"""
        self.logger.debug(f"🌀 Processing unknown event: {event.type}")
        
        # Store for pattern analysis
        if 'unknown_events' not in self.memory:
            self.memory['unknown_events'] = []
        
        self.memory['unknown_events'].append({
            'type': event.type,
            'payload': event.payload,
            'timestamp': datetime.now().isoformat()
        })

    def _assess_threat_level(self, target_data: Dict) -> float:
        """Assess threat level of a target (0.0 to 1.0)"""
        threat_score = 0.0
        
        # Check for security indicators
        if 'technologies' in target_data:
            technologies = target_data['technologies']
            
            # High-value targets
            if any(tech in str(technologies).lower() for tech in ['admin', 'login', 'auth', 'api']):
                threat_score += 0.3
            
            # Vulnerable technologies
            if any(tech in str(technologies).lower() for tech in ['wordpress', 'drupal', 'joomla']):
                threat_score += 0.2
        
        # Check for exposed endpoints
        if 'endpoints' in target_data:
            endpoints = target_data['endpoints']
            if len(endpoints) > 10:
                threat_score += 0.2
        
        # Form presence indicates interaction potential
        if target_data.get('forms_detected', 0) > 0:
            threat_score += 0.3
        
        return min(threat_score, 1.0)

    def _recommend_personas(self, target_data: Dict) -> List[str]:
        """Recommend persona types based on target analysis"""
        personas = []
        
        # Determine appropriate personas based on target characteristics
        if 'e-commerce' in str(target_data).lower():
            personas.extend(['shopping_enthusiast', 'price_researcher'])
        
        if 'blog' in str(target_data).lower() or 'news' in str(target_data).lower():
            personas.extend(['content_consumer', 'casual_reader'])
        
        if 'login' in str(target_data).lower() or 'admin' in str(target_data).lower():
            personas.extend(['legitimate_user', 'tech_savvy_visitor'])
        
        # Default personas
        if not personas:
            personas = ['curious_visitor', 'casual_browser']
        
        return personas

    async def _auto_deploy_ghost_session(self, target_url: str, target_data: Dict):
        """Automatically deploy ghost session based on analysis"""
        self.logger.info(f"🚀 Auto-deploying ghost session for: {target_url}")
        
        # Determine objectives based on target analysis
        objectives = self._determine_objectives(target_data)
        
        # Create mission
        mission_id = self.operator.create_mission(target_url, "Auto-deployed Ghost Session")
        
        # Start ghost session
        session_results = self.ghost_engine.start_ghost_session(
            target_url, 
            mission_id, 
            objectives
        )
        
        # Store session information
        self.memory['active_sessions'][session_results['session_id']] = {
            'target_url': target_url,
            'mission_id': mission_id,
            'objectives': objectives,
            'started_at': datetime.now().isoformat(),
            'results': session_results
        }
        
        # Emit event about deployment
        await self.event_bus.emit(ShadowFoxEvent(
            type=EventType.AGENT_RESPONSE,
            payload=f"Ghost session deployed for {target_url} with {len(session_results['personas_deployed'])} personas",
            source="EnhancedGhostThreads"
        ))

    def _determine_objectives(self, target_data: Dict) -> List[str]:
        """Determine appropriate objectives based on target analysis"""
        objectives = ["stealth_reconnaissance"]  # Always include recon
        
        # Add specific objectives based on target characteristics
        if target_data.get('forms_detected', 0) > 0:
            objectives.append("form_injection")
        
        if 'login' in str(target_data).lower():
            objectives.extend(["session_extraction", "token_harvesting"])
        
        if target_data.get('cookies_enabled', True):
            objectives.append("behavioral_mapping")
        
        return objectives

    async def _deploy_exploitation_personas(self, vuln_data: Dict):
        """Deploy specialized personas for vulnerability exploitation"""
        self.logger.info("🎯 Deploying exploitation personas...")
        
        # Create specialized personas for exploitation
        exploit_personas = []
        for i in range(2):  # Deploy 2 specialized personas
            persona = self.ghost_engine.create_persona()
            
            # Modify persona for exploitation
            persona.shadow_attributes['stealth_payloads']['exploit_mode'] = True
            persona.shadow_attributes['exploitation_target'] = vuln_data
            
            exploit_personas.append(persona)
        
        self.logger.info(f"🔧 Deployed {len(exploit_personas)} exploitation personas")

    def _indicates_successful_infiltration(self, response_data: Any) -> bool:
        """Analyze if response indicates successful infiltration"""
        response_str = str(response_data).lower()
        
        success_indicators = [
            'successful', 'authenticated', 'logged in', 'access granted',
            'admin panel', 'dashboard', 'privilege', 'unauthorized access'
        ]
        
        return any(indicator in response_str for indicator in success_indicators)

    async def _enhance_stealth_operations(self):
        """Enhance stealth operations after successful infiltration"""
        self.logger.info("🔒 Enhancing stealth operations...")
        
        # Increase stealth settings for all active personas
        for persona_id, persona in self.ghost_engine.active_personas.items():
            # Reduce error rate
            persona.behavior['error_rate'] *= 0.5
            
            # Increase typing realism
            persona.behavior['typing_speed'] *= random.uniform(0.8, 1.2)
            
            # Enable advanced stealth features
            persona.shadow_attributes['stealth_payloads']['advanced_evasion'] = True

    async def _update_persona_strategies(self):
        """Update persona strategies based on learned data"""
        if not self.memory['successful_payloads'] and not self.memory['failed_payloads']:
            return
        
        self.logger.info("🧠 Updating persona strategies based on learned data...")
        
        # Analyze successful patterns
        successful_patterns = self._analyze_payload_patterns(self.memory['successful_payloads'])
        
        # Update persona generation to favor successful patterns
        for persona_id, persona in self.ghost_engine.active_personas.items():
            if successful_patterns:
                persona.shadow_attributes['learned_patterns'] = successful_patterns
                self.logger.debug(f"Updated strategies for persona {persona_id}")

    def _analyze_payload_patterns(self, payloads: List[Dict]) -> Dict:
        """Analyze successful payload patterns"""
        patterns = {
            'common_techniques': [],
            'effective_timing': [],
            'successful_contexts': []
        }
        
        # Simple pattern analysis (can be enhanced with ML)
        for payload_data in payloads[-10:]:  # Analyze last 10 successful payloads
            payload = payload_data.get('payload', '')
            
            if 'script' in payload.lower():
                patterns['common_techniques'].append('script_injection')
            if 'select' in payload.lower():
                patterns['common_techniques'].append('sql_injection')
            if 'img' in payload.lower():
                patterns['common_techniques'].append('html_injection')
        
        return patterns

    async def adaptive_learning_loop(self):
        """Background task for continuous adaptive learning"""
        while True:
            try:
                if self.adaptive_learning_enabled:
                    await self._perform_adaptive_learning()
                
                await asyncio.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in adaptive learning loop: {e}")
                await asyncio.sleep(60)

    async def _perform_adaptive_learning(self):
        """Perform adaptive learning analysis"""
        # Analyze persona performance
        for session_id, session_data in self.memory['active_sessions'].items():
            # Performance metrics
            success_rate = self._calculate_session_success_rate(session_data)
            
            if success_rate > 0.8:
                self.logger.info(f"📈 High-performing session detected: {session_id}")
                # Store successful strategies
                await self._store_successful_strategies(session_data)

    def _calculate_session_success_rate(self, session_data: Dict) -> float:
        """Calculate success rate for a session"""
        results = session_data.get('results', {})
        
        total_activities = len(results.get('stealth_activities', []))
        successful_activities = len(results.get('anomalies_injected', []))
        
        if total_activities == 0:
            return 0.0
        
        return successful_activities / total_activities

    async def _store_successful_strategies(self, session_data: Dict):
        """Store successful strategies for future use"""
        strategies = {
            'objectives': session_data.get('objectives', []),
            'success_rate': self._calculate_session_success_rate(session_data),
            'timestamp': datetime.now().isoformat()
        }
        
        if 'successful_strategies' not in self.memory:
            self.memory['successful_strategies'] = []
        
        self.memory['successful_strategies'].append(strategies)

    async def threat_correlation_loop(self):
        """Background task for threat intelligence correlation"""
        while True:
            try:
                if self.ai_config['threat_correlation']:
                    await self._correlate_threat_intelligence()
                
                await asyncio.sleep(600)  # Run every 10 minutes
                
            except Exception as e:
                self.logger.error(f"Error in threat correlation loop: {e}")
                await asyncio.sleep(120)

    async def _correlate_threat_intelligence(self):
        """Correlate threat intelligence across different sources"""
        # Analyze patterns across targets, vulnerabilities, and successful attacks
        targets = self.memory.get('targets', {})
        intel = self.memory.get('threat_intelligence', {})
        
        if len(targets) > 1 and len(intel) > 0:
            correlations = self._find_threat_correlations(targets, intel)
            
            if correlations:
                self.logger.info(f"🔍 Found {len(correlations)} threat correlations")
                await self._act_on_correlations(correlations)

    def _find_threat_correlations(self, targets: Dict, intel: Dict) -> List[Dict]:
        """Find correlations between targets and threat intelligence"""
        correlations = []
        
        # Simple correlation logic (can be enhanced)
        for target_url, target_data in targets.items():
            threat_level = target_data.get('threat_level', 0)
            
            if threat_level > 0.5:
                # Look for similar patterns in other targets
                similar_targets = [
                    url for url, data in targets.items() 
                    if url != target_url and data.get('threat_level', 0) > 0.5
                ]
                
                if similar_targets:
                    correlations.append({
                        'primary_target': target_url,
                        'similar_targets': similar_targets,
                        'correlation_type': 'high_threat_cluster'
                    })
        
        return correlations

    async def _act_on_correlations(self, correlations: List[Dict]):
        """Take action based on threat correlations"""
        for correlation in correlations:
            if correlation['correlation_type'] == 'high_threat_cluster':
                # Increase monitoring for correlated targets
                for target in correlation['similar_targets']:
                    self.logger.info(f"🎯 Increasing monitoring for correlated target: {target}")

    async def _generate_intelligence_report(self, mission_data: Dict) -> Dict:
        """Generate comprehensive intelligence report"""
        report = {
            'mission_id': mission_data.get('id'),
            'completed_at': datetime.now().isoformat(),
            'personas_used': len(self.ghost_engine.active_personas),
            'successful_payloads': len(self.memory['successful_payloads']),
            'failed_payloads': len(self.memory['failed_payloads']),
            'targets_analyzed': len(self.memory['targets']),
            'threat_intelligence_gathered': len(self.memory['threat_intelligence']),
            'key_findings': self._extract_key_findings(),
            'recommendations': self._generate_recommendations()
        }
        
        return report

    def _extract_key_findings(self) -> List[str]:
        """Extract key findings from collected data"""
        findings = []
        
        # Analyze successful payload patterns
        if self.memory['successful_payloads']:
            findings.append(f"Identified {len(self.memory['successful_payloads'])} successful attack vectors")
        
        # High-threat targets
        high_threat_targets = [
            url for url, data in self.memory['targets'].items()
            if data.get('threat_level', 0) > 0.7
        ]
        
        if high_threat_targets:
            findings.append(f"Detected {len(high_threat_targets)} high-threat targets")
        
        return findings

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Based on successful strategies
        if 'successful_strategies' in self.memory and self.memory['successful_strategies']:
            recommendations.append("Continue using proven successful attack patterns")
        
        # Based on failed attempts
        if len(self.memory['failed_payloads']) > len(self.memory['successful_payloads']):
            recommendations.append("Consider adjusting payload strategies for better success rate")
        
        return recommendations

    async def get_intelligence_summary(self) -> Dict:
        """Get current intelligence summary"""
        return {
            'active_sessions': len(self.memory['active_sessions']),
            'targets_monitored': len(self.memory['targets']),
            'successful_operations': len(self.memory['successful_payloads']),
            'threat_intelligence_items': len(self.memory['threat_intelligence']),
            'adaptive_learning_status': self.adaptive_learning_enabled,
            'memory_usage': len(str(self.memory))
        }

# Alias for backward compatibility
GhostThreads = EnhancedGhostThreads
