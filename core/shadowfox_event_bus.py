#/10usr/bin/env python3
"""
ShadowFox17 - Event Bus System
Real-time komunikacija između modula sa AI decision making
"""

import asyncio
import threading
import time
import json
import logging
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import weakref
import hashlib


class EventPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class EventType(Enum):
    # Mission events
    MISSION_STARTED = "mission_started"
    MISSION_PHASE_CHANGED = "mission_phase_changed"
    MISSION_COMPLETED = "mission_completed"
    MISSION_ERROR = "mission_error"

    # Target discovery
    TARGET_DISCOVERED = "target_discovered"
    ENDPOINT_FOUND = "endpoint_found"
    PARAMETER_FOUND = "parameter_found"
    TECHNOLOGY_DETECTED = "technology_detected"

    # Payload events
    PAYLOAD_GENERATED = "payload_generated"
    PAYLOAD_SUCCESSFUL = "payload_successful"
    PAYLOAD_FAILED = "payload_failed"
    PAYLOAD_MUTATED = "payload_mutated"

    # Vulnerability events
    VULNERABILITY_FOUND = "vulnerability_found"
    VULNERABILITY_CONFIRMED = "vulnerability_confirmed"
    FALSE_POSITIVE = "false_positive"

    # AI events
    AI_DECISION = "ai_decision"
    AI_LEARNING = "ai_learning"
    AI_PATTERN_DETECTED = "ai_pattern_detected"

    # System events
    MODULE_STARTED = "module_started"
    MODULE_STOPPED = "module_stopped"
    MODULE_ERROR = "module_error"
    RATE_LIMIT_HIT = "rate_limit_hit"

    # Proxy events
    REQUEST_INTERCEPTED = "request_intercepted"
    RESPONSE_ANALYZED = "response_analyzed"
    ANOMALY_DETECTED = "anomaly_detected"


@dataclass
class ShadowFoxEvent:
    event_type: EventType
    mission_id: str
    source_module: str
    data: Dict[str, Any]
    timestamp: float = None
    priority: EventPriority = EventPriority.NORMAL
    event_id: str = None
    correlation_id: str = None

    def __post_init__(self):
        if not self.event_id:
            self.event_id = f"evt_{int(time.time() * 1000000)}"
        if not self.timestamp:
            self.timestamp = time.time()


class EventHandler:
    """Wrapper za event handler funkcije"""

    def __init__(self, callback: Callable, module_name: str,
                 event_types: List[EventType], priority: int = 0,
                 async_handler: bool = False):
        self.callback = callback
        self.module_name = module_name
        self.event_types = set(event_types)
        self.priority = priority  # Viši broj = viši prioritet
        self.async_handler = async_handler
        self.call_count = 0
        self.error_count = 0
        self.last_called = 0
        self.avg_execution_time = 0.0

    def can_handle(self, event_type: EventType) -> bool:
        return event_type in self.event_types

    async def handle_event(self, event: ShadowFoxEvent) -> bool:
        """Poziva handler i vraća True ako je uspešno"""
        start_time = time.time()
        try:
            if self.async_handler:
                if asyncio.iscoroutinefunction(self.callback):
                    await self.callback(event)
                else:
                    await asyncio.get_event_loop().run_in_executor(None, self.callback, event)
            else:
                self.callback(event)

            # Statistike
            execution_time = time.time() - start_time
            self.call_count += 1
            self.last_called = time.time()
            self.avg_execution_time = (
                (self.avg_execution_time * (self.call_count - 1)) + execution_time) / self.call_count

            return True

        except Exception as e:
            self.error_count += 1
            logging.error(f"Event handler error in {self.module_name}: {e}")
            return False


class ShadowFoxEventBus:
    """
    Centralni event bus za ShadowFox module
    Thread-safe sa async podrškom i AI decision making
    """

    def __init__(self, max_history: int = 10000):
        self.handlers: Dict[EventType, List[EventHandler]] = defaultdict(list)
        self.event_history: deque = deque(maxlen=max_history)
        self.event_stats: Dict[EventType, Dict] = defaultdict(lambda: {
            'total_count': 0,
            'success_count': 0,
            'error_count': 0,
            'avg_processing_time': 0.0
        })

        # Threading

        self._lock = asyncio.Lock()
        self._shutdown = False

        # Async support
        self._loop = None
        self._event_queue = deque()
        self._processing_thread = None

        # AI Decision making
        self.ai_patterns: Dict[str, Any] = {}
        self.correlation_tracker: Dict[str,
                                       List[ShadowFoxEvent]] = defaultdict(list)

        # Middleware pipeline
        self.middleware: List[Callable] = []

        # Event filtering
        self.filters: Dict[str, Callable] = {}

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("ShadowFoxEventBus")

        # Startuj processing thread
        self._start_processing_thread()

    async def _dispatch(self, event: ShadowFoxEvent):
        """
        Interna metoda za slanje eventa svim registrovanim handlerima
        """
        async with self._lock:
            self._event_queue.append(event)

    # Odmah pokreni procesor ako nije aktivan
        if not self._processing_thread or not self._processing_thread.is_alive():
            self._start_processing_thread()

    def add_middleware(self, middleware_func: Callable):
        """Dodaje middleware za event processing"""
        self.middleware.append(middleware_func)

    async def start(self):
        """
        Pokreće ShadowFox EventBus (placeholder za sada)
        """
        self.logger.info("[🚌] ShadowFoxEventBus.start() pozvan — OK")

    def add_filter(self, filter_name: str, filter_func: Callable):
        """Dodaje filter za event-e"""
        self.filters[filter_name] = filter_func

    from typing import Callable, List
    import asyncio
    import time


    async def register_handler(
        self,
        event_types: List[EventType],
        callback: Callable,
        module_name: str,
        priority: int = 0,
        async_handler: bool = False
        ) -> str:
        """Registruje event handler"""

        if not isinstance(event_types, list):
            event_types = [event_types]

        handler = EventHandler(
            callback,
            module_name,
            event_types,
            priority,
            async_handler
        )
        handler_id = f"handler_{module_name}_{int(time.time() * 1000)}"

        async with self._lock:
            for event_type in event_types:
                self.handlers[event_type].append(handler)

            # Sortiraj po prioritetu (veći broj = viši prioritet)
                self.handlers[event_type].sort(
                    key=lambda h: h.priority,
                    reverse=True
                )

            self.logger.info(f"Registered handler {handler_id} for {module_name}")
            return handler_id
    async def unregister_handler(self, handler_id: str, module_name: str):
        """Uklanja event handler"""
        async with self._lock:
            self._lock = asyncio.Lock()
            for event_type in self.handlers:
                self.handlers[event_type] = [
                    h for h in self.handlers[event_type] if h.module_name != module_name]

        self.logger.info(
            f"Unregistered handler {handler_id} for {module_name}")

    def _start_processing_thread(self):
        """Startuje background thread za event processing"""
        if self._processing_thread and self._processing_thread.is_alive():
            return

        self._processing_thread = threading.Thread(
            target=self._process_events_loop,
            daemon=True,
            name="ShadowFoxEventProcessor"
        )
        self._processing_thread.start()

    async def _process_events_loop(self):
        """Main event processing loop"""
        while not self._shutdown:
            try:
                # Dobij event iz queue
                async with self._lock:
                    self._lock = asyncio.Lock()
                    if not self._event_queue:
                        time.sleep(0.01)  # Short sleep da ne troši CPU
                        continue
                    event = self._event_queue.popleft()

                # Procesiraj event
                asyncio.run(self._process_single_event(event))

            except Exception as e:
                self.logger.error(f"Error in event processing loop: {e}")
                time.sleep(0.1)

    async def _process_single_event(self, event: ShadowFoxEvent):
        """Procesira pojedinačni event"""
        start_time = time.time()

        try:
            # Primeni middleware
            for middleware in self.middleware:
                event = middleware(event)
                if not event:  # Middleware može da blokira event
                    return

            # Primeni filtere
            for filter_name, filter_func in self.filters.items():
                if not filter_func(event):
                    self.logger.debug(
                        f"Event {event.event_id} filtered by {filter_name}")
                    return

            # AI Pattern Detection
            self._detect_patterns(event)

            # Correlation tracking
            if event.correlation_id:
                self.correlation_tracker[event.correlation_id].append(event)

            # Pozovi handlere
            handlers = self.handlers.get(event.event_type, [])
            success_count = 0

            for handler in handlers:
                if handler.can_handle(event.event_type):
                    success = await handler.handle_event(event)
                    if success:
                        success_count += 1

            # Statistike
            processing_time = time.time() - start_time
            stats = self.event_stats[event.event_type]
            stats['total_count'] += 1
            stats['success_count'] += success_count
            stats['avg_processing_time'] = (
                (stats['avg_processing_time'] * (stats['total_count'] - 1) + processing_time) /
                stats['total_count']
            )

            # Dodaj u history
            self.event_history.append(event)

            self.logger.debug(
                f"Processed event {event.event_id} with {success_count} successful handlers")

        except Exception as e:
            self.event_stats[event.event_type]['error_count'] += 1
            self.logger.error(f"Error processing event {event.event_id}: {e}")

    def _detect_patterns(self, event: ShadowFoxEvent):
        """AI Pattern Detection - detektuje obrasce u event-ima"""
        try:
            # Pattern 1: Uzastopni payload uspesi
            if event.event_type == EventType.PAYLOAD_SUCCESSFUL:
                recent_successes = [e for e in list(self.event_history)[-10:]
                                    if e.event_type == EventType.PAYLOAD_SUCCESSFUL
                                    and e.mission_id == event.mission_id]

                if len(recent_successes) >= 3:
                    pattern_event = ShadowFoxEvent(
                        event_type=EventType.AI_PATTERN_DETECTED,
                        mission_id=event.mission_id,
                        source_module="ai_pattern_detector",
                        data={
                            'pattern_type': 'payload_success_streak',
                            'streak_count': len(recent_successes),
                            'confidence': min(0.9, len(recent_successes) / 10)
                        }
                    )
                    self._queue_event(pattern_event)

            # Pattern 2: Rate limiting detection
            if event.event_type == EventType.RATE_LIMIT_HIT:
                recent_rate_limits = [e for e in list(self.event_history)[-20:]
                                      if e.event_type == EventType.RATE_LIMIT_HIT
                                      and e.mission_id == event.mission_id]

                if len(recent_rate_limits) >= 2:
                    pattern_event = ShadowFoxEvent(
                        event_type=EventType.AI_PATTERN_DETECTED,
                        mission_id=event.mission_id,
                        source_module="ai_pattern_detector",
                        data={
                            'pattern_type': 'aggressive_rate_limiting',
                            'rate_limit_count': len(recent_rate_limits),
                            'recommendation': 'reduce_attack_intensity'
                        }
                    )
                    self._queue_event(pattern_event)

            # Pattern 3: Vulnerability clustering
            if event.event_type == EventType.VULNERABILITY_FOUND:
                recent_vulns = [e for e in list(self.event_history)[-50:]
                                if e.event_type == EventType.VULNERABILITY_FOUND
                                and e.mission_id == event.mission_id]

                if len(recent_vulns) >= 5:
                    vuln_types = [e.data.get('vuln_type')
                                  for e in recent_vulns]
                    most_common = max(set(vuln_types), key=vuln_types.count)

                    pattern_event = ShadowFoxEvent(
                        event_type=EventType.AI_PATTERN_DETECTED,
                        mission_id=event.mission_id,
                        source_module="ai_pattern_detector",
                        data={
                            'pattern_type': 'vulnerability_cluster',
                            'dominant_vuln_type': most_common,
                            'cluster_size': len(recent_vulns),
                            'recommendation': f'focus_on_{most_common.lower()}_payloads'})
                    self._queue_event(pattern_event)

        except Exception as e:
            self.logger.error(f"Error in pattern detection: {e}")

    async def _queue_event(self, event: ShadowFoxEvent):
        """Dodaje event u processing queue"""
        async with self._lock:
            self._lock = asyncio.Lock()
            self._event_queue.append(event)

    async def publish(self, *args, **kwargs) -> str:
        """
        Publikuje event na bus – podržava i ShadowFoxEvent i klasične parametre
        """
        if len(args) == 1 and isinstance(args[0], ShadowFoxEvent):
            event = args[0]
        else:
            event = ShadowFoxEvent(
                event_type=kwargs.get("event_type"),
                mission_id=kwargs.get("mission_id"),
                source_module=kwargs.get("source_module"),
                data=kwargs.get("data"),
                timestamp=kwargs.get("timestamp", time.time()),
                priority=kwargs.get("priority", EventPriority.NORMAL),
                correlation_id=kwargs.get("correlation_id")
            )

        await self._dispatch(event)

        self.logger.debug(
            f"Published event {event.event_id} of type {event.event_type}")
        return event.event_id

    def publish_sync(self,
                     event_type: EventType,
                     mission_id: str,
                     source_module: str,
                     data: Dict[str,
                                Any]) -> List[bool]:
        """Synchronous event publishing - čeka da se event procesi"""
        event = ShadowFoxEvent(
            event_type=event_type,
            mission_id=mission_id,
            source_module=source_module,
            data=data,
            timestamp=time.time()
        )

        # Procesuj direktno bez queue
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._process_single_event(event))
        finally:
            loop.close()

        return True

    def wait_for_event(self, event_type: EventType, mission_id: str,
                       timeout: float = 30.0) -> Optional[ShadowFoxEvent]:
        """Čeka specifični event sa timeout"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            # Pretraži recent history
            for event in reversed(list(self.event_history)):
                if (event.event_type == event_type and
                    event.mission_id == mission_id and
                        event.timestamp > start_time):
                    return event

            time.sleep(0.1)

        return None

    def get_correlated_events(
            self,
            correlation_id: str) -> List[ShadowFoxEvent]:
        """Dobija sve event-e sa istim correlation_id"""
        return self.correlation_tracker.get(correlation_id, [])

    def get_event_stats(self, event_type: EventType = None) -> Dict:
        """Dobija statistike za event-e"""
        if event_type:
            return self.event_stats.get(event_type, {})

        return dict(self.event_stats)

    def get_recent_events(
            self,
            mission_id: str = None,
            event_type: EventType = None,
            limit: int = 100) -> List[ShadowFoxEvent]:
        """Dobija recent event-e sa filterima"""
        events = list(self.event_history)

        if mission_id:
            events = [e for e in events if e.mission_id == mission_id]

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        return events[-limit:]

    def create_correlation_id(self, prefix: str = "corr") -> str:
        """Generiše correlation ID za p

ovezane event-e"""
        timestamp = str(time.time())
        hash_input = f"{prefix}_{timestamp}_{threading.current_thread().dent}"
        return f"{prefix}_{hashlib.sha256(hash_input.encode()).hexdigest()[:12]}"

    async def shutdown(self):
        """Graceful shutdown event bus-a"""
        self.logger.info("Shutting down ShadowFox Event Bus...")
        self._shutdown = True

        # Čekaj da se završi processing thread
        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=5.0)

        # Procesiraj preostale event-e
        async with self._lock:
            self._lock = asyncio.Lock()
            remaining_events = len(self._event_queue)
            if remaining_events > 0:
                self.logger.info(
                    f"Processing {remaining_events} remaining events...")

                # Brzо procesiraj preostale event-e
                for _ in range(min(remaining_events, 100)):  # Limit za safety
                    if self._event_queue:
                        event = self._event_queue.popleft()
                        try:
                            asyncio.run(self._process_single_event(event))
                        except BaseException:
                            pass

        self.logger.info("ShadowFox Event Bus shutdown complete")


# === DECORATOR ZA LAKO REGISTROVANJE HANDLER-A ===

def event_handler(
    *event_types,
    priority: int = 0,
        async_handler: bool = False):
    """Decorator za registrovanje event handler-a"""
    def decorator(func):
        func._shadowfox_event_types = event_types
        func._shadowfox_priority = priority
        func._shadowfox_async = async_handler
        return func
    return decorator


# === HELPER KLASE ===

class EventMiddleware:
    """Base klasa za event middleware"""

    def __call__(self, event: ShadowFoxEvent) -> Optional[ShadowFoxEvent]:
        return self.process(event)

    def process(self, event: ShadowFoxEvent) -> Optional[ShadowFoxEvent]:
        return event


class LoggingMiddleware(EventMiddleware):
    """Middleware za logovanje event-a"""

    def __init__(self, log_level: int = logging.INFO):
        self.logger = logging.getLogger("EventLogging")
        self.log_level = log_level

    def process(self, event: ShadowFoxEvent) -> Optional[ShadowFoxEvent]:
        self.logger.log(
            self.log_level,
            f"Event: {event.event_type.value} | Mission: {event.mission_id} | "
            f"Source: {event.source_module} | Data: {json.dumps(event.data, default=str)[:200]}"
        )
        return event

class RateLimitMiddleware(EventMiddleware):
    """Middleware za rate limiting event-a"""

    def __init__(self, max_events_per_second: int = 100):
        self.max_events = max_events_per_second
        self.event_timestamps = deque()

    def process(self, event: ShadowFoxEvent) -> Optional[ShadowFoxEvent]:
        now = time.time()

        # Ukloni stare timestamps
        while self.event_timestamps and self.event_timestamps[0] < now - 1:
            self.event_timestamps.popleft()

        # Proveri rate limit
        if len(self.event_timestamps) >= self.max_events:
            logging.warning(
                f"Rate limit exceeded, dropping event {event.event_id}")
            return None

        self.event_timestamps.append(now)
        return event


# === USAGE EXAMPLE ===
if __name__ == "__main__":
    # Inicijalizuj event bus
    event_bus = ShadowFoxEventBus()

    # Dodaj middleware
    event_bus.add_middleware(LoggingMiddleware())
    event_bus.add_middleware(RateLimitMiddleware(max_events_per_second=50))

    # Test handler
    def vulnerability_handler(event: ShadowFoxEvent):
        print(f"VULNERABILITY FOUND: {event.data}")

    def payload_handler(event: ShadowFoxEvent):
        print(f"PAYLOAD SUCCESS: {event.data}")

    # Registruj handler-e
    event_bus.register_handler(
        [EventType.VULNERABILITY_FOUND],
        vulnerability_handler,
        "test_vuln_handler"
    )

    event_bus.register_handler(
        [EventType.PAYLOAD_SUCCESSFUL],
        payload_handler,
        "test_payload_handler"
    )

    # Test event publishing
    mission_id = "test_mission_123"

    # Publih neki event-i
    event_bus.publish(
        EventType.VULNERABILITY_FOUND,
        mission_id,
        "test_module",
        {
            "vuln_type": "XSS",
            "url": "https://example.com/search",
            "severity": "HIGH"
        }
    )

    event_bus.publish(
        EventType.PAYLOAD_SUCCESSFUL,
        mission_id,
        "fuzzer_module",
        {
            "payload": "<script>alert(1)</script>",
            "response_time": 0.5
        }
    )

    # Čekaj malo da se procese
    time.sleep(2)

    # Dobij statistike
    stats = event_bus.get_event_stats()
    print(f"Event stats: {stats}")

    # Dobij recent events
    recent = event_bus.get_recent_events(mission_id=mission_id)
    print(f"Recent events: {len(recent)}")

    # Shutdown
    event_bus.shutdown()
