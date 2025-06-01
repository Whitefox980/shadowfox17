#!/usr/bin/env python3
"""
ShadowFox17 - Main Entry Point
AI-Driven Penetration Testing Framework
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "modules")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "modules/payloads")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import time
import signal
import argparse
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

# ShadowFox imports
from core.shadowfox_db import ShadowFoxDB
from core.shadowfox_event_bus import ShadowFoxEventBus, EventType, ShadowFoxEvent, EventPriority
from core.orchestrator import ShadowFoxOrchestrator
from modules.command.operator import ShadowFoxOperator
from modules.ai.explainable_ai import ExplainableAI
from modules.ai.taktician_agent import TakticianAgent
from modules.command.mission_controller import ShadowFoxMissionController
from modules.attacks.ghost_threads import ShadowPersona
from modules.attacks.fuzz_engine import FuzzEngine
from modules.attacks.xse_engine import VulnType
from modules.payloads.rainbow_mutation import RainbowMutation
from modules.payloads.mutation_engine import MutationEngine
from modules.intelligence.dom_collector import DOMCollector
from modules.intelligence.pathfinder import AttackSurface
from modules.intelligence.vulnerability_mapper import VulnSeverity
from modules.reporting.pdf_exporter import PDFExporter
from modules.proxy.shadow_proxy import AIPayloadMutator
from modules.proxy.traffic_shaper import TrafficShaper
from core.base_module import ModuleStatus
from modules.ai.ai_brain import TaskPriority
from modules.attacks.smart_shadow_agent import SmartShadowAgent
from modules.payloads.payload_seeder import PayloadLibrarySeeder
from modules.intelligence.shadow_spyder import CrawlResult
from modules.reporting.proof_collector import ProofCollector
from core.orchestrator import ModuleStatus
from core.shadowfox_event_bus import EventHandler
from modules.ai.ai_brain import AIBrain

from modules.ai.shadow_operator import ShadowFoxOperator
from modules.monitor.ghost_task_monitor import GhostThreadMonitor
asyncio.create_task(GhostThreadMonitor().monitor())
operator = ShadowFoxOperator()
class ShadowFoxCLI:
    """
    Main ShadowFox CLI interface
    Upravlja celim lifecycle-om sistema
    """
    
    def __init__(self):
        self.console = Console()
        self.db: Optional[ShadowFoxDB] = None
        self.event_bus: Optional[ShadowFoxEventBus] = None
        self.orchestrator: Optional[ShadowFoxOrchestrator] = None

        self.operator = ShadowFoxOperator(
        base_dir="shadowfox17",
        db=self.db,
        event_bus=self.event_bus
        )
        
        self.current_mission_id: Optional[str] = None
        self.shutdown_requested = False
        brain = AIBrain(operator)
        # Statistike
        self.start_time = time.time()
        self.mission_count = 0
        self.total_vulnerabilities = 0
        
        # Setup logging
        self.setup_logging()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    async def interactive_mode(self):
        self.console.print("[blue]🔁 Pokrećem interaktivni režim...[/blue]")
    # tvoj CLI event-loop ide ovde
    def setup_logging(self):
        """Podešava logging sistem"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"shadowfox_{int(time.time())}.log"),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("ShadowFoxCLI")
    
    def signal_handler(self, signum, frame):
        """Handles graceful shutdown"""
        self.console.print("\n[yellow]🛑 Shutdown signal received. Stopping ShadowFox...[/yellow]")
        self.shutdown_requested = True
        
        if self.current_mission_id and self.db:
            self.db.update_mission_status(self.current_mission_id, "interrupted")
        
        self.shutdown()
        sys.exit(0)
    
    def print_banner(self):
        """Prikazuje ShadowFox banner"""
        banner = """
    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗ ██╗  ██╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔═══██╗╚██╗██╔╝
    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║█████╗  ██║   ██║ ╚███╔╝ 
    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══╝  ██║   ██║ ██╔██╗ 
    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║     ╚██████╔╝██╔╝ ██╗
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝
    
                    🦊 AI-Driven Penetration Testing Framework v17 🦊
                           Advanced Modular Security Assessment
        """
        
        self.console.print(Panel(
            Text(banner, style="bold cyan"),
            title="[bold red]ShadowFox17[/bold red]",
            border_style="red"
        ))
    
    async def initialize_system(self):
        """Inicijalizuje sve komponente sistema"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Database
            task = progress.add_task("🗃️  Initializing database...", total=None)
            try:
                self.db = ShadowFoxDB()
                progress.update(task, description="✅ Database initialized")
                await asyncio.sleep(0.5)
            except Exception as e:
                self.console.print(f"[red]❌ Database initialization failed: {e}[/red]")
                return False
            
            # Event Bus
            task = progress.add_task("🚌 Starting event bus...", total=None)
            try:
                self.event_bus = ShadowFoxEventBus()
                await self.event_bus.start()
                self.setup_core_event_handlers()
                progress.update(task, description="✅ Event bus started")
                await asyncio.sleep(0.5)
            except Exception as e:
                self.console.print(f"[red]❌ Event bus initialization failed: {e}[/red]")
                return False
            
            # Orchestrator
            task = progress.add_task("🎼 Initializing orchestrator...", total=None)
            try:
                self.orchestrator = ShadowFoxOrchestrator(self.db, self.event_bus)
                await self.orchestrator.initialize()
                progress.update(task, description="✅ Orchestrator initialized")
                await asyncio.sleep(0.5)
            except Exception as e:
                self.console.print(f"[red]❌ Orchestrator initialization failed: {e}[/red]")
                return False
            
            # Operator
            task = progress.add_task("👤 Starting operator...", total=None)
            try:
                self.operator = ShadowFoxOperator(self.db, self.event_bus)
                await self.operator.initialize()
                progress.update(task, description="✅ Operator ready")
                await asyncio.sleep(0.5)
            except Exception as e:
                self.console.print(f"[red]❌ Operator initialization failed: {e}[/red]")
                return False
        
        return True
    
    def setup_core_event_handlers(self):
        """Podešava osnovne event handlere"""
        
        def on_mission_started(event: ShadowFoxEvent):
            self.current_mission_id = event.data.get('mission_id')
            self.mission_count += 1
            self.console.print(f"[green]🚀 Mission started: {self.current_mission_id}[/green]")
        
        def on_vulnerability_found(event: ShadowFoxEvent):
            self.total_vulnerabilities += 1
            vuln_type = event.data.get('vuln_type', 'Unknown')
            severity = event.data.get('severity', 'Unknown')
            url = event.data.get('url', 'Unknown')
            
            color = {
                'CRITICAL': 'red',
                'HIGH': 'orange3',
                'MEDIUM': 'yellow',
                'LOW': 'green',
                'INFO': 'blue'
            }.get(severity, 'white')
            
            self.console.print(f"[{color}]🎯 VULNERABILITY FOUND: {vuln_type} ({severity}) at {url}[/{color}]")
        
        def on_mission_completed(event: ShadowFoxEvent):
            mission_id = event.data.get('mission_id')
            stats = event.data.get('stats', {})
            
            self.console.print(f"[green]✅ Mission completed: {mission_id}[/green]")
            self.show_mission_summary(stats)
        
        def on_ai_decision(event: ShadowFoxEvent):
            decision = event.data.get('decision', 'Unknown')
            confidence = event.data.get('confidence', 0.0)
            
            if confidence > 0.8:
                self.console.print(f"[cyan]🧠 AI Decision: {decision} (confidence: {confidence:.2f})[/cyan]")
        
        # Registracija handlera
        self.event_bus.register_handler(
            [EventType.MISSION_STARTED], on_mission_started, "CLI"
        )
        self.event_bus.register_handler(
            [EventType.VULNERABILITY_FOUND], on_vulnerability_found, "CLI"
        )
        self.event_bus.register_handler(
            [EventType.MISSION_COMPLETED], on_mission_completed, "CLI"
        )
        self.event_bus.register_handler(
            [EventType.AI_DECISION], on_ai_decision, "CLI"
        )
    
    async def run_mission(self, target_url: str, config: Dict):
        """Pokreće misiju"""
        try:
            self.console.print(f"[cyan]🎯 Starting mission against: {target_url}[/cyan]")
            
            # Kreiranje misije
            mission_id = self.db.create_mission(target_url, config)
            self.current_mission_id = mission_id
            
            # Event za početak misije
            await self.event_bus.publish(ShadowFoxEvent(
                event_type=EventType.MISSION_STARTED,
                mission_id=mission_id,
                source_module="CLI",
                data={
                    'mission_id': mission_id,
                    'target_url': target_url,
                    'config': config
                },
                priority=EventPriority.HIGH
            ))
            
            # Pokretanje kroz Orchestrator
            success = await self.orchestrator.start_mission(target_url, config)
            
            if success:
                self.console.print("[green]✅ Mission completed successfully[/green]")
            else:
                self.console.print("[red]❌ Mission failed or interrupted[/red]")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Mission execution error: {e}")
            self.console.print(f"[red]❌ Mission error: {e}[/red]")
            return False
    
    def show_mission_summary(self, stats: Dict):
        """Prikazuje sažetak misije"""
        table = Table(title="Mission Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Vulnerabilities Found", str(stats.get('vulnerabilities', 0)))
        table.add_row("Payloads Tested", str(stats.get('payloads', 0)))
        table.add_row("Intelligence Gathered", str(stats.get('intelligence', 0)))
        table.add_row("Success Rate", f"{stats.get('avg_payload_success', 0):.2%}")
        table.add_row("Duration", f"{stats.get('duration', 0):.1f}s")
        
        self.console.print(table)
    
    async def interactive_mode(self):
        """Interaktivni režim rada"""
        self.interactive_mode = True
        self.console.print("[cyan]🔄 Entering interactive mode...[/cyan]")
        
        while not self.shutdown_requested:
            try:
                command = Prompt.ask(

                    "\n[bold cyan]ShadowFox>[/bold cyan]",
                    choices=["mission", "status", "stats", "modules", "help", "exit"],
                    default="help"
                )
                self.console.print(f"[yellow]DEBUG CMD: '{command}'[/yellow]")
                if command == "exit":
                    break
                elif command == "help":
                    self.show_help()
                elif command == "mission":
                    await self.interactive_mission()
                elif command == "status":
                    self.show_status()
                elif command == "stats":
                    self.show_stats()
                elif command == "modules":
                    self.show_modules()
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'exit' to quit properly[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
    
    async def interactive_mission(self):
        """Interaktivno kreiranje misije"""
        target_url = Prompt.ask("🎯 Target URL")
        
        intensity = Prompt.ask("📶 Intenzitet [low/medium/high/extreme]", choices=["low", "medium", "high", "extreme"], default="medium")
        stealth = Confirm.ask("🕵️‍♂️ Aktivirati stealth režim?", default=False)
        use_ai = Confirm.ask("🧠 Aktivirati AI donošenje odluka?", default=True)

# Dummy prikaz misije za sada
        self.console.print("\n[bold green]✅ Misija kreirana![/bold green]")
        self.console.print(f"🌐 Target: {target_url}")
        self.console.print(f"📶 Intenzitet: {intensity}")
        self.console.print(f"🕵️‍♂️ Stealth: {'Da' if stealth else 'Ne'}")
        self.console.print(f"🧠 AI: {'Aktivirano' if use_ai else 'Deaktivirano'}")

# Ovde kasnije zovemo orchestrator.start_mission(...) sa parametrima
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"
        
        # Konfiguracija
        intensity = Prompt.ask(
            "⚡ Attack intensity",
            choices=["low", "medium", "high", "extreme"],
            default="medium"
        )
        
        stealth = Confirm.ask("🥷 Enable stealth mode?", default=True)
        
        ai_enabled = Confirm.ask("🧠 Enable AI decision making?", default=True)
        
        config = {
            "intensity": intensity,
            "stealth": stealth,
            "ai_enabled": ai_enabled,
            "max_threads": {"low": 1, "medium": 3, "high": 5, "extreme": 10}[intensity],
            "delay_range": [1, 3] if stealth else [0.1, 0.5]
        }
        
        # Confirm and run
        self.console.print(f"\n[cyan]Configuration:[/cyan]")
        self.console.print(f"Target: {target_url}")
        self.console.print(f"Intensity: {intensity}")
        self.console.print(f"Stealth: {stealth}")
        self.console.print(f"AI: {ai_enabled}")
        
        if Confirm.ask("\n🚀 Start mission?", default=True):
            await self.run_mission(target_url, config)
    
    def show_help(self):
        """Prikazuje help"""
        help_text = """
[bold cyan]ShadowFox Commands:[/bold cyan]

[green]mission[/green]  - Start a new penetration testing mission
[green]status[/green]   - Show current system status
[green]stats[/green]    - Show overall statistics
[green]modules[/green]  - Show loaded modules status
[green]help[/green]     - Show this help
[green]exit[/green]     - Exit ShadowFox

[yellow]Example Mission Flow:[/yellow]
1. Run 'mission' command
2. Enter target URL (e.g., https://example.com)
3. Configure attack parameters
4. Monitor progress in real-time
5. Review results and generated reports
        """
        self.console.print(Panel(help_text, title="Help", border_style="blue"))
    
    def show_status(self):
        """Prikazuje status sistema"""
        uptime = time.time() - self.start_time
        
        status_table = Table(title="System Status")
        status_table.add_column("Component", style="cyan")
        status_table.add_column("Status", style="green")
        status_table.add_column("Info", style="white")
        
        # System components
        status_table.add_row("Database", "✅ Active", f"SQLite connection")
        status_table.add_row("Event Bus", "✅ Active", f"{len(self.event_bus.handlers) if self.event_bus else 0} handlers")
        status_table.add_row("Orchestrator", "✅ Active", "Ready for missions")
        status_table.add_row("Operator", "✅ Active", "AI-enabled")
        
        # Runtime info
        status_table.add_row("Uptime", f"{uptime:.1f}s", f"Started at {time.ctime(self.start_time)}")
        status_table.add_row("Current Mission", 
                           self.current_mission_id or "None", 
                           "Active" if self.current_mission_id else "Idle")
        
        self.console.print(status_table)
    
    def show_stats(self):
        """Prikazuje statistike"""
        stats_table = Table(title="Overall Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Missions Run", str(self.mission_count))
        stats_table.add_row("Vulnerabilities Found", str(self.total_vulnerabilities))
        stats_table.add_row("Uptime", f"{time.time() - self.start_time:.1f}s")
        
        if self.db:
            # Database stats
            try:
                # Get recent missions
                # This would need to be implemented in the DB class
                pass
            except:
                pass
        
        self.console.print(stats_table)
    
    def show_modules(self):
        """Prikazuje status modula"""
        if not self.orchestrator:
            self.console.print("[red]Orchestrator not initialized[/red]")
            return
        
        modules_table = Table(title="Module Status")
        modules_table.add_column("Module", style="cyan")
        modules_table.add_column("Status", style="green")
        modules_table.add_column("Last Activity", style="white")
        
        # This would be populated by the orchestrator
        sample_modules = [
            ("shadow_spider", "✅ Ready", "5min ago"),
            ("payload_seeder", "✅ Ready", "2min ago"),
            ("smart_shadow_agent", "✅ Ready", "1min ago"),
            ("ai_brain", "✅ Ready", "30sec ago"),
            ("proof_collector", "✅ Ready", "10sec ago")
        ]
        
        for module, status, activity in sample_modules:
            modules_table.add_row(module, status, activity)
        
        self.console.print(modules_table)
    
    def shutdown(self):
        """Graceful shutdown"""
        self.console.print("[yellow]🛑 Shutting down ShadowFox...[/yellow]")
        
        if self.orchestrator:
            try:
                asyncio.run(self.orchestrator.shutdown())
            except:
                pass
        
        if self.event_bus:
            try:
                asyncio.run(self.event_bus.shutdown())
            except:
                pass
        
        self.console.print("[green]✅ ShadowFox shutdown complete[/green]")

def create_parser():
    """Kreira argument parser"""
    parser = argparse.ArgumentParser(
        description="ShadowFox17 - AI-Driven Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shadowfox.py -t https://example.com                    # Quick scan
  shadowfox.py -t https://example.com -i high --stealth  # High intensity stealth scan
  shadowfox.py --interactive                             # Interactive mode
  shadowfox.py --config config.json                     # Use configuration file
        """
    )
    
    # Main options
    parser.add_argument('-t', '--target', help='Target URL to test')
    parser.add_argument('-i', '--intensity', 
                       choices=['low', 'medium', 'high', 'extreme'],
                       default='medium',
                       help='Attack intensity level')
    parser.add_argument('--stealth', action='store_true', 
                       help='Enable stealth mode (slower but less detectable)')
    parser.add_argument('--no-ai', action='store_true',
                       help='Disable AI decision making')
    parser.add_argument('--interactive', action='store_true',
                       help='Run in interactive mode')
    
    # Configuration
    parser.add_argument('--config', help='JSON configuration file')
    parser.add_argument('--threads', type=int, default=3,
                       help='Number of concurrent threads')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Base delay between requests (seconds)')
    
    # Output
    parser.add_argument('--output-dir', default='reports',
                       help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Quiet mode (minimal output)')
    
    return parser

async def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Create CLI instance
    cli = ShadowFoxCLI()
    asyncio.create_task(op.agents["MutationEngine"].run())
    asyncio.create_task(op.agents["ReconAgent"].run())
    asyncio.create_task(op.agents["SmartShadowAgent"].run())
    asyncio.create_task(op.brain.live_monitor())
    
    op.brain.print_brain_status()
    # Show banner
    if not args.quiet:
        cli.print_banner()
    
    # Initialize system
    cli.console.print("[cyan]🔧 Initializing ShadowFox systems...[/cyan]")
    
    if not await cli.initialize_system():
        cli.console.print("[red]❌ Failed to initialize ShadowFox[/red]")
        return 1
    
    try:
        # Handle different modes
        if args.interactive:
            await cli.interactive_mode()
        elif args.target:
            # Load config
            config = {}
            if args.config:
                try:
                    with open(args.config, 'r') as f:
                        config = json.load(f)
                except Exception as e:
                    cli.console.print(f"[red]❌ Config file error: {e}[/red]")
                    return 1
            
            # Override with CLI args
            config.update({
                'intensity': args.intensity,
                'stealth': args.stealth,
                'ai_enabled': not args.no_ai,
                'max_threads': args.threads,
                'base_delay': args.delay,
                'output_dir': args.output_dir,
                'verbose': args.verbose
            })
            
            # Run mission
            success = await cli.run_mission(args.target, config)
            return 0 if success else 1
        else:
            # No specific mode, show help and enter interactive
            parser.print_help()
            cli.console.print("\n[cyan]💡 No target specified. Entering interactive mode...[/cyan]")
            await cli.interactive_mode()
    
    except KeyboardInterrupt:
        cli.console.print("\n[yellow]🛑 Interrupted by user[/yellow]")
    except Exception as e:
        cli.console.print(f"[red]❌ Fatal error: {e}[/red]")
        return 1
    finally:
        cli.shutdown()
    
    return 0
if __name__ == "__main__":
    # Ensure we're running in the right directory
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)
    
    # Run async main
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 ShadowFox interrupted")
        sys.exit(1)
