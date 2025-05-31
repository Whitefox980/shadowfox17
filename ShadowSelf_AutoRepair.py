#!/usr/bin/env python3
"""
ShadowSelf_AutoRepair.py
AI asistent za održavanje i nadogradnju ShadowFox17 frameworka

Autor: ShadowFox17 Team
Verzija: 1.0.0
"""

import os
import sys
import ast
import json
import shutil
import tempfile
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
import difflib

# Rich biblioteka za vizuelne prikaze
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, TaskID
    from rich.text import Text
    from rich.diff import Diff
    from rich.tree import Tree
    from rich.prompt import Confirm, Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich biblioteka nije instalirana. Koristićemo osnovni prikaz.")
    print("   Instaliraj sa: pip install rich")

@dataclass
class ModuleInfo:
    """Informacije o modulu"""
    name: str
    file_path: str
    class_name: Optional[str]
    is_shadowfox_module: bool
    dependencies: List[str]
    is_integrated: bool
    integration_status: Dict[str, bool]

@dataclass
class BackupInfo:
    """Informacije o backup-u"""
    timestamp: str
    files_backed_up: List[str]
    operation: str
    description: str

class ShadowSelfAutoRepair:
    """Glavni autorepair sistem"""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.project_root = Path.cwd()
        self.backups_dir = self.project_root / "backups"
        self.logs_dir = self.project_root / "logs"
        self.snapshot_file = self.project_root / "modules_snapshot.json"
        
        # Kreiranje potrebnih direktorijuma
        self.backups_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        
        # Log fajl
        self.log_file = self.logs_dir / "auto_repair.log"
        
        # Glavni fajlovi za integraciju
        self.integration_files = {
            'main': self.project_root / "main.py",
            'router': self.project_root / "option_router.py", 
            'orchestrator': self.project_root / "core" / "ShadowFoxOrchestrator.py",
            'registry': self.project_root / "registry.py"
        }
        
        # Direktorijumi za skeniranje
        self.scan_dirs = ['modules', 'core', 'logic']
        
        # Trenutno otkriveni moduli
        self.discovered_modules: List[ModuleInfo] = []
        
    def log(self, message: str, level: str = "INFO"):
        """Logovanje poruka"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Prikaz u konzoli
        if self.console:
            if level == "ERROR":
                self.console.print(log_entry, style="red")
            elif level == "WARNING":
                self.console.print(log_entry, style="yellow")
            elif level == "SUCCESS":
                self.console.print(log_entry, style="green")
            else:
                self.console.print(log_entry, style="blue")
        else:
            print(log_entry)
            
        # Upis u log fajl
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')
    
    def create_backup(self, files_to_backup: List[str], operation: str) -> str:
        """Kreiranje backup-a fajlova"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = self.backups_dir / timestamp
        backup_dir.mkdir(exist_ok=True)
        
        backed_up_files = []
        
        for file_path in files_to_backup:
            file_path = Path(file_path)
            if file_path.exists():
                # Očuvavanje strukture direktorijuma
                relative_path = file_path.relative_to(self.project_root)
                backup_file_path = backup_dir / relative_path
                backup_file_path.parent.mkdir(parents=True, exist_ok=True)
                
                shutil.copy2(file_path, backup_file_path)
                backed_up_files.append(str(relative_path))
                
        # Čuvanje backup info
        backup_info = BackupInfo(
            timestamp=timestamp,
            files_backed_up=backed_up_files,
            operation=operation,
            description=f"Backup pre {operation} operacije"
        )
        
        info_file = backup_dir / "backup_info.json"
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(backup_info), f, indent=2, ensure_ascii=False)
            
        self.log(f"Backup kreiran: {timestamp} ({len(backed_up_files)} fajlova)", "SUCCESS")
        return timestamp
    
    def list_backups(self) -> List[BackupInfo]:
        """Lista svih dostupnih backup-ova"""
        backups = []
        
        for backup_dir in sorted(self.backups_dir.iterdir(), reverse=True):
            if backup_dir.is_dir():
                info_file = backup_dir / "backup_info.json"
                if info_file.exists():
                    try:
                        with open(info_file, 'r', encoding='utf-8') as f:
                            backup_data = json.load(f)
                            backups.append(BackupInfo(**backup_data))
                    except Exception as e:
                        self.log(f"Greška pri čitanju backup info: {e}", "WARNING")
        
        return backups
    
    def restore_backup(self, timestamp: str) -> bool:
        """Vraćanje backup-a"""
        backup_dir = self.backups_dir / timestamp
        
        if not backup_dir.exists():
            self.log(f"Backup {timestamp} ne postoji!", "ERROR")
            return False
            
        info_file = backup_dir / "backup_info.json"
        if not info_file.exists():
            self.log(f"Backup info fajl ne postoji za {timestamp}!", "ERROR")
            return False
            
        try:
            with open(info_file, 'r', encoding='utf-8') as f:
                backup_info = BackupInfo(**json.load(f))
                
            # Vraćanje fajlova
            restored_count = 0
            for relative_path in backup_info.files_backed_up:
                backup_file = backup_dir / relative_path
                original_file = self.project_root / relative_path
                
                if backup_file.exists():
                    # Kreiranje direktorijuma ako ne postoji
                    original_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(backup_file, original_file)
                    restored_count += 1
                    
            self.log(f"Uspešno vraćeno {restored_count} fajlova iz backup-a {timestamp}", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Greška pri vraćanju backup-a: {e}", "ERROR")
            return False
    
    def parse_python_file(self, file_path: Path) -> Dict:
        """Parsiranje Python fajla pomoću AST"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            tree = ast.parse(content)
            
            result = {
                'imports': [],
                'classes': [],
                'functions': [],
                'has_main': False,
                'content': content
            }
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        result['imports'].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        result['imports'].append(f"{module}.{alias.name}")
                elif isinstance(node, ast.ClassDef):
                    result['classes'].append(node.name)
                elif isinstance(node, ast.FunctionDef):
                    result['functions'].append(node.name)
                    if node.name == 'main':
                        result['has_main'] = True
                        
            return result
            
        except Exception as e:
            self.log(f"Greška pri parsiranju {file_path}: {e}", "WARNING")
            return {'imports': [], 'classes': [], 'functions': [], 'has_main': False, 'content': ''}
    
    def discover_modules(self) -> List[ModuleInfo]:
        """Otkrivanje svih modula u projektu"""
        modules = []
        
        for scan_dir in self.scan_dirs:
            scan_path = self.project_root / scan_dir
            if not scan_path.exists():
                continue
                
            for py_file in scan_path.rglob("*.py"):
                if py_file.name.startswith('__'):
                    continue
                    
                parsed = self.parse_python_file(py_file)
                
                # Provera da li nasleđuje ShadowFoxModule
                is_shadowfox = any('ShadowFoxModule' in cls or 'ShadowFox' in cls 
                                   for cls in parsed['classes'])
                
                # Pronalaženje glavne klase
                main_class = None
                for cls in parsed['classes']:
                    if 'Module' in cls or 'Handler' in cls or 'Manager' in cls:
                        main_class = cls
                        break
                
                if not main_class and parsed['classes']:
                    main_class = parsed['classes'][0]
                
                # Detekcija zavisnosti
                dependencies = [imp for imp in parsed['imports'] 
                               if any(dep in imp for dep in ['core', 'modules', 'shadowfox'])]
                
                # Provera integracije
                integration_status = self.check_integration_status(py_file, main_class)
                
                module_info = ModuleInfo(
                    name=py_file.stem,
                    file_path=str(py_file.relative_to(self.project_root)),
                    class_name=main_class,
                    is_shadowfox_module=is_shadowfox,
                    dependencies=dependencies,
                    is_integrated=all(integration_status.values()),
                    integration_status=integration_status
                )
                
                modules.append(module_info)
                
        self.discovered_modules = modules
        return modules
    
    def check_integration_status(self, file_path: Path, class_name: Optional[str]) -> Dict[str, bool]:
        """Provera da li je modul integrisan u glavne fajlove"""
        status = {
            'main.py': False,
            'option_router.py': False,
            'orchestrator': False,
            'registry.py': False
        }
        
        module_name = file_path.stem
        
        # Provera main.py
        main_file = self.integration_files['main']
        if main_file.exists():
            content = main_file.read_text(encoding='utf-8')
            if module_name in content or (class_name and class_name in content):
                status['main.py'] = True
                
        # Provera option_router.py
        router_file = self.integration_files['router']
        if router_file.exists():
            content = router_file.read_text(encoding='utf-8')
            if module_name in content or (class_name and class_name in content):
                status['option_router.py'] = True
                
        # Provera orchestrator
        orch_file = self.integration_files['orchestrator']
        if orch_file.exists():
            content = orch_file.read_text(encoding='utf-8')
            if module_name in content or (class_name and class_name in content):
                status['orchestrator'] = True
                
        # Provera registry
        reg_file = self.integration_files['registry']
        if reg_file.exists():
            content = reg_file.read_text(encoding='utf-8')
            if module_name in content or (class_name and class_name in content):
                status['registry.py'] = True
                
        return status
    
    def scan_command(self, visual: bool = False):
        """--scan komanda"""
        self.log("Početak skeniranja modula...", "INFO")
        
        modules = self.discover_modules()
        
        if not modules:
            self.log("Nijedan modul nije pronađen.", "WARNING")
            return
            
        # Vizuelni prikaz
        if visual and self.console:
            self.display_scan_results_visual(modules)
        else:
            self.display_scan_results_simple(modules)
            
        # Ažuriranje snapshot-a
        self.update_snapshot(modules)
        
        self.log(f"Skeniranje završeno. Pronađeno {len(modules)} modula.", "SUCCESS")
    
    def display_scan_results_visual(self, modules: List[ModuleInfo]):
        """Vizuelni prikaz rezultata skeniranja"""
        table = Table(title="🔍 Otkriveni Moduli")
        
        table.add_column("Naziv", style="cyan")
        table.add_column("Putanja", style="blue")
        table.add_column("Klasa", style="green")
        table.add_column("ShadowFox", justify="center")
        table.add_column("Integrisan", justify="center")
        table.add_column("Status", style="yellow")
        
        for module in modules:
            shadowfox_icon = "✅" if module.is_shadowfox_module else "❌"
            integrated_icon = "✅" if module.is_integrated else "❌"
            
            # Status integracije
            status_parts = []
            for key, value in module.integration_status.items():
                if value:
                    status_parts.append(f"✅{key}")
                else:
                    status_parts.append(f"❌{key}")
            status_text = " | ".join(status_parts)
            
            table.add_row(
                module.name,
                module.file_path,
                module.class_name or "N/A",
                shadowfox_icon,
                integrated_icon,
                status_text
            )
            
        self.console.print(table)
    
    def display_scan_results_simple(self, modules: List[ModuleInfo]):
        """Jednostavan prikaz rezultata skeniranja"""
        print("\n" + "="*60)
        print("🔍 OTKRIVENI MODULI")
        print("="*60)
        
        for i, module in enumerate(modules, 1):
            print(f"\n{i}. {module.name}")
            print(f"   Putanja: {module.file_path}")
            print(f"   Klasa: {module.class_name or 'N/A'}")
            print(f"   ShadowFox modul: {'Da' if module.is_shadowfox_module else 'Ne'}")
            print(f"   Integrisan: {'Da' if module.is_integrated else 'Ne'}")
            
            if not module.is_integrated:
                print("   Nedostaje u:")
                for key, value in module.integration_status.items():
                    if not value:
                        print(f"     - {key}")
    
    def suggest_command(self):
        """--suggest komanda"""
        if not self.discovered_modules:
            self.discover_modules()
            
        non_integrated = [m for m in self.discovered_modules if not m.is_integrated]
        
        if not non_integrated:
            self.log("Svi moduli su već integrisani!", "SUCCESS")
            return
            
        self.log(f"Pronađeno {len(non_integrated)} neintegrisanih modula", "INFO")
        
        for module in non_integrated:
            self.display_integration_suggestions(module)
    
    def display_integration_suggestions(self, module: ModuleInfo):
        """Prikaz predloga za integraciju modula"""
        if self.console:
            panel = Panel(
                self.generate_integration_code(module),
                title=f"🔧 Predlog integracije za {module.name}",
                border_style="blue"
            )
            self.console.print(panel)
        else:
            print(f"\n🔧 PREDLOG INTEGRACIJE ZA {module.name.upper()}")
            print("-" * 50)
            print(self.generate_integration_code(module))
    
    def generate_integration_code(self, module: ModuleInfo) -> str:
        """Generisanje koda za integraciju modula"""
        suggestions = []
        
        # Import predlog
        import_line = f"from {module.file_path.replace('/', '.').replace('.py', '')} import {module.class_name or module.name}"
        suggestions.append(f"IMPORT: {import_line}")
        
        # Main.py predlog
        if not module.integration_status.get('main.py'):
            suggestions.append(f"MAIN.PY: Dodaj poziv u main() funkciju")
            
        # Router predlog
        if not module.integration_status.get('option_router.py'):
            suggestions.append(f"ROUTER: router.add_route('{module.name}', {module.class_name or module.name})")
            
        # Orchestrator predlog  
        if not module.integration_status.get('orchestrator'):
            suggestions.append(f"ORCHESTRATOR: orchestrator.register_module({module.class_name or module.name})")
            
        # Registry predlog
        if not module.integration_status.get('registry.py'):
            suggestions.append(f"REGISTRY: MODULES['{module.name}'] = {module.class_name or module.name}")
            
        return "\n".join(suggestions)
    
    def auto_fix_command(self, dry_run: bool = False):
        """--auto-fix komanda"""
        if not self.discovered_modules:
            self.discover_modules()
            
        non_integrated = [m for m in self.discovered_modules if not m.is_integrated]
        
        if not non_integrated:
            self.log("Svi moduli su već integrisani!", "SUCCESS")
            return
            
        if not dry_run:
            # Kreiranje backup-a
            files_to_backup = [str(f) for f in self.integration_files.values() if f.exists()]
            backup_timestamp = self.create_backup(files_to_backup, "auto-fix")
            
        for module in non_integrated:
            self.log(f"Integrisanje modula: {module.name}", "INFO")
            
            if dry_run:
                self.log(f"[DRY RUN] Bi integrisao: {module.name}", "INFO")
                self.display_integration_suggestions(module)
            else:
                self.integrate_module(module)
    
    def integrate_module(self, module: ModuleInfo) -> bool:
        """Integracija modula u sistem"""
        success = True
        
        try:
            # Import linija
            import_line = f"from {module.file_path.replace('/', '.').replace('.py', '')} import {module.class_name or module.name}"
            
            # Integracija u main.py
            if not module.integration_status.get('main.py'):
                success &= self.add_to_main_py(module, import_line)
                
            # Integracija u router
            if not module.integration_status.get('option_router.py'):
                success &= self.add_to_router(module, import_line)
                
            # Integracija u orchestrator
            if not module.integration_status.get('orchestrator'):
                success &= self.add_to_orchestrator(module, import_line)
                
            # Integracija u registry
            if not module.integration_status.get('registry.py'):
                success &= self.add_to_registry(module, import_line)
                
            if success:
                self.log(f"Modul {module.name} uspešno integrisan!", "SUCCESS")
            else:
                self.log(f"Parcijalna integracija modula {module.name}", "WARNING")
                
        except Exception as e:
            self.log(f"Greška pri integraciji modula {module.name}: {e}", "ERROR")
            success = False
            
        return success
    
    def add_to_main_py(self, module: ModuleInfo, import_line: str) -> bool:
        """Dodavanje u main.py"""
        main_file = self.integration_files['main']
        if not main_file.exists():
            return False
            
        try:
            content = main_file.read_text(encoding='utf-8')
            
            # Provera da li import već postoji
            if import_line in content:
                return True
                
            # Pronalaženje mesta za dodavanje import-a
            lines = content.split('\n')
            import_index = -1
            
            for i, line in enumerate(lines):
                if line.strip().startswith('import ') or line.strip().startswith('from '):
                    import_index = i
            
            # Dodavanje import-a
            if import_index >= 0:
                lines.insert(import_index + 1, import_line)
            else:
                lines.insert(0, import_line)
                
            # Pisanje fajla
            main_file.write_text('\n'.join(lines), encoding='utf-8')
            self.log(f"Dodato u main.py: {import_line}", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Greška pri dodavanju u main.py: {e}", "ERROR")
            return False
    
    def add_to_router(self, module: ModuleInfo, import_line: str) -> bool:
        """Dodavanje u option_router.py"""
        router_file = self.integration_files['router']
        if not router_file.exists():
            return False
            
        try:
            content = router_file.read_text(encoding='utf-8')
            
            if import_line not in content:
                # Dodavanje import-a
                lines = content.split('\n')
                import_index = -1
                
                for i, line in enumerate(lines):
                    if line.strip().startswith('import ') or line.strip().startswith('from '):
                        import_index = i
                        
                if import_index >= 0:
                    lines.insert(import_index + 1, import_line)
                    
                # Dodavanje u router registraciju
                router_line = f"    router.add_route('{module.name}', {module.class_name or module.name})"
                
                # Pronalaženje mesta za dodavanje
                for i, line in enumerate(lines):
                    if 'router.add_route' in line or '# INSERT MODULE HERE' in line:
                        lines.insert(i + 1, router_line)
                        break
                        
                router_file.write_text('\n'.join(lines), encoding='utf-8')
                self.log(f"Dodato u router: {module.name}", "SUCCESS")
                
            return True
            
        except Exception as e:
            self.log(f"Greška pri dodavanju u router: {e}", "ERROR")
            return False
    
    def add_to_orchestrator(self, module: ModuleInfo, import_line: str) -> bool:
        """Dodavanje u orchestrator"""
        orch_file = self.integration_files['orchestrator']
        if not orch_file.exists():
            return False
            
        try:
            content = orch_file.read_text(encoding='utf-8')
            
            if import_line not in content:
                lines = content.split('\n')
                
                # Dodavanje import-a
                import_index = -1
                for i, line in enumerate(lines):
                    if line.strip().startswith('import ') or line.strip().startswith('from '):
                        import_index = i
                        
                if import_index >= 0:
                    lines.insert(import_index + 1, import_line)
                    
                # Dodavanje registracije
                register_line = f"        self.register_module({module.class_name or module.name}())"
                
                for i, line in enumerate(lines):
                    if 'register_module' in line or '# INSERT MODULE HERE' in line:
                        lines.insert(i + 1, register_line)
                        break
                        
                orch_file.write_text('\n'.join(lines), encoding='utf-8')
                self.log(f"Dodato u orchestrator: {module.name}", "SUCCESS")
                
            return True
            
        except Exception as e:
            self.log(f"Greška pri dodavanju u orchestrator: {e}", "ERROR") 
            return False
    
    def add_to_registry(self, module: ModuleInfo, import_line: str) -> bool:
        """Dodavanje u registry.py"""
        reg_file = self.integration_files['registry']
        if not reg_file.exists():
            return False
            
        try:
            content = reg_file.read_text(encoding='utf-8')
            
            if import_line not in content:
                lines = content.split('\n')
                
                # Dodavanje import-a
                import_index = -1
                for i, line in enumerate(lines):
                    if line.strip().startswith('import ') or line.strip().startswith('from '):
                        import_index = i
                        
                if import_index >= 0:
                    lines.insert(import_index + 1, import_line)
                    
                # Dodavanje u MODULES dictionary
                module_line = f"    '{module.name}': {module.class_name or module.name},"
                
                for i, line in enumerate(lines):
                    if 'MODULES' in line and '{' in line:
                        lines.insert(i + 1, module_line)
                        break
                        
                reg_file.write_text('\n'.join(lines), encoding='utf-8')
                self.log(f"Dodato u registry: {module.name}", "SUCCESS")
                
            return True
            
        except Exception as e:
            self.log(f"Greška pri dodavanju u registry: {e}", "ERROR")
            return False
    
    def undo_command(self):
        """--undo komanda"""
        backups = self.list_backups()
        
        if not backups:
            self.log("Nema dostupnih backup-ova za vraćanje.", "WARNING")
            return
            
        if self.console:
            # Vizuelni prikaz backup-ova
            table = Table(title="📦 Dostupni Backup-ovi")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Operacija", style="blue")
            table.add_column("Fajlovi", style="green")
            table.add_column("Opis", style="yellow")
            
            for backup in backups[:10]:  # Prikaži poslednih 10
                table.add_row(
                    backup.timestamp,
                    backup.operation,
                    str(len(backup.files_backed_up)),
                    backup.description
                )
                
            self.console.print(table)
            
            # Pitanje za vraćanje
            if Confirm.ask("Da li želite da vratite poslednji backup?"):
                self.restore_backup(backups[0].timestamp)
        else:
            print("\n📦 DOSTUPNI BACKUP-OVI:")
            for i, backup in enumerate(backups[:5], 1):
                print(f"{i}. {backup.timestamp} - {backup.operation} ({len(backup.files_backed_up)} fajlova)")
                
            choice = input("\nUnesite broj backup-a za vraćanje (Enter za poslednji): ").strip()
            
            if not choice:
                self.restore_backup(backups[0].timestamp)
            else:
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(backups):
                        self.restore_backup(backups[index].timestamp)
                    else:
                        self.log("Nevaljan izbor!", "ERROR")
                except ValueError:
                    self.log("Nevaljan broj!", "ERROR")
    
    def update_snapshot(self, modules: List[ModuleInfo]):
        """Ažuriranje snapshot-a modula"""
        snapshot_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'modules': [asdict(module) for module in modules]
        }
        
        with open(self.snapshot_file, 'w', encoding='utf-8') as f:
            json.dump(snapshot_data, f, indent=2, ensure_ascii=False)
            
        self.log("Snapshot ažuriran", "INFO")

def main():
    """Glavna funkcija CLI-ja"""
    parser = argparse.ArgumentParser(
        description="🦊 ShadowSelf AutoRepair - AI asistent za održavanje ShadowFox17 frameworka",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Primeri korišćenja:
  python ShadowSelf_AutoRepair.py --scan --visual
  python ShadowSelf_AutoRepair.py --suggest
  python ShadowSelf_AutoRepair.py --auto-fix --dry-run
  python ShadowSelf_AutoRepair.py --undo
  python ShadowSelf_AutoRepair.py --scan --log
        """
    )

    parser.add_argument('--scan', action='store_true',
                        help='Skenira sve podfoldere i detektuje module')
    parser.add_argument('--suggest', action='store_true',
                        help='Predlaže gde treba dodati integracije za nove module')
    parser.add_argument('--auto-fix', action='store_true',
                        help='Automatski pokušava da doda potrebne importove i registre')
    parser.add_argument('--dry-run', action='store_true',
                        help='Ne menja ništa, već prikazuje šta bi uradio')
    parser.add_argument('--undo', action='store_true',
                        help='Vraća poslednje izmene (backup restore)')
    parser.add_argument('--visual', action='store_true',
                        help='Prikazuje vizuelni pregled strukture modula')
    parser.add_argument('--log', action='store_true',
                        help='Zapisuje izveštaj u log fajl')

    args = parser.parse_args()

    # Backup sistem
    if args.undo:
        restore_backup()
        return

    if args.scan:
        modules = scan_modules()
        if args.visual:
            visual_output(modules)
        if args.log:
            save_log(modules)

    if args.suggest:
        modules = scan_modules()
        suggestions = suggest_fixes(modules)
        for s in suggestions:
            print(f"[SUGGEST] {s}")

    if args.auto_fix:
        modules = scan_modules()
        suggestions = suggest_fixes(modules)
        apply_fixes(suggestions, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
