#!/usr/bin/env python3
"""
ShadowSelf_AutoRepair.py
Automatski popravlja i integriše module u ShadowFox17 framework
"""

import os
import sys
import ast
import re
from pathlib import Path
from typing import List, Dict, Optional

class ShadowAutoFixer:
    def __init__(self):
        self.project_root = Path.cwd()
        self.scan_dirs = ['modules', 'core', 'logic']
        self.main_files = {
            'main': self.project_root / "main.py",
            'router': self.project_root / "option_router.py",
            'orchestrator': self.project_root / "core" / "ShadowFoxOrchestrator.py",
            'registry': self.project_root / "registry.py"
        }
        
    def log(self, msg):
        print(f"🔧 {msg}")
        
    def find_all_modules(self) -> List[Dict]:
        """Pronalazi sve Python module u scan direktorijumima"""
        modules = []
        
        for scan_dir in self.scan_dirs:
            scan_path = self.project_root / scan_dir
            if not scan_path.exists():
                continue
                
            for py_file in scan_path.rglob("*.py"):
                if py_file.name.startswith('__') or py_file.name == "ShadowSelf_AutoRepair.py":
                    continue
                    
                module_info = self.analyze_module(py_file)
                if module_info:
                    modules.append(module_info)
        
        return modules
    
    def analyze_module(self, file_path: Path) -> Optional[Dict]:
        """Analizira Python modul i izvlači informacije"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            classes = []
            functions = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.FunctionDef) and not node.name.startswith('_'):
                    functions.append(node.name)
            
            # Pronalazi glavnu klasu ili funkciju
            main_class = None
            main_function = None
            
            # Traži klase sa "Module", "Handler", "Manager" u imenu
            for cls in classes:
                if any(keyword in cls for keyword in ['Module', 'Handler', 'Manager', 'Tool', 'Util']):
                    main_class = cls
                    break
            
            # Ako nema glavnu klasu, uzmi prvu
            if not main_class and classes:
                main_class = classes[0]
            
            # Traži main funkciju
            if 'main' in functions:
                main_function = 'main'
            elif functions:
                main_function = functions[0]
            
            if not main_class and not main_function:
                return None
                
            return {
                'name': file_path.stem,
                'file_path': file_path,
                'relative_path': str(file_path.relative_to(self.project_root)),
                'main_class': main_class,
                'main_function': main_function,
                'all_classes': classes,
                'all_functions': functions,
                'content': content
            }
            
        except Exception as e:
            self.log(f"Greška pri analizi {file_path}: {e}")
            return None
    
    def check_if_integrated(self, module: Dict) -> Dict[str, bool]:
        """Proverava da li je modul integrisan u glavne fajlove"""
        status = {}
        module_name = module['name']
        
        for file_key, file_path in self.main_files.items():
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')
                    # Proverava da li se spominje modul u fajlu
                    status[file_key] = (module_name.lower() in content.lower() or 
                                      (module['main_class'] and module['main_class'] in content))
                except:
                    status[file_key] = False
            else:
                status[file_key] = False
                
        return status
    
    def auto_fix_all(self):
        """Glavna funkcija - pronalazi i popravlja sve module"""
        self.log("Tražim module...")
        modules = self.find_all_modules()
        
        if not modules:
            self.log("Nema modula za popravku!")
            return
            
        self.log(f"Pronašao {len(modules)} modula")
        
        for module in modules:
            self.log(f"\n--- Analiziram: {module['name']} ---")
            integration_status = self.check_if_integrated(module)
            
            needs_fixing = not all(integration_status.values())
            
            if needs_fixing:
                self.log(f"Popravaljam {module['name']}...")
                self.integrate_module(module)
            else:
                self.log(f"{module['name']} je već integrisan ✅")
    
    def integrate_module(self, module: Dict):
        """Integriše modul u sve potrebne fajlove"""
        module_name = module['name']
        class_name = module['main_class']
        function_name = module['main_function']
        
        # Kreiranje import linije
        import_path = module['relative_path'].replace('/', '.').replace('.py', '')
        
        if class_name:
            import_line = f"from {import_path} import {class_name}"
            callable_name = class_name
        elif function_name:
            import_line = f"from {import_path} import {function_name}"
            callable_name = function_name
        else:
            import_line = f"import {import_path}"
            callable_name = module_name
        
        # Dodaj u main.py
        self.add_to_main(module, import_line, callable_name)
        
        # Dodaj u option_router.py
        self.add_to_router(module, import_line, callable_name)
        
        # Dodaj u orchestrator
        self.add_to_orchestrator(module, import_line, callable_name)
        
        # Dodaj u registry
        self.add_to_registry(module, import_line, callable_name)
        
        self.log(f"{module_name} integrisan! ✅")
    
    def add_to_main(self, module: Dict, import_line: str, callable_name: str):
        """Dodaje modul u main.py"""
        main_file = self.main_files['main']
        
        if not main_file.exists():
            # Kreira osnovni main.py
            content = '''#!/usr/bin/env python3
"""
ShadowFox17 Main Entry Point
"""

def main():
    print("ShadowFox17 started!")

if __name__ == "__main__":
    main()
'''
            main_file.write_text(content, encoding='utf-8')
            
        content = main_file.read_text(encoding='utf-8')
        
        # Dodaj import ako ne postoji
        if import_line not in content:
            lines = content.split('\n')
            
            # Pronađi poslednji import
            import_index = 0
            for i, line in enumerate(lines):
                if line.strip().startswith(('import ', 'from ')):
                    import_index = i + 1
            
            lines.insert(import_index, import_line)
            content = '\n'.join(lines)
        
        # Dodaj poziv u main() funkciju
        if 'def main():' in content and callable_name not in content:
            content = content.replace(
                'def main():',
                f'def main():\n    # Auto-added: {module["name"]}\n    try:\n        {callable_name}()\n    except Exception as e:\n        print(f"Error in {module["name"]}: {{e}}")'
            )
        
        main_file.write_text(content, encoding='utf-8')
        self.log(f"  ✅ Dodano u main.py")
    
    def add_to_router(self, module: Dict, import_line: str, callable_name: str):
        """Dodaje modul u option_router.py"""
        router_file = self.main_files['router']
        
        if not router_file.exists():
            # Kreira osnovni router
            content = '''#!/usr/bin/env python3
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
'''
            router_file.write_text(content, encoding='utf-8')
        
        content = router_file.read_text(encoding='utf-8')
        
        # Dodaj import
        if import_line not in content:
            lines = content.split('\n')
            import_index = 0
            for i, line in enumerate(lines):
                if line.strip().startswith(('import ', 'from ')):
                    import_index = i + 1
            lines.insert(import_index, import_line)
            content = '\n'.join(lines)
        
        # Dodaj rutu
        route_line = f'router.add_route("{module["name"]}", {callable_name})'
        if route_line not in content:
            content += f'\n# Auto-added route\n{route_line}\n'
        
        router_file.write_text(content, encoding='utf-8')
        self.log(f"  ✅ Dodano u option_router.py")
    
    def add_to_orchestrator(self, module: Dict, import_line: str, callable_name: str):
        """Dodaje modul u orchestrator"""
        orch_file = self.main_files['orchestrator']
        
        if not orch_file.exists():
            orch_file.parent.mkdir(parents=True, exist_ok=True)
            content = '''#!/usr/bin/env python3
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
'''
            orch_file.write_text(content, encoding='utf-8')
        
        content = orch_file.read_text(encoding='utf-8')
        
        # Dodaj import
        if import_line not in content:
            lines = content.split('\n')
            import_index = 0
            for i, line in enumerate(lines):
                if line.strip().startswith(('import ', 'from ')):
                    import_index = i + 1
            lines.insert(import_index, import_line)
            content = '\n'.join(lines)
        
        # Dodaj registraciju
        register_line = f'orchestrator.register_module({callable_name})'
        if register_line not in content:
            content += f'\n# Auto-registered module\n{register_line}\n'
        
        orch_file.write_text(content, encoding='utf-8')
        self.log(f"  ✅ Dodano u orchestrator")
    
    def add_to_registry(self, module: Dict, import_line: str, callable_name: str):
        """Dodaje modul u registry.py"""
        reg_file = self.main_files['registry']
        
        if not reg_file.exists():
            content = '''#!/usr/bin/env python3
"""
ShadowFox17 Module Registry
"""

MODULES = {}

def register_module(name, module):
    MODULES[name] = module
    print(f"Module {name} registered in registry")

def get_module(name):
    return MODULES.get(name, None)
'''
            reg_file.write_text(content, encoding='utf-8')
        
        content = reg_file.read_text(encoding='utf-8')
        
        # Dodaj import
        if import_line not in content:
            lines = content.split('\n')
            import_index = 0
            for i, line in enumerate(lines):
                if line.strip().startswith(('import ', 'from ')):
                    import_index = i + 1
            lines.insert(import_index, import_line)
            content = '\n'.join(lines)
        
        # Dodaj u registry
        register_line = f'register_module("{module["name"]}", {callable_name})'
        if register_line not in content:
            content += f'\n# Auto-registered\n{register_line}\n'
        
        reg_file.write_text(content, encoding='utf-8')
        self.log(f"  ✅ Dodano u registry.py")

def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ShadowFox17 AutoRepair - Automatski integriše module")
    parser.add_argument('--fix', action='store_true', help='Popravi sve module (default)')
    parser.add_argument('--scan', action='store_true', help='Samo skenira module')
    
    args = parser.parse_args()
    
    fixer = ShadowAutoFixer()
    
    if args.scan:
        modules = fixer.find_all_modules()
        print(f"\n🔍 Pronađeno {len(modules)} modula:")
        for module in modules:
            status = fixer.check_if_integrated(module)
            integrated = "✅" if all(status.values()) else "❌"
            print(f"  {integrated} {module['name']} - {module['main_class'] or module['main_function'] or 'N/A'}")
    else:
        # Default: popravi sve
        fixer.auto_fix_all()
        print("\n🎉 AutoRepair završen! Svi moduli su integrisani.")

if __name__ == "__main__":
    main()
