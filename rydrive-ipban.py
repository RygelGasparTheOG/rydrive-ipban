#!/usr/bin/env python3
"""
RyDrive IP Ban Proxy with Web UI
A man-in-the-middle proxy that filters connections to RyDrive based on IP blocklist.
Part of the RyDrive project: https://github.com/RygelGasparTheOG/rydrive

This proxy sits between clients and your RyDrive server, blocking unwanted IPs
before they ever reach RyDrive. No modifications to rydrive.py needed!

Usage:
    1. Start RyDrive normally: python rydrive.py
    2. Start this proxy: python rydrive_proxy.py
    3. Point clients to port 8081 instead of 8080
    4. Access Web UI at http://localhost:8082
"""

import socket
import threading
import json
from datetime import datetime
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import time

# ============================================================================
# CONFIGURATION
# ============================================================================
PROXY_HOST = '0.0.0.0'      # Listen on all interfaces
PROXY_PORT = 8081            # Public-facing port (clients connect here)
RYDRIVE_HOST = '127.0.0.1'  # RyDrive server location
RYDRIVE_PORT = 8080          # RyDrive actual port (as set in rydrive.py)

WEB_UI_HOST = '0.0.0.0'     # Web UI host
WEB_UI_PORT = 8082           # Web UI port

BLOCKED_IPS_FILE = 'blocked_ips.json'
RELOAD_INTERVAL = 30  # Seconds between blocklist reloads

# ============================================================================
# IP FILTER
# ============================================================================
class IPFilter:
    """Manages the blocked IP list"""
    
    def __init__(self):
        self.blocked_ips = self.load_blocked_ips()
        self.lock = threading.Lock()
        self.stats = {
            'blocked_attempts': 0,
            'allowed_connections': 0,
            'last_blocked_ip': None,
            'last_blocked_time': None
        }
    
    def load_blocked_ips(self):
        """Load blocked IPs from JSON file"""
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                blocked = set(data.get('blocked_ips', []))
                return blocked
        except FileNotFoundError:
            print(f"[INFO] {BLOCKED_IPS_FILE} not found, creating empty blocklist...")
            self._create_empty_blocklist()
            return set()
        except json.JSONDecodeError as e:
            print(f"[ERROR] Error parsing {BLOCKED_IPS_FILE}: {e}")
            print("[INFO] Starting with empty blocklist")
            return set()
    
    def _create_empty_blocklist(self):
        """Create an empty blocked_ips.json file"""
        template = {
            "blocked_ips": [],
            "_comment": "Add IP addresses to block in the array above. Updates every 30 seconds."
        }
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(template, f, indent=2)
    
    def is_blocked(self, ip):
        """Check if an IP is blocked"""
        with self.lock:
            return ip in self.blocked_ips
    
    def add_ip(self, ip):
        """Add an IP to the blocklist"""
        with self.lock:
            self.blocked_ips.add(ip)
            self._save_blocked_ips()
            return True
    
    def remove_ip(self, ip):
        """Remove an IP from the blocklist"""
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self._save_blocked_ips()
                return True
            return False
    
    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            data = {
                "blocked_ips": sorted(list(self.blocked_ips)),
                "_comment": "Managed by RyDrive IP Ban Proxy Web UI"
            }
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[ERROR] Failed to save blocklist: {e}")
    
    def reload(self):
        """Reload blocked IPs from file"""
        new_blocked = self.load_blocked_ips()
        with self.lock:
            old_count = len(self.blocked_ips)
            self.blocked_ips = new_blocked
            new_count = len(self.blocked_ips)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if old_count != new_count:
            print(f"[{timestamp}] Blocklist updated: {new_count} IPs blocked (was {old_count})")
        
        return new_count
    
    def get_stats(self):
        """Get current statistics"""
        with self.lock:
            return {
                'blocked_count': len(self.blocked_ips),
                'blocked_ips': sorted(list(self.blocked_ips)),
                'blocked_attempts': self.stats['blocked_attempts'],
                'allowed_connections': self.stats['allowed_connections'],
                'last_blocked_ip': self.stats['last_blocked_ip'],
                'last_blocked_time': self.stats['last_blocked_time']
            }
    
    def increment_blocked(self, ip):
        """Increment blocked attempt counter"""
        with self.lock:
            self.stats['blocked_attempts'] += 1
            self.stats['last_blocked_ip'] = ip
            self.stats['last_blocked_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def increment_allowed(self):
        """Increment allowed connection counter"""
        with self.lock:
            self.stats['allowed_connections'] += 1


# ============================================================================
# PROXY HANDLER
# ============================================================================
class ProxyHandler:
    """Handles individual client connections"""
    
    def __init__(self, client_socket, client_address, ip_filter):
        self.client_socket = client_socket
        self.client_address = client_address
        self.ip_filter = ip_filter
        self.client_ip = client_address[0]
    
    def handle(self):
        """Handle client connection - check blocklist and forward or reject"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if IP is blocked
        if self.ip_filter.is_blocked(self.client_ip):
            print(f"[{timestamp}] BLOCKED: {self.client_ip}:{self.client_address[1]}")
            self.ip_filter.increment_blocked(self.client_ip)
            self._send_forbidden()
            return
        
        print(f"[{timestamp}] ALLOWED: {self.client_ip}:{self.client_address[1]} -> RyDrive")
        self.ip_filter.increment_allowed()
        
        # Forward connection to RyDrive
        try:
            self._forward_to_rydrive()
        except ConnectionRefusedError:
            print(f"[{timestamp}] ERROR: Cannot connect to RyDrive at {RYDRIVE_HOST}:{RYDRIVE_PORT}")
            print(f"           Make sure rydrive.py is running on port {RYDRIVE_PORT}!")
            self._send_service_unavailable()
        except Exception as e:
            print(f"[{timestamp}] Error forwarding {self.client_ip}: {e}")
        finally:
            self.client_socket.close()
    
    def _send_forbidden(self):
        """Send HTTP 403 Forbidden response"""
        try:
            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<!DOCTYPE html>"
                "<html><head><title>Access Denied</title></head>"
                "<body style='font-family: system-ui; text-align: center; padding: 50px;'>"
                "<h1>Access Denied</h1>"
                "<p>Your IP address has been blocked from accessing RyDrive.</p>"
                f"<p style='color: #666;'>IP: {self.client_ip}</p>"
                "</body></html>"
            )
            self.client_socket.sendall(response.encode())
        except:
            pass
        finally:
            self.client_socket.close()
    
    def _send_service_unavailable(self):
        """Send HTTP 503 Service Unavailable response"""
        try:
            response = (
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<!DOCTYPE html>"
                "<html><head><title>Service Unavailable</title></head>"
                "<body style='font-family: system-ui; text-align: center; padding: 50px;'>"
                "<h1>Service Unavailable</h1>"
                "<p>RyDrive server is not responding.</p>"
                "<p>Please ensure rydrive.py is running.</p>"
                "</body></html>"
            )
            self.client_socket.sendall(response.encode())
        except:
            pass
    
    def _forward_to_rydrive(self):
        """Forward connection to RyDrive server"""
        # Connect to RyDrive server
        rydrive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rydrive_socket.connect((RYDRIVE_HOST, RYDRIVE_PORT))
        
        # Start bidirectional forwarding
        client_to_server = threading.Thread(
            target=self._forward_data,
            args=(self.client_socket, rydrive_socket)
        )
        server_to_client = threading.Thread(
            target=self._forward_data,
            args=(rydrive_socket, self.client_socket)
        )
        
        client_to_server.daemon = True
        server_to_client.daemon = True
        
        client_to_server.start()
        server_to_client.start()
        
        client_to_server.join()
        server_to_client.join()
        
        rydrive_socket.close()
    
    def _forward_data(self, source, destination):
        """Forward data between two sockets"""
        try:
            while True:
                data = source.recv(8192)
                if not data:
                    break
                destination.sendall(data)
        except:
            pass
        finally:
            try:
                source.shutdown(socket.SHUT_RD)
                destination.shutdown(socket.SHUT_WR)
            except:
                pass


# ============================================================================
# WEB UI HANDLER
# ============================================================================
class WebUIHandler(BaseHTTPRequestHandler):
    """Web UI request handler"""
    
    ip_filter = None  # Set by ProxyServer
    
    def log_message(self, format, *args):
        """Suppress default request logging"""
        pass
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/' or self.path == '/index.html':
            self._serve_dashboard()
        elif self.path == '/api/stats':
            self._serve_stats()
        else:
            self.send_error(404)
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/api/add':
            self._handle_add_ip()
        elif self.path == '/api/remove':
            self._handle_remove_ip()
        else:
            self.send_error(404)
    
    def _serve_dashboard(self):
        """Serve the main dashboard HTML"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RyDrive IP Ban Proxy - Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            color: #2d3748;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header p {
            color: #718096;
            font-size: 14px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #718096;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .stat-value {
            color: #2d3748;
            font-size: 32px;
            font-weight: 700;
        }
        .stat-card.blocked .stat-value { color: #e53e3e; }
        .stat-card.allowed .stat-value { color: #38a169; }
        .main-panel {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .section-title {
            color: #2d3748;
            font-size: 20px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }
        .add-form {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }
        .add-form input {
            flex: 1;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        .add-form input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-1px);
        }
        .btn-danger {
            background: #e53e3e;
            color: white;
            padding: 8px 16px;
            font-size: 13px;
        }
        .btn-danger:hover {
            background: #c53030;
        }
        .ip-list {
            max-height: 400px;
            overflow-y: auto;
        }
        .ip-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            border-bottom: 1px solid #e2e8f0;
            transition: background 0.2s;
        }
        .ip-item:hover {
            background: #f7fafc;
        }
        .ip-item:last-child {
            border-bottom: none;
        }
        .ip-address {
            font-family: 'Courier New', monospace;
            font-size: 15px;
            color: #2d3748;
            font-weight: 500;
        }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #a0aec0;
        }
        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .alert-success {
            background: #c6f6d5;
            color: #22543d;
            border-left: 4px solid #38a169;
        }
        .alert-error {
            background: #fed7d7;
            color: #742a2a;
            border-left: 4px solid #e53e3e;
        }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RyDrive IP Ban Proxy</h1>
            <p>Admin Panel - Manage blocked IP addresses</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card blocked">
                <h3>Blocked IPs</h3>
                <div class="stat-value" id="blockedCount">0</div>
            </div>
            <div class="stat-card blocked">
                <h3>Blocked Attempts</h3>
                <div class="stat-value" id="blockedAttempts">0</div>
            </div>
            <div class="stat-card allowed">
                <h3>Allowed Connections</h3>
                <div class="stat-value" id="allowedConnections">0</div>
            </div>
        </div>
        
        <div class="main-panel">
            <div id="alertBox" class="alert hidden"></div>
            
            <h2 class="section-title">Add IP Address</h2>
            <div class="add-form">
                <input type="text" id="ipInput" placeholder="Enter IP address (e.g., 192.168.1.100)" pattern="^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$">
                <button class="btn btn-primary" onclick="addIP()">Block IP</button>
            </div>
            
            <h2 class="section-title">Blocked IP Addresses</h2>
            <div id="ipList" class="ip-list">
                <div class="empty-state">
                    <div>Loading...</div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function showAlert(message, type) {
            const alertBox = document.getElementById('alertBox');
            alertBox.textContent = message;
            alertBox.className = 'alert alert-' + type;
            alertBox.classList.remove('hidden');
            setTimeout(() => alertBox.classList.add('hidden'), 3000);
        }
        
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                document.getElementById('blockedCount').textContent = data.blocked_count;
                document.getElementById('blockedAttempts').textContent = data.blocked_attempts;
                document.getElementById('allowedConnections').textContent = data.allowed_connections;
                
                const ipList = document.getElementById('ipList');
                if (data.blocked_ips.length === 0) {
                    ipList.innerHTML = '<div class="empty-state"><div>No blocked IPs</div></div>';
                } else {
                    ipList.innerHTML = data.blocked_ips.map(ip => `
                        <div class="ip-item">
                            <span class="ip-address">${ip}</span>
                            <button class="btn btn-danger" onclick="removeIP('${ip}')">Remove</button>
                        </div>
                    `).join('');
                }
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        async function addIP() {
            const input = document.getElementById('ipInput');
            const ip = input.value.trim();
            
            if (!ip) {
                showAlert('Please enter an IP address', 'error');
                return;
            }
            
            const ipPattern = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
            if (!ipPattern.test(ip)) {
                showAlert('Invalid IP address format', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'ip=' + encodeURIComponent(ip)
                });
                
                const result = await response.json();
                if (result.success) {
                    showAlert('IP address blocked successfully', 'success');
                    input.value = '';
                    loadStats();
                } else {
                    showAlert(result.message || 'Failed to block IP', 'error');
                }
            } catch (error) {
                showAlert('Error: ' + error.message, 'error');
            }
        }
        
        async function removeIP(ip) {
            if (!confirm('Remove ' + ip + ' from blocklist?')) return;
            
            try {
                const response = await fetch('/api/remove', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'ip=' + encodeURIComponent(ip)
                });
                
                const result = await response.json();
                if (result.success) {
                    showAlert('IP address removed successfully', 'success');
                    loadStats();
                } else {
                    showAlert(result.message || 'Failed to remove IP', 'error');
                }
            } catch (error) {
                showAlert('Error: ' + error.message, 'error');
            }
        }
        
        document.getElementById('ipInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') addIP();
        });
        
        loadStats();
        setInterval(loadStats, 5000);
    </script>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def _serve_stats(self):
        """Serve statistics JSON"""
        stats = self.ip_filter.get_stats()
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(stats).encode())
    
    def _handle_add_ip(self):
        """Handle add IP request"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        params = parse_qs(post_data)
        
        ip = params.get('ip', [''])[0].strip()
        
        if not ip:
            response = {'success': False, 'message': 'No IP provided'}
        elif self.ip_filter.is_blocked(ip):
            response = {'success': False, 'message': 'IP already blocked'}
        else:
            self.ip_filter.add_ip(ip)
            response = {'success': True, 'message': 'IP blocked successfully'}
            print(f"[WEB UI] Added IP to blocklist: {ip}")
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def _handle_remove_ip(self):
        """Handle remove IP request"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        params = parse_qs(post_data)
        
        ip = params.get('ip', [''])[0].strip()
        
        if not ip:
            response = {'success': False, 'message': 'No IP provided'}
        elif self.ip_filter.remove_ip(ip):
            response = {'success': True, 'message': 'IP removed successfully'}
            print(f"[WEB UI] Removed IP from blocklist: {ip}")
        else:
            response = {'success': False, 'message': 'IP not in blocklist'}
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())


# ============================================================================
# PROXY SERVER
# ============================================================================
class ProxyServer:
    """Main proxy server that intercepts connections to RyDrive"""
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ip_filter = IPFilter()
        self.server_socket = None
        self.running = False
    
    def start(self):
        """Start the proxy server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
        except OSError as e:
            print(f"[ERROR] Cannot bind to port {self.port}")
            print(f"   {e}")
            print(f"\n   Make sure port {self.port} is not already in use.")
            print(f"   You can change PROXY_PORT in the configuration section.")
            sys.exit(1)
        
        self.server_socket.listen(100)
        self.running = True
        
        self._print_banner()
        
        # Start Web UI
        web_thread = threading.Thread(target=self._start_web_ui, daemon=True)
        web_thread.start()
        
        # Start auto-reload thread
        reload_thread = threading.Thread(target=self._auto_reload, daemon=True)
        reload_thread.start()
        
        # Accept connections
        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                handler = ProxyHandler(client_socket, client_address, self.ip_filter)
                client_thread = threading.Thread(target=handler.handle)
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n\n[INFO] Shutting down proxy...")
        finally:
            self.running = False
            self.server_socket.close()
    
    def _start_web_ui(self):
        """Start the Web UI server"""
        WebUIHandler.ip_filter = self.ip_filter
        
        try:
            web_server = HTTPServer((WEB_UI_HOST, WEB_UI_PORT), WebUIHandler)
            print(f"[INFO] Web UI started at http://localhost:{WEB_UI_PORT}")
            web_server.serve_forever()
        except Exception as e:
            print(f"[ERROR] Failed to start Web UI: {e}")
    
    def _print_banner(self):
        """Print startup banner"""
        print("\n" + "=" * 70)
        print("RyDrive IP Ban Proxy with Web UI")
        print("=" * 70)
        print(f"Proxy listening on:  {self.host}:{self.port}")
        print(f"Forwarding to:       {RYDRIVE_HOST}:{RYDRIVE_PORT} (RyDrive)")
        print(f"Web UI:              http://localhost:{WEB_UI_PORT}")
        print(f"Blocked IPs:         {len(self.ip_filter.blocked_ips)}")
        print(f"Blocklist file:      {BLOCKED_IPS_FILE}")
        print(f"Auto-reload:         Every {RELOAD_INTERVAL} seconds")
        print("=" * 70)
        print("\nConfiguration:")
        print(f"   - Clients should connect to port {self.port} (not {RYDRIVE_PORT})")
        print(f"   - RyDrive must be running on port {RYDRIVE_PORT}")
        print(f"   - Manage blocklist at http://localhost:{WEB_UI_PORT}")
        print("\nPress Ctrl+C to stop\n")
    
    def _auto_reload(self):
        """Automatically reload blocked IPs periodically"""
        while self.running:
            time.sleep(RELOAD_INTERVAL)
            if self.running:
                self.ip_filter.reload()


# ============================================================================
# MAIN
# ============================================================================
def main():
    """Main entry point"""
    # Ensure blocked_ips.json exists
    try:
        with open(BLOCKED_IPS_FILE, 'r') as f:
            pass
    except FileNotFoundError:
        pass  # IPFilter will create it
    
    # Start proxy server
    proxy = ProxyServer(PROXY_HOST, PROXY_PORT)
    proxy.start()


if __name__ == "__main__":
    main()
