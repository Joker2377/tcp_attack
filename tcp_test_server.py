#!/usr/bin/env python3
"""
TCP Test Server and Client for Hijacking Attack Testing
Creates controllable TCP connections to test hijacking attacks
"""

import socket
import threading
import time
import argparse
import sys

class TCPTestServer:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        self.running = False
        
    def start(self):
        """Start the test server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[*] TCP Test Server started on {self.host}:{self.port}")
            print(f"[*] Waiting for connections...")
            
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    print(f"[+] New connection from {client_addr}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                    self.clients.append((client_socket, client_addr))
                    
                except socket.error:
                    if self.running:
                        print("[!] Socket error occurred")
                    break
                    
        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, client_addr):
        """Handle individual client connection"""
        try:
            while self.running:
                # Send periodic heartbeat
                try:
                    client_socket.send(b"HEARTBEAT\n")
                    time.sleep(15)
                except socket.error:
                    print(f"[!] Client {client_addr} disconnected")
                    break
                    
                # Check for incoming data
                client_socket.settimeout(0.1)
                try:
                    data = client_socket.recv(1024)
                    if data:
                        print(f"[<] Received from {client_addr}: {data.decode().strip()}")
                        # Echo back
                        client_socket.send(f"ECHO: {data.decode()}".encode())
                    else:
                        print(f"[!] Client {client_addr} closed connection")
                        break
                except socket.timeout:
                    continue
                except socket.error:
                    print(f"[!] Client {client_addr} connection error")
                    break
                    
        except Exception as e:
            print(f"[!] Client handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("[*] Server stopped")

class TCPTestClient:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
    def connect(self):
        """Connect to the test server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.running = True
            
            local_addr = self.socket.getsockname()
            print(f"[+] Connected to {self.host}:{self.port} from {local_addr}")
            print(f"[*] Local port: {local_addr[1]} (use this for hijacking attack)")
            
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def run(self):
        """Run the client communication loop"""
        if not self.connect():
            return
            
        try:
            while self.running:
                # Check for incoming data
                self.socket.settimeout(1.0)
                try:
                    data = self.socket.recv(1024)
                    if data:
                        print(f"[>] Received: {data.decode().strip()}")
                    else:
                        print("[!] Server closed connection")
                        break
                except socket.timeout:
                    # Send periodic message
                    try:
                        message = f"CLIENT_MSG_{int(time.time())}"
                        #self.socket.send(message.encode() + b"\n")
                    except socket.error:
                        print("[!] Failed to send message")
                        break
                except socket.error as e:
                    print(f"[!] Socket error: {e}")
                    break
                    
        except KeyboardInterrupt:
            print("\n[*] Client interrupted by user")
        except Exception as e:
            print(f"[!] Client error: {e}")
        finally:
            self.disconnect()
    
    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print("[*] Client disconnected")

class TCPConnectionMonitor:
    """Monitor TCP connections to help with attack planning"""
    
    @staticmethod
    def show_connections(port=None):
        """Show active TCP connections"""
        import subprocess
        
        try:
            if sys.platform.startswith('linux'):
                cmd = ['ss', '-tuln']
                if port:
                    cmd.extend(['--sport', f':{port}'])
            else:
                cmd = ['netstat', '-an']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            print("[*] Active TCP connections:")
            print(result.stdout)
            
        except Exception as e:
            print(f"[!] Failed to show connections: {e}")
    
    @staticmethod
    def find_target_connections(target_port):
        """Find connections to target port"""
        import subprocess
        
        try:
            if sys.platform.startswith('linux'):
                cmd = ['ss', '-tuln', '--dport', f':{target_port}']
            else:
                cmd = ['netstat', '-an']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            connections = []
            for line in result.stdout.split('\n'):
                if str(target_port) in line and 'ESTABLISHED' in line:
                    connections.append(line.strip())
            
            return connections
            
        except Exception as e:
            print(f"[!] Failed to find connections: {e}")
            return []

def main():
    parser = argparse.ArgumentParser(description='TCP Test Server/Client for Hijacking Tests')
    parser.add_argument('mode', choices=['server', 'client', 'monitor'], 
                       help='Mode: server, client, or monitor')
    parser.add_argument('--host', default='127.0.0.1', help='Host address')
    parser.add_argument('--port', type=int, default=12345, help='Port number')
    
    args = parser.parse_args()
    
    try:
        if args.mode == 'server':
            server = TCPTestServer(args.host, args.port)
            server.start()
            
        elif args.mode == 'client':
            client = TCPTestClient(args.host, args.port)
            client.run()
            
        elif args.mode == 'monitor':
            print(f"[*] Monitoring connections on port {args.port}")
            TCPConnectionMonitor.show_connections()
            
            connections = TCPConnectionMonitor.find_target_connections(args.port)
            if connections:
                print(f"\n[*] Active connections to port {args.port}:")
                for conn in connections:
                    print(f"  {conn}")
            else:
                print(f"\n[*] No active connections to port {args.port}")
                
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()