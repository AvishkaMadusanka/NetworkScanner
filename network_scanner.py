#!/usr/bin/env python3
import socket
import ipaddress
import threading
import argparse
from datetime import datetime
import sys
import struct
import platform

class NetworkScanner:
    def __init__(self, target, ports=None, timeout=1, threads=100):

        self.target = target
        self.timeout = timeout
        self.max_threads = threads
        self.active_hosts = []
        self.open_ports = {}
        self.lock = threading.Lock()
        
        # Parse ports
        if ports:
            self.ports = self._parse_ports(ports)
        else:
            self.ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 
                         445, 3306, 3389, 5432, 8080, 8443]
    
    def _parse_ports(self, port_input):
       
        ports = []
        if '-' in port_input:
            start, end = map(int, port_input.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in port_input.split(',')]
        return ports
    
    def _get_service_name(self, port):
        
        services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT",
            8443: "HTTPS-ALT"
        }
        return services.get(port, "Unknown")
    
    def _ping_host(self, ip):
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            # Try common ports to check if host is up
            result = sock.connect_ex((str(ip), 80))
            sock.close()
            
            if result == 0:
                return True
            
            # Try ping alternative - connect to port 443
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(ip), 443))
            sock.close()
            
            return result == 0
        except:
            return False
    
    def _scan_port(self, ip, port):
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(ip), port))
            
            if result == 0:
                try:
                    # Try to grab banner
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    banner = ""
                
                with self.lock:
                    if str(ip) not in self.open_ports:
                        self.open_ports[str(ip)] = []
                    self.open_ports[str(ip)].append({
                        'port': port,
                        'service': self._get_service_name(port),
                        'banner': banner[:100] if banner else "No banner"
                    })
            
            sock.close()
        except:
            pass
    
    def _get_hostname(self, ip):
        
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except:
            return "Unknown"
    
    def scan_host(self, ip):
        
        print(f"[*] Scanning {ip}...")
        
        hostname = self._get_hostname(ip)
        
        threads = []
        for port in self.ports:
            while threading.active_count() > self.max_threads:
                pass
            
            thread = threading.Thread(target=self._scan_port, args=(ip, port))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        if str(ip) in self.open_ports:
            with self.lock:
                self.active_hosts.append({
                    'ip': str(ip),
                    'hostname': hostname
                })
    
    def scan_network(self):
        
        try:
            network = ipaddress.ip_network(self.target, strict=False)
        except ValueError as e:
            print(f"[!] Invalid target: {e}")
            return
        
        print(f"\n{'='*60}")
        print(f"Network Scanner")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Ports: {len(self.ports)} ports")
        print(f"Threads: {self.max_threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        for ip in network.hosts():
            self.scan_host(ip)
        
        self._print_results()
    
    def _print_results(self):
        
        print(f"\n{'='*60}")
        print(f"Scan Results")
        print(f"{'='*60}\n")
        
        if not self.open_ports:
            print("[!] No open ports found")
            return
        
        for host_info in self.active_hosts:
            ip = host_info['ip']
            hostname = host_info['hostname']
            
            print(f"\n[+] Host: {ip}")
            if hostname != "Unknown":
                print(f"    Hostname: {hostname}")
            
            if ip in self.open_ports:
                print(f"    Open Ports:")
                for port_info in sorted(self.open_ports[ip], key=lambda x: x['port']):
                    print(f"      {port_info['port']:5d}/tcp  {port_info['service']:15s}  {port_info['banner']}")
        
        print(f"\n{'='*60}")
        print(f"Summary:")
        print(f"  Active Hosts: {len(self.active_hosts)}")
        print(f"  Total Open Ports: {sum(len(ports) for ports in self.open_ports.values())}")
        print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Network Scanner - For authorized use only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py 192.168.1.0/24
  python network_scanner.py 192.168.1.1 -p 1-1000
  python network_scanner.py 10.0.0.0/24 -p 80,443,8080 -t 200
  python network_scanner.py scanme.nmap.org -p 1-100

WARNING: Only scan networks you own or have explicit permission to scan.
Unauthorized network scanning may be illegal in your jurisdiction.
        """
    )
    
    parser.add_argument('target', help='Target IP address or CIDR (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., "1-1024" or "80,443,8080")')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1, help='Socket timeout in seconds (default: 1)')
    
    args = parser.parse_args()
    
    # Warning message
    print("\n" + "!"*60)
    print("WARNING: Use this tool only on networks you own or have")
    print("explicit permission to scan. Unauthorized scanning may be illegal.")
    print("!"*60 + "\n")
    
    try:
        scanner = NetworkScanner(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            threads=args.threads
        )
        scanner.scan_network()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()