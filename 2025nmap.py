import asyncio
import socket
import argparse
import ipaddress
import json
import os
import sys
from collections import namedtuple

try:
    from scapy.all import sr1, TCP, IP, RandShort
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)

# --- Data Structures ---
ScanResult = namedtuple('ScanResult', ['host', 'port', 'status', 'banner'])

# --- Core Scanner Class ---
class Scanner:
    def __init__(self, targets, ports, scan_type='tcp', timeout=1.0, concurrency=100, service_scan=False):
        self.targets = targets
        self.ports = ports
        self.scan_type = scan_type
        self.timeout = timeout
        self.concurrency = concurrency
        self.service_scan = service_scan
        self.results = []

    async def grab_banner(self, host, port):
        """Tries to grab a banner from an open port by performing a full connect."""
        if not self.service_scan:
            return ''
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.write(b'\r\n')
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return banner.decode(errors='ignore').strip()
        except Exception:
            return '' # Ignore errors in banner grabbing

    async def tcp_connect_scan(self, host, port):
        """Asynchronously performs a standard TCP connect scan."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            banner = await self.grab_banner(host, port)
            return ScanResult(host, port, 'open', banner)
        except (socket.timeout, asyncio.TimeoutError):
            return ScanResult(host, port, 'filtered', '')
        except (ConnectionRefusedError, OSError):
            return ScanResult(host, port, 'closed', '')
        except Exception as e:
            return ScanResult(host, port, 'error', str(e))

    async def syn_scan(self, host, port):
        """Performs a SYN scan using Scapy. Requires root privileges."""
        try:
            src_port = RandShort()
            packet = IP(dst=str(host)) / TCP(sport=src_port, dport=port, flags='S')
            
            # Run blocking scapy call in a separate thread
            response = await asyncio.to_thread(
                sr1, packet, timeout=self.timeout, verbose=0
            )

            if response is None:
                return ScanResult(host, port, 'filtered', '')
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12: # SYN/ACK
                    # Send RST to tear down connection
                    rst_packet = IP(dst=str(host)) / TCP(sport=src_port, dport=port, flags='R')
                    await asyncio.to_thread(sr1, rst_packet, timeout=self.timeout, verbose=0)
                    banner = await self.grab_banner(host, port)
                    return ScanResult(host, port, 'open', banner)
                elif response.getlayer(TCP).flags == 0x14: # RST/ACK
                    return ScanResult(host, port, 'closed', '')
            return ScanResult(host, port, 'filtered', '') # No or unexpected response
        except Exception as e:
            return ScanResult(host, port, 'error', str(e))

    async def worker(self, queue):
        """Pulls tasks from the queue and executes the appropriate scan type."""
        while True:
            try:
                host, port = await queue.get()
                if self.scan_type == 'syn':
                    result = await self.syn_scan(host, port)
                else:
                    result = await self.tcp_connect_scan(host, port)
                
                if result.status == 'open':
                    print(f"[+] {result.host}:{result.port} is {result.status} - {result.banner}")
                self.results.append(result)
                queue.task_done()
            except asyncio.CancelledError:
                break

    async def run(self):
        """Main entry point to start the scanning process."""
        queue = asyncio.Queue()
        for target in self.targets:
            for port in self.ports:
                await queue.put((str(target), port))

        tasks = [asyncio.create_task(self.worker(queue)) for _ in range(self.concurrency)]
        await queue.join()

        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

# --- Utility Functions ---
def parse_ports(port_string):
    ports = set()
    if not port_string:
        return []
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def parse_targets(target_string):
    targets = []
    try:
        network = ipaddress.ip_network(target_string, strict=False)
        targets.extend(network.hosts() if network.num_addresses > 1 else [network.network_address])
    except ValueError:
        targets.append(target_string)
    return targets

def print_results(results, output_format):
    if output_format == 'json':
        json_results = [r._asdict() for r in results]
        print(json.dumps(json_results, indent=4))
        return

    for result in sorted(results, key=lambda x: (x.host, x.port)):
        if result.status == 'open':
            print(f"Host: {result.host}\tPort: {result.port}\tStatus: {result.status}\tBanner: {result.banner}")

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="A dependency-light, asynchronous network scanner.")
    parser.add_argument("targets", help="Target host(s) or network(s).")
    parser.add_argument("-p", "--ports", default="22,80,443", help="Ports to scan.")
    parser.add_argument("-sS", "--syn-scan", action='store_true', help="Perform a stealthy SYN scan (requires root).")
    parser.add_argument("-sV", "--service-scan", action='store_true', help="Enable service detection.")
    parser.add_argument("-o", "--output", choices=['normal', 'json'], default='normal', help="Output format.")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout.")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrency level.")

    args = parser.parse_args()

    if args.syn_scan and os.geteuid() != 0:
        print("Error: SYN scan (-sS) requires root privileges.")
        sys.exit(1)

    try:
        targets = parse_targets(args.targets)
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: Invalid target or port specification. {e}")
        return

    scan_type = 'syn' if args.syn_scan else 'tcp'
    print(f"[*] Starting {scan_type.upper()} scan on {len(targets)} host(s) and {len(ports)} port(s)...")
    
    scanner = Scanner(targets, ports, scan_type, args.timeout, args.concurrency, args.service_scan)
    
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user.")
    finally:
        print("[*] Scan complete.")
        if args.output:
            print_results(scanner.results, args.output)

if __name__ == "__main__":
    main()

}
