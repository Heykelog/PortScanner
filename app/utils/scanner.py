import nmap
import ipaddress
import socket
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
import threading

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Thread local storage
thread_local = threading.local()

class PortScanner:
    def __init__(self, max_workers=10):
        self.max_workers = max_workers
        self.lock = threading.Lock()
    
    def get_scanner(self):
        """Get a thread-local nmap scanner instance"""
        if not hasattr(thread_local, 'scanner'):
            thread_local.scanner = nmap.PortScanner()
        return thread_local.scanner
    
    def is_valid_ip(self, ip: str) -> bool:
        """Check if the IP address is valid"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_valid_subnet(self, subnet: str) -> bool:
        """Check if the subnet CIDR is valid"""
        try:
            ipaddress.ip_network(subnet, strict=False)
            return True
        except ValueError:
            return False
    
    def discover_live_hosts(self, subnet: str) -> List[str]:
        """Quickly discover live hosts in a subnet using ping scan"""
        if not self.is_valid_subnet(subnet):
            logger.error(f"Invalid subnet: {subnet}")
            return []
        
        try:
            scanner = self.get_scanner()
            logger.info(f"Discovering live hosts in subnet: {subnet}")
            
            # Use ping scan (-sn) for quick host discovery
            ping_result = scanner.scan(hosts=subnet, arguments='-sn')
            
            # Extract live hosts
            live_hosts = []
            for host, host_data in ping_result['scan'].items():
                if host_data['status']['state'] == 'up':
                    live_hosts.append(host)
            
            logger.info(f"Found {len(live_hosts)} live hosts in subnet {subnet}")
            return live_hosts
        except Exception as e:
            logger.error(f"Error discovering hosts in subnet {subnet}: {e}")
            return []
    
    def scan_host(self, host: str, ports: str = '1-1024', arguments: str = '-sV') -> Dict[str, Any]:
        """Scan a single host for open ports"""
        if not self.is_valid_ip(host):
            logger.error(f"Invalid IP address: {host}")
            return {'error': f"Invalid IP address: {host}"}
        
        try:
            scanner = self.get_scanner()
            logger.info(f"Scanning host: {host} on ports {ports}")
            result = scanner.scan(hosts=host, ports=ports, arguments=arguments)
            return result
        except Exception as e:
            logger.error(f"Error scanning host {host}: {e}")
            return {'error': str(e)}
    
    def process_subnet(self, subnet: str, ports: str = '1-1024', arguments: str = '-sV') -> List[Dict[str, Any]]:
        """Process a subnet by scanning each host"""
        if not self.is_valid_subnet(subnet):
            logger.error(f"Invalid subnet: {subnet}")
            return [{'error': f"Invalid subnet: {subnet}"}]
        
        try:
            # Get all IPs in the subnet
            network = ipaddress.ip_network(subnet, strict=False)
            
            # Scan all hosts
            results = []
            for ip in network.hosts():
                ip_str = str(ip)
                result = self.scan_host(ip_str, ports, arguments)
                
                # If there's a result for this host, add it
                if 'scan' in result and ip_str in result['scan'] and result['scan'][ip_str]['status']['state'] == 'up':
                    with self.lock:
                        results.append({
                            'ip': ip_str,
                            'result': result['scan'][ip_str]
                        })
            
            return results
        except Exception as e:
            logger.error(f"Error processing subnet {subnet}: {e}")
            return [{'error': str(e)}]
    
    def scan_subnet(self, subnet: str, ports: str = '1-1024', arguments: str = '-sV') -> List[Dict[str, Any]]:
        """Scan a subnet for hosts and open ports"""
        try:
            logger.info(f"Scanning subnet: {subnet} on ports {ports}")
            
            # First, perform a quick host discovery to find active hosts
            live_hosts = self.discover_live_hosts(subnet)
            
            if not live_hosts:
                logger.info(f"No live hosts found in subnet {subnet}")
                return []
            
            logger.info(f"Performing port scans on {len(live_hosts)} live hosts in subnet {subnet}")
            
            # Scan ports on live hosts
            results = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_host = {executor.submit(self.scan_host, host, ports, arguments): host for host in live_hosts}
                for future in future_to_host:
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if 'scan' in result and host in result['scan']:
                            results.append({
                                'ip': host,
                                'result': result['scan'][host]
                            })
                    except Exception as e:
                        logger.error(f"Error processing result for {host}: {e}")
            
            return results
        except Exception as e:
            logger.error(f"Error scanning subnet {subnet}: {e}")
            return [{'error': str(e)}]
    
    def scan_multiple_subnets(self, subnets: List[str], ports: str = '1-1024', arguments: str = '-sV') -> Dict[str, List[Dict[str, Any]]]:
        """Scan multiple subnets in parallel"""
        results = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subnet = {executor.submit(self.scan_subnet, subnet, ports, arguments): subnet for subnet in subnets}
            for future in future_to_subnet:
                subnet = future_to_subnet[future]
                try:
                    subnet_results = future.result()
                    results[subnet] = subnet_results
                except Exception as e:
                    logger.error(f"Error processing results for subnet {subnet}: {e}")
                    results[subnet] = [{'error': str(e)}]
        
        return results
    
    def get_service_details(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract service details from scan results"""
        services = []
        
        if 'tcp' in result:
            for port, data in result['tcp'].items():
                service = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': data['state'],
                    'service': data.get('name', ''),
                    'product': data.get('product', ''),
                    'version': data.get('version', ''),
                    'extrainfo': data.get('extrainfo', '')
                }
                services.append(service)
                
        if 'udp' in result:
            for port, data in result['udp'].items():
                service = {
                    'port': port,
                    'protocol': 'udp',
                    'state': data['state'],
                    'service': data.get('name', ''),
                    'product': data.get('product', ''),
                    'version': data.get('version', ''),
                    'extrainfo': data.get('extrainfo', '')
                }
                services.append(service)
                
        return services

class VulnerabilityScanner:
    def __init__(self, port_scanner=None):
        if port_scanner is None:
            self.port_scanner = PortScanner()
        else:
            self.port_scanner = port_scanner
    
    def scan_for_vulnerabilities(self, host: str, ports: str = None) -> Dict[str, Any]:
        """Scan for vulnerabilities on specified host"""
        scanner = self.port_scanner.get_scanner()
        
        # If ports not specified, use all ports
        if not ports:
            ports = '1-65535'
            
        try:
            # Vulnerability scanning with scripts
            logger.info(f"Scanning for vulnerabilities on {host}")
            result = scanner.scan(hosts=host, ports=ports, arguments='-sV --script vuln')
            
            return result
        except Exception as e:
            logger.error(f"Error scanning for vulnerabilities on {host}: {e}")
            return {'error': str(e)}
    
    def extract_vulnerabilities(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability information from scan results"""
        vulnerabilities = []
        
        if 'scan' not in result:
            return vulnerabilities
            
        for host_ip, host_data in result['scan'].items():
            if 'tcp' not in host_data:
                continue
                
            for port, port_data in host_data['tcp'].items():
                if 'script' not in port_data:
                    continue
                    
                # Extract vulnerability data from scripts
                for script_name, script_output in port_data['script'].items():
                    if script_name.startswith('vuln'):
                        # Parse the vulnerability output
                        vulnerability = {
                            'host': host_ip,
                            'port': port,
                            'name': script_name,
                            'details': script_output
                        }
                        
                        # Try to extract CVE IDs
                        import re
                        cve_pattern = r'CVE-\d{4}-\d{4,}'
                        cves = re.findall(cve_pattern, script_output)
                        if cves:
                            vulnerability['cve_ids'] = cves
                            
                        vulnerabilities.append(vulnerability)
                        
        return vulnerabilities 