from app.tasks import celery
from app.utils.scanner import PortScanner, VulnerabilityScanner
from app import db
from app.models import (
    Scan, ScanResult, ScanEnvironment, Subnet, Host, 
    Port, Vulnerability, ScanTargetList, ScanTarget
)
from datetime import datetime
import logging
import ipaddress
from sqlalchemy import and_, or_

# Configure logging
logger = logging.getLogger(__name__)

@celery.task(name='tasks.run_port_scan')
def run_port_scan(scan_id, port_range='1-1024'):
    """
    Run port scan on the target subnets asynchronously
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            # Get scan details
            scan = Scan.query.get(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return {'status': 'error', 'message': f"Scan {scan_id} not found"}
            
            scan.status = 'running'
            scan.start_time = datetime.utcnow()
            db.session.commit()
            
            scanner = PortScanner(max_workers=10)
            
            # Get targets
            targets = []
            if scan.target_list_id:
                target_entries = ScanTarget.query.filter_by(list_id=scan.target_list_id).all()
                for entry in target_entries:
                    targets.append(entry.target)
            else:
                # Use all subnets in the environment
                subnets = Subnet.query.filter_by(environment_id=scan.environment_id).all()
                for subnet in subnets:
                    targets.append(subnet.cidr)
            
            scan.target_count = len(targets)
            db.session.commit()
            
            if not targets:
                scan.status = 'failed'
                scan.end_time = datetime.utcnow()
                db.session.commit()
                return {'status': 'error', 'message': "No targets found for scan"}
            
            # Run scan on all targets
            new_ports_count = 0
            open_ports_count = 0
            host_count = 0
            
            for target in targets:
                if scanner.is_valid_subnet(target):
                    # It's a subnet - first discover live hosts, then scan only those
                    logger.info(f"Processing subnet {target}")
                    live_hosts = scanner.discover_live_hosts(target)
                    total_hosts = sum(1 for _ in ipaddress.ip_network(target, strict=False).hosts())
                    
                    logger.info(f"Found {len(live_hosts)} live hosts out of {total_hosts} total in subnet {target}")
                    
                    if not live_hosts:
                        logger.info(f"No live hosts found in subnet {target}, skipping port scan")
                        continue
                    
                    # Scan only the live hosts
                    scan_results = scanner.scan_subnet(target, ports=port_range)
                    if scan_results:
                        process_subnet_results(scan, target, scan_results)
                        
                        # Update counts
                        host_count += len(scan_results)
                        for host_result in scan_results:
                            if 'result' in host_result:
                                services = scanner.get_service_details(host_result['result'])
                                open_services = [s for s in services if s['state'] == 'open']
                                open_ports_count += len(open_services)
                                
                                # Get new ports count by checking is_new flag in database
                                host = Host.query.filter_by(ip_address=host_result['ip']).first()
                                if host:
                                    new_ports = Port.query.filter_by(host_id=host.id, is_new=True).count()
                                    new_ports_count += new_ports
                elif scanner.is_valid_ip(target):
                    # It's a single IP - check if it's alive first
                    live_hosts = scanner.discover_live_hosts(f"{target}/32")
                    if not live_hosts:
                        logger.info(f"Host {target} is not alive, skipping port scan")
                        continue
                    
                    # Host is alive, scan it
                    logger.info(f"Host {target} is alive, performing port scan")
                    scan_result = scanner.scan_host(target, ports=port_range)
                    if 'scan' in scan_result and target in scan_result['scan']:
                        process_host_result(scan, target, scan_result['scan'][target])
                        
                        # Update counts
                        host_count += 1
                        services = scanner.get_service_details(scan_result['scan'][target])
                        open_services = [s for s in services if s['state'] == 'open']
                        open_ports_count += len(open_services)
                        
                        # Get new ports count
                        host = Host.query.filter_by(ip_address=target).first()
                        if host:
                            new_ports = Port.query.filter_by(host_id=host.id, is_new=True).count()
                            new_ports_count += new_ports
            
            # Update scan status
            scan.status = 'completed'
            scan.end_time = datetime.utcnow()
            scan.discovered_hosts = host_count
            scan.open_ports_found = open_ports_count
            scan.new_ports_found = new_ports_count
            db.session.commit()
            
            # If there are new ports, run vulnerability scan if configured
            if new_ports_count > 0 and scan.scan_type == 'vulnerability_scan':
                run_vulnerability_scan.delay(scan_id)
                
            return {
                'status': 'success',
                'message': "Scan completed successfully",
                'hosts_found': host_count,
                'open_ports': open_ports_count,
                'new_ports': new_ports_count
            }
            
        except Exception as e:
            logger.error(f"Error running port scan {scan_id}: {str(e)}")
            # Update scan status to failed
            try:
                scan.status = 'failed'
                scan.end_time = datetime.utcnow()
                db.session.commit()
            except:
                pass
                
            return {'status': 'error', 'message': str(e)}

def process_subnet_results(scan, subnet_cidr, results):
    """Process scan results for a subnet"""
    for host_result in results:
        if 'ip' in host_result and 'result' in host_result:
            process_host_result(scan, host_result['ip'], host_result['result'])

def process_host_result(scan, ip_address, result):
    """Process scan results for a host"""
    # Find or create subnet
    subnet = None
    for subnet_obj in Subnet.query.filter_by(environment_id=scan.environment_id).all():
        try:
            network = ipaddress.ip_network(subnet_obj.cidr, strict=False)
            if ipaddress.ip_address(ip_address) in network:
                subnet = subnet_obj
                break
        except:
            continue
    
    if not subnet:
        # Create new subnet with /24 mask
        ip_parts = ip_address.split('.')
        subnet_cidr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        subnet = Subnet(
            cidr=subnet_cidr,
            description=f"Auto-created subnet for {ip_address}",
            environment_id=scan.environment_id
        )
        db.session.add(subnet)
        db.session.commit()
    
    # Find or create host
    host = Host.query.filter_by(ip_address=ip_address).first()
    if not host:
        # New host
        hostname = result.get('hostname', '')
        host = Host(
            ip_address=ip_address,
            hostname=hostname,
            subnet_id=subnet.id,
            first_discovered=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            status='active'
        )
        db.session.add(host)
        db.session.commit()
        
        # Add scan result
        scan_result = ScanResult(
            scan_id=scan.id,
            host_id=host.id,
            result_type='new_host',
            details=f"New host discovered: {ip_address}"
        )
        db.session.add(scan_result)
        db.session.commit()
    else:
        # Update existing host
        host.last_seen = datetime.utcnow()
        host.status = 'active'
        db.session.commit()
    
    # Process ports
    if 'tcp' in result:
        process_ports(scan, host, result['tcp'], 'tcp')
    
    if 'udp' in result:
        process_ports(scan, host, result['udp'], 'udp')

def process_ports(scan, host, ports_data, protocol):
    """Process port scan results"""
    for port_number, port_data in ports_data.items():
        port_number = int(port_number)
        
        # Only process open ports
        if port_data['state'] != 'open':
            continue
            
        # Check if port exists
        port = Port.query.filter_by(
            host_id=host.id,
            port_number=port_number,
            protocol=protocol
        ).first()
        
        if not port:
            # New port found
            port = Port(
                port_number=port_number,
                protocol=protocol,
                service=port_data.get('name', ''),
                version=port_data.get('product', '') + ' ' + port_data.get('version', ''),
                host_id=host.id,
                status='open',
                is_new=True
            )
            db.session.add(port)
            db.session.commit()
            
            # Add scan result
            scan_result = ScanResult(
                scan_id=scan.id,
                host_id=host.id,
                port_id=port.id,
                result_type='new_port',
                details=f"New port discovered: {port_number}/{protocol} ({port_data.get('name', 'unknown')})"
            )
            db.session.add(scan_result)
            db.session.commit()
        else:
            # Update existing port
            old_status = port.status
            port.status = 'open'
            port.last_seen = datetime.utcnow()
            port.service = port_data.get('name', port.service)
            port.version = port_data.get('product', '') + ' ' + port_data.get('version', '')
            
            # If port was previously closed/filtered, mark as change
            if old_status != 'open':
                port.is_new = True
                
                # Add scan result
                scan_result = ScanResult(
                    scan_id=scan.id,
                    host_id=host.id,
                    port_id=port.id,
                    result_type='port_change',
                    details=f"Port status changed: {port_number}/{protocol} {old_status} -> open"
                )
                db.session.add(scan_result)
            
            db.session.commit()

@celery.task(name='tasks.run_vulnerability_scan')
def run_vulnerability_scan(scan_id):
    """
    Run vulnerability scan on open ports found during port scan
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            # Get scan details
            scan = Scan.query.get(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return {'status': 'error', 'message': f"Scan {scan_id} not found"}
            
            # Only update status if this is a standalone vulnerability scan
            if scan.status != 'completed':
                scan.status = 'running'
                scan.start_time = datetime.utcnow()
                db.session.commit()
            
            # Create scanner
            vuln_scanner = VulnerabilityScanner()
            
            # Get all hosts with open ports from the port scan
            scan_results = ScanResult.query.filter_by(scan_id=scan_id).all()
            host_ids = set()
            for result in scan_results:
                host_ids.add(result.host_id)
            
            vuln_count = 0
            
            # Process each host
            for host_id in host_ids:
                host = Host.query.get(host_id)
                if not host:
                    continue
                
                # Get open ports
                open_ports = Port.query.filter_by(host_id=host.id, status='open').all()
                if not open_ports:
                    continue
                
                # Build port list for scanning
                port_list = ','.join([str(p.port_number) for p in open_ports])
                
                # Run vulnerability scan
                result = vuln_scanner.scan_for_vulnerabilities(host.ip_address, port_list)
                
                # Process results
                vulnerabilities = vuln_scanner.extract_vulnerabilities(result)
                
                for vuln_data in vulnerabilities:
                    port_number = int(vuln_data['port'])
                    
                    # Find the port
                    port = Port.query.filter_by(
                        host_id=host.id,
                        port_number=port_number
                    ).first()
                    
                    if not port:
                        continue
                    
                    # Mark port as vulnerable
                    port.is_vulnerable = True
                    db.session.commit()
                    
                    # Create vulnerability record
                    cve_ids = vuln_data.get('cve_ids', [])
                    cve_id = cve_ids[0] if cve_ids else None
                    
                    vulnerability = Vulnerability(
                        cve_id=cve_id,
                        name=vuln_data['name'],
                        description=vuln_data['details'],
                        severity='high',  # Default to high, would need better parsing for accurate severity
                        port_id=port.id,
                        details=vuln_data['details']
                    )
                    db.session.add(vulnerability)
                    db.session.commit()
                    
                    # Create scan result
                    scan_result = ScanResult(
                        scan_id=scan.id,
                        host_id=host.id,
                        port_id=port.id,
                        result_type='vulnerability',
                        details=f"Vulnerability found: {vuln_data['name']} on port {port_number}"
                    )
                    db.session.add(scan_result)
                    db.session.commit()
                    
                    vuln_count += 1
            
            # Update scan status
            if scan.status != 'completed':
                scan.status = 'completed'
                scan.end_time = datetime.utcnow()
            
            scan.vulnerabilities_found = vuln_count
            db.session.commit()
            
            return {
                'status': 'success',
                'message': "Vulnerability scan completed successfully",
                'vulnerabilities_found': vuln_count
            }
            
        except Exception as e:
            logger.error(f"Error running vulnerability scan {scan_id}: {str(e)}")
            # Update scan status to failed
            try:
                scan.status = 'failed'
                scan.end_time = datetime.utcnow()
                db.session.commit()
            except:
                pass
                
            return {'status': 'error', 'message': str(e)}

@celery.task(name='tasks.scheduled_scan')
def scheduled_scan():
    """
    Check for scheduled scans and run them if needed
    """
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            # Get current time
            now = datetime.utcnow()
            current_time = now.time()
            current_weekday = now.weekday()  # 0 = Monday, 6 = Sunday
            current_day = now.day  # 1-31
            
            # Find schedules that should run now
            schedules = ScanSchedule.query.filter_by(is_active=True).all()
            
            for schedule in schedules:
                should_run = False
                
                # Check if the scan should run at this time
                time_match = (
                    schedule.time_of_day.hour == current_time.hour and 
                    schedule.time_of_day.minute == current_time.minute
                )
                
                if not time_match:
                    continue
                
                # Check frequency
                if schedule.frequency == 'daily':
                    should_run = True
                elif schedule.frequency == 'weekly' and schedule.day_of_week == current_weekday:
                    should_run = True
                elif schedule.frequency == 'monthly' and schedule.day_of_month == current_day:
                    should_run = True
                
                if should_run:
                    # Create a new scan
                    scan = Scan(
                        name=f"Scheduled scan: {schedule.name} - {now.strftime('%Y-%m-%d %H:%M')}",
                        status='pending',
                        scan_type='port_scan',
                        schedule_id=schedule.id,
                        environment_id=schedule.environment_id
                    )
                    
                    # If schedule is for specific subnet
                    if schedule.subnet_id:
                        # Create target list with this subnet
                        target_list = ScanTargetList(
                            name=f"Temporary list for {schedule.name} on {now.strftime('%Y-%m-%d')}",
                            description=f"Automatically created for scheduled scan"
                        )
                        db.session.add(target_list)
                        db.session.commit()
                        
                        subnet = Subnet.query.get(schedule.subnet_id)
                        if subnet:
                            target = ScanTarget(
                                target=subnet.cidr,
                                target_type='subnet',
                                list_id=target_list.id
                            )
                            db.session.add(target)
                            db.session.commit()
                            
                            scan.target_list_id = target_list.id
                    
                    db.session.add(scan)
                    db.session.commit()
                    
                    # Run the scan
                    run_port_scan.delay(scan.id)
        except Exception as e:
            logger.error(f"Error running scheduled scan: {str(e)}")
            return {'status': 'error', 'message': str(e)} 