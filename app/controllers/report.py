from flask import Blueprint, render_template, request, jsonify, send_file, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import (
    Scan, ScanResult, ScanEnvironment, Subnet, Host, 
    Port, Vulnerability, ScanSchedule
)
from sqlalchemy import func, and_, or_, desc, asc
from datetime import datetime, timedelta
import csv
import io
import json
import os

report = Blueprint('report', __name__, url_prefix='/report')

@report.route('/')
@login_required
def index():
    environments = ScanEnvironment.query.all()
    return render_template('report/index.html', environments=environments)

@report.route('/port-distribution')
@login_required
def port_distribution():
    """Report showing distribution of open ports"""
    # Query parameters
    env_id = request.args.get('env_id', type=int)
    limit = request.args.get('limit', 20, type=int)
    
    # Base query to get port counts
    query = db.session.query(
        Port.port_number,
        func.count(Port.id).label('port_count')
    ).filter(Port.status == 'open')
    
    # Apply environment filter if provided
    if env_id:
        env = ScanEnvironment.query.get_or_404(env_id)
        query = query.join(Host).join(Subnet).filter(Subnet.environment_id == env_id)
        environment_name = env.name
    else:
        environment_name = "All Environments"
    
    # Group by port number and order by count
    results = query.group_by(Port.port_number).order_by(desc('port_count')).limit(limit).all()
    
    # Format for chart display
    port_numbers = [str(r[0]) for r in results]
    port_counts = [r[1] for r in results]
    
    # Get environments for filter dropdown
    environments = ScanEnvironment.query.all()
    
    return render_template('report/port_distribution.html',
                          port_numbers=port_numbers,
                          port_counts=port_counts,
                          environments=environments,
                          current_env_id=env_id,
                          environment_name=environment_name,
                          limit=limit)

@report.route('/host-status')
@login_required
def host_status():
    """Report showing subnet and host status"""
    # Query parameters
    env_id = request.args.get('env_id', type=int)
    
    if env_id:
        env = ScanEnvironment.query.get_or_404(env_id)
        environment_name = env.name
        
        # Get subnets in this environment
        subnets = Subnet.query.filter_by(environment_id=env_id).all()
    else:
        environment_name = "All Environments"
        subnets = Subnet.query.all()
    
    # Prepare data for display
    subnet_data = []
    
    for subnet in subnets:
        # Count hosts
        total_hosts = Host.query.filter_by(subnet_id=subnet.id).count()
        active_hosts = Host.query.filter_by(subnet_id=subnet.id, status='active').count()
        
        # Calculate address space
        try:
            import ipaddress
            network = ipaddress.ip_network(subnet.cidr, strict=False)
            host_capacity = network.num_addresses - 2  # minus network and broadcast
            utilization = (total_hosts / host_capacity) * 100 if host_capacity > 0 else 0
        except:
            host_capacity = "Unknown"
            utilization = 0
        
        subnet_data.append({
            'id': subnet.id,
            'cidr': subnet.cidr,
            'description': subnet.description,
            'total_hosts': total_hosts,
            'active_hosts': active_hosts,
            'host_capacity': host_capacity if isinstance(host_capacity, int) else "N/A",
            'utilization': round(utilization, 2) if isinstance(host_capacity, int) else "N/A"
        })
    
    # Get environments for filter dropdown
    environments = ScanEnvironment.query.all()
    
    return render_template('report/host_status.html',
                          subnet_data=subnet_data,
                          environments=environments,
                          current_env_id=env_id,
                          environment_name=environment_name)

@report.route('/vulnerabilities')
@login_required
def vulnerabilities():
    """Report showing vulnerabilities found"""
    # Query parameters
    env_id = request.args.get('env_id', type=int)
    severity = request.args.get('severity', '')
    
    # Base query with explicit join path
    query = db.session.query(
        Vulnerability,
        Port,
        Host
    ).select_from(Vulnerability).join(Port).join(Host)
    
    # Apply filters
    if env_id:
        env = ScanEnvironment.query.get_or_404(env_id)
        query = query.join(Subnet, Host.subnet_id == Subnet.id).filter(Subnet.environment_id == env_id)
        environment_name = env.name
    else:
        environment_name = "All Environments"
    
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    
    # Get results
    results = query.order_by(Vulnerability.severity.desc(), Host.ip_address).all()
    
    # Process results for display
    vuln_data = []
    for vuln, port, host in results:
        vuln_data.append({
            'id': vuln.id,
            'name': vuln.name,
            'cve_id': vuln.cve_id or "N/A",
            'severity': vuln.severity,
            'host': host.ip_address,
            'port': f"{port.port_number}/{port.protocol}",
            'description': vuln.description,
            'discovered_at': vuln.discovered_at
        })
    
    # Get environments for filter dropdown
    environments = ScanEnvironment.query.all()
    
    return render_template('report/vulnerabilities.html',
                          vuln_data=vuln_data,
                          environments=environments,
                          current_env_id=env_id,
                          current_severity=severity,
                          environment_name=environment_name)

@report.route('/new-findings')
@login_required
def new_findings():
    """Report showing new findings in a time period"""
    # Query parameters
    days = request.args.get('days', 7, type=int)
    env_id = request.args.get('env_id', type=int)
    
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Base queries for new hosts and ports
    host_query = Host.query.filter(Host.first_discovered >= start_date)
    port_query = Port.query.filter(Port.first_discovered >= start_date, Port.status == 'open')
    
    # Apply environment filter if provided
    if env_id:
        env = ScanEnvironment.query.get_or_404(env_id)
        host_query = host_query.join(Subnet).filter(Subnet.environment_id == env_id)
        port_query = port_query.join(Host).join(Subnet).filter(Subnet.environment_id == env_id)
        environment_name = env.name
    else:
        environment_name = "All Environments"
    
    # Get results
    new_hosts = host_query.order_by(Host.first_discovered.desc()).all()
    
    # For ports, join with Host to get IP address
    new_ports_data = db.session.query(
        Port, Host
    ).join(Host).filter(
        Port.first_discovered >= start_date,
        Port.status == 'open'
    )
    
    if env_id:
        new_ports_data = new_ports_data.join(Subnet, Host.subnet_id == Subnet.id).filter(Subnet.environment_id == env_id)
    
    new_ports_data = new_ports_data.order_by(Port.first_discovered.desc()).all()
    
    # Format port data for display
    new_ports = []
    for port, host in new_ports_data:
        new_ports.append({
            'port_id': port.id,
            'port_number': port.port_number,
            'protocol': port.protocol,
            'service': port.service,
            'host_ip': host.ip_address,
            'first_discovered': port.first_discovered
        })
    
    # Get environments for filter dropdown
    environments = ScanEnvironment.query.all()
    
    return render_template('report/new_findings.html',
                          new_hosts=new_hosts,
                          new_ports=new_ports,
                          environments=environments,
                          current_env_id=env_id,
                          days=days,
                          start_date=start_date.strftime('%Y-%m-%d'),
                          end_date=end_date.strftime('%Y-%m-%d'),
                          environment_name=environment_name)

@report.route('/service-summary')
@login_required
def service_summary():
    """Report showing summary of services running on ports"""
    # Query parameters
    env_id = request.args.get('env_id', type=int)
    
    # Base query to get service counts
    query = db.session.query(
        Port.service,
        func.count(Port.id).label('service_count')
    ).filter(Port.status == 'open', Port.service != '')
    
    # Apply environment filter if provided
    if env_id:
        env = ScanEnvironment.query.get_or_404(env_id)
        query = query.join(Host).join(Subnet).filter(Subnet.environment_id == env_id)
        environment_name = env.name
    else:
        environment_name = "All Environments"
    
    # Group by service and order by count
    results = query.group_by(Port.service).order_by(desc('service_count')).all()
    
    # Format for chart display
    services = [r[0] or 'Unknown' for r in results]
    service_counts = [r[1] for r in results]
    
    # Get environments for filter dropdown
    environments = ScanEnvironment.query.all()
    
    return render_template('report/service_summary.html',
                          services=services,
                          service_counts=service_counts,
                          environments=environments,
                          current_env_id=env_id,
                          environment_name=environment_name)

@report.route('/comparison')
@login_required
def comparison():
    """Report comparing two scan results"""
    # Query parameters
    scan_id_1 = request.args.get('scan_id_1', type=int)
    scan_id_2 = request.args.get('scan_id_2', type=int)
    
    # Get most recent scans for default selection
    recent_scans = Scan.query.filter_by(status='completed').order_by(Scan.end_time.desc()).limit(10).all()
    
    if not scan_id_1 or not scan_id_2:
        # No comparison yet, just show the form
        return render_template('report/comparison.html',
                              recent_scans=recent_scans,
                              scan_id_1=scan_id_1,
                              scan_id_2=scan_id_2)
    
    # Get scan details
    scan1 = Scan.query.get_or_404(scan_id_1)
    scan2 = Scan.query.get_or_404(scan_id_2)
    
    # Ensure both scans are completed
    if scan1.status != 'completed' or scan2.status != 'completed':
        flash('Both scans must be completed for comparison.', 'danger')
        return redirect(url_for('report.comparison'))
    
    # Get results summary
    scan1_results = {
        'new_hosts': ScanResult.query.filter_by(scan_id=scan_id_1, result_type='new_host').count(),
        'new_ports': ScanResult.query.filter_by(scan_id=scan_id_1, result_type='new_port').count(),
        'vulnerabilities': ScanResult.query.filter_by(scan_id=scan_id_1, result_type='vulnerability').count()
    }
    
    scan2_results = {
        'new_hosts': ScanResult.query.filter_by(scan_id=scan_id_2, result_type='new_host').count(),
        'new_ports': ScanResult.query.filter_by(scan_id=scan_id_2, result_type='new_port').count(),
        'vulnerabilities': ScanResult.query.filter_by(scan_id=scan_id_2, result_type='vulnerability').count()
    }
    
    # Find differences in hosts
    scan1_hosts = set(result.host_id for result in ScanResult.query.filter_by(scan_id=scan_id_1).all())
    scan2_hosts = set(result.host_id for result in ScanResult.query.filter_by(scan_id=scan_id_2).all())
    
    hosts_in_1_not_2 = scan1_hosts - scan2_hosts
    hosts_in_2_not_1 = scan2_hosts - scan1_hosts
    
    # Find differences in ports
    scan1_ports = set(
        (result.host_id, result.port_id) 
        for result in ScanResult.query.filter_by(scan_id=scan_id_1).filter(ScanResult.port_id != None).all()
    )
    scan2_ports = set(
        (result.host_id, result.port_id) 
        for result in ScanResult.query.filter_by(scan_id=scan_id_2).filter(ScanResult.port_id != None).all()
    )
    
    ports_in_1_not_2 = scan1_ports - scan2_ports
    ports_in_2_not_1 = scan2_ports - scan1_ports
    
    # Get host and port details for differences
    host_details_1_not_2 = []
    if hosts_in_1_not_2:
        host_query = Host.query.filter(Host.id.in_(hosts_in_1_not_2)).all()
        host_details_1_not_2 = [{'id': h.id, 'ip': h.ip_address} for h in host_query]
    
    host_details_2_not_1 = []
    if hosts_in_2_not_1:
        host_query = Host.query.filter(Host.id.in_(hosts_in_2_not_1)).all()
        host_details_2_not_1 = [{'id': h.id, 'ip': h.ip_address} for h in host_query]
    
    port_details_1_not_2 = []
    if ports_in_1_not_2:
        for host_id, port_id in ports_in_1_not_2:
            port = Port.query.get(port_id)
            host = Host.query.get(host_id)
            if port and host:
                port_details_1_not_2.append({
                    'host_ip': host.ip_address,
                    'port_number': port.port_number,
                    'protocol': port.protocol,
                    'service': port.service
                })
    
    port_details_2_not_1 = []
    if ports_in_2_not_1:
        for host_id, port_id in ports_in_2_not_1:
            port = Port.query.get(port_id)
            host = Host.query.get(host_id)
            if port and host:
                port_details_2_not_1.append({
                    'host_ip': host.ip_address,
                    'port_number': port.port_number,
                    'protocol': port.protocol,
                    'service': port.service
                })
    
    return render_template('report/comparison.html',
                          recent_scans=recent_scans,
                          scan_id_1=scan_id_1,
                          scan_id_2=scan_id_2,
                          scan1=scan1,
                          scan2=scan2,
                          scan1_results=scan1_results,
                          scan2_results=scan2_results,
                          host_details_1_not_2=host_details_1_not_2,
                          host_details_2_not_1=host_details_2_not_1,
                          port_details_1_not_2=port_details_1_not_2,
                          port_details_2_not_1=port_details_2_not_1)

@report.route('/export', methods=['GET', 'POST'])
@login_required
def export_report():
    """Export report data as CSV"""
    # Get parameters from either GET or POST
    report_type = request.form.get('report_type') or request.args.get('type')
    env_id = request.form.get('env_id', type=int) or request.args.get('env_id', type=int)
    
    if not report_type:
        flash('Report type is required.', 'danger')
        return redirect(url_for('report.index'))
    
    # Create in-memory CSV file
    output = io.StringIO()
    writer = csv.writer(output)
    
    if report_type == 'hosts':
        # Export all hosts
        query = Host.query
        
        if env_id:
            query = query.join(Subnet).filter(Subnet.environment_id == env_id)
        
        hosts = query.order_by(Host.ip_address).all()
        
        # Write CSV header
        writer.writerow(['IP Address', 'Hostname', 'Status', 'First Discovered', 'Last Seen', 'Subnet'])
        
        # Write data
        for host in hosts:
            subnet = Subnet.query.get(host.subnet_id)
            writer.writerow([
                host.ip_address,
                host.hostname or '',
                host.status,
                host.first_discovered.strftime('%Y-%m-%d %H:%M:%S'),
                host.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                subnet.cidr if subnet else ''
            ])
        
        filename = 'hosts_report.csv'
        
    elif report_type == 'ports':
        # Export all ports
        query = db.session.query(Port, Host).join(Host)
        
        if env_id:
            query = query.join(Subnet, Host.subnet_id == Subnet.id).filter(Subnet.environment_id == env_id)
        
        ports = query.order_by(Host.ip_address, Port.port_number).all()
        
        # Write CSV header
        writer.writerow(['IP Address', 'Port Number', 'Protocol', 'Status', 'Service', 'Version', 'First Discovered', 'Last Seen', 'Is New', 'Is Vulnerable'])
        
        # Write data
        for port, host in ports:
            writer.writerow([
                host.ip_address,
                port.port_number,
                port.protocol,
                port.status,
                port.service or '',
                port.version or '',
                port.first_discovered.strftime('%Y-%m-%d %H:%M:%S'),
                port.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                'Yes' if port.is_new else 'No',
                'Yes' if port.is_vulnerable else 'No'
            ])
        
        filename = 'ports_report.csv'
        
    elif report_type == 'port':
        # Export hosts with specific port
        port_number = request.form.get('port_number', type=int) or request.args.get('port', type=int)
        
        if not port_number:
            flash('Port number is required for port export.', 'danger')
            return redirect(url_for('report.index'))
        
        query = db.session.query(Host, Port).join(Port).filter(Port.port_number == port_number)
        
        if env_id:
            query = query.join(Subnet, Host.subnet_id == Subnet.id).filter(Subnet.environment_id == env_id)
        
        results = query.order_by(Host.ip_address).all()
        
        # Write CSV header
        writer.writerow(['IP Address', 'Hostname', 'Status', 'Service', 'Protocol', 'First Discovered', 'Last Seen'])
        
        # Write data
        for host, port in results:
            writer.writerow([
                host.ip_address,
                host.hostname or '',
                port.status,
                port.service or '',
                port.protocol,
                host.first_discovered.strftime('%Y-%m-%d %H:%M:%S'),
                host.last_seen.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        filename = f'port_{port_number}_hosts.csv'
    elif report_type == 'service':
        # Export hosts with specific service
        service_name = request.form.get('service') or request.args.get('service')
        
        if not service_name:
            flash('Service name is required for service export.', 'danger')
            return redirect(url_for('report.index'))
        
        query = db.session.query(Host, Port).join(Port).filter(Port.service == service_name)
        
        if env_id:
            query = query.join(Subnet, Host.subnet_id == Subnet.id).filter(Subnet.environment_id == env_id)
        
        results = query.order_by(Host.ip_address, Port.port_number).all()
        
        # Write CSV header
        writer.writerow(['IP Address', 'Port', 'Protocol', 'Version', 'Status', 'First Discovered'])
        
        # Write data
        for host, port in results:
            writer.writerow([
                host.ip_address,
                port.port_number,
                port.protocol,
                port.version or '',
                port.status,
                port.first_discovered.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        filename = f'service_{service_name}_hosts.csv'
    elif report_type == 'subnet':
        # Export hosts from specific subnet
        subnet_id = request.form.get('subnet_id', type=int) or request.args.get('subnet_id', type=int)
        
        if not subnet_id:
            flash('Subnet ID is required for subnet export.', 'danger')
            return redirect(url_for('report.index'))
        
        subnet = Subnet.query.get_or_404(subnet_id)
        hosts = Host.query.filter_by(subnet_id=subnet_id).order_by(Host.ip_address).all()
        
        # Write CSV header
        writer.writerow(['IP Address', 'Hostname', 'Status', 'First Discovered', 'Last Seen', 'Open Ports'])
        
        # Write data
        for host in hosts:
            open_ports = Port.query.filter_by(host_id=host.id, status='open').count()
            writer.writerow([
                host.ip_address,
                host.hostname or '',
                host.status,
                host.first_discovered.strftime('%Y-%m-%d %H:%M:%S'),
                host.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                open_ports
            ])
        
        filename = f'subnet_{subnet.cidr.replace("/", "-")}_hosts.csv'
    elif report_type == 'vulnerabilities':
        # Export all vulnerabilities
        query = db.session.query(Vulnerability, Port, Host).join(Port).join(Host)
        
        if env_id:
            query = query.join(Subnet, Host.subnet_id == Subnet.id).filter(Subnet.environment_id == env_id)
        
        vulns = query.order_by(Host.ip_address, Port.port_number).all()
        
        # Write CSV header
        writer.writerow(['IP Address', 'Port', 'CVE ID', 'Name', 'Severity', 'Description', 'Discovered At'])
        
        # Write data
        for vuln, port, host in vulns:
            writer.writerow([
                host.ip_address,
                f"{port.port_number}/{port.protocol}",
                vuln.cve_id or '',
                vuln.name,
                vuln.severity,
                vuln.description or '',
                vuln.discovered_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        filename = 'vulnerabilities_report.csv'
    elif report_type == 'scan_results':
        # Export specific scan results
        scan_id = request.form.get('scan_id', type=int)
        
        if not scan_id:
            flash('Scan ID is required for scan results export.', 'danger')
            return redirect(url_for('report.index'))
        
        scan = Scan.query.get_or_404(scan_id)
        results = ScanResult.query.filter_by(scan_id=scan_id).all()
        
        # Write CSV header
        writer.writerow(['Result Type', 'Host IP', 'Port', 'Details', 'Timestamp'])
        
        # Write data
        for result in results:
            host = Host.query.get(result.host_id)
            port_info = ''
            if result.port_id:
                port = Port.query.get(result.port_id)
                if port:
                    port_info = f"{port.port_number}/{port.protocol}"
            
            writer.writerow([
                result.result_type,
                host.ip_address if host else '',
                port_info,
                result.details or '',
                result.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        filename = f'scan_results_{scan_id}.csv'
    else:
        flash('Invalid report type.', 'danger')
        return redirect(url_for('report.index'))
    
    # Reset file pointer and create response
    output.seek(0)
    
    # Return CSV file
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        as_attachment=True,
        download_name=filename,
        mimetype='text/csv'
    ) 