from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models import ScanEnvironment, Subnet, Host, Port, Scan, ScanResult
from app.controllers.auth import admin_required
from sqlalchemy import func, desc, and_, or_
from datetime import datetime, timedelta
from app.models.scan import ScanTargetList, ScanTarget

main = Blueprint('main', __name__)

@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main.route('/dashboard')
@login_required
def dashboard():
    # Recent scans
    recent_scans = Scan.query.order_by(Scan.start_time.desc()).limit(5).all()
    
    # Environment summary
    environments = ScanEnvironment.query.all()
    env_summary = []
    
    for env in environments:
        subnet_count = Subnet.query.filter_by(environment_id=env.id).count()
        host_count = Host.query.join(Subnet).filter(Subnet.environment_id == env.id).count()
        port_count = Port.query.join(Host).join(Subnet).filter(Subnet.environment_id == env.id).count()
        
        env_summary.append({
            'name': env.name,
            'subnet_count': subnet_count,
            'host_count': host_count,
            'port_count': port_count
        })
    
    # New findings in the last 24 hours
    yesterday = datetime.utcnow() - timedelta(days=1)
    new_hosts = Host.query.filter(Host.first_discovered >= yesterday).count()
    new_ports = Port.query.filter(Port.first_discovered >= yesterday).count()
    
    # Scan stats
    total_scans = Scan.query.count()
    completed_scans = Scan.query.filter_by(status='completed').count()
    failed_scans = Scan.query.filter_by(status='failed').count()
    
    return render_template('main/dashboard.html', 
                          recent_scans=recent_scans,
                          env_summary=env_summary,
                          new_hosts=new_hosts,
                          new_ports=new_ports,
                          total_scans=total_scans,
                          completed_scans=completed_scans,
                          failed_scans=failed_scans)

@main.route('/environments')
@login_required
def environments():
    environments = ScanEnvironment.query.all()
    return render_template('main/environments.html', environments=environments)

@main.route('/environments/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_environment():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if ScanEnvironment.query.filter_by(name=name).first():
            flash('Environment with this name already exists.', 'danger')
            return render_template('main/new_environment.html')
        
        environment = ScanEnvironment(name=name, description=description)
        db.session.add(environment)
        db.session.commit()
        
        flash('Environment created successfully!', 'success')
        return redirect(url_for('main.environments'))
    
    return render_template('main/new_environment.html')

@main.route('/environments/<int:env_id>')
@login_required
def view_environment(env_id):
    environment = ScanEnvironment.query.get_or_404(env_id)
    subnets = Subnet.query.filter_by(environment_id=env_id).all()
    
    # Summary stats
    host_count = Host.query.join(Subnet).filter(Subnet.environment_id == env_id).count()
    port_count = Port.query.join(Host).join(Subnet).filter(Subnet.environment_id == env_id).count()
    
    return render_template('main/view_environment.html', 
                          environment=environment,
                          subnets=subnets,
                          host_count=host_count,
                          port_count=port_count,
                          Scan=Scan)

@main.route('/environments/<int:env_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_environment(env_id):
    environment = ScanEnvironment.query.get_or_404(env_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        # Check if name already exists but not for this environment
        existing = ScanEnvironment.query.filter(
            and_(ScanEnvironment.name == name, ScanEnvironment.id != env_id)
        ).first()
        
        if existing:
            flash('Environment with this name already exists.', 'danger')
            return render_template('main/edit_environment.html', environment=environment)
        
        environment.name = name
        environment.description = description
        environment.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Environment updated successfully!', 'success')
        return redirect(url_for('main.view_environment', env_id=env_id))
    
    return render_template('main/edit_environment.html', environment=environment)

@main.route('/environments/<int:env_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_environment(env_id):
    environment = ScanEnvironment.query.get_or_404(env_id)
    
    # Now we can safely delete the environment due to cascade deletion
    db.session.delete(environment)
    db.session.commit()
    
    flash('Environment and all related data deleted successfully!', 'success')
    return redirect(url_for('main.environments'))

@main.route('/subnets/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_subnet():
    environments = ScanEnvironment.query.all()
    
    if not environments:
        flash('You need to create an environment first.', 'warning')
        return redirect(url_for('main.new_environment'))
    
    # Get all target lists for the dropdown selection
    target_lists = ScanTargetList.query.all()
    
    if request.method == 'POST':
        description = request.form.get('description')
        environment_id = request.form.get('environment_id')
        input_method = request.form.get('input_method')
        
        cidr_list = []
        
        # Process based on the selected input method
        if input_method == 'manual':
            cidr_input = request.form.get('cidr')
            if cidr_input:
                cidr_list = [cidr.strip() for cidr in cidr_input.split(',') if cidr.strip()]
        elif input_method == 'target_list':
            target_list_id = request.form.get('target_list_id')
            if target_list_id:
                # Get all subnet targets from the selected list
                subnet_targets = ScanTarget.query.filter_by(
                    list_id=target_list_id, 
                    target_type='subnet'
                ).all()
                cidr_list = [target.target for target in subnet_targets]
        
        if not cidr_list:
            flash('Please enter at least one valid CIDR range or select a target list with subnets.', 'danger')
            return render_template('main/new_subnet.html', 
                                  environments=environments,
                                  target_lists=target_lists)
        
        # Track success and failures
        success_count = 0
        failed_cidrs = []
        
        # Process each CIDR
        for cidr in cidr_list:
            # Fix common format issues
            # If there's no dot in the last segment, assume it's a network address format issue
            if not '.' in cidr.split('/')[0].split('.')[-1]:
                parts = cidr.split('/')
                if len(parts) == 2:
                    ip_parts = parts[0].split('.')
                    if len(ip_parts) == 4:
                        # Replace the last part with 0
                        ip_parts[-1] = '0'
                        fixed_cidr = '.'.join(ip_parts) + '/' + parts[1]
                        cidr = fixed_cidr
            
            # Validate CIDR format
            try:
                import ipaddress
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                failed_cidrs.append(f"{cidr} (Invalid format: {str(e)})")
                continue
            
            # Check if subnet already exists in this environment
            if Subnet.query.filter_by(cidr=cidr, environment_id=environment_id).first():
                failed_cidrs.append(f"{cidr} (already exists)")
                continue
            
            # Create the subnet
            subnet = Subnet(
                cidr=cidr,
                description=description,
                environment_id=environment_id
            )
            
            db.session.add(subnet)
            success_count += 1
        
        # Commit all successful subnets
        if success_count > 0:
            db.session.commit()
            
            if len(failed_cidrs) > 0:
                flash(f'Added {success_count} subnet(s). Failed to add: {", ".join(failed_cidrs)}', 'warning')
            else:
                flash(f'Successfully added {success_count} subnet(s).', 'success')
            
            return redirect(url_for('main.view_environment', env_id=environment_id))
        else:
            flash(f'Failed to add any subnets. Issues with: {", ".join(failed_cidrs)}', 'danger')
            return render_template('main/new_subnet.html', 
                                  environments=environments,
                                  target_lists=target_lists)
    
    # Pre-select environment_id if provided in query parameter
    env_id = request.args.get('env_id')
    
    return render_template('main/new_subnet.html', 
                          environments=environments,
                          target_lists=target_lists,
                          env_id=env_id)

@main.route('/subnets/<int:subnet_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_subnet(subnet_id):
    subnet = Subnet.query.get_or_404(subnet_id)
    environments = ScanEnvironment.query.all()
    
    if request.method == 'POST':
        cidr = request.form.get('cidr')
        description = request.form.get('description')
        environment_id = request.form.get('environment_id')
        
        # Validate CIDR format
        try:
            import ipaddress
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            flash('Invalid CIDR format.', 'danger')
            return render_template('main/edit_subnet.html', subnet=subnet, environments=environments)
        
        # Check if subnet already exists but not this one
        existing = Subnet.query.filter(
            and_(Subnet.cidr == cidr, Subnet.environment_id == environment_id, Subnet.id != subnet_id)
        ).first()
        
        if existing:
            flash('Subnet already exists in this environment.', 'danger')
            return render_template('main/edit_subnet.html', subnet=subnet, environments=environments)
        
        subnet.cidr = cidr
        subnet.description = description
        subnet.environment_id = environment_id
        subnet.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Subnet updated successfully!', 'success')
        return redirect(url_for('main.view_environment', env_id=environment_id))
    
    return render_template('main/edit_subnet.html', subnet=subnet, environments=environments)

@main.route('/subnets/<int:subnet_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_subnet(subnet_id):
    subnet = Subnet.query.get_or_404(subnet_id)
    environment_id = subnet.environment_id
    
    # Now we can safely delete the subnet due to cascade deletion
    db.session.delete(subnet)
    db.session.commit()
    
    flash('Subnet and all related hosts deleted successfully!', 'success')
    return redirect(url_for('main.view_environment', env_id=environment_id))

@main.route('/hosts')
@login_required
def hosts():
    # Get query parameters
    subnet_id = request.args.get('subnet_id', type=int)
    env_id = request.args.get('env_id', type=int)
    search = request.args.get('search', '')
    
    query = Host.query
    
    # Apply filters
    if subnet_id:
        query = query.filter_by(subnet_id=subnet_id)
    elif env_id:
        query = query.join(Subnet).filter(Subnet.environment_id == env_id)
    
    if search:
        query = query.filter(Host.ip_address.like(f'%{search}%'))
    
    hosts = query.order_by(Host.ip_address).all()
    
    # Get list of environments and subnets for filter dropdowns
    environments = ScanEnvironment.query.all()
    subnets = Subnet.query.all()
    
    return render_template('main/hosts.html', 
                          hosts=hosts, 
                          environments=environments, 
                          subnets=subnets,
                          current_env_id=env_id,
                          current_subnet_id=subnet_id,
                          search=search)

@main.route('/hosts/<int:host_id>')
@login_required
def view_host(host_id):
    host = Host.query.get_or_404(host_id)
    ports = Port.query.filter_by(host_id=host_id).order_by(Port.port_number).all()
    
    # Recent scan results
    scan_results = ScanResult.query.filter_by(host_id=host_id).order_by(ScanResult.timestamp.desc()).limit(10).all()
    
    return render_template('main/view_host.html', host=host, ports=ports, scan_results=scan_results)

@main.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    
    if not query:
        return render_template('main/search_results.html', query='', hosts=[], ports=[])
    
    # Search hosts
    hosts = Host.query.filter(Host.ip_address.like(f'%{query}%')).all()
    
    # Search ports
    ports = db.session.query(Port, Host).join(Host).filter(
        or_(
            Host.ip_address.like(f'%{query}%'),
            Port.port_number == query if query.isdigit() else False,
            Port.service.like(f'%{query}%')
        )
    ).all()
    
    return render_template('main/search_results.html', query=query, hosts=hosts, ports=ports)

@main.route('/api/ports-by-number')
@login_required
def ports_by_number():
    """API endpoint for ports grouped by port number"""
    port_number = request.args.get('port', type=int)
    env_id = request.args.get('env_id', type=int)
    
    if not port_number:
        return jsonify({'error': 'Port number is required'}), 400
    
    query = db.session.query(Host.ip_address, Port.status, Port.service).join(Port)
    
    # Filter by environment if specified
    if env_id:
        query = query.join(Subnet).filter(Subnet.environment_id == env_id)
    
    # Filter by port number
    query = query.filter(Port.port_number == port_number)
    
    results = query.all()
    
    hosts = [{'ip': row[0], 'status': row[1], 'service': row[2]} for row in results]
    
    return jsonify({
        'port': port_number,
        'hosts': hosts,
        'count': len(hosts)
    }) 