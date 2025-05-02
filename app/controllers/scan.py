from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models import (
    Scan, ScanResult, ScanEnvironment, Subnet, 
    ScanSchedule, ScanTargetList, ScanTarget
)
from app.controllers.auth import admin_required
from app.tasks.scan_tasks import run_port_scan, run_vulnerability_scan
from datetime import datetime, timedelta
from sqlalchemy import and_, or_, desc

scan = Blueprint('scan', __name__, url_prefix='/scan')

@scan.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Filter parameters
    status = request.args.get('status', '')
    env_id = request.args.get('env_id', type=int)
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Scan.query
    
    # Apply filters
    if status:
        query = query.filter_by(status=status)
    
    if env_id:
        query = query.filter_by(environment_id=env_id)
    
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Scan.start_time >= from_date)
        except ValueError:
            flash(f'Invalid date format: {date_from}. Use YYYY-MM-DD.', 'warning')
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d')
            to_date = to_date + timedelta(days=1)  # Include the end date
            query = query.filter(Scan.start_time <= to_date)
        except ValueError:
            flash(f'Invalid date format: {date_to}. Use YYYY-MM-DD.', 'warning')
    
    # Paginate results
    scans_pagination = query.order_by(Scan.start_time.desc()).paginate(page=page, per_page=per_page)
    
    # Get environments for filter dropdown
    environments = ScanEnvironment.query.all()
    
    return render_template('scan/index.html', 
                          scans=scans_pagination.items, 
                          pagination=scans_pagination,
                          environments=environments,
                          current_status=status,
                          current_env_id=env_id,
                          date_from=date_from,
                          date_to=date_to)

@scan.route('/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_scan():
    # Get all environments
    environments = ScanEnvironment.query.all()
    
    if not environments:
        flash('You need to create an environment first.', 'warning')
        return redirect(url_for('main.new_environment'))
    
    # Get all target lists
    target_lists = ScanTargetList.query.all()
    
    if request.method == 'POST':
        scan_name = request.form.get('name')
        environment_id = request.form.get('environment_id')
        scan_type = request.form.get('scan_type')
        target_list_id = request.form.get('target_list_id')
        custom_targets = request.form.get('custom_targets')
        port_range = request.form.get('port_range', '1-1024')
        
        if not scan_name or not environment_id or not scan_type:
            flash('Missing required fields.', 'danger')
            return render_template('scan/new_scan.html', 
                                  environments=environments, 
                                  target_lists=target_lists)
        
        # Create the scan
        scan = Scan(
            name=scan_name,
            status='pending',
            scan_type=scan_type,
            environment_id=environment_id,
            created_by=current_user.id
        )
        
        if target_list_id and target_list_id != 'custom':
            scan.target_list_id = target_list_id
        elif custom_targets:
            # Create a new target list for this scan
            target_list = ScanTargetList(
                name=f"Custom list for {scan_name}",
                description="Created for one-time scan"
            )
            db.session.add(target_list)
            db.session.flush()
            
            # Add targets
            for target in custom_targets.splitlines():
                target = target.strip()
                if not target:
                    continue
                
                # Determine if it's a subnet or host
                target_type = 'subnet' if '/' in target else 'host'
                
                # Create target entry
                target_entry = ScanTarget(
                    target=target,
                    target_type=target_type,
                    list_id=target_list.id
                )
                db.session.add(target_entry)
            
            scan.target_list_id = target_list.id
        
        db.session.add(scan)
        db.session.commit()
        
        # Start the scan as a background task
        run_port_scan.delay(scan.id, port_range)
        
        flash('Scan created and started in the background.', 'success')
        return redirect(url_for('scan.view_scan', scan_id=scan.id))
    
    return render_template('scan/new_scan.html', 
                          environments=environments, 
                          target_lists=target_lists)

@scan.route('/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Get scan results
    results = ScanResult.query.filter_by(scan_id=scan_id).order_by(ScanResult.timestamp.desc()).all()
    
    # Group results by type
    new_hosts = [r for r in results if r.result_type == 'new_host']
    new_ports = [r for r in results if r.result_type == 'new_port']
    port_changes = [r for r in results if r.result_type == 'port_change']
    vulnerabilities = [r for r in results if r.result_type == 'vulnerability']
    
    return render_template('scan/view_scan.html', 
                          scan=scan,
                          new_hosts=new_hosts,
                          new_ports=new_ports,
                          port_changes=port_changes,
                          vulnerabilities=vulnerabilities)

@scan.route('/<int:scan_id>/run-vulnerability-scan', methods=['POST'])
@login_required
@admin_required
def run_vuln_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Only run on completed port scans
    if scan.status != 'completed':
        flash('Vulnerability scan can only be run on completed port scans.', 'danger')
        return redirect(url_for('scan.view_scan', scan_id=scan_id))
    
    # Start vulnerability scan
    run_vulnerability_scan.delay(scan_id)
    
    flash('Vulnerability scan started in the background.', 'success')
    return redirect(url_for('scan.view_scan', scan_id=scan_id))

@scan.route('/<int:scan_id>/rescan', methods=['POST'])
@login_required
@admin_required
def rescan(scan_id):
    original_scan = Scan.query.get_or_404(scan_id)
    
    # Create a new scan with the same parameters
    new_scan = Scan(
        name=f"Rescan of {original_scan.name}",
        status='pending',
        scan_type=original_scan.scan_type,
        environment_id=original_scan.environment_id,
        target_list_id=original_scan.target_list_id,
        created_by=current_user.id
    )
    
    db.session.add(new_scan)
    db.session.commit()
    
    # Start the scan as a background task with default port range
    run_port_scan.delay(new_scan.id, "1-1024")
    
    flash('New scan created and started in the background.', 'success')
    return redirect(url_for('scan.view_scan', scan_id=new_scan.id))

@scan.route('/<int:scan_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Delete scan results
    ScanResult.query.filter_by(scan_id=scan_id).delete()
    
    # Delete scan
    db.session.delete(scan)
    db.session.commit()
    
    flash('Scan deleted successfully.', 'success')
    return redirect(url_for('scan.index'))

@scan.route('/target-lists')
@login_required
def target_lists():
    target_lists = ScanTargetList.query.all()
    return render_template('scan/target_lists.html', target_lists=target_lists)

@scan.route('/target-lists/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_target_list():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        targets = request.form.get('targets')
        
        if not name or not targets:
            flash('Name and at least one target are required.', 'danger')
            return render_template('scan/new_target_list.html')
        
        # Check if name already exists
        if ScanTargetList.query.filter_by(name=name).first():
            flash('Target list with this name already exists.', 'danger')
            return render_template('scan/new_target_list.html')
        
        # Create target list
        target_list = ScanTargetList(name=name, description=description)
        db.session.add(target_list)
        db.session.flush()
        
        # Add targets
        for target in targets.splitlines():
            target = target.strip()
            if not target:
                continue
            
            # Determine if it's a subnet or host
            target_type = 'subnet' if '/' in target else 'host'
            
            # Create target entry
            target_entry = ScanTarget(
                target=target,
                target_type=target_type,
                list_id=target_list.id
            )
            db.session.add(target_entry)
        
        db.session.commit()
        
        flash('Target list created successfully.', 'success')
        return redirect(url_for('scan.target_lists'))
    
    return render_template('scan/new_target_list.html')

@scan.route('/target-lists/<int:list_id>')
@login_required
def view_target_list(list_id):
    target_list = ScanTargetList.query.get_or_404(list_id)
    targets = ScanTarget.query.filter_by(list_id=list_id).all()
    
    return render_template('scan/view_target_list.html', target_list=target_list, targets=targets)

@scan.route('/target-lists/<int:list_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_target_list(list_id):
    target_list = ScanTargetList.query.get_or_404(list_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        targets = request.form.get('targets')
        
        if not name or not targets:
            flash('Name and at least one target are required.', 'danger')
            return render_template('scan/edit_target_list.html', target_list=target_list)
        
        # Check if name already exists but not for this list
        existing = ScanTargetList.query.filter(
            and_(ScanTargetList.name == name, ScanTargetList.id != list_id)
        ).first()
        
        if existing:
            flash('Target list with this name already exists.', 'danger')
            return render_template('scan/edit_target_list.html', target_list=target_list)
        
        # Update list
        target_list.name = name
        target_list.description = description
        target_list.updated_at = datetime.utcnow()
        
        # Delete existing targets
        ScanTarget.query.filter_by(list_id=list_id).delete()
        
        # Add targets
        for target in targets.splitlines():
            target = target.strip()
            if not target:
                continue
            
            # Determine if it's a subnet or host
            target_type = 'subnet' if '/' in target else 'host'
            
            # Create target entry
            target_entry = ScanTarget(
                target=target,
                target_type=target_type,
                list_id=list_id
            )
            db.session.add(target_entry)
        
        db.session.commit()
        
        flash('Target list updated successfully.', 'success')
        return redirect(url_for('scan.view_target_list', list_id=list_id))
    
    # Get existing targets for display
    targets = ScanTarget.query.filter_by(list_id=list_id).all()
    targets_text = '\n'.join([t.target for t in targets])
    
    return render_template('scan/edit_target_list.html', 
                          target_list=target_list,
                          targets_text=targets_text)

@scan.route('/target-lists/<int:list_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_target_list(list_id):
    target_list = ScanTargetList.query.get_or_404(list_id)
    
    # Check if any scans use this target list
    if Scan.query.filter_by(target_list_id=list_id).first():
        flash('Cannot delete target list that is used by scans.', 'danger')
        return redirect(url_for('scan.view_target_list', list_id=list_id))
    
    # Delete targets
    ScanTarget.query.filter_by(list_id=list_id).delete()
    
    # Delete list
    db.session.delete(target_list)
    db.session.commit()
    
    flash('Target list deleted successfully.', 'success')
    return redirect(url_for('scan.target_lists'))

@scan.route('/schedules')
@login_required
def schedules():
    schedules = ScanSchedule.query.all()
    return render_template('scan/schedules.html', schedules=schedules)

@scan.route('/schedules/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_schedule():
    environments = ScanEnvironment.query.all()
    
    if not environments:
        flash('You need to create an environment first.', 'warning')
        return redirect(url_for('main.new_environment'))
    
    subnets = Subnet.query.all()
    
    if request.method == 'POST':
        name = request.form.get('name')
        frequency = request.form.get('frequency')
        time_of_day = request.form.get('time_of_day')
        day_of_week = request.form.get('day_of_week')
        day_of_month = request.form.get('day_of_month')
        environment_id = request.form.get('environment_id')
        subnet_id = request.form.get('subnet_id') if request.form.get('subnet_id') != 'all' else None
        
        if not name or not frequency or not time_of_day or not environment_id:
            flash('Missing required fields.', 'danger')
            return render_template('scan/new_schedule.html', 
                                  environments=environments,
                                  subnets=subnets)
        
        # Convert time string to Time object
        try:
            hour, minute = time_of_day.split(':')
            time_obj = datetime.strptime(f"{hour}:{minute}", '%H:%M').time()
        except ValueError:
            flash('Invalid time format. Use HH:MM.', 'danger')
            return render_template('scan/new_schedule.html', 
                                  environments=environments,
                                  subnets=subnets)
        
        # Create schedule
        schedule = ScanSchedule(
            name=name,
            frequency=frequency,
            time_of_day=time_obj,
            environment_id=environment_id
        )
        
        if frequency == 'weekly' and day_of_week:
            schedule.day_of_week = int(day_of_week)
        
        if frequency == 'monthly' and day_of_month:
            schedule.day_of_month = int(day_of_month)
        
        if subnet_id:
            schedule.subnet_id = subnet_id
        
        db.session.add(schedule)
        db.session.commit()
        
        flash('Schedule created successfully.', 'success')
        return redirect(url_for('scan.schedules'))
    
    return render_template('scan/new_schedule.html', 
                          environments=environments,
                          subnets=subnets)

@scan.route('/schedules/<int:schedule_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_schedule(schedule_id):
    schedule = ScanSchedule.query.get_or_404(schedule_id)
    environments = ScanEnvironment.query.all()
    subnets = Subnet.query.all()
    
    if request.method == 'POST':
        name = request.form.get('name')
        frequency = request.form.get('frequency')
        time_of_day = request.form.get('time_of_day')
        day_of_week = request.form.get('day_of_week')
        day_of_month = request.form.get('day_of_month')
        environment_id = request.form.get('environment_id')
        subnet_id = request.form.get('subnet_id') if request.form.get('subnet_id') != 'all' else None
        is_active = True if request.form.get('is_active') else False
        
        if not name or not frequency or not time_of_day or not environment_id:
            flash('Missing required fields.', 'danger')
            return render_template('scan/edit_schedule.html', 
                                  schedule=schedule,
                                  environments=environments,
                                  subnets=subnets)
        
        # Convert time string to Time object
        try:
            hour, minute = time_of_day.split(':')
            time_obj = datetime.strptime(f"{hour}:{minute}", '%H:%M').time()
        except ValueError:
            flash('Invalid time format. Use HH:MM.', 'danger')
            return render_template('scan/edit_schedule.html', 
                                  schedule=schedule,
                                  environments=environments,
                                  subnets=subnets)
        
        # Update schedule
        schedule.name = name
        schedule.frequency = frequency
        schedule.time_of_day = time_obj
        schedule.environment_id = environment_id
        schedule.subnet_id = subnet_id
        schedule.is_active = is_active
        schedule.updated_at = datetime.utcnow()
        
        # Update frequency-specific fields
        if frequency == 'weekly':
            schedule.day_of_week = int(day_of_week) if day_of_week else None
            schedule.day_of_month = None
        elif frequency == 'monthly':
            schedule.day_of_month = int(day_of_month) if day_of_month else None
            schedule.day_of_week = None
        else:
            schedule.day_of_week = None
            schedule.day_of_month = None
        
        db.session.commit()
        
        flash('Schedule updated successfully.', 'success')
        return redirect(url_for('scan.schedules'))
    
    return render_template('scan/edit_schedule.html', 
                          schedule=schedule,
                          environments=environments,
                          subnets=subnets)

@scan.route('/schedules/<int:schedule_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_schedule(schedule_id):
    schedule = ScanSchedule.query.get_or_404(schedule_id)
    
    db.session.delete(schedule)
    db.session.commit()
    
    flash('Schedule deleted successfully.', 'success')
    return redirect(url_for('scan.schedules')) 