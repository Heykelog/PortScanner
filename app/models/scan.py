from app import db
from datetime import datetime

class ScanSchedule(db.Model):
    """Represents a scan schedule configuration"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    frequency = db.Column(db.String(20))  # daily, weekly, monthly, custom
    time_of_day = db.Column(db.Time, default=datetime.strptime('00:00', '%H:%M').time())
    day_of_week = db.Column(db.Integer, nullable=True)  # 0-6 for weekly (Monday=0)
    day_of_month = db.Column(db.Integer, nullable=True)  # 1-31 for monthly
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    environment_id = db.Column(db.Integer, db.ForeignKey('scan_environment.id'))
    subnet_id = db.Column(db.Integer, db.ForeignKey('subnet.id'), nullable=True)
    
    # Relationships
    scans = db.relationship('Scan', backref='schedule', lazy='dynamic', cascade="all, delete-orphan")
    environment = db.relationship('ScanEnvironment')
    subnet = db.relationship('Subnet', backref='schedules')
    
    def __repr__(self):
        return f'<ScanSchedule {self.name}>'
        
class ScanTargetList(db.Model):
    """Represents a list of scan targets (subnets or individual IPs)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    targets = db.relationship('ScanTarget', backref='target_list', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<ScanTargetList {self.name}>'
        
class ScanTarget(db.Model):
    """Represents a scan target (subnet or individual IP)"""
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(64))  # CIDR or IP
    target_type = db.Column(db.String(10))  # subnet, host
    list_id = db.Column(db.Integer, db.ForeignKey('scan_target_list.id'))
    
    def __repr__(self):
        return f'<ScanTarget {self.target}>'

class Scan(db.Model):
    """Represents a single scan run"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    scan_type = db.Column(db.String(20))  # port_scan, vulnerability_scan
    target_count = db.Column(db.Integer, default=0)
    discovered_hosts = db.Column(db.Integer, default=0)
    open_ports_found = db.Column(db.Integer, default=0)
    new_ports_found = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    schedule_id = db.Column(db.Integer, db.ForeignKey('scan_schedule.id'), nullable=True)
    environment_id = db.Column(db.Integer, db.ForeignKey('scan_environment.id'))
    target_list_id = db.Column(db.Integer, db.ForeignKey('scan_target_list.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    environment = db.relationship('ScanEnvironment')
    target_list = db.relationship('ScanTargetList')
    creator = db.relationship('User')
    results = db.relationship('ScanResult', backref='scan_relation', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Scan {self.name} ({self.status})>'

class ScanResult(db.Model):
    """Represents the detailed results of a scan"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'))
    port_id = db.Column(db.Integer, db.ForeignKey('port.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    result_type = db.Column(db.String(20))  # new_host, new_port, port_change, vulnerability
    details = db.Column(db.Text, nullable=True)
    
    # Relationships
    scan = db.relationship('Scan', overlaps="scan_relation,results")
    host = db.relationship('Host', overlaps="host_relation")
    port = db.relationship('Port', overlaps="port_relation,scan_results")
    
    def __repr__(self):
        return f'<ScanResult {self.result_type} for {self.host.ip_address}>' 