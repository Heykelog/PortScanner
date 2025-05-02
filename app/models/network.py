from app import db
from datetime import datetime

class ScanEnvironment(db.Model):
    """Represents a scan environment like Prod, Test, Integration"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    subnets = db.relationship('Subnet', backref='environment', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<ScanEnvironment {self.name}>'

class Subnet(db.Model):
    """Represents a subnet within the network"""
    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(18), index=True)  # For example: 192.168.1.0/24
    description = db.Column(db.Text, nullable=True)
    environment_id = db.Column(db.Integer, db.ForeignKey('scan_environment.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    hosts = db.relationship('Host', backref='subnet', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Subnet {self.cidr}>'

class Host(db.Model):
    """Represents a host within a subnet"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), index=True)
    hostname = db.Column(db.String(64), nullable=True)
    subnet_id = db.Column(db.Integer, db.ForeignKey('subnet.id'))
    first_discovered = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(10), default='active')  # active, inactive, etc.
    
    # Relationships
    ports = db.relationship('Port', backref='host', lazy='dynamic', cascade="all, delete-orphan")
    scan_results = db.relationship('ScanResult', backref='host_relation', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Host {self.ip_address}>'

class Port(db.Model):
    """Represents a port on a host"""
    id = db.Column(db.Integer, primary_key=True)
    port_number = db.Column(db.Integer, index=True)
    protocol = db.Column(db.String(5))  # tcp, udp
    service = db.Column(db.String(64), nullable=True)
    version = db.Column(db.String(64), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'))
    first_discovered = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))  # open, closed, filtered
    is_new = db.Column(db.Boolean, default=True)
    is_vulnerable = db.Column(db.Boolean, default=False)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='port', lazy='dynamic', cascade="all, delete-orphan")
    scan_results = db.relationship('ScanResult', backref='port_relation', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Port {self.port_number}/{self.protocol} on {self.host.ip_address}>'

class Vulnerability(db.Model):
    """Represents a vulnerability found on a port"""
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), nullable=True)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    severity = db.Column(db.String(10))  # low, medium, high, critical
    port_id = db.Column(db.Integer, db.ForeignKey('port.id'))
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Vulnerability {self.cve_id or self.name}>' 