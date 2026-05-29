from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)  
    password = db.Column(db.String(200), nullable=False)
    
    def check_password(self, password_input):
        try:
            
            return check_password_hash(self.password, password_input)
        except ValueError:
            
            return self.password == password_input

    def __repr__(self):
        return f'<User {self.username}>'

    def __repr__(self):
        return f'<User {self.username}>'

class Laptop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    laptop_name = db.Column(db.String(50), nullable=False)
    laptop_model = db.Column(db.String(50), nullable=False)
    serial_number = db.Column(db.String(50), nullable=False)
    laptop_os = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='active', nullable=False)  # New status field

    def __repr__(self):
        return f'<Laptop {self.laptop_name} {self.laptop_model}>'

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.String(500))  # JSON or text details

class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    email = db.Column(db.String(120))  # store attempted email 
    action = db.Column(db.String(50), nullable=False)  # 'login_success', 'login_failed', 'register_success', 'register_failed'
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.String(500))

    user = db.relationship('User', backref='auth_logs', lazy=True)

    def __repr__(self):
        return f"<AuthLog {self.action} by {self.email or 'Unknown'} at {self.timestamp}>"

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    histories = db.relationship('BrowserHistory', backref='users', lazy=True)

class BrowserHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    browser = db.Column(db.String(50))
    url = db.Column(db.String(2000))
    title = db.Column(db.String(500))
    visit_count = db.Column(db.Integer, default=1)
    last_visit_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<BrowserHistory {self.url}>'

class Anomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    anomaly_type = db.Column(db.String(50), nullable=False)  
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    severity = db.Column(db.String(20), nullable=False)  
    details = db.Column(db.String(500))

class FileTransfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # in bytes
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_threat = db.Column(db.Boolean, default=False)
    threat_details = db.Column(db.String(500))
    status = db.Column(db.String(50), default='pending')  # 'pending', 'scanned', 'blocked', 'delivered'
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='files_sent')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='files_received')

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
        #db.drop_all()  # Uncomment to drop all tables

class FirebaseUser(UserMixin):
    def __init__(self, user_id, username, email, role, password_hash):
        self.id = str(user_id)
        self.username = username
        self.email = email
        self.role = role
        self.password = password_hash
        
    def get_id(self):
        return self.id
        
    def check_password(self, password_input):
        from werkzeug.security import check_password_hash
        try:
            return check_password_hash(self.password, password_input)
        except ValueError:
            return self.password == password_input