from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stock_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_premium = db.Column(db.Boolean, default=False)
    receive_notifications = db.Column(db.Boolean, default=True)
    email_alerts = db.Column(db.Boolean, default=True)
    risk_tolerance = db.Column(db.String(20), default='moderate')
    investment_experience = db.Column(db.String(20), default='beginner')
    
    portfolios = db.relationship('Portfolio', backref='user', lazy=True, cascade='all, delete-orphan')
    watchlists = db.relationship('Watchlist', backref='user', lazy=True, cascade='all, delete-orphan')

class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total_value = db.Column(db.Float, default=0.0)
    total_invested = db.Column(db.Float, default=0.0)
    
    holdings = db.relationship('Holding', backref='portfolio', lazy=True, cascade='all, delete-orphan')

class Holding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    portfolio_id = db.Column(db.Integer, db.ForeignKey('portfolio.id'), nullable=False)
    symbol = db.Column(db.String(10), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    purchase_price = db.Column(db.Float, nullable=False)
    current_price = db.Column(db.Float, default=0.0)

class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    symbol = db.Column(db.String(10), nullable=False)
    added_date = db.Column(db.DateTime, default=datetime.utcnow)
    alert_price = db.Column(db.Float)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# HTML Templates as strings
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Stock Dashboard - Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 5px; cursor: pointer; width: 100%; }
        button:hover { background: #0056b3; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 5px; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        a { color: #007bff; text-decoration: none; }
        .text-center { text-align: center; }
        h2 { color: #333; text-align: center; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Stock Dashboard Login</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-error">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        
        <div class="text-center" style="margin-top: 20px;">
            <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
        </div>
    </div>
</body>
</html>
"""

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Stock Dashboard - Register</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #28a745; color: white; padding: 12px 20px; border: none; border-radius: 5px; cursor: pointer; width: 100%; }
        button:hover { background: #218838; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 5px; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        a { color: #007bff; text-decoration: none; }
        .text-center { text-align: center; }
        h2 { color: #333; text-align: center; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Create Account</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-error">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>First Name:</label>
                <input type="text" name="first_name">
            </div>
            <div class="form-group">
                <label>Last Name:</label>
                <input type="text" name="last_name">
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Register</button>
        </form>
        
        <div class="text-center" style="margin-top: 20px;">
            <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
        </div>
    </div>
</body>
</html>
"""

PROFILE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Stock Dashboard - Profile</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f8f9fa; }
        .navbar { background: #343a40; color: white; padding: 1rem 2rem; }
        .navbar h1 { margin: 0; display: inline-block; }
        .navbar .user-info { float: right; }
        .navbar a { color: #fff; text-decoration: none; margin-left: 15px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .profile-header { background: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .profile-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-card h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; text-transform: uppercase; }
        .stat-card .value { font-size: 24px; font-weight: bold; color: #333; }
        .stat-card .change { font-size: 12px; margin-top: 5px; }
        .positive { color: #28a745; }
        .negative { color: #dc3545; }
        .section { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { margin-top: 0; color: #333; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .btn-secondary { background: #6c757d; }
        .btn-secondary:hover { background: #545b62; }
        .table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background: #f8f9fa; font-weight: bold; }
        .alert { padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>📈 Stock Dashboard</h1>
        <div class="user-info">
            Welcome, {{ user.first_name or user.username }}!
            <a href="{{ url_for('profile') }}">Profile</a>
            <a href="{{ url_for('edit_profile') }}">Settings</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
    </div>

    <div class="container">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-success">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="profile-header">
            <h1>👤 {{ user.first_name }} {{ user.last_name or user.username }}</h1>
            <p><strong>Email:</strong> {{ user.email }}</p>
            <p><strong>Member since:</strong> {{ stats.member_since }}</p>
            <p><strong>Account Age:</strong> {{ stats.account_age }} days</p>
            {% if user.bio %}
                <p><strong>Bio:</strong> {{ user.bio }}</p>
            {% endif %}
        </div>

        <div class="profile-stats">
            <div class="stat-card">
                <h3>Total Portfolio Value</h3>
                <div class="value">${{ "%.2f"|format(stats.total_portfolio_value) }}</div>
                <div class="change {% if stats.return_percentage >= 0 %}positive{% else %}negative{% endif %}">
                    {{ "%.2f"|format(stats.return_percentage) }}% Total Return
                </div>
            </div>
            
            <div class="stat-card">
                <h3>Total Invested</h3>
                <div class="value">${{ "%.2f"|format(stats.total_invested) }}</div>
                <div class="change">Principal Amount</div>
            </div>
            
            <div class="stat-card">
                <h3>Total Return</h3>
                <div class="value {% if stats.total_return >= 0 %}positive{% else %}negative{% endif %}">
                    ${{ "%.2f"|format(stats.total_return) }}
                </div>
                <div class="change">Profit/Loss</div>
            </div>
            
            <div class="stat-card">
                <h3>Portfolios</h3>
                <div class="value">{{ stats.total_portfolios }}</div>
                <div class="change">{{ stats.total_holdings }} Total Holdings</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Recent Portfolios</h2>
            {% if recent_portfolios %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Portfolio Name</th>
                            <th>Value</th>
                            <th>Invested</th>
                            <th>Return</th>
                            <th>Holdings</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for portfolio in recent_portfolios %}
                        <tr>
                            <td>{{ portfolio.name }}</td>
                            <td>${{ "%.2f"|format(portfolio.total_value) }}</td>
                            <td>${{ "%.2f"|format(portfolio.total_invested) }}</td>
                            <td class="{% if (portfolio.total_value - portfolio.total_invested) >= 0 %}positive{% else %}negative{% endif %}">
                                ${{ "%.2f"|format(portfolio.total_value - portfolio.total_invested) }}
                            </td>
                            <td>{{ portfolio.holdings|length }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p>No portfolios created yet. <a href="#" onclick="alert('Portfolio creation feature coming soon!')">Create your first portfolio</a></p>
            {% endif %}
        </div>

        <div class="section">
            <h2>👁️ Watchlist</h2>
            {% if recent_watchlist %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Symbol</th>
                            <th>Added Date</th>
                            <th>Alert Price</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in recent_watchlist %}
                        <tr>
                            <td><strong>{{ item.symbol }}</strong></td>
                            <td>{{ item.added_date.strftime('%Y-%m-%d') }}</td>
                            <td>{{ "$%.2f"|format(item.alert_price) if item.alert_price else 'No alert set' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p>Your watchlist is empty. <a href="#" onclick="alert('Watchlist feature coming soon!')">Add stocks to watch</a></p>
            {% endif %}
        </div>

        <div class="section">
            <h2>⚙️ Account Settings</h2>
            <p><strong>Risk Tolerance:</strong> {{ user.risk_tolerance.title() }}</p>
            <p><strong>Investment Experience:</strong> {{ user.investment_experience.title() }}</p>
            <p><strong>Notifications:</strong> {{ 'Enabled' if user.receive_notifications else 'Disabled' }}</p>
            <p><strong>Email Alerts:</strong> {{ 'Enabled' if user.email_alerts else 'Disabled' }}</p>
            <button onclick="window.location.href='{{ url_for('edit_profile') }}'">Edit Profile</button>
        </div>
    </div>
</body>
</html>
"""

EDIT_PROFILE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Edit Profile - Stock Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f8f9fa; }
        .navbar { background: #343a40; color: white; padding: 1rem 2rem; }
        .navbar h1 { margin: 0; display: inline-block; }
        .navbar a { color: #fff; text-decoration: none; margin-left: 15px; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .section { background: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
        input[type="text"], input[type="email"], input[type="password"], textarea, select { 
            width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; 
        }
        textarea { resize: vertical; height: 100px; }
        button { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; }
        button:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-secondary { background: #6c757d; }
        .btn-secondary:hover { background: #545b62; }
        .checkbox-group { display: flex; align-items: center; margin: 10px 0; }
        .checkbox-group input[type="checkbox"] { width: auto; margin-right: 10px; }
        .alert { padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>📈 Stock Dashboard</h1>
        <div style="float: right;">
            <a href="{{ url_for('profile') }}">Back to Profile</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
    </div>

    <div class="container">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-success">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="section">
            <h2>Edit Profile Information</h2>
            <form method="POST">
                <div class="form-group">
                    <label>First Name:</label>
                    <input type="text" name="first_name" value="{{ user.first_name or '' }}">
                </div>
                
                <div class="form-group">
                    <label>Last Name:</label>
                    <input type="text" name="last_name" value="{{ user.last_name or '' }}">
                </div>
                
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" name="email" value="{{ user.email }}" required>
                </div>
                
                <div class="form-group">
                    <label>Phone:</label>
                    <input type="text" name="phone" value="{{ user.phone or '' }}">
                </div>
                
                <div class="form-group">
                    <label>Bio:</label>
                    <textarea name="bio" placeholder="Tell us about yourself...">{{ user.bio or '' }}</textarea>
                </div>
                
                <div class="form-group">
                    <label>Risk Tolerance:</label>
                    <select name="risk_tolerance">
                        <option value="conservative" {{ 'selected' if user.risk_tolerance == 'conservative' else '' }}>Conservative</option>
                        <option value="moderate" {{ 'selected' if user.risk_tolerance == 'moderate' else '' }}>Moderate</option>
                        <option value="aggressive" {{ 'selected' if user.risk_tolerance == 'aggressive' else '' }}>Aggressive</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Investment Experience:</label>
                    <select name="investment_experience">
                        <option value="beginner" {{ 'selected' if user.investment_experience == 'beginner' else '' }}>Beginner</option>
                        <option value="intermediate" {{ 'selected' if user.investment_experience == 'intermediate' else '' }}>Intermediate</option>
                        <option value="expert" {{ 'selected' if user.investment_experience == 'expert' else '' }}>Expert</option>
                    </select>
                </div>
                
                <div class="checkbox-group">
                    <input type="checkbox" name="receive_notifications" {{ 'checked' if user.receive_notifications else '' }}>
                    <label>Receive push notifications</label>
                </div>
                
                <div class="checkbox-group">
                    <input type="checkbox" name="email_alerts" {{ 'checked' if user.email_alerts else '' }}>
                    <label>Receive email alerts</label>
                </div>
                
                <button type="submit">Update Profile</button>
                <button type="button" class="btn-secondary" onclick="window.location.href='{{ url_for('profile') }}'">Cancel</button>
            </form>
        </div>

        <div class="section">
            <h2>Change Password</h2>
            <form method="POST" action="{{ url_for('change_password') }}">
                <div class="form-group">
                    <label>Current Password:</label>
                    <input type="password" name="current_password" required>
                </div>
                
                <div class="form-group">
                    <label>New Password:</label>
                    <input type="password" name="new_password" required>
                </div>
                
                <div class="form-group">
                    <label>Confirm New Password:</label>
                    <input type="password" name="confirm_password" required>
                </div>
                
                <button type="submit">Change Password</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

class ProfileManager:
    @staticmethod
    def get_user_stats(user_id):
        user = User.query.get(user_id)
        if not user:
            return None
        
        portfolios = Portfolio.query.filter_by(user_id=user_id).all()
        total_portfolios = len(portfolios)
        
        # Mock data for demonstration
        total_portfolio_value = sum(p.total_value for p in portfolios) or random.uniform(50000, 150000)
        total_invested = sum(p.total_invested for p in portfolios) or random.uniform(40000, 120000)
        total_return = total_portfolio_value - total_invested
        return_percentage = (total_return / total_invested * 100) if total_invested > 0 else 0
        
        total_holdings = sum(len(p.holdings) for p in portfolios) or random.randint(5, 25)
        watchlist_count = Watchlist.query.filter_by(user_id=user_id).count() or random.randint(3, 15)
        account_age = (datetime.utcnow() - user.created_at).days
        
        return {
            'total_portfolios': total_portfolios or 3,
            'total_portfolio_value': total_portfolio_value,
            'total_invested': total_invested,
            'total_return': total_return,
            'return_percentage': return_percentage,
            'total_holdings': total_holdings,
            'watchlist_count': watchlist_count,
            'account_age': account_age,
            'member_since': user.created_at.strftime('%B %Y'),
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never'
        }

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template_string(REGISTER_TEMPLATE)
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template_string(REGISTER_TEMPLATE)
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Create sample data for demo
        create_sample_data(user.id)
        
        login_user(user)
        flash('Account created successfully!')
        return redirect(url_for('profile'))
    
    return render_template_string(REGISTER_TEMPLATE)

def create_sample_data(user_id):
    """Create sample portfolios and watchlist for demo"""
    # Create sample portfolios
    portfolio1 = Portfolio(
        user_id=user_id,
        name="Growth Portfolio",
        description="High-growth technology stocks",
        total_value=75000.0,
        total_invested=60000.0
    )
    
    portfolio2 = Portfolio(
        user_id=user_id,
        name="Dividend Portfolio",
        description="Stable dividend-paying stocks",
        total_value=45000.0,
        total_invested=42000.0
    )
    
    db.session.add(portfolio1)
    db.session.add(portfolio2)
    db.session.commit()
    
    # Create sample holdings
    holdings = [
        Holding(portfolio_id=portfolio1.id, symbol="AAPL", quantity=50, purchase_price=150.0, current_price=180.0),
        Holding(portfolio_id=portfolio1.id, symbol="GOOGL", quantity=10, purchase_price=2500.0, current_price=2800.0),
        Holding(portfolio_id=portfolio2.id, symbol="JNJ", quantity=100, purchase_price=160.0, current_price=165.0),
        Holding(portfolio_id=portfolio2.id, symbol="PG", quantity=75, purchase_price=140.0, current_price=145.0),
    ]
    
    for holding in holdings:
        db.session.add(holding)
