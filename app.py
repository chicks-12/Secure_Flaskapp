from flask import Flask, render_template, redirect, url_for, flash, request, abort
from markupsafe import escape
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import re
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800 # 30 minutes session timeout

# Security Headers Middleware
@app.after_request
def apply_security_headers(response):
response.headers['X-Content-Type-Options'] = 'nosniff'
response.headers['X-Frame-Options'] = 'SAMEORIGIN'
response.headers['X-XSS-Protection'] = '1; mode=block'
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:;"
return response

# Mock database (in production, use SQLAlchemy with parameterized queries)
users_db = {
1: {
"id": 1,
"username": "admin",
"email": "admin@example.com",
"password": generate_password_hash("SecurePass123!"),
"failed_attempts": 0,
"locked_until": None
}
}

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

class User(UserMixin):
def __init__(self, user_data):
self.id = user_data['id']
self.username = user_data['username']
self.email = user_data['email']
self.password = user_data['password']

@login_manager.user_loader
def load_user(user_id):
user_data = users_db.get(int(user_id))
if user_data and (user_data.get('locked_until') is None or user_data['locked_until'] < datetime.now()):
return User(user_data)
return None

# Custom Validators
def validate_password_strength(form, field):
if len(field.data) < 12:
raise ValidationError('Password must be at least 12 characters long')
if not re.search(r'[A-Z]', field.data):
raise ValidationError('Password must contain at least one uppercase letter')
if not re.search(r'[a-z]', field.data):
raise ValidationError('Password must contain at least one lowercase letter')
if not re.search(r'[0-9]', field.data):
raise ValidationError('Password must contain at least one number')
if not re.search(r'[^A-Za-z0-9]', field.data):
raise ValidationError('Password must contain at least one special character')

def validate_username(form, field):
if not re.match(r'^[a-zA-Z0-9_]{4,20}$', field.data):
raise ValidationError('Username must be 4-20 characters (letters, numbers, underscores only)')

# Forms with enhanced validation
class RegistrationForm(FlaskForm):
username = StringField('Username', validators=[
DataRequired(),
Length(min=4, max=20),
validate_username
])
email = StringField('Email', validators=[
DataRequired(),
Email(),
Length(max=100)
])
password = PasswordField('Password', validators=[
DataRequired(),
validate_password_strength
])
submit = SubmitField('Register')

class LoginForm(FlaskForm):
username = StringField('Username', validators=[DataRequired()])
password = PasswordField('Password', validators=[DataRequired()])
submit = SubmitField('Login')

class TaskForm(FlaskForm):
task = StringField('Task', validators=[
DataRequired(),
Length(max=100),
lambda form, field: None if not re.search(r'<[^>]+>', field.data) else ValidationError('HTML tags are not allowed')
])
submit = SubmitField('Add Task')

# Routes with security enhancements
@app.route('/')
def home():
return render_template('home.html', now=datetime.now().year)

@app.route('/register', methods=['GET', 'POST'])
def register():
if current_user.is_authenticated:
return redirect(url_for('tasks'))
form = RegistrationForm()
if form.validate_on_submit():
# Check if username or email already exists
if any(u['username'] == form.username.data for u in users_db.values()):
flash('Username already taken!', 'danger')
return redirect(url_for('register'))
if any(u['email'] == form.email.data for u in users_db.values()):
flash('Email already registered!', 'danger')
return redirect(url_for('register'))
# Create new user
new_id = max(users_db.keys()) + 1
users_db[new_id] = {
"id": new_id,
"username": form.username.data,
"email": form.email.data,
"password": generate_password_hash(form.password.data),
"failed_attempts": 0,
"locked_until": None
}
flash('Account created successfully! Please login.', 'success')
return redirect(url_for('login'))
return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
if current_user.is_authenticated:
return redirect(url_for('tasks'))
form = LoginForm()
if form.validate_on_submit():
user_data = next((u for u in users_db.values() if u['username'] == form.username.data), None)
# Account lockout check
if user_data and user_data.get('locked_until') and user_data['locked_until'] > datetime.now():
remaining_time = (user_data['locked_until'] - datetime.now()).seconds // 60
flash(f'Account locked. Try again in {remaining_time} minutes.', 'danger')
return redirect(url_for('login'))
if user_data and check_password_hash(user_data['password'], form.password.data):
# Reset failed attempts on successful login
user_data['failed_attempts'] = 0
user_data['locked_until'] = None
user = User(user_data)
login_user(user)
flash('Logged in successfully!', 'success')
next_page = request.args.get('next')
return redirect(next_page or url_for('tasks'))
else:
# Increment failed attempts
if user_data:
user_data['failed_attempts'] = user_data.get('failed_attempts', 0) + 1
if user_data['failed_attempts'] >= 5:
user_data['locked_until'] = datetime.now() + timedelta(minutes=30)
flash('Account locked for 30 minutes due to too many failed attempts.', 'danger')
else:
flash(f'Invalid credentials. {5 - user_data["failed_attempts"]} attempts remaining.', 'danger')
else:
flash('Invalid credentials.', 'danger')
return render_template('login.html', form=form, now=datetime.now().year)

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
form = TaskForm()
if form.validate_on_submit():
task = escape(form.task.data) # XSS protection
flash(f'Task added: {task}', 'success')
return render_template('tasks.html', form=form)

@app.route('/logout')
@login_required
def logout():
logout_user()
flash('You have been logged out.', 'info')
return redirect(url_for('home'))

if __name__ == '__main__':
app.run(host='0.0.0.0', port=5000, debug=False) 
